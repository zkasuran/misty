// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The offline-first state machine.
//!
//! ```text
//!                 ┌──────────────────── sync_once ────────────────────┐
//!                 │                                                   │
//!   Idle ──▶ Delete ──▶ Pull ──▶ verify ──▶ merge ──▶ record ──▶ Push ──▶ 409? ──▶ Idle
//!                 │     │  ▲       │                    │         │        │
//!      purged rows,     │  └─ has_more                  │         │        └─ merge,
//!      If-Match'd       │                               │         │           retry,
//!                       └── page too large: halve       │         │           bounded
//!                           the page, do not            │         └─ 200: record,
//!                           count it as a page          │            next item
//!                                                       └─ one durable save per page
//! ```
//!
//! Four invariants hold at every arrow, and the tests are named after them.
//!
//! **A write is never lost.** The outbound queue is *derived* from the vault's own
//! rows (see [`crate::state`]), so the vault's commit is the enqueue. There is no
//! window in which a write exists locally and is not queued.
//!
//! **A write is never applied twice.** Every push carries `If-Match`, so a resend
//! after an interruption either lands once (`200`) or is told what it missed
//! (`409`). And merge is a CRDT join, so re-merging a page the client already
//! merged changes nothing.
//!
//! **Progress is committed before it is claimed.** A page is merged into the
//! vault — one vault transaction — and only then is the cursor saved. Crash in
//! between and the page is re-fetched and re-merged, which is idempotent. The
//! opposite order would silently skip a page.
//!
//! **Nothing unverified is merged.** Every envelope's signer is looked up in the
//! client-signed roster and its signature checked before it reaches
//! [`Vault::merge_remote`], and a change that fails is dropped from the batch and
//! counted rather than aborting the page. A hostile server cannot stall a sync by
//! injecting one bad row, and it cannot get a bad row merged either.
//!
//! The delete pass is the one step that runs before the pull rather than after,
//! and [`SyncEngine::sync_once`] explains why: a row this device purged is still
//! in the change feed until it is gone from the server, so pulling first would
//! hand the device its own tombstone back forever.
//!
//! # What the engine will not do
//!
//! It will not act on SPEC §6.1's `deleted` flag, ever. It will not overwrite an
//! envelope it could not attribute: a `409` whose current envelope fails the
//! roster check stops the push with [`SyncError::UnknownSigner`] rather than
//! clobbering it, because "I do not recognise this writer" is a signal for the
//! user and a prompt to refresh the roster, not a licence to delete someone's
//! work. And it will not merge: merge is `misty-vault`'s, property-tested there.

use misty_crypto::envelope::{Envelope, EnvelopeKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::keys::VaultKey;
use misty_crypto::{DeviceId, ItemId};
use misty_otp::Clock;
use misty_vault::{Conflict, RemoteChange, RewrapProgress, Vault, VaultStore};

use crate::backoff::{Backoff, Sleeper};
use crate::client::{SyncClient, SyncConfig};
use crate::error::{Result, SyncError};
use crate::limits;
use crate::roster;
use crate::state::{Fingerprint, KnownRow, RotationState, StateStore, SyncState, TimeSample};
use crate::time::{Drift, DriftTracker};
use crate::transport::Transport;
use crate::wire::{FeedChange, PutOutcome, Quota, ServerVersion};

/// Why one change from the feed was not merged.
///
/// Carries no `item_id` on purpose: a rejection is a fact about the exchange, and
/// a count per reason is what a UI needs. The `item_id` is in the feed the server
/// sent, not in anything this client produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Rejection {
    /// The envelope did not parse as an envelope.
    Malformed,
    /// The envelope was larger than [`limits::MAX_ENVELOPE_LEN`].
    TooLarge,
    /// The signer is not in the roster (SPEC §6.2, threat model `A6`).
    UnknownSigner,
    /// The signature did not verify under the signer's rostered key.
    SignatureInvalid,
}

/// One item the server does not yet have this device's version of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PendingWrite {
    /// Which item.
    pub item_id: ItemId,
    /// What has to happen to it.
    pub action: PendingAction,
}

/// What a pending write will do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PendingAction {
    /// Send this device's envelope.
    Put,
    /// Drop a row this device has purged (SPEC §4's 90-day tombstone GC).
    Delete,
}

/// What one [`SyncEngine::sync_once`] did.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Change-feed pages read.
    pub pages: usize,
    /// Changes the server offered.
    pub changes_seen: usize,
    /// Changes verified and merged.
    pub applied: usize,
    /// Changes carrying something the vault does not model — a roster, a settings
    /// blob. Verified, then set aside.
    pub ignored: usize,
    /// Changes refused, one entry per refusal.
    pub rejected: Vec<Rejection>,
    /// Items pushed successfully.
    pub pushed: usize,
    /// Rows deleted server-side after a local tombstone purge.
    pub deleted: usize,
    /// `409`s resolved by merging and retrying.
    pub conflicts_resolved: usize,
    /// Items still pending when this returned.
    pub pending_after: usize,
    /// Where the change feed now stands.
    pub cursor: Option<i64>,
    /// Divergences the merge kept both sides of, from `misty-vault`.
    pub conflicts: Vec<Conflict>,
    /// A roster the feed carried, still sealed.
    ///
    /// The engine cannot adopt it: the roster is the vault's trust anchor and the
    /// caller has to re-open the vault with it. Hand it to
    /// [`crate::roster::open_roster`], which verifies that it chains to a device
    /// the current roster already trusts.
    pub roster_update: Option<(ItemId, Vec<u8>)>,
}

impl core::fmt::Debug for SyncReport {
    /// Counts, and the roster update as a length rather than as bytes.
    ///
    /// A report is a value for the app rather than a log line, but a derived
    /// `Debug` here would put a whole sealed roster — up to 64 KiB of base64 —
    /// into whatever formatted it, and an assertion message that dumps an
    /// envelope is unreadable as well as unwise. `conflicts` does name item ids,
    /// because a conflict a user has to resolve is meaningless without them; that
    /// is `misty-vault`'s type and its decision.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyncReport")
            .field("pages", &self.pages)
            .field("changes_seen", &self.changes_seen)
            .field("applied", &self.applied)
            .field("ignored", &self.ignored)
            .field("rejected", &self.rejected)
            .field("pushed", &self.pushed)
            .field("deleted", &self.deleted)
            .field("conflicts_resolved", &self.conflicts_resolved)
            .field("pending_after", &self.pending_after)
            .field("cursor", &self.cursor)
            .field("conflicts", &self.conflicts)
            .field(
                "roster_update_bytes",
                &self
                    .roster_update
                    .as_ref()
                    .map(|(_, envelope)| envelope.len()),
            )
            .finish()
    }
}

impl SyncReport {
    /// Whether anything at all happened.
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        self.applied == 0
            && self.pushed == 0
            && self.deleted == 0
            && self.rejected.is_empty()
            && self.roster_update.is_none()
    }

    /// How many changes were refused.
    #[must_use]
    pub fn rejected_count(&self, reason: Rejection) -> usize {
        self.rejected
            .iter()
            .filter(|entry| **entry == reason)
            .count()
    }
}

/// The sync engine: one vault, one server, one durable state.
#[derive(Debug)]
pub struct SyncEngine<T: Transport, S: StateStore> {
    client: SyncClient<T>,
    store: S,
    state: SyncState,
    backoff: Backoff,
}

impl<T: Transport, S: StateStore> SyncEngine<T, S> {
    /// Builds an engine, loading whatever the last run left behind.
    ///
    /// # Errors
    ///
    /// [`SyncError::StateStore`] if the state cannot be read, or
    /// [`SyncError::StateTooNew`] if it came from a newer build.
    pub fn new(
        transport: T,
        config: SyncConfig,
        identity: DeviceIdentity,
        store: S,
    ) -> Result<Self> {
        let state = store.load()?;
        state.check_version()?;
        Ok(Self {
            client: SyncClient::new(transport, config, identity),
            store,
            state,
            backoff: Backoff::default(),
        })
    }

    /// Replaces the retry schedule.
    #[must_use]
    pub const fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// The endpoint layer, for a caller that needs one request rather than a sync.
    #[must_use]
    pub const fn client(&self) -> &SyncClient<T> {
        &self.client
    }

    /// The endpoint layer, mutably.
    pub const fn client_mut(&mut self) -> &mut SyncClient<T> {
        &mut self.client
    }

    /// The durable state, as it stands in memory.
    #[must_use]
    pub const fn state(&self) -> &SyncState {
        &self.state
    }

    /// The state store, for a caller that needs to inspect what was persisted.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Where the change feed stands.
    #[must_use]
    pub const fn cursor(&self) -> Option<i64> {
        self.state.cursor
    }

    /// The measured clock offset and what the UI should say about it (SPEC §6.5).
    #[must_use]
    pub const fn drift(&self) -> Drift {
        Drift::new(self.state.time)
    }

    /// Whether an epoch rotation is unfinished.
    #[must_use]
    pub const fn rotation(&self) -> Option<RotationState> {
        self.state.rotation
    }

    /// The outbound queue, derived from the vault rather than remembered.
    ///
    /// An item is pending when the envelope the vault holds is not the envelope
    /// the server last confirmed. See [`crate::state`] for why this is derived:
    /// the vault's own commit becomes the enqueue, so there is no window in which
    /// a write exists and is not queued.
    ///
    /// # Errors
    ///
    /// [`SyncError::Vault`] if the vault's store cannot be read, or
    /// [`SyncError::Crypto`] if a fingerprint cannot be computed.
    pub fn pending<VS: VaultStore, C: Clock>(
        &self,
        vault: &Vault<VS, C>,
    ) -> Result<Vec<PendingWrite>> {
        let rows = vault
            .store()
            .load_all()
            .map_err(|error| SyncError::vault("read the vault", error))?;
        let mut out = Vec::new();
        for row in &rows {
            let fingerprint = Fingerprint::of(&row.envelope)?;
            let confirmed = self
                .state
                .known
                .get(&row.item_id)
                .is_some_and(|known| known.fingerprint == Some(fingerprint));
            if !confirmed {
                out.push(PendingWrite {
                    item_id: row.item_id,
                    action: PendingAction::Put,
                });
            }
        }
        // A row the server has and the vault no longer does is a completed
        // tombstone purge. Only items and groups qualify: a roster or settings
        // blob has no vault row by design, and deleting one because it is
        // "missing" would erase the trust anchor.
        for (item_id, known) in &self.state.known {
            if known.is_deletable() && !rows.iter().any(|row| row.item_id == *item_id) {
                out.push(PendingWrite {
                    item_id: *item_id,
                    action: PendingAction::Delete,
                });
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Pulls, then pushes, once.
    ///
    /// Pull before push so that local writes are merged against the newest remote
    /// state before they are sent, which turns most would-be `409`s into a merge
    /// that has already happened.
    ///
    /// The one exception is the server-side delete that follows a tombstone purge,
    /// which runs *first*. A purged row is still in the change feed until it is
    /// gone from the server, so pulling first would hand this device its own
    /// tombstone straight back and re-create the row it had just collected —
    /// forever, on every sync. Doing the delete first is safe because it carries
    /// `If-Match`: if any device has written that item since, the server answers
    /// `409`, the delete does not happen, and the pull that follows brings the
    /// newer value in.
    ///
    /// Interrupting this at any await point is safe. See the module docs for the
    /// four invariants that make it so.
    ///
    /// # Errors
    ///
    /// Any [`SyncError`]. A transport failure part way through is not a partial
    /// application: whatever had been merged and saved before it stays, and the
    /// next call resumes from there.
    pub async fn sync_once<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &mut Vault<VS, C>,
        roster: &Roster,
    ) -> Result<SyncReport> {
        let mut report = SyncReport::default();
        self.push_deletes(vault, &mut report).await?;
        self.pull(vault, roster, &mut report).await?;
        self.push_writes(vault, roster, &mut report).await?;
        report.cursor = self.state.cursor;
        report.pending_after = self.pending(vault)?.len();
        Ok(report)
    }

    /// Runs [`sync_once`](Self::sync_once) until it succeeds, backing off between
    /// attempts.
    ///
    /// Only retries what is worth retrying: a transport failure, a `429`, a `5xx`.
    /// A rejected roster, an unknown signer or a replayed time response are not
    /// transient and retrying them would just hide them.
    ///
    /// # Errors
    ///
    /// The last error, if `attempts` are exhausted or the failure is not
    /// retriable.
    pub async fn run<VS: VaultStore, C: Clock, K: Sleeper>(
        &mut self,
        vault: &mut Vault<VS, C>,
        roster: &Roster,
        sleeper: &K,
        attempts: u32,
    ) -> Result<SyncReport> {
        let mut last = Err(SyncError::Transport {
            operation: "sync",
            kind: crate::error::TransportKind::Environment,
        });
        for attempt in 0..attempts.max(1) {
            last = self.sync_once(vault, roster).await;
            match &last {
                Ok(_) => return last,
                Err(error) if is_retriable(error) => {
                    // The session may be what failed; a fresh challenge is cheap.
                    self.client.forget_session();
                    sleeper.sleep_ms(self.backoff.next_delay_ms(attempt)?).await;
                }
                Err(_) => return last,
            }
        }
        last
    }

    /// Walks the change feed from the stored cursor to the end.
    async fn pull<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &mut Vault<VS, C>,
        roster: &Roster,
        report: &mut SyncReport,
    ) -> Result<()> {
        let mut limit = self.client.config().page_limit.max(1);
        loop {
            if report.pages >= limits::MAX_PAGES_PER_SYNC {
                return Err(SyncError::FeedTooLong {
                    max: limits::MAX_PAGES_PER_SYNC,
                });
            }
            let cursor = self.state.cursor.unwrap_or(0);
            let feed = match self.client.changes(self.state.cursor, limit).await {
                Ok(feed) => feed,
                // A page that does not fit is not a protocol failure and must not
                // wedge the sync: ask for fewer changes. This does not count as a
                // page, because no progress was made.
                Err(SyncError::ResponseTooLarge { .. } | SyncError::EnvelopeTooLarge { .. })
                    if limit > 1 =>
                {
                    limit = (limit / 2).max(1);
                    continue;
                }
                Err(error) => return Err(error),
            };
            report.pages = report.pages.saturating_add(1);
            report.changes_seen = report.changes_seen.saturating_add(feed.changes.len());

            // Every change must be strictly newer than where we already are, and
            // the resume point must not move backwards. `decode_change_feed` has
            // already proved the page ascends internally; this is the half that
            // needs the cursor.
            for change in &feed.changes {
                if change.seq <= cursor {
                    return Err(SyncError::SeqRollback {
                        offered: change.seq,
                        cursor,
                    });
                }
            }
            if feed.next_seq < cursor {
                return Err(SyncError::SeqRollback {
                    offered: feed.next_seq,
                    cursor,
                });
            }

            // A roster change is a change of trust anchor: every change after it
            // may be signed by a device only the *new* roster knows about, and
            // verifying those against the old roster would reject them and then
            // advance the cursor past them for good. So the page stops at the
            // roster, the cursor stops at its `seq`, and the caller adopts it and
            // syncs again.
            let halt_at = feed.changes.iter().position(is_roster_change);
            let (slice, next_cursor) = match halt_at {
                Some(index) => (
                    feed.changes.get(..=index).unwrap_or(&feed.changes),
                    feed.changes.get(index).map_or(feed.next_seq, |c| c.seq),
                ),
                None => (feed.changes.as_slice(), feed.next_seq),
            };

            self.apply_page(vault, roster, slice, report)?;
            self.state.cursor = Some(next_cursor);
            self.store.save(&self.state)?;
            if halt_at.is_some() {
                return Ok(());
            }

            // Stop when the server says so, and also when it says otherwise but
            // has nothing to add: `has_more` is the server's claim, and an endless
            // stream of empty pages is a denial of service dressed as politeness.
            if !feed.has_more || (feed.changes.is_empty() && feed.next_seq <= cursor) {
                return Ok(());
            }
        }
    }

    /// Verifies a page, merges what survives, and records what the server holds.
    ///
    /// The order is the crash guarantee: the vault's own transaction commits
    /// first, then this crate's state. A crash in between re-reads the page, and
    /// re-merging a page is a no-op because merge is a join.
    fn apply_page<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &mut Vault<VS, C>,
        roster: &Roster,
        changes: &[FeedChange],
        report: &mut SyncReport,
    ) -> Result<()> {
        let mut batch: Vec<RemoteChange> = Vec::new();
        let mut accepted: Vec<(&FeedChange, Option<EnvelopeKind>)> = Vec::new();
        for change in changes {
            // SPEC §6.1's `deleted` flag is read by the decoder and used by
            // nothing. `change.deleted` is deliberately not consulted here or
            // anywhere else: a delete is a signed tombstone inside the payload,
            // and a server that could delete by asserting a boolean would hold the
            // one destructive power this design exists to deny it.
            let Some(envelope) = change.envelope.as_deref() else {
                // A row whose bytes the server reclaimed. There is nothing to
                // verify and nothing to merge; the `version` is still worth having,
                // and the absent fingerprint keeps the item pending so this device
                // offers its own copy back.
                accepted.push((change, None));
                continue;
            };
            match self.verify_change(&change.item_id, envelope, roster) {
                Err(reason) => report.rejected.push(reason),
                Ok(kind) => {
                    accepted.push((change, Some(kind)));
                    if matches!(kind, EnvelopeKind::Item | EnvelopeKind::Group) {
                        batch.push(RemoteChange {
                            item_id: change.item_id,
                            seq: Some(change.seq),
                            version: change.version.as_ref().map(ServerVersion::to_bytes),
                            envelope: envelope.to_vec(),
                        });
                    } else {
                        report.ignored = report.ignored.saturating_add(1);
                        if kind == EnvelopeKind::DeviceRoster {
                            report.roster_update = Some((change.item_id, envelope.to_vec()));
                        }
                    }
                }
            }
        }

        if !batch.is_empty() {
            let merged = vault
                .merge_remote(&batch)
                .map_err(|error| SyncError::vault("merge remote changes", error))?;
            report.applied = report.applied.saturating_add(merged.applied);
            report.ignored = report.ignored.saturating_add(merged.ignored);
            for conflict in merged.conflicts {
                if !report.conflicts.contains(&conflict) {
                    report.conflicts.push(conflict);
                }
            }
        }

        // Only accepted changes update what the server is known to hold. A
        // rejected envelope leaves the previous fingerprint in place, so the item
        // stays pending and this device's own copy is offered back — a tampered
        // row heals rather than sticking.
        for (change, kind) in accepted {
            let fingerprint = change
                .envelope
                .as_deref()
                .map(Fingerprint::of)
                .transpose()?;
            // A reclaimed row has no authenticated `kind`. Recording the kind this
            // device already believed keeps a purge from becoming a delete candidate
            // for something that was never an item; an unknown value is not
            // deletable, which is the safe default.
            let kind = kind.map_or_else(
                || {
                    self.state
                        .known
                        .get(&change.item_id)
                        .map_or(0, |known| known.kind)
                },
                EnvelopeKind::as_u8,
            );
            self.state.known.insert(
                change.item_id,
                KnownRow {
                    kind,
                    fingerprint,
                    version: change.version.clone(),
                    seq: Some(change.seq),
                },
            );
        }
        Ok(())
    }

    /// Roster membership and signature, before anything is decrypted.
    ///
    /// SPEC §2.4 fixes the order and `misty-crypto` enforces it with a type: the
    /// only way to a decrypting method is through
    /// [`Envelope::verify`](misty_crypto::envelope::Envelope::verify), which looks
    /// the signer up in the roster first. This function stops at that point and
    /// returns the authenticated `kind`, so the engine can route a change without
    /// having decrypted it.
    fn verify_change(
        &self,
        item_id: &ItemId,
        envelope: &[u8],
        roster: &Roster,
    ) -> core::result::Result<EnvelopeKind, Rejection> {
        if envelope.len() > limits::MAX_ENVELOPE_LEN {
            return Err(Rejection::TooLarge);
        }
        let parsed = Envelope::parse(envelope).map_err(|_| Rejection::Malformed)?;
        let kind = parsed.header().kind;
        parsed
            .verify(item_id, roster)
            .map_err(|error| match error {
                misty_crypto::Error::UnknownSigner { .. } => Rejection::UnknownSigner,
                misty_crypto::Error::SignatureInvalid | misty_crypto::Error::BadVerifyingKey => {
                    Rejection::SignatureInvalid
                }
                _ => Rejection::Malformed,
            })?;
        Ok(kind)
    }

    /// The same check, as a hard error, for the `409` path.
    ///
    /// A conflict is a claim that someone else wrote first. If this client cannot
    /// attribute that write to a rostered device, it stops: overwriting would be
    /// the one way a hostile server gets a client to destroy data on its behalf,
    /// and the honest case — a device enrolled since the last roster fetch — is
    /// fixed by fetching the roster, not by clobbering.
    fn verify_conflict(
        &self,
        item_id: &ItemId,
        envelope: &[u8],
        roster: &Roster,
    ) -> Result<EnvelopeKind> {
        if envelope.len() > limits::MAX_ENVELOPE_LEN {
            return Err(SyncError::EnvelopeTooLarge {
                len: envelope.len(),
                max: limits::MAX_ENVELOPE_LEN,
            });
        }
        let parsed = Envelope::parse(envelope)?;
        let kind = parsed.header().kind;
        parsed
            .verify(item_id, roster)
            .map_err(|error| match error {
                misty_crypto::Error::UnknownSigner { signer } => {
                    SyncError::UnknownSigner { signer }
                }
                other => SyncError::Crypto(other),
            })?;
        Ok(kind)
    }

    /// Drops server rows this device has purged (SPEC §4's 90-day tombstone GC).
    ///
    /// Runs before the pull; see [`sync_once`](Self::sync_once) for why.
    async fn push_deletes<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &Vault<VS, C>,
        report: &mut SyncReport,
    ) -> Result<()> {
        for write in self.pending(vault)? {
            if write.action != PendingAction::Delete {
                continue;
            }
            let version = self.state.version_of(&write.item_id).cloned();
            self.client
                .delete_item(&write.item_id, version.as_ref())
                .await?;
            self.state.known.remove(&write.item_id);
            self.store.save(&self.state)?;
            report.deleted = report.deleted.saturating_add(1);
        }
        Ok(())
    }

    /// Sends everything the server does not have.
    async fn push_writes<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &mut Vault<VS, C>,
        roster: &Roster,
        report: &mut SyncReport,
    ) -> Result<()> {
        for write in self.pending(vault)? {
            if write.action != PendingAction::Put {
                continue;
            }
            self.push_one(vault, roster, &write.item_id, report).await?;
        }
        Ok(())
    }

    /// Pushes one item, resolving `409`s by merging and retrying.
    ///
    /// # Errors
    ///
    /// [`SyncError::ConflictLoop`] if the server neither accepts the write nor
    /// makes progress within [`limits::MAX_CONFLICT_RETRIES`],
    /// [`SyncError::UnknownSigner`] if a conflicting envelope cannot be
    /// attributed, or anything the transport or the vault reports.
    async fn push_one<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &mut Vault<VS, C>,
        roster: &Roster,
        item_id: &ItemId,
        report: &mut SyncReport,
    ) -> Result<()> {
        for _ in 0..=limits::MAX_CONFLICT_RETRIES {
            let Some(row) = vault
                .stored(item_id)
                .map_err(|error| SyncError::vault("read the item", error))?
            else {
                // Purged between deriving the queue and getting here. Nothing to
                // send, and the delete pass will pick it up next time.
                return Ok(());
            };
            let local = Fingerprint::of(&row.envelope)?;
            if self
                .state
                .known
                .get(item_id)
                .is_some_and(|known| known.fingerprint == Some(local))
            {
                // A merge during an earlier round of this loop landed on exactly
                // what the server already has. Converged; sending it again would
                // only burn a `seq`.
                return Ok(());
            }

            let version = self.state.version_of(item_id).cloned();
            match self
                .client
                .put_item(item_id, &row.envelope, version.as_ref())
                .await?
            {
                PutOutcome::Applied { seq, version } => {
                    self.state.known.insert(
                        *item_id,
                        KnownRow {
                            kind: row.kind.as_u8(),
                            fingerprint: Some(local),
                            version: Some(version),
                            seq: Some(seq),
                        },
                    );
                    self.store.save(&self.state)?;
                    report.pushed = report.pushed.saturating_add(1);
                    return Ok(());
                }
                PutOutcome::Conflict { version, envelope } => {
                    self.resolve_conflict(vault, roster, item_id, version, envelope, report)?;
                }
            }
        }
        Err(SyncError::ConflictLoop {
            max: limits::MAX_CONFLICT_RETRIES,
        })
    }

    /// Merges what the server said it already had, so the next attempt carries a
    /// value that subsumes both.
    ///
    /// Three shapes of `409` arrive here and only the first involves a merge:
    ///
    /// * a version **and** an envelope — someone else wrote; verify it, merge it,
    ///   retry with their version;
    /// * a version and **no** envelope — the row exists but its bytes were
    ///   reclaimed after a `DELETE` (SPEC §6.1 keeps the row so `version` stays
    ///   monotonic). Nothing to merge; retry with the version;
    /// * **neither** — the row does not exist, which `misty-server` says as
    ///   `version: 0`. Retry as a create, which is what dropping the recorded
    ///   version achieves.
    ///
    /// Refuses to loop: if the server answers a second `409` with the same
    /// envelope *and* the same version this client has already merged, no further
    /// attempt can change the outcome, so it stops immediately rather than
    /// spending all [`limits::MAX_CONFLICT_RETRIES`].
    fn resolve_conflict<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &mut Vault<VS, C>,
        roster: &Roster,
        item_id: &ItemId,
        version: Option<ServerVersion>,
        envelope: Option<Vec<u8>>,
        report: &mut SyncReport,
    ) -> Result<()> {
        let Some(envelope) = envelope else {
            // No bytes to merge. Record whatever version arrived — `None` means
            // "retry as a create" — and let the loop send this device's copy.
            match version {
                None => {
                    self.state.known.remove(item_id);
                }
                Some(version) => {
                    let kind = self.state.known.get(item_id).map_or(0, |known| known.kind);
                    self.state.known.insert(
                        *item_id,
                        KnownRow {
                            kind,
                            fingerprint: None,
                            version: Some(version),
                            seq: None,
                        },
                    );
                }
            }
            self.store.save(&self.state)?;
            report.conflicts_resolved = report.conflicts_resolved.saturating_add(1);
            return Ok(());
        };

        let kind = self.verify_conflict(item_id, &envelope, roster)?;
        let fingerprint = Fingerprint::of(&envelope)?;
        if self
            .state
            .known
            .get(item_id)
            .is_some_and(|known| known.fingerprint == Some(fingerprint) && known.version == version)
        {
            return Err(SyncError::ConflictLoop {
                max: limits::MAX_CONFLICT_RETRIES,
            });
        }
        self.state.known.insert(
            *item_id,
            KnownRow {
                kind: kind.as_u8(),
                fingerprint: Some(fingerprint),
                version,
                seq: None,
            },
        );
        if matches!(kind, EnvelopeKind::Item | EnvelopeKind::Group) {
            let merged = vault
                .merge_remote(&[RemoteChange {
                    item_id: *item_id,
                    seq: None,
                    version: None,
                    envelope,
                }])
                .map_err(|error| SyncError::vault("merge a conflicting write", error))?;
            for conflict in merged.conflicts {
                if !report.conflicts.contains(&conflict) {
                    report.conflicts.push(conflict);
                }
            }
        }
        self.store.save(&self.state)?;
        report.conflicts_resolved = report.conflicts_resolved.saturating_add(1);
        Ok(())
    }

    /// Measures the server's clock and stores the offset (SPEC §6.5).
    ///
    /// Reads `clock` and never writes it. Apply the result with
    /// [`Clock::with_skew_ms`] or
    /// [`Drift::effective_now_ms`].
    ///
    /// # Errors
    ///
    /// [`SyncError::TimeNonceMismatch`] for a replayed response,
    /// [`SyncError::TimeSignatureInvalid`] for one signed by the wrong key,
    /// [`SyncError::TimeWentBackwards`] for a rollback, or a transport failure.
    pub async fn measure_time<C: Clock>(&mut self, clock: &C) -> Result<TimeSample> {
        let local = i64::try_from(clock.now_unix_ms()).unwrap_or(i64::MAX);
        let server_ms = self.client.signed_time().await?;
        let sample = DriftTracker::new(self.state.time).accept(local, server_ms)?;
        self.state.time = Some(sample);
        self.store.save(&self.state)?;
        Ok(sample)
    }

    /// `GET /v1/quota`.
    ///
    /// # Errors
    ///
    /// As [`SyncClient::quota`].
    pub async fn quota(&mut self) -> Result<Quota> {
        self.client.quota().await
    }

    /// Seals the roster and writes it to its derived address (SPEC §6.2).
    ///
    /// # Errors
    ///
    /// [`SyncError::RosterRejected`] if the roster is not signed by this device,
    /// or anything the transport reports.
    pub async fn push_roster<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &Vault<VS, C>,
        roster: &Roster,
        vault_key: &VaultKey,
    ) -> Result<RosterPush> {
        let (item_id, sealed) =
            roster::seal_roster(roster, vault_key, vault.epoch(), self.client.identity())?;
        let version = self.state.version_of(&item_id).cloned();
        match self
            .client
            .put_item(&item_id, &sealed, version.as_ref())
            .await?
        {
            PutOutcome::Applied { seq, version } => {
                self.state.known.insert(
                    item_id,
                    KnownRow {
                        kind: EnvelopeKind::DeviceRoster.as_u8(),
                        fingerprint: Some(Fingerprint::of(&sealed)?),
                        version: Some(version),
                        seq: Some(seq),
                    },
                );
                self.store.save(&self.state)?;
                Ok(RosterPush::Applied)
            }
            // Two devices enrolled a third at the same time. There is no CRDT for
            // a device list and inventing one here would be guessing about who is
            // trusted, so the conflict is handed back: adopt the other roster,
            // re-apply the change, push again.
            PutOutcome::Conflict { version, envelope } => {
                self.state.known.insert(
                    item_id,
                    KnownRow {
                        kind: EnvelopeKind::DeviceRoster.as_u8(),
                        fingerprint: envelope.as_deref().map(Fingerprint::of).transpose()?,
                        version,
                        seq: None,
                    },
                );
                self.store.save(&self.state)?;
                // A conflict with no envelope means the server holds a roster row
                // whose bytes are gone, or none at all. There is nothing to adopt,
                // so the retry is the caller's: report it as superseded by nothing.
                Ok(RosterPush::Superseded {
                    item_id,
                    envelope: envelope.unwrap_or_default(),
                })
            }
        }
    }

    /// Approves an enrollment: seals the grant, pushes the roster successor, then
    /// delivers the grant (SPEC §6.3).
    ///
    /// The order is the point, and it is why this exists rather than leaving the
    /// three calls to the caller.
    ///
    /// **Seal first.** Sealing is where the confirmation code is checked, and it
    /// sends nothing. A user who compares the six digits, finds them wrong and
    /// declines has published no roster and granted no key — which is exactly what a
    /// substituted QR payload has to be answered with.
    ///
    /// **Roster before grant.** If the grant went first and the roster write then
    /// failed, the new device would hold `VK` and be able to write envelopes that
    /// every other device rejects — a device that appears to work and silently does
    /// not replicate. The other way round, a failure leaves a roster naming a device
    /// that never finished joining, which costs one unused row.
    ///
    /// The caller's roster is not modified. On success the successor comes back in
    /// [`Approval::Approved`]; adopt it, re-open the vault with it, and sync.
    ///
    /// # Errors
    ///
    /// [`SyncError::Crypto`] with
    /// [`ConfirmationCodeMismatch`](misty_crypto::Error::ConfirmationCodeMismatch)
    /// if `typed_code` does not match the request the server delivered — which is
    /// what stops a substituted QR payload — or anything the transport reports.
    pub async fn approve_enrollment<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &Vault<VS, C>,
        roster: &Roster,
        approval: &crate::enroll::PendingApproval,
        typed_code: &str,
        grant: &GrantDetails<'_>,
    ) -> Result<Approval> {
        let record = crate::enroll::record_for(
            approval.request(),
            grant.enrolled_at,
            self.client.identity().device_id(),
        )?;
        // A duplicate handle onto the same keys, because sealing the grant needs
        // `&DeviceIdentity` while delivering it needs `&mut SyncClient`.
        let signer = crate::duplicate_identity(self.client.identity());
        let mut successor = roster.clone();
        successor.add(record.clone())?;
        successor.sign(&signer)?;

        let sealed = approval.seal(
            typed_code,
            &misty_crypto::enrollment::GrantContents {
                vault_id: self.client.config().vault_id,
                vault_key: grant.vault_key,
                epoch: vault.epoch(),
                server_url: grant.server_url,
                roster: &successor,
            },
            &signer,
        )?;

        match self.push_roster(vault, &successor, grant.vault_key).await? {
            RosterPush::Superseded { item_id, envelope } => {
                Ok(Approval::RosterSuperseded { item_id, envelope })
            }
            RosterPush::Applied => {
                approval.deliver(&mut self.client, &sealed).await?;
                Ok(Approval::Approved {
                    roster: successor,
                    record,
                })
            }
        }
    }

    /// the epoch (SPEC §6.4).
    ///
    /// The epoch is bumped only if the roster push landed. Rotating first would
    /// leave a vault re-sealing under an epoch whose reason for existing never
    /// reached the server.
    ///
    /// # What this does not achieve, and SPEC §6.4 should say so
    ///
    /// `EK_n = HKDF(VK, "misty/epoch/v1", LE32(n))`, so **any device that still
    /// holds `VK` can derive every future epoch key.** A revoked device that was
    /// ever unlocked holds `VK`. Bumping the epoch therefore does not take read
    /// access away from it; what it does is force every object to be re-sealed
    /// and re-signed by a device that is still trusted, which retires the revoked
    /// device's signatures and any item key it may have leaked in isolation.
    ///
    /// §6.4 opens with "revoking a device removes it from the roster, re-signs,
    /// and bumps `epoch`" and only later mentions, as a separate topic, that
    /// rotating `VK` is "the response to a suspected `VK` compromise". Read in
    /// order, that invites the conclusion that revocation is complete without it.
    /// It is not: for any device that has ever been unlocked, revocation MUST be
    /// followed by a `VK` rotation and a new Recovery Kit, and the UI has to say
    /// so. `misty-vault` exposes no `VK` rotation, so this crate cannot do it.
    ///
    /// # Errors
    ///
    /// [`SyncError::Crypto`] if the roster will not sign, or anything the
    /// transport or the vault reports.
    pub async fn revoke_device<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &mut Vault<VS, C>,
        roster: &Roster,
        revoked: &DeviceId,
        vault_key: &VaultKey,
    ) -> Result<Revocation> {
        let mut successor = roster.clone();
        let removed = successor.remove(revoked);
        successor.sign(self.client.identity())?;
        match self.push_roster(vault, &successor, vault_key).await? {
            RosterPush::Superseded { item_id, envelope } => {
                Ok(Revocation::RosterSuperseded { item_id, envelope })
            }
            RosterPush::Applied => {
                let epoch = vault
                    .rotate_epoch()
                    .map_err(|error| SyncError::vault("rotate the epoch", error))?;
                self.state.rotation = Some(RotationState {
                    target_epoch: epoch,
                });
                self.store.save(&self.state)?;
                Ok(Revocation::Revoked {
                    removed,
                    roster: successor,
                    epoch,
                })
            }
        }
    }

    /// Re-seals up to `limit` objects under the current epoch (SPEC §6.4).
    ///
    /// Lazy, resumable and safe to interrupt, and it needs no bookkeeping of its
    /// own to be any of those. `misty-vault` makes each object its own
    /// transaction, and every re-sealed object simply becomes pending because its
    /// envelope no longer matches the fingerprint the server confirmed — so an
    /// interrupted rotation resumes by being called again, and the pushes follow
    /// from the derived queue rather than from a list someone had to keep.
    ///
    /// Rotation re-seals rather than re-wrapping the 48-byte item key, because
    /// SPEC §2.4 binds `epoch` into the payload's AAD; §6.4 already records that
    /// correction and `misty-vault` implements it.
    ///
    /// # Errors
    ///
    /// [`SyncError::Vault`] if an object cannot be re-sealed.
    pub fn rotate_step<VS: VaultStore, C: Clock>(
        &mut self,
        vault: &mut Vault<VS, C>,
        limit: usize,
    ) -> Result<RewrapProgress> {
        let progress = vault
            .rewrap_to_current_epoch(limit)
            .map_err(|error| SyncError::vault("re-seal for the new epoch", error))?;
        if progress.remaining == 0 && self.state.rotation.is_some() {
            self.state.rotation = None;
            self.store.save(&self.state)?;
        }
        Ok(progress)
    }

    /// Forgets what the server was known to hold, forcing a full re-push and a
    /// re-read of the feed from the beginning.
    ///
    /// The repair path for a state store that was lost or restored from an old
    /// backup. It is safe but not cheap: every item is re-sent, every `409` is
    /// merged, and the vault converges on the union — which is exactly what a
    /// CRDT is for.
    ///
    /// # Errors
    ///
    /// [`SyncError::StateStore`] if the reset cannot be persisted.
    pub fn reset(&mut self) -> Result<()> {
        self.state = SyncState::new();
        self.store.save(&self.state)
    }
}

/// Whether a change carries a roster, by its authenticated `kind`.
///
/// Unverified at this point — the signature check happens in `apply_page` — but
/// `kind` is inside the AAD, so a server that lies about it produces an envelope
/// that fails to verify and is rejected there. The worst a lie achieves is
/// stopping a page early.
fn is_roster_change(change: &FeedChange) -> bool {
    change.envelope.as_deref().is_some_and(|envelope| {
        Envelope::parse(envelope)
            .is_ok_and(|parsed| parsed.header().kind == EnvelopeKind::DeviceRoster)
    })
}

/// Whether waiting and trying again could plausibly help.
fn is_retriable(error: &SyncError) -> bool {
    match error {
        SyncError::Transport { .. } => true,
        SyncError::Server { status, .. } => *status == 429 || *status >= 500,
        _ => false,
    }
}

/// What [`SyncEngine::approve_enrollment`] seals into the grant.
///
/// The vault id and the epoch are not here: the engine already knows the first
/// and reads the second off the vault, and letting a caller pass a different one
/// would be a way to seal a grant that opens nothing.
#[derive(Debug)]
pub struct GrantDetails<'a> {
    /// The vault key the joining device is being given. Borrowed; it is copied
    /// only into the sealed CBOR, by `misty-crypto`.
    pub vault_key: &'a VaultKey,
    /// Where the vault syncs, so the new device knows who to talk to.
    pub server_url: &'a str,
    /// Unix milliseconds to record in the roster entry.
    pub enrolled_at: i64,
}

/// What [`SyncEngine::approve_enrollment`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Approval {
    /// The new device is in the roster on the server, and the grant is waiting for
    /// it. Adopt `roster` and re-open the vault with it.
    Approved {
        /// The roster the server now holds.
        roster: Roster,
        /// The record that was added, for a confirmation screen.
        record: misty_crypto::identity::DeviceRecord,
    },
    /// Another device wrote a roster first, so nothing was granted. Adopt the
    /// roster the server holds with [`crate::roster::open_roster`] and try again.
    RosterSuperseded {
        /// The roster's address.
        item_id: ItemId,
        /// The sealed roster the server holds.
        envelope: Vec<u8>,
    },
}

/// What [`SyncEngine::push_roster`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RosterPush {
    /// The roster is now the server's.
    Applied,
    /// Another device wrote a roster first. Adopt it with
    /// [`crate::roster::open_roster`], re-apply the change, and push again.
    Superseded {
        /// The roster's address, for [`crate::roster::open_roster`].
        item_id: ItemId,
        /// The sealed roster the server holds.
        envelope: Vec<u8>,
    },
}

/// What [`SyncEngine::revoke_device`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Revocation {
    /// The successor roster is the server's and the epoch has been bumped.
    ///
    /// Keep using the **previous** roster locally until
    /// [`SyncEngine::rotate_step`] reports `remaining == 0`; only then re-open the
    /// vault under `roster`. See [`SyncEngine::revoke_device`].
    Revoked {
        /// Whether the device was in the roster to begin with.
        removed: bool,
        /// The roster the server now holds.
        roster: Roster,
        /// The epoch the vault is now sealing under.
        epoch: u32,
    },
    /// Another device wrote a roster first; nothing was revoked and the epoch was
    /// not bumped. Adopt the roster the server holds and try again.
    RosterSuperseded {
        /// The roster's address.
        item_id: ItemId,
        /// The sealed roster the server holds.
        envelope: Vec<u8>,
    },
}
