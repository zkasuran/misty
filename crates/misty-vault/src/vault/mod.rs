// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The vault handle: open, read, write, merge, rotate.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use misty_crypto::envelope::{self, Envelope, EnvelopeKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::keys::{EpochKey, VaultKey};
use misty_crypto::{derive, DeviceId, ItemId};
use misty_otp::Clock;

use crate::codec;
use crate::conflict::Conflict;
use crate::error::{Result, VaultError};
use crate::hlc::{Hlc, HlcClock};
use crate::ids::GroupId;
use crate::merge::ItemSet;
use crate::model::{Group, Item};
use crate::store::{StoredEnvelope, VaultStore};

mod sync;
mod write;

pub use sync::{MergeReport, RemoteChange, RewrapProgress};

/// How a listing is ordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SortKey {
    /// The user's manual order first, then issuer. Items with no manual position
    /// sort after those that have one.
    #[default]
    Manual,
    /// Issuer, then account, then nickname — the SPEC §3.1 cluster order.
    Issuer,
    /// Most recently used first.
    LastUsed,
    /// Most used first, by the summed G-counter.
    MostUsed,
    /// Newest first.
    Created,
}

/// An unlocked vault.
///
/// Holds the decrypted model in memory, which SPEC §5 chooses deliberately: a
/// vault is under 10 000 items, and a full in-memory model after unlock is both
/// simpler than an encrypted index and leaks strictly less, because there is no
/// index whose shape answers questions about the contents.
///
/// Generic over the store (SPEC §5: SQLite cannot follow the core to the web) and
/// over the clock, because `wasm32-unknown-unknown` has no `SystemTime` and
/// because a vault that reads a global clock cannot be tested for a 30-day trash
/// sweep. [`misty_otp::Clock`] is reused rather than redefined.
pub struct Vault<S: VaultStore, C: Clock> {
    store: S,
    clock: C,
    vault_key: VaultKey,
    device: DeviceIdentity,
    roster: Roster,
    epoch: u32,
    hlc: HlcClock,
    items: ItemSet,
    groups: BTreeMap<GroupId, Group>,
    conflicts: Vec<Conflict>,
}

impl<S: VaultStore, C: Clock> Vault<S, C> {
    /// Opens and unlocks a vault.
    ///
    /// Every stored envelope is verified against `roster` and decrypted before this
    /// returns, so a tampered row is a failure to open rather than a surprise
    /// later. `roster`'s own signature is checked here too: it is the trust anchor
    /// for every other check (SPEC §6.2), and a caller who forgot to verify it
    /// would silently be trusting the server's idea of which devices exist.
    ///
    /// # Errors
    ///
    /// [`VaultError::DeviceNotInRoster`] if `device` is not a member,
    /// [`VaultError::CorruptRecord`] if a stored row does not verify, decrypt or
    /// decode, or [`VaultError::Crypto`] if the roster itself does not verify.
    pub fn open(
        store: S,
        clock: C,
        vault_key: VaultKey,
        device: DeviceIdentity,
        roster: Roster,
    ) -> Result<Self> {
        roster.verify()?;
        if roster.contains(&device.device_id()).is_none() {
            return Err(VaultError::DeviceNotInRoster {
                device: device.device_id(),
            });
        }
        let epoch = store.epoch()?;
        let mut vault = Self {
            store,
            clock,
            vault_key,
            hlc: HlcClock::new(device.device_id()),
            device,
            roster,
            epoch,
            items: ItemSet::new(),
            groups: BTreeMap::new(),
            conflicts: Vec::new(),
        };
        vault.load()?;
        Ok(vault)
    }

    /// Reads every row into the model.
    fn load(&mut self) -> Result<()> {
        // One epoch key per distinct epoch rather than per row: rotation is lazy
        // (SPEC §6.4), so a vault legitimately holds items at several epochs.
        let mut epoch_keys: BTreeMap<u32, EpochKey> = BTreeMap::new();
        for record in self.store.load_all()? {
            let id = record.item_id;
            let header = *Envelope::parse(&record.envelope)
                .map_err(|error| VaultError::corrupt(id, error.into()))?
                .header();

            // `kind` and `hlc_max` are plaintext columns, so a hostile server can
            // rewrite them. `kind` is also inside the authenticated header, and
            // `hlc_max` is recomputable from the payload, so both are cross-checked
            // below: a rewritten column cannot hide an item or reorder a sync.
            if header.kind != record.kind {
                return Err(VaultError::corrupt(
                    id,
                    VaultError::KindMismatch {
                        expected: "the authenticated envelope kind",
                        found: "the stored kind column",
                    },
                ));
            }
            if !matches!(header.kind, EnvelopeKind::Item | EnvelopeKind::Group) {
                // A roster or settings blob may share the table; the vault models
                // neither, and the header that says so is authenticated.
                continue;
            }

            let key = match epoch_keys.entry(header.epoch) {
                Entry::Occupied(slot) => slot.into_mut(),
                Entry::Vacant(slot) => {
                    slot.insert(derive::epoch_key(&self.vault_key, header.epoch)?)
                }
            };
            let payload = envelope::open(&record.envelope, &id, key, &self.roster)
                .map_err(|error| VaultError::corrupt(id, error.into()))?;

            if header.kind == EnvelopeKind::Item {
                let item =
                    codec::decode_item(&payload).map_err(|error| VaultError::corrupt(id, error))?;
                self.check_identity(id, item.id(), item.max_hlc(), record.hlc_max)?;
                for hlc in item.every_hlc() {
                    self.hlc.observe(&hlc);
                }
                self.items.insert(item)?;
            } else {
                let group = codec::decode_group(&payload)
                    .map_err(|error| VaultError::corrupt(id, error))?;
                self.check_identity(id, group.id().as_item_id(), group.max_hlc(), record.hlc_max)?;
                for hlc in group.every_hlc() {
                    self.hlc.observe(&hlc);
                }
                self.groups.insert(group.id(), group);
            }
        }
        Ok(())
    }

    /// Cross-checks a decoded payload against the plaintext columns it was stored
    /// beside.
    fn check_identity(
        &self,
        storage_key: ItemId,
        payload_id: ItemId,
        payload_hlc_max: Hlc,
        stored_hlc_max: Hlc,
    ) -> Result<()> {
        if payload_id != storage_key {
            return Err(VaultError::corrupt(
                storage_key,
                VaultError::IdMismatch {
                    expected: storage_key,
                    found: payload_id,
                },
            ));
        }
        if payload_hlc_max != stored_hlc_max {
            return Err(VaultError::corrupt(
                storage_key,
                VaultError::Storage {
                    detail: "hlc_max column does not match the authenticated payload".to_owned(),
                },
            ));
        }
        Ok(())
    }

    /// This device's id.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.hlc.device_id()
    }

    /// The current key epoch (SPEC §2.2).
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The store, for a caller that needs to inspect it. Read-only: a write that
    /// bypassed the vault would leave the in-memory model wrong.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// The clock this vault reads.
    #[must_use]
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    /// The whole item set, deleted and trashed items included. The unit SPEC §4's
    /// convergence property is stated over.
    #[must_use]
    pub const fn item_set(&self) -> &ItemSet {
        &self.items
    }

    /// Locks the vault, returning the store. Every key is zeroized as this drops.
    #[must_use]
    pub fn lock(self) -> S {
        self.store
    }

    /// One item, whatever its state.
    #[must_use]
    pub fn get(&self, id: &ItemId) -> Option<&Item> {
        self.items.get(id)
    }

    /// One item, or [`VaultError::NoSuchItem`].
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`].
    pub fn item(&self, id: &ItemId) -> Result<&Item> {
        self.items.get(id).ok_or(VaultError::NoSuchItem { id: *id })
    }

    /// Items that belong in a normal listing: not deleted, not trashed.
    pub fn list(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|item| item.is_live())
    }

    /// Items in the trash, newest first.
    #[must_use]
    pub fn trash(&self) -> Vec<&Item> {
        let mut out: Vec<&Item> = self.items.iter().filter(|item| item.is_trashed()).collect();
        out.sort_by_key(|item| core::cmp::Reverse(item.trashed_at()));
        out
    }

    /// Live items matching `query` in any user-visible text field.
    ///
    /// Runs over the decrypted model, never over an index (SPEC §5).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&Item> {
        self.list().filter(|item| item.matches(query)).collect()
    }

    /// Live items, sorted.
    #[must_use]
    pub fn sorted(&self, key: SortKey) -> Vec<&Item> {
        let mut out: Vec<&Item> = self.list().collect();
        match key {
            // `Option` sorts `None` first, and an item with no manual position
            // belongs *after* the ones the user placed by hand — hence the
            // `is_none()` first key.
            SortKey::Manual => out.sort_by(|a, b| {
                (a.manual_order().is_none(), a.manual_order())
                    .cmp(&(b.manual_order().is_none(), b.manual_order()))
                    .then_with(|| cluster_key(a).cmp(&cluster_key(b)))
            }),
            SortKey::Issuer => out.sort_by_key(|item| cluster_key(item)),
            SortKey::LastUsed => out.sort_by(|a, b| {
                b.last_used_at()
                    .cmp(&a.last_used_at())
                    .then_with(|| cluster_key(a).cmp(&cluster_key(b)))
            }),
            SortKey::MostUsed => out.sort_by(|a, b| {
                b.use_count()
                    .cmp(&a.use_count())
                    .then_with(|| cluster_key(a).cmp(&cluster_key(b)))
            }),
            SortKey::Created => out.sort_by(|a, b| {
                b.created_at()
                    .cmp(&a.created_at())
                    .then_with(|| cluster_key(a).cmp(&cluster_key(b)))
            }),
        }
        out
    }

    /// Every live item sharing an `(issuer, account)` pair, in cluster order.
    ///
    /// SPEC §3.1 requires same-issuer items to be rendered as a group with the
    /// account and nickname always visible. This is the query behind that, and it
    /// is also what [`Vault::add`](Self::add) uses to enforce the collision rule.
    #[must_use]
    pub fn same_site_cluster(&self, issuer: &str, account: &str) -> Vec<&Item> {
        let wanted = (crate::text::fold(issuer), crate::text::fold(account));
        let mut out: Vec<&Item> = self
            .items
            .iter()
            .filter(|item| item.is_live() && item.same_site_key() == wanted)
            .collect();
        out.sort_by_key(|item| cluster_key(item));
        out
    }

    /// Groups that have not been deleted, in name order.
    #[must_use]
    pub fn groups(&self) -> Vec<&Group> {
        let mut out: Vec<&Group> = self
            .groups
            .values()
            .filter(|group| !group.is_deleted())
            .collect();
        out.sort_by(|a, b| {
            (a.manual_order().is_none(), a.manual_order())
                .cmp(&(b.manual_order().is_none(), b.manual_order()))
                .then_with(|| crate::text::fold(a.name()).cmp(&crate::text::fold(b.name())))
        });
        out
    }

    /// One group, or [`VaultError::NoSuchGroup`].
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchGroup`].
    pub fn group(&self, id: &GroupId) -> Result<&Group> {
        self.groups
            .get(id)
            .ok_or(VaultError::NoSuchGroup { id: *id })
    }

    /// Conflicts a merge could not decide, deduplicated.
    #[must_use]
    pub fn conflicts(&self) -> &[Conflict] {
        &self.conflicts
    }

    /// Takes the conflict list, leaving it empty. For a UI that has shown them.
    #[must_use]
    pub fn take_conflicts(&mut self) -> Vec<Conflict> {
        core::mem::take(&mut self.conflicts)
    }

    /// The stored row for an item, for a sync layer that wants to push it.
    ///
    /// # Errors
    ///
    /// As [`VaultStore::get`].
    pub fn stored(&self, id: &ItemId) -> Result<Option<StoredEnvelope>> {
        self.store.get(id)
    }
}

/// SPEC §3.1's cluster order: issuer, then account, then nickname. Case-folded, so
/// `GitHub` and `github` are one cluster rather than two.
fn cluster_key(item: &Item) -> (String, String, String) {
    let (issuer, account) = item.same_site_key();
    (
        issuer,
        account,
        item.nickname().map(crate::text::fold).unwrap_or_default(),
    )
}

impl<S: VaultStore, C: Clock> core::fmt::Debug for Vault<S, C> {
    /// Counts, never contents. A `Debug` that printed the model would put every
    /// issuer the user has an account with into whatever log formatted it
    /// (SPEC §9).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("device", &self.device.device_id())
            .field("epoch", &self.epoch)
            .field("items", &self.items.len())
            .field("groups", &self.groups.len())
            .field("conflicts", &self.conflicts.len())
            .field("hlc", &self.hlc.last())
            .field("vault_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}
