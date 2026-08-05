// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Merging what a peer wrote, and rotating the epoch.
//!
//! # A merge is one transaction, and the model is rolled back with it
//!
//! SPEC §5: "Every merge is a single transaction. A crash mid-sync MUST leave the
//! vault at its pre-merge state." The storage half of that is
//! [`VaultStore::transaction`]. The in-memory half is this module's structure:
//! every change is merged into a **copy** of the model, every envelope is sealed
//! before the transaction opens, and the copy is adopted only after the commit
//! returns. A write that fails at row seven of nine leaves both the database and
//! the model exactly as they were, and `tests/crash_injection.rs` asserts that for
//! every failure position.
//!
//! Cloning the model costs O(n). SPEC §5 caps a vault at well under 10 000 items,
//! so that is a few megabytes on an operation that happens at sync time — and it
//! buys an exactly-correct rollback with nothing to reconstruct.
//!
//! # The server's `deleted` flag is not trusted, and is not read
//!
//! SPEC §6.1's change feed carries `deleted` alongside each change.
//! [`RemoteChange`] does not have that field. A delete in Misty is a
//! [`Tombstone`](crate::Tombstone) *inside* the signed, encrypted payload, so it is
//! something one of the user's own devices said. Honouring a bare flag from the
//! transport would hand a hostile server (threat model `A1`) the ability to erase a
//! vault it cannot read, which is the one destructive power the whole design is
//! built to deny it.
//!
//! # Deviation from SPEC §6.4: rotation cannot skip the payload
//!
//! SPEC §2.4 and §6.4 say rotation "re-wraps 48-byte item keys rather than
//! re-encrypting payloads". With the envelope as SPEC §2.4 actually specifies it,
//! that is not achievable: the payload's AEAD binds
//! `aad = Header || item_id`, and `Header` contains `epoch` at offset 6. Changing
//! `epoch` therefore invalidates the payload's Poly1305 tag as well as the wrapped
//! key's, so the payload must be re-encrypted — or at minimum re-authenticated,
//! which `misty-crypto` exposes no API for and should not.
//!
//! So [`Vault::rewrap_to_current_epoch`] decrypts and re-seals. The cost is real
//! but small: payloads are one or two 256-byte buckets, so a 1 000-item vault is
//! roughly 500 KB of writes rather than SPEC's claimed 48 KB. The *interruptible*
//! and *lazy* properties SPEC §6.4 asks for are preserved exactly — items carry
//! their own epoch, mixed epochs open fine, and each item is its own transaction.
//!
//! **This is a spec bug, not a disagreement.** Either §6.4 should say "re-encrypts
//! payloads under a fresh item key, ~500 KB per 1 000 items", or §2.4 should move
//! `epoch` out of the payload's AAD — and it should not, because an epoch that is
//! not authenticated is an epoch an attacker can relabel.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use misty_crypto::envelope::{Envelope, EnvelopeKind};
use misty_crypto::keys::EpochKey;
use misty_crypto::{derive, envelope, ItemId};
use misty_otp::Clock;

use crate::codec;
use crate::conflict::Conflict;
use crate::error::{Result, VaultError};
use crate::ids::GroupId;
use crate::merge::VaultForkIds;
use crate::model::{Group, Item};
use crate::store::{StoredEnvelope, VaultStore};
use crate::vault::Vault;

/// One entry from SPEC §6.1's change feed.
///
/// `seq` and `version` are the server's; the vault stores them verbatim so the
/// sync layer's next `If-Match` is not lost to a crash.
///
/// SPEC §6.1's feed also carries a `deleted` flag. This type deliberately does not:
/// a delete in Misty is a [`Tombstone`](crate::Tombstone) *inside* the signed,
/// encrypted payload, so honouring a bare flag from the transport would hand a
/// hostile server the power to erase a vault it cannot read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteChange {
    /// Storage key.
    pub item_id: ItemId,
    /// The server's sequence number for this change.
    pub seq: Option<i64>,
    /// The server's optimistic-concurrency token.
    pub version: Option<Vec<u8>>,
    /// The sealed envelope, exactly as it came off the wire.
    pub envelope: Vec<u8>,
}

/// What a merge did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Changes that were verified, decoded and merged.
    pub applied: usize,
    /// Changes skipped because they hold something the vault does not model — a
    /// roster or a settings blob. Their `kind` is authenticated, so this is the
    /// signer's statement about the payload, not the server's.
    pub ignored: usize,
    /// Items whose stored row changed.
    pub items_written: Vec<ItemId>,
    /// Groups whose stored row changed.
    pub groups_written: Vec<GroupId>,
    /// Divergences the merge kept both sides of.
    pub conflicts: Vec<Conflict>,
}

/// How far a lazy re-wrap has got.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RewrapProgress {
    /// Objects re-sealed under the current epoch by this call.
    pub rewrapped: usize,
    /// Objects still at an older epoch.
    pub remaining: usize,
}

/// A decoded change, before anything has been merged.
///
/// [`Item`] is boxed because it is five times the size of a [`Group`], and a batch
/// of a thousand group changes should not each carry an item-sized hole.
enum Decoded {
    Item(Box<Item>),
    Group(Box<Group>),
}

impl<S: VaultStore, C: Clock> Vault<S, C> {
    /// Verifies, decrypts, decodes and merges a batch of remote changes.
    ///
    /// Nothing is written until every change in the batch has been verified and
    /// decoded, and then everything is written in one transaction. A batch with one
    /// bad envelope in it changes nothing at all — which is the behaviour a sync
    /// layer needs, because it can then retry the whole page rather than work out
    /// which half landed.
    ///
    /// # Errors
    ///
    /// [`VaultError::Crypto`] for an envelope that does not verify, does not
    /// decrypt, or is signed by a device absent from the roster;
    /// [`VaultError::IdMismatch`] if a payload's own id is not the key it arrived
    /// under; anything the decoder rejects; anything
    /// [`ItemSet::absorb`](crate::ItemSet::absorb) reports; or a storage failure.
    pub fn merge_remote(&mut self, changes: &[RemoteChange]) -> Result<MergeReport> {
        // Phase 1 — verify and decode everything. No state is touched.
        let mut epoch_keys: BTreeMap<u32, EpochKey> = BTreeMap::new();
        let mut decoded: Vec<(&RemoteChange, Decoded)> = Vec::new();
        let mut ignored = 0usize;
        for change in changes {
            let header = *Envelope::parse(&change.envelope)?.header();
            if !matches!(header.kind, EnvelopeKind::Item | EnvelopeKind::Group) {
                ignored += 1;
                continue;
            }
            let key = match epoch_keys.entry(header.epoch) {
                Entry::Occupied(slot) => slot.into_mut(),
                Entry::Vacant(slot) => {
                    slot.insert(derive::epoch_key(&self.vault_key, header.epoch)?)
                }
            };
            let payload = envelope::open(&change.envelope, &change.item_id, key, &self.roster)?;
            if header.kind == EnvelopeKind::Item {
                let item = codec::decode_item(&payload)?;
                if item.id() != change.item_id {
                    return Err(VaultError::IdMismatch {
                        expected: change.item_id,
                        found: item.id(),
                    });
                }
                decoded.push((change, Decoded::Item(Box::new(item))));
            } else {
                let group = codec::decode_group(&payload)?;
                if group.id().as_item_id() != change.item_id {
                    return Err(VaultError::IdMismatch {
                        expected: change.item_id,
                        found: group.id().as_item_id(),
                    });
                }
                decoded.push((change, Decoded::Group(Box::new(group))));
            }
        }

        // Phase 2 — merge into copies.
        let mut items = self.items.clone();
        let mut groups = self.groups.clone();
        let mut conflicts = Vec::new();
        let mut touched_items = Vec::new();
        let mut touched_groups = Vec::new();
        {
            let fork = VaultForkIds::new(&self.vault_key);
            for (_, change) in &decoded {
                match change {
                    Decoded::Item(item) => {
                        touched_items.extend(items.absorb(
                            (**item).clone(),
                            &fork,
                            &mut conflicts,
                        )?);
                    }
                    Decoded::Group(group) => {
                        match groups.entry(group.id()) {
                            Entry::Occupied(mut slot) => slot.get_mut().merge(group)?,
                            Entry::Vacant(slot) => {
                                slot.insert((**group).clone());
                            }
                        }
                        touched_groups.push(group.id());
                    }
                }
            }
        }
        touched_items.sort_unstable();
        touched_items.dedup();
        touched_groups.sort_unstable();
        touched_groups.dedup();

        // Phase 3 — seal outside the transaction, so the transaction is short and
        // so nothing that can fail on CPU work happens while a write lock is held.
        let records =
            self.records_for(&decoded, &items, &groups, &touched_items, &touched_groups)?;
        self.store.transaction(|store| {
            for record in &records {
                store.put(record)?;
            }
            Ok(())
        })?;

        // Phase 4 — adopt. Nothing above this line changed observable state.
        //
        // The local clock is pulled up past everything that arrived, so this
        // device's next write sorts after a remote edit it has just seen. Only the
        // touched objects need looking at: nothing else changed.
        for id in &touched_items {
            if let Some(item) = items.get(id) {
                for hlc in item.every_hlc() {
                    self.hlc.observe(&hlc);
                }
            }
        }
        for id in &touched_groups {
            if let Some(group) = groups.get(id) {
                for hlc in group.every_hlc() {
                    self.hlc.observe(&hlc);
                }
            }
        }
        self.items = items;
        self.groups = groups;
        for conflict in &conflicts {
            if !self.conflicts.contains(conflict) {
                self.conflicts.push(conflict.clone());
            }
        }
        Ok(MergeReport {
            applied: decoded.len(),
            ignored,
            items_written: touched_items,
            groups_written: touched_groups,
            conflicts,
        })
    }

    /// Builds the rows for everything a merge touched.
    ///
    /// An object whose merged value is byte-for-byte the incoming one is stored as
    /// the **peer's own envelope**, with the peer's `seq` and `version`. That is not
    /// only cheaper than re-sealing: it keeps the writing device's signature on the
    /// bytes, so a later audit can still tell who wrote what, and it keeps the
    /// server's concurrency token attached to the version the server actually has.
    /// Anything the merge changed is re-sealed by this device, because the merged
    /// value is a new value that no peer has signed.
    fn records_for(
        &self,
        decoded: &[(&RemoteChange, Decoded)],
        items: &crate::merge::ItemSet,
        groups: &BTreeMap<GroupId, Group>,
        touched_items: &[ItemId],
        touched_groups: &[GroupId],
    ) -> Result<Vec<StoredEnvelope>> {
        let mut verbatim_items: BTreeMap<ItemId, &RemoteChange> = BTreeMap::new();
        let mut verbatim_groups: BTreeMap<GroupId, &RemoteChange> = BTreeMap::new();
        for (change, incoming) in decoded {
            match incoming {
                Decoded::Item(item) => {
                    if items.get(&item.id()) == Some(&**item) {
                        verbatim_items.insert(item.id(), change);
                    }
                }
                Decoded::Group(group) => {
                    if groups.get(&group.id()) == Some(&**group) {
                        verbatim_groups.insert(group.id(), change);
                    }
                }
            }
        }

        let mut records = Vec::with_capacity(touched_items.len() + touched_groups.len());
        for id in touched_items {
            let item = items.get(id).ok_or(VaultError::NoSuchItem { id: *id })?;
            records.push(match verbatim_items.get(id) {
                Some(change) => StoredEnvelope {
                    item_id: *id,
                    kind: EnvelopeKind::Item,
                    seq: change.seq,
                    version: change.version.clone(),
                    envelope: change.envelope.clone(),
                    hlc_max: item.max_hlc(),
                },
                None => self.item_record(item)?,
            });
        }
        for id in touched_groups {
            let group = groups.get(id).ok_or(VaultError::NoSuchGroup { id: *id })?;
            records.push(match verbatim_groups.get(id) {
                Some(change) => StoredEnvelope {
                    item_id: id.as_item_id(),
                    kind: EnvelopeKind::Group,
                    seq: change.seq,
                    version: change.version.clone(),
                    envelope: change.envelope.clone(),
                    hlc_max: group.max_hlc(),
                },
                None => self.group_record(group)?,
            });
        }
        Ok(records)
    }

    /// Bumps the epoch (SPEC §6.4), which is what device revocation does.
    ///
    /// Existing items keep their old epoch until
    /// [`rewrap_to_current_epoch`](Self::rewrap_to_current_epoch) reaches them.
    /// That is the lazy, interruptible rotation SPEC §6.4 asks for: every envelope
    /// names its own epoch, so a vault with items at three epochs opens normally.
    ///
    /// # Errors
    ///
    /// [`VaultError::EpochExhausted`] at [`u32::MAX`], or a storage failure.
    pub fn rotate_epoch(&mut self) -> Result<u32> {
        let next = self
            .epoch
            .checked_add(1)
            .ok_or(VaultError::EpochExhausted)?;
        self.store.transaction(|store| store.set_epoch(next))?;
        self.epoch = next;
        Ok(next)
    }

    /// Re-seals up to `limit` objects that are not yet at the current epoch.
    ///
    /// Each object is its own transaction, so an interrupted rotation leaves a
    /// consistent vault with a mix of epochs and picks up where it left off. No
    /// clock is ticked and no field changes: re-wrapping is not a logical write, so
    /// it must not affect any merge.
    ///
    /// This **decrypts and re-seals** rather than re-wrapping the 48-byte item key
    /// in place, because SPEC §2.4 binds `epoch` into the payload's AEAD as part of
    /// `aad = Header || item_id`: changing the epoch invalidates the payload tag as
    /// well as the wrapped key's. That is a spec bug in §6.4, written up at the top
    /// of this module's source.
    ///
    /// # Errors
    ///
    /// A storage failure, or [`VaultError::Crypto`] if an envelope no longer parses.
    pub fn rewrap_to_current_epoch(&mut self, limit: usize) -> Result<RewrapProgress> {
        let mut stale = Vec::new();
        for record in self.store.load_all()? {
            let header = *Envelope::parse(&record.envelope)?.header();
            if header.epoch != self.epoch {
                stale.push((record.item_id, header.kind));
            }
        }
        stale.sort_unstable_by_key(|(id, _)| *id);
        let total = stale.len();
        let mut rewrapped = 0usize;
        for (id, kind) in stale.into_iter().take(limit) {
            let record = if kind == EnvelopeKind::Item {
                let item = self.item(&id)?;
                self.item_record(item)?
            } else {
                let group = self.group(&GroupId::from_item_id(id))?;
                self.group_record(group)?
            };
            self.store.transaction(|store| store.put(&record))?;
            rewrapped += 1;
        }
        Ok(RewrapProgress {
            rewrapped,
            remaining: total.saturating_sub(rewrapped),
        })
    }
}
