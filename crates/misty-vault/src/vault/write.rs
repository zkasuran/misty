// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local writes: add, edit, use, trash, restore, purge.
//!
//! Every one of them follows the same three steps, in this order:
//!
//! 1. mutate a **clone** of the object,
//! 2. encode, seal and store it inside a transaction,
//! 3. only then adopt the clone into the in-memory model.
//!
//! Step 3 after step 2 is what makes a failed write invisible. If storage refuses
//! — a full disk, a locked database, a payload over the limit — the model is
//! untouched, and the caller's next read sees exactly what it saw before. The
//! alternative, mutating in place and rolling back on error, has to reconstruct the
//! old value from somewhere, and the only place it exists is the row that just
//! failed to be overwritten.

use misty_crypto::envelope::{self, EnvelopeKind};
use misty_crypto::{derive, ItemId};
use misty_otp::{Clock, SecretBytes};

use crate::codec;
use crate::edit::{Edit, NewItem};
use crate::error::{Result, VaultError};
use crate::hlc::Hlc;
use crate::ids::GroupId;
use crate::limits;
use crate::model::{Group, Item, Tombstone, TombstoneReason};
use crate::store::{StoredEnvelope, VaultStore};
use crate::text;
use crate::vault::Vault;

impl<S: VaultStore, C: Clock> Vault<S, C> {
    /// The clock, as milliseconds since the Unix epoch, saturating into `i64`.
    fn now_ms(&self) -> i64 {
        i64::try_from(self.clock.now_unix_ms()).unwrap_or(i64::MAX)
    }

    /// The next clock reading for a local write.
    fn tick(&mut self) -> Result<Hlc> {
        let now = self.clock.now_unix_ms();
        self.hlc.tick(now)
    }

    fn epoch_key(&self, epoch: u32) -> Result<misty_crypto::keys::EpochKey> {
        Ok(derive::epoch_key(&self.vault_key, epoch)?)
    }

    /// Seals an item under `epoch`, signed by this device.
    fn seal_item(&self, item: &Item, epoch: u32) -> Result<Vec<u8>> {
        let payload = codec::encode_item(item)?;
        Ok(envelope::seal(
            EnvelopeKind::Item,
            epoch,
            &item.id(),
            &payload,
            &self.epoch_key(epoch)?,
            &self.device,
        )?)
    }

    fn seal_group(&self, group: &Group, epoch: u32) -> Result<Vec<u8>> {
        let payload = codec::encode_group(group)?;
        Ok(envelope::seal(
            EnvelopeKind::Group,
            epoch,
            &group.id().as_item_id(),
            &payload,
            &self.epoch_key(epoch)?,
            &self.device,
        )?)
    }

    /// Builds the row for an item, carrying over the server's `seq` and `version`.
    ///
    /// Carrying them over matters: they are the server's view of this item, and
    /// SPEC §6.1 uses `version` as the `If-Match` for the next push. Resetting them
    /// on every local edit would turn every push into a 409 and a re-fetch.
    pub(crate) fn item_record(&self, item: &Item) -> Result<StoredEnvelope> {
        let previous = self.store.get(&item.id())?;
        Ok(StoredEnvelope {
            item_id: item.id(),
            kind: EnvelopeKind::Item,
            seq: previous.as_ref().and_then(|row| row.seq),
            version: previous.and_then(|row| row.version),
            envelope: self.seal_item(item, self.epoch)?,
            hlc_max: item.max_hlc(),
        })
    }

    pub(crate) fn group_record(&self, group: &Group) -> Result<StoredEnvelope> {
        let previous = self.store.get(&group.id().as_item_id())?;
        Ok(StoredEnvelope {
            item_id: group.id().as_item_id(),
            kind: EnvelopeKind::Group,
            seq: previous.as_ref().and_then(|row| row.seq),
            version: previous.and_then(|row| row.version),
            envelope: self.seal_group(group, self.epoch)?,
            hlc_max: group.max_hlc(),
        })
    }

    /// Persists an item, then adopts it. See the [module docs](self) for the order.
    fn commit_item(&mut self, item: Item) -> Result<()> {
        let record = self.item_record(&item)?;
        self.store.transaction(|store| store.put(&record))?;
        self.items.replace(item);
        Ok(())
    }

    fn commit_group(&mut self, group: Group) -> Result<()> {
        let record = self.group_record(&group)?;
        self.store.transaction(|store| store.put(&record))?;
        self.groups.insert(group.id(), group);
        Ok(())
    }

    /// Clones an item, hands it to `change` with a fresh clock, and commits it.
    fn mutate_item(
        &mut self,
        id: &ItemId,
        change: impl FnOnce(&mut Item, Hlc) -> Result<()>,
    ) -> Result<()> {
        let mut item = self.item(id)?.clone();
        let hlc = self.tick()?;
        change(&mut item, hlc)?;
        self.commit_item(item)
    }

    /// Adds an item, enforcing SPEC §3.1's same-site rule.
    ///
    /// # Errors
    ///
    /// * [`VaultError::DuplicateAccount`] — `(issuer, account, secret)` all match
    ///   an existing item, so this is the same credential twice. Drop it, or fold
    ///   its metadata in with [`merge_duplicate`](Self::merge_duplicate).
    /// * [`VaultError::AmbiguousAccount`] — `(issuer, account)` match but the
    ///   secret does not, and the nickname would not tell the two apart. These are
    ///   two real accounts and both are meant to be kept: set a distinguishing
    ///   nickname and retry.
    /// * anything the text rules or the storage path reject.
    pub fn add(&mut self, new: NewItem) -> Result<ItemId> {
        new.validate()?;
        self.check_same_site(&new)?;
        let id = ItemId::generate()?;
        let created_at = self.now_ms();
        let hlc = self.tick()?;
        let item = Item::create(id, &new, hlc, created_at);
        self.commit_item(item)?;
        Ok(id)
    }

    /// SPEC §3.1, rules 1 and 5.
    ///
    /// Nicknames inside one `(issuer, account)` cluster must be pairwise distinct,
    /// with "no nickname" counting as one of the values. That is the weakest rule
    /// that guarantees a human can name which item they mean — and it is why
    /// adding a second unlabelled `ada@example.com` at GitHub fails while adding a
    /// second one called "work" succeeds.
    fn check_same_site(&self, new: &NewItem) -> Result<()> {
        let cluster = self.same_site_cluster(&new.issuer, &new.account);
        if let Some(existing) = cluster
            .iter()
            .find(|item| item.secret() == new.otp.secret())
        {
            return Err(VaultError::DuplicateAccount {
                existing: existing.id(),
            });
        }
        let wanted = new.nickname.as_deref().map(text::fold);
        if let Some(existing) = cluster
            .iter()
            .find(|item| item.nickname().map(text::fold) == wanted)
        {
            return Err(VaultError::AmbiguousAccount {
                existing: existing.id(),
            });
        }
        Ok(())
    }

    /// Folds a genuine duplicate's metadata into the item it duplicates.
    ///
    /// The other half of SPEC §3.1 rule 5: identical `(issuer, account, secret)` is
    /// one credential, so "offer to merge" means adding the incoming item's tags,
    /// origins and groups to the existing item rather than creating a second row.
    /// Its `nickname`, `note`, `icon` and `color` are applied only where they were
    /// set, so a re-import cannot blank a label the user typed.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], or [`VaultError::SecretIsImmutable`] if the two
    /// secrets differ — in which case this is not a duplicate and both items must
    /// be kept.
    pub fn merge_duplicate(&mut self, existing: &ItemId, new: NewItem) -> Result<()> {
        new.validate()?;
        if self.item(existing)?.secret() != new.otp.secret() {
            return Err(VaultError::SecretIsImmutable { item: *existing });
        }
        self.mutate_item(existing, |item, hlc| {
            for tag in new.tags {
                item.tags.add(tag, hlc);
            }
            for origin in new.origins {
                item.origins.add(origin, hlc);
            }
            for group in new.groups {
                item.groups.add(group, hlc);
            }
            if let Some(nickname) = new.nickname {
                item.nickname.set(Some(nickname), hlc);
            }
            if let Some(note) = new.note {
                item.note.set(Some(note), hlc);
            }
            if let Some(icon) = new.icon {
                item.icon.set(icon, hlc);
            }
            if let Some(color) = new.color {
                item.color.set(Some(color), hlc);
            }
            // Max-wins, like every other write to this field: a re-import that
            // carries an older counter must not roll a HOTP token back.
            item.hotp_counter.set(new.otp.counter());
            Ok(())
        })
    }

    /// Applies an [`Edit`] as one write.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], anything [`Edit`] validates, or
    /// [`VaultError::AmbiguousAccount`] if renaming would leave two items in one
    /// cluster that a human could not tell apart.
    pub fn update(&mut self, id: &ItemId, edit: Edit) -> Result<()> {
        let mut candidate = self.item(id)?.clone();
        let hlc = self.tick()?;
        edit.apply(&mut candidate, hlc)?;
        // The rename case: SPEC §3.1's rule is about the *state* of the vault, not
        // only about `add`. Renaming one item onto another's `(issuer, account)`
        // produces exactly the ambiguity rule 1 exists to prevent.
        let ambiguous = self
            .same_site_cluster(candidate.issuer(), candidate.account())
            .into_iter()
            .find(|other| {
                other.id() != candidate.id()
                    && other.nickname().map(text::fold) == candidate.nickname().map(text::fold)
            })
            .map(Item::id);
        if let Some(existing) = ambiguous {
            return Err(VaultError::AmbiguousAccount { existing });
        }
        self.commit_item(candidate)
    }

    /// Adds a tag.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], [`VaultError::TooManyElements`] past
    /// [`MAX_SET_ENTRIES`](crate::limits::MAX_SET_ENTRIES), or anything the text
    /// rules reject.
    pub fn add_tag(&mut self, id: &ItemId, tag: impl Into<String>) -> Result<()> {
        let tag = tag.into();
        text::check_required_label("tags", &tag, limits::MAX_TAG_LEN)?;
        self.mutate_item(id, |item, hlc| {
            check_room("tags", item.tags_stored_len(), item.has_tag(&tag))?;
            item.tags.add(tag, hlc);
            Ok(())
        })
    }

    /// Removes a tag. A no-op if the item never had it.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], or a storage failure.
    pub fn remove_tag(&mut self, id: &ItemId, tag: &str) -> Result<()> {
        let tag = tag.to_owned();
        self.mutate_item(id, |item, hlc| {
            item.tags.remove(&tag, hlc);
            Ok(())
        })
    }

    /// Adds an origin the extension may autofill into (SPEC §1, `A11`).
    ///
    /// Folded to lowercase, so one site cannot become two OR-Set elements that the
    /// mismatch warning then treats as different.
    ///
    /// # Errors
    ///
    /// As [`add_tag`](Self::add_tag).
    pub fn add_origin(&mut self, id: &ItemId, origin: &str) -> Result<()> {
        let origin = origin.trim().to_lowercase();
        text::check_required_label("origins", &origin, limits::MAX_ORIGIN_LEN)?;
        self.mutate_item(id, |item, hlc| {
            check_room(
                "origins",
                item.origins_stored_len(),
                item.has_origin(&origin),
            )?;
            item.origins.add(origin, hlc);
            Ok(())
        })
    }

    /// Removes an origin.
    ///
    /// # Errors
    ///
    /// As [`remove_tag`](Self::remove_tag).
    pub fn remove_origin(&mut self, id: &ItemId, origin: &str) -> Result<()> {
        let origin = origin.trim().to_lowercase();
        self.mutate_item(id, |item, hlc| {
            item.origins.remove(&origin, hlc);
            Ok(())
        })
    }

    /// Puts an item in a group.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], [`VaultError::NoSuchGroup`], or
    /// [`VaultError::TooManyElements`].
    pub fn add_to_group(&mut self, id: &ItemId, group: GroupId) -> Result<()> {
        self.group(&group)?;
        self.mutate_item(id, |item, hlc| {
            check_room("groups", item.groups_stored_len(), item.in_group(&group))?;
            item.groups.add(group, hlc);
            Ok(())
        })
    }

    /// Takes an item out of a group.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`].
    pub fn remove_from_group(&mut self, id: &ItemId, group: GroupId) -> Result<()> {
        self.mutate_item(id, |item, hlc| {
            item.groups.remove(&group, hlc);
            Ok(())
        })
    }

    /// Records that a code was generated: bumps this device's usage count and
    /// `last_used_at`.
    ///
    /// Neither field carries an [`Hlc`], and that is deliberate — see
    /// [`crate::crdt`]. Using a token is not an edit, so this cannot resurrect a
    /// deleted item.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], or a storage failure.
    pub fn record_use(&mut self, id: &ItemId) -> Result<()> {
        let now = self.now_ms();
        let device = self.device_id();
        let mut item = self.item(id)?.clone();
        item.usage.increment(device, 1);
        item.last_used_at.set(Some(now));
        self.commit_item(item)
    }

    /// Advances a HOTP counter and returns the new value.
    ///
    /// Max-wins on merge, so this can only ever move forward: a lower counter would
    /// replay a code the issuer has already consumed (SPEC §4).
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], or a storage failure.
    pub fn advance_hotp_counter(&mut self, id: &ItemId) -> Result<u64> {
        let mut item = self.item(id)?.clone();
        let next = item.hotp_counter().saturating_add(1);
        item.hotp_counter.set(next);
        self.commit_item(item)?;
        Ok(next)
    }

    /// Sets a HOTP counter forward, for a resynchronisation flow.
    ///
    /// Refuses to move backwards rather than failing: the register is max-wins, and
    /// a caller that asks for a lower value gets the value that is actually stored.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], or a storage failure.
    pub fn set_hotp_counter(&mut self, id: &ItemId, counter: u64) -> Result<u64> {
        let mut item = self.item(id)?.clone();
        item.hotp_counter.set(counter);
        let settled = item.hotp_counter();
        self.commit_item(item)?;
        Ok(settled)
    }

    /// Replaces an item's secret, for an import repair.
    ///
    /// This is the **only** way a secret ever changes, and it is deliberately its
    /// own method rather than a field on [`Edit`]: `otp.secret` is immutable as far
    /// as merge is concerned (SPEC §4), so changing it locally is not an edit but a
    /// statement that the stored credential was wrong. The realistic case is a
    /// mis-imported token that the user re-scans from the issuer's QR code.
    ///
    /// A peer that has not seen the repair still holds the old secret, and the next
    /// merge will therefore keep **both** as separate items and raise
    /// [`Conflict::DivergentSecret`](crate::Conflict::DivergentSecret). That is the
    /// designed outcome, not a bug: one of the two secrets works and this crate has
    /// no way to know which.
    ///
    /// No clock is ticked, because no clocked field changes.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], [`VaultError::Otp`] if the secret is empty or
    /// over `MAX_SECRET_LEN`, or a storage failure.
    pub fn repair_secret(&mut self, id: &ItemId, secret: SecretBytes) -> Result<()> {
        let mut item = self.item(id)?.clone();
        // Ask `misty-otp` whether the secret is usable rather than restating its
        // bounds here.
        let mut probe = item.otp()?;
        probe.set_secret(secret.clone())?;
        item.secret = secret;
        self.commit_item(item)
    }

    /// Moves an item to the trash.
    ///
    /// SPEC §4: deleted items go to a trash with 30 days of retention *before* the
    /// tombstone is written, so a delete that propagates over sync is recoverable
    /// on every device rather than only on the one that made it.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], or a storage failure.
    pub fn trash_item(&mut self, id: &ItemId) -> Result<()> {
        let now = self.now_ms();
        self.mutate_item(id, |item, hlc| {
            item.trashed_at.set(Some(now), hlc);
            Ok(())
        })
    }

    /// Takes an item back out of the trash.
    ///
    /// Works even after a tombstone was written, because a restore *is* a later
    /// edit and SPEC §4 says a delete must not beat one. That is not a loophole:
    /// it is the property that makes "undelete" possible at all in a system where
    /// the delete may already have reached three other devices.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], or a storage failure.
    pub fn restore_item(&mut self, id: &ItemId) -> Result<()> {
        self.mutate_item(id, |item, hlc| {
            item.trashed_at.set(None, hlc);
            Ok(())
        })
    }

    /// Writes a tombstone now, skipping the trash.
    ///
    /// The row stays until [`purge_tombstones`](Self::purge_tombstones) collects
    /// it: a delete has to be a *value* to be replicable, and dropping the row
    /// immediately would let any peer that still holds the item put it straight
    /// back.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchItem`], or a storage failure.
    pub fn delete_item(&mut self, id: &ItemId) -> Result<()> {
        self.mutate_item(id, |item, hlc| {
            item.deleted = Some(Tombstone::new(hlc, TombstoneReason::User));
            Ok(())
        })
    }

    /// Writes tombstones for every item whose trash retention has expired.
    ///
    /// Returns the ids swept. Each is its own transaction: this is housekeeping,
    /// and a failure part way through should leave the items it already handled
    /// swept rather than redoing them.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn sweep_trash(&mut self) -> Result<Vec<ItemId>> {
        let now = self.now_ms();
        let expired: Vec<ItemId> = self
            .items
            .iter()
            .filter(|item| item.is_trashed() && item.trash_expired(now))
            .map(Item::id)
            .collect();
        for id in &expired {
            self.mutate_item(id, |item, hlc| {
                item.deleted = Some(Tombstone::new(hlc, TombstoneReason::TrashExpired));
                Ok(())
            })?;
        }
        Ok(expired)
    }

    /// Drops rows whose tombstone is older than SPEC §4's 90-day retention.
    ///
    /// Returns the ids purged.
    ///
    /// # A purge is not replicated, and cannot be
    ///
    /// This is the one operation in the crate that is not a CRDT join, because
    /// "forget that this ever existed" has no representation that survives a merge.
    /// A peer that has been offline for more than 90 days and still holds the item
    /// will reintroduce it on its next sync. That is the standard tombstone
    /// garbage-collection trade-off, and the 90-day window is what makes it
    /// acceptable: it is far longer than any plausible offline period, and the cost
    /// of being wrong is a resurrected item the user can delete again rather than a
    /// lost one.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn purge_tombstones(&mut self) -> Result<Vec<ItemId>> {
        let now = self.clock.now_unix_ms();
        let purgeable: Vec<ItemId> = self
            .items
            .iter()
            .filter(|item| {
                item.is_deleted()
                    && item.tombstone().is_some_and(|stone| {
                        stone.is_purgeable(now, limits::TOMBSTONE_RETENTION_MS)
                    })
            })
            .map(Item::id)
            .collect();
        let groups: Vec<GroupId> = self
            .groups
            .values()
            .filter(|group| {
                group.is_deleted()
                    && group.tombstone().is_some_and(|stone| {
                        stone.is_purgeable(now, limits::TOMBSTONE_RETENTION_MS)
                    })
            })
            .map(Group::id)
            .collect();
        self.store.transaction(|store| {
            for id in &purgeable {
                store.remove(id)?;
            }
            for id in &groups {
                store.remove(&id.as_item_id())?;
            }
            Ok(())
        })?;
        for id in &purgeable {
            self.items.purge(id);
        }
        for id in &groups {
            self.groups.remove(id);
        }
        Ok(purgeable)
    }

    /// Creates a group.
    ///
    /// # Errors
    ///
    /// Anything the text rules reject, or a storage failure.
    pub fn add_group(&mut self, name: impl Into<String>) -> Result<GroupId> {
        let name = name.into();
        text::check_required_label("group.name", &name, limits::MAX_GROUP_NAME_LEN)?;
        let id = GroupId::generate()?;
        let created_at = self.now_ms();
        let hlc = self.tick()?;
        self.commit_group(Group::create(id, name, hlc, created_at))?;
        Ok(id)
    }

    /// Renames a group, or sets its colour or manual position.
    ///
    /// `None` leaves a field alone. A group's name is a single last-writer-wins
    /// register, so two devices renaming concurrently converge on one name rather
    /// than splitting the group in two.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchGroup`], anything the text rules reject, or a storage
    /// failure.
    pub fn update_group(
        &mut self,
        id: &GroupId,
        name: Option<String>,
        color: Option<Option<u32>>,
        manual_order: Option<Option<i64>>,
    ) -> Result<()> {
        if let Some(name) = &name {
            text::check_required_label("group.name", name, limits::MAX_GROUP_NAME_LEN)?;
        }
        let mut group = self.group(id)?.clone();
        let hlc = self.tick()?;
        if let Some(name) = name {
            group.name.set(name, hlc);
        }
        if let Some(color) = color {
            group.color.set(color, hlc);
        }
        if let Some(order) = manual_order {
            group.manual_order.set(order, hlc);
        }
        self.commit_group(group)
    }

    /// Deletes a group.
    ///
    /// Members are not touched: membership lives in each item's OR-Set, so an item
    /// referring to a deleted group simply has one fewer group. Rewriting every
    /// member would be a multi-item write with no cross-device transaction, and a
    /// concurrent edit on another device would leave it half applied.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoSuchGroup`], or a storage failure.
    pub fn delete_group(&mut self, id: &GroupId) -> Result<()> {
        let mut group = self.group(id)?.clone();
        let hlc = self.tick()?;
        group.deleted = Some(Tombstone::new(hlc, TombstoneReason::User));
        self.commit_group(group)
    }
}

/// Refuses to grow an OR-Set past the mutation limit.
///
/// `already_present` short-circuits it: re-adding a tag the item already has has to
/// keep working on a full item, because it changes nothing.
fn check_room(field: &'static str, stored: usize, already_present: bool) -> Result<()> {
    if already_present || stored < limits::MAX_SET_ENTRIES {
        return Ok(());
    }
    Err(VaultError::TooManyElements {
        field,
        max: limits::MAX_SET_ENTRIES,
        found: stored,
    })
}
