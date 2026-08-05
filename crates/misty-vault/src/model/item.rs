// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One vault item: SPEC §3's field list, wearing SPEC §4's merge rules.
//!
//! # Why this is not SPEC §3's struct verbatim
//!
//! SPEC §3 lists the fields as plain values — `issuer: String`, `favorite: bool`.
//! SPEC §4 then requires that "mutable fields carry a hybrid logical clock", and
//! the two cannot both be literally true. So each field here is wrapped in the
//! replicated type that implements its rule:
//!
//! | SPEC §3 field | Here | Rule |
//! |---|---|---|
//! | `issuer`, `account`, `nickname`, `note`, `icon`, `color`, `favorite`, `manual_order`, `archived`, `hidden`, `requires_reveal_auth` | [`Lww`] | last writer wins |
//! | `groups`, `tags`, `origins` | [`OrSet`] | add wins on tie |
//! | `usage` | [`UsageCounter`] | per-device max, read as sum |
//! | `last_used_at` | [`MaxWins`] | later reading wins |
//! | `created_at` | [`MinWins`] | earlier claim wins |
//! | `deleted` | [`Tombstone`] | wins only over *earlier* edits |
//!
//! `otp: OtpConfig` is decomposed rather than wrapped, because its fields do not
//! share one rule: `secret` is immutable, `counter` is max-wins, and
//! `algorithm`/`digits`/`period` are last-writer-wins.
//! [`Item::otp`] reassembles a real [`OtpConfig`] on demand, so callers still get
//! the type SPEC §3 promises and `misty-otp` stays the only definition of it.
//!
//! Every field is private. A field mutated without a clock is a field that will
//! lose its next merge for no reason, so the only way in is
//! [`Vault::update`](crate::Vault::update), which stamps one.

use misty_crypto::ItemId;
use misty_otp::{HashAlg, OtpConfig, OtpKind, SecretBytes};

use crate::conflict::Conflict;
use crate::crdt::{Lww, MaxWins, Merge, MinWins, OrSet, UsageCounter};
use crate::edit::NewItem;
use crate::error::{Result, VaultError};
use crate::hlc::Hlc;
use crate::ids::GroupId;
use crate::limits;
use crate::model::icon::IconRef;
use crate::model::tombstone::{self, Tombstone};
use crate::text;

/// One stored credential and everything the app knows about it.
///
/// Every field is wrapped in the replicated type that implements its SPEC §4 merge
/// rule; see [`crate::crdt`] for those types and `README.md` for the field-by-field
/// table. `otp: OtpConfig` is decomposed rather than wrapped, because its fields do
/// not share one rule, and [`Item::otp`] reassembles it on demand.
#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub(crate) id: ItemId,
    pub(crate) secret: SecretBytes,
    pub(crate) kind: Lww<OtpKind>,
    pub(crate) algorithm: Lww<HashAlg>,
    pub(crate) digits: Lww<u8>,
    pub(crate) period: Lww<u16>,
    pub(crate) pin: Lww<Option<SecretBytes>>,
    pub(crate) hotp_counter: MaxWins<u64>,
    pub(crate) issuer: Lww<String>,
    pub(crate) account: Lww<String>,
    pub(crate) nickname: Lww<Option<String>>,
    pub(crate) note: Lww<Option<String>>,
    pub(crate) groups: OrSet<GroupId>,
    pub(crate) tags: OrSet<String>,
    pub(crate) origins: OrSet<String>,
    pub(crate) icon: Lww<IconRef>,
    pub(crate) color: Lww<Option<u32>>,
    pub(crate) favorite: Lww<bool>,
    pub(crate) manual_order: Lww<Option<i64>>,
    pub(crate) archived: Lww<bool>,
    pub(crate) hidden: Lww<bool>,
    pub(crate) requires_reveal_auth: Lww<bool>,
    pub(crate) trashed_at: Lww<Option<i64>>,
    pub(crate) usage: UsageCounter,
    pub(crate) last_used_at: MaxWins<Option<i64>>,
    pub(crate) created_at: MinWins<i64>,
    pub(crate) deleted: Option<Tombstone>,
}

impl Item {
    /// Builds an item whose every field was written at `hlc`.
    ///
    /// `pub(crate)`: the public door is [`Vault::add`](crate::Vault::add), which
    /// also enforces SPEC §3.1's collision rule. Creating an item outside a vault
    /// would skip that check.
    ///
    /// Everything is stamped with the *same* clock, the optional fields included.
    /// Adding a tag with a second, later reading would make one `add` look like
    /// two writes, and would make the item's `max_field_hlc` — the value SPEC §4's
    /// delete rule compares against — depend on how many optional fields the
    /// caller happened to fill in.
    pub(crate) fn create(id: ItemId, new: &NewItem, hlc: Hlc, created_at_ms: i64) -> Self {
        let otp = &new.otp;
        let mut item = Self {
            id,
            secret: otp.secret().clone(),
            kind: Lww::new(otp.kind(), hlc),
            algorithm: Lww::new(otp.algorithm(), hlc),
            digits: Lww::new(otp.digits(), hlc),
            period: Lww::new(otp.period(), hlc),
            pin: Lww::new(otp.pin().cloned(), hlc),
            hotp_counter: MaxWins::new(otp.counter()),
            issuer: Lww::new(new.issuer.clone(), hlc),
            account: Lww::new(new.account.clone(), hlc),
            nickname: Lww::new(new.nickname.clone(), hlc),
            note: Lww::new(new.note.clone(), hlc),
            groups: OrSet::new(),
            tags: OrSet::new(),
            origins: OrSet::new(),
            icon: Lww::new(new.icon.clone().unwrap_or_default(), hlc),
            color: Lww::new(new.color, hlc),
            favorite: Lww::new(new.favorite, hlc),
            manual_order: Lww::new(None, hlc),
            archived: Lww::new(false, hlc),
            hidden: Lww::new(false, hlc),
            requires_reveal_auth: Lww::new(new.requires_reveal_auth, hlc),
            trashed_at: Lww::new(None, hlc),
            usage: UsageCounter::new(),
            last_used_at: MaxWins::new(None),
            created_at: MinWins::new(created_at_ms),
            deleted: None,
        };
        for tag in &new.tags {
            item.tags.add(tag.clone(), hlc);
        }
        for origin in &new.origins {
            item.origins.add(origin.clone(), hlc);
        }
        for group in &new.groups {
            item.groups.add(*group, hlc);
        }
        item
    }

    /// The storage key.
    #[must_use]
    pub const fn id(&self) -> ItemId {
        self.id
    }

    /// The shared secret. **Immutable** for the lifetime of the item: see
    /// [`Item::merge`].
    #[must_use]
    pub const fn secret(&self) -> &SecretBytes {
        &self.secret
    }

    /// The one-time-password configuration, reassembled.
    ///
    /// Note that [`OtpConfig`] normalises parameters a variant fixes — a Steam
    /// item reports five digits however many are stored — so this is the value to
    /// generate codes from, while the individual accessors report what was
    /// written.
    ///
    /// # Errors
    ///
    /// [`VaultError::Otp`] if the stored parameters no longer make a usable
    /// configuration. Unreachable for items this crate wrote or decoded, both of
    /// which validate first.
    pub fn otp(&self) -> Result<OtpConfig> {
        let mut builder = OtpConfig::builder(*self.kind.get(), self.secret.clone())
            .algorithm(*self.algorithm.get())
            .digits(*self.digits.get())
            .period(*self.period.get())
            .counter(self.hotp_counter.get());
        if let Some(pin) = self.pin.get() {
            builder = builder.pin(Some(pin.clone()));
        }
        Ok(builder.build()?)
    }

    /// Which OTP construction this item uses.
    #[must_use]
    pub const fn kind(&self) -> OtpKind {
        *self.kind.get()
    }

    /// The HMAC hash, as written. See [`Item::otp`] on normalisation.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlg {
        *self.algorithm.get()
    }

    /// The digit count, as written.
    #[must_use]
    pub const fn digits(&self) -> u8 {
        *self.digits.get()
    }

    /// The time step in seconds, as written.
    #[must_use]
    pub const fn period(&self) -> u16 {
        *self.period.get()
    }

    /// The HOTP counter. Merged max-wins, never last-writer-wins.
    #[must_use]
    pub const fn hotp_counter(&self) -> u64 {
        self.hotp_counter.get()
    }

    /// The mOTP or Yandex PIN, if one is set.
    #[must_use]
    pub fn pin(&self) -> Option<&SecretBytes> {
        self.pin.get().as_ref()
    }

    /// The issuer, for example `"GitHub"`.
    #[must_use]
    pub fn issuer(&self) -> &str {
        self.issuer.get()
    }

    /// The account, for example `"ada@example.com"`.
    #[must_use]
    pub fn account(&self) -> &str {
        self.account.get()
    }

    /// The user's disambiguating label, if set. SPEC §3.1 requires one whenever
    /// two items share an `(issuer, account)` pair.
    #[must_use]
    pub fn nickname(&self) -> Option<&str> {
        self.nickname.get().as_deref()
    }

    /// The user's note, if any.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.get().as_deref()
    }

    /// Groups this item belongs to, in id order.
    pub fn groups(&self) -> impl Iterator<Item = &GroupId> {
        self.groups.iter()
    }

    /// Tags, in sort order.
    pub fn tags(&self) -> impl Iterator<Item = &String> {
        self.tags.iter()
    }

    /// Origins the extension may autofill into, in sort order (SPEC §1, `A11`).
    pub fn origins(&self) -> impl Iterator<Item = &String> {
        self.origins.iter()
    }

    /// Whether `tag` is currently on this item.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(&tag.to_owned())
    }

    /// Whether `origin` is currently on this item.
    #[must_use]
    pub fn has_origin(&self, origin: &str) -> bool {
        self.origins.contains(&origin.to_owned())
    }

    /// Whether the item is currently in `group`.
    #[must_use]
    pub fn in_group(&self, group: &GroupId) -> bool {
        self.groups.contains(group)
    }

    /// Retained tag entries, removed ones included. The count the storage limit
    /// applies to.
    #[must_use]
    pub fn tags_stored_len(&self) -> usize {
        self.tags.stored_len()
    }

    /// Retained origin entries, removed ones included.
    #[must_use]
    pub fn origins_stored_len(&self) -> usize {
        self.origins.stored_len()
    }

    /// Retained group entries, removed ones included.
    #[must_use]
    pub fn groups_stored_len(&self) -> usize {
        self.groups.stored_len()
    }

    /// The icon.
    #[must_use]
    pub const fn icon(&self) -> &IconRef {
        self.icon.get()
    }

    /// The ARGB colour override, if set.
    #[must_use]
    pub const fn color(&self) -> Option<u32> {
        *self.color.get()
    }

    /// Whether the user pinned this item.
    #[must_use]
    pub const fn favorite(&self) -> bool {
        *self.favorite.get()
    }

    /// The user's manual sort position, if set.
    #[must_use]
    pub const fn manual_order(&self) -> Option<i64> {
        *self.manual_order.get()
    }

    /// Whether the item is archived.
    #[must_use]
    pub const fn archived(&self) -> bool {
        *self.archived.get()
    }

    /// Whether the item is hidden from the default list (SPEC §1, `A10`).
    #[must_use]
    pub const fn hidden(&self) -> bool {
        *self.hidden.get()
    }

    /// Whether revealing a code needs a fresh biometric or PIN check
    /// (SPEC §1, `A4`).
    #[must_use]
    pub const fn requires_reveal_auth(&self) -> bool {
        *self.requires_reveal_auth.get()
    }

    /// The per-device usage counter.
    #[must_use]
    pub const fn usage(&self) -> &UsageCounter {
        &self.usage
    }

    /// Total uses across every device.
    #[must_use]
    pub fn use_count(&self) -> u64 {
        self.usage.total()
    }

    /// When a code was last generated, in Unix milliseconds.
    #[must_use]
    pub const fn last_used_at(&self) -> Option<i64> {
        self.last_used_at.get()
    }

    /// When the item was created, in Unix milliseconds.
    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at.get()
    }

    /// When the item was moved to the trash, if it is there.
    #[must_use]
    pub const fn trashed_at(&self) -> Option<i64> {
        *self.trashed_at.get()
    }

    /// The tombstone, if one was ever written. Present does **not** mean deleted:
    /// see [`Item::is_deleted`].
    #[must_use]
    pub fn tombstone(&self) -> Option<&Tombstone> {
        self.deleted.as_ref()
    }

    /// The greatest clock across every field *edit*, ignoring the tombstone.
    ///
    /// This is the value SPEC §4's delete rule compares against. `usage`,
    /// `hotp_counter` and `last_used_at` carry no clock and are deliberately not
    /// represented here: generating a code from an item is not an edit, and using
    /// a token on a device that had not yet seen the delete must not resurrect
    /// it.
    #[must_use]
    pub fn max_field_hlc(&self) -> Hlc {
        // Written as a fold over an array so that adding a field to the struct
        // and forgetting it here is a visible omission rather than a subtle one.
        let registers = [
            self.kind.hlc(),
            self.algorithm.hlc(),
            self.digits.hlc(),
            self.period.hlc(),
            self.pin.hlc(),
            self.issuer.hlc(),
            self.account.hlc(),
            self.nickname.hlc(),
            self.note.hlc(),
            self.icon.hlc(),
            self.color.hlc(),
            self.favorite.hlc(),
            self.manual_order.hlc(),
            self.archived.hlc(),
            self.hidden.hlc(),
            self.requires_reveal_auth.hlc(),
            self.trashed_at.hlc(),
        ];
        let from_registers = registers.into_iter().fold(self.issuer.hlc(), Hlc::max);
        [
            self.groups.max_hlc(),
            self.tags.max_hlc(),
            self.origins.max_hlc(),
        ]
        .into_iter()
        .flatten()
        .fold(from_registers, Hlc::max)
    }

    /// The greatest clock anywhere in the item, tombstone included.
    ///
    /// Stored alongside the envelope as `hlc_max` (SPEC §5) so a sync layer can
    /// order changes without decrypting anything.
    #[must_use]
    pub fn max_hlc(&self) -> Hlc {
        match self.deleted {
            Some(stone) => self.max_field_hlc().max(stone.hlc),
            None => self.max_field_hlc(),
        }
    }

    /// Whether the item is deleted: a tombstone exists **and** no field was
    /// edited after it (SPEC §4).
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        tombstone::tombstone_wins(self.deleted.as_ref(), self.max_field_hlc())
    }

    /// Whether the item is in the trash, awaiting either a restore or the 30-day
    /// sweep.
    #[must_use]
    pub fn is_trashed(&self) -> bool {
        self.trashed_at().is_some() && !self.is_deleted()
    }

    /// Whether the item belongs in a normal listing: not deleted, not trashed.
    #[must_use]
    pub fn is_live(&self) -> bool {
        !self.is_deleted() && !self.is_trashed()
    }

    /// Whether the trash retention window has expired, so the sweep should write
    /// a tombstone (SPEC §4: 30 days).
    #[must_use]
    pub fn trash_expired(&self, now_ms: i64) -> bool {
        self.trashed_at()
            .is_some_and(|at| now_ms.saturating_sub(at) >= limits::TRASH_RETENTION_MS)
    }

    /// The `(issuer, account)` pair SPEC §3.1's collision rule is defined on,
    /// case-folded and trimmed.
    #[must_use]
    pub fn same_site_key(&self) -> (String, String) {
        (text::fold(self.issuer()), text::fold(self.account()))
    }

    /// Whether `needle` appears in any user-visible text field.
    ///
    /// Search runs over the decrypted in-memory model, never over an index
    /// (SPEC §5): an encrypted index that answers "does this vault contain
    /// `github`" leaks exactly the metadata threat model `A1` exists to protect.
    #[must_use]
    pub fn matches(&self, needle: &str) -> bool {
        let needle = text::fold(needle);
        if needle.is_empty() {
            return true;
        }
        let mut haystacks: Vec<&str> = vec![self.issuer(), self.account()];
        haystacks.extend(self.nickname());
        haystacks.extend(self.note());
        haystacks.extend(self.tags().map(String::as_str));
        haystacks.extend(self.origins().map(String::as_str));
        haystacks
            .into_iter()
            .any(|field| text::fold(field).contains(&needle))
    }

    /// Checks every invariant a decoded item must satisfy.
    ///
    /// Run on every payload that arrives from storage or from a peer, before the
    /// item joins the model. An authenticated payload is still not a trusted one:
    /// it may have been written by an older build, a buggy client, or an importer
    /// that did not validate.
    ///
    /// # Errors
    ///
    /// [`VaultError::StringTooLong`], [`VaultError::DisallowedCharacter`],
    /// [`VaultError::EmptyField`], [`VaultError::TooManyElements`],
    /// [`VaultError::HlcOutOfRange`], or [`VaultError::Otp`] if the OTP
    /// parameters do not describe a usable token.
    pub fn validate(&self) -> Result<()> {
        text::check_required_label("issuer", self.issuer(), limits::MAX_ISSUER_LEN)?;
        text::check_required_label("account", self.account(), limits::MAX_ACCOUNT_LEN)?;
        if let Some(nickname) = self.nickname() {
            text::check_required_label("nickname", nickname, limits::MAX_NICKNAME_LEN)?;
        }
        if let Some(note) = self.note() {
            text::check_prose("note", note, limits::MAX_NOTE_LEN)?;
        }
        self.icon.get().validate()?;

        check_set_len("tags", self.tags.stored_len())?;
        check_set_len("origins", self.origins.stored_len())?;
        check_set_len("groups", self.groups.stored_len())?;
        for tag in self.tags.entries().map(|(tag, _)| tag) {
            text::check_required_label("tags", tag, limits::MAX_TAG_LEN)?;
        }
        for origin in self.origins.entries().map(|(origin, _)| origin) {
            text::check_required_label("origins", origin, limits::MAX_ORIGIN_LEN)?;
        }
        if self.usage.len() > limits::MAX_USAGE_DEVICES {
            return Err(VaultError::TooManyElements {
                field: "usage",
                max: limits::MAX_USAGE_DEVICES,
                found: self.usage.len(),
            });
        }

        // Every clock in the item, including the ones inside the sets and the
        // tombstone. `Hlc::new` is the single definition of the window.
        for hlc in self.every_hlc() {
            Hlc::new(hlc.wall_ms, hlc.counter, hlc.device_id)?;
        }

        // The OTP parameters have to describe a token that can actually generate
        // a code: `digits` in 1..=10, `period` in 1..=3600, a non-empty secret
        // within `MAX_SECRET_LEN`. `misty-otp` owns those bounds, so ask it
        // rather than restating them.
        self.otp()?;
        Ok(())
    }

    /// Every clock in the item, for validation and for the clock catch-up on
    /// open.
    pub(crate) fn every_hlc(&self) -> Vec<Hlc> {
        let mut out = vec![
            self.kind.hlc(),
            self.algorithm.hlc(),
            self.digits.hlc(),
            self.period.hlc(),
            self.pin.hlc(),
            self.issuer.hlc(),
            self.account.hlc(),
            self.nickname.hlc(),
            self.note.hlc(),
            self.icon.hlc(),
            self.color.hlc(),
            self.favorite.hlc(),
            self.manual_order.hlc(),
            self.archived.hlc(),
            self.hidden.hlc(),
            self.requires_reveal_auth.hlc(),
            self.trashed_at.hlc(),
        ];
        for (_, entry) in self.groups.entries() {
            out.push(entry.added);
            out.extend(entry.removed);
        }
        for (_, entry) in self.tags.entries() {
            out.push(entry.added);
            out.extend(entry.removed);
        }
        for (_, entry) in self.origins.entries() {
            out.push(entry.added);
            out.extend(entry.removed);
        }
        if let Some(stone) = self.deleted {
            out.push(stone.hlc);
        }
        out
    }
}

fn check_set_len(field: &'static str, found: usize) -> Result<()> {
    if found > limits::MAX_DECODED_SET_ENTRIES {
        return Err(VaultError::TooManyElements {
            field,
            max: limits::MAX_DECODED_SET_ENTRIES,
            found,
        });
    }
    Ok(())
}

impl Item {
    /// Joins another version of this same item into `self` (SPEC §4).
    ///
    /// # Preconditions
    ///
    /// Both sides must have the same `id` and the same `secret`. Divergent
    /// secrets are **not** resolved here, because there is no correct way to
    /// resolve them: see [`ItemSet::absorb`](crate::ItemSet::absorb), which keeps
    /// both credentials as separate items. This function refuses rather than
    /// guessing, so no caller can accidentally reach the guessing path.
    ///
    /// # Conflicts
    ///
    /// `conflicts` is appended to, never read. It is a *report*, not state: it
    /// takes no part in the byte-identical convergence property, and it is not
    /// deduplicated here — merging the same remote twice reports the same
    /// divergence twice, and [`Vault`](crate::Vault) deduplicates before
    /// surfacing it.
    ///
    /// # Errors
    ///
    /// [`VaultError::IdMismatch`] or [`VaultError::SecretIsImmutable`] if the
    /// preconditions do not hold, or [`VaultError::ClockCollision`] if two
    /// versions of one field carry identical clocks and different values.
    pub fn merge(&mut self, remote: &Self, conflicts: &mut Vec<Conflict>) -> Result<()> {
        if self.id != remote.id {
            return Err(VaultError::IdMismatch {
                expected: self.id,
                found: remote.id,
            });
        }
        if self.secret != remote.secret {
            return Err(VaultError::SecretIsImmutable { item: self.id });
        }

        // A divergent PIN is reported before it is resolved. Unlike the secret it
        // is resolved — see the crate README on why — but the user still has to be
        // told, because the losing side may be the one that actually works.
        if self.pin.get() != remote.pin.get() {
            conflicts.push(Conflict::DivergentPin { item: self.id });
        }

        // Last-writer-wins fields (SPEC §4, row 1). `otp.kind` and `otp.pin` are
        // here rather than in the immutable row: see the crate README.
        self.kind.merge(&remote.kind, "otp.kind")?;
        self.algorithm.merge(&remote.algorithm, "otp.algorithm")?;
        self.digits.merge(&remote.digits, "otp.digits")?;
        self.period.merge(&remote.period, "otp.period")?;
        self.pin.merge(&remote.pin, "otp.pin")?;
        self.issuer.merge(&remote.issuer, "issuer")?;
        self.account.merge(&remote.account, "account")?;
        self.nickname.merge(&remote.nickname, "nickname")?;
        self.note.merge(&remote.note, "note")?;
        self.icon.merge(&remote.icon, "icon")?;
        self.color.merge(&remote.color, "color")?;
        self.favorite.merge(&remote.favorite, "favorite")?;
        self.manual_order
            .merge(&remote.manual_order, "manual_order")?;
        self.archived.merge(&remote.archived, "archived")?;
        self.hidden.merge(&remote.hidden, "hidden")?;
        self.requires_reveal_auth
            .merge(&remote.requires_reveal_auth, "requires_reveal_auth")?;
        self.trashed_at.merge(&remote.trashed_at, "trashed_at")?;

        // Max-wins: a lower HOTP counter would replay a consumed code and
        // desynchronise the issuer (SPEC §4, row 2).
        self.hotp_counter
            .merge(&remote.hotp_counter, "otp.counter")?;
        self.last_used_at
            .merge(&remote.last_used_at, "last_used_at")?;

        // Min-wins: the earliest creation claim is the only one that can be true.
        self.created_at.merge(&remote.created_at, "created_at")?;

        // Per-device G-counter, read as the sum (SPEC §4, row 3).
        self.usage.merge(&remote.usage, "usage")?;

        // OR-Sets: add wins on tie (SPEC §4, row 4).
        self.groups.merge(&remote.groups, "groups")?;
        self.tags.merge(&remote.tags, "tags")?;
        self.origins.merge(&remote.origins, "origins")?;

        // The tombstone is kept whichever way this goes; whether it *wins* is
        // decided by `is_deleted` against the merged field clocks (SPEC §4,
        // row 5).
        tombstone::merge_tombstone(&mut self.deleted, &remote.deleted);
        Ok(())
    }

    /// Replaces the item's id. Used only when a credential divergence forks an
    /// item onto a derived id.
    pub(crate) fn rebind(&mut self, id: ItemId) {
        self.id = id;
    }
}
