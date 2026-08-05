// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a caller passes in to create or change an item.
//!
//! Both types exist so that a mutation is *one* call carrying *one* clock. The
//! alternative — public mutable fields, or a setter per field — would either give
//! every field its own clock (making one user edit look like fifteen concurrent
//! ones) or let a field be changed with no clock at all, which is a field that
//! loses its next merge for no reason.

use misty_otp::{HashAlg, OtpConfig, OtpKind, SecretBytes};

use crate::error::Result;
use crate::hlc::Hlc;
use crate::ids::GroupId;
use crate::limits;
use crate::model::{IconRef, Item};
use crate::text;

/// Everything needed to add an item.
///
/// `issuer` and `account` are required because SPEC §3.1's collision rule is
/// defined on them; everything else is optional.
#[derive(Clone, Debug)]
pub struct NewItem {
    pub(crate) otp: OtpConfig,
    pub(crate) issuer: String,
    pub(crate) account: String,
    pub(crate) nickname: Option<String>,
    pub(crate) note: Option<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) origins: Vec<String>,
    pub(crate) groups: Vec<GroupId>,
    pub(crate) icon: Option<IconRef>,
    pub(crate) color: Option<u32>,
    pub(crate) favorite: bool,
    pub(crate) requires_reveal_auth: bool,
}

impl NewItem {
    /// An item for `otp`, belonging to `account` at `issuer`.
    pub fn new(otp: OtpConfig, issuer: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            otp,
            issuer: issuer.into(),
            account: account.into(),
            nickname: None,
            note: None,
            tags: Vec::new(),
            origins: Vec::new(),
            groups: Vec::new(),
            icon: None,
            color: None,
            favorite: false,
            requires_reveal_auth: false,
        }
    }

    /// The distinguishing label SPEC §3.1 requires when two items share an
    /// `(issuer, account)` pair.
    #[must_use]
    pub fn nickname(mut self, nickname: impl Into<String>) -> Self {
        self.nickname = Some(nickname.into());
        self
    }

    /// A free-text note.
    #[must_use]
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(normalise_newlines(&note.into()));
        self
    }

    /// Adds a tag.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Adds an origin the extension may autofill into.
    #[must_use]
    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.origins.push(normalise_origin(&origin.into()));
        self
    }

    /// Puts the item in a group.
    #[must_use]
    pub fn group(mut self, group: GroupId) -> Self {
        self.groups.push(group);
        self
    }

    /// Sets the icon.
    #[must_use]
    pub fn icon(mut self, icon: IconRef) -> Self {
        self.icon = Some(icon);
        self
    }

    /// Sets the ARGB colour override.
    #[must_use]
    pub const fn color(mut self, color: u32) -> Self {
        self.color = Some(color);
        self
    }

    /// Pins the item.
    #[must_use]
    pub const fn favorite(mut self, favorite: bool) -> Self {
        self.favorite = favorite;
        self
    }

    /// Requires a fresh biometric or PIN check before a code is revealed.
    #[must_use]
    pub const fn requires_reveal_auth(mut self, required: bool) -> Self {
        self.requires_reveal_auth = required;
        self
    }

    /// Checks everything that can be checked before an id is drawn.
    ///
    /// # Errors
    ///
    /// Anything [`text`] rejects, or [`VaultError::TooManyElements`](crate::VaultError::TooManyElements).
    pub(crate) fn validate(&self) -> Result<()> {
        text::check_required_label("issuer", &self.issuer, limits::MAX_ISSUER_LEN)?;
        text::check_required_label("account", &self.account, limits::MAX_ACCOUNT_LEN)?;
        if let Some(nickname) = &self.nickname {
            text::check_required_label("nickname", nickname, limits::MAX_NICKNAME_LEN)?;
        }
        if let Some(note) = &self.note {
            text::check_prose("note", note, limits::MAX_NOTE_LEN)?;
        }
        if let Some(icon) = &self.icon {
            icon.validate()?;
        }
        for tag in &self.tags {
            text::check_required_label("tags", tag, limits::MAX_TAG_LEN)?;
        }
        for origin in &self.origins {
            text::check_required_label("origins", origin, limits::MAX_ORIGIN_LEN)?;
        }
        check_added_len("tags", self.tags.len())?;
        check_added_len("origins", self.origins.len())?;
        check_added_len("groups", self.groups.len())?;
        Ok(())
    }
}

fn check_added_len(field: &'static str, len: usize) -> Result<()> {
    if len > limits::MAX_SET_ENTRIES {
        return Err(crate::VaultError::TooManyElements {
            field,
            max: limits::MAX_SET_ENTRIES,
            found: len,
        });
    }
    Ok(())
}

/// `\r\n` and a lone `\r` become `\n`.
///
/// A bare carriage return is rejected everywhere in this crate (see
/// [`text`]), and pasted text routinely contains them. Normalising is friendlier
/// than refusing and safer than allowing.
fn normalise_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// Origins are compared and displayed case-insensitively, so they are stored
/// folded: `Example.COM` and `example.com` must not become two OR-Set elements
/// that a mismatch warning then treats as different sites.
fn normalise_origin(origin: &str) -> String {
    origin.trim().to_lowercase()
}

/// A set of field changes to apply as one write.
///
/// Every field set here is stamped with the *same* [`Hlc`]: one user action is one
/// write. Giving each field its own reading would make a single rename look like a
/// burst of concurrent edits, which is only visible when it goes wrong — as a
/// merge that picks a field from the wrong side.
///
/// `Option<Option<T>>` is the shape of a nullable field: `None` means "leave it
/// alone", `Some(None)` means "clear it".
#[derive(Clone, Debug, Default)]
pub struct Edit {
    issuer: Option<String>,
    account: Option<String>,
    nickname: Option<Option<String>>,
    note: Option<Option<String>>,
    icon: Option<IconRef>,
    color: Option<Option<u32>>,
    favorite: Option<bool>,
    manual_order: Option<Option<i64>>,
    archived: Option<bool>,
    hidden: Option<bool>,
    requires_reveal_auth: Option<bool>,
    kind: Option<OtpKind>,
    algorithm: Option<HashAlg>,
    digits: Option<u8>,
    period: Option<u16>,
    pin: Option<Option<SecretBytes>>,
}

impl Edit {
    /// An edit that changes nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this edit would change nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.issuer.is_none()
            && self.account.is_none()
            && self.nickname.is_none()
            && self.note.is_none()
            && self.icon.is_none()
            && self.color.is_none()
            && self.favorite.is_none()
            && self.manual_order.is_none()
            && self.archived.is_none()
            && self.hidden.is_none()
            && self.requires_reveal_auth.is_none()
            && self.kind.is_none()
            && self.algorithm.is_none()
            && self.digits.is_none()
            && self.period.is_none()
            && self.pin.is_none()
    }

    /// Sets the issuer.
    #[must_use]
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets the account.
    #[must_use]
    pub fn account(mut self, account: impl Into<String>) -> Self {
        self.account = Some(account.into());
        self
    }

    /// Sets or clears the nickname.
    #[must_use]
    pub fn nickname(mut self, nickname: Option<String>) -> Self {
        self.nickname = Some(nickname);
        self
    }

    /// Sets or clears the note. `\r\n` is normalised to `\n`.
    #[must_use]
    pub fn note(mut self, note: Option<String>) -> Self {
        self.note = Some(note.as_deref().map(normalise_newlines));
        self
    }

    /// Sets the icon.
    #[must_use]
    pub fn icon(mut self, icon: IconRef) -> Self {
        self.icon = Some(icon);
        self
    }

    /// Sets or clears the ARGB colour override.
    #[must_use]
    pub const fn color(mut self, color: Option<u32>) -> Self {
        self.color = Some(color);
        self
    }

    /// Pins or unpins the item.
    #[must_use]
    pub const fn favorite(mut self, favorite: bool) -> Self {
        self.favorite = Some(favorite);
        self
    }

    /// Sets or clears the manual sort position.
    #[must_use]
    pub const fn manual_order(mut self, order: Option<i64>) -> Self {
        self.manual_order = Some(order);
        self
    }

    /// Archives or unarchives the item.
    #[must_use]
    pub const fn archived(mut self, archived: bool) -> Self {
        self.archived = Some(archived);
        self
    }

    /// Hides or unhides the item (SPEC §1, `A10`).
    #[must_use]
    pub const fn hidden(mut self, hidden: bool) -> Self {
        self.hidden = Some(hidden);
        self
    }

    /// Sets the per-item reveal gate.
    #[must_use]
    pub const fn requires_reveal_auth(mut self, required: bool) -> Self {
        self.requires_reveal_auth = Some(required);
        self
    }

    /// Corrects the OTP construction — a mis-detected import, usually.
    #[must_use]
    pub const fn kind(mut self, kind: OtpKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Sets the HMAC hash.
    #[must_use]
    pub const fn algorithm(mut self, algorithm: HashAlg) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Sets the digit count.
    #[must_use]
    pub const fn digits(mut self, digits: u8) -> Self {
        self.digits = Some(digits);
        self
    }

    /// Sets the time step in seconds.
    #[must_use]
    pub const fn period(mut self, period: u16) -> Self {
        self.period = Some(period);
        self
    }

    /// Sets or clears the mOTP/Yandex PIN.
    #[must_use]
    pub fn pin(mut self, pin: Option<SecretBytes>) -> Self {
        self.pin = Some(pin);
        self
    }

    /// Validates every provided value, then applies all of them at `hlc`.
    ///
    /// Validation happens before the first mutation, so a rejected edit leaves the
    /// item exactly as it was: the caller does not have to reload to recover from
    /// a bad field.
    pub(crate) fn apply(self, item: &mut Item, hlc: Hlc) -> Result<()> {
        if let Some(issuer) = &self.issuer {
            text::check_required_label("issuer", issuer, limits::MAX_ISSUER_LEN)?;
        }
        if let Some(account) = &self.account {
            text::check_required_label("account", account, limits::MAX_ACCOUNT_LEN)?;
        }
        if let Some(Some(nickname)) = &self.nickname {
            text::check_required_label("nickname", nickname, limits::MAX_NICKNAME_LEN)?;
        }
        if let Some(Some(note)) = &self.note {
            text::check_prose("note", note, limits::MAX_NOTE_LEN)?;
        }
        if let Some(icon) = &self.icon {
            icon.validate()?;
        }
        // `digits` and `period` are range-checked by `misty-otp`, which owns those
        // bounds. Building a throwaway config is how this crate asks rather than
        // restating them — and restating them is how they drift.
        let mut probe = item.otp()?;
        if let Some(kind) = self.kind {
            probe = OtpConfig::builder(kind, probe.secret().clone())
                .algorithm(probe.algorithm())
                .digits(probe.digits())
                .period(probe.period())
                .counter(probe.counter())
                .pin(probe.pin().cloned())
                .build()?;
        }
        if let Some(algorithm) = self.algorithm {
            probe.set_algorithm(algorithm);
        }
        if let Some(digits) = self.digits {
            probe.set_digits(digits)?;
        }
        if let Some(period) = self.period {
            probe.set_period(period)?;
        }

        if let Some(issuer) = self.issuer {
            item.issuer.set(issuer, hlc);
        }
        if let Some(account) = self.account {
            item.account.set(account, hlc);
        }
        if let Some(nickname) = self.nickname {
            item.nickname.set(nickname, hlc);
        }
        if let Some(note) = self.note {
            item.note.set(note, hlc);
        }
        if let Some(icon) = self.icon {
            item.icon.set(icon, hlc);
        }
        if let Some(color) = self.color {
            item.color.set(color, hlc);
        }
        if let Some(favorite) = self.favorite {
            item.favorite.set(favorite, hlc);
        }
        if let Some(order) = self.manual_order {
            item.manual_order.set(order, hlc);
        }
        if let Some(archived) = self.archived {
            item.archived.set(archived, hlc);
        }
        if let Some(hidden) = self.hidden {
            item.hidden.set(hidden, hlc);
        }
        if let Some(required) = self.requires_reveal_auth {
            item.requires_reveal_auth.set(required, hlc);
        }
        if let Some(kind) = self.kind {
            item.kind.set(kind, hlc);
        }
        if let Some(algorithm) = self.algorithm {
            item.algorithm.set(algorithm, hlc);
        }
        if let Some(digits) = self.digits {
            item.digits.set(digits, hlc);
        }
        if let Some(period) = self.period {
            item.period.set(period, hlc);
        }
        if let Some(pin) = self.pin {
            item.pin.set(pin, hlc);
        }
        Ok(())
    }
}
