// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The DTO layer (SPEC §11.2): owned, non-generic, `'static` values that cross the
//! boundary by copy.
//!
//! Every type here derives `Serialize`/`Deserialize` — the one representation both
//! UniFFI and wasm-bindgen agree on — carries no borrow, generic, or `impl Trait`,
//! and holds no secret material. Read snapshots (`*View`) mirror the public accessors
//! of the live core objects; input DTOs (`*Input`) drive the mutators; report DTOs
//! carry sync/merge outcomes. Ids cross as lowercase hex (§6.1.1).

use serde::{Deserialize, Serialize};

/// The OTP algorithm family. Mirrors `misty_otp::OtpKind`; the DTO reports the *true*
/// kind the user chose, never the `Blizzard`→`Totp` wire alias (SPEC §11.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpKind {
    /// RFC 6238 time-based.
    Totp,
    /// RFC 4226 counter-based.
    Hotp,
    /// Steam's five-character alphabet.
    Steam,
    /// Mobile-OTP (mOTP), PIN-salted.
    Motp,
    /// Blizzard authenticator.
    Blizzard,
    /// Yandex, PIN-salted.
    Yandex,
}

/// The HMAC hash. Mirrors `misty_otp::HashAlg`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlg {
    /// SHA-1 (the RFC default).
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

/// Why an item or group is a tombstone. Mirrors `misty_vault` `TombstoneReason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TombstoneReason {
    /// The user deleted it.
    User,
    /// It aged out of the trash.
    TrashExpired,
}

/// A sort order for [`Facade::sorted`](crate::Facade). Mirrors `misty_vault::SortKey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortKey {
    /// The user's manual order.
    Manual,
    /// By issuer, case-insensitive.
    Issuer,
    /// Most recently used first.
    LastUsed,
    /// Most frequently used first.
    MostUsed,
    /// Most recently created first.
    Created,
}

/// An item's icon. Mirrors `misty_vault` `IconRef`; tuple variants become named
/// fields so the serde object has stable keys (SPEC §11.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IconRef {
    /// A bundled icon, by slug.
    Bundled {
        /// The bundled icon's slug.
        slug: String,
    },
    /// A custom icon stored as a blob (hex `BlobId`).
    Custom {
        /// The blob's id, lowercase hex.
        blob_id: String,
    },
    /// Rendered initials on a colour (ARGB).
    Initials {
        /// ARGB colour.
        color: u32,
    },
}

/// A merge conflict surfaced to the consumer. Mirrors `misty_vault::Conflict`
/// (which is `#[non_exhaustive]` in the core); an unrecognized future variant maps
/// to [`Conflict::Unknown`] rather than vanishing (SPEC §11.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Conflict {
    /// Two live items disagree on the secret; both were kept, `forked` is the copy.
    DivergentSecret {
        /// The item kept under the original id (hex).
        kept: String,
        /// The forked copy under a derived id (hex).
        forked: String,
    },
    /// An item's PIN diverged.
    DivergentPin {
        /// The affected item id (hex).
        item: String,
    },
    /// A conflict this build does not render specifically; the id is still surfaced.
    Unknown {
        /// The affected item id (hex).
        item: String,
    },
}

/// A read-only view of a hybrid logical clock (SPEC §4). Opaque to the consumer, who
/// MUST NOT construct or reorder one — minting an `Hlc` is the vault's job (§8.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HlcView {
    /// Wall-clock milliseconds, bounded to `[2020-01-01, 2100-01-01)` (§4.1).
    pub wall_ms: u64,
    /// Tie-break counter.
    pub counter: u16,
    /// The writing device's id (hex).
    pub device_id: String,
}

/// A tombstone view. Mirrors `misty_vault` `Tombstone`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TombstoneView {
    /// When the deletion happened, as a clock reading.
    pub hlc: HlcView,
    /// Why.
    pub reason: TombstoneReason,
}
/// An owned snapshot of one item, carrying **no** secret (SPEC §11.2). The only
/// trace of a PIN is [`has_pin`](Self::has_pin); the secret has no field at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemView {
    /// Item id, lowercase hex.
    pub id: String,
    /// The true OTP kind the user chose.
    pub kind: OtpKind,
    /// HMAC hash.
    pub algorithm: HashAlg,
    /// Number of digits.
    pub digits: u8,
    /// TOTP period, seconds.
    pub period: u16,
    /// HOTP counter.
    pub hotp_counter: u64,
    /// Whether a PIN is set (the only trace of one).
    pub has_pin: bool,
    /// Issuer label.
    pub issuer: String,
    /// Account label.
    pub account: String,
    /// Optional nickname.
    pub nickname: Option<String>,
    /// Optional note.
    pub note: Option<String>,
    /// Group ids (hex).
    pub groups: Vec<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Autofill origins (§9.1).
    pub origins: Vec<String>,
    /// Icon.
    pub icon: IconRef,
    /// Optional ARGB colour.
    pub color: Option<u32>,
    /// Favourite flag.
    pub favorite: bool,
    /// Manual sort position.
    pub manual_order: Option<i64>,
    /// Archived flag.
    pub archived: bool,
    /// Hidden flag.
    pub hidden: bool,
    /// Whether revealing a code requires re-auth (§3, §9).
    pub requires_reveal_auth: bool,
    /// Total use count (flattened G-counter).
    pub use_count: u64,
    /// Last-used time, unix ms.
    pub last_used_at: Option<i64>,
    /// Creation time, unix ms.
    pub created_at: i64,
    /// Time trashed, unix ms.
    pub trashed_at: Option<i64>,
    /// `is_live` predicate (§4).
    pub is_live: bool,
    /// `is_trashed` predicate (§4).
    pub is_trashed: bool,
    /// `is_deleted` predicate (§4).
    pub is_deleted: bool,
    /// Tombstone, if deleted.
    pub deleted: Option<TombstoneView>,
}
/// An owned snapshot of one group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupView {
    /// Group id, lowercase hex.
    pub id: String,
    /// Name.
    pub name: String,
    /// Optional ARGB colour.
    pub color: Option<u32>,
    /// Manual sort position.
    pub manual_order: Option<i64>,
    /// Creation time, unix ms.
    pub created_at: i64,
    /// `is_deleted` predicate.
    pub is_deleted: bool,
    /// Tombstone, if deleted.
    pub deleted: Option<TombstoneView>,
}

/// A generated OTP code — the accepted secret-egress exception (SPEC §11.6 rule 4).
/// Produced on demand, never cached across the boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeView {
    /// The formatted digits. A platform string for at most one period.
    pub code: String,
    /// The instant the code expires, unix ms; the host expires it here.
    pub valid_until_ms: i64,
    /// The window length, ms, so the host can render a countdown.
    pub period_ms: i64,
}

/// A roster update carried back from a sync, flattening
/// `SyncReport.roster_update: Option<(ItemId, Vec<u8>)>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterUpdateView {
    /// The roster item's id (hex).
    pub item_id: String,
    /// Opaque ciphertext — not a secret (SPEC §11.6).
    pub envelope: Vec<u8>,
}

/// The owned outcome of one sync, derived from `misty_sync::SyncReport`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReportView {
    /// Conflicts surfaced by the merge.
    pub conflicts: Vec<Conflict>,
    /// A roster update, if one arrived.
    pub roster_update: Option<RosterUpdateView>,
    /// Changes pulled from the server.
    pub pulled: u32,
    /// Changes pushed to the server.
    pub pushed: u32,
    /// Remote changes applied to the vault.
    pub applied: u32,
}

/// The owned outcome of a local merge, from a `MergeReport`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeReportView {
    /// Conflicts surfaced by the merge.
    pub conflicts: Vec<Conflict>,
    /// Items merged.
    pub merged: u32,
}
/// A nullable field an [`EditInput`] may reset to absent (SPEC §11.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClearableField {
    /// Clear the nickname.
    Nickname,
    /// Clear the note.
    Note,
    /// Clear the colour.
    Color,
    /// Clear the manual sort position.
    ManualOrder,
    /// Clear the PIN.
    Pin,
}

/// Input to add a new item (SPEC §11.2). `secret`/`pin` are owned byte buffers the
/// facade turns into `SecretBytes` and zeroizes at once (§11.6 rule 2); this type is
/// deliberately **not** `Serialize` and its `Debug` redacts the secret material.
#[derive(Deserialize)]
pub struct NewItemInput {
    /// OTP kind.
    pub kind: OtpKind,
    /// HMAC hash.
    pub algorithm: HashAlg,
    /// Digits.
    pub digits: u8,
    /// TOTP period, seconds.
    pub period: u16,
    /// HOTP counter.
    pub hotp_counter: u64,
    /// Raw secret bytes → `SecretBytes`; zeroized after use.
    pub secret: Vec<u8>,
    /// Optional PIN bytes → `SecretBytes`; zeroized after use.
    pub pin: Option<Vec<u8>>,
    /// Issuer label.
    pub issuer: String,
    /// Account label.
    pub account: String,
    /// Optional nickname.
    pub nickname: Option<String>,
    /// Optional note.
    pub note: Option<String>,
    /// Group ids (hex).
    pub groups: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Autofill origins (§9.1).
    pub origins: Vec<String>,
    /// Optional icon.
    pub icon: Option<IconRef>,
    /// Optional ARGB colour.
    pub color: Option<u32>,
    /// Favourite flag.
    pub favorite: bool,
}

impl core::fmt::Debug for NewItemInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NewItemInput")
            .field("kind", &self.kind)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("hotp_counter", &self.hotp_counter)
            .field("secret", &"[redacted]")
            .field("pin", &self.pin.as_ref().map(|_| "[redacted]"))
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("nickname", &self.nickname)
            .field("note", &self.note)
            .field("groups", &self.groups)
            .field("tags", &self.tags)
            .field("origins", &self.origins)
            .field("icon", &self.icon)
            .field("color", &self.color)
            .field("favorite", &self.favorite)
            .finish()
    }
}
/// A sparse edit (SPEC §11.2). A `None` field leaves the current value unchanged;
/// naming a field in `clear` resets a nullable field to absent (an `Option<Option<T>>`
/// would not lower cleanly through UniFFI). `pin` sets/replaces a PIN and is zeroized
/// after use; there is no in-place secret edit — that goes through `repair_secret`.
/// Not `Serialize`; `Debug` redacts the PIN.
#[derive(Default, Deserialize)]
pub struct EditInput {
    /// New issuer.
    pub issuer: Option<String>,
    /// New account.
    pub account: Option<String>,
    /// New nickname.
    pub nickname: Option<String>,
    /// New note.
    pub note: Option<String>,
    /// Replacement group set (hex ids).
    pub groups: Option<Vec<String>>,
    /// Replacement tag set.
    pub tags: Option<Vec<String>>,
    /// Replacement origin set (§9.1).
    pub origins: Option<Vec<String>>,
    /// New icon.
    pub icon: Option<IconRef>,
    /// New ARGB colour.
    pub color: Option<u32>,
    /// New manual sort position.
    pub manual_order: Option<i64>,
    /// New favourite flag.
    pub favorite: Option<bool>,
    /// New archived flag.
    pub archived: Option<bool>,
    /// New hidden flag.
    pub hidden: Option<bool>,
    /// New reveal-auth flag.
    pub requires_reveal_auth: Option<bool>,
    /// Set/replace the PIN (bytes → `SecretBytes`; zeroized after use).
    pub pin: Option<Vec<u8>>,
    /// Nullable fields to reset to absent.
    ///
    /// `#[serde(default)]` because this type's whole purpose is a *sparse* edit, and
    /// without it a caller that wants to change one field must still send `clear: []`.
    /// serde treats a missing `Option<T>` as `None` on its own, so every other field
    /// here was already optional and this one was the lone exception — a foreign caller
    /// building the object property by property got `missing field "clear"` and no hint
    /// that an empty list was what it wanted. Every other field means "leave alone" when
    /// absent; so does this one, and now it says so.
    #[serde(default)]
    pub clear: Vec<ClearableField>,
}

impl core::fmt::Debug for EditInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EditInput")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("nickname", &self.nickname)
            .field("note", &self.note)
            .field("groups", &self.groups)
            .field("tags", &self.tags)
            .field("origins", &self.origins)
            .field("icon", &self.icon)
            .field("color", &self.color)
            .field("manual_order", &self.manual_order)
            .field("favorite", &self.favorite)
            .field("archived", &self.archived)
            .field("hidden", &self.hidden)
            .field("requires_reveal_auth", &self.requires_reveal_auth)
            .field("pin", &self.pin.as_ref().map(|_| "[redacted]"))
            .field("clear", &self.clear)
            .finish()
    }
}

// --- conversions from the live core types into owned DTOs (SPEC §11.2) ---

use misty_otp::{HashAlg as CoreHashAlg, OtpKind as CoreOtpKind};
use misty_vault::{
    Conflict as CoreConflict, Group, Hlc, IconRef as CoreIconRef, Item, Tombstone,
    TombstoneReason as CoreTombstoneReason,
};

impl From<CoreOtpKind> for OtpKind {
    fn from(k: CoreOtpKind) -> Self {
        match k {
            CoreOtpKind::Totp => Self::Totp,
            CoreOtpKind::Hotp => Self::Hotp,
            CoreOtpKind::Steam => Self::Steam,
            CoreOtpKind::Motp => Self::Motp,
            CoreOtpKind::Blizzard => Self::Blizzard,
            CoreOtpKind::Yandex => Self::Yandex,
        }
    }
}

impl From<CoreHashAlg> for HashAlg {
    fn from(a: CoreHashAlg) -> Self {
        match a {
            CoreHashAlg::Sha1 => Self::Sha1,
            CoreHashAlg::Sha256 => Self::Sha256,
            CoreHashAlg::Sha512 => Self::Sha512,
        }
    }
}

impl From<CoreTombstoneReason> for TombstoneReason {
    fn from(r: CoreTombstoneReason) -> Self {
        match r {
            CoreTombstoneReason::User => Self::User,
            CoreTombstoneReason::TrashExpired => Self::TrashExpired,
        }
    }
}
impl From<&CoreIconRef> for IconRef {
    fn from(icon: &CoreIconRef) -> Self {
        match icon {
            CoreIconRef::Bundled(slug) => Self::Bundled { slug: slug.clone() },
            CoreIconRef::Custom(blob) => Self::Custom {
                blob_id: blob.to_hex(),
            },
            CoreIconRef::Initials { color } => Self::Initials { color: *color },
        }
    }
}

impl From<&CoreConflict> for Conflict {
    fn from(c: &CoreConflict) -> Self {
        match c {
            CoreConflict::DivergentSecret { kept, forked } => Self::DivergentSecret {
                kept: kept.to_hex(),
                forked: forked.to_hex(),
            },
            CoreConflict::DivergentPin { item } => Self::DivergentPin {
                item: item.to_hex(),
            },
            // `Conflict` is `#[non_exhaustive]`: surface an unknown variant, never drop it.
            _ => Self::Unknown {
                item: c.item().to_hex(),
            },
        }
    }
}

impl From<Hlc> for HlcView {
    fn from(h: Hlc) -> Self {
        Self {
            wall_ms: h.wall_ms,
            counter: h.counter,
            device_id: h.device_id.to_hex(),
        }
    }
}

impl From<&Tombstone> for TombstoneView {
    fn from(t: &Tombstone) -> Self {
        Self {
            hlc: t.hlc.into(),
            reason: t.reason.into(),
        }
    }
}
impl From<&Item> for ItemView {
    fn from(item: &Item) -> Self {
        Self {
            id: item.id().to_hex(),
            kind: item.kind().into(),
            algorithm: item.algorithm().into(),
            digits: item.digits(),
            period: item.period(),
            hotp_counter: item.hotp_counter(),
            has_pin: item.pin().is_some(),
            issuer: item.issuer().to_string(),
            account: item.account().to_string(),
            nickname: item.nickname().map(str::to_string),
            note: item.note().map(str::to_string),
            groups: item.groups().map(misty_vault::GroupId::to_hex).collect(),
            tags: item.tags().cloned().collect(),
            origins: item.origins().cloned().collect(),
            icon: item.icon().into(),
            color: item.color(),
            favorite: item.favorite(),
            manual_order: item.manual_order(),
            archived: item.archived(),
            hidden: item.hidden(),
            requires_reveal_auth: item.requires_reveal_auth(),
            use_count: item.use_count(),
            last_used_at: item.last_used_at(),
            created_at: item.created_at(),
            trashed_at: item.trashed_at(),
            is_live: item.is_live(),
            is_trashed: item.is_trashed(),
            is_deleted: item.is_deleted(),
            deleted: item.tombstone().map(TombstoneView::from),
        }
    }
}

impl From<&Group> for GroupView {
    fn from(group: &Group) -> Self {
        Self {
            id: group.id().to_hex(),
            name: group.name().to_string(),
            color: group.color(),
            manual_order: group.manual_order(),
            created_at: group.created_at(),
            is_deleted: group.is_deleted(),
            deleted: group.tombstone().map(TombstoneView::from),
        }
    }
}

impl From<OtpKind> for CoreOtpKind {
    fn from(k: OtpKind) -> Self {
        match k {
            OtpKind::Totp => Self::Totp,
            OtpKind::Hotp => Self::Hotp,
            OtpKind::Steam => Self::Steam,
            OtpKind::Motp => Self::Motp,
            OtpKind::Blizzard => Self::Blizzard,
            OtpKind::Yandex => Self::Yandex,
        }
    }
}

impl From<HashAlg> for CoreHashAlg {
    fn from(a: HashAlg) -> Self {
        match a {
            HashAlg::Sha1 => Self::Sha1,
            HashAlg::Sha256 => Self::Sha256,
            HashAlg::Sha512 => Self::Sha512,
        }
    }
}

impl From<SortKey> for misty_vault::SortKey {
    fn from(k: SortKey) -> Self {
        match k {
            SortKey::Manual => Self::Manual,
            SortKey::Issuer => Self::Issuer,
            SortKey::LastUsed => Self::LastUsed,
            SortKey::MostUsed => Self::MostUsed,
            SortKey::Created => Self::Created,
        }
    }
}
