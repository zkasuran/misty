// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed errors.
//!
//! Three rules hold for every variant:
//!
//! 1. **No secret material.** No secret byte, no PIN, no note text, no tag. An
//!    error naming a field names the *field*, never its contents. A vault error
//!    is logged; a vault's contents are not (SPEC §9).
//! 2. **Distinguishable failures.** A caller must be able to tell "this
//!    `(issuer, account)` needs a nickname" from "this is the same credential
//!    twice" without matching on strings, because SPEC §3.1 requires two
//!    different pieces of UI for those two cases.
//! 3. **No panics on this path.** Everything reachable from a decoded payload
//!    returns one of these.

use misty_crypto::{DeviceId, ItemId};

use crate::ids::GroupId;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, VaultError>;

/// Everything that can go wrong in `misty-vault`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// A cryptographic operation failed: a bad signature, an unknown signer, a
    /// tampered envelope, a wrong epoch key.
    #[error(transparent)]
    Crypto(#[from] misty_crypto::Error),

    /// The OTP model rejected a parameter — an out-of-range digit count, an
    /// empty secret.
    #[error(transparent)]
    Otp(#[from] misty_otp::OtpError),

    /// CBOR encoding or decoding failed.
    #[error("CBOR {operation} failed: {detail}")]
    Cbor {
        /// `"encode"` or `"decode"`.
        operation: &'static str,
        /// Underlying reason, as reported by `ciborium`.
        detail: String,
    },

    /// A payload declared a `format_version` this build does not implement.
    /// Forward compatibility is deliberately not attempted: a newer writer may
    /// have changed what the following fields mean.
    #[error("{context}: unsupported format_version {found}, this build implements {supported}")]
    UnsupportedFormatVersion {
        /// What was being decoded.
        context: &'static str,
        /// The version found in the payload.
        found: u8,
        /// The version this build implements.
        supported: u8,
    },

    /// A payload was larger than this crate will decode.
    #[error("{context}: payload of {len} bytes exceeds the {max} byte limit")]
    PayloadTooLarge {
        /// What was being decoded.
        context: &'static str,
        /// Length offered.
        len: usize,
        /// Hard limit.
        max: usize,
    },

    /// A text field was longer than its limit. Carries the field name and the
    /// limit, never the text.
    #[error("field {field} is {found} bytes, longer than the {max} byte limit")]
    StringTooLong {
        /// Which field.
        field: &'static str,
        /// Hard limit, in bytes of UTF-8.
        max: usize,
        /// Length offered.
        found: usize,
    },

    /// A text field carried a character that MUST NOT appear in a label: a
    /// control character, an embedded NUL, a bidirectional override, a
    /// zero-width character, or a byte-order mark.
    ///
    /// Non-ASCII text is **not** an error. `日本銀行` is a real bank
    /// (SPEC §7.2); only adversarial text is rejected. The offending character
    /// is reported as a code point, which is not secret in the way the field's
    /// contents are, and only its position is given.
    #[error("field {field} contains a disallowed character U+{code:04X} at position {index}")]
    DisallowedCharacter {
        /// Which field.
        field: &'static str,
        /// Unicode scalar value of the offending character.
        code: u32,
        /// Zero-based character position.
        index: usize,
    },

    /// A field that must not be blank was blank or whitespace only.
    #[error("field {field} must not be empty")]
    EmptyField {
        /// Which field.
        field: &'static str,
    },

    /// A collection exceeded its element limit.
    #[error("field {field} holds {found} entries, more than the {max} allowed")]
    TooManyElements {
        /// Which field.
        field: &'static str,
        /// Hard limit.
        max: usize,
        /// Count offered.
        found: usize,
    },

    /// An OR-Set or usage counter named the same key twice. Rejected rather
    /// than resolved: the two entries carry different clocks, so "the last one
    /// wins" would make decoding depend on encoder order.
    #[error("field {field} names the same key twice")]
    DuplicateKey {
        /// Which field.
        field: &'static str,
    },

    /// A payload used a wire value this build does not know for an enumerated
    /// field. Rejected rather than defaulted: silently reading an unknown OTP
    /// construction as `Totp` would generate wrong codes and look like a broken
    /// service.
    #[error("field {field} has unknown wire value {found}")]
    UnknownEnumValue {
        /// Which field.
        field: &'static str,
        /// The byte found.
        found: u8,
    },

    /// An [`Hlc`](crate::Hlc) fell outside the window the format allows. The
    /// window is absolute, not relative to the reader's clock, so every device
    /// rejects exactly the same values and merge stays independent of wall time.
    #[error("hybrid logical clock wall_ms {wall_ms} is outside the window {min}..{max}")]
    HlcOutOfRange {
        /// The value found.
        wall_ms: u64,
        /// Inclusive lower bound.
        min: u64,
        /// Exclusive upper bound.
        max: u64,
    },

    /// The local clock has no room left to order another write: it is already at
    /// the top of the [`Hlc`](crate::Hlc) window with a saturated counter.
    #[error("the hybrid logical clock is exhausted")]
    ClockExhausted,

    /// Two versions of one field carry byte-identical clocks but different
    /// values.
    ///
    /// Unreachable for writes produced by this crate: an [`Hlc`](crate::Hlc)
    /// names a device, a millisecond and a per-millisecond counter, and
    /// [`HlcClock`](crate::HlcClock) never issues the same triple twice. It is
    /// surfaced instead of resolved because "pick one" would make merge
    /// non-commutative, and a writer that reuses a clock is a bug that must be
    /// found rather than absorbed.
    #[error("field {field} has two different values under identical clocks")]
    ClockCollision {
        /// Which field.
        field: &'static str,
    },

    /// A merge was handed a payload whose embedded id is not the storage key it
    /// arrived under. The envelope binds `item_id` in its AAD, so this means the
    /// *payload* disagrees with itself, not that the envelope was relocated.
    #[error("payload declares id {found} but was stored under {expected}")]
    IdMismatch {
        /// The storage key.
        expected: ItemId,
        /// The id inside the payload.
        found: ItemId,
    },

    /// A merge was handed two objects of different kinds under one id.
    #[error("{expected} and {found} cannot be merged")]
    KindMismatch {
        /// What the local object is.
        expected: &'static str,
        /// What arrived.
        found: &'static str,
    },

    /// [`Item::merge`](crate::Item::merge) was handed two items with different
    /// secrets.
    ///
    /// `otp.secret` is immutable (SPEC §4), and the two sides are two real
    /// credentials rather than two versions of one. Resolving that belongs to
    /// [`ItemSet::absorb`](crate::ItemSet::absorb), which keeps both; this error
    /// exists so no caller can reach a code path that would have to pick one.
    #[error("item {item}: otp.secret is immutable and the two versions disagree")]
    SecretIsImmutable {
        /// The item whose secret diverged.
        item: ItemId,
    },

    /// No item with that id.
    #[error("no item {id}")]
    NoSuchItem {
        /// The id looked up.
        id: ItemId,
    },

    /// No group with that id.
    #[error("no group {id}")]
    NoSuchGroup {
        /// The id looked up.
        id: GroupId,
    },

    /// An id that must be new was already taken.
    #[error("item {id} already exists")]
    ItemExists {
        /// The colliding id.
        id: ItemId,
    },

    /// SPEC §3.1: adding this item would leave two items with the same
    /// `(issuer, account)` and no way for a human to tell them apart. Set a
    /// distinguishing `nickname` and retry — this is not a duplicate, and both
    /// items are meant to be kept.
    #[error("an item with this issuer and account already exists ({existing}); it needs a distinguishing nickname")]
    AmbiguousAccount {
        /// The item already present.
        existing: ItemId,
    },

    /// SPEC §3.1: `(issuer, account, secret)` all match an existing item, so
    /// this is the same credential twice. Drop it, or fold its metadata into the
    /// existing item with
    /// [`Vault::merge_duplicate`](crate::Vault::merge_duplicate).
    #[error("this is the same credential as item {existing}")]
    DuplicateAccount {
        /// The item already present.
        existing: ItemId,
    },

    /// A merge forked further than [`MAX_MERGE_STEPS`](crate::limits::MAX_MERGE_STEPS).
    #[error("merge did not settle within {max} steps")]
    MergeDidNotSettle {
        /// The bound.
        max: usize,
    },

    /// A stored record did not survive the trip back: a tampered envelope, a
    /// truncated blob, a payload this build cannot decode.
    #[error("stored record {item_id} is corrupt")]
    CorruptRecord {
        /// Which record.
        item_id: ItemId,
        /// The underlying failure.
        #[source]
        source: Box<VaultError>,
    },

    /// The vault was opened with a device that the roster does not list. A
    /// device that cannot be trusted to sign cannot be trusted to write
    /// (SPEC §6.2).
    #[error("device {device} is not in the roster")]
    DeviceNotInRoster {
        /// The device that tried to open the vault.
        device: DeviceId,
    },

    /// The storage backend failed.
    #[error("storage error: {detail}")]
    Storage {
        /// What the backend reported. Never contains item contents: envelopes
        /// are opaque to the backend.
        detail: String,
    },

    /// A transaction was committed or rolled back without being opened.
    #[error("no transaction is open")]
    NoTransaction,

    /// The on-disk schema is newer than this build. Migrations are forward-only
    /// (SPEC §5), so an older binary MUST refuse rather than guess.
    #[error("database schema version {found} is newer than the {supported} this build implements")]
    SchemaTooNew {
        /// Version found in the file.
        found: u32,
        /// Version this build implements.
        supported: u32,
    },

    /// The epoch counter is at [`u32::MAX`]. Rotating again would wrap, and two
    /// different epochs sharing a number would derive one key for two generations
    /// of wrapped item keys.
    #[error("the epoch counter is exhausted")]
    EpochExhausted,
}

impl VaultError {
    /// Wraps a decode failure as [`VaultError::CorruptRecord`].
    pub(crate) fn corrupt(item_id: ItemId, source: Self) -> Self {
        Self::CorruptRecord {
            item_id,
            source: Box::new(source),
        }
    }
}
