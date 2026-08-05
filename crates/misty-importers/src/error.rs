// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed failure.
//!
//! Two levels, because an import has two levels of failure:
//!
//! * [`ImportError`] — the *file* could not be read at all: wrong format, wrong
//!   passphrase, truncated container. Nothing was imported.
//! * [`RowError`] — one *row* could not be read. The rest of the batch is
//!   unaffected, and the row is reported through
//!   [`RowOutcome::Failed`](crate::RowOutcome::Failed).
//!
//! # No error in this crate contains secret material
//!
//! Every variant names the row and the problem. None of them carries a field
//! *value*, because the value is routinely the secret, and an error message is
//! the single most likely thing to reach a log file, a bug report, or a
//! screenshot. `tests/redaction.rs` asserts this over every importer and every
//! hostile input.
//!
//! That rule is also why raw [`serde_json`] and [`quick_xml`] messages are never
//! forwarded: `serde_json` renders the offending value into its message ("invalid
//! type: string \"…\""), which would defeat the whole property. Position is kept,
//! text is dropped.

use crate::model::SourceFormat;

/// Result alias for whole-input operations.
pub type Result<T> = core::result::Result<T, ImportError>;

/// The file could not be read. Nothing was imported.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ImportError {
    /// No importer recognized the input.
    #[error("no importer recognized this file")]
    UnrecognizedFormat,

    /// The input was empty. Never a legitimate export.
    #[error("the input is empty")]
    Empty,

    /// The input was larger than [`Limits::max_input_bytes`](crate::Limits).
    #[error("input is {len} bytes, maximum is {max}")]
    InputTooLarge {
        /// Length of the offending input, in bytes.
        len: usize,
        /// The accepted maximum.
        max: usize,
    },

    /// A text format was not valid UTF-8. UTF-16 exports (a Windows habit) land
    /// here; the caller should transcode before retrying.
    #[error("input is not valid UTF-8 text")]
    NotUtf8,

    /// JSON would not parse. The message is deliberately position-only: the
    /// parser's own message quotes the offending value, which may be a secret.
    #[error("invalid JSON at line {line}, column {column}")]
    Json {
        /// One-based line of the first syntax error.
        line: usize,
        /// One-based column of the first syntax error.
        column: usize,
    },

    /// XML would not parse. Position only, for the same reason as [`Self::Json`].
    #[error("invalid XML at byte offset {offset}")]
    Xml {
        /// Byte offset of the first error.
        offset: u64,
    },

    /// A base64 field would not decode.
    #[error("field {0:?} is not valid base64")]
    Base64(&'static str),

    /// A hex field would not decode, or had the wrong length.
    #[error("field {0:?} is not valid hex of the expected length")]
    Hex(&'static str),

    /// A required top-level field was absent.
    #[error("required field {0:?} is missing")]
    MissingField(&'static str),

    /// A required top-level field had an unusable value.
    #[error("field {0:?} has an unusable value")]
    InvalidField(&'static str),

    /// The container declared a format version this crate does not implement.
    #[error("{format} export version {version} is not supported")]
    UnsupportedVersion {
        /// Which format declared it.
        format: SourceFormat,
        /// The version the file declared.
        version: u64,
    },

    /// The file is encrypted and no passphrase was supplied.
    #[error("{0} export is encrypted; a passphrase is required")]
    PassphraseRequired(SourceFormat),

    /// The file is encrypted in a way this crate deliberately does not implement,
    /// and no passphrase can change that.
    ///
    /// Two situations reach here, and both are documented per format in
    /// `README.md`: an export sealed with a key that never leaves the vendor's app
    /// (Bitwarden's account-key export), and one whose construction could not be
    /// implemented from primitives this crate is willing to carry (Ente's libsodium
    /// secretstream). The error names the plaintext export the vendor also offers,
    /// because that is the answer the user needs.
    #[error("{format} encrypted exports are not supported: {advice}")]
    EncryptedNotSupported {
        /// Which format.
        format: SourceFormat,
        /// What the user should do instead.
        advice: &'static str,
    },

    /// Authenticated decryption failed. Either the passphrase is wrong or the
    /// file has been altered; AEAD cannot tell those apart, and neither can this
    /// message.
    #[error("could not decrypt: wrong passphrase, or the file is damaged")]
    DecryptionFailed,

    /// A key-derivation parameter in the file's own header was out of the
    /// accepted range.
    ///
    /// Rejected, never clamped, for the reason SPEC 2.3 gives: clamping an
    /// attacker-supplied cost down to something survivable derives a *different*
    /// key, so the user is told their passphrase is wrong when the real problem is
    /// a malformed header. The parameter is named so the failure is diagnosable.
    #[error("key-derivation parameter {name:?} is {value}, which is outside the accepted range")]
    KdfParam {
        /// Parameter name as the vendor's header spells it.
        name: &'static str,
        /// The value the header asked for.
        value: u64,
    },

    /// A hand-rolled protobuf payload was malformed.
    #[error("malformed protobuf: {0}")]
    Protobuf(#[from] ProtobufError),

    /// The generic CSV/JSON importer needs a column mapping and could not infer
    /// one from a header row.
    #[error("a column mapping is required: no recognizable header row")]
    MappingRequired,

    /// A mapping named a column that the file does not have.
    #[error("mapped column {0:?} is not present in the input")]
    MappedColumnMissing(&'static str),

    /// The input declared or contained more rows than
    /// [`Limits::max_rows`](crate::Limits) allows.
    #[error("input has more than {max} rows")]
    TooManyRows {
        /// The accepted maximum.
        max: usize,
    },

    /// A row was wider or longer than [`Limits`](crate::Limits) allows, in a
    /// format where that makes the rest of the file unparseable.
    #[error("row {row} exceeds the {limit} limit of {max}")]
    RowTooLarge {
        /// One-based row number.
        row: usize,
        /// Which limit was hit.
        limit: &'static str,
        /// The accepted maximum.
        max: usize,
    },
}

/// One row could not be read. The rest of the batch is unaffected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RowError {
    /// A field this format requires was absent or empty.
    #[error("required field {0:?} is missing")]
    MissingField(&'static str),

    /// A field was present but unusable. The *value* is deliberately not shown.
    #[error("field {0:?} has an invalid value")]
    InvalidField(&'static str),

    /// A field was longer than [`Limits`](crate::Limits) allows.
    #[error("field {field:?} is {len} bytes, maximum is {max}")]
    FieldTooLong {
        /// Which field.
        field: &'static str,
        /// Its length in bytes.
        len: usize,
        /// The accepted maximum.
        max: usize,
    },

    /// The row was not shaped the way this format requires — an object where an
    /// array belongs, a scalar where an object belongs.
    #[error("row is not shaped like a {0} record")]
    WrongShape(SourceFormat),

    /// The OTP engine rejected the parameters. This is where an undecodable
    /// secret, an out-of-range digit count, and a malformed `otpauth://` URI
    /// arrive.
    #[error("{0}")]
    Otp(#[from] misty_otp::OtpError),

    /// A per-row protobuf sub-message was malformed.
    #[error("malformed protobuf: {0}")]
    Protobuf(#[from] ProtobufError),

    /// Text in the row was not valid UTF-8.
    #[error("field {0:?} is not valid UTF-8")]
    NotUtf8(&'static str),
}

/// Why a hand-rolled protobuf decode failed.
///
/// The decoder is deliberately ours rather than `prost`'s: `prost` needs `protoc`
/// at build time, which is a C toolchain dependency in a crate that must compile
/// to `wasm32-unknown-unknown`, and the message in question has five fields.
/// Every one of these variants exists because a hostile QR code can produce it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtobufError {
    /// The buffer ended mid-value.
    #[error("truncated at offset {offset}")]
    Truncated {
        /// Offset where more bytes were needed.
        offset: usize,
    },

    /// A varint ran past ten bytes, or its tenth byte set bits above 64.
    #[error("varint at offset {offset} does not terminate within 64 bits")]
    VarintOverflow {
        /// Offset of the first byte of the varint.
        offset: usize,
    },

    /// A length-delimited field declared more bytes than the buffer holds. This
    /// is the "4 GB declared length" case: rejected before any allocation.
    #[error("field {field} declares {len} bytes but only {remaining} remain")]
    LengthTooLarge {
        /// Field number.
        field: u32,
        /// The declared length.
        len: u64,
        /// Bytes actually left in the buffer.
        remaining: usize,
    },

    /// Field number 0, which protobuf does not allow.
    #[error("field number 0 at offset {offset}")]
    ZeroField {
        /// Offset of the offending tag.
        offset: usize,
    },

    /// Wire type 3 or 4 (deprecated groups) or 6/7 (unassigned). Skipping a
    /// group needs a matching end tag, so it cannot be skipped safely without
    /// implementing groups; refusing is the honest answer.
    #[error("unsupported wire type {wire} on field {field}")]
    UnsupportedWireType {
        /// The wire type.
        wire: u8,
        /// Field number it appeared on.
        field: u32,
    },

    /// A `string` field held bytes that are not UTF-8.
    #[error("field {field} is a string but is not valid UTF-8")]
    NotUtf8 {
        /// Field number.
        field: u32,
    },

    /// A field arrived on a wire type its declared type cannot use — a `string`
    /// sent as a varint, for instance.
    #[error("field {field} has the wrong wire type for its declared type")]
    WrongType {
        /// Field number.
        field: u32,
    },

    /// The payload nested deeper than this decoder walks. The migration payload
    /// is two levels; anything deeper is not that message.
    #[error("nested deeper than {max} levels")]
    TooDeep {
        /// The accepted maximum.
        max: u32,
    },
}
