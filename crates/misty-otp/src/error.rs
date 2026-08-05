// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types. Every fallible operation in this crate reports through
//! [`OtpError`]; nothing panics on caller- or QR-supplied input.

use crate::config::OtpKind;

/// Convenience alias for results carrying an [`OtpError`].
pub type Result<T> = core::result::Result<T, OtpError>;

/// Everything that can go wrong building a configuration, decoding a secret,
/// generating a code, or parsing an `otpauth://` URI.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OtpError {
    /// `digits` was outside [`MIN_DIGITS`](crate::MIN_DIGITS)`..=`[`MAX_DIGITS`](crate::MAX_DIGITS).
    #[error("invalid digits {0}: must be {min}..={max}", min = crate::MIN_DIGITS, max = crate::MAX_DIGITS)]
    InvalidDigits(u64),

    /// `period` was outside [`MIN_PERIOD`](crate::MIN_PERIOD)`..=`[`MAX_PERIOD`](crate::MAX_PERIOD) seconds.
    #[error("invalid period {0}s: must be {min}..={max}", min = crate::MIN_PERIOD, max = crate::MAX_PERIOD)]
    InvalidPeriod(u64),

    /// The secret decoded to zero bytes. Never legitimate.
    #[error("secret is empty")]
    EmptySecret,

    /// The secret was longer than [`MAX_SECRET_LEN`](crate::MAX_SECRET_LEN).
    #[error("secret is {len} bytes, maximum is {max}")]
    SecretTooLong {
        /// Length of the offending secret, in bytes.
        len: usize,
        /// The accepted maximum.
        max: usize,
    },

    /// The variant needs a PIN and none was configured.
    #[error("{0} requires a PIN")]
    MissingPin(OtpKind),

    /// A base32 secret could not be decoded.
    #[error("invalid base32: {0}")]
    Base32(#[from] Base32Error),

    /// A hex secret could not be decoded. mOTP secrets are hex, not base32.
    #[error("invalid hex secret")]
    InvalidHexSecret,

    /// An `otpauth://` URI could not be parsed.
    #[error("invalid otpauth uri: {0}")]
    Uri(#[from] UriError),

    /// Timestamp arithmetic left the range representable in `u64` milliseconds.
    #[error("timestamp {0} ms is out of the representable range")]
    TimeOutOfRange(u64),

    /// The HOTP counter cannot be advanced past [`u64::MAX`].
    #[error("hotp counter {0} cannot be advanced further")]
    CounterExhausted(u64),

    /// An invariant this crate maintains internally did not hold — for example a
    /// digest shorter than the 20 bytes RFC 4226 truncation needs, which no
    /// supported hash can produce.
    ///
    /// Reported rather than asserted so that no input can reach a panic
    /// (SPEC 10.8). Seeing one is a bug in this crate.
    #[error("internal invariant violated: {0}")]
    Internal(&'static str),
}

/// Why a base32 string was rejected.
///
/// Decoding is deliberately lenient about the things real-world QR payloads get
/// wrong (lowercase, missing padding, spaces, hyphens) and strict about
/// everything else. See [`crate::base32`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Base32Error {
    /// A character that is neither in the RFC 4648 base32 alphabet nor one of
    /// the tolerated separators.
    #[error("invalid base32 character {ch:?} at offset {offset}")]
    InvalidChar {
        /// The offending character.
        ch: char,
        /// Its byte offset in the input.
        offset: usize,
    },

    /// `=` padding was followed by more data.
    #[error("base32 padding at offset {offset} is followed by data")]
    PaddingInMiddle {
        /// Byte offset of the first data character after padding started.
        offset: usize,
    },

    /// The number of significant characters cannot encode a whole number of
    /// bytes: `n % 8` must not be 1, 3, or 6.
    #[error("truncated base32: {chars} significant characters cannot encode whole bytes")]
    InvalidLength {
        /// Count of significant (non-separator, non-padding) characters.
        chars: usize,
    },

    /// Input longer than [`base32::MAX_INPUT_CHARS`](crate::base32::MAX_INPUT_CHARS).
    #[error("base32 input is {len} bytes, maximum is {max}")]
    TooLong {
        /// Length of the offending input, in bytes.
        len: usize,
        /// The accepted maximum.
        max: usize,
    },
}

/// Why an `otpauth://` URI was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UriError {
    /// Input longer than [`MAX_URI_LEN`](crate::MAX_URI_LEN).
    #[error("uri is {len} bytes, maximum is {max}")]
    TooLong {
        /// Length of the offending input, in bytes.
        len: usize,
        /// The accepted maximum.
        max: usize,
    },

    /// The URI parsed, but its canonical form would be longer than
    /// [`MAX_URI_LEN`](crate::MAX_URI_LEN) and so could not be parsed back.
    ///
    /// Percent-encoding can triple a label's length, so an input just under the
    /// cap can serialize to something over it. Rejecting here is what makes
    /// "everything that parses round-trips" true without exception — found by
    /// the fuzzer, which is the only way anyone finds this class of bug.
    #[error("canonical form would be {len} bytes, maximum is {max}")]
    CanonicalTooLong {
        /// Length the canonical form would have, in bytes.
        len: usize,
        /// The accepted maximum.
        max: usize,
    },

    /// The scheme was not `otpauth`, or `://` was missing.
    #[error("not an otpauth:// uri")]
    NotOtpauth,

    /// `otpauth-migration://` is a Google Authenticator protobuf payload. It is
    /// the importers crate's job, not this parser's.
    #[error("otpauth-migration:// is handled by the importers, not by this parser")]
    MigrationUri,

    /// The OTP type (the URI authority) is not one this crate implements.
    #[error("unknown otp type")]
    UnknownKind,

    /// A required query parameter was absent.
    #[error("missing required parameter {0:?}")]
    MissingParam(&'static str),

    /// A known query parameter appeared more than once, so its value would have
    /// to be guessed.
    #[error("parameter {0:?} appears more than once")]
    DuplicateParam(&'static str),

    /// A known query parameter had a value this crate cannot interpret. The
    /// value is deliberately left out of the message: it may be the secret.
    #[error("parameter {0:?} has an invalid value")]
    InvalidParam(&'static str),

    /// A `%` escape was truncated or contained non-hex digits.
    #[error("invalid percent-escape at offset {offset}")]
    BadPercentEscape {
        /// Byte offset of the offending `%`.
        offset: usize,
    },

    /// Percent-decoding produced bytes that are not valid UTF-8.
    #[error("percent-decoded text is not valid UTF-8")]
    NotUtf8,

    /// A control character (including NUL) appeared in decoded text. These are
    /// never legitimate in an issuer, account, or parameter value, and they are
    /// a classic terminal- and log-injection vector.
    #[error("control character U+{0:04X} is not allowed")]
    ControlChar(u32),

    /// The query string was malformed (for example, a stray `?` or an empty
    /// parameter name).
    #[error("malformed query string")]
    MalformedQuery,
}
