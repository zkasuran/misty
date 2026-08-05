// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Misty's one-time-password engine.
//!
//! This crate is deliberately narrow: it turns a secret plus a moving factor
//! into a displayable code, and it parses and emits `otpauth://` URIs. It holds
//! no state, touches no clock it was not handed, does no I/O, and knows nothing
//! about vaults, storage, or sync.
//!
//! # Supported variants
//!
//! | Variant | Moving factor | Output | Reference |
//! |---|---|---|---|
//! | [`OtpKind::Hotp`] | counter | `digits` decimal digits | RFC 4226 |
//! | [`OtpKind::Totp`] | `unix_secs / period` | `digits` decimal digits | RFC 6238 |
//! | [`OtpKind::Steam`] | `unix_secs / 30` | 5 chars of `23456789BCDFGHJKMNPQRTVWXY` | no standard; see `README.md` |
//! | [`OtpKind::Motp`] | `unix_secs / 10` | 6 lowercase hex chars | Mobile-OTP |
//! | [`OtpKind::Blizzard`] | `unix_secs / 30` | 8 decimal digits | RFC 6238 with SHA-1, 8 digits |
//! | [`OtpKind::Yandex`] | `unix_secs / 30` | 8 lowercase letters | no standard; see `README.md` |
//!
//! Every variant has its own `otpauth://` type, except [`OtpKind::Blizzard`],
//! which is a preset for 8-digit SHA-1 TOTP and is *written* as `totp` so other
//! authenticators can import it. See [`OtpKind::serializes_as`].
//!
//! # Example
//!
//! ```
//! use misty_otp::{Code, OtpConfig, OtpUri, SecretBytes};
//!
//! let uri = OtpUri::parse("otpauth://totp/ACME:ada@example.com\
//!                          ?secret=JBSWY3DPEHPK3PXP&issuer=ACME&digits=6&period=30")?;
//! assert_eq!(uri.account(), "ada@example.com");
//! assert_eq!(uri.issuer(), Some("ACME"));
//!
//! // Generate the code for a specific instant instead of "now" so this doctest
//! // is deterministic.
//! let code: Code = uri.config().generate_at(1_234_567_890_000)?;
//! assert_eq!(code.value().len(), 6);
//! assert_eq!(code.remaining_ms(), Some(30_000));
//! # Ok::<(), misty_otp::OtpError>(())
//! ```
//!
//! # Security posture
//!
//! * [`SecretBytes`] renders as `[redacted]` through both [`core::fmt::Debug`]
//!   and [`core::fmt::Display`], and intentionally implements neither
//!   `Serialize` nor `Deserialize`. Persistence goes through the vault's
//!   encryption path, never through this type.
//! * [`Code`] renders as `[redacted]` through `Debug`. `Display` renders the
//!   code, because the UI has to; do not log it.
//! * [`OtpUri::to_uri`] returns a [`Zeroizing<String>`](zeroize::Zeroizing)
//!   because the URI embeds the secret. [`OtpUri`] deliberately does *not*
//!   implement `Display`, so it cannot be leaked into a log line by accident.
//! * Nothing in this crate panics on any input. Parsing hostile QR payloads is
//!   the whole point of [`OtpUri::parse`]; it returns [`OtpError`] instead of
//!   guessing, and it is a fuzz target (`fuzz/fuzz_targets/otpauth_uri.rs`).
//! * Code comparison for counter resynchronization uses
//!   [`subtle::ConstantTimeEq`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![deny(clippy::all)]

pub mod base32;
mod clock;
mod code;
mod config;
mod error;
mod generate;
mod percent;
pub mod raw;
mod secret;
mod uri;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use clock::SystemClock;
pub use clock::{Clock, FixedClock, SkewedClock};
pub use code::{Code, CodeWindow};
pub use config::{
    HashAlg, OtpConfig, OtpConfigBuilder, OtpKind, SecretEncoding, MAX_DIGITS, MAX_PERIOD,
    MAX_SECRET_LEN, MIN_DIGITS, MIN_PERIOD,
};
pub use error::{Base32Error, OtpError, Result, UriError};
pub use generate::{hotp, MAX_RESYNC_WINDOW};
pub use secret::SecretBytes;
pub use uri::{OtpUri, UriWarning, MAX_URI_LEN};
