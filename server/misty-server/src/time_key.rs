// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The server's Ed25519 signing key for `/v1/time`, and the clock it attests to.
//!
//! SPEC §6.5 exists because TOTP is only as correct as the clock: a network
//! attacker who can walk a client's effective clock can walk it into a window
//! where old codes still validate. A signed timestamp closes that, but *only* if
//! the signature cannot be replayed — so the signed payload binds a
//! client-supplied nonce.
//!
//! # Deviation from SPEC §6.1 and §6.6
//!
//! SPEC §6.1 specifies `GET /v1/time -> {unix_ms, sig}` with no nonce. As
//! written that is replayable forever: an attacker who records one response can
//! serve it back indefinitely and pin a client's clock to that instant, which is
//! precisely the attack §6.5 says the signature exists to prevent. This
//! implementation therefore **requires** `?nonce=` and signs it. The domain
//! constant `b"misty/time/v1"` is also absent from SPEC §6.6's table of
//! wire-visible constants, and belongs there.
//!
//! # What the key leaks
//!
//! Nothing about any vault. An attacker holding it can forge timestamps —
//! adversary `A2` — and can do so whether or not they also hold the database, so
//! the key is deliberately **not** stored in the database. It comes from the
//! environment, ideally from a file the process can read and nothing else can.

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Domain separator for `/v1/time` signatures. Wire-visible; belongs in
/// SPEC §6.6.
pub const TIME_SIGNING_CONTEXT: &[u8] = b"misty/time/v1";

/// Shortest accepted `/v1/time` nonce, in raw bytes.
pub const MIN_NONCE_BYTES: usize = 16;

/// Longest accepted `/v1/time` nonce, in raw bytes. A cap because the nonce is
/// signed, and signing is the one place a caller can make the server do work.
pub const MAX_NONCE_BYTES: usize = 64;

/// Why a signing key could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The value was neither 64 hex characters nor 32 bytes of base64.
    #[error("MISTY_TIME_SIGNING_KEY must be 64 hex characters or base64 for 32 bytes")]
    Malformed,
    /// The key file could not be read.
    #[error("reading MISTY_TIME_SIGNING_KEY_FILE: {0}")]
    File(#[from] std::io::Error),
    /// The OS CSPRNG failed while generating an ephemeral key.
    #[error("the operating system CSPRNG failed")]
    Entropy,
}

/// Where a key came from. Logged at startup so an operator can see, in the
/// first line of output, whether restarts will invalidate pinned keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    /// `MISTY_TIME_SIGNING_KEY`.
    Environment,
    /// `MISTY_TIME_SIGNING_KEY_FILE`.
    File,
    /// Generated at startup. Every restart produces a different key, so every
    /// client's pin breaks. Development only.
    Ephemeral,
}

/// The server's `/v1/time` signing key.
pub struct TimeKey {
    signing: SigningKey,
    origin: KeyOrigin,
}

impl TimeKey {
    /// Builds from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32], origin: KeyOrigin) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
            origin,
        }
    }

    /// Generates a throwaway key. Development only: a restart invalidates every
    /// client's pin.
    ///
    /// # Errors
    ///
    /// [`KeyError::Entropy`].
    pub fn generate() -> Result<Self, KeyError> {
        let seed = crate::token::random_array::<32>().map_err(|_| KeyError::Entropy)?;
        Ok(Self::from_seed(&seed, KeyOrigin::Ephemeral))
    }

    /// Loads from `MISTY_TIME_SIGNING_KEY`, else `MISTY_TIME_SIGNING_KEY_FILE`,
    /// else generates an ephemeral key.
    ///
    /// # Errors
    ///
    /// [`KeyError`] if a supplied value is unreadable or malformed. A malformed
    /// key is fatal rather than a fallback to generation: silently swapping in a
    /// different key would break every pinned client while the process looked
    /// healthy.
    pub fn from_env() -> Result<Self, KeyError> {
        if let Ok(text) = std::env::var("MISTY_TIME_SIGNING_KEY") {
            if !text.trim().is_empty() {
                return Ok(Self::from_seed(
                    &parse_seed(text.trim())?,
                    KeyOrigin::Environment,
                ));
            }
        }
        if let Ok(path) = std::env::var("MISTY_TIME_SIGNING_KEY_FILE") {
            if !path.trim().is_empty() {
                return Self::from_file(Path::new(path.trim()));
            }
        }
        Self::generate()
    }

    /// Loads from a file holding the seed as hex or base64, with surrounding
    /// whitespace ignored.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub fn from_file(path: &Path) -> Result<Self, KeyError> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::from_seed(&parse_seed(text.trim())?, KeyOrigin::File))
    }

    /// The public half. Operators publish this; clients pin it (SPEC §6.5).
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Where this key came from.
    #[must_use]
    pub const fn origin(&self) -> KeyOrigin {
        self.origin
    }

    /// Signs a timestamp bound to `nonce`.
    #[must_use]
    pub fn sign_time(&self, nonce: &[u8], unix_ms: i64) -> [u8; 64] {
        self.signing.sign(&time_payload(nonce, unix_ms)).to_bytes()
    }
}

impl core::fmt::Debug for TimeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TimeKey {{ origin: {:?}, public: {}, private: [redacted] }}",
            self.origin,
            hex::encode(self.public_key())
        )
    }
}

/// The exact bytes a `/v1/time` signature covers:
///
/// ```text
/// "misty/time/v1"
/// LE32(nonce_len) || nonce
/// LE64(unix_ms)
/// ```
///
/// The nonce is length-prefixed so that no `(nonce, timestamp)` pair can be
/// re-read as a different pair — without the prefix, a nonce ending in the
/// timestamp's bytes would be ambiguous.
#[must_use]
pub fn time_payload(nonce: &[u8], unix_ms: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(TIME_SIGNING_CONTEXT.len() + 4 + nonce.len() + 8);
    out.extend_from_slice(TIME_SIGNING_CONTEXT);
    out.extend_from_slice(&u32::try_from(nonce.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&unix_ms.to_le_bytes());
    out
}

/// Verifies a `/v1/time` response against a pinned public key.
///
/// This is the check the client performs. It lives here so the server's tests
/// exercise the same code path a client would, rather than a re-derivation of it.
#[must_use]
pub fn verify_time(public_key: &[u8; 32], nonce: &[u8], unix_ms: i64, signature: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(bytes) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    key.verify_strict(
        &time_payload(nonce, unix_ms),
        &Signature::from_bytes(&bytes),
    )
    .is_ok()
}

fn parse_seed(text: &str) -> Result<[u8; 32], KeyError> {
    if text.len() == 64 {
        if let Ok(bytes) = hex::decode(text) {
            if let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok(array);
            }
        }
    }
    // Both alphabets are accepted because an operator pasting a key from
    // `openssl rand -base64 32` and one pasting from a base64url tool are both
    // doing something reasonable, and the two alphabets cannot be confused: a
    // string valid in both decodes to the same bytes.
    use base64::Engine as _;
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(text.as_bytes()) {
            if let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok(array);
            }
        }
    }
    Err(KeyError::Malformed)
}

/// Milliseconds since the Unix epoch, from the system clock.
///
/// Returns `0` if the clock is before the epoch, which is the only failure mode
/// and is not worth propagating: a server whose clock reads 1969 has a bigger
/// problem than a rounding choice, and clients treat implausible offsets as
/// untrustworthy anyway (SPEC §6.5).
#[must_use]
pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_for_its_own_nonce_only() {
        let key = TimeKey::from_seed(&[3u8; 32], KeyOrigin::Ephemeral);
        let signature = key.sign_time(b"nonce-one-16byte", 1_700_000_000_000);
        assert!(verify_time(
            &key.public_key(),
            b"nonce-one-16byte",
            1_700_000_000_000,
            &signature
        ));
        assert!(!verify_time(
            &key.public_key(),
            b"nonce-two-16byte",
            1_700_000_000_000,
            &signature
        ));
    }

    #[test]
    fn a_signature_does_not_transfer_to_another_timestamp() {
        let key = TimeKey::from_seed(&[4u8; 32], KeyOrigin::Ephemeral);
        let signature = key.sign_time(b"0123456789abcdef", 1_000);
        assert!(!verify_time(
            &key.public_key(),
            b"0123456789abcdef",
            1_001,
            &signature
        ));
    }

    #[test]
    fn a_signature_does_not_verify_under_another_key() {
        let a = TimeKey::from_seed(&[5u8; 32], KeyOrigin::Ephemeral);
        let b = TimeKey::from_seed(&[6u8; 32], KeyOrigin::Ephemeral);
        let signature = a.sign_time(b"0123456789abcdef", 7);
        assert!(!verify_time(
            &b.public_key(),
            b"0123456789abcdef",
            7,
            &signature
        ));
    }

    #[test]
    fn the_payload_is_unambiguously_framed() {
        // Without the length prefix these two would sign identical bytes.
        let a = time_payload(b"ab", 0);
        let mut nonce = b"ab".to_vec();
        nonce.extend_from_slice(&0i64.to_le_bytes());
        let b = time_payload(&nonce, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn seeds_parse_from_hex_and_both_base64_alphabets() {
        use base64::Engine as _;
        let seed = [9u8; 32];
        let expected = TimeKey::from_seed(&seed, KeyOrigin::Environment).public_key();
        for text in [
            hex::encode(seed),
            base64::engine::general_purpose::STANDARD.encode(seed),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed),
        ] {
            let parsed = parse_seed(&text).unwrap_or_else(|_| panic!("failed on {text}"));
            assert_eq!(
                TimeKey::from_seed(&parsed, KeyOrigin::Environment).public_key(),
                expected
            );
        }
    }

    #[test]
    fn a_malformed_seed_is_fatal_rather_than_generating_a_new_key() {
        assert!(matches!(parse_seed("not-a-key"), Err(KeyError::Malformed)));
        assert!(matches!(parse_seed(""), Err(KeyError::Malformed)));
        assert!(matches!(
            parse_seed(&"aa".repeat(16)),
            Err(KeyError::Malformed)
        ));
    }

    #[test]
    fn debug_never_shows_the_private_half() {
        let key = TimeKey::from_seed(&[1u8; 32], KeyOrigin::File);
        let text = format!("{key:?}");
        assert!(text.contains("private: [redacted]"));
        assert!(!text.contains(&"01".repeat(32)));
    }

    #[test]
    fn the_clock_is_after_2020() {
        assert!(now_unix_ms() > 1_577_836_800_000, "clock before 2020-01-01");
    }
}
