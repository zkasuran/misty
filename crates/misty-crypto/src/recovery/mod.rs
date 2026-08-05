// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The Recovery Kit (SPEC §2.6).
//!
//! One 32-byte [`RecoveryKey`], three interchangeable renderings of exactly the
//! same bytes:
//!
//! * **Words** — 24 BIP-39 English words with an 8-bit SHA-256 checksum. See
//!   [`words`].
//! * **Compact** — Crockford Base32 of `RK || CRC32(RK)`, grouped in 8s. See
//!   [`compact`].
//! * **QR** — `misty-recovery:v1:` followed by the compact form.
//!
//! All three decode back to identical bytes; `recovery_encodings_agree` in
//! `tests/recovery_kit.rs` asserts it over random keys.
//!
//! `recovery_blob = wrap(RK, VK, "misty/recovery/v1")` is stored locally and MAY
//! be stored on the server. It is inert without the kit: see
//! [`wrap_vault_key`].
//!
//! # What the UI must do with this
//!
//! Show the kit exactly once, require the user to confirm they stored it by
//! re-entering three random words, and never render it again afterwards. Losing
//! the kit with no enrolled device means permanent loss, and SPEC §2.6 requires
//! that to be stated in plain language at setup — not in a footnote.

mod crc32;

pub mod compact;
pub mod words;

#[cfg(test)]
mod tests;

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead;
use crate::keys::{RecoveryKey, VaultKey, KEY_LEN};
use crate::{random, Error, Result};

pub use compact::{from_compact, to_compact, COMPACT_CHAR_COUNT, COMPACT_GROUP_LEN};
pub use words::{
    from_words, nearest_words, suggest_word_repairs, to_words, wordlist, WordRepair,
    RECOVERY_WORD_COUNT, WORDLIST_LEN,
};

/// Prefix of the QR payload.
pub const RECOVERY_QR_PREFIX: &str = "misty-recovery:v1:";

/// AEAD context (AAD) for `recovery_blob`.
pub const RECOVERY_WRAP_CONTEXT: &[u8] = b"misty/recovery/v1";

/// Length of `recovery_blob`: 24-byte nonce, 32-byte key, 16-byte tag.
pub const RECOVERY_BLOB_LEN: usize = aead::NONCE_LEN + KEY_LEN + aead::TAG_LEN;

/// The Recovery Kit, in all three renderings.
///
/// `Debug` renders `[redacted]`, and every field is zeroized on drop. The
/// strings are the recovery key in a human-readable form: treat them exactly as
/// you would the key.
pub struct RecoveryKit {
    words: Vec<&'static str>,
    compact: String,
    qr: String,
}

impl RecoveryKit {
    /// The 24 words, in order.
    #[must_use]
    pub fn words(&self) -> &[&'static str] {
        &self.words
    }

    /// The compact code, grouped in 8s.
    #[must_use]
    pub fn compact(&self) -> &str {
        &self.compact
    }

    /// The QR payload.
    #[must_use]
    pub fn qr(&self) -> &str {
        &self.qr
    }
}

impl Zeroize for RecoveryKit {
    fn zeroize(&mut self) {
        // The words are `&'static str` into the embedded wordlist — there is
        // nothing to wipe in them, and wiping the wordlist would be a bug. The
        // secret is the *order*, so the vector itself is cleared.
        self.words.clear();
        self.compact.zeroize();
        self.qr.zeroize();
    }
}

// Hand-written rather than derived: `#[derive(ZeroizeOnDrop)]` zeroizes every
// field, and `Vec<&'static str>` cannot be zeroized (nor should it be).
impl Drop for RecoveryKit {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RecoveryKit {}

impl fmt::Debug for RecoveryKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKit([redacted])")
    }
}

impl fmt::Display for RecoveryKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Renders a recovery key in all three encodings.
#[must_use]
pub fn kit(key: &RecoveryKey) -> RecoveryKit {
    let compact = to_compact(key);
    RecoveryKit {
        words: to_words(key),
        qr: to_qr_from_compact(&compact),
        compact,
    }
}

/// The QR payload for a recovery key.
#[must_use]
pub fn to_qr(key: &RecoveryKey) -> String {
    to_qr_from_compact(&to_compact(key))
}

fn to_qr_from_compact(compact: &str) -> String {
    let mut out = String::with_capacity(RECOVERY_QR_PREFIX.len() + compact.len());
    out.push_str(RECOVERY_QR_PREFIX);
    out.push_str(compact);
    out
}

/// Parses a scanned QR payload.
///
/// The prefix match is case-insensitive because some scanners upper-case
/// alphanumeric QR content.
///
/// # Errors
///
/// [`Error::BadQrPrefix`], plus anything [`from_compact`] rejects.
pub fn from_qr(payload: &str) -> Result<RecoveryKey> {
    let trimmed = payload.trim();
    let prefix_len = RECOVERY_QR_PREFIX.len();
    let (prefix, rest) = trimmed
        .split_at_checked(prefix_len)
        .ok_or(Error::BadQrPrefix)?;
    if !prefix.eq_ignore_ascii_case(RECOVERY_QR_PREFIX) {
        return Err(Error::BadQrPrefix);
    }
    from_compact(rest)
}

/// `recovery_blob = wrap(RK, VK, "misty/recovery/v1")`, laid out as
/// `nonce[24] || ciphertext[48]`.
///
/// The nonce is stored because it must be: it is fresh random per wrap, as SPEC
/// §2.1 requires, and there is nowhere else to keep it. The blob is inert
/// without the kit, which is why it MAY be stored on the server.
///
/// # Errors
///
/// [`Error::Random`] if the CSPRNG fails.
pub fn wrap_vault_key(recovery_key: &RecoveryKey, vault_key: &VaultKey) -> Result<Vec<u8>> {
    wrap_vault_key_with(
        recovery_key,
        vault_key,
        random::array::<{ aead::NONCE_LEN }>()?,
    )
}

pub(crate) fn wrap_vault_key_with(
    recovery_key: &RecoveryKey,
    vault_key: &VaultKey,
    nonce: [u8; aead::NONCE_LEN],
) -> Result<Vec<u8>> {
    let ciphertext = aead::encrypt(
        recovery_key.expose_secret(),
        &nonce,
        RECOVERY_WRAP_CONTEXT,
        vault_key.expose_secret(),
    )?;
    let mut blob = Vec::with_capacity(RECOVERY_BLOB_LEN);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Recovers the vault key from `recovery_blob`.
///
/// # Errors
///
/// [`Error::RecoveryBlobMalformed`] if the blob is not
/// [`RECOVERY_BLOB_LEN`] bytes, or [`Error::RecoveryUnwrapFailed`] if it does
/// not authenticate under `recovery_key`.
pub fn unwrap_vault_key(recovery_key: &RecoveryKey, blob: &[u8]) -> Result<VaultKey> {
    if blob.len() != RECOVERY_BLOB_LEN {
        return Err(Error::RecoveryBlobMalformed);
    }
    let (nonce_bytes, ciphertext) = blob
        .split_at_checked(aead::NONCE_LEN)
        .ok_or(Error::RecoveryBlobMalformed)?;
    let mut nonce = [0u8; aead::NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);

    let plaintext = aead::decrypt(
        recovery_key.expose_secret(),
        &nonce,
        RECOVERY_WRAP_CONTEXT,
        ciphertext,
        Error::RecoveryUnwrapFailed,
    )?;
    let mut key = [0u8; KEY_LEN];
    if plaintext.len() != KEY_LEN {
        return Err(Error::RecoveryUnwrapFailed);
    }
    key.copy_from_slice(&plaintext);
    let vault_key = VaultKey::from_bytes(key);
    key.zeroize();
    Ok(vault_key)
}
