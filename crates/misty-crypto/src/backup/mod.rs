// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `.mistybak` backup file (SPEC §2.5). `BACKUP_FORMAT_VERSION = 1`.
//!
//! ```text
//!   off  len  field
//!     0    8  magic = b"MISTYBAK"
//!     8    1  format_version = 1
//!     9    1  kdf_id = 1 (Argon2id)
//!    10    4  argon2_memory_kib: u32
//!    14    4  argon2_iterations: u32
//!    18    4  argon2_parallelism: u32
//!    22   16  salt
//!    38   24  nonce
//!    62    8  reserved, MUST be zero
//!    70   ..  XChaCha20Poly1305(key=Argon2id(passphrase, salt, params),
//!                               nonce, pt=deflate(CBOR(payload)), aad=Header)
//! ```
//!
//! Backups are the `A8` mitigation: a copy that leaks out of someone's cloud
//! drive is protected by its **own** Argon2id-derived key from a **separate**
//! passphrase. Nothing about the vault's own unlock factors is involved, so
//! provider security is never relied on.
//!
//! # Why the KDF parameters are in cleartext, and why that is safe
//!
//! A phone must be able to open a backup a desktop wrote at the `Sensitive`
//! tier, so the parameters travel with the file. That makes them
//! attacker-controlled, which is why [`BackupHeader::parse`] bounds them
//! ([`KdfParams::validate`]) before any allocation happens: a header claiming
//! 64 GiB of memory is a denial-of-service vector on a path that necessarily
//! runs before the passphrase can be checked.
//!
//! Out-of-range parameters are **rejected, not clamped**. Clamping would derive
//! a different key and report "wrong passphrase" for a file that was merely
//! written by something unusual — a far more confusing failure. Writers cannot
//! choose arbitrary costs in the first place: [`seal_bytes`] takes a
//! [`KdfTier`].
//!
//! # DEFLATE, not zstd
//!
//! `miniz_oxide` is pure Rust. The `zstd` crate carries C and would break the
//! `wasm32-unknown-unknown` build, which is the same reason `getrandom` needs
//! its `js` feature (SPEC §2.5).

use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::aead;
use crate::kdf::{KdfParams, KdfTier, KDF_ID_ARGON2ID, SALT_LEN};
use crate::{random, Error, Result};

#[cfg(test)]
mod tests;

/// `magic`, offset 0.
pub const BACKUP_MAGIC: [u8; 8] = *b"MISTYBAK";

/// `format_version`, offset 8.
pub const BACKUP_FORMAT_VERSION: u8 = 1;

/// Length of the cleartext header, which is also the AEAD's AAD.
pub const BACKUP_HEADER_LEN: usize = 70;

/// File extension, without the dot.
pub const BACKUP_EXTENSION: &str = "mistybak";

/// Tier used for backup files unless the caller says otherwise.
///
/// A backup file is offline, attacked at leisure, and unlocked once in a while
/// by a human who is expecting it to take a moment (SPEC §2.3).
pub const DEFAULT_TIER: KdfTier = KdfTier::Sensitive;

/// Largest plaintext this crate will inflate to, a compression-bomb bound.
pub const MAX_DECOMPRESSED_LEN: usize = 64 * 1024 * 1024;

/// DEFLATE level. 6 is the usual space/time compromise; the value is part of
/// the frozen golden vector but not of the format — any level decompresses.
const DEFLATE_LEVEL: u8 = 6;

const RESERVED_LEN: usize = 8;

/// The parsed cleartext header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupHeader {
    /// Always [`BACKUP_FORMAT_VERSION`] for headers this build produced.
    pub format_version: u8,
    /// Always [`KDF_ID_ARGON2ID`] in this format version.
    pub kdf_id: u8,
    /// Argon2id costs, in cleartext so any device can open the file.
    pub params: KdfParams,
    /// Argon2id salt.
    pub salt: [u8; SALT_LEN],
    /// XChaCha20-Poly1305 nonce.
    pub nonce: [u8; aead::NONCE_LEN],
}

impl BackupHeader {
    /// A header for this build's format version and KDF.
    #[must_use]
    pub const fn new(
        params: KdfParams,
        salt: [u8; SALT_LEN],
        nonce: [u8; aead::NONCE_LEN],
    ) -> Self {
        Self {
            format_version: BACKUP_FORMAT_VERSION,
            kdf_id: KDF_ID_ARGON2ID,
            params,
            salt,
            nonce,
        }
    }

    /// Serialises to the exact 70 wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BACKUP_HEADER_LEN] {
        let mut out = [0u8; BACKUP_HEADER_LEN];
        let mut written = 0usize;
        let mut put = |bytes: &[u8]| {
            let end = written.saturating_add(bytes.len());
            if let Some(slot) = out.get_mut(written..end) {
                slot.copy_from_slice(bytes);
                written = end;
            }
        };
        put(&BACKUP_MAGIC);
        put(&[self.format_version]);
        put(&[self.kdf_id]);
        put(&self.params.memory_kib.to_le_bytes());
        put(&self.params.iterations.to_le_bytes());
        put(&self.params.parallelism.to_le_bytes());
        put(&self.salt);
        put(&self.nonce);
        // Offsets 62..70 stay zero: `reserved`.
        out
    }
    /// Parses the first 70 bytes of `bytes`.
    ///
    /// Rejections, in order: too short, wrong magic, unknown `format_version`,
    /// unknown `kdf_id`, non-zero `reserved`, out-of-range costs.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`], [`Error::BadBackupMagic`],
    /// [`Error::UnsupportedFormatVersion`], [`Error::UnknownKdfId`],
    /// [`Error::ReservedNotZero`], [`Error::KdfParamsRejected`].
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = bytes.get(..BACKUP_HEADER_LEN).ok_or(Error::Truncated {
            context: "backup header",
            needed: BACKUP_HEADER_LEN,
            got: bytes.len(),
        })?;
        let field = |offset: usize, len: usize| -> Result<&[u8]> {
            header.get(offset..offset + len).ok_or(Error::Truncated {
                context: "backup header",
                needed: offset + len,
                got: header.len(),
            })
        };
        let le32 = |offset: usize| -> Result<u32> {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(field(offset, 4)?);
            Ok(u32::from_le_bytes(buf))
        };

        if field(0, 8)? != BACKUP_MAGIC {
            return Err(Error::BadBackupMagic);
        }
        let format_version = *field(8, 1)?.first().unwrap_or(&0);
        if format_version != BACKUP_FORMAT_VERSION {
            return Err(Error::UnsupportedFormatVersion {
                context: "backup",
                found: format_version,
                supported: BACKUP_FORMAT_VERSION,
            });
        }
        let kdf_id = *field(9, 1)?.first().unwrap_or(&0);
        if kdf_id != KDF_ID_ARGON2ID {
            return Err(Error::UnknownKdfId { found: kdf_id });
        }
        if field(62, RESERVED_LEN)?.iter().any(|byte| *byte != 0) {
            return Err(Error::ReservedNotZero {
                context: "backup header",
            });
        }
        let params = KdfParams::new(le32(10)?, le32(14)?, le32(18)?);
        params.validate()?;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(field(22, SALT_LEN)?);
        let mut nonce = [0u8; aead::NONCE_LEN];
        nonce.copy_from_slice(field(38, aead::NONCE_LEN)?);

        Ok(Self {
            format_version,
            kdf_id,
            params,
            salt,
            nonce,
        })
    }
}

/// Seals already-serialised bytes into a backup file.
///
/// # Errors
///
/// [`Error::Random`] if the CSPRNG fails, or anything
/// [`KdfParams::derive_key`] returns.
pub fn seal_bytes(passphrase: &[u8], tier: KdfTier, payload: &[u8]) -> Result<Vec<u8>> {
    seal_bytes_with(
        passphrase,
        tier.params(),
        random::array::<SALT_LEN>()?,
        random::array::<{ aead::NONCE_LEN }>()?,
        payload,
    )
}

/// Seals a CBOR-serialisable value into a backup file.
///
/// This is the SPEC §2.5 pipeline end to end:
/// `XChaCha20Poly1305(Argon2id(passphrase), deflate(CBOR(value)))`.
///
/// # Errors
///
/// As [`seal_bytes`], plus [`Error::Cbor`] if `value` cannot be encoded.
pub fn seal<T: Serialize>(passphrase: &[u8], tier: KdfTier, value: &T) -> Result<Vec<u8>> {
    let mut encoded = Zeroizing::new(Vec::new());
    ciborium::into_writer(value, &mut *encoded).map_err(|error| Error::Cbor {
        operation: "encode",
        detail: error.to_string(),
    })?;
    seal_bytes(passphrase, tier, &encoded)
}

/// Seals with explicit costs, salt and nonce. The deterministic seam the golden
/// vectors use; there is no public API that accepts a nonce.
pub(crate) fn seal_bytes_with(
    passphrase: &[u8],
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; aead::NONCE_LEN],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let header = BackupHeader::new(params, salt, nonce).to_bytes();
    let key = params.derive_key(passphrase, &salt)?;
    let compressed = Zeroizing::new(miniz_oxide::deflate::compress_to_vec(
        payload,
        DEFLATE_LEVEL,
    ));
    let ciphertext = aead::encrypt(key.expose_secret(), &nonce, &header, &compressed)?;

    let mut out = Vec::with_capacity(BACKUP_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a backup file, returning the caller's serialised bytes.
///
/// The result is zeroized on drop.
///
/// # Errors
///
/// Anything [`BackupHeader::parse`] rejects, [`Error::Truncated`] if the body
/// cannot hold an AEAD tag, [`Error::BackupDecryptFailed`] for a wrong
/// passphrase or a tampered file, [`Error::Inflate`] or
/// [`Error::InflateLimit`].
pub fn open_bytes(passphrase: &[u8], file: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let header = BackupHeader::parse(file)?;
    // AAD is the header as it appears in the file, not a re-serialisation of
    // the parsed struct: authenticate the bytes that were actually read.
    let (header_bytes, body) =
        file.split_at_checked(BACKUP_HEADER_LEN)
            .ok_or(Error::Truncated {
                context: "backup header",
                needed: BACKUP_HEADER_LEN,
                got: file.len(),
            })?;
    if body.len() < aead::TAG_LEN {
        return Err(Error::Truncated {
            context: "backup body",
            needed: BACKUP_HEADER_LEN + aead::TAG_LEN,
            got: file.len(),
        });
    }
    let key = header.params.derive_key(passphrase, &header.salt)?;
    let compressed = aead::decrypt(
        key.expose_secret(),
        &header.nonce,
        header_bytes,
        body,
        Error::BackupDecryptFailed,
    )?;
    inflate(&compressed)
}

/// Opens a backup file and decodes its CBOR payload.
///
/// # Errors
///
/// As [`open_bytes`], plus [`Error::Cbor`].
pub fn open<T: DeserializeOwned>(passphrase: &[u8], file: &[u8]) -> Result<T> {
    let bytes = open_bytes(passphrase, file)?;
    ciborium::from_reader(bytes.as_slice()).map_err(|error| Error::Cbor {
        operation: "decode",
        detail: error.to_string(),
    })
}

fn inflate(compressed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    inflate_with_limit(compressed, MAX_DECOMPRESSED_LEN)
}

/// Split out so the limit can be tested with a small bomb instead of a 64 MiB
/// one.
fn inflate_with_limit(compressed: &[u8], max: usize) -> Result<Zeroizing<Vec<u8>>> {
    match miniz_oxide::inflate::decompress_to_vec_with_limit(compressed, max) {
        Ok(plain) => Ok(Zeroizing::new(plain)),
        Err(error) => {
            // The partial output is plaintext; do not let it fall out of scope
            // unwiped just because decompression failed.
            let mut partial = error.output;
            partial.zeroize();
            if error.status == miniz_oxide::inflate::TINFLStatus::HasMoreOutput {
                return Err(Error::InflateLimit { max });
            }
            Err(Error::Inflate {
                detail: "not a valid DEFLATE stream",
            })
        }
    }
}
