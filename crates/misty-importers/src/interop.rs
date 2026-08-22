// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Other applications' cryptography.
//!
//! **None of this is Misty's cryptography.** SPEC 2.1 fixes Misty's primitives at
//! XChaCha20-Poly1305, Argon2id and HKDF-SHA-512, and nothing here is used to
//! protect anything Misty writes. These are the algorithms Aegis and andOTP chose
//! for *their* backups, implemented only so a user can leave them. Every one is
//! pure Rust, because a C dependency would end the `wasm32-unknown-unknown` build
//! and the browser extension imports files too.
//!
//! # Parameters from a file's own header are rejected, never clamped
//!
//! Each of these formats stores its KDF cost in cleartext in the file, which means
//! an attacker who hands the user a file chooses that cost. Clamping a hostile
//! 64 GiB scrypt cost down to something survivable derives a *different key*, so
//! the user is told their password is wrong when the real problem is a malformed
//! header — a bug that is close to impossible to diagnose from the outside. SPEC 2.3
//! says reject and name the parameter, and that is what
//! [`ImportError::KdfParam`] does.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::Zeroizing;

use crate::context::Limits;
use crate::error::{ImportError, Result};

/// Length of every key in this module. All three formats use AES-256.
pub(crate) const KEY_LEN: usize = 32;
/// AES-GCM nonce length. Aegis and andOTP both use the 96-bit default.
pub(crate) const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length.
pub(crate) const TAG_LEN: usize = 16;

/// Derive a 32-byte key with scrypt, as Aegis does.
///
/// `n`, `r` and `p` come from the vault header. `n` must be a power of two — the
/// algorithm requires it — and the resulting memory cost, `128 * r * n` bytes, must
/// be within [`Limits::max_kdf_memory_bytes`].
pub(crate) fn scrypt_key(
    passphrase: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
    limits: &Limits,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if n < 2 || !n.is_power_of_two() {
        return Err(ImportError::KdfParam {
            name: "n",
            value: n,
        });
    }
    // `trailing_zeros` of a power of two is its log2, and n >= 2 means it is 1..63.
    let log_n = u8::try_from(n.trailing_zeros()).map_err(|_| ImportError::KdfParam {
        name: "n",
        value: n,
    })?;
    if r == 0 {
        return Err(ImportError::KdfParam {
            name: "r",
            value: u64::from(r),
        });
    }
    if p == 0 {
        return Err(ImportError::KdfParam {
            name: "p",
            value: u64::from(p),
        });
    }
    let memory = u64::from(r)
        .checked_mul(n)
        .and_then(|product| product.checked_mul(128))
        .ok_or(ImportError::KdfParam {
            name: "n",
            value: n,
        })?;
    if memory > limits.max_kdf_memory_bytes {
        return Err(ImportError::KdfParam {
            name: "n",
            value: memory,
        });
    }
    // scrypt's own parameter validation catches the r*p ceiling the RFC sets.
    let params = scrypt::Params::new(log_n, r, p, KEY_LEN).map_err(|_| ImportError::KdfParam {
        name: "r",
        value: u64::from(r),
    })?;

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    scrypt::scrypt(passphrase, salt, &params, key.as_mut()).map_err(|_| ImportError::KdfParam {
        name: "n",
        value: n,
    })?;
    Ok(key)
}

/// Derive a 32-byte key with PBKDF2-HMAC-SHA-1, as andOTP does.
///
/// SHA-1 is not a choice: it is what `PBKDF2WithHmacSHA1`, the JCE name andOTP
/// passes, means. PBKDF2's security here rests on HMAC, which SHA-1's collision
/// weaknesses do not break.
pub(crate) fn pbkdf2_sha1_key(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u64,
    limits: &Limits,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let rounds = check_iterations(iterations, limits)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, salt, rounds, key.as_mut());
    Ok(key)
}

/// Derive a 32-byte key with PBKDF2-HMAC-SHA-256, which 2FAS uses.
pub(crate) fn pbkdf2_sha256_key(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u64,
    limits: &Limits,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let rounds = check_iterations(iterations, limits)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase, salt, rounds, key.as_mut());
    Ok(key)
}

fn check_iterations(iterations: u64, limits: &Limits) -> Result<u32> {
    if iterations == 0 || iterations > limits.max_kdf_iterations {
        return Err(ImportError::KdfParam {
            name: "iterations",
            value: iterations,
        });
    }
    u32::try_from(iterations).map_err(|_| ImportError::KdfParam {
        name: "iterations",
        value: iterations,
    })
}

/// A 32-byte key derived as SHA-256 of the password, which andOTP's older
/// "password only" backup used before it grew a KDF.
pub(crate) fn sha256_key(passphrase: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(passphrase);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&digest);
    key
}

/// Open an AES-256-GCM box whose tag is appended to the ciphertext.
///
/// A failure here is reported as [`ImportError::DecryptionFailed`] and nothing
/// else: AEAD cannot distinguish a wrong key from a tampered file, so neither can
/// the message.
pub(crate) fn aes256gcm_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN || ciphertext_and_tag.len() < TAG_LEN {
        return Err(ImportError::DecryptionFailed);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ImportError::DecryptionFailed)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext_and_tag)
        .map_err(|_| ImportError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

/// Open an AES-256-GCM box whose tag is stored separately from the ciphertext, as
/// Aegis's header does.
pub(crate) fn aes256gcm_open_split(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if tag.len() != TAG_LEN {
        return Err(ImportError::DecryptionFailed);
    }
    let mut joined = Zeroizing::new(Vec::with_capacity(ciphertext.len() + tag.len()));
    joined.extend_from_slice(ciphertext);
    joined.extend_from_slice(tag);
    aes256gcm_open(key, nonce, &joined)
}

#[cfg(test)]
mod tests {
    // `Aead` (for `encrypt`) arrives through `super::*` — this module's own import at the
    // top of the file. Re-importing it here is redundant and `-D warnings` rejects it.
    use super::*;

    /// NIST SP 800-38A / RFC 7539-style self-check: this crate can open what it
    /// can seal, which is the property the fixture generators rely on.
    #[test]
    fn gcm_round_trips_and_rejects_a_flipped_bit() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), b"plaintext".as_ref())
            .unwrap();

        assert_eq!(
            &*aes256gcm_open(&key, &nonce, &sealed).unwrap(),
            b"plaintext"
        );

        let mut tampered = sealed.clone();
        if let Some(byte) = tampered.first_mut() {
            *byte ^= 1;
        }
        assert_eq!(
            aes256gcm_open(&key, &nonce, &tampered),
            Err(ImportError::DecryptionFailed)
        );
        assert_eq!(
            aes256gcm_open(&[0u8; KEY_LEN], &nonce, &sealed),
            Err(ImportError::DecryptionFailed)
        );
        // A short nonce or a ciphertext with no room for a tag is refused before
        // the cipher is even built.
        assert_eq!(
            aes256gcm_open(&key, &[0u8; 4], &sealed),
            Err(ImportError::DecryptionFailed)
        );
        assert_eq!(
            aes256gcm_open(&key, &nonce, &[0u8; 4]),
            Err(ImportError::DecryptionFailed)
        );
    }

    #[test]
    fn a_split_tag_and_an_appended_tag_agree() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), b"aegis header".as_ref())
            .unwrap();
        let (ciphertext, tag) = sealed.split_at(sealed.len() - TAG_LEN);
        assert_eq!(
            &*aes256gcm_open_split(&key, &nonce, ciphertext, tag).unwrap(),
            b"aegis header"
        );
        assert_eq!(
            aes256gcm_open_split(&key, &nonce, ciphertext, &tag[..4]),
            Err(ImportError::DecryptionFailed)
        );
    }

    /// RFC 7914 §12 test vector, so this is not merely self-consistent.
    #[test]
    fn scrypt_matches_the_rfc_7914_vector() {
        // scrypt("password", "NaCl", N=1024, r=8, p=16, dkLen=64); the first 32
        // bytes are what a 32-byte request returns.
        let expected = [
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
            0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63,
            0x4b, 0x37, 0x31, 0x62,
        ];
        let key = scrypt_key(b"password", b"NaCl", 1024, 8, 16, &Limits::default()).unwrap();
        assert_eq!(&*key, &expected);
    }

    #[test]
    fn hostile_kdf_parameters_are_named_and_refused() {
        let limits = Limits::default();
        // Not a power of two.
        assert_eq!(
            scrypt_key(b"p", b"s", 1000, 8, 1, &limits),
            Err(ImportError::KdfParam {
                name: "n",
                value: 1000
            })
        );
        // 128 * 8 * 2^33 bytes: refused, not clamped.
        assert!(matches!(
            scrypt_key(b"p", b"s", 1 << 33, 8, 1, &limits),
            Err(ImportError::KdfParam { name: "n", .. })
        ));
        assert!(matches!(
            scrypt_key(b"p", b"s", 1024, 0, 1, &limits),
            Err(ImportError::KdfParam { name: "r", .. })
        ));
        assert!(matches!(
            scrypt_key(b"p", b"s", 1024, 8, 0, &limits),
            Err(ImportError::KdfParam { name: "p", .. })
        ));
        assert!(matches!(
            pbkdf2_sha1_key(b"p", b"s", 0, &limits),
            Err(ImportError::KdfParam {
                name: "iterations",
                ..
            })
        ));
        assert!(matches!(
            pbkdf2_sha1_key(b"p", b"s", u64::from(u32::MAX) + 1, &limits),
            Err(ImportError::KdfParam {
                name: "iterations",
                ..
            })
        ));
    }

    /// RFC 6070 test vector for PBKDF2-HMAC-SHA-1, truncated to 32 bytes: the
    /// 4096-iteration case with a 25-byte derived key extended to 32.
    #[test]
    fn pbkdf2_sha1_matches_rfc_6070() {
        let key = pbkdf2_sha1_key(b"password", b"salt", 4096, &Limits::default()).unwrap();
        // RFC 6070: 4096 iterations, dkLen 20 -> 4b007901b765489abead49d926f721d065a429c1
        let expected_prefix = [
            0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7,
            0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1,
        ];
        assert_eq!(key.get(..20), Some(&expected_prefix[..]));
    }

    #[test]
    fn sha256_key_is_the_digest_itself() {
        // NIST: SHA-256("abc").
        let key = sha256_key(b"abc");
        assert_eq!(
            hex::encode(*key),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
