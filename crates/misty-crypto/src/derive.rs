// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HKDF-SHA-512 key schedules.
//!
//! Two schedules live here:
//!
//! * **Epoch keys** (SPEC §2.2): `EK_n = HKDF(ikm=VK, salt="misty/epoch/v1",
//!   info=LE32(n))`. Rotating the epoch re-wraps 48-byte item keys instead of
//!   re-encrypting payloads, which is what makes revoking a device cheap
//!   (SPEC §6.4).
//! * **Enrollment** (SPEC §6.3): the X25519 shared secret becomes a sealing key
//!   through a domain-separated HKDF that also commits to both public keys and
//!   the `enroll_id`.

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::keys::{EpochKey, KdfKey, VaultKey, KEY_LEN};
use crate::{EnrollId, Error, Result};

/// HKDF salt for the epoch schedule. Fixed by SPEC §2.2.
pub const EPOCH_SALT: &[u8] = b"misty/epoch/v1";

/// Domain separator for the enrollment schedule.
pub const ENROLLMENT_INFO_PREFIX: &[u8] = b"misty/enroll/v1";

/// HKDF-SHA-512 extract-then-expand.
///
/// # Errors
///
/// [`Error::Kdf`] if `okm` is longer than HKDF-SHA-512 can produce
/// (255 × 64 = 16320 bytes).
pub fn hkdf_sha512(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(info, okm)
        .map_err(|_| Error::Kdf {
            detail: "HKDF-SHA-512 cannot produce an output that long".into(),
        })
}

/// Derives `EK_n` from the vault key.
///
/// `EK_n = HKDF-SHA512(ikm=VK, salt="misty/epoch/v1", info=LE32(n))`
///
/// # Errors
///
/// As [`hkdf_sha512`]; unreachable for a 32-byte output.
pub fn epoch_key(vault_key: &VaultKey, epoch: u32) -> Result<EpochKey> {
    let mut okm = [0u8; KEY_LEN];
    let result = hkdf_sha512(
        vault_key.expose_secret(),
        EPOCH_SALT,
        &epoch.to_le_bytes(),
        &mut okm,
    )
    .map(|()| EpochKey::from_bytes(epoch, okm));
    okm.zeroize();
    result
}

/// Turns an X25519 shared secret into an enrollment sealing key.
///
/// ```text
/// ikm  = X25519(scalar, point)                    32 bytes
/// salt = enroll_id                                16 bytes
/// info = "misty/enroll/v1" || approver_x25519_pub || new_device_x25519_pub
/// ```
///
/// SPEC §6.3 only says "X25519 + HKDF"; the exact inputs are defined here.
/// Committing to `enroll_id` and to **both** public keys means a sealed grant
/// cannot be replayed into a different enrollment, and neither party can be
/// fooled about whose key it agreed with (an unknown key-share attack).
///
/// # Errors
///
/// As [`hkdf_sha512`]; unreachable for a 32-byte output.
pub fn enrollment_sealing_key(
    shared_secret: &[u8; 32],
    enroll_id: &EnrollId,
    approver_x25519_pub: &[u8; 32],
    new_device_x25519_pub: &[u8; 32],
) -> Result<KdfKey> {
    let mut info = Vec::with_capacity(ENROLLMENT_INFO_PREFIX.len() + 64);
    info.extend_from_slice(ENROLLMENT_INFO_PREFIX);
    info.extend_from_slice(approver_x25519_pub);
    info.extend_from_slice(new_device_x25519_pub);

    let mut okm = [0u8; KEY_LEN];
    let result = hkdf_sha512(shared_secret, enroll_id.as_bytes(), &info, &mut okm)
        .map(|()| KdfKey::from_bytes(okm));
    okm.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Authoritative: RFC 5869 §A.1, A.2 and A.3.
    ///
    /// RFC 5869 publishes SHA-1 and SHA-256 vectors only, so these run against
    /// HKDF-SHA-256 rather than the SHA-512 Misty uses. They are here because
    /// they check the extract-then-expand construction, the empty-salt and
    /// empty-info edge cases, and multi-block output — the parts of HKDF where
    /// an implementation goes wrong. The SHA-512 wiring Misty actually calls is
    /// pinned by `epoch_key_frozen_vector` below.
    #[test]
    fn hkdf_sha256_rfc5869_vectors() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let expand = |ikm: &[u8], salt: &[u8], info: &[u8], len: usize| -> Vec<u8> {
            let mut okm = vec![0u8; len];
            Hkdf::<Sha256>::new(Some(salt), ikm)
                .expand(info, &mut okm)
                .unwrap();
            okm
        };

        // A.1: basic case.
        assert_eq!(
            expand(
                &[0x0b; 22],
                &hex_literal::hex!("000102030405060708090a0b0c"),
                &hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9"),
                42
            ),
            hex_literal::hex!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"
            )
        );

        // A.2: longer inputs and outputs, so `expand` runs several rounds.
        let ikm: Vec<u8> = (0u8..=0x4f).collect();
        let salt: Vec<u8> = (0x60u8..=0xaf).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();
        assert_eq!(
            expand(&ikm, &salt, &info, 82),
            hex_literal::hex!(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                "cc30c58179ec3e87c14c01d5c1f3434f1d87"
            )
        );

        // A.3: zero-length salt and info.
        assert_eq!(
            expand(&[0x0b; 22], &[], &[], 42),
            hex_literal::hex!(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                "9d201395faa4b61a96c8"
            )
        );
    }

    /// Self-generated regression vector, **not** authoritative.
    ///
    /// No published HKDF-SHA-512 vectors exist (RFC 5869 covers SHA-1 and
    /// SHA-256 only), and the RFC 5869 SHA-256 cases are checked against the
    /// same `hkdf` crate in `tests/kat_rfc_vectors.rs`. This vector's job is
    /// narrower: it freezes *our* salt and info construction so a later edit to
    /// `EPOCH_SALT`, to the `LE32` encoding, or to the argument order cannot
    /// pass silently.
    ///
    /// The values were cross-checked against an independent HKDF-SHA-512
    /// implementation written directly on Python's `hmac`/`hashlib`, so they
    /// are not merely a recording of what this crate happens to do.
    #[test]
    fn epoch_key_frozen_vector() {
        let vk = VaultKey::from_bytes([0x11; 32]);

        let ek0 = epoch_key(&vk, 0).unwrap();
        assert_eq!(ek0.epoch(), 0);
        assert_eq!(
            ek0.expose_secret(),
            &hex_literal::hex!("8f502793b86a1c19bdc881d2c349729f84ef1b0956051f5e57e11603f23ca5fe")
        );

        let ek7 = epoch_key(&vk, 7).unwrap();
        assert_eq!(ek7.epoch(), 7);
        assert_eq!(
            ek7.expose_secret(),
            &hex_literal::hex!("d19fc437bc561f90753f3a2f223a33aa57b7a10b439acda0e3ce7e04f814733e")
        );
    }

    #[test]
    fn epoch_keys_differ_per_epoch_and_per_vault_key() {
        let vk = VaultKey::from_bytes([0x11; 32]);
        let other = VaultKey::from_bytes([0x12; 32]);
        let a = epoch_key(&vk, 1).unwrap();
        let b = epoch_key(&vk, 2).unwrap();
        let c = epoch_key(&other, 1).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_ne!(a.expose_secret(), c.expose_secret());
    }

    #[test]
    fn epoch_info_is_little_endian() {
        // LE32(1) = 01 00 00 00. If this were big-endian, epoch 1 would collide
        // with epoch 16777216 in any implementation that got it the other way.
        let vk = VaultKey::from_bytes([0x11; 32]);
        let mut expected = [0u8; KEY_LEN];
        hkdf_sha512(
            vk.expose_secret(),
            EPOCH_SALT,
            &[0x01, 0x00, 0x00, 0x00],
            &mut expected,
        )
        .unwrap();
        assert_eq!(epoch_key(&vk, 1).unwrap().expose_secret(), &expected);
    }

    #[test]
    fn enrollment_key_binds_both_public_keys_and_the_enroll_id() {
        let shared = [0x42; 32];
        let id = EnrollId::from_bytes([1; 16]);
        let approver = [0xaa; 32];
        let new_device = [0xbb; 32];

        let base = enrollment_sealing_key(&shared, &id, &approver, &new_device).unwrap();
        let other_id = EnrollId::from_bytes([2; 16]);
        let swapped = enrollment_sealing_key(&shared, &id, &new_device, &approver).unwrap();

        assert!(!base.constant_time_eq(
            &enrollment_sealing_key(&shared, &other_id, &approver, &new_device).unwrap()
        ));
        assert!(!base.constant_time_eq(&swapped));
    }
}
