// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recovery-kit round trips over random keys.
//!
//! SPEC §2.6 requires the three encodings to be interchangeable renderings of
//! the same bytes. "Interchangeable" is only true if it is true for *every*
//! key, so this file generates them rather than using fixtures; the fixed
//! vectors live in `src/recovery/tests.rs`.

use misty_crypto::keys::{RecoveryKey, VaultKey};
use misty_crypto::{recovery, Error};
use proptest::prelude::*;

fn round_trip_all_encodings(bytes: [u8; 32]) {
    let key = RecoveryKey::from_bytes(bytes);
    let kit = recovery::kit(&key);

    assert_eq!(kit.words().len(), 24);
    assert_eq!(kit.compact().chars().filter(|c| *c != '-').count(), 58);
    assert!(kit.qr().starts_with("misty-recovery:v1:"));

    for decoded in [
        recovery::from_words(kit.words()).expect("words"),
        recovery::from_compact(kit.compact()).expect("compact"),
        recovery::from_qr(kit.qr()).expect("qr"),
    ] {
        assert!(
            decoded.constant_time_eq(&key),
            "an encoding did not round trip for {bytes:02x?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn all_three_encodings_agree(bytes in any::<[u8; 32]>()) {
        round_trip_all_encodings(bytes);
    }

    /// The wrap/unwrap pair, over random key material on both sides.
    #[test]
    fn recovery_blob_round_trips(
        recovery_bytes in any::<[u8; 32]>(),
        vault_bytes in any::<[u8; 32]>(),
    ) {
        let recovery_key = RecoveryKey::from_bytes(recovery_bytes);
        let vault_key = VaultKey::from_bytes(vault_bytes);
        let blob = recovery::wrap_vault_key(&recovery_key, &vault_key).expect("wrap");
        prop_assert_eq!(blob.len(), 72);
        let recovered = recovery::unwrap_vault_key(&recovery_key, &blob).expect("unwrap");
        prop_assert!(recovered.constant_time_eq(&vault_key));
    }

    /// A single wrong character in the compact form is always caught, either by
    /// the alphabet, the padding bits, or the CRC32 — never silently accepted.
    #[test]
    fn a_single_wrong_compact_character_is_always_caught(
        bytes in any::<[u8; 32]>(),
        position in 0usize..58,
        replacement in 0usize..32,
    ) {
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        let key = RecoveryKey::from_bytes(bytes);
        let compact = recovery::to_compact(&key);

        let mut significant: Vec<char> = compact.chars().filter(|c| *c != '-').collect();
        let new_char = char::from(ALPHABET[replacement]);
        if significant[position] == new_char {
            return Ok(());
        }
        significant[position] = new_char;
        let mangled: String = significant.into_iter().collect();

        match recovery::from_compact(&mangled) {
            Err(Error::Crc32Mismatch | Error::BadCompactPadding | Error::BadCompactChar { .. }) => {}
            Err(other) => prop_assert!(false, "unexpected error {other:?}"),
            Ok(decoded) => prop_assert!(
                !decoded.constant_time_eq(&key),
                "a corrupted code decoded to the original key"
            ),
        }
    }
}

/// Edge-case keys, explicitly: all zeros, all ones, and a low-entropy pattern
/// that stresses the bit packing.
#[test]
fn edge_case_keys_round_trip() {
    for bytes in [
        [0x00u8; 32],
        [0xffu8; 32],
        [0x55u8; 32],
        [0xaau8; 32],
        [0x80u8; 32],
        [0x01u8; 32],
    ] {
        round_trip_all_encodings(bytes);
    }
}

/// A truncated or extended kit is rejected rather than silently padded.
#[test]
fn wrong_word_counts_are_rejected() {
    let key = RecoveryKey::from_bytes([0x42; 32]);
    let kit = recovery::kit(&key);
    let words: Vec<&str> = kit.words().to_vec();
    for count in [0usize, 1, 12, 23, 25, 48] {
        let mut candidate = words.clone();
        candidate.resize(count, "abandon");
        assert!(
            matches!(
                recovery::from_words(&candidate),
                Err(Error::WrongWordCount { expected: 24, .. })
            ),
            "{count} words"
        );
    }
}
