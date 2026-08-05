// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recovery-kit unit tests. The cross-encoding round trips over random keys
//! live in `tests/recovery_kit.rs`; these are the fixed vectors and the
//! rejection cases.

use hex_literal::hex;

use super::*;

/// A fixed recovery key, so the encodings below are reproducible.
const KEY: [u8; 32] = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

fn key() -> RecoveryKey {
    RecoveryKey::from_bytes(KEY)
}

#[test]
fn wordlist_is_the_canonical_bip39_list() {
    use sha2::{Digest, Sha256};
    // A substituted wordlist would produce kits that decode to the wrong key,
    // silently, for every user.
    let digest = Sha256::digest(include_str!("english.txt").as_bytes());
    assert_eq!(
        digest.as_slice(),
        &hex!("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"),
        "BIP-39 English wordlist has been modified"
    );
    assert_eq!(wordlist().count(), WORDLIST_LEN);
    assert_eq!(wordlist().next(), Some("abandon"));
    assert_eq!(wordlist().last(), Some("zoo"));
}

/// FROZEN GOLDEN VECTOR — the three encodings of one fixed key.
///
/// The 24 words are the standard BIP-39 construction, and
/// `tests/kat_rfc_vectors.rs` checks eight authoritative BIP-39 vectors against
/// the same code. The compact and QR forms are Misty's own; both were
/// cross-checked against an independent Crockford encoder and `zlib.crc32`.
#[test]
fn golden_encodings() {
    let kit = kit(&key());

    assert_eq!(
        kit.words().join(" "),
        "abandon amount liar amount expire adjust cage candy arch gather drum \
         bullet absurd math era live bid rhythm alien crouch range attend \
         journey unaware"
    );
    assert_eq!(
        kit.compact(),
        "000G40R4-0M30E209-185GR38E-1W8124GK-2GAHC5RR-34D1P70X-3RFS29KY-H8"
    );
    assert_eq!(
        kit.qr(),
        "misty-recovery:v1:000G40R4-0M30E209-185GR38E-1W8124GK-2GAHC5RR-34D1P70X-3RFS29KY-H8"
    );

    // All three decode back to the same 32 bytes.
    assert!(from_words(kit.words()).unwrap().constant_time_eq(&key()));
    assert!(from_compact(kit.compact())
        .unwrap()
        .constant_time_eq(&key()));
    assert!(from_qr(kit.qr()).unwrap().constant_time_eq(&key()));
}

#[test]
fn kit_debug_and_display_are_redacted() {
    let kit = kit(&key());
    assert_eq!(format!("{kit:?}"), "RecoveryKit([redacted])");
    assert_eq!(format!("{kit}"), "[redacted]");
    // And no fragment of any encoding leaks through either.
    for rendering in [format!("{kit:?}"), format!("{kit}")] {
        assert!(!rendering.contains("abandon"));
        assert!(!rendering.contains("000G40R4"));
    }
}

#[test]
fn word_count_and_checksum_are_enforced() {
    let kit = kit(&key());
    let mut words: Vec<&str> = kit.words().to_vec();

    assert!(matches!(
        from_words(&words[..23]),
        Err(Error::WrongWordCount {
            expected: 24,
            found: 23
        })
    ));

    words.push("zoo");
    assert!(matches!(
        from_words(&words),
        Err(Error::WrongWordCount { found: 25, .. })
    ));

    let mut words: Vec<&str> = kit.words().to_vec();
    words[5] = "notaword";
    assert!(matches!(
        from_words(&words),
        Err(Error::UnknownWord { index: 5 })
    ));

    // Swap two words: every word is real, the checksum is not.
    let mut words: Vec<&str> = kit.words().to_vec();
    words.swap(0, 1);
    assert!(matches!(
        from_words(&words),
        Err(Error::WordChecksumMismatch)
    ));
}

#[test]
fn words_are_case_and_whitespace_insensitive() {
    let kit = kit(&key());
    let sloppy: Vec<String> = kit
        .words()
        .iter()
        .enumerate()
        .map(|(index, word)| {
            if index % 2 == 0 {
                format!("  {}  ", word.to_uppercase())
            } else {
                (*word).to_owned()
            }
        })
        .collect();
    assert!(from_words(&sloppy).unwrap().constant_time_eq(&key()));
}
#[test]
fn a_single_typo_is_repairable() {
    let kit = kit(&key());
    let truth: Vec<&str> = kit.words().to_vec();

    // Case 1: a word that is not in the list at all — "gather" with a letter
    // dropped.
    let mut typed: Vec<String> = truth.iter().map(|word| (*word).to_owned()).collect();
    typed[9] = "gathr".to_owned();
    assert!(matches!(
        from_words(&typed),
        Err(Error::UnknownWord { index: 9 })
    ));
    let repairs = suggest_word_repairs(&typed);
    assert!(
        repairs.contains(&WordRepair {
            index: 9,
            candidate: "gather"
        }),
        "expected 'gather' among {repairs:?}"
    );
    for repair in &repairs {
        assert_eq!(repair.index, 9, "only the unknown word is a candidate");
    }

    // Case 2: a real word in the wrong slot — "live" read as "life", one
    // substitution, so the checksum is the only thing that objects.
    let mut typed: Vec<String> = truth.iter().map(|word| (*word).to_owned()).collect();
    typed[15] = "life".to_owned();
    assert!(matches!(
        from_words(&typed),
        Err(Error::WordChecksumMismatch)
    ));
    let repairs = suggest_word_repairs(&typed);
    assert!(
        repairs.iter().any(|repair| repair.candidate == "live"),
        "expected 'live' among {repairs:?}"
    );

    // Applying the suggestion recovers the key exactly.
    let repair = repairs
        .iter()
        .find(|repair| repair.candidate == "live")
        .unwrap();
    let mut fixed = typed.clone();
    fixed[repair.index] = repair.candidate.to_owned();
    assert!(from_words(&fixed).unwrap().constant_time_eq(&key()));
}

#[test]
fn a_valid_kit_needs_no_repair_and_hopeless_input_gets_none() {
    let kit = kit(&key());
    assert!(suggest_word_repairs(kit.words()).is_empty());

    // Two words destroyed is not a typo.
    let mut typed: Vec<String> = kit.words().iter().map(|w| (*w).to_owned()).collect();
    typed[1] = "qqqq".to_owned();
    typed[2] = "wwww".to_owned();
    assert!(suggest_word_repairs(&typed).is_empty());

    // Wrong length gets nothing rather than a panic.
    assert!(suggest_word_repairs(&typed[..5]).is_empty());
    assert!(suggest_word_repairs::<String>(&[]).is_empty());
}

#[test]
fn nearest_words_finds_near_misses() {
    assert!(nearest_words("aim", 0).contains(&"aim"));
    assert!(nearest_words("ai", 1).contains(&"aim"));
    assert!(nearest_words("zoa", 1).contains(&"zoo"));
    assert!(nearest_words("qqqqqqqq", 1).is_empty());
}

#[test]
fn compact_rejects_malformed_input() {
    let kit = kit(&key());
    let compact = kit.compact().to_owned();

    assert!(matches!(
        from_compact(&compact[..20]),
        Err(Error::BadCompactLength { expected: 58, .. })
    ));

    // 'U' is not in Crockford's alphabet.
    let mut bad = compact.clone();
    bad = bad.replacen('0', "U", 1);
    assert!(matches!(
        from_compact(&bad),
        Err(Error::BadCompactChar { .. })
    ));

    // A flipped character breaks the CRC32.
    let mut bad: Vec<char> = compact.chars().collect();
    bad[0] = if bad[0] == '1' { '2' } else { '1' };
    let bad: String = bad.into_iter().collect();
    assert!(matches!(from_compact(&bad), Err(Error::Crc32Mismatch)));

    // Non-zero trailing bits: 288 bits of payload occupy 58 five-bit
    // characters, so the last character's low two bits are padding. The frozen
    // vector ends in '8' (0b01000); '9' (0b01001) sets a padding bit without
    // touching any payload byte, so the CRC still matches and only the padding
    // check can catch it.
    let mut bad: Vec<char> = compact.chars().collect();
    let last = bad.len() - 1;
    assert_eq!(bad[last], '8');
    bad[last] = '9';
    let bad: String = bad.into_iter().collect();
    assert!(matches!(from_compact(&bad), Err(Error::BadCompactPadding)));
}

#[test]
fn compact_folds_the_confusable_characters() {
    let kit = kit(&key());
    let compact = kit.compact().to_owned();
    // O -> 0 and I/L -> 1, in either case, and separators are ignored.
    let mangled = compact
        .to_lowercase()
        .replace('0', "O")
        .replace('1', "l")
        .replace('-', " ");
    assert!(from_compact(&mangled).unwrap().constant_time_eq(&key()));
}

#[test]
fn qr_prefix_is_required() {
    let kit = kit(&key());
    assert!(matches!(from_qr(kit.compact()), Err(Error::BadQrPrefix)));
    assert!(matches!(from_qr(""), Err(Error::BadQrPrefix)));
    assert!(matches!(
        from_qr("misty-recovery:v2:000G40R4"),
        Err(Error::BadQrPrefix)
    ));
    // Scanners that upper-case alphanumeric payloads are tolerated.
    let shouty = kit.qr().to_uppercase();
    assert!(from_qr(&shouty).unwrap().constant_time_eq(&key()));
}
/// FROZEN GOLDEN VECTOR — `recovery_blob` with a fixed nonce.
///
/// Cross-checked against libsodium's
/// `crypto_aead_xchacha20poly1305_ietf_encrypt`.
#[test]
fn golden_recovery_blob() {
    let vault_key = VaultKey::from_bytes([0x11; 32]);
    let nonce = hex!("808182838485868788898a8b8c8d8e8f9091929394959697");
    let blob = wrap_vault_key_with(&key(), &vault_key, nonce).unwrap();
    assert_eq!(blob.len(), RECOVERY_BLOB_LEN);
    assert_eq!(blob.len(), 72);
    assert_eq!(
        blob,
        hex!(
            "808182838485868788898a8b8c8d8e8f9091929394959697" // nonce
            // XChaCha20Poly1305(key=RK, nonce, pt=VK, aad="misty/recovery/v1")
            "53ff4848f685527b0d0932ea5eac09c068804dc092eaabe8f17b7bcba6c30d60"
            "29f7b09bc51fac8b97716b01f8a1f8d3"
        )
    );
    let recovered = unwrap_vault_key(&key(), &blob).unwrap();
    assert!(recovered.constant_time_eq(&vault_key));
}

#[test]
fn recovery_blob_rejects_the_wrong_key_and_malformed_input() {
    let vault_key = VaultKey::from_bytes([0x11; 32]);
    let blob = wrap_vault_key(&key(), &vault_key).unwrap();

    let wrong = RecoveryKey::from_bytes([0xff; 32]);
    assert!(matches!(
        unwrap_vault_key(&wrong, &blob),
        Err(Error::RecoveryUnwrapFailed)
    ));

    for len in [0, 23, 24, 71, 73] {
        let mut truncated = blob.clone();
        truncated.resize(len, 0);
        assert!(
            matches!(
                unwrap_vault_key(&key(), &truncated),
                Err(Error::RecoveryBlobMalformed)
            ),
            "len {len}"
        );
    }

    let mut tampered = blob.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(matches!(
        unwrap_vault_key(&key(), &tampered),
        Err(Error::RecoveryUnwrapFailed)
    ));

    // The context string is the AAD: a blob wrapped under another context must
    // not open. (Proved by encrypting with a different AAD directly.)
    let nonce = [0x5a; 24];
    let foreign = crate::aead::encrypt(
        key().expose_secret(),
        &nonce,
        b"misty/not-recovery/v1",
        vault_key.expose_secret(),
    )
    .unwrap();
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&foreign);
    assert!(matches!(
        unwrap_vault_key(&key(), &blob),
        Err(Error::RecoveryUnwrapFailed)
    ));
}

#[test]
fn two_wraps_of_the_same_key_differ() {
    let vault_key = VaultKey::from_bytes([0x11; 32]);
    let a = wrap_vault_key(&key(), &vault_key).unwrap();
    let b = wrap_vault_key(&key(), &vault_key).unwrap();
    assert_ne!(a, b, "fresh nonce per wrap");
}

#[test]
fn spec_constants_are_what_the_spec_says() {
    assert_eq!(RECOVERY_QR_PREFIX, "misty-recovery:v1:");
    assert_eq!(RECOVERY_WRAP_CONTEXT, b"misty/recovery/v1");
    assert_eq!(RECOVERY_WORD_COUNT, 24);
    assert_eq!(WORDLIST_LEN, 2048);
    assert_eq!(COMPACT_GROUP_LEN, 8);
}
