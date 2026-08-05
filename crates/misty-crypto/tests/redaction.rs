// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redaction: no key type may print its bytes.
//!
//! A secret in a log line is a release blocker (SPEC §3, §9). These assertions
//! are cheap and they are the only automated defence against someone adding
//! `#[derive(Debug)]` to a key type five months from now.

use misty_crypto::identity::DeviceIdentity;
use misty_crypto::keys::{EpochKey, ItemKey, KdfKey, RecoveryKey, VaultKey};
use misty_crypto::{recovery, DeviceId};

/// A byte pattern whose hex and decimal renderings are both easy to search for
/// and cannot appear in the words "redacted" or "EpochKey".
const PATTERN: [u8; 32] = [0x8f; 32];

fn assert_redacted(label: &str, rendered: &str) {
    assert!(
        rendered.contains("[redacted]"),
        "{label}: {rendered:?} does not say [redacted]"
    );
    for leak in ["8f8f", "143, 143", "[143", "8F8F"] {
        assert!(
            !rendered.contains(leak),
            "{label}: {rendered:?} leaks key material ({leak})"
        );
    }
}

#[test]
fn every_key_type_redacts_debug_and_display() {
    let vault = VaultKey::from_bytes(PATTERN);
    let item = ItemKey::from_bytes(PATTERN);
    let recovery_key = RecoveryKey::from_bytes(PATTERN);
    let kdf = KdfKey::from_bytes(PATTERN);
    let epoch = EpochKey::from_bytes(11, PATTERN);

    assert_redacted("VaultKey/Debug", &format!("{vault:?}"));
    assert_redacted("VaultKey/Display", &format!("{vault}"));
    assert_redacted("ItemKey/Debug", &format!("{item:?}"));
    assert_redacted("ItemKey/Display", &format!("{item}"));
    assert_redacted("RecoveryKey/Debug", &format!("{recovery_key:?}"));
    assert_redacted("RecoveryKey/Display", &format!("{recovery_key}"));
    assert_redacted("KdfKey/Debug", &format!("{kdf:?}"));
    assert_redacted("KdfKey/Display", &format!("{kdf}"));
    assert_redacted("EpochKey/Debug", &format!("{epoch:?}"));
    assert_redacted("EpochKey/Display", &format!("{epoch}"));

    // The epoch number itself is not secret and is worth having in a log.
    assert!(format!("{epoch:?}").contains("11"));
}

#[test]
fn device_identity_redacts_its_private_keys() {
    let identity =
        DeviceIdentity::from_secret_bytes(DeviceId::from_bytes([0x8f; 16]), &PATTERN, PATTERN);
    let rendered = format!("{identity:?}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
    // The device id is public metadata — it travels in cleartext in every
    // envelope header — so it may appear.
    assert!(
        rendered.contains("8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f"),
        "{rendered}"
    );
    // The 32-byte private keys must not.
    assert!(!rendered.contains(&"8f".repeat(32)), "{rendered}");
}

#[test]
fn the_recovery_kit_redacts_all_three_encodings() {
    let key = RecoveryKey::from_bytes(PATTERN);
    let kit = recovery::kit(&key);
    let words = kit.words().join(" ");
    let compact = kit.compact().to_owned();

    for rendered in [format!("{kit:?}"), format!("{kit}")] {
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(!rendered.contains(&words), "{rendered}");
        assert!(!rendered.contains(&compact), "{rendered}");
        // The whole rendering is 24 characters or fewer; there is no room for
        // an encoding to hide in it.
        assert!(rendered.len() < 32, "{rendered}");
    }
}

#[test]
fn errors_never_carry_secret_material() {
    use misty_crypto::recovery::from_words;

    // The one error that is *about* a secret value: a bad recovery word. It
    // carries the position, never the word.
    let key = RecoveryKey::from_bytes(PATTERN);
    let kit = recovery::kit(&key);
    let mut words: Vec<String> = kit.words().iter().map(|w| (*w).to_owned()).collect();
    let original = words[7].clone();
    words[7] = "zzzzsecretzzzz".to_owned();

    let error = from_words(&words).unwrap_err();
    let rendered = format!("{error} / {error:?}");
    assert!(rendered.contains('7'), "{rendered}");
    assert!(!rendered.contains("zzzzsecretzzzz"), "{rendered}");
    assert!(!rendered.contains(&original), "{rendered}");
}
