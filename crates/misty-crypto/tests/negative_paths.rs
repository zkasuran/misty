// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One test per typed error, through the public API.
//!
//! The point is not coverage for its own sake: a caller has to be able to tell
//! "this is not a Misty file" from "wrong passphrase" from "this device is not
//! in your roster", because those three mean completely different things to a
//! user. String matching on error messages is not an acceptable way to do that,
//! so every distinguishable failure gets its own variant and its own assertion
//! here.
//!
//! Two cases cannot be reached from outside the crate and live in unit tests
//! instead: a hostile padding length prefix inside an otherwise valid envelope
//! (`src/envelope/tests.rs::a_hostile_padding_prefix_inside_a_valid_envelope_is_rejected`)
//! and the frozen golden byte layouts.

use misty_crypto::backup::{self, BackupHeader};
use misty_crypto::derive;
use misty_crypto::envelope::{self, EnvelopeKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::kdf::{KdfParams, KdfTier};
use misty_crypto::keys::{EpochKey, RecoveryKey, VaultKey};
use misty_crypto::{recovery, DeviceId, Error, ItemId};

const EPOCH: u32 = 3;

fn identity(seed: u8) -> DeviceIdentity {
    DeviceIdentity::from_secret_bytes(
        DeviceId::from_bytes([seed; 16]),
        &[seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
    )
}

fn roster_of(identity: &DeviceIdentity) -> Roster {
    let record = identity.record("Device", "linux", 1, None).expect("record");
    let mut roster = Roster::new(vec![record]);
    roster.sign(identity).expect("sign");
    roster
}

fn epoch_key(epoch: u32) -> EpochKey {
    derive::epoch_key(&VaultKey::from_bytes([0x77; 32]), epoch).expect("epoch key")
}

fn item_id() -> ItemId {
    ItemId::from_bytes([0x78; 16])
}

fn sealed(identity: &DeviceIdentity) -> Vec<u8> {
    envelope::seal(
        EnvelopeKind::Item,
        EPOCH,
        &item_id(),
        b"negative path payload",
        &epoch_key(EPOCH),
        identity,
    )
    .expect("seal")
}

fn open_error(bytes: &[u8], item: &ItemId, key: &EpochKey, roster: &Roster) -> Error {
    envelope::open(bytes, item, key, roster).expect_err("must fail")
}

#[test]
fn envelope_bad_magic() {
    let identity = identity(0x10);
    let mut bytes = sealed(&identity);
    bytes[0] = b'X';
    assert!(matches!(
        open_error(&bytes, &item_id(), &epoch_key(EPOCH), &roster_of(&identity)),
        Error::BadEnvelopeMagic
    ));
}

#[test]
fn envelope_future_format_version() {
    let identity = identity(0x11);
    let mut bytes = sealed(&identity);
    bytes[4] = 2;
    assert!(matches!(
        open_error(&bytes, &item_id(), &epoch_key(EPOCH), &roster_of(&identity)),
        Error::UnsupportedFormatVersion {
            context: "envelope",
            found: 2,
            supported: 1
        }
    ));
}

#[test]
fn envelope_unknown_kind() {
    let identity = identity(0x12);
    let mut bytes = sealed(&identity);
    bytes[5] = 6;
    assert!(matches!(
        open_error(&bytes, &item_id(), &epoch_key(EPOCH), &roster_of(&identity)),
        Error::UnknownEnvelopeKind { found: 6 }
    ));
}

#[test]
fn envelope_truncated() {
    let identity = identity(0x13);
    let bytes = sealed(&identity);
    assert!(matches!(
        open_error(
            &bytes[..457],
            &item_id(),
            &epoch_key(EPOCH),
            &roster_of(&identity)
        ),
        Error::Truncated {
            context: "envelope",
            needed: 458,
            got: 457
        }
    ));
}

#[test]
fn envelope_malformed_body_length() {
    let identity = identity(0x14);
    let mut bytes = sealed(&identity);
    bytes.push(0);
    assert!(matches!(
        open_error(&bytes, &item_id(), &epoch_key(EPOCH), &roster_of(&identity)),
        Error::MalformedBody { .. }
    ));
}

#[test]
fn envelope_unknown_signer() {
    let writer = identity(0x15);
    let bytes = sealed(&writer);
    // A roster that knows a different device entirely.
    let other = identity(0x16);
    assert!(matches!(
        open_error(&bytes, &item_id(), &epoch_key(EPOCH), &roster_of(&other)),
        Error::UnknownSigner { signer } if signer == DeviceId::from_bytes([0x15; 16])
    ));
}

#[test]
fn envelope_tampered_header_ciphertext_and_signature() {
    let identity = identity(0x17);
    let roster = roster_of(&identity);
    let valid = sealed(&identity);

    for (label, offset) in [
        ("header epoch", 6usize),
        ("wik nonce", 26),
        ("wrapped item key", 80),
        ("ciphertext", 200),
        ("signature", 400),
    ] {
        let mut bytes = valid.clone();
        bytes[offset] ^= 0x01;
        assert!(
            matches!(
                open_error(&bytes, &item_id(), &epoch_key(EPOCH), &roster),
                Error::SignatureInvalid
            ),
            "{label}"
        );
    }
}

#[test]
fn envelope_wrong_item_id() {
    let identity = identity(0x18);
    let bytes = sealed(&identity);
    let elsewhere = ItemId::from_bytes([0x79; 16]);
    assert!(matches!(
        open_error(&bytes, &elsewhere, &epoch_key(EPOCH), &roster_of(&identity)),
        Error::SignatureInvalid
    ));
}

#[test]
fn envelope_wrong_epoch() {
    let identity = identity(0x19);
    let bytes = sealed(&identity);
    assert!(matches!(
        open_error(
            &bytes,
            &item_id(),
            &epoch_key(EPOCH + 1),
            &roster_of(&identity)
        ),
        Error::EpochMismatch {
            expected: 4,
            found: 3
        }
    ));
}

#[test]
fn envelope_wrong_epoch_key_bytes() {
    let identity = identity(0x1a);
    let bytes = sealed(&identity);
    let impostor = EpochKey::from_bytes(EPOCH, [0x99; 32]);
    assert!(matches!(
        open_error(&bytes, &item_id(), &impostor, &roster_of(&identity)),
        Error::ItemKeyUnwrapFailed
    ));
}

#[test]
fn envelope_payload_too_large() {
    let identity = identity(0x1b);
    let oversized = vec![0u8; 16 * 1024 * 1024 + 1];
    assert!(matches!(
        envelope::seal(
            EnvelopeKind::Item,
            EPOCH,
            &item_id(),
            &oversized,
            &epoch_key(EPOCH),
            &identity
        ),
        Err(Error::PayloadTooLarge {
            max: 16_777_216,
            ..
        })
    ));
}
#[test]
fn roster_errors_are_distinguishable() {
    let first = identity(0x20);
    let second = identity(0x21);

    let unsigned = Roster::new(vec![first.record("A", "linux", 1, None).unwrap()]);
    assert!(matches!(unsigned.verify(), Err(Error::RosterUnsigned)));

    // Signed by a device that is not a member.
    let mut roster = Roster::new(vec![first.record("A", "linux", 1, None).unwrap()]);
    assert!(matches!(
        roster.sign(&second),
        Err(Error::RosterSignerNotInRoster { signer }) if signer == DeviceId::from_bytes([0x21; 16])
    ));

    // Duplicate device.
    roster.sign(&first).unwrap();
    assert!(matches!(
        roster.add(first.record("A again", "linux", 2, None).unwrap()),
        Err(Error::DuplicateDevice { .. })
    ));

    // A tampered signature.
    let mut bad = roster.clone();
    let mut signature = *bad.signature.expect("signed").as_bytes();
    signature[0] ^= 0x01;
    bad.signature = Some(misty_crypto::SignatureBytes::from_bytes(signature));
    assert!(matches!(bad.verify(), Err(Error::RosterSignatureInvalid)));

    // A record whose public key is not a valid Ed25519 point. (`[0x02; 32]` is
    // not on the curve; `[0xff; 32]`, which looks more obviously wrong, happens
    // to decompress fine — which is exactly why this is asserted rather than
    // assumed.)
    let mut broken = roster.clone();
    broken.devices[0].ed25519_pub = [0x02; 32];
    assert!(matches!(broken.verify(), Err(Error::BadVerifyingKey)));

    // Over-long strings.
    assert!(matches!(
        first.record(&"n".repeat(65), "linux", 1, None),
        Err(Error::StringTooLong {
            field: "device name",
            max: 64
        })
    ));
    assert!(matches!(
        first.record("A", &"p".repeat(33), 1, None),
        Err(Error::StringTooLong {
            field: "device platform",
            max: 32
        })
    ));

    // Adding then removing leaves the roster unsigned again, so a revoked
    // device cannot be resurrected by replaying an old signature.
    let mut roster = roster.clone();
    assert!(roster.remove(&DeviceId::from_bytes([0x20; 16])));
    assert!(matches!(roster.verify(), Err(Error::RosterUnsigned)));
    assert!(!roster.remove(&DeviceId::from_bytes([0x20; 16])));
}

#[test]
fn backup_wrong_magic_version_reserved_and_costs() {
    let header = BackupHeader::new(KdfParams::new(32, 1, 1), [1; 16], [2; 24]);
    let mut file = header.to_bytes().to_vec();
    file.extend(core::iter::repeat_n(0u8, 32));

    let mut bad = file.clone();
    bad[0] = b'X';
    assert!(matches!(
        BackupHeader::parse(&bad),
        Err(Error::BadBackupMagic)
    ));

    let mut bad = file.clone();
    bad[8] = 2;
    assert!(matches!(
        BackupHeader::parse(&bad),
        Err(Error::UnsupportedFormatVersion {
            context: "backup",
            found: 2,
            supported: 1
        })
    ));

    let mut bad = file.clone();
    bad[9] = 2;
    assert!(matches!(
        BackupHeader::parse(&bad),
        Err(Error::UnknownKdfId { found: 2 })
    ));

    let mut bad = file.clone();
    bad[69] = 1;
    assert!(matches!(
        BackupHeader::parse(&bad),
        Err(Error::ReservedNotZero {
            context: "backup header"
        })
    ));

    let mut bad = file.clone();
    bad[10..14].copy_from_slice(&(64u32 * 1024 * 1024).to_le_bytes());
    assert!(matches!(
        BackupHeader::parse(&bad),
        Err(Error::KdfParamsRejected {
            memory_kib: 67_108_864,
            ..
        })
    ));

    assert!(matches!(
        BackupHeader::parse(&file[..69]),
        Err(Error::Truncated {
            context: "backup header",
            needed: 70,
            ..
        })
    ));
}

#[test]
fn backup_wrong_passphrase_and_tampering() {
    let file = backup::seal_bytes(b"right", KdfTier::Interactive, b"payload").expect("seal");
    assert!(matches!(
        backup::open_bytes(b"wrong", &file),
        Err(Error::BackupDecryptFailed)
    ));

    let mut tampered = file.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(matches!(
        backup::open_bytes(b"right", &tampered),
        Err(Error::BackupDecryptFailed)
    ));

    // And the successful path, so the test is not vacuous.
    assert_eq!(
        backup::open_bytes(b"right", &file)
            .expect("open")
            .as_slice(),
        b"payload"
    );
}

#[test]
fn recovery_errors_are_distinguishable() {
    let key = RecoveryKey::from_bytes([0x31; 32]);
    let kit = recovery::kit(&key);

    let words: Vec<&str> = kit.words().to_vec();
    assert!(matches!(
        recovery::from_words(&words[..12]),
        Err(Error::WrongWordCount {
            expected: 24,
            found: 12
        })
    ));

    let mut broken = words.clone();
    broken[0] = "notaword";
    assert!(matches!(
        recovery::from_words(&broken),
        Err(Error::UnknownWord { index: 0 })
    ));

    let mut swapped = words.clone();
    swapped.swap(3, 4);
    assert!(matches!(
        recovery::from_words(&swapped),
        Err(Error::WordChecksumMismatch)
    ));

    assert!(matches!(
        recovery::from_compact("SHORT"),
        Err(Error::BadCompactLength {
            expected: 58,
            found: 5
        })
    ));
    assert!(matches!(
        recovery::from_compact(&"U".repeat(58)),
        Err(Error::BadCompactChar { index: 0 })
    ));
    assert!(matches!(
        recovery::from_compact(&"0".repeat(58)),
        Err(Error::Crc32Mismatch)
    ));
    assert!(matches!(
        recovery::from_qr(kit.compact()),
        Err(Error::BadQrPrefix)
    ));
    assert!(matches!(
        recovery::unwrap_vault_key(&key, &[0u8; 71]),
        Err(Error::RecoveryBlobMalformed)
    ));
    assert!(matches!(
        recovery::unwrap_vault_key(&key, &[0u8; 72]),
        Err(Error::RecoveryUnwrapFailed)
    ));
}
