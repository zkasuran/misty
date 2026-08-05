// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SPEC §6.3 enrollment flow, end to end, plus everything that must fail.

use misty_crypto::derive;
use misty_crypto::enrollment::{self, GrantContents, NewDeviceEnrollment};
use misty_crypto::envelope::{self, EnvelopeKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::keys::VaultKey;
use misty_crypto::{DeviceId, Error, ItemId, VaultId};

const EPOCH: u32 = 9;

fn approver() -> DeviceIdentity {
    DeviceIdentity::from_secret_bytes(DeviceId::from_bytes([0x01; 16]), &[0x02; 32], [0x03; 32])
}

fn newcomer() -> DeviceIdentity {
    DeviceIdentity::from_secret_bytes(DeviceId::from_bytes([0x11; 16]), &[0x12; 32], [0x13; 32])
}

fn vault_id() -> VaultId {
    VaultId::from_bytes([0x21; 16])
}

/// The approver's roster, already containing the new device and re-signed —
/// the state SPEC §6.3 step 3 requires before the grant is sealed.
fn roster_with_both(approver: &DeviceIdentity, newcomer: &DeviceIdentity) -> Roster {
    let mut roster = Roster::new(vec![approver
        .record("Ada's Desktop", "linux", 1_700_000_000_000, None)
        .expect("record")]);
    roster
        .add(
            newcomer
                .record(
                    "Ada's Pixel",
                    "android",
                    1_700_000_100_000,
                    Some(approver.device_id()),
                )
                .expect("record"),
        )
        .expect("add");
    roster.sign(approver).expect("sign");
    roster
}

#[test]
fn the_happy_path() {
    let approver = approver();
    let newcomer = newcomer();
    let vault_key = VaultKey::from_bytes([0x31; 32]);

    // 1. The new device publishes its request and a 6-digit code.
    let enrollment =
        NewDeviceEnrollment::begin(&newcomer, "Ada's Pixel", "android").expect("begin");
    let code = enrollment.confirmation_code();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(enrollment.request().device_id, newcomer.device_id());
    assert_eq!(enrollment.request().ed25519_pub, newcomer.ed25519_public());

    // 2 and 3. The approver compares the code out of band, adds the device to
    // the roster, re-signs, and seals the grant.
    let roster = roster_with_both(&approver, &newcomer);
    let sealed = enrollment::approve(
        enrollment.request(),
        &code,
        &GrantContents {
            vault_id: vault_id(),
            vault_key: &vault_key,
            epoch: EPOCH,
            server_url: "https://sync.example.com",
            roster: &roster,
        },
        &approver,
    )
    .expect("approve");

    // 4. The new device unseals and checks the chain.
    let grant = enrollment.open(&sealed).expect("open");
    assert_eq!(grant.vault_id, vault_id());
    assert_eq!(grant.epoch, EPOCH);
    assert_eq!(grant.server_url, "https://sync.example.com");
    assert!(grant.vault_key.constant_time_eq(&vault_key));
    assert_eq!(grant.roster.devices.len(), 2);
    assert!(grant.roster.contains(&newcomer.device_id()).is_some());
    grant.roster.verify().expect("delivered roster verifies");

    // And the grant is actually usable: the new device can now open what the
    // approver wrote.
    let epoch_key = derive::epoch_key(&grant.vault_key, EPOCH).expect("epoch key");
    let item_id = ItemId::from_bytes([0x41; 16]);
    let written = envelope::seal(
        EnvelopeKind::Item,
        EPOCH,
        &item_id,
        b"an item written before enrollment",
        &derive::epoch_key(&vault_key, EPOCH).expect("epoch key"),
        &approver,
    )
    .expect("seal");
    let opened = envelope::open(&written, &item_id, &epoch_key, &grant.roster).expect("open");
    assert_eq!(opened.as_slice(), b"an item written before enrollment");
}

#[test]
fn the_confirmation_code_gates_approval() {
    let approver = approver();
    let newcomer = newcomer();
    let vault_key = VaultKey::from_bytes([0x32; 32]);
    let enrollment =
        NewDeviceEnrollment::begin(&newcomer, "Ada's Pixel", "android").expect("begin");
    let roster = roster_with_both(&approver, &newcomer);
    let contents = GrantContents {
        vault_id: vault_id(),
        vault_key: &vault_key,
        epoch: EPOCH,
        server_url: "https://sync.example.com",
        roster: &roster,
    };

    for wrong in ["000000", "12345", "1234567", "", "abcdef"] {
        assert!(
            matches!(
                enrollment::approve(enrollment.request(), wrong, &contents, &approver),
                Err(Error::ConfirmationCodeMismatch)
            ),
            "code {wrong:?} should not have been accepted"
        );
    }
    // Surrounding whitespace is what a user types, and is tolerated.
    let padded = format!("  {}  ", enrollment.confirmation_code());
    assert!(enrollment::approve(enrollment.request(), &padded, &contents, &approver).is_ok());
}

#[test]
fn the_code_changes_if_any_field_is_substituted() {
    // The whole point of the 6-digit code: a server that rewrites the QR
    // payload cannot keep the code the user is reading aloud.
    let newcomer = newcomer();
    let enrollment =
        NewDeviceEnrollment::begin(&newcomer, "Ada's Pixel", "android").expect("begin");
    let original = enrollment.request().clone();
    let code = original.confirmation_code();

    let mut substituted = original.clone();
    substituted.x25519_pub = [0x99; 32];
    assert_ne!(substituted.confirmation_code(), code, "x25519_pub");

    let mut substituted = original.clone();
    substituted.ed25519_pub = [0x99; 32];
    assert_ne!(substituted.confirmation_code(), code, "ed25519_pub");

    let mut substituted = original.clone();
    substituted.device_id = DeviceId::from_bytes([0x99; 16]);
    assert_ne!(substituted.confirmation_code(), code, "device_id");

    let mut substituted = original.clone();
    substituted.name = "Ada's Pixe1".to_owned();
    assert_ne!(substituted.confirmation_code(), code, "name");

    // And the encoding is unambiguous across the two length-prefixed strings.
    let mut shifted = original.clone();
    shifted.name = "AB".to_owned();
    shifted.platform = "C".to_owned();
    let mut other = original.clone();
    other.name = "A".to_owned();
    other.platform = "BC".to_owned();
    assert_ne!(shifted.confirmation_code(), other.confirmation_code());
}
#[test]
fn a_grant_delivering_a_roster_without_the_new_device_is_refused() {
    let approver = approver();
    let newcomer = newcomer();
    let vault_key = VaultKey::from_bytes([0x33; 32]);
    let enrollment =
        NewDeviceEnrollment::begin(&newcomer, "Ada's Pixel", "android").expect("begin");

    // The approver forgot to add the new device before signing.
    let mut roster = Roster::new(vec![approver
        .record("Ada's Desktop", "linux", 1, None)
        .expect("record")]);
    roster.sign(&approver).expect("sign");

    assert!(matches!(
        enrollment::approve(
            enrollment.request(),
            &enrollment.confirmation_code(),
            &GrantContents {
                vault_id: vault_id(),
                vault_key: &vault_key,
                epoch: EPOCH,
                server_url: "https://sync.example.com",
                roster: &roster,
            },
            &approver,
        ),
        Err(Error::DeviceNotInRoster { .. })
    ));
}

#[test]
fn an_unsigned_roster_cannot_be_granted() {
    let approver = approver();
    let newcomer = newcomer();
    let vault_key = VaultKey::from_bytes([0x34; 32]);
    let enrollment =
        NewDeviceEnrollment::begin(&newcomer, "Ada's Pixel", "android").expect("begin");

    let mut roster = roster_with_both(&approver, &newcomer);
    roster.signature = None;
    roster.signed_by = None;

    assert!(matches!(
        enrollment::approve(
            enrollment.request(),
            &enrollment.confirmation_code(),
            &GrantContents {
                vault_id: vault_id(),
                vault_key: &vault_key,
                epoch: EPOCH,
                server_url: "https://sync.example.com",
                roster: &roster,
            },
            &approver,
        ),
        Err(Error::RosterUnsigned)
    ));
}

#[test]
fn a_sealed_grant_cannot_be_replayed_into_another_enrollment() {
    let approver = approver();
    let newcomer = newcomer();
    let vault_key = VaultKey::from_bytes([0x35; 32]);
    let roster = roster_with_both(&approver, &newcomer);
    let contents = GrantContents {
        vault_id: vault_id(),
        vault_key: &vault_key,
        epoch: EPOCH,
        server_url: "https://sync.example.com",
        roster: &roster,
    };

    let first = NewDeviceEnrollment::begin(&newcomer, "Ada's Pixel", "android").expect("begin");
    let sealed = enrollment::approve(
        first.request(),
        &first.confirmation_code(),
        &contents,
        &approver,
    )
    .expect("approve");

    // A second attempt has a different enroll_id and a different ephemeral key.
    let second = NewDeviceEnrollment::begin(&newcomer, "Ada's Pixel", "android").expect("begin");
    assert!(matches!(second.open(&sealed), Err(Error::EnrollIdMismatch)));

    // Even with the enroll_id forced to match, the ephemeral key does not.
    let mut relabelled = sealed.clone();
    relabelled.enroll_id = second.request().enroll_id;
    assert!(matches!(
        second.open(&relabelled),
        Err(Error::EnrollmentUnsealFailed)
    ));

    // And the original still opens, so the test is not vacuous.
    assert!(first.open(&sealed).is_ok());
}

#[test]
fn a_tampered_sealed_grant_is_refused() {
    let approver = approver();
    let newcomer = newcomer();
    let vault_key = VaultKey::from_bytes([0x36; 32]);
    let roster = roster_with_both(&approver, &newcomer);
    let enrollment =
        NewDeviceEnrollment::begin(&newcomer, "Ada's Pixel", "android").expect("begin");
    let sealed = enrollment::approve(
        enrollment.request(),
        &enrollment.confirmation_code(),
        &GrantContents {
            vault_id: vault_id(),
            vault_key: &vault_key,
            epoch: EPOCH,
            server_url: "https://sync.example.com",
            roster: &roster,
        },
        &approver,
    )
    .expect("approve");

    // Ciphertext.
    let mut bad = sealed.clone();
    bad.ciphertext[0] ^= 0x01;
    assert!(matches!(
        enrollment.open(&bad),
        Err(Error::EnrollmentUnsealFailed)
    ));

    // Nonce.
    let mut bad = sealed.clone();
    bad.nonce[0] ^= 0x01;
    assert!(matches!(
        enrollment.open(&bad),
        Err(Error::EnrollmentUnsealFailed)
    ));

    // Approver's ephemeral public key.
    let mut bad = sealed.clone();
    bad.approver_x25519_pub[0] ^= 0x01;
    assert!(matches!(
        enrollment.open(&bad),
        Err(Error::EnrollmentUnsealFailed)
    ));

    // Approver's claimed identity: the AAD covers it, so the AEAD objects
    // before the signature check is even reached.
    let mut bad = sealed.clone();
    bad.approver_device_id = DeviceId::from_bytes([0xaa; 16]);
    assert!(matches!(
        enrollment.open(&bad),
        Err(Error::EnrollmentUnsealFailed)
    ));

    // Signature.
    let mut signature = *sealed.signature.as_bytes();
    signature[0] ^= 0x01;
    let mut bad = sealed.clone();
    bad.signature = misty_crypto::SignatureBytes::from_bytes(signature);
    assert!(matches!(
        enrollment.open(&bad),
        Err(Error::EnrollmentSignatureInvalid)
    ));

    // Unmodified, it opens.
    assert!(enrollment.open(&sealed).is_ok());
}

#[test]
fn over_long_fields_are_refused() {
    let newcomer = newcomer();
    assert!(matches!(
        NewDeviceEnrollment::begin(&newcomer, &"n".repeat(65), "android"),
        Err(Error::StringTooLong {
            field: "device name",
            ..
        })
    ));
    assert!(matches!(
        NewDeviceEnrollment::begin(&newcomer, "Ada's Pixel", &"p".repeat(33)),
        Err(Error::StringTooLong {
            field: "device platform",
            ..
        })
    ));

    let approver = approver();
    let newcomer_enrollment =
        NewDeviceEnrollment::begin(&newcomer, "Ada's Pixel", "android").expect("begin");
    let vault_key = VaultKey::from_bytes([0x37; 32]);
    let roster = roster_with_both(&approver, &newcomer);
    assert!(matches!(
        enrollment::approve(
            newcomer_enrollment.request(),
            &newcomer_enrollment.confirmation_code(),
            &GrantContents {
                vault_id: vault_id(),
                vault_key: &vault_key,
                epoch: EPOCH,
                server_url: &"u".repeat(513),
                roster: &roster,
            },
            &approver,
        ),
        Err(Error::StringTooLong {
            field: "server_url",
            ..
        })
    ));
}
