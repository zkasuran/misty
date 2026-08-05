// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Envelope unit tests, including the frozen golden-byte vectors.
//!
//! These live inside the module rather than in `tests/` for two reasons:
//!
//! * the golden vectors need [`seal_with`], the crate-private seam that accepts
//!   explicit keys and nonces — there is deliberately no public API that lets a
//!   caller choose a nonce;
//! * they must run on every `cargo test`, not only with `--all-features`. Format
//!   drift is the failure these catch, and it must never be possible to skip
//!   them.

use core::cell::Cell;

use hex_literal::hex;

use super::*;
use crate::derive;
use crate::identity::DeviceRecord;
use crate::keys::VaultKey;

thread_local! {
    /// Counts how many times [`Verified::open`] has entered the decryption
    /// stage on this thread. Thread-local because libtest gives each test its
    /// own thread; tests that read it reset it first so `--test-threads=1` is
    /// also correct.
    static DECRYPT_ATTEMPTS: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn note_decrypt_attempt() {
    DECRYPT_ATTEMPTS.with(|count| count.set(count.get() + 1));
}

fn reset_decrypt_attempts() {
    DECRYPT_ATTEMPTS.with(|count| count.set(0));
}

fn decrypt_attempts() -> usize {
    DECRYPT_ATTEMPTS.with(Cell::get)
}

/// RFC 8032 §7.1 TEST 1 secret key, reused as a fixed device key so the golden
/// vectors are reproducible by hand from published material.
const SIGNING_SECRET: [u8; 32] =
    hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const OTHER_SIGNING_SECRET: [u8; 32] =
    hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");

const DEVICE_ID: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
const OTHER_DEVICE_ID: [u8; 16] = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
const ITEM_ID: [u8; 16] = hex!("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
const VAULT_KEY: [u8; 32] = [0x11; 32];
const ITEM_KEY: [u8; 32] = [0x42; 32];
const GOLDEN_EPOCH: u32 = 7;
const GOLDEN_PAYLOAD: &[u8] = b"misty golden envelope payload";

fn identity() -> DeviceIdentity {
    DeviceIdentity::from_secret_bytes(DeviceId::from_bytes(DEVICE_ID), &SIGNING_SECRET, [0x33; 32])
}

fn other_identity() -> DeviceIdentity {
    DeviceIdentity::from_secret_bytes(
        DeviceId::from_bytes(OTHER_DEVICE_ID),
        &OTHER_SIGNING_SECRET,
        [0x44; 32],
    )
}

fn epoch_key(epoch: u32) -> EpochKey {
    derive::epoch_key(&VaultKey::from_bytes(VAULT_KEY), epoch).unwrap()
}

fn item_id() -> ItemId {
    ItemId::from_bytes(ITEM_ID)
}

fn record_for(identity: &DeviceIdentity, name: &str) -> DeviceRecord {
    identity
        .record(name, "linux", 1_700_000_000_000, None)
        .unwrap()
}

/// A roster containing only the golden device.
fn roster() -> Roster {
    let mut roster = Roster::new(vec![record_for(&identity(), "Golden Device")]);
    roster.sign(&identity()).unwrap();
    roster
}

/// Fixed nonces for the golden vectors: 0x20..=0x37 and 0x40..=0x57.
fn nonces() -> Nonces {
    Nonces {
        wik: hex!("202122232425262728292a2b2c2d2e2f3031323334353637"),
        payload: hex!("404142434445464748494a4b4c4d4e4f5051525354555657"),
    }
}

/// The frozen envelope: fixed device key, epoch key, item key and nonces.
fn golden_envelope() -> Vec<u8> {
    let identity = identity();
    let epoch_key = epoch_key(GOLDEN_EPOCH);
    let item_key = ItemKey::from_bytes(ITEM_KEY);
    let padded = pad(GOLDEN_PAYLOAD).unwrap();
    seal_with(
        &SealInputs {
            kind: EnvelopeKind::Item,
            item_id: &item_id(),
            epoch_key: &epoch_key,
            item_key: &item_key,
            identity: &identity,
            nonces: nonces(),
        },
        &padded,
    )
    .unwrap()
}
/// FROZEN GOLDEN VECTOR — self-generated, and the most important test here.
///
/// Every byte of an envelope, for fixed inputs. If this fails and the format
/// was not deliberately changed, something drifted: an offset, an endianness, a
/// nonce order, an AAD, the padding rule, or the signed message. If the format
/// *was* changed on purpose, [`ENVELOPE_FORMAT_VERSION`] must move with it.
///
/// Inputs (all fixed, none random):
///
/// ```text
/// signing key   RFC 8032 §7.1 TEST 1 secret, 9d61b19d..7f60
/// device_id     000102..0f
/// item_id       a0a1a2..af
/// vault key     0x11 * 32, so EK_7 = HKDF-SHA512 per SPEC 2.2
/// item key      0x42 * 32
/// wik_nonce     0x20..0x37
/// payload_nonce 0x40..0x57
/// kind          Item (1), epoch 7
/// payload       b"misty golden envelope payload" (29 bytes)
/// ```
///
/// The expected bytes were cross-checked against an independent
/// implementation: libsodium's `crypto_aead_xchacha20poly1305_ietf` and
/// Ed25519 via PyNaCl, with HKDF-SHA-512 written directly on Python's
/// `hmac`/`hashlib`. All four segments matched, so this vector pins the format
/// against something other than itself. libsodium cannot be used in the
/// product — it does not build for `wasm32-unknown-unknown` (SPEC §0) — but it
/// makes an excellent oracle.
#[test]
fn golden_envelope_bytes() {
    let sealed = golden_envelope();

    // 74 header + 48 wrapped key + (256 padded + 16 tag) + 64 signature.
    assert_eq!(sealed.len(), 458);
    assert_eq!(sealed.len(), MIN_ENVELOPE_LEN);

    let header = hex!(
        "4d535459" // magic "TOTM"
        "01" // format_version
        "01" // kind = Item
        "07000000" // epoch = 7, little-endian
        "000102030405060708090a0b0c0d0e0f" // signer_device_id
        "202122232425262728292a2b2c2d2e2f3031323334353637" // wik_nonce
        "404142434445464748494a4b4c4d4e4f5051525354555657" // payload_nonce
    );
    assert_eq!(&sealed[..HEADER_LEN], &header);
    assert_eq!(
        Header::parse(&sealed).unwrap().to_bytes(),
        header,
        "parse and serialise must agree byte for byte"
    );

    assert_eq!(
        &sealed[HEADER_LEN..HEADER_LEN + WRAPPED_ITEM_KEY_LEN],
        &WRAPPED_ITEM_KEY_GOLDEN,
        "wrapped_item_key"
    );
    assert_eq!(
        &sealed[HEADER_LEN + WRAPPED_ITEM_KEY_LEN..sealed.len() - SIGNATURE_LEN],
        &CIPHERTEXT_GOLDEN,
        "ciphertext"
    );
    assert_eq!(
        &sealed[sealed.len() - SIGNATURE_LEN..],
        &SIGNATURE_GOLDEN,
        "signature"
    );

    // And it opens, so the vector is not merely stable but correct.
    let opened = open(&sealed, &item_id(), &epoch_key(GOLDEN_EPOCH), &roster()).unwrap();
    assert_eq!(opened.as_slice(), GOLDEN_PAYLOAD);
}

/// Golden `wrapped_item_key`: `XChaCha20Poly1305(EK_7, wik_nonce, IK,
/// aad=Header||item_id)`.
const WRAPPED_ITEM_KEY_GOLDEN: [u8; 48] = hex!(
    "ad30804521f4a448c6cdc243991b8fa0706fbceda48e3aff27fb71ee63c88669"
    "d69529a9ad39ac423dd4138a0662a7e1"
);

/// Golden `ciphertext`: one 256-byte padding block plus a 16-byte tag.
const CIPHERTEXT_GOLDEN: [u8; 272] = hex!(
    "024c157bec77b6fa78fe75745688bd4beba685718eb436367ca89dfe4567d9a0"
    "4cd130f672493b8226146562783a08fe944efa2812bd719aa7f4980c6078db64"
    "0c3c20a6ef1bbe72da80da1c634aa3dc8ed2722a0df5282a7df93c4077fabf35"
    "953882bea759893f87ea8aec3f30ce0aba94b954c765ce6a8f2e15cbbc6cf238"
    "963f266106522dff9723d2468d8ed5232c5db2c613f673c68045526f1f98d009"
    "d2cc5a303e3fef4caabfd6140140f8acc9b4d81db03fe93a9622ec84a15a344a"
    "1394d7cccd98b12e94d5dcd1e90e66b48c15ebbdba3e55ddd2e736c14bb3ff74"
    "29e658315ef2d5464f917b487454eca4f39f4073bc427d36b6f739ca30f2630f"
    "b41175a0bfd4c7eaf18b0181a34426ab"
);

/// Golden `signature`: `Ed25519(Header||item_id||wrapped_item_key||ciphertext)`.
const SIGNATURE_GOLDEN: [u8; 64] = hex!(
    "7d1975127d2ee5a40b1700c797d3ebc66ba0e90251e84e750756ab904315860f"
    "fe52245e0f7cdcf3ee3751624a60ae3a235b7c8e1be87231b6f2650b5a2a1d08"
);

#[test]
fn round_trip_for_every_kind_and_epoch() {
    let identity = identity();
    for kind in [
        EnvelopeKind::Item,
        EnvelopeKind::DeviceRoster,
        EnvelopeKind::Settings,
        EnvelopeKind::Group,
        EnvelopeKind::CustomIcon,
    ] {
        for epoch in [0u32, 1, 7, u32::MAX] {
            let key = epoch_key(epoch);
            let sealed = seal(kind, epoch, &item_id(), b"payload", &key, &identity).unwrap();
            assert_eq!(Envelope::parse(&sealed).unwrap().header().kind, kind);
            assert_eq!(Envelope::parse(&sealed).unwrap().header().epoch, epoch);
            let opened = open(&sealed, &item_id(), &key, &roster()).unwrap();
            assert_eq!(opened.as_slice(), b"payload");
        }
    }
}

#[test]
fn two_seals_of_the_same_payload_differ() {
    // Fresh item key and fresh nonces every time; identical envelopes would
    // mean a broken nonce source.
    let identity = identity();
    let key = epoch_key(3);
    let a = seal(EnvelopeKind::Item, 3, &item_id(), b"x", &key, &identity).unwrap();
    let b = seal(EnvelopeKind::Item, 3, &item_id(), b"x", &key, &identity).unwrap();
    assert_ne!(a, b);
    assert_eq!(a.len(), b.len());
}

#[test]
fn envelope_length_buckets_to_256_bytes() {
    let identity = identity();
    let key = epoch_key(1);
    let overhead = HEADER_LEN + WRAPPED_ITEM_KEY_LEN + aead::TAG_LEN + SIGNATURE_LEN;
    for (payload_len, blocks) in [(0, 1), (251, 1), (252, 1), (253, 2), (508, 2), (509, 3)] {
        let sealed = seal(
            EnvelopeKind::Item,
            1,
            &item_id(),
            &vec![0xa5; payload_len],
            &key,
            &identity,
        )
        .unwrap();
        assert_eq!(
            sealed.len(),
            overhead + blocks * PAD_BLOCK,
            "payload of {payload_len} bytes"
        );
    }
}

#[test]
fn seal_rejects_an_epoch_that_disagrees_with_the_key() {
    let identity = identity();
    let key = epoch_key(4);
    assert!(matches!(
        seal(EnvelopeKind::Item, 5, &item_id(), b"x", &key, &identity),
        Err(Error::EpochMismatch {
            expected: 4,
            found: 5
        })
    ));
}
// --- the mandatory order: nothing is decrypted before verification ---

#[test]
fn an_envelope_from_an_unknown_signer_fails_before_any_decryption() {
    reset_decrypt_attempts();
    let sealed = seal(
        EnvelopeKind::Item,
        7,
        &item_id(),
        b"payload",
        &epoch_key(7),
        &other_identity(), // not in the roster
    )
    .unwrap();

    let error = open(&sealed, &item_id(), &epoch_key(7), &roster()).unwrap_err();
    assert!(
        matches!(error, Error::UnknownSigner { signer } if signer == DeviceId::from_bytes(OTHER_DEVICE_ID)),
        "got {error:?}"
    );
    assert_eq!(
        decrypt_attempts(),
        0,
        "decryption must not be attempted for an unknown signer"
    );
}

#[test]
fn a_tampered_ciphertext_fails_before_any_decryption() {
    reset_decrypt_attempts();
    let mut sealed = golden_envelope();
    let target = HEADER_LEN + WRAPPED_ITEM_KEY_LEN + 10;
    sealed[target] ^= 0x01;

    let error = open(&sealed, &item_id(), &epoch_key(GOLDEN_EPOCH), &roster()).unwrap_err();
    assert!(matches!(error, Error::SignatureInvalid), "got {error:?}");
    assert_eq!(
        decrypt_attempts(),
        0,
        "the signature covers the ciphertext, so tampering is caught before the AEAD runs"
    );
}

#[test]
fn a_tampered_header_fails_before_any_decryption() {
    for (offset, field) in [
        (0usize, "magic"),
        (4, "format_version"),
        (5, "kind"),
        (6, "epoch"),
        (10, "signer_device_id"),
        (26, "wik_nonce"),
        (50, "payload_nonce"),
    ] {
        reset_decrypt_attempts();
        let mut sealed = golden_envelope();
        sealed[offset] ^= 0x40;
        let error = open(&sealed, &item_id(), &epoch_key(GOLDEN_EPOCH), &roster()).unwrap_err();
        match offset {
            0 => assert!(
                matches!(error, Error::BadEnvelopeMagic),
                "{field}: {error:?}"
            ),
            4 => assert!(
                matches!(error, Error::UnsupportedFormatVersion { found: 0x41, .. }),
                "{field}: {error:?}"
            ),
            5 => assert!(
                matches!(error, Error::UnknownEnvelopeKind { found: 0x41 }),
                "{field}: {error:?}"
            ),
            10 => assert!(
                matches!(error, Error::UnknownSigner { .. }),
                "{field}: {error:?}"
            ),
            // Every other header byte is covered by the signature, including
            // the epoch: a rewritten epoch is a forged envelope, not an
            // epoch mismatch.
            _ => assert!(
                matches!(error, Error::SignatureInvalid),
                "{field}: {error:?}"
            ),
        }
        assert_eq!(decrypt_attempts(), 0, "tampered {field}");
    }
}

#[test]
fn a_tampered_signature_fails_before_any_decryption() {
    reset_decrypt_attempts();
    let mut sealed = golden_envelope();
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01;
    let error = open(&sealed, &item_id(), &epoch_key(GOLDEN_EPOCH), &roster()).unwrap_err();
    assert!(matches!(error, Error::SignatureInvalid), "got {error:?}");
    assert_eq!(decrypt_attempts(), 0);
}

#[test]
fn a_wrong_item_id_fails_before_any_decryption() {
    reset_decrypt_attempts();
    let sealed = golden_envelope();
    let elsewhere = ItemId::from_bytes([0x99; 16]);
    let error = open(&sealed, &elsewhere, &epoch_key(GOLDEN_EPOCH), &roster()).unwrap_err();
    // The signature covers item_id, so relocation is caught at step 3.
    assert!(matches!(error, Error::SignatureInvalid), "got {error:?}");
    assert_eq!(decrypt_attempts(), 0);
}
#[test]
fn aad_binding_holds_even_against_a_correctly_resigned_relocation() {
    // The strong form of the relocation test. An attacker who can also sign
    // (a compromised but still-rostered device, or the writer itself) rewrites
    // the signature so it is valid for a *different* item_id, leaving the
    // ciphertexts alone. Verification now passes, so this is the case where the
    // AAD is the only thing standing between the envelope and the wrong item.
    reset_decrypt_attempts();
    let sealed = golden_envelope();
    let elsewhere = ItemId::from_bytes([0x99; 16]);

    let mut forged = sealed.clone();
    let body_len = sealed.len() - SIGNATURE_LEN;
    let mut message = Vec::new();
    message.extend_from_slice(&sealed[..HEADER_LEN]);
    message.extend_from_slice(elsewhere.as_bytes());
    message.extend_from_slice(&sealed[HEADER_LEN..body_len]);
    let signature = identity().sign(&message);
    forged[body_len..].copy_from_slice(signature.as_bytes());

    // Signature verification passes for the new id...
    let envelope = Envelope::parse(&forged).unwrap();
    let verified = envelope.verify(&elsewhere, &roster()).unwrap();
    // ...and the AEAD still refuses, because item_id is in the AAD.
    let error = verified.open(&epoch_key(GOLDEN_EPOCH)).unwrap_err();
    assert!(matches!(error, Error::ItemKeyUnwrapFailed), "got {error:?}");
    assert_eq!(
        decrypt_attempts(),
        1,
        "this one is supposed to reach the AEAD"
    );

    // The same bytes still open under their real id.
    assert!(open(&sealed, &item_id(), &epoch_key(GOLDEN_EPOCH), &roster()).is_ok());
}

#[test]
fn the_wrong_epoch_key_is_rejected_with_a_typed_error_and_no_decryption() {
    reset_decrypt_attempts();
    let sealed = golden_envelope();
    let error = open(&sealed, &item_id(), &epoch_key(8), &roster()).unwrap_err();
    assert!(
        matches!(
            error,
            Error::EpochMismatch {
                expected: 8,
                found: 7
            }
        ),
        "got {error:?}"
    );
    assert_eq!(decrypt_attempts(), 0);
}

#[test]
fn an_epoch_key_with_the_right_number_but_wrong_bytes_fails_at_the_unwrap() {
    reset_decrypt_attempts();
    let sealed = golden_envelope();
    let impostor = EpochKey::from_bytes(GOLDEN_EPOCH, [0xee; 32]);
    let error = open(&sealed, &item_id(), &impostor, &roster()).unwrap_err();
    assert!(matches!(error, Error::ItemKeyUnwrapFailed), "got {error:?}");
    assert_eq!(decrypt_attempts(), 1);
}

#[test]
fn truncated_buffers_are_rejected() {
    let sealed = golden_envelope();
    for len in [0, 1, 73, 74, 121, 122, 185, 457] {
        let error = Envelope::parse(&sealed[..len]).unwrap_err();
        assert!(
            matches!(
                error,
                Error::Truncated {
                    needed: MIN_ENVELOPE_LEN,
                    ..
                }
            ),
            "len {len}: {error:?}"
        );
    }
    // Long enough, but the ciphertext is not 256n + 16.
    let mut ragged = sealed.clone();
    ragged.extend_from_slice(&[0u8; 3]);
    assert!(matches!(
        Envelope::parse(&ragged),
        Err(Error::MalformedBody { .. })
    ));
}

#[test]
fn a_hostile_padding_prefix_inside_a_valid_envelope_is_rejected() {
    // A correctly signed, correctly encrypted envelope whose *plaintext* is
    // malformed. Only the writer can produce this, but `unpad` must not trust
    // the length prefix even so.
    let identity = identity();
    let key = epoch_key(2);
    let item_key = ItemKey::from_bytes(ITEM_KEY);
    let mut hostile = vec![0u8; PAD_BLOCK];
    hostile[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let sealed = seal_with(
        &SealInputs {
            kind: EnvelopeKind::Item,
            item_id: &item_id(),
            epoch_key: &key,
            item_key: &item_key,
            identity: &identity,
            nonces: nonces(),
        },
        &hostile,
    )
    .unwrap();

    let error = open(&sealed, &item_id(), &key, &roster()).unwrap_err();
    assert!(
        matches!(
            error,
            Error::BadPaddingLength {
                declared: u32::MAX,
                available: 252
            }
        ),
        "got {error:?}"
    );
}

#[test]
fn the_bootstrap_path_verifies_against_an_explicit_key() {
    // Opening the roster envelope itself: the signer's key comes from an
    // enrollment grant, not from a roster we have not read yet.
    let identity = identity();
    let key = epoch_key(1);
    let sealed = seal(
        EnvelopeKind::DeviceRoster,
        1,
        &item_id(),
        b"roster bytes",
        &key,
        &identity,
    )
    .unwrap();

    let opened = open_with_signer(&sealed, &item_id(), &key, &identity.ed25519_public()).unwrap();
    assert_eq!(opened.as_slice(), b"roster bytes");

    let error = open_with_signer(
        &sealed,
        &item_id(),
        &key,
        &other_identity().ed25519_public(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::SignatureInvalid), "got {error:?}");
}

#[test]
fn an_unsigned_or_wrongly_signed_roster_does_not_open_anything() {
    // `open` trusts the roster it is given, so the caller must verify it. These
    // assertions pin the roster's own guarantees.
    let identity = identity();
    let unsigned = Roster::new(vec![record_for(&identity, "Golden Device")]);
    assert!(matches!(unsigned.verify(), Err(Error::RosterUnsigned)));

    let mut signed = roster();
    assert!(signed.verify().is_ok());
    if let Some(signature) = signed.signature.as_mut() {
        let mut bytes = *signature.as_bytes();
        bytes[0] ^= 0x01;
        *signature = crate::SignatureBytes::from_bytes(bytes);
    }
    assert!(matches!(
        signed.verify(),
        Err(Error::RosterSignatureInvalid)
    ));
}
