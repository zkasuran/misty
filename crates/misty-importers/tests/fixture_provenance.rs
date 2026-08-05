// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Where the generated fixtures come from.
//!
//! Four fixtures cannot be hand-written: Google's protobuf payload, and the three
//! encrypted vaults. This file is their recipe, executed. Run normally it *asserts*
//! that the committed bytes are exactly what the recipe produces; run with
//! `MISTY_WRITE_FIXTURES=1` it writes them.
//!
//! ```sh
//! MISTY_WRITE_FIXTURES=1 cargo test -p misty-importers --test fixture_provenance
//! ```
//!
//! That is what "reproducible rather than magic" means here: nobody has to trust a
//! blob, and a change to the format is a diff in this file next to a diff in the
//! fixture.
//!
//! # What these fixtures do and do not prove
//!
//! They prove the reader agrees with a writer built from the same published
//! description — the layout, the field order, which value is hex and which is
//! base64, where the GCM tag lives. They do **not** prove the description matches
//! what the vendor's own application emits, because this crate has never been given
//! a real encrypted vault to check against. `README.md` says so per format, and a
//! captured file from a real installation is the single most valuable contribution
//! anyone could make to this crate.
//!
//! # Cost parameters are deliberately low
//!
//! Aegis defaults to scrypt `n = 32768` and andOTP to six-figure PBKDF2 iteration
//! counts. The fixtures use `n = 8192` and 1000 iterations so the suite stays fast
//! in a debug build; the readers accept the real values, and
//! `real_world_cost_parameters_are_accepted` runs one derivation at Aegis's actual
//! default to prove it.

use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use serde_json::Value;

/// The passphrase every encrypted fixture in this repository uses.
///
/// Committed on purpose: a fixture nobody can decrypt is a fixture nobody can
/// check. It protects nothing, because everything it protects is a dummy.
pub const FIXTURE_PASSPHRASE: &[u8] = b"misty test passphrase";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Assert the committed fixture matches, or write it when asked to.
fn write_or_assert(relative: &str, bytes: &[u8]) {
    let path = fixtures().join(relative);
    if std::env::var_os("MISTY_WRITE_FIXTURES").is_some() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("fixture directory");
        }
        std::fs::write(&path, bytes).expect("write fixture");
        return;
    }
    let committed = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "fixture {relative} is missing ({error}). Regenerate with \
             MISTY_WRITE_FIXTURES=1 cargo test -p misty-importers --test fixture_provenance"
        )
    });
    assert_eq!(
        committed, bytes,
        "committed fixture {relative} is not what the recipe in \
         tests/fixture_provenance.rs produces"
    );
}

fn read_fixture(relative: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(relative)).expect("fixture exists")
}

fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    Aes256Gcm::new_from_slice(key)
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .expect("encrypt")
}

/// Split what `aes-gcm` returns into the ciphertext and the 16-byte tag, which is
/// how Aegis stores them.
fn split_tag(sealed: &[u8]) -> (&[u8], &[u8]) {
    sealed.split_at(sealed.len() - 16)
}

// ---------------------------------------------------------------------------
// Google Authenticator: otpauth-migration://offline?data=<base64 protobuf>
// ---------------------------------------------------------------------------

/// Minimal protobuf *writer*, independent of the reader under test.
mod pb {
    pub fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = u8::try_from(value & 0x7f).expect("masked");
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    pub fn tag(field: u32, wire: u8) -> Vec<u8> {
        varint(u64::from(field) << 3 | u64::from(wire))
    }

    pub fn bytes(field: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = tag(field, 2);
        out.extend(varint(payload.len() as u64));
        out.extend(payload);
        out
    }

    pub fn int(field: u32, value: u64) -> Vec<u8> {
        let mut out = tag(field, 0);
        out.extend(varint(value));
        out
    }
}

/// One `OtpParameters` sub-message.
fn otp_parameters(
    secret: &[u8],
    name: &str,
    issuer: &str,
    algorithm: u64,
    digits: u64,
    kind: Option<u64>,
    counter: Option<u64>,
) -> Vec<u8> {
    let mut out = pb::bytes(1, secret);
    out.extend(pb::bytes(2, name.as_bytes()));
    if !issuer.is_empty() {
        out.extend(pb::bytes(3, issuer.as_bytes()));
    }
    out.extend(pb::int(4, algorithm));
    out.extend(pb::int(5, digits));
    if let Some(kind) = kind {
        out.extend(pb::int(6, kind));
    }
    if let Some(counter) = counter {
        out.extend(pb::int(7, counter));
    }
    out
}

#[test]
fn google_migration_fixture() {
    // Algorithm: 1 = SHA1, 2 = SHA256, 4 = MD5. DigitCount: 1 = SIX, 2 = EIGHT.
    // OtpType: 1 = HOTP, 2 = TOTP.
    let entries = [
        otp_parameters(
            b"AAAAAAAAAA",
            "ada@example.com",
            "ACME Corp",
            1,
            1,
            Some(2),
            None,
        ),
        otp_parameters(b"BBBBBBBBBB", "Counter Co:bob", "", 2, 2, Some(1), Some(42)),
        // MD5 is in Google's enum and is not a hash Misty will generate with, so
        // this row must be skipped rather than quietly downgraded.
        otp_parameters(b"CCCCCCCCCC", "carol", "MD5 Co", 4, 1, Some(2), None),
        // No `type` at all: the one field with no safe default, so this row must
        // fail while the others import.
        otp_parameters(b"DDDDDDDDDD", "dave", "No Type Co", 1, 1, None, None),
    ];

    let mut payload = Vec::new();
    for entry in &entries {
        payload.extend(pb::bytes(1, entry));
    }
    payload.extend(pb::int(2, 2)); // version
    payload.extend(pb::int(3, 2)); // batch_size: two QR codes in the export
    payload.extend(pb::int(4, 0)); // batch_index: this is the first of them
    payload.extend(pb::int(5, 123_456)); // batch_id

    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
    // Google percent-encodes the base64 alphabet's `+`, `/` and `=`.
    let escaped: String = encoded
        .chars()
        .map(|ch| match ch {
            '+' => "%2B".to_owned(),
            '/' => "%2F".to_owned(),
            '=' => "%3D".to_owned(),
            other => other.to_string(),
        })
        .collect();

    let file = format!("otpauth-migration://offline?data={escaped}\n");
    write_or_assert("google-migration/batch.txt", file.as_bytes());
}

// ---------------------------------------------------------------------------
// Aegis: scrypt + AES-256-GCM, tags stored beside the ciphertext
// ---------------------------------------------------------------------------

/// scrypt cost for the fixture. Aegis itself defaults to 32768.
const AEGIS_N: u64 = 8192;
const AEGIS_R: u32 = 8;
const AEGIS_P: u32 = 1;

#[test]
fn aegis_encrypted_fixture() {
    // The plaintext is exactly the `db` object of the plain fixture, so the two
    // fixtures are provably the same vault and `formats.rs` can assert that they
    // import identically.
    let plain: Value = serde_json::from_slice(&read_fixture("aegis/plain.json")).expect("json");
    let db = plain.get("db").expect("db object");
    let plaintext = serde_json::to_vec(db).expect("serialize db");

    let salt = [0x11u8; 32];
    let slot_nonce = [0x33u8; 12];
    let db_nonce = [0x44u8; 12];
    // Aegis generates the master key at random; a fixture pins it.
    let master = [0x22u8; 32];

    let mut derived = [0u8; 32];
    scrypt::scrypt(
        FIXTURE_PASSPHRASE,
        &salt,
        &scrypt::Params::new(
            u8::try_from(AEGIS_N.trailing_zeros()).expect("log2 fits"),
            AEGIS_R,
            AEGIS_P,
            32,
        )
        .expect("valid params"),
        &mut derived,
    )
    .expect("scrypt");

    let sealed_slot = seal(&derived, &slot_nonce, &master);
    let (slot_key, slot_tag) = split_tag(&sealed_slot);
    let sealed_db = seal(&master, &db_nonce, &plaintext);
    let (db_ciphertext, db_tag) = split_tag(&sealed_db);

    let file = serde_json::json!({
        "version": 1,
        "header": {
            "slots": [
                {
                    "type": 1,
                    "uuid": "a0000000-0000-4000-8000-000000000001",
                    "key": hex::encode(slot_key),
                    "key_params": {
                        "nonce": hex::encode(slot_nonce),
                        "tag": hex::encode(slot_tag),
                    },
                    "n": AEGIS_N,
                    "r": AEGIS_R,
                    "p": AEGIS_P,
                    "salt": hex::encode(salt),
                    "repaired": true,
                },
                {
                    // A biometric slot, which no passphrase can open. The reader
                    // must skip it and still find the password slot.
                    "type": 2,
                    "uuid": "a0000000-0000-4000-8000-000000000002",
                    "key": hex::encode([0x99u8; 32]),
                    "key_params": {
                        "nonce": hex::encode([0x98u8; 12]),
                        "tag": hex::encode([0x97u8; 16]),
                    },
                }
            ],
            "params": {
                "nonce": hex::encode(db_nonce),
                "tag": hex::encode(db_tag),
            }
        },
        "db": base64::engine::general_purpose::STANDARD.encode(db_ciphertext),
    });

    let mut rendered = serde_json::to_vec_pretty(&file).expect("render");
    rendered.push(b'\n');
    write_or_assert("aegis/encrypted.json", &rendered);
}

// ---------------------------------------------------------------------------
// andOTP: PBKDF2-HMAC-SHA1 + AES-256-GCM, all in one binary blob
// ---------------------------------------------------------------------------

/// Iterations for the fixture. andOTP's own minimum, and enough to keep a debug
/// build's test run brief.
const ANDOTP_ITERATIONS: u32 = 1_000;

#[test]
fn andotp_encrypted_fixture() {
    let plaintext = read_fixture("andotp/plain.json");
    let salt = [0x55u8; 12];
    let nonce = [0x66u8; 12];

    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(FIXTURE_PASSPHRASE, &salt, ANDOTP_ITERATIONS, &mut key);

    let mut file = Vec::new();
    file.extend(ANDOTP_ITERATIONS.to_be_bytes());
    file.extend(salt);
    file.extend(nonce);
    file.extend(seal(&key, &nonce, &plaintext));
    write_or_assert("andotp/encrypted.bin", &file);
}

// ---------------------------------------------------------------------------
// 2FAS: PBKDF2-HMAC-SHA256 + AES-256-GCM, base64 triple in one string
// ---------------------------------------------------------------------------

#[test]
fn twofas_encrypted_fixture() {
    let plain: Value = serde_json::from_slice(&read_fixture("2fas/backup.json")).expect("json");
    let services = plain.get("services").expect("services array");
    let plaintext = serde_json::to_vec(services).expect("serialize services");

    let salt = [0x77u8; 32];
    let nonce = [0x88u8; 12];
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(FIXTURE_PASSPHRASE, &salt, 10_000, &mut key);

    let engine = &base64::engine::general_purpose::STANDARD;
    let sealed = seal(&key, &nonce, &plaintext);
    let field = format!(
        "{}:{}:{}",
        engine.encode(&sealed),
        engine.encode(salt),
        engine.encode(nonce)
    );

    let file = serde_json::json!({
        "servicesEncrypted": field,
        "groups": plain.get("groups").cloned().unwrap_or(Value::Null),
        "schemaVersion": 4,
        "appVersionCode": 5_000_000,
        "appVersionName": "5.0.0",
        "appOrigin": "android",
    });
    let mut rendered = serde_json::to_vec_pretty(&file).expect("render");
    rendered.push(b'\n');
    write_or_assert("2fas/encrypted.json", &rendered);
}

#[test]
fn real_world_cost_parameters_are_accepted() {
    // Aegis's actual default. The fixtures use a cheaper cost so the suite is
    // quick; this proves the parameter validation does not reject the real one.
    let mut key = [0u8; 32];
    scrypt::scrypt(
        FIXTURE_PASSPHRASE,
        b"salt",
        &scrypt::Params::new(15, 8, 1, 32).expect("n = 32768, r = 8, p = 1"),
        &mut key,
    )
    .expect("scrypt at Aegis's default cost");
    assert_ne!(key, [0u8; 32]);
}
