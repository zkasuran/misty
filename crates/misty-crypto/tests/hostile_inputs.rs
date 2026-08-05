// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A corpus of malformed envelopes and backup headers, run on stable CI.
//!
//! The `fuzz/` targets cover the same two entry points with coverage-guided
//! mutation, but they need nightly and a fuzzing run. This file is the part that
//! runs on every commit: fixed hostile inputs plus systematic mutations of a
//! valid object. The contract under test is narrow and absolute — **every input
//! either opens correctly or returns a typed error, and nothing panics.**

use misty_crypto::backup::{self, BackupHeader};
use misty_crypto::derive;
use misty_crypto::envelope::{self, Envelope, EnvelopeKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::kdf::KdfParams;
use misty_crypto::keys::{EpochKey, VaultKey};
use misty_crypto::{DeviceId, ItemId};

const EPOCH: u32 = 2;

/// Cheap Argon2 costs. The hostile-backup cases have to run the KDF to reach
/// the AEAD, and a real tier would make this file take minutes.
const FAST: KdfParams = KdfParams::new(32, 1, 1);

const PASSPHRASE: &[u8] = b"hostile input corpus";

/// Built once per test: the Ed25519 and HKDF work is the expensive part, and
/// these tests run hundreds of probes.
struct Fixture {
    roster: Roster,
    epoch_key: EpochKey,
    item_id: ItemId,
    valid: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let identity = DeviceIdentity::from_secret_bytes(
            DeviceId::from_bytes([0x41; 16]),
            &[0x42; 32],
            [0x43; 32],
        );
        let record = identity
            .record("Hostile Test", "linux", 1, None)
            .expect("record");
        let mut roster = Roster::new(vec![record]);
        roster.sign(&identity).expect("sign");

        let epoch_key =
            derive::epoch_key(&VaultKey::from_bytes([0x44; 32]), EPOCH).expect("epoch key");
        let item_id = ItemId::from_bytes([0x45; 16]);
        let valid = envelope::seal(
            EnvelopeKind::Item,
            EPOCH,
            &item_id,
            b"hostile input corpus",
            &epoch_key,
            &identity,
        )
        .expect("seal");

        Self {
            roster,
            epoch_key,
            item_id,
            valid,
        }
    }

    /// Every call must return. Nothing but the exact envelope may open.
    fn probe(&self, bytes: &[u8], label: &str) {
        let parsed = Envelope::parse(bytes);
        let opened = envelope::open(bytes, &self.item_id, &self.epoch_key, &self.roster);
        if opened.is_ok() {
            assert_eq!(bytes, self.valid.as_slice(), "{label}: a mutation opened");
        }
        if parsed.is_err() {
            assert!(opened.is_err(), "{label}: parse failed but open did not");
        }
    }
}

#[test]
fn fixed_hostile_envelopes() {
    let fixture = Fixture::new();
    let valid = fixture.valid.clone();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("one byte", vec![0]),
        ("magic only", b"MSTY".to_vec()),
        ("all zeros, minimum length", vec![0u8; 458]),
        ("all 0xff, minimum length", vec![0xffu8; 458]),
        ("header only", valid[..74].to_vec()),
        ("header and wrapped key", valid[..122].to_vec()),
        ("missing signature", valid[..valid.len() - 64].to_vec()),
        (
            "valid header, garbage body",
            valid[..74]
                .iter()
                .copied()
                .chain(core::iter::repeat_n(0xaa, 384))
                .collect(),
        ),
        (
            "valid envelope plus a whole extra block",
            valid
                .iter()
                .copied()
                .chain(core::iter::repeat_n(0u8, 256))
                .collect(),
        ),
        (
            "kind byte out of range",
            valid
                .iter()
                .enumerate()
                .map(|(index, byte)| if index == 5 { 0xff } else { *byte })
                .collect(),
        ),
    ];

    for (label, bytes) in cases {
        fixture.probe(&bytes, label);
    }
}

#[test]
fn every_truncation_of_a_valid_envelope() {
    let fixture = Fixture::new();
    let valid = fixture.valid.clone();
    for len in 0..=valid.len() {
        fixture.probe(&valid[..len], "truncation");
    }
}

#[test]
fn every_single_byte_of_a_valid_envelope_matters() {
    let fixture = Fixture::new();
    let valid = fixture.valid.clone();
    for offset in 0..valid.len() {
        let mut mutated = valid.clone();
        if let Some(byte) = mutated.get_mut(offset) {
            *byte ^= 0x80;
        }
        fixture.probe(&mutated, "bit flip");
    }
}

#[test]
fn extra_trailing_bytes_are_rejected() {
    let fixture = Fixture::new();
    for extra in 1..=8 {
        let mut longer = fixture.valid.clone();
        longer.extend(core::iter::repeat_n(0u8, extra));
        assert!(
            envelope::open(
                &longer,
                &fixture.item_id,
                &fixture.epoch_key,
                &fixture.roster
            )
            .is_err(),
            "{extra} extra bytes"
        );
    }
}
/// A valid backup file with deliberately cheap Argon2 costs, built through the
/// public header API so the hostile cases can afford to run the KDF.
fn cheap_backup() -> Vec<u8> {
    // `backup::seal_bytes` only accepts a tier (64 MiB and up), so the file is
    // assembled from the public header type. This is exactly the shape of a
    // file written by a device that chose low costs.
    let header = BackupHeader::new(FAST, [0x51; 16], [0x52; 24]);
    let mut file = header.to_bytes().to_vec();
    // A body that decrypts to nothing useful is fine: these tests are about not
    // panicking and about typed errors, and the one success case is checked in
    // `src/backup/tests.rs`.
    file.extend(core::iter::repeat_n(0u8, 64));
    file
}

#[test]
fn fixed_hostile_backup_headers() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("one byte", vec![0]),
        ("magic only", b"MISTYBAK".to_vec()),
        ("all zeros, header length", vec![0u8; 70]),
        ("all 0xff, header length", vec![0xffu8; 70]),
        ("all 0xff, header plus body", vec![0xffu8; 200]),
        ("69 bytes", vec![0x11u8; 69]),
        ("cheap but authentic-looking", cheap_backup()),
    ];

    for (label, bytes) in cases {
        // Neither call may panic.
        let parsed = BackupHeader::parse(&bytes);
        let opened = backup::open_bytes(PASSPHRASE, &bytes);
        assert!(opened.is_err(), "{label}: a hostile backup opened");
        if parsed.is_err() {
            assert!(opened.is_err(), "{label}");
        }
    }
}

#[test]
fn every_truncation_and_mutation_of_a_backup_header() {
    let file = cheap_backup();
    for len in 0..=file.len() {
        let _ = BackupHeader::parse(&file[..len]);
        let _ = backup::open_bytes(PASSPHRASE, &file[..len]);
    }
    // Mutate every byte of the header. Some mutations stay parseable (a
    // different salt is still a salt); none may open, and none may panic.
    for offset in 0..70 {
        for delta in [0x01u8, 0x80, 0xff] {
            let mut mutated = file.clone();
            if let Some(byte) = mutated.get_mut(offset) {
                *byte ^= delta;
            }
            let _ = BackupHeader::parse(&mutated);
            assert!(
                backup::open_bytes(PASSPHRASE, &mutated).is_err(),
                "offset {offset} delta {delta:#x} opened"
            );
        }
    }
}

#[test]
fn hostile_kdf_costs_in_a_header_never_run() {
    // Every combination of extreme costs. If any of these reached `argon2` the
    // test would either take hours or be killed by the OOM killer, so simply
    // completing is the assertion.
    let mut file = cheap_backup();
    for memory in [0u32, 1, 7, u32::MAX / 2, u32::MAX] {
        for iterations in [0u32, u32::MAX] {
            for parallelism in [0u32, u32::MAX] {
                file[10..14].copy_from_slice(&memory.to_le_bytes());
                file[14..18].copy_from_slice(&iterations.to_le_bytes());
                file[18..22].copy_from_slice(&parallelism.to_le_bytes());
                assert!(
                    BackupHeader::parse(&file).is_err(),
                    "m={memory} t={iterations} p={parallelism} was accepted"
                );
                assert!(backup::open_bytes(PASSPHRASE, &file).is_err());
            }
        }
    }
}

#[test]
fn recovery_decoders_never_panic() {
    use misty_crypto::recovery;

    let hostile: Vec<String> = vec![
        String::new(),
        "-".repeat(64),
        "0".repeat(58),
        "z".repeat(1000),
        "misty-recovery:v1:".to_owned(),
        "misty-recovery:v1:--------".to_owned(),
        "\u{1f600}".repeat(58),
        "abandon ".repeat(24),
    ];
    for text in &hostile {
        let _ = recovery::from_compact(text);
        let _ = recovery::from_qr(text);
        let words: Vec<&str> = text.split_whitespace().collect();
        let _ = recovery::from_words(&words);
        let _ = recovery::suggest_word_repairs(&words);
    }
    for len in 0..=80 {
        let blob = vec![0x5au8; len];
        let _ = recovery::unwrap_vault_key(
            &misty_crypto::keys::RecoveryKey::from_bytes([0x60; 32]),
            &blob,
        );
    }
}
