// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One test per format, asserting the exact parsed model.
//!
//! Every assertion goes through `common::check`, which compares issuer, account,
//! kind, algorithm, digit count, period, counter, secret bytes, PIN, note,
//! nickname, tags, groups, origins, favourite, archived and source. A test that
//! passes here has pinned the whole model, not the two fields somebody remembered.
//!
//! The fixtures are in `tests/fixtures/<slug>/`. Every secret in them is an obvious
//! dummy — `AAAAAAAAAAAAAAAA` and friends — and no real enrolment exists anywhere in
//! this repository. `tests/fixture_provenance.rs` documents where the four generated
//! fixtures come from.

mod common;

use common::{b32, check, hex_secret, import_detected, import_with, item, outcome_kinds, Expect};
use misty_importers::{
    AegisImporter, AndOtpImporter, ColumnMapping, CsvImporter, DuplicatePolicy, EnteAuthImporter,
    ExistingItems, ImportContext, ImportError, ImportWarning, Importer, JsonImporter, RowOutcome,
    SkipReason, SourceFormat, TwoFasImporter,
};
use misty_otp::{HashAlg, OtpKind};

const PASSPHRASE: &[u8] = common::FIXTURE_PASSPHRASE;

// ---------------------------------------------------------------------------
// otpauth:// URIs
// ---------------------------------------------------------------------------

#[test]
fn otpauth_uri_list() {
    let ctx = ImportContext::new();
    let report = import_detected("otpauth/uris.txt", &ctx);

    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "imported", "imported", "imported", "failed", "imported"]
    );

    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            algorithm: HashAlg::Sha256,
            digits: 8,
            period: 60,
            secret: b32("AAAAAAAAAAAAAAAA"),
            ..Expect::default()
        },
    );
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("GitHub"),
            account: "bob",
            kind: OtpKind::Hotp,
            counter: 42,
            secret: b32("BBBBBBBBBBBBBBBB"),
            ..Expect::default()
        },
    );
    check(
        item(&report, 2),
        &Expect {
            issuer: Some("Valve"),
            account: "carol",
            kind: OtpKind::Steam,
            digits: 5,
            secret: b32("CCCCCCCCCCCCCCCC"),
            ..Expect::default()
        },
    );
    check(
        item(&report, 3),
        &Expect {
            issuer: Some("Bank"),
            account: "dave",
            kind: OtpKind::Motp,
            period: 10,
            secret: hex_secret("aaaaaaaaaaaaaaaa"),
            pin: Some(b"1234"),
            ..Expect::default()
        },
    );
    check(
        item(&report, 4),
        &Expect {
            issuer: Some("Yandex"),
            account: "erin",
            kind: OtpKind::Yandex,
            algorithm: HashAlg::Sha256,
            digits: 8,
            secret: b32("DDDDDDDDDDDDDDDD"),
            pin: Some(b"1234"),
            ..Expect::default()
        },
    );
    check(
        item(&report, 5),
        &Expect {
            issuer: Some("日本銀行"),
            account: "fay",
            secret: b32("EEEEEEEEEEEEEEEE"),
            ..Expect::default()
        },
    );
}

// ---------------------------------------------------------------------------
// Google Authenticator
// ---------------------------------------------------------------------------

#[test]
fn google_migration_protobuf() {
    let ctx = ImportContext::new();
    let report = import_detected("google-migration/batch.txt", &ctx);

    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "skipped", "failed"]
    );

    // The secret is raw bytes in the protobuf, not base32 text.
    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            secret: b"AAAAAAAAAA".to_vec(),
            source: SourceFormat::GoogleMigration,
            ..Expect::default()
        },
    );
    // No `issuer` field: the `Issuer:account` label is split, as `otpauth://` does.
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Counter Co"),
            account: "bob",
            kind: OtpKind::Hotp,
            algorithm: HashAlg::Sha256,
            digits: 8,
            counter: 42,
            secret: b"BBBBBBBBBB".to_vec(),
            source: SourceFormat::GoogleMigration,
            ..Expect::default()
        },
    );

    // MD5 is in Google's enum and is not a hash Misty generates with.
    assert!(matches!(
        &report.outcomes[2],
        RowOutcome::Skipped {
            reason: SkipReason::UnsupportedAlgorithm(name),
            ..
        } if name == "MD5"
    ));
    // A missing `type` is refused rather than guessed.
    assert!(matches!(&report.outcomes[3], RowOutcome::Failed { .. }));

    // One QR code of a two-code export: the report says which part is missing.
    assert!(!report.is_complete_batch());
    assert_eq!(report.missing_batch_parts(), vec![1]);
}

// ---------------------------------------------------------------------------
// Aegis
// ---------------------------------------------------------------------------

/// What both Aegis fixtures must produce. Written once because the encrypted
/// fixture's plaintext *is* the plain fixture's `db`, which is what makes
/// "the two fixtures are the same vault" a checkable claim.
fn check_aegis(report: &misty_importers::ImportReport) {
    assert_eq!(
        outcome_kinds(report),
        vec![
            "imported", "imported", "imported", "imported", "imported", "imported", "skipped",
            "failed"
        ]
    );
    check(
        item(report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            secret: b32("AAAAAAAAAAAAAAAA"),
            note: Some("first line\nsecond line"),
            groups: &["Work"],
            favorite: true,
            source: SourceFormat::Aegis,
            ..Expect::default()
        },
    );
    check(
        item(report, 1),
        &Expect {
            issuer: Some("Long Period"),
            account: "bob",
            algorithm: HashAlg::Sha512,
            digits: 8,
            period: 60,
            secret: b32("BBBBBBBBBBBBBBBB"),
            source: SourceFormat::Aegis,
            ..Expect::default()
        },
    );
    check(
        item(report, 2),
        &Expect {
            issuer: Some("Counter Co"),
            account: "carol",
            kind: OtpKind::Hotp,
            counter: 7,
            secret: b32("CCCCCCCCCCCCCCCC"),
            source: SourceFormat::Aegis,
            ..Expect::default()
        },
    );
    check(
        item(report, 3),
        &Expect {
            issuer: Some("Valve"),
            account: "dave",
            kind: OtpKind::Steam,
            digits: 5,
            secret: b32("DDDDDDDDDDDDDDDD"),
            source: SourceFormat::Aegis,
            ..Expect::default()
        },
    );
    check(
        item(report, 4),
        &Expect {
            issuer: Some("Bank"),
            account: "erin",
            kind: OtpKind::Motp,
            period: 10,
            secret: hex_secret("aaaaaaaaaaaaaaaa"),
            pin: Some(b"1234"),
            source: SourceFormat::Aegis,
            ..Expect::default()
        },
    );
    check(
        item(report, 5),
        &Expect {
            issuer: Some("Yandex"),
            account: "fay",
            kind: OtpKind::Yandex,
            algorithm: HashAlg::Sha256,
            digits: 8,
            secret: b32("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"),
            pin: Some(b"5678"),
            source: SourceFormat::Aegis,
            ..Expect::default()
        },
    );
}

#[test]
fn aegis_plain_vault() {
    let ctx = ImportContext::new();
    let report = import_detected("aegis/plain.json", &ctx);
    check_aegis(&report);

    // The embedded icon on the second entry is reported as dropped, not silently
    // discarded.
    assert!(matches!(
        &report.outcomes[1],
        RowOutcome::Imported { warnings, .. }
            if warnings.contains(&ImportWarning::DroppedField("icon"))
    ));
    // A Yandex secret longer than 16 bytes: only the prefix keys the code, and the
    // row says so.
    assert!(matches!(
        &report.outcomes[5],
        RowOutcome::Imported { warnings, .. }
            if warnings.contains(&ImportWarning::SecretPrefixUsed(16))
    ));
    // The unsupported type is skipped by name.
    assert!(matches!(
        &report.outcomes[6],
        RowOutcome::Skipped {
            reason: SkipReason::UnsupportedType(name),
            ..
        } if name == "carrier-pigeon"
    ));
}

#[test]
fn aegis_encrypted_vault_matches_the_plain_one() {
    let bytes = common::fixture("aegis/encrypted.json");

    // Without a passphrase the file is recognized and refused, not misread.
    let importer = misty_importers::detect(&bytes).expect("detected");
    assert_eq!(importer.format(), SourceFormat::Aegis);
    assert!(importer.needs_passphrase(&bytes));
    assert_eq!(
        importer.import(&bytes, &ImportContext::new()),
        Err(ImportError::PassphraseRequired(SourceFormat::Aegis))
    );

    // A wrong passphrase is an authentication failure, never a partial import.
    assert_eq!(
        importer.import(&bytes, &ImportContext::new().with_passphrase(b"wrong")),
        Err(ImportError::DecryptionFailed)
    );

    let ctx = ImportContext::new().with_passphrase(PASSPHRASE);
    let report = AegisImporter.import(&bytes, &ctx).expect("decrypts");
    check_aegis(&report);

    // Byte-for-byte the same items as the plain fixture.
    let plain = import_with(&AegisImporter, "aegis/plain.json", &ImportContext::new());
    assert_eq!(report.items, plain.items);
}

// ---------------------------------------------------------------------------
// 2FAS
// ---------------------------------------------------------------------------

fn check_twofas(report: &misty_importers::ImportReport) {
    assert_eq!(
        outcome_kinds(report),
        vec!["imported", "imported", "imported", "skipped"]
    );
    check(
        item(report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            secret: b32("AAAAAAAAAAAAAAAA"),
            groups: &["Work"],
            source: SourceFormat::TwoFas,
            ..Expect::default()
        },
    );
    check(
        item(report, 1),
        &Expect {
            issuer: Some("Counter Co"),
            account: "bob",
            kind: OtpKind::Hotp,
            algorithm: HashAlg::Sha256,
            digits: 8,
            counter: 42,
            secret: b32("BBBBBBBBBBBBBBBB"),
            source: SourceFormat::TwoFas,
            ..Expect::default()
        },
    );
    check(
        item(report, 2),
        &Expect {
            issuer: Some("Valve"),
            account: "carol",
            kind: OtpKind::Steam,
            digits: 5,
            secret: b32("CCCCCCCCCCCCCCCC"),
            source: SourceFormat::TwoFas,
            ..Expect::default()
        },
    );
    assert_eq!(item(report, 0).created_at, Some(1_690_000_000_000));
}

#[test]
fn twofas_plain_backup() {
    let report = import_detected("2fas/backup.json", &ImportContext::new());
    check_twofas(&report);
}

#[test]
fn twofas_encrypted_backup_matches_the_plain_one() {
    let bytes = common::fixture("2fas/encrypted.json");
    assert!(TwoFasImporter.needs_passphrase(&bytes));
    assert_eq!(
        TwoFasImporter.import(&bytes, &ImportContext::new()),
        Err(ImportError::PassphraseRequired(SourceFormat::TwoFas))
    );
    let ctx = ImportContext::new().with_passphrase(PASSPHRASE);
    let report = TwoFasImporter.import(&bytes, &ctx).expect("decrypts");
    check_twofas(&report);
}

// ---------------------------------------------------------------------------
// andOTP
// ---------------------------------------------------------------------------

fn check_andotp(report: &misty_importers::ImportReport) {
    assert_eq!(
        outcome_kinds(report),
        vec!["imported", "imported", "imported", "skipped", "failed"]
    );
    check(
        item(report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            secret: b32("AAAAAAAAAAAAAAAA"),
            tags: &["work", "critical"],
            source: SourceFormat::AndOtp,
            ..Expect::default()
        },
    );
    // An empty `issuer` with `Issuer:label` in the label: split, as andOTP's own
    // imports leave it.
    check(
        item(report, 1),
        &Expect {
            issuer: Some("Counter Co"),
            account: "bob",
            kind: OtpKind::Hotp,
            algorithm: HashAlg::Sha256,
            digits: 8,
            counter: 42,
            secret: b32("BBBBBBBBBBBBBBBB"),
            source: SourceFormat::AndOtp,
            ..Expect::default()
        },
    );
    check(
        item(report, 2),
        &Expect {
            issuer: Some("Valve"),
            account: "carol",
            kind: OtpKind::Steam,
            digits: 5,
            secret: b32("CCCCCCCCCCCCCCCC"),
            source: SourceFormat::AndOtp,
            ..Expect::default()
        },
    );
    assert_eq!(item(report, 0).last_used_at, Some(1_690_000_000_000));
}

#[test]
fn andotp_plain_backup() {
    let report = import_detected("andotp/plain.json", &ImportContext::new());
    check_andotp(&report);
}

#[test]
fn andotp_encrypted_backup_matches_the_plain_one() {
    let bytes = common::fixture("andotp/encrypted.bin");
    assert!(AndOtpImporter.needs_passphrase(&bytes));
    assert_eq!(
        AndOtpImporter.import(&bytes, &ImportContext::new()),
        Err(ImportError::PassphraseRequired(SourceFormat::AndOtp))
    );
    assert_eq!(
        AndOtpImporter.import(&bytes, &ImportContext::new().with_passphrase(b"wrong")),
        Err(ImportError::DecryptionFailed)
    );
    let ctx = ImportContext::new().with_passphrase(PASSPHRASE);
    let report = AndOtpImporter.import(&bytes, &ctx).expect("decrypts");
    check_andotp(&report);

    let plain = import_with(&AndOtpImporter, "andotp/plain.json", &ImportContext::new());
    assert_eq!(report.items, plain.items);
}

// ---------------------------------------------------------------------------
// FreeOTP and FreeOTP+
// ---------------------------------------------------------------------------

#[test]
fn freeotp_shared_preferences_xml() {
    let report = import_detected("freeotp/tokens.xml", &ImportContext::new());
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "skipped"]
    );

    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            secret: vec![65; 10],
            source: SourceFormat::FreeOtp,
            ..Expect::default()
        },
    );
    // The signed-byte array: -86 is 0xAA, -1 is 0xFF. Reading these as unsigned
    // would import a working-looking token that generates wrong codes.
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Counter Co"),
            account: "bob",
            kind: OtpKind::Hotp,
            algorithm: HashAlg::Sha256,
            digits: 8,
            // The file says 42. FreeOTP stores the counter it last used, and an
            // `otpauth://` counter is the next one, so 43 is the correct import.
            counter: 43,
            secret: vec![0xaa, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            source: SourceFormat::FreeOtp,
            ..Expect::default()
        },
    );
    // A preference that is not a token is skipped, not failed.
    assert!(matches!(
        &report.outcomes[2],
        RowOutcome::Skipped {
            reason: SkipReason::NoOtpSecret,
            ..
        }
    ));
}

#[test]
fn freeotp_plus_json_backup() {
    let report = import_detected("freeotp-plus/backup.json", &ImportContext::new());
    assert_eq!(report.imported(), 3);
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Valve"),
            account: "carol",
            secret: vec![0xaa, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            source: SourceFormat::FreeOtpPlus,
            ..Expect::default()
        },
    );
    check(
        item(&report, 2),
        &Expect {
            issuer: Some("Counter Co"),
            account: "bob",
            kind: OtpKind::Hotp,
            algorithm: HashAlg::Sha512,
            digits: 8,
            // 7 in the file, one behind the `otpauth://` convention.
            counter: 8,
            secret: vec![66; 10],
            source: SourceFormat::FreeOtpPlus,
            ..Expect::default()
        },
    );
}

// ---------------------------------------------------------------------------
// Bitwarden
// ---------------------------------------------------------------------------

#[test]
fn bitwarden_authenticator_export() {
    let report = import_detected("bitwarden/authenticator.json", &ImportContext::new());
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "imported", "skipped", "skipped"]
    );

    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            algorithm: HashAlg::Sha256,
            digits: 8,
            period: 60,
            secret: b32("AAAAAAAAAAAAAAAA"),
            note: Some("kept in the vault"),
            groups: &["Work"],
            origins: &["login.acme.example"],
            favorite: true,
            source: SourceFormat::Bitwarden,
            ..Expect::default()
        },
    );
    // A bare base32 secret with no parameters at all: every parameter is this
    // crate's default, and the row says so three times.
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Bare Secret Co"),
            account: "bob",
            secret: b32("BBBBBBBBBBBBBBBB"),
            source: SourceFormat::Bitwarden,
            ..Expect::default()
        },
    );
    assert!(matches!(
        &report.outcomes[1],
        RowOutcome::Imported { warnings, .. }
            if warnings.contains(&ImportWarning::AssumedDefault("digits"))
                && warnings.contains(&ImportWarning::AssumedDefault("period"))
                && warnings.contains(&ImportWarning::AssumedDefault("algorithm"))
    ));
    // `steam://SECRET`, which is how Bitwarden stores a Steam token.
    check(
        item(&report, 2),
        &Expect {
            issuer: Some("Valve"),
            account: "carol",
            kind: OtpKind::Steam,
            digits: 5,
            secret: b32("CCCCCCCCCCCCCCCC"),
            source: SourceFormat::Bitwarden,
            ..Expect::default()
        },
    );
    // A login with no TOTP, and a secure note: both skipped, neither a failure.
    for index in [3, 4] {
        assert!(matches!(
            &report.outcomes[index],
            RowOutcome::Skipped {
                reason: SkipReason::NoOtpSecret,
                ..
            }
        ));
    }
}

// ---------------------------------------------------------------------------
// Ente Auth
// ---------------------------------------------------------------------------

#[test]
fn ente_auth_plaintext_export() {
    let bytes = common::fixture("ente/codes.txt");
    // Ente's export is a URI list, so both readers claim it; the one that reads
    // `codeDisplay` must win.
    assert_eq!(
        misty_importers::detect(&bytes).map(Importer::format),
        Some(SourceFormat::EnteAuth)
    );

    let report = EnteAuthImporter
        .import(&bytes, &ImportContext::new())
        .expect("imports");
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "imported"]
    );

    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            secret: b32("AAAAAAAAAAAAAAAA"),
            note: Some("a note"),
            tags: &["work"],
            favorite: true,
            source: SourceFormat::EnteAuth,
            ..Expect::default()
        },
    );
    // Ente's trash is recoverable, so a trashed entry is imported archived rather
    // than dropped — losing a token during a migration cannot be undone.
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Deleted Co"),
            account: "bob",
            algorithm: HashAlg::Sha256,
            digits: 8,
            period: 60,
            secret: b32("BBBBBBBBBBBBBBBB"),
            archived: true,
            source: SourceFormat::EnteAuth,
            ..Expect::default()
        },
    );
    assert!(matches!(
        &report.outcomes[1],
        RowOutcome::Imported { warnings, .. }
            if warnings.contains(&ImportWarning::ImportedAsArchived)
    ));
    // A line with no `codeDisplay` at all still imports.
    check(
        item(&report, 2),
        &Expect {
            issuer: Some("Valve"),
            account: "carol",
            kind: OtpKind::Steam,
            digits: 5,
            secret: b32("CCCCCCCCCCCCCCCC"),
            source: SourceFormat::EnteAuth,
            ..Expect::default()
        },
    );
}

// ---------------------------------------------------------------------------
// Raivo, LastPass
// ---------------------------------------------------------------------------

#[test]
fn raivo_export() {
    let report = import_detected("raivo/export.json", &ImportContext::new());
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "skipped"]
    );

    // Every value in a Raivo export is a string, numbers included.
    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            secret: b32("AAAAAAAAAAAAAAAA"),
            favorite: true,
            source: SourceFormat::Raivo,
            ..Expect::default()
        },
    );
    assert_eq!(item(&report, 0).icon_hint.as_deref(), Some("acme"));
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Counter Co"),
            account: "bob",
            kind: OtpKind::Hotp,
            algorithm: HashAlg::Sha256,
            digits: 8,
            counter: 42,
            secret: b32("BBBBBBBBBBBBBBBB"),
            source: SourceFormat::Raivo,
            ..Expect::default()
        },
    );
}

#[test]
fn lastpass_export() {
    let report = import_detected("lastpass/export.json", &ImportContext::new());
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "failed"]
    );

    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            secret: b32("AAAAAAAAAAAAAAAA"),
            groups: &["Work"],
            favorite: true,
            source: SourceFormat::LastPass,
            ..Expect::default()
        },
    );
    assert_eq!(item(&report, 0).created_at, Some(1_690_000_000_000));
    // The user renamed this one. Both namings are kept, because SPEC 3.1 wants
    // same-issuer accounts distinguishable and this is free information.
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Renamed By User"),
            account: "bob",
            algorithm: HashAlg::Sha512,
            digits: 8,
            period: 60,
            secret: b32("BBBBBBBBBBBBBBBB"),
            nickname: Some("Original Co: bob@original.example"),
            source: SourceFormat::LastPass,
            ..Expect::default()
        },
    );
}

// ---------------------------------------------------------------------------
// Proton Pass
// ---------------------------------------------------------------------------

#[test]
fn proton_pass_export() {
    let report = import_detected("proton-pass/export.json", &ImportContext::new());
    // One item with two TOTP fields becomes two rows: the login's own token and
    // the backup token somebody deliberately added.
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "imported", "skipped"]
    );

    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            secret: b32("AAAAAAAAAAAAAAAA"),
            note: Some("a note"),
            groups: &["Personal"],
            origins: &["login.acme.example"],
            favorite: true,
            source: SourceFormat::ProtonPass,
            ..Expect::default()
        },
    );
    assert_eq!(item(&report, 0).created_at, Some(1_690_000_000_000));
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            secret: b32("BBBBBBBBBBBBBBBB"),
            note: Some("a note"),
            nickname: Some("backup token"),
            groups: &["Personal"],
            origins: &["login.acme.example"],
            favorite: true,
            source: SourceFormat::ProtonPass,
            ..Expect::default()
        },
    );
    // `state: 2` is Proton's trash.
    check(
        item(&report, 2),
        &Expect {
            issuer: Some("Trashed Co"),
            account: "bob",
            secret: b32("CCCCCCCCCCCCCCCC"),
            groups: &["Personal"],
            archived: true,
            source: SourceFormat::ProtonPass,
            ..Expect::default()
        },
    );
}

// ---------------------------------------------------------------------------
// KeePassXC
// ---------------------------------------------------------------------------

#[test]
fn keepassxc_xml_export() {
    let report = import_detected("keepassxc/export.xml", &ImportContext::new());
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "skipped", "imported", "imported", "imported"]
    );

    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            algorithm: HashAlg::Sha256,
            digits: 8,
            period: 60,
            secret: b32("AAAAAAAAAAAAAAAA"),
            note: Some("a note"),
            origins: &["login.acme.example"],
            source: SourceFormat::KeePassXcXml,
            ..Expect::default()
        },
    );
    // The legacy `TOTP Seed` + `TOTP Settings` pair: `60;8`.
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Legacy Co"),
            account: "carol",
            digits: 8,
            period: 60,
            secret: b32("BBBBBBBBBBBBBBBB"),
            groups: &["Work"],
            source: SourceFormat::KeePassXcXml,
            ..Expect::default()
        },
    );
    // `30;S` is a Steam token, not a 6-digit TOTP with a stray letter.
    check(
        item(&report, 2),
        &Expect {
            issuer: Some("Valve"),
            account: "dave",
            kind: OtpKind::Steam,
            digits: 5,
            secret: b32("CCCCCCCCCCCCCCCC"),
            groups: &["Work"],
            source: SourceFormat::KeePassXcXml,
            ..Expect::default()
        },
    );
    // KeeOtp's query-string form.
    check(
        item(&report, 3),
        &Expect {
            issuer: Some("KeeOtp Co"),
            account: "erin",
            digits: 7,
            period: 45,
            secret: b32("DDDDDDDDDDDDDDDD"),
            groups: &["Work"],
            source: SourceFormat::KeePassXcXml,
            ..Expect::default()
        },
    );

    // The `<History>` entry holds a superseded secret. Importing it would give the
    // user two tokens with no way to tell which one works.
    let all_secrets: Vec<Vec<u8>> = report
        .items
        .iter()
        .map(|item| item.otp.secret().expose_secret().to_vec())
        .collect();
    assert!(!all_secrets.contains(&b32("ZZZZZZZZZZZZZZZZ")));
}

#[test]
fn keepassxc_csv_export_through_the_generic_reader() {
    let mapping = ColumnMapping::keepassxc_csv();
    let ctx = ImportContext::new().with_mapping(&mapping);
    let report = import_with(&CsvImporter, "keepassxc/export.csv", &ctx);
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "skipped", "imported"]
    );
    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            algorithm: HashAlg::Sha256,
            digits: 8,
            period: 60,
            secret: b32("AAAAAAAAAAAAAAAA"),
            note: Some("a note"),
            groups: &["Root"],
            origins: &["login.acme.example"],
            source: SourceFormat::Csv,
            ..Expect::default()
        },
    );
    // A quoted field with a newline in it survives, and the group path is kept
    // verbatim for the caller to split.
    assert_eq!(
        item(&report, 1).note.as_deref(),
        Some("a note with a\nnewline in it")
    );
    assert_eq!(item(&report, 1).groups, vec!["Root/Work".to_owned()]);
}

// ---------------------------------------------------------------------------
// Authy, and the generic readers
// ---------------------------------------------------------------------------

#[test]
fn authy_extracted_dump() {
    let report = import_detected("authy/tokens.json", &ImportContext::new());
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "skipped"]
    );

    // Seven digits because the record says so, and a ten-second step because
    // `account_type: "authy"` makes this one of Authy's own tokens — which is the
    // difference between codes that work and codes that look right and never do.
    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            digits: 7,
            period: 10,
            secret: b32("AAAAAAAAAAAAAAAA"),
            source: SourceFormat::Authy,
            ..Expect::default()
        },
    );
    // A third-party token Authy was merely storing keeps the otpauth default.
    assert_eq!(item(&report, 1).otp.period(), 30);
    assert!(matches!(
        &report.outcomes[0],
        RowOutcome::Imported { warnings, .. }
            if warnings.contains(&ImportWarning::AssumedDefault("period"))
    ));
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Third Party Co"),
            account: "bob",
            secret: b32("BBBBBBBBBBBBBBBB"),
            source: SourceFormat::Authy,
            ..Expect::default()
        },
    );
    // A row whose seed is still wrapped is skipped with a reason, not decrypted
    // with parameters nobody could verify.
    assert!(matches!(
        &report.outcomes[2],
        RowOutcome::Skipped {
            reason: SkipReason::EncryptedSecret,
            ..
        }
    ));
}

#[test]
fn generic_csv_with_an_inferred_header() {
    let report = import_detected("csv/generic.csv", &ImportContext::new());
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "imported", "failed", "skipped"]
    );
    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            algorithm: HashAlg::Sha256,
            digits: 8,
            period: 60,
            secret: b32("AAAAAAAAAAAAAAAA"),
            note: Some("a note, with a comma"),
            tags: &["work", "critical"],
            groups: &["Work"],
            source: SourceFormat::Csv,
            ..Expect::default()
        },
    );
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Counter Co"),
            account: "bob",
            kind: OtpKind::Hotp,
            counter: 42,
            secret: b32("BBBBBBBBBBBBBBBB"),
            source: SourceFormat::Csv,
            ..Expect::default()
        },
    );
    check(
        item(&report, 2),
        &Expect {
            issuer: Some("Valve"),
            account: "carol",
            kind: OtpKind::Steam,
            digits: 5,
            secret: b32("CCCCCCCCCCCCCCCC"),
            source: SourceFormat::Csv,
            ..Expect::default()
        },
    );
}

#[test]
fn generic_json_with_a_caller_supplied_mapping() {
    let mapping = ColumnMapping::new()
        .array_path("records")
        .issuer("service.name")
        .account("user")
        .secret("otp.seed")
        .kind("otp.kind")
        .algorithm("otp.hash")
        .digits("otp.length")
        .period("otp.step")
        .counter("otp.counter")
        .note("comment");
    let ctx = ImportContext::new().with_mapping(&mapping);
    let report = import_with(&JsonImporter, "json/generic.json", &ctx);
    assert_eq!(
        outcome_kinds(&report),
        vec!["imported", "imported", "failed"]
    );

    // The numbers in this file are JSON numbers, not strings.
    check(
        item(&report, 0),
        &Expect {
            issuer: Some("ACME Corp"),
            account: "ada@example.com",
            algorithm: HashAlg::Sha256,
            digits: 8,
            period: 60,
            secret: b32("AAAAAAAAAAAAAAAA"),
            note: Some("a note"),
            source: SourceFormat::Json,
            ..Expect::default()
        },
    );
    check(
        item(&report, 1),
        &Expect {
            issuer: Some("Counter Co"),
            account: "bob",
            kind: OtpKind::Hotp,
            counter: 42,
            secret: b32("BBBBBBBBBBBBBBBB"),
            source: SourceFormat::Json,
            ..Expect::default()
        },
    );
}

#[test]
fn generic_json_without_a_mapping_asks_for_one() {
    let bytes = common::fixture("json/generic.json");
    assert_eq!(
        JsonImporter.import(&bytes, &ImportContext::new()),
        Err(ImportError::MappingRequired)
    );
}

#[test]
fn a_mapping_naming_a_column_the_file_lacks_fails_the_file_not_every_row() {
    let mapping = ColumnMapping::new().secret("No Such Column");
    let ctx = ImportContext::new().with_mapping(&mapping);
    let bytes = common::fixture("csv/generic.csv");
    assert_eq!(
        CsvImporter.import(&bytes, &ctx),
        Err(ImportError::MappedColumnMissing("secret"))
    );
}

// ---------------------------------------------------------------------------
// Cross-format behaviour: detection, duplicates, preview
// ---------------------------------------------------------------------------

#[test]
fn every_fixture_is_detected_as_its_own_format() {
    // The mapping from directory name to format is the point: a fixture that starts
    // being read by the wrong importer is a regression this catches.
    let expected: &[(&str, SourceFormat)] = &[
        ("otpauth", SourceFormat::Otpauth),
        ("google-migration", SourceFormat::GoogleMigration),
        ("aegis", SourceFormat::Aegis),
        ("2fas", SourceFormat::TwoFas),
        ("andotp", SourceFormat::AndOtp),
        ("freeotp", SourceFormat::FreeOtp),
        ("freeotp-plus", SourceFormat::FreeOtpPlus),
        ("bitwarden", SourceFormat::Bitwarden),
        ("ente", SourceFormat::EnteAuth),
        ("raivo", SourceFormat::Raivo),
        ("lastpass", SourceFormat::LastPass),
        ("proton-pass", SourceFormat::ProtonPass),
        ("keepassxc", SourceFormat::KeePassXcXml),
        ("authy", SourceFormat::Authy),
        ("csv", SourceFormat::Csv),
        ("json", SourceFormat::Json),
    ];

    for (slug, file, bytes) in common::all_fixtures() {
        let Some((_, format)) = expected.iter().find(|(name, _)| *name == slug) else {
            panic!("fixture directory {slug:?} has no expected format in this test");
        };
        // The KeePassXC CSV export is read by the generic CSV importer with a
        // preset mapping, which is the documented path for it.
        let format = if file.ends_with(".csv") && slug == "keepassxc" {
            SourceFormat::Csv
        } else {
            *format
        };
        let detected = misty_importers::detect(&bytes)
            .map(Importer::format)
            .unwrap_or_else(|| panic!("nothing recognized {slug}/{file}"));
        assert_eq!(detected, format, "{slug}/{file}");
    }
}

#[test]
fn every_format_has_exactly_one_importer() {
    for format in SourceFormat::ALL {
        let found = misty_importers::importers()
            .iter()
            .filter(|importer| importer.format() == format)
            .count();
        assert_eq!(found, 1, "{format}");
    }
    assert_eq!(misty_importers::importers().len(), SourceFormat::ALL.len());
}

#[test]
fn duplicates_are_skipped_against_the_callers_own_items() {
    let first = import_detected("otpauth/uris.txt", &ImportContext::new());

    // Feed everything that was just imported back in as "already present".
    let mut existing = ExistingItems::new();
    for item in &first.items {
        existing.add(item.issuer.as_deref(), &item.account, item.otp.secret());
    }

    let ctx = ImportContext::new().with_existing(&existing);
    let again = import_detected("otpauth/uris.txt", &ctx);
    assert_eq!(again.imported(), 0);
    assert_eq!(again.skipped(), 6);
    assert!(again.outcomes.iter().any(|outcome| matches!(
        outcome,
        RowOutcome::Skipped {
            reason: SkipReason::DuplicateOfExisting,
            ..
        }
    )));

    // With `Keep`, the same rows import and say they were duplicates.
    let ctx = ctx.with_duplicate_policy(DuplicatePolicy::Keep);
    let kept = import_detected("otpauth/uris.txt", &ctx);
    assert_eq!(kept.imported(), 6);
    assert!(kept.outcomes.iter().all(|outcome| matches!(
        outcome,
        RowOutcome::Imported { warnings, .. }
            if warnings.contains(&ImportWarning::DuplicateOfExisting)
    ) || matches!(outcome, RowOutcome::Failed { .. })));
}

#[test]
fn the_same_issuer_and_account_with_a_different_secret_is_two_real_accounts() {
    // SPEC 3.1.5: keep both, and warn so the UI makes the user name them apart.
    let mut existing = ExistingItems::new();
    existing.add(
        Some("ACME Corp"),
        "ada@example.com",
        &misty_otp::SecretBytes::from_base32("ZZZZZZZZZZZZZZZZ").expect("base32"),
    );
    let ctx = ImportContext::new().with_existing(&existing);
    let report = import_detected("otpauth/uris.txt", &ctx);

    assert_eq!(report.imported(), 6);
    assert!(matches!(
        &report.outcomes[0],
        RowOutcome::Imported { warnings, .. }
            if warnings.contains(&ImportWarning::CollidesWithExisting)
    ));
}

#[test]
fn a_file_that_repeats_a_row_imports_it_once() {
    let uri = b"otpauth://totp/ACME:ada?secret=AAAAAAAAAAAAAAAA\n\
                otpauth://totp/ACME:ada?secret=AAAAAAAAAAAAAAAA\n";
    let report = misty_importers::import_auto(uri, &ImportContext::new()).expect("imports");
    assert_eq!(report.imported(), 1);
    assert!(matches!(
        &report.outcomes[1],
        RowOutcome::Skipped {
            reason: SkipReason::DuplicateInBatch,
            ..
        }
    ));
}

#[test]
fn a_preview_is_exactly_the_import_it_previews() {
    for (slug, file, bytes) in common::all_fixtures() {
        let Some(importer) = misty_importers::detect(&bytes) else {
            continue;
        };
        let ctx = ImportContext::new().with_passphrase(PASSPHRASE);
        let (Ok(report), Ok(preview)) = (
            importer.import(&bytes, &ctx),
            importer.preview(&bytes, &ctx),
        ) else {
            continue;
        };
        assert_eq!(
            report.imported(),
            preview.would_import(),
            "{slug}/{file}: preview disagrees with the import"
        );
        assert_eq!(report.skipped(), preview.skipped(), "{slug}/{file}");
        assert_eq!(report.failed(), preview.failed(), "{slug}/{file}");
        for (item, shown) in report.items.iter().zip(&preview.items) {
            assert_eq!(shown.issuer.as_deref(), item.issuer.as_deref());
            assert_eq!(shown.account, item.account);
            assert_eq!(shown.digits, item.otp.digits());
            assert_eq!(shown.period, item.otp.period());
            assert_eq!(shown.algorithm, item.otp.algorithm().as_str());
            assert_eq!(shown.secret_len, item.otp.secret().len());
        }
    }
}

#[test]
fn a_single_scanned_uri_needs_no_batch_around_it() {
    // What a QR scanner hands over: one URI, no file, no batch to isolate a
    // failure from, so the failure is the return value.
    let item = misty_importers::OtpauthImporter::one(
        "  otpauth://totp/ACME:ada?secret=AAAAAAAAAAAAAAAA&digits=8  ",
    )
    .expect("one URI");
    check(
        &item,
        &Expect {
            issuer: Some("ACME"),
            account: "ada",
            digits: 8,
            secret: b32("AAAAAAAAAAAAAAAA"),
            ..Expect::default()
        },
    );
    assert!(misty_importers::OtpauthImporter::one("not a uri").is_err());
}

#[test]
fn the_row_limit_stops_an_import_rather_than_truncating_it() {
    let mut file = String::new();
    for index in 0..50 {
        file.push_str(&format!(
            "otpauth://totp/Bulk:user{index}?secret=AAAAAAAAAAAAAAAA\n"
        ));
    }
    let limits = misty_importers::Limits {
        max_rows: 10,
        ..misty_importers::Limits::default()
    };
    let ctx = ImportContext::new().with_limits(limits);
    // Refusing is the honest answer: a silently truncated import of a credential
    // file is indistinguishable from a complete one.
    assert_eq!(
        misty_importers::import_auto(file.as_bytes(), &ctx),
        Err(ImportError::TooManyRows { max: 10 })
    );
}
