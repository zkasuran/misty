// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared helpers for the integration suites.
//!
//! Every fixture assertion goes through [`check`], so a format's test says what the
//! parsed model *is* — kind, algorithm, digit count, period, counter, secret bytes —
//! rather than spot-checking whichever field the author remembered.

#![allow(dead_code, reason = "each test binary uses a different subset")]

use std::path::{Path, PathBuf};

use misty_importers::{
    ImportContext, ImportReport, ImportedItem, Importer, RowOutcome, SourceFormat,
};
use misty_otp::{HashAlg, OtpKind, SecretBytes};

/// The passphrase every encrypted fixture uses. See `fixture_provenance.rs`.
pub const FIXTURE_PASSPHRASE: &[u8] = b"misty test passphrase";

/// Path to the fixture directory.
pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Read one fixture, panicking with a useful message if it is missing.
pub fn fixture(relative: &str) -> Vec<u8> {
    let path = fixtures().join(relative);
    std::fs::read(&path).unwrap_or_else(|error| panic!("fixture {relative}: {error}"))
}

/// Every fixture file, as `(format slug, file name, bytes)`.
pub fn all_fixtures() -> Vec<(String, String, Vec<u8>)> {
    let mut out = Vec::new();
    let root = fixtures();
    let mut dirs: Vec<_> = std::fs::read_dir(&root)
        .expect("fixture root")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        let slug = dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .expect("fixture directory")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect();
        files.sort();
        for file in files {
            let name = file
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_owned();
            let bytes = std::fs::read(&file).expect("fixture file");
            out.push((slug.clone(), name, bytes));
        }
    }
    out
}

/// Base32-decode a dummy secret into the bytes it stands for.
pub fn b32(encoded: &str) -> Vec<u8> {
    SecretBytes::from_base32(encoded)
        .expect("test secret is valid base32")
        .expose_secret()
        .to_vec()
}

/// Hex-decode a dummy mOTP secret.
pub fn hex_secret(encoded: &str) -> Vec<u8> {
    SecretBytes::from_hex(encoded)
        .expect("test secret is valid hex")
        .expose_secret()
        .to_vec()
}

/// Import a fixture with the importer that owns it.
pub fn import_with(
    importer: &dyn Importer,
    relative: &str,
    ctx: &ImportContext<'_>,
) -> ImportReport {
    let bytes = fixture(relative);
    importer
        .import(&bytes, ctx)
        .unwrap_or_else(|error| panic!("importing {relative}: {error}"))
}

/// Import a fixture through `detect`, which is what a UI does.
pub fn import_detected(relative: &str, ctx: &ImportContext<'_>) -> ImportReport {
    let bytes = fixture(relative);
    let importer = misty_importers::detect(&bytes)
        .unwrap_or_else(|| panic!("no importer recognized {relative}"));
    importer
        .import(&bytes, ctx)
        .unwrap_or_else(|error| panic!("importing {relative}: {error}"))
}

/// What one imported item must be.
#[derive(Debug)]
pub struct Expect<'a> {
    pub issuer: Option<&'a str>,
    pub account: &'a str,
    pub kind: OtpKind,
    pub algorithm: HashAlg,
    pub digits: u8,
    pub period: u16,
    pub counter: u64,
    pub secret: Vec<u8>,
    pub pin: Option<&'a [u8]>,
    pub note: Option<&'a str>,
    pub nickname: Option<&'a str>,
    pub tags: &'a [&'a str],
    pub groups: &'a [&'a str],
    pub origins: &'a [&'a str],
    pub favorite: bool,
    pub archived: bool,
    pub source: SourceFormat,
}

impl Default for Expect<'_> {
    fn default() -> Self {
        Self {
            issuer: None,
            account: "",
            kind: OtpKind::Totp,
            algorithm: HashAlg::Sha1,
            digits: 6,
            period: 30,
            counter: 0,
            secret: Vec::new(),
            pin: None,
            note: None,
            nickname: None,
            tags: &[],
            groups: &[],
            origins: &[],
            favorite: false,
            archived: false,
            source: SourceFormat::Otpauth,
        }
    }
}

/// Assert an item is exactly what was expected, field by field.
#[track_caller]
pub fn check(item: &ImportedItem, expected: &Expect<'_>) {
    let otp = &item.otp;
    assert_eq!(item.issuer.as_deref(), expected.issuer, "issuer");
    assert_eq!(item.account, expected.account, "account");
    assert_eq!(otp.kind(), expected.kind, "kind");
    assert_eq!(otp.algorithm(), expected.algorithm, "algorithm");
    assert_eq!(otp.digits(), expected.digits, "digits");
    assert_eq!(otp.period(), expected.period, "period");
    assert_eq!(otp.counter(), expected.counter, "counter");
    assert_eq!(
        otp.secret().expose_secret(),
        expected.secret.as_slice(),
        "secret bytes"
    );
    assert_eq!(
        otp.pin().map(|pin| pin.expose_secret().to_vec()),
        expected.pin.map(<[u8]>::to_vec),
        "pin"
    );
    assert_eq!(item.note.as_deref(), expected.note, "note");
    assert_eq!(item.nickname.as_deref(), expected.nickname, "nickname");
    assert_eq!(item.tags, expected.tags, "tags");
    assert_eq!(item.groups, expected.groups, "groups");
    assert_eq!(item.origins, expected.origins, "origins");
    assert_eq!(item.favorite, expected.favorite, "favorite");
    assert_eq!(item.archived, expected.archived, "archived");
    assert_eq!(item.source, expected.source, "source");
}

/// The outcomes, rendered as short strings, for asserting the shape of a batch
/// without spelling out every field.
pub fn outcome_kinds(report: &ImportReport) -> Vec<&'static str> {
    report
        .outcomes
        .iter()
        .map(|outcome| match outcome {
            RowOutcome::Imported { .. } => "imported",
            RowOutcome::Skipped { .. } => "skipped",
            RowOutcome::Failed { .. } => "failed",
            // `RowOutcome` is `#[non_exhaustive]`, so a new variant is a compile
            // error here rather than a silently mislabelled row.
            _ => "unknown",
        })
        .collect()
}

/// The item at `index`, or a panic naming what was there instead.
#[track_caller]
pub fn item(report: &ImportReport, index: usize) -> &ImportedItem {
    report
        .items
        .get(index)
        .unwrap_or_else(|| panic!("no item {index}; {} were imported", report.items.len()))
}
