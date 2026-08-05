// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Export, and the round-trip property.
//!
//! SPEC 8 says no lock-in in either direction, which is only true if what this
//! crate writes is what it — and everyone else — can read back. The property here is
//! the strong form: **any batch of valid items exports to `otpauth://` and
//! re-imports to an identical model.**
//!
//! There is one documented exception, and it belongs to `misty-otp` rather than to
//! this crate: a [`Blizzard`](misty_otp::OtpKind::Blizzard) token is written as
//! plain 8-digit SHA-1 TOTP, because its algorithm is exactly that and a private
//! `blizzard` URI type would only stop every other authenticator importing it
//! (SPEC 7.1). [`ImportedItem::export_form`] is the model that comes back, so the
//! property is stated without an escape clause.

mod common;

use misty_importers::export::{
    self, ExportError, PLAINTEXT_EXPORT_CONFIRMATION, PLAINTEXT_EXPORT_WARNING,
};
use misty_importers::{
    ColumnMapping, DuplicatePolicy, ImportContext, ImportedItem, Importer, JsonImporter,
    OtpauthImporter, SourceFormat,
};
use misty_otp::{OtpConfig, OtpKind, SecretBytes};
use proptest::prelude::*;

/// Text that is legitimate in an issuer or an account name.
///
/// Deliberately includes spaces, `@`, `.`, `+` and `:` — the last is the one a
/// naive parser splits on — and stays short so a canonical URI cannot exceed
/// `MAX_URI_LEN` for a reason unrelated to what is being tested.
fn safe_text() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-zA-Z0-9 @.+:_-]{0,24}").expect("valid regex")
}

fn kinds() -> impl Strategy<Value = OtpKind> {
    prop_oneof![
        Just(OtpKind::Totp),
        Just(OtpKind::Hotp),
        Just(OtpKind::Steam),
        Just(OtpKind::Motp),
        Just(OtpKind::Blizzard),
        Just(OtpKind::Yandex),
    ]
}

fn items() -> impl Strategy<Value = ImportedItem> {
    (
        kinds(),
        prop::collection::vec(any::<u8>(), 1..40),
        1u8..=10,
        1u16..=3600,
        any::<u64>(),
        proptest::option::of(safe_text()),
        safe_text(),
        proptest::string::string_regex("[0-9]{1,8}").expect("valid regex"),
    )
        .prop_map(
            |(kind, secret, digits, period, counter, issuer, account, pin)| {
                let config = OtpConfig::builder(kind, SecretBytes::new(secret))
                    .digits(digits)
                    .period(period)
                    .counter(counter)
                    .pin(Some(SecretBytes::from_slice(pin.as_bytes())))
                    .build()
                    .expect("every generated parameter is in range");
                ImportedItem::new(SourceFormat::Otpauth, config, issuer, account)
            },
        )
}

proptest! {
    /// The property. Duplicates are kept rather than skipped, because two
    /// identical generated items are a duplicate by construction and this test is
    /// about serialization, not about deduplication.
    #[test]
    fn any_batch_round_trips_through_otpauth(batch in prop::collection::vec(items(), 1..12)) {
        let file = export::uri_list(&batch);
        let ctx = ImportContext::new().with_duplicate_policy(DuplicatePolicy::Keep);
        let report = OtpauthImporter
            .import(file.as_bytes(), &ctx)
            .expect("everything this crate writes, it reads");

        prop_assert_eq!(report.items.len(), batch.len());
        for (original, reimported) in batch.iter().zip(&report.items) {
            prop_assert_eq!(reimported, &original.export_form(SourceFormat::Otpauth));
        }
    }

    /// And the same batch survives the plaintext JSON export, which carries a URI
    /// per item precisely so that it can be walked back in.
    #[test]
    fn any_batch_round_trips_through_plaintext_json(batch in prop::collection::vec(items(), 1..12)) {
        let file = export::plaintext_json(&batch, PLAINTEXT_EXPORT_CONFIRMATION)
            .expect("confirmed");
        let mapping = ColumnMapping::misty_plaintext_json();
        let ctx = ImportContext::new()
            .with_mapping(&mapping)
            .with_duplicate_policy(DuplicatePolicy::Keep);
        let report = JsonImporter
            .import(file.as_bytes(), &ctx)
            .expect("the escape hatch is walkable in both directions");

        prop_assert_eq!(report.items.len(), batch.len());
        for (original, reimported) in batch.iter().zip(&report.items) {
            let expected = original.export_form(SourceFormat::Json);
            prop_assert_eq!(&reimported.otp, &expected.otp);
            prop_assert_eq!(reimported.issuer.as_deref(), expected.issuer.as_deref());
            prop_assert_eq!(&reimported.account, &expected.account);
        }
    }
}

#[test]
fn every_fixture_round_trips_through_the_uri_export() {
    // The property test generates models; this one takes what real fixtures parse
    // into, which is a different distribution and catches different mistakes.
    for (slug, file, bytes) in common::all_fixtures() {
        let Some(importer) = misty_importers::detect(&bytes) else {
            continue;
        };
        let ctx = ImportContext::new().with_passphrase(common::FIXTURE_PASSPHRASE);
        let Ok(report) = importer.import(&bytes, &ctx) else {
            continue;
        };
        if report.items.is_empty() {
            continue;
        }

        let exported = export::uri_list(&report.items);
        let ctx = ImportContext::new().with_duplicate_policy(DuplicatePolicy::Keep);
        let again = OtpauthImporter
            .import(exported.as_bytes(), &ctx)
            .unwrap_or_else(|error| panic!("{slug}/{file} re-import: {error}"));

        assert_eq!(
            again.items.len(),
            report.items.len(),
            "{slug}/{file}: lost items on re-import"
        );
        for (original, reimported) in report.items.iter().zip(&again.items) {
            assert_eq!(
                reimported,
                &original.export_form(SourceFormat::Otpauth),
                "{slug}/{file}"
            );
        }
    }
}

#[test]
fn a_unicode_issuer_survives_the_round_trip() {
    let config = OtpConfig::totp(SecretBytes::from_base32("AAAAAAAAAAAAAAAA").expect("base32"))
        .expect("valid");
    let item = ImportedItem::new(
        SourceFormat::Otpauth,
        config,
        Some("日本銀行".to_owned()),
        "アダ:ada@example.com".to_owned(),
    );
    let file = export::uri_list(std::slice::from_ref(&item));
    let report = OtpauthImporter
        .import(file.as_bytes(), &ImportContext::new())
        .expect("imports");
    assert_eq!(report.items.first(), Some(&item));
}

#[test]
fn the_plaintext_export_is_gated_on_the_confirmation_phrase() {
    let report = common::import_detected("otpauth/uris.txt", &ImportContext::new());

    // SPEC 2.5 wants a typed confirmation. A UI could enforce that and forget to;
    // the library refusing means the gate cannot be skipped by accident.
    for wrong in ["", "yes", "export my secrets in plain text"] {
        assert_eq!(
            export::plaintext_json(&report.items, wrong).err(),
            Some(ExportError::ConfirmationRequired),
            "{wrong:?} must not be accepted"
        );
    }

    let file =
        export::plaintext_json(&report.items, PLAINTEXT_EXPORT_CONFIRMATION).expect("confirmed");

    // The warning is the first thing in the file, because JSON has no comments and
    // a warning nobody scrolls to is not a warning.
    assert!(file.starts_with("{\n  \"_WARNING\": "), "{}", &file[..64]);
    assert!(file.contains(PLAINTEXT_EXPORT_WARNING));

    // And it is valid JSON, so the escape hatch works with other tools.
    let parsed: serde_json::Value = serde_json::from_str(&file).expect("valid JSON");
    assert_eq!(
        parsed.get("item_count").and_then(serde_json::Value::as_u64),
        Some(report.items.len() as u64)
    );
    assert_eq!(
        parsed.get("format").and_then(serde_json::Value::as_str),
        Some("misty-plaintext-export")
    );
}

#[test]
fn the_qr_sheet_carries_one_labelled_uri_per_item_and_hides_them_from_debug() {
    let report = common::import_detected("otpauth/uris.txt", &ImportContext::new());
    let sheet = export::qr_sheet(&report.items);

    assert_eq!(sheet.len(), report.items.len());
    assert!(!sheet.is_empty());
    let first = sheet.entries.first().expect("an entry");
    assert_eq!(first.label, "ACME Corp: ada@example.com");
    assert_eq!(first.kind, "TOTP");
    assert!(first.uri.starts_with("otpauth://totp/"));

    // The URI is a complete credential; `Debug` must not print it.
    let rendered = format!("{first:?}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
    assert!(!rendered.contains("AAAAAAAAAAAAAAAA"), "{rendered}");
}
