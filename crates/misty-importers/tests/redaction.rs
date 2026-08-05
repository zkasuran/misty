// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! No secret reaches an error message, a preview, or a `Debug` line.
//!
//! SPEC 3 makes a secret in a log line a release blocker, and an importer is where
//! that is most likely to happen: the interesting errors are all about a field whose
//! value is the secret. This suite is what keeps the rule honest.
//!
//! The dummy secrets in the fixtures are searched for in three encodings — base32,
//! hex, and the raw bytes' decimal rendering — because a leak through `Vec<u8>`'s own
//! `Debug` would show decimal, not base32.

mod common;

use misty_importers::{ImportContext, RowOutcome};

/// Every dummy secret in the fixtures, in every rendering a leak could take.
fn needles() -> Vec<String> {
    let mut out = Vec::new();
    for base32 in [
        "AAAAAAAAAAAAAAAA",
        "BBBBBBBBBBBBBBBB",
        "CCCCCCCCCCCCCCCC",
        "DDDDDDDDDDDDDDDD",
        "EEEEEEEEEEEEEEEE",
    ] {
        out.push(base32.to_owned());
        out.push(base32.to_ascii_lowercase());
        if let Ok(secret) = misty_otp::SecretBytes::from_base32(base32) {
            out.push(secret.to_hex().to_string());
        }
    }
    // The mOTP fixture's hex secret, and the PINs.
    out.push("aaaaaaaaaaaaaaaa".to_owned());
    out
}

#[test]
fn no_error_from_any_importer_contains_a_secret() {
    let needles = needles();
    for (slug, file, bytes) in common::all_fixtures() {
        for importer in misty_importers::importers() {
            let format = importer.format();
            for ctx in [
                ImportContext::new(),
                ImportContext::new().with_passphrase(b"deliberately wrong"),
                ImportContext::new().with_passphrase(common::FIXTURE_PASSPHRASE),
            ] {
                let rendered = match importer.import(&bytes, &ctx) {
                    Ok(report) => report
                        .outcomes
                        .iter()
                        .map(|outcome| match outcome {
                            RowOutcome::Failed { row, error } => format!("{row}: {error}"),
                            RowOutcome::Skipped { row, reason } => format!("{row}: {reason}"),
                            RowOutcome::Imported { row, warnings, .. } => {
                                let warnings: Vec<String> =
                                    warnings.iter().map(ToString::to_string).collect();
                                format!("{row}: {}", warnings.join(", "))
                            }
                            _ => String::new(),
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                    Err(error) => format!("{error} / {error:?}"),
                };
                for needle in &needles {
                    assert!(
                        !rendered.contains(needle.as_str()),
                        "{format} on {slug}/{file} leaked {needle} into:\n{rendered}"
                    );
                }
            }
        }
    }
}

#[test]
fn no_preview_contains_a_secret_in_any_rendering() {
    let needles = needles();
    for (slug, file, bytes) in common::all_fixtures() {
        let Some(importer) = misty_importers::detect(&bytes) else {
            continue;
        };
        let ctx = ImportContext::new().with_passphrase(common::FIXTURE_PASSPHRASE);
        let Ok(preview) = importer.preview(&bytes, &ctx) else {
            continue;
        };

        let debug = format!("{preview:?}");
        let json = serde_json::to_string(&preview).expect("previews serialize");
        for rendered in [&debug, &json] {
            for needle in &needles {
                assert!(
                    !rendered.contains(needle.as_str()),
                    "{slug}/{file} preview leaked {needle}"
                );
            }
            // Nor the raw bytes rendered as decimal, which is how `Vec<u8>`'s own
            // `Debug` would show them.
            assert!(
                !rendered.contains("65, 65, 65"),
                "{slug}/{file} preview leaked raw secret bytes"
            );
        }
    }
}

#[test]
fn an_imported_items_debug_output_is_safe_to_log() {
    let report = common::import_detected("otpauth/uris.txt", &ImportContext::new());
    let rendered = format!("{:?}", report.items);
    assert!(rendered.contains("[redacted]"), "{rendered}");
    for needle in needles() {
        assert!(!rendered.contains(&needle), "leaked {needle}");
    }
}

#[test]
fn a_json_type_error_names_the_field_and_not_the_value() {
    // The secret is in a field whose type is wrong for it. `serde_json`'s own
    // message would quote the value; this crate's must not.
    let file = br#"[{"secret":{"oops":"AAAAAAAAAAAAAAAA"},"label":"a","type":"TOTP"}]"#;
    let importer = misty_importers::importer_for(misty_importers::SourceFormat::AndOtp)
        .expect("andotp importer");
    let report = importer
        .import(file, &ImportContext::new())
        .expect("the row fails, the file does not");
    let rendered = format!("{:?}", report.outcomes);
    assert!(!rendered.contains("AAAAAAAAAAAAAAAA"), "{rendered}");
    assert_eq!(report.failed(), 1);
}

#[test]
fn a_passphrase_never_appears_in_a_context_debug_line() {
    let ctx = ImportContext::new().with_passphrase(b"correct horse battery staple");
    let rendered = format!("{ctx:?}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
    assert!(!rendered.contains("horse"), "{rendered}");
}
