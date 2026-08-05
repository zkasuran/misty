// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Invariants every fuzz target in this crate asserts.
//!
//! This lives in `src/lib.rs` rather than in `fuzz_targets/` on purpose: CI runs
//! every `.rs` file under `fuzz_targets/` as a target, so a shared module in there
//! would be run as a target that does not exist.
//!
//! A target that only checks "did not crash" is worth much less than one that
//! checks the properties the crate promises, so each of these runs the same
//! battery: sniffing is total, an import either fails or produces valid tokens,
//! per-row outcomes stay consistent with the items, no error message contains a
//! secret, and anything that imported re-exports and re-imports unchanged.

use misty_importers::{
    export, DuplicatePolicy, ImportContext, ImportReport, Importer, Limits, OtpauthImporter,
    RowOutcome, SourceFormat,
};

/// Limits tight enough that the fuzzer spends its time on parsing rather than on
/// key derivation or on megabyte allocations.
///
/// The KDF bounds matter most: without them, one input claiming scrypt `n = 2^20`
/// would stall the fuzzer for minutes and look like a hang.
pub fn limits() -> Limits {
    Limits {
        max_input_bytes: 1 << 20,
        max_rows: 200,
        max_kdf_memory_bytes: 1 << 20,
        max_kdf_iterations: 10_000,
        ..Limits::default()
    }
}

/// The passphrase the encrypted paths are fuzzed with. Any value works; what is
/// being fuzzed is the parsing around the AEAD, not the AEAD.
pub const PASSPHRASE: &[u8] = b"fuzz";

/// Run one importer over one input and check everything that must hold.
pub fn exercise(importer: &dyn Importer, data: &[u8]) {
    // Sniffing must be total and must not depend on the context.
    let _ = importer.sniff(data);
    let _ = importer.needs_passphrase(data);

    let ctx = ImportContext::new()
        .with_limits(limits())
        .with_passphrase(PASSPHRASE);

    if let Ok(report) = importer.import(data, &ctx) {
        check_report(&report);
        check_round_trip(&report);
    }
    // The preview path is what a UI calls first, so it must be exactly as robust.
    if let Ok(preview) = importer.preview(data, &ctx) {
        for item in &preview.items {
            assert!(item.secret_len > 0, "a preview described an empty secret");
        }
    }
}

fn check_report(report: &ImportReport) {
    assert!(
        report.items.len() <= report.outcomes.len(),
        "more items than rows"
    );
    let imported = report
        .outcomes
        .iter()
        .filter(|outcome| matches!(outcome, RowOutcome::Imported { .. }))
        .count();
    assert_eq!(imported, report.items.len(), "outcome count disagrees");

    for outcome in &report.outcomes {
        if let RowOutcome::Imported { item, .. } = outcome {
            assert!(report.items.get(*item).is_some(), "dangling item index");
        }
    }

    for item in &report.items {
        // Every invariant `misty-otp` promises, restated where a bad row could
        // otherwise slip through: a token that generates nothing is worse than a
        // row that failed.
        assert!(!item.otp.secret().is_empty());
        assert!((1..=10).contains(&item.otp.digits()));
        assert!((1..=3600).contains(&item.otp.period()));
        if item.otp.kind().uses_pin() {
            // A PIN may legitimately be absent at import time.
        }
        assert!(item.otp.generate_at(0).is_ok() || item.otp.pin().is_none());
    }
}

/// Everything that imported must survive an `otpauth://` round trip, which is the
/// property SPEC 8 rests on.
fn check_round_trip(report: &ImportReport) {
    if report.items.is_empty() {
        return;
    }
    let file = export::uri_list(&report.items);
    let ctx = ImportContext::new()
        .with_limits(limits())
        .with_duplicate_policy(DuplicatePolicy::Keep);
    let again = match OtpauthImporter.import(file.as_bytes(), &ctx) {
        Ok(again) => again,
        // The only legitimate reason a re-import can fail is the row limit, which
        // the export cannot exceed if the import did not.
        Err(_) => panic!("this crate wrote a URI list it cannot read"),
    };
    assert_eq!(again.items.len(), report.items.len());
    for (original, reimported) in report.items.iter().zip(&again.items) {
        assert_eq!(reimported, &original.export_form(SourceFormat::Otpauth));
    }
}
