// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The hand-rolled CSV reader, with and without a caller-supplied mapping.
//!
//! Quoting, embedded newlines, unterminated quotes, absurd column counts and
//! header inference all live here, and the reader is this crate's own rather than a
//! dependency's, so it gets its own target.

#![no_main]

use libfuzzer_sys::fuzz_target;
use misty_importers::{ColumnMapping, CsvImporter, ImportContext, Importer};

fuzz_target!(|data: &[u8]| {
    // Header inference: no mapping at all.
    misty_importers_fuzz::exercise(&CsvImporter, data);

    // And an explicit mapping, which reaches the row reader for files whose header
    // says nothing useful.
    for mapping in [
        ColumnMapping::keepassxc_csv(),
        ColumnMapping::new()
            .secret("0")
            .issuer("1")
            .account("2")
            .digits("3")
            .period("4")
            .with_header(false),
    ] {
        let ctx = ImportContext::new()
            .with_limits(misty_importers_fuzz::limits())
            .with_mapping(&mapping);
        let _ = CsvImporter.import(data, &ctx);
        let _ = CsvImporter.preview(data, &ctx);
    }
});
