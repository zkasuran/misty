// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every importer, on every input.
//!
//! `detect` runs all sixteen sniffers over whatever the user chose, and a UI lets
//! them point the wrong importer at a file, so "this parser only sees its own
//! format" is never true. This target enforces the crate-wide rule: for any bytes
//! and any importer, nothing panics and nothing hangs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use misty_importers::ImportContext;

fuzz_target!(|data: &[u8]| {
    let _ = misty_importers::detect_all(data);
    let _ = misty_importers::detect_format(data);

    for importer in misty_importers::importers() {
        misty_importers_fuzz::exercise(*importer, data);
    }

    let ctx = ImportContext::new().with_limits(misty_importers_fuzz::limits());
    let _ = misty_importers::import_auto(data, &ctx);
    let _ = misty_importers::preview_auto(data, &ctx);
});
