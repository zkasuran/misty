// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! andOTP backups, plain and encrypted.
//!
//! The encrypted layout is a bare binary header — four bytes of iteration count,
//! then two twelve-byte fields — with no magic number, so almost any input reaches
//! the key-derivation path. That is exactly what makes it worth fuzzing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use misty_importers::AndOtpImporter;

fuzz_target!(|data: &[u8]| {
    misty_importers_fuzz::exercise(&AndOtpImporter, data);
});
