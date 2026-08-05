// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Aegis vaults, plain and encrypted.
//!
//! Covers the JSON reader, the hex and base64 header fields, the scrypt parameter
//! validation, and the AES-256-GCM unwrapping — including the case where a hostile
//! header names a key-derivation cost that must be refused rather than clamped.

#![no_main]

use libfuzzer_sys::fuzz_target;
use misty_importers::AegisImporter;

fuzz_target!(|data: &[u8]| {
    misty_importers_fuzz::exercise(&AegisImporter, data);
});
