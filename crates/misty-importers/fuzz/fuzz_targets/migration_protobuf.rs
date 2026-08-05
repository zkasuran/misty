// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Google Authenticator's `otpauth-migration://offline?data=` payload.
//!
//! The hand-rolled protobuf decoder is the highest-risk parser in the crate: the
//! input is base64 inside a URI inside a QR code from a stranger, and every length
//! in it is attacker-chosen. SPEC 10.7 requires this target.

#![no_main]

use libfuzzer_sys::fuzz_target;
use misty_importers::{GoogleMigrationImporter, SourceFormat};

fuzz_target!(|data: &[u8]| {
    misty_importers_fuzz::exercise(&GoogleMigrationImporter, data);

    // The same bytes, wrapped as a URI, so the fuzzer reaches the protobuf decoder
    // even before it learns the scheme by itself.
    let mut wrapped = b"otpauth-migration://offline?data=".to_vec();
    wrapped.extend(
        data.iter()
            .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'%')),
    );
    misty_importers_fuzz::exercise(&GoogleMigrationImporter, &wrapped);

    let _ = SourceFormat::GoogleMigration;
});
