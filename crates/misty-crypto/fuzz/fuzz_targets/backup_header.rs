// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#![no_main]
//! Fuzzes the backup header parser and, cheaply, the whole open path
//! (SPEC §10 rule 7).
//!
//! Run with:
//!
//! ```text
//! cd crates/misty-crypto/fuzz
//! cargo +nightly fuzz run backup_header
//! ```
//!
//! The header is the interesting target because it is attacker-controlled *and*
//! it chooses the Argon2 costs the parser will accept. A header claiming 64 GiB
//! of memory must be rejected, not honoured, so this target deliberately
//! exercises the cost fields.
//!
//! `open_bytes` is only called when the accepted costs are small. Otherwise the
//! fuzzer would spend all of its time inside Argon2 doing legitimate work — and
//! the fact that costs above the cap are refused at parse time is exactly what
//! the guard below asserts.

use libfuzzer_sys::fuzz_target;
use misty_crypto::backup::{self, BackupHeader};

/// Argon2 memory, in KiB, above which this target does not run the KDF.
const CHEAP_ENOUGH_KIB: u32 = 1024;

fuzz_target!(|data: &[u8]| {
    match BackupHeader::parse(data) {
        Err(_) => {
            // A header the parser rejected must not open either.
            assert!(backup::open_bytes(b"fuzz passphrase", data).is_err());
        }
        Ok(header) => {
            // Whatever was accepted must be within the documented bounds.
            assert!(header.params.validate().is_ok());
            if header.params.memory_kib <= CHEAP_ENOUGH_KIB {
                let _ = backup::open_bytes(b"fuzz passphrase", data);
            }
        }
    }
});
