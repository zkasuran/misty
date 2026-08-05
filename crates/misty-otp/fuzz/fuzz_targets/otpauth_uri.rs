// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target for the `otpauth://` parser (SPEC 7, SPEC 10.7).
//!
//! Run with:
//!
//! ```text
//! cargo install cargo-fuzz
//! cd crates/misty-otp
//! mkdir -p fuzz/corpus/otpauth_uri
//! cargo +nightly fuzz run otpauth_uri fuzz/corpus/otpauth_uri fuzz/seeds/otpauth_uri
//! ```
//!
//! The first corpus directory is the writable one; the committed seeds are passed
//! after it so libFuzzer only reads them.
//!
//! The target asserts three things beyond "does not crash":
//!
//! 1. anything that parses must re-serialize and re-parse to the model
//!    `export_form` predicts — identity for every kind but `Blizzard`, which is
//!    documented to export as interoperable `totp` (the SPEC 7 round-trip
//!    property, on inputs a human would never think of);
//! 2. a URI this crate produced must always parse, so serialization cannot emit
//!    something its own parser rejects;
//! 3. generating from whatever was parsed must not panic either — the parser is
//!    not the only code reachable from a hostile QR code.

#![no_main]

use libfuzzer_sys::fuzz_target;
use misty_otp::OtpUri;

fuzz_target!(|data: &[u8]| {
    // The parser takes `&str`; invalid UTF-8 is the caller's problem, and QR
    // decoders hand us text.
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(parsed) = OtpUri::parse(input) else {
        return;
    };

    let serialized = parsed.to_uri();
    let reparsed = match OtpUri::parse(&serialized) {
        Ok(reparsed) => reparsed,
        Err(error) => panic!("this crate emitted a uri it cannot parse: {error}"),
    };
    assert_eq!(reparsed, parsed.export_form(), "round-trip changed the model");
    let kind = parsed.config().kind();
    if kind == kind.serializes_as() {
        assert_eq!(parsed, reparsed, "round-trip changed the model");
    } else {
        // Blizzard normalizes to TOTP; the codes must still agree.
        for unix_ms in [0, 59_000, 1_700_000_000_000] {
            let before = parsed.config().generate_at(unix_ms);
            let after = reparsed.config().generate_at(unix_ms);
            assert_eq!(
                before.map(|code| code.value().to_owned()).ok(),
                after.map(|code| code.value().to_owned()).ok(),
                "normalized export changed the code"
            );
        }
    }
    assert_eq!(
        &*reparsed.to_uri(),
        &*serialized,
        "serialization is not idempotent"
    );

    // Warnings describe the input, so a canonical uri must produce none.
    match OtpUri::parse_with_warnings(&serialized) {
        Ok((_, warnings)) => assert!(
            warnings.is_empty(),
            "canonical uri produced warnings: {warnings:?}"
        ),
        Err(error) => panic!("this crate emitted a uri it cannot parse: {error}"),
    }

    // Generation is reachable from parsed input too, so it is in scope here.
    for unix_ms in [0, 1_700_000_000_000, u64::MAX] {
        let _ = parsed.config().generate_at(unix_ms);
        let _ = parsed.config().next_code_at(unix_ms);
        let _ = parsed.config().counter_at(unix_ms);
    }
    let _ = parsed.config().resync_counter("00000000", 4);
});
