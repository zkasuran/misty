// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

#![no_main]
//! Fuzzes the enrollment QR decoder (SPEC §6.3.1, §10 rule 7).
//!
//! Run with:
//!
//! ```text
//! cd crates/misty-sync/fuzz
//! cargo +nightly fuzz run enroll_qr
//! ```
//!
//! A QR payload is the other input nobody authenticated: a camera reads it off a
//! screen, or off a sticker somebody left on a laptop. It is base64 of CBOR of a
//! struct with two user-supplied strings, and it is decoded *before* any
//! confirmation code has been compared, so this parser runs on whatever the
//! attacker put in front of the lens.
//!
//! The contract: any byte string either decodes to a request whose fields are
//! within bounds, or returns a typed error. And anything that decodes must
//! round-trip, because the approving device re-encodes the request to publish it
//! and a payload it could read but not write would strand an enrollment.

use libfuzzer_sys::fuzz_target;
use misty_sync::enroll::{decode_qr_payload, decode_request, encode_qr_payload};

fuzz_target!(|data: &[u8]| {
    // As bytes, for the CBOR path.
    if let Ok(request) = decode_request(data) {
        let payload = encode_qr_payload(&request).expect("a decodable request must re-encode");
        let again = decode_qr_payload(&payload).expect("and re-decode");
        assert_eq!(again, request, "the QR encoding does not round-trip");
        // The code is a pure function of the request, so it must agree too. It is
        // what the user compares out of band, and a code that depended on anything
        // outside the payload would be comparing two different things.
        assert_eq!(again.confirmation_code(), request.confirmation_code());
        assert_eq!(request.confirmation_code().len(), 6);
    }

    // As text, for the scanner path.
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(request) = decode_qr_payload(text) {
            let payload = encode_qr_payload(&request).expect("re-encode");
            assert_eq!(
                decode_qr_payload(&payload).expect("re-decode"),
                request,
                "the QR encoding does not round-trip"
            );
        }
    }
});
