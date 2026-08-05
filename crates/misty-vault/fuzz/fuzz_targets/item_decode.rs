// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#![no_main]
//! Fuzzes the CBOR item decoder (SPEC §10 rule 7).
//!
//! Run with:
//!
//! ```text
//! cd crates/misty-vault/fuzz
//! cargo +nightly fuzz run item_decode
//! ```
//!
//! The contract: for **any** byte string, [`decode_item`] and [`decode_group`]
//! either succeed or return a typed error. No panic, no unbounded allocation, no
//! infinite loop.
//!
//! This is the crate's hostile-input boundary. The envelope layer has already proved
//! that a rostered device signed these bytes, which is not the same as proving they
//! are well formed: the signer may have been an older build, a buggy importer, or a
//! device whose keys an attacker holds (threat model `A5`). Everything past this
//! function assumes the model's invariants hold, so this is where they are
//! established.
//!
//! Two extra properties are asserted rather than merely exercised:
//!
//! * anything that decodes must **re-encode**, because the encoder validates and a
//!   payload this crate can read but not write would be a row it could not update;
//! * re-encoding and decoding again must give the same bytes, because that is the
//!   canonicalisation the convergence property in SPEC §4 is measured on.
//!
//! `tests/hostile_inputs.rs` covers the same entry points on stable, so CI has
//! coverage of them on every commit without a fuzzing run.

use libfuzzer_sys::fuzz_target;
use misty_vault::{decode_group, decode_item, encode_group, encode_item, Hlc};

fuzz_target!(|data: &[u8]| {
    if let Ok(item) = decode_item(data) {
        let encoded = encode_item(&item).expect("a decodable item must re-encode");
        let again = decode_item(&encoded).expect("a re-encoded item must decode");
        let twice = encode_item(&again).expect("and re-encode again");
        assert_eq!(
            encoded.as_slice(),
            twice.as_slice(),
            "encoding is not canonical"
        );
    }

    if let Ok(group) = decode_group(data) {
        let encoded = encode_group(&group).expect("a decodable group must re-encode");
        let again = decode_group(&encoded).expect("a re-encoded group must decode");
        assert_eq!(
            encoded,
            encode_group(&again).expect("and re-encode again"),
            "encoding is not canonical"
        );
    }

    // The clock parser on its own, so the fuzzer can reach it without having to
    // build a whole valid payload first.
    let _ = Hlc::from_slice(data);
});
