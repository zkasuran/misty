// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#![no_main]
//! Fuzzes the envelope decode path (SPEC §10 rule 7).
//!
//! Run with:
//!
//! ```text
//! cd crates/misty-crypto/fuzz
//! cargo +nightly fuzz run envelope_open
//! ```
//!
//! The contract: for **any** byte string, `Envelope::parse` and
//! `envelope::open` either succeed or return a typed error. No panic, no
//! unbounded allocation, no infinite loop. `envelope::open` is the function a
//! hostile sync server feeds directly (threat model `A1`), so it is the single
//! most exposed entry point in the crate.
//!
//! The fixed keys and roster are built once: the target is the parser and the
//! verification order, not key generation.

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use misty_crypto::derive;
use misty_crypto::envelope::{self, Envelope};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::keys::{EpochKey, VaultKey};
use misty_crypto::{DeviceId, ItemId};

struct Fixture {
    roster: Roster,
    epoch_key: EpochKey,
    item_id: ItemId,
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let identity = DeviceIdentity::from_secret_bytes(
        DeviceId::from_bytes([0x41; 16]),
        &[0x42; 32],
        [0x43; 32],
    );
    let mut roster = Roster::new(vec![identity
        .record("Fuzz Device", "linux", 1, None)
        .expect("record")]);
    roster.sign(&identity).expect("sign");
    Fixture {
        roster,
        epoch_key: derive::epoch_key(&VaultKey::from_bytes([0x44; 32]), 2).expect("epoch key"),
        item_id: ItemId::from_bytes([0x45; 16]),
    }
});

fuzz_target!(|data: &[u8]| {
    let fixture = &*FIXTURE;
    let _ = Envelope::parse(data);
    let _ = envelope::open(data, &fixture.item_id, &fixture.epoch_key, &fixture.roster);
    // Also the bootstrap path, which skips the roster lookup.
    let _ = envelope::open_with_signer(data, &fixture.item_id, &fixture.epoch_key, &[0x42; 32]);
    // And the padding parser on its own, so the fuzzer can reach it without
    // having to forge a signature first.
    let _ = envelope::unpad(data);
});
