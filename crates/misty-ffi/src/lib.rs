// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Misty's binding shim (SPEC §11.7): it lowers the [`misty`] facade to the two
//! foreign toolchains and holds no logic of its own.
//!
//! * On `wasm32`, `web` exposes the facade to JavaScript through `wasm-bindgen`:
//!   async methods return `Promise`s, DTOs cross as plain serde objects, and errors
//!   reject with `{ code, message, retryable }` (§11.7.2).
//! * On every other target, [`native`] exposes the *same* facade to Kotlin (Android)
//!   and Swift (iOS / macOS / the desktop shell) through UniFFI: async methods become
//!   `suspend fun` / Swift `async`, the DTOs cross as `data class`/`struct` values, and
//!   failures are thrown carrying the same `{ code, message, retryable }` triple
//!   (§11.7.1). The DTOs are not re-declared here — they are `misty`'s own types,
//!   registered with UniFFI as remote types, so a facade change is a compile error
//!   rather than a silent divergence between the two bindings.
//!
//! Both bindings are built over the identical mock core ([`mock_facade`]) from the
//! identical [`mock_fixtures`], which is what lets one conformance suite (§11.8.2) run
//! the same script through both and compare the results.
//!
//! This crate is the one exception to `#![forbid(unsafe_code)]` (SPEC §10 rule 1):
//! the binding toolchains generate `unsafe`. It adds none of its own.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(target_arch = "wasm32")]
pub mod web;

// The UniFFI scaffolding for the whole crate. The namespace is set explicitly so the
// generated module is `misty` (`misty.swift`, `misty.kt`) rather than `misty_ffi`: the
// binding shim is an implementation detail, and the API foreign code sees is the
// facade's (SPEC §11.7).
#[cfg(not(target_arch = "wasm32"))]
uniffi::setup_scaffolding!("misty");

use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::{DeviceId, VaultId};
use misty_otp::FixedClock;
use misty_sync::{duplicate_identity, MemoryStateStore, MockServer, SyncConfig, SyncEngine};
use misty_vault::MemoryStore;

/// The wall-clock reading the mock core is pinned to — a fixed value inside the §4.1
/// HLC window, so `generate` yields the same code on every runtime (SPEC §11.8.2).
const MOCK_NOW_MS: u64 = 1_700_000_000_000;
/// The auto-lock timeout the mock core is configured with, milliseconds (SPEC §11.5).
const MOCK_TIMEOUT_MS: i64 = 60_000;
/// The mock vault id.
const MOCK_VAULT_ID: [u8; 16] = [0x11; 16];
/// The vault key both mock devices unlock with — an obvious dummy, as §8 requires of
/// fixtures in a public repository.
const MOCK_VAULT_KEY: [u8; 32] = [0x2b; 32];
/// The TOTP secret the conformance flow adds — an obvious dummy (§8).
const MOCK_TOTP_SECRET: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
/// The device seed this build *is*.
const MOCK_LOCAL_SEED: u8 = 1;
/// The device seed of the pre-enrolled peer the flow revokes (§6.4).
const MOCK_PEER_SEED: u8 = 2;

/// The inputs every binding's conformance run uses, so no foreign language re-derives
/// a fixture and none of them can quietly disagree (SPEC §11.8.2).
///
/// Inputs only. The *expected* outputs live in `conformance/fixtures.json` and are
/// pinned as literals by each suite — if Rust also handed those over, a suite would be
/// asserting the core against itself.
#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct MockFixtures {
    /// The vault key to unlock with.
    pub vault_key: Vec<u8>,
    /// The TOTP secret to add.
    pub totp_secret: Vec<u8>,
    /// The pre-enrolled peer device's id, lowercase hex — the device the flow revokes.
    pub peer_device_id: String,
    /// The pinned wall-clock reading, unix ms.
    pub now_ms: i64,
    /// The configured auto-lock timeout, ms.
    pub auto_lock_timeout_ms: i64,
}

/// The [`MockFixtures`] for this build.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
#[must_use]
pub fn mock_fixtures() -> MockFixtures {
    MockFixtures {
        vault_key: MOCK_VAULT_KEY.to_vec(),
        totp_secret: MOCK_TOTP_SECRET.to_vec(),
        peer_device_id: mock_device(MOCK_PEER_SEED).device_id().to_hex(),
        now_ms: MOCK_NOW_MS as i64,
        auto_lock_timeout_ms: MOCK_TIMEOUT_MS,
    }
}

/// A mock device identity, derived from a seed exactly as
/// `crates/misty/tests/conformance.rs` derives it — same seeds, same ids, same roster.
fn mock_device(seed: u8) -> DeviceIdentity {
    DeviceIdentity::from_secret_bytes(
        DeviceId::from_bytes([seed; 16]),
        &[seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
    )
}

/// Build the in-memory mock core (SPEC §11.8.1): the real facade compiled with
/// `MemoryStore` + `MockTransport`, two signed devices in a pre-signed roster, and a
/// fixed clock. This is a *build configuration* of `crates/misty`, not a
/// reimplementation — it exercises the real merge, envelope, and sync state machine
/// with only the disk and the network swapped for deterministic doubles.
///
/// The second device is pre-rostered so the flow's `revoke` step (§6.4) has something
/// to revoke, matching the native Rust conformance test rather than diverging from it.
///
/// Returns the handle and the owning task, which the caller drives: `tokio::spawn` on
/// native, `spawn_local` on wasm (§11.4.3).
pub fn mock_facade() -> (misty::Facade, impl core::future::Future<Output = ()>) {
    let local = mock_device(MOCK_LOCAL_SEED);
    let peer = mock_device(MOCK_PEER_SEED);

    let mut roster = Roster::new(vec![
        local
            .record("this device", "mock", 1, None)
            .expect("local device record"),
        peer.record("peer device", "mock", 1, None)
            .expect("peer device record"),
    ]);
    roster.sign(&local).expect("sign roster");

    let vault_id = VaultId::from_bytes(MOCK_VAULT_ID);
    let server = MockServer::new(vault_id).expect("mock server");
    server.register(&local);
    server.register(&peer);

    let engine = SyncEngine::new(
        server.transport(),
        SyncConfig::new(vault_id, server.time_public_key()),
        duplicate_identity(&local),
        MemoryStateStore::new(),
    )
    .expect("sync engine");

    misty::spawn(
        MemoryStore::new(),
        FixedClock::new(MOCK_NOW_MS),
        local,
        roster,
        engine,
        misty::ManualClock::new(0),
        MOCK_TIMEOUT_MS,
    )
}
