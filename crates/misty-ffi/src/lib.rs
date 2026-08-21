// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Misty's binding shim (SPEC §11.7): it lowers the [`misty`] facade to the two
//! foreign toolchains and holds no logic of its own.
//!
//! * On `wasm32`, [`web`] exposes the facade to JavaScript through `wasm-bindgen`:
//!   async methods return `Promise`s, DTOs cross as plain serde objects, and errors
//!   reject with `{ code, message, retryable }` (§11.7.2).
//! * On native, the same facade is intended to be lowered to Kotlin and Swift through
//!   UniFFI; generating and *running* those bindings needs a JVM and (for Apple) a
//!   macOS runner, so that leg lives in CI (see the crate README).
//!
//! This crate is the one exception to `#![forbid(unsafe_code)]` (SPEC §10 rule 1):
//! the binding toolchains generate `unsafe`. It adds none of its own.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

#[cfg(target_arch = "wasm32")]
pub mod web;

/// Build the in-memory mock core (SPEC §11.8.1): the real facade compiled with
/// `MemoryStore` + `MockTransport`, a single signed device, and a fixed clock. This
/// is the configuration the web binding and the conformance suite develop against.
#[cfg(target_arch = "wasm32")]
fn mock_facade() -> (misty::Facade, impl core::future::Future<Output = ()>) {
    use misty_crypto::identity::{DeviceIdentity, Roster};
    use misty_crypto::{DeviceId, VaultId};
    use misty_otp::FixedClock;
    use misty_sync::{duplicate_identity, MemoryStateStore, MockServer, SyncConfig, SyncEngine};
    use misty_vault::MemoryStore;

    // A fixed reading inside the §4.1 HLC window; obvious dummy device seeds (§8).
    const NOW: u64 = 1_700_000_000_000;
    let device =
        DeviceIdentity::from_secret_bytes(DeviceId::from_bytes([1u8; 16]), &[2u8; 32], [3u8; 32]);
    let record = device.record("web", "wasm", 1, None).expect("record");
    let mut roster = Roster::new(vec![record]);
    roster.sign(&device).expect("sign roster");

    let vault_id = VaultId::from_bytes([0x11; 16]);
    let server = MockServer::new(vault_id).expect("mock server");
    server.register(&device);
    let engine = SyncEngine::new(
        server.transport(),
        SyncConfig::new(vault_id, server.time_public_key()),
        duplicate_identity(&device),
        MemoryStateStore::new(),
    )
    .expect("sync engine");

    misty::spawn(
        MemoryStore::new(),
        FixedClock::new(NOW),
        device,
        roster,
        engine,
        misty::ManualClock::new(0),
        60_000,
    )
}
