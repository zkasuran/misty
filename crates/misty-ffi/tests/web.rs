// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The wasm leg of the SPEC §11.8 conformance gate: the real facade, compiled to
//! `wasm32` with the mock core, driven through the flow inside a headless browser.
//! Run with a matching chromedriver, e.g.:
//!
//! ```sh
//! CHROMEDRIVER=/path/to/chromedriver \
//!   cargo test -p misty-ffi --target wasm32-unknown-unknown
//! ```

#![cfg(target_arch = "wasm32")]

use misty::dto::{HashAlg, NewItemInput, OtpKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::{DeviceId, VaultId};
use misty_otp::FixedClock;
use misty_sync::{duplicate_identity, MemoryStateStore, MockServer, SyncConfig, SyncEngine};
use misty_vault::MemoryStore;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

const NOW: u64 = 1_700_000_000_000;

fn new_totp() -> NewItemInput {
    NewItemInput {
        kind: OtpKind::Totp,
        algorithm: HashAlg::Sha1,
        digits: 6,
        period: 30,
        hotp_counter: 0,
        secret: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        pin: None,
        issuer: "GitHub".to_string(),
        account: "ada@example.com".to_string(),
        nickname: None,
        note: None,
        groups: Vec::new(),
        tags: Vec::new(),
        origins: Vec::new(),
        icon: None,
        color: None,
        favorite: false,
    }
}

#[wasm_bindgen_test]
async fn the_facade_runs_the_flow_in_a_browser() {
    let device =
        DeviceIdentity::from_secret_bytes(DeviceId::from_bytes([1u8; 16]), &[2u8; 32], [3u8; 32]);
    let mut roster = Roster::new(vec![device.record("web", "wasm", 1, None).unwrap()]);
    roster.sign(&device).unwrap();
    let vault_id = VaultId::from_bytes([0x11; 16]);
    let server = MockServer::new(vault_id).unwrap();
    server.register(&device);
    let engine = SyncEngine::new(
        server.transport(),
        SyncConfig::new(vault_id, server.time_public_key()),
        duplicate_identity(&device),
        MemoryStateStore::new(),
    )
    .unwrap();

    // Drive the real facade on the browser's own event loop (spawn_local, not block_on).
    let (facade, task) = misty::spawn(
        MemoryStore::new(),
        FixedClock::new(NOW),
        device,
        roster,
        engine,
        misty::ManualClock::new(0),
        60_000,
    );
    wasm_bindgen_futures::spawn_local(task);

    facade.unlock(vec![0x2b; 32]).await.unwrap();
    let id = facade.add(new_totp()).await.unwrap();
    let code = facade.generate_code(id).await.unwrap();
    assert_eq!(code.code.len(), 6);
    facade.sync_once().await.unwrap();
    assert_eq!(facade.list().await.unwrap().len(), 1);
    facade.lock().await.unwrap();
    assert!(facade.lock_state().await.unwrap().locked);
    facade.shutdown().await.unwrap();
}
