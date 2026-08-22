// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The wasm leg of the SPEC §11.8 conformance gate: the real facade, compiled to
//! `wasm32` with the mock core, driven through the flow inside a headless browser.
//!
//! Same script, same fixtures, and the same pinned literals as
//! `tests/native.rs` (the exported UniFFI object) and
//! `conformance/ConformanceFlow.swift` (the generated Swift). Run with a matching
//! chromedriver, e.g.:
//!
//! ```sh
//! CHROMEDRIVER=/path/to/chromedriver \
//!   cargo test -p misty-ffi --target wasm32-unknown-unknown
//! ```
//!
//! The driver differs from the native leg by necessity: `block_on` does not exist here
//! (§11.4.3), so the actor task runs on the browser's own event loop via `spawn_local`,
//! with the mock sleeper collapsing every sync delay so no wall-clock time passes.

#![cfg(target_arch = "wasm32")]

use misty::dto::{HashAlg, NewItemInput, OtpKind};
use misty::{ErrorCode, LifecycleEvent};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// Expected outputs, pinned. Keep in step with `conformance/fixtures.json` and with the
/// literals in `tests/native.rs` and `conformance/ConformanceFlow.swift`.
const EXPECTED_CODE: &str = "746722";
const EXPECTED_ISSUER: &str = "GitHub";
const EXPECTED_ACCOUNT: &str = "ada@example.com";

fn new_totp(secret: Vec<u8>) -> NewItemInput {
    NewItemInput {
        kind: OtpKind::Totp,
        algorithm: HashAlg::Sha1,
        digits: 6,
        period: 30,
        hotp_counter: 0,
        secret,
        pin: None,
        issuer: EXPECTED_ISSUER.to_string(),
        account: EXPECTED_ACCOUNT.to_string(),
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
    let fixtures = misty_ffi::mock_fixtures();
    let (facade, task) = misty_ffi::mock_facade();
    wasm_bindgen_futures::spawn_local(task);

    // enroll — the mock core's pre-signed two-device roster (§11.8.1).
    assert!(facade.lock_state().await.unwrap().locked, "starts locked");
    facade.unlock(fixtures.vault_key.clone()).await.unwrap();
    assert!(!facade.lock_state().await.unwrap().locked);

    // add
    let id = facade
        .add(new_totp(fixtures.totp_secret.clone()))
        .await
        .unwrap();
    let item = facade.item(id.clone()).await.unwrap();
    assert_eq!(item.issuer, EXPECTED_ISSUER);
    assert_eq!(item.account, EXPECTED_ACCOUNT);
    assert!(!item.has_pin);

    // generate — an exact value: the clock is pinned, so a length check would be weaker.
    let code = facade.generate_code(id.clone()).await.unwrap();
    assert_eq!(code.code, EXPECTED_CODE);
    assert_eq!(code.period_ms, 30_000);

    // sync
    let report = facade.sync_once().await.unwrap();
    assert_eq!(report.pushed, 1);
    assert!(report.conflicts.is_empty());
    assert_eq!(facade.list().await.unwrap().len(), 1);
    assert_eq!(
        facade
            .search(EXPECTED_ISSUER.to_string())
            .await
            .unwrap()
            .len(),
        1
    );

    // The same fixed corpus of failures, asserted on `code` alone (§11.3.2).
    assert_eq!(
        facade.item("00".repeat(16)).await.unwrap_err().code,
        ErrorCode::NotFound
    );

    // lock
    facade.lock().await.unwrap();
    assert!(facade.lock_state().await.unwrap().locked);
    assert_eq!(
        facade.list().await.unwrap_err().code,
        ErrorCode::VaultLocked
    );
    assert_eq!(
        facade.sync_once().await.unwrap_err().code,
        ErrorCode::VaultLocked
    );

    // unlock
    facade.unlock(fixtures.vault_key.clone()).await.unwrap();
    assert!(!facade.lock_state().await.unwrap().locked);

    // revoke (§6.4)
    facade
        .revoke_device(fixtures.peer_device_id.clone())
        .await
        .unwrap();
    assert_eq!(
        facade.generate_code(id).await.unwrap().code,
        EXPECTED_CODE,
        "the code survives epoch rotation"
    );
    facade.sync_once().await.unwrap();

    assert!(
        facade
            .report_lifecycle(LifecycleEvent::Backgrounded)
            .await
            .unwrap()
            .locked
    );

    facade.shutdown().await.unwrap();
}
