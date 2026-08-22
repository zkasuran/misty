// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The §11.8.2 conformance flow driven through the **exported UniFFI surface** —
//! `native::MistyFacade`, not `misty::Facade` — on the native target.
//!
//! `crates/misty/tests/conformance.rs` already runs this flow against the Rust facade;
//! this runs it one layer out, through the object Kotlin and Swift are generated from,
//! so a break in the binding shim is caught here rather than in a foreign toolchain.
//! `conformance/ConformanceFlow.swift` asserts the *same* literals against the *same*
//! fixtures; `conformance/fixtures.json` is where those literals are written down.

#![cfg(not(target_arch = "wasm32"))]

use misty_ffi::native::{MistyError, MistyFacade};

/// Expected outputs, pinned. Keep in step with `conformance/fixtures.json` and with the
/// literals in `conformance/ConformanceFlow.swift` — three copies of one contract is the
/// point: if the bindings disagree, one of them fails.
const EXPECTED_CODE: &str = "746722";
const EXPECTED_ISSUER: &str = "GitHub";
const EXPECTED_ACCOUNT: &str = "ada@example.com";

fn new_totp(secret: Vec<u8>) -> misty::dto::NewItemInput {
    misty::dto::NewItemInput {
        kind: misty::dto::OtpKind::Totp,
        algorithm: misty::dto::HashAlg::Sha1,
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

/// Assert a call failed with a specific stable `code` — never on the message (§11.3.2).
fn assert_code(error: &MistyError, expected: &str) {
    let MistyError::Failed {
        code, retryable, ..
    } = error;
    assert_eq!(code, expected, "stable error code");
    assert!(!retryable, "{expected} is not retryable (§11.3.3)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_exported_object_runs_the_flow() {
    let fixtures = misty_ffi::mock_fixtures();
    let facade = MistyFacade::new().expect("construct the facade over the mock core");

    // enroll — represented by the mock core's pre-signed two-device roster (§11.8.1),
    // exactly as crates/misty/tests/conformance.rs represents it.
    assert!(
        facade.lock_state().await.unwrap().locked,
        "the facade starts locked (§11.5)"
    );
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
    assert!(!item.has_pin, "no PIN was set, and no secret is surfaced");

    // generate — the pinned clock makes this an exact value, not a length check.
    let code = facade.generate_code(id.clone()).await.unwrap();
    assert_eq!(code.code, EXPECTED_CODE);
    assert_eq!(code.period_ms, 30_000);

    // sync
    let report = facade.sync_once().await.unwrap();
    assert_eq!(report.pushed, 1, "the new item was pushed");
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

    // A fixed corpus of failures, asserted on `code` alone (§11.3.2).
    assert_code(
        &facade.item("00".repeat(16)).await.unwrap_err(),
        "NOT_FOUND",
    );

    // lock — reads and sync then fail with VAULT_LOCKED.
    facade.lock().await.unwrap();
    assert!(facade.lock_state().await.unwrap().locked);
    assert_code(&facade.list().await.unwrap_err(), "VAULT_LOCKED");
    assert_code(&facade.sync_once().await.unwrap_err(), "VAULT_LOCKED");

    // unlock
    facade.unlock(fixtures.vault_key.clone()).await.unwrap();
    assert!(!facade.lock_state().await.unwrap().locked);

    // revoke — the epoch rotates, the vault is re-sealed under a successor roster, and
    // the code survives it (§6.4).
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

    // A lifecycle event locks immediately (§11.5.5).
    assert!(
        facade
            .report_lifecycle(misty::LifecycleEvent::Backgrounded)
            .await
            .unwrap()
            .locked
    );

    facade.shutdown().await.unwrap();
}
