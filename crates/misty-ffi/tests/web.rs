// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The wasm leg of the SPEC §11.8 conformance gate, driven through the **exported
//! wasm-bindgen surface** — `web::MistyFacade`, the class JavaScript actually holds.
//!
//! This distinction is the whole value of the leg. An earlier version of this file
//! called `misty::Facade` directly and never touched the binding: it awaited Rust
//! futures, read Rust structs, and matched on a Rust `ErrorCode`. Everything the wasm
//! projection actually does — `future_to_promise`, serde-lowering a DTO to a plain
//! object, serde-*raising* a plain object into `NewItemInput`, and `err_to_js` building
//! the `{ code, message, retryable }` rejection — was untested, so a break in any of it
//! would have shipped green. That is the §11.8 failure mode inside the gate meant to
//! catch it.
//!
//! So every call below goes through a `Promise` and every value is read with
//! `Reflect::get`, exactly as JavaScript reads it. Inputs are built as plain JS objects,
//! which is what proves the serde *enum* representations (`kind: "Totp"`,
//! `algorithm: "Sha1"`, a bare `"Backgrounded"` string for a lifecycle event) are what
//! the facade expects.
//!
//! Same script, same fixtures, and the same pinned literals as `tests/native.rs` (the
//! exported UniFFI object) and `conformance/ConformanceFlow.swift` (the generated
//! Swift). Run it with a matching chromedriver:
//!
//! ```sh
//! CHROMEDRIVER=/path/to/chromedriver \
//!   cargo test -p misty-ffi --target wasm32-unknown-unknown --test web
//! ```
//!
//! The driver differs from the native leg by necessity: `block_on` does not exist here
//! (§11.4.3), so the actor task runs on the browser's own event loop via `spawn_local`,
//! with the mock sleeper collapsing every sync delay so no wall-clock time passes.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

use misty_ffi::web::MistyFacade;

wasm_bindgen_test_configure!(run_in_browser);

// --- expected outputs, pinned (conformance/fixtures.json) ---

const EXPECTED_CODE: &str = "746722";
const EXPECTED_PERIOD_MS: f64 = 30_000.0;
const EXPECTED_ISSUER: &str = "GitHub";
const EXPECTED_ACCOUNT: &str = "ada@example.com";

// Only the stable `code` is asserted — never `message` (§11.3.2).
const UNKNOWN_ITEM_ID: &str = "NOT_FOUND";
const READ_WHILE_LOCKED: &str = "VAULT_LOCKED";
const SYNC_WHILE_LOCKED: &str = "VAULT_LOCKED";

// --- reading values the way JavaScript reads them ---

fn get(object: &JsValue, key: &str) -> JsValue {
    js_sys::Reflect::get(object, &JsValue::from_str(key))
        .unwrap_or_else(|_| panic!("property `{key}` is readable"))
}

fn get_string(object: &JsValue, key: &str) -> String {
    get(object, key)
        .as_string()
        .unwrap_or_else(|| panic!("property `{key}` is a string"))
}

fn get_bool(object: &JsValue, key: &str) -> bool {
    get(object, key)
        .as_bool()
        .unwrap_or_else(|| panic!("property `{key}` is a boolean"))
}

fn get_number(object: &JsValue, key: &str) -> f64 {
    get(object, key)
        .as_f64()
        .unwrap_or_else(|| panic!("property `{key}` is a number"))
}

fn array_len(value: &JsValue) -> u32 {
    js_sys::Array::from(value).length()
}

/// Await a `Promise` the binding returned and expect it to resolve.
async fn resolve(promise: js_sys::Promise) -> JsValue {
    JsFuture::from(promise).await.expect("the promise resolved")
}

/// Await a `Promise` expecting a **rejection**, and return the stable `code` off it.
///
/// Asserting the code rather than merely "it threw" is the §11.3.2 rule: a binding that
/// rejected with the right shape and the wrong code would pass a bare `catch`. The
/// `retryable` flag is checked at the same time, since it is a frozen function of the
/// code (§11.3.3) and neither of these codes is transient.
async fn reject_code(promise: js_sys::Promise) -> String {
    let error = JsFuture::from(promise)
        .await
        .expect_err("the promise rejected");
    assert!(
        !get_bool(&error, "retryable"),
        "this failure must not be marked retryable"
    );
    assert!(
        !get_string(&error, "message").is_empty(),
        "a message is present, even though nothing may parse it"
    );
    get_string(&error, "code")
}

/// Build the `NewItemInput` as a plain JS object — the serde shape a real caller sends.
/// Enum fields cross as their variant names, which is the part a Rust-level test cannot
/// check.
fn new_totp_object(secret: &[u8]) -> JsValue {
    let object = js_sys::Object::new();
    let set = |key: &str, value: JsValue| {
        js_sys::Reflect::set(&object, &JsValue::from_str(key), &value).expect("set property");
    };

    set("kind", JsValue::from_str("Totp"));
    set("algorithm", JsValue::from_str("Sha1"));
    set("digits", JsValue::from_f64(6.0));
    set("period", JsValue::from_f64(30.0));
    set("hotp_counter", JsValue::from_f64(0.0));
    set(
        "secret",
        js_sys::Uint8Array::from(secret).unchecked_into::<JsValue>(),
    );
    set("pin", JsValue::NULL);
    set("issuer", JsValue::from_str(EXPECTED_ISSUER));
    set("account", JsValue::from_str(EXPECTED_ACCOUNT));
    set("nickname", JsValue::NULL);
    set("note", JsValue::NULL);
    set("groups", js_sys::Array::new().unchecked_into::<JsValue>());
    set("tags", js_sys::Array::new().unchecked_into::<JsValue>());
    set("origins", js_sys::Array::new().unchecked_into::<JsValue>());
    set("icon", JsValue::NULL);
    set("color", JsValue::NULL);
    set("favorite", JsValue::FALSE);

    object.unchecked_into()
}

#[wasm_bindgen_test]
async fn the_js_binding_runs_the_conformance_flow_in_a_browser() {
    // Inputs come from the shared fixture set, never re-derived here (§11.8.2). The
    // Rust accessor supplies the byte buffers; the JS-visible `mockFixtures()` is
    // asserted to agree, which is what proves that accessor crosses the boundary.
    let fixtures = misty_ffi::mock_fixtures();
    let js_fixtures = misty_ffi::web::mock_fixtures().expect("mockFixtures() lowers to JS");
    assert_eq!(
        get_string(&js_fixtures, "peer_device_id"),
        fixtures.peer_device_id,
        "the JS fixture accessor reports the same peer device"
    );

    let facade = MistyFacade::new();

    // enroll — the mock core's pre-signed two-device roster (§11.8.1).
    let state = resolve(facade.lock_state()).await;
    assert!(get_bool(&state, "locked"), "the facade starts locked");

    resolve(facade.unlock(fixtures.vault_key.clone())).await;
    let state = resolve(facade.lock_state()).await;
    assert!(!get_bool(&state, "locked"));

    // add — a plain JS object in, a hex id string out.
    let id = resolve(facade.add(new_totp_object(&fixtures.totp_secret)))
        .await
        .as_string()
        .expect("add resolves with a hex id string");

    let item = resolve(facade.item(id.clone())).await;
    assert_eq!(get_string(&item, "issuer"), EXPECTED_ISSUER);
    assert_eq!(get_string(&item, "account"), EXPECTED_ACCOUNT);
    assert!(!get_bool(&item, "has_pin"), "no PIN was set");
    assert_eq!(
        get_string(&item, "kind"),
        "Totp",
        "the enum round-trips through serde unchanged"
    );
    assert_eq!(get_string(&item, "algorithm"), "Sha1");
    assert!(
        get(&item, "secret").is_undefined(),
        "an ItemView has no secret field at all (§11.2)"
    );

    // generate — an exact value, because the clock is pinned (§11.8.2).
    let code = resolve(facade.generate_code(id.clone())).await;
    assert_eq!(get_string(&code, "code"), EXPECTED_CODE);
    assert_eq!(get_number(&code, "period_ms"), EXPECTED_PERIOD_MS);

    // sync
    let report = resolve(facade.sync_once()).await;
    assert_eq!(
        get_number(&report, "pushed"),
        1.0,
        "the new item was pushed"
    );
    assert_eq!(array_len(&get(&report, "conflicts")), 0);
    assert_eq!(array_len(&resolve(facade.list()).await), 1);
    assert_eq!(
        array_len(&resolve(facade.search(EXPECTED_ISSUER.to_string())).await),
        1
    );

    // The same fixed corpus of failures, asserted on `code` alone (§11.3.2).
    assert_eq!(
        reject_code(facade.item("00".repeat(16))).await,
        UNKNOWN_ITEM_ID
    );

    // lock — reads and sync then reject with VAULT_LOCKED.
    resolve(facade.lock()).await;
    let state = resolve(facade.lock_state()).await;
    assert!(get_bool(&state, "locked"));
    assert_eq!(reject_code(facade.list()).await, READ_WHILE_LOCKED);
    assert_eq!(reject_code(facade.sync_once()).await, SYNC_WHILE_LOCKED);

    // unlock
    resolve(facade.unlock(fixtures.vault_key.clone())).await;
    let state = resolve(facade.lock_state()).await;
    assert!(!get_bool(&state, "locked"));

    // revoke — the epoch rotates, the vault is re-sealed under a successor roster, and
    // the code survives it (§6.4).
    resolve(facade.revoke_device(fixtures.peer_device_id.clone())).await;
    let code_after = resolve(facade.generate_code(id)).await;
    assert_eq!(
        get_string(&code_after, "code"),
        EXPECTED_CODE,
        "the code survives epoch rotation"
    );
    resolve(facade.sync_once()).await;

    // A lifecycle event locks immediately (§11.5.5). It crosses as a bare variant
    // string, which is the serde form the shell will send.
    let state = resolve(facade.report_lifecycle(JsValue::from_str("Backgrounded"))).await;
    assert!(
        get_bool(&state, "locked"),
        "backgrounding locks immediately"
    );

    // Shutdown is an explicit command, never a dropped promise.
    resolve(facade.shutdown()).await;
}

/// The rest of the JS surface, which the §11.8.2 flow does not touch.
///
/// This is deliberately **not** folded into the flow above: that script must stay
/// byte-identical across all five legs, so widening it here would make the wasm leg a
/// different test from the Swift and Kotlin ones. What this covers instead is the part
/// only JavaScript can get wrong — the serde *shape* of the input DTOs. `EditInput` and
/// `SortKey` cross as a plain object and a bare string, and a mismatch in either is
/// invisible to a Rust-level test because Rust builds them as typed values.
#[wasm_bindgen_test]
async fn the_js_binding_exposes_the_whole_facade() {
    let fixtures = misty_ffi::mock_fixtures();
    let facade = MistyFacade::new();
    resolve(facade.unlock(fixtures.vault_key.clone())).await;

    let id = resolve(facade.add(new_totp_object(&fixtures.totp_secret)))
        .await
        .as_string()
        .expect("hex id");

    // get() returns the item rather than rejecting, and null for an absent one.
    assert!(!resolve(facade.get(id.clone())).await.is_null());
    assert!(
        resolve(facade.get("00".repeat(16))).await.is_null(),
        "get() reports absence as null, it does not reject"
    );

    // sorted() takes a bare variant string.
    assert_eq!(
        array_len(&resolve(facade.sorted(JsValue::from_str("Issuer"))).await),
        1
    );

    // Groups: create, read back, attach via update(), then delete.
    let group_id = resolve(facade.add_group("Work".to_string()))
        .await
        .as_string()
        .expect("hex id");
    let group = resolve(facade.group(group_id.clone())).await;
    assert_eq!(get_string(&group, "name"), "Work");

    // EditInput as a plain object: a sparse edit, with absent fields left alone.
    let edit = js_sys::Object::new();
    js_sys::Reflect::set(
        &edit,
        &JsValue::from_str("nickname"),
        &JsValue::from_str("work github"),
    )
    .expect("set");
    let groups = js_sys::Array::new();
    groups.push(&JsValue::from_str(&group_id));
    js_sys::Reflect::set(&edit, &JsValue::from_str("groups"), &groups).expect("set");
    resolve(facade.update(id.clone(), edit.into())).await;

    let item = resolve(facade.item(id.clone())).await;
    assert_eq!(get_string(&item, "nickname"), "work github");
    assert_eq!(array_len(&get(&item, "groups")), 1);

    // Use counting, then the trash round trip.
    resolve(facade.record_use(id.clone())).await;
    assert_eq!(
        get_number(&resolve(facade.item(id.clone())).await, "use_count"),
        1.0
    );

    resolve(facade.trash_item(id.clone())).await;
    assert_eq!(array_len(&resolve(facade.trash()).await), 1);
    assert_eq!(array_len(&resolve(facade.list()).await), 0);
    resolve(facade.restore_item(id.clone())).await;
    assert_eq!(array_len(&resolve(facade.list()).await), 1);

    // Conflicts are a DTO, not a rejection (§11.3.1): an empty list, not a throw.
    assert_eq!(array_len(&resolve(facade.conflicts()).await), 0);

    resolve(facade.delete_group(group_id)).await;
    resolve(facade.delete_item(id)).await;
    assert_eq!(array_len(&resolve(facade.list()).await), 0);

    resolve(facade.shutdown()).await;
}
