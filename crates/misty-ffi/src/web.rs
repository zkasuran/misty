// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The wasm-bindgen web/extension binding (SPEC §11.7.2).

use misty::Facade;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

/// The Misty facade, exposed to JavaScript and configured with the in-memory mock
/// core (SPEC §11.8.1). Every method returns a `Promise`: it resolves with an owned
/// DTO (a plain object) or rejects with `{ code, message, retryable }` (§11.3).
#[wasm_bindgen]
pub struct MistyFacade {
    inner: Facade,
}

#[wasm_bindgen]
impl MistyFacade {
    /// Build the facade over the mock core and start its owning task.
    #[wasm_bindgen(constructor)]
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let (inner, task) = crate::mock_facade();
        wasm_bindgen_futures::spawn_local(task);
        Self { inner }
    }

    /// Unlock the vault with raw key material.
    pub fn unlock(&self, key: Vec<u8>) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.unlock(key)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// Add an item from a `NewItemInput` object; resolves with its hex id.
    pub fn add(&self, input: JsValue) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            let input: misty::dto::NewItemInput = serde_wasm_bindgen::from_value(input)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            f.add(input).await.map(JsValue::from).map_err(err_to_js)
        })
    }

    /// Generate the current code for an item; resolves with a `CodeView`.
    #[wasm_bindgen(js_name = generateCode)]
    pub fn generate_code(&self, id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(
            async move { f.generate_code(id).await.map_err(err_to_js).and_then(to_js) },
        )
    }

    /// All live items as `ItemView` objects.
    pub fn list(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.list().await.map_err(err_to_js).and_then(to_js) })
    }

    /// Run one sync round-trip; resolves with a `SyncReportView`.
    #[wasm_bindgen(js_name = syncOnce)]
    pub fn sync_once(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.sync_once().await.map_err(err_to_js).and_then(to_js) })
    }

    /// Lock the vault now.
    pub fn lock(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.lock()
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// The current lock state as a `{ locked }` object.
    #[wasm_bindgen(js_name = lockState)]
    pub fn lock_state(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.lock_state().await.map_err(err_to_js).and_then(to_js) })
    }

    /// A wake-only poll that re-runs the auto-lock deadline check (SPEC §11.5.4). This
    /// is what makes the extension's auto-lock survive a reaped MV3 service worker:
    /// the deadline is an absolute timestamp checked on wake, not a timer that dies
    /// with the worker (§9.1).
    pub fn poll(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.poll().await.map_err(err_to_js).and_then(to_js) })
    }

    /// Report a shell lifecycle event — `"Backgrounded"`, `"ScreenLocked"`,
    /// `"WillSleep"`, or `"UserActivity"` (SPEC §11.5.5). Resolves with the resulting
    /// lock state.
    #[wasm_bindgen(js_name = reportLifecycle)]
    pub fn report_lifecycle(&self, event: JsValue) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            let event: misty::LifecycleEvent = serde_wasm_bindgen::from_value(event)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            f.report_lifecycle(event)
                .await
                .map_err(err_to_js)
                .and_then(to_js)
        })
    }

    /// One item by hex id as an `ItemView`, or a `NOT_FOUND` rejection.
    pub fn item(&self, id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.item(id).await.map_err(err_to_js).and_then(to_js) })
    }

    /// Live items whose issuer/account/labels match `query`.
    pub fn search(&self, query: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.search(query).await.map_err(err_to_js).and_then(to_js) })
    }

    /// Revoke a device by hex id: the epoch rotates and the vault is re-sealed under a
    /// successor roster (SPEC §6.4).
    #[wasm_bindgen(js_name = revokeDevice)]
    pub fn revoke_device(&self, device_id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.revoke_device(device_id)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// Stop the owning task. An explicit command, not a dropped promise.
    pub fn shutdown(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.shutdown()
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }
}

/// The shared conformance fixtures (SPEC §11.8.2), as a plain object — the same values
/// `mock_fixtures()` hands the UniFFI bindings, so neither leg re-derives a device id
/// or a key.
#[wasm_bindgen(js_name = mockFixtures)]
pub fn mock_fixtures() -> Result<JsValue, JsValue> {
    to_js(crate::mock_fixtures())
}

fn to_js<T: serde::Serialize>(value: T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&value).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Lower a [`misty::FacadeError`] to the JS rejection object `{ code, message,
/// retryable }` — the stable `code` is what bindings branch on (SPEC §11.3.2).
fn err_to_js(error: misty::FacadeError) -> JsValue {
    let obj = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("code"),
        &JsValue::from_str(error.code.as_str()),
    );
    let _ = js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("message"),
        &JsValue::from_str(&error.message),
    );
    let _ = js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("retryable"),
        &JsValue::from_bool(error.retryable()),
    );
    obj.into()
}
