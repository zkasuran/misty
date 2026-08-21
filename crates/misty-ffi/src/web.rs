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
