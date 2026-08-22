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

    /// One item by hex id, or `null` if absent. Unlike [`item`](Self::item) this does
    /// not reject for a missing id — it is the "look, don't assert" reader.
    pub fn get(&self, id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.get(id).await.map_err(err_to_js).and_then(to_js) })
    }

    /// Live items in a given sort order: `"Manual"`, `"Issuer"`, `"LastUsed"`,
    /// `"MostUsed"`, or `"Created"`.
    pub fn sorted(&self, key: JsValue) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            let key: misty::dto::SortKey = serde_wasm_bindgen::from_value(key)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            f.sorted(key).await.map_err(err_to_js).and_then(to_js)
        })
    }

    /// Items currently in the trash.
    pub fn trash(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.trash().await.map_err(err_to_js).and_then(to_js) })
    }

    /// All groups, tombstones included — a caller that wants only live groups filters on
    /// `is_deleted` rather than being handed a pre-filtered list it cannot audit.
    pub fn groups(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.groups().await.map_err(err_to_js).and_then(to_js) })
    }

    /// One group by hex id, or a `NOT_FOUND` rejection.
    pub fn group(&self, id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.group(id).await.map_err(err_to_js).and_then(to_js) })
    }

    /// The unresolved merge conflicts. These are **not** errors: they ride inside an
    /// owned DTO and are never thrown (SPEC §11.3.1).
    pub fn conflicts(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.conflicts().await.map_err(err_to_js).and_then(to_js) })
    }

    /// Apply a sparse edit from an `EditInput` object. A field left absent is unchanged;
    /// naming a field in `clear` resets it to absent (SPEC §11.2).
    pub fn update(&self, id: String, edit: JsValue) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            let edit: misty::dto::EditInput = serde_wasm_bindgen::from_value(edit)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            f.update(id, edit)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// Move an item to the trash.
    #[wasm_bindgen(js_name = trashItem)]
    pub fn trash_item(&self, id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.trash_item(id)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// Restore an item from the trash.
    #[wasm_bindgen(js_name = restoreItem)]
    pub fn restore_item(&self, id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.restore_item(id)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// Delete an item, leaving a tombstone so the deletion converges (SPEC §4).
    #[wasm_bindgen(js_name = deleteItem)]
    pub fn delete_item(&self, id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.delete_item(id)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// Record a use of an item: the flattened G-counter and the last-used time.
    #[wasm_bindgen(js_name = recordUse)]
    pub fn record_use(&self, id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.record_use(id)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// Create a group; resolves with its new hex id.
    #[wasm_bindgen(js_name = addGroup)]
    pub fn add_group(&self, name: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.add_group(name)
                .await
                .map(JsValue::from)
                .map_err(err_to_js)
        })
    }

    /// Delete a group, leaving a tombstone.
    #[wasm_bindgen(js_name = deleteGroup)]
    pub fn delete_group(&self, id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.delete_group(id)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// Replace a mis-typed secret on an existing item. The bytes are zeroized on our
    /// side; the caller should overwrite its own buffer too (SPEC §11.6).
    #[wasm_bindgen(js_name = repairSecret)]
    pub fn repair_secret(&self, id: String, secret: Vec<u8>) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.repair_secret(id, secret)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// Advance a HOTP counter by one; resolves with the new value.
    #[wasm_bindgen(js_name = advanceHotpCounter)]
    pub fn advance_hotp_counter(&self, id: String) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.advance_hotp_counter(id)
                .await
                .map_err(err_to_js)
                .and_then(to_js)
        })
    }

    /// Set a HOTP counter explicitly; resolves with the stored value.
    #[wasm_bindgen(js_name = setHotpCounter)]
    pub fn set_hotp_counter(&self, id: String, counter: u64) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.set_hotp_counter(id, counter)
                .await
                .map_err(err_to_js)
                .and_then(to_js)
        })
    }

    /// Age expired items out of the trash; resolves with their hex ids.
    #[wasm_bindgen(js_name = sweepTrash)]
    pub fn sweep_trash(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move { f.sweep_trash().await.map_err(err_to_js).and_then(to_js) })
    }

    /// Drop tombstones past the retention horizon; resolves with their hex ids.
    #[wasm_bindgen(js_name = purgeTombstones)]
    pub fn purge_tombstones(&self) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.purge_tombstones()
                .await
                .map_err(err_to_js)
                .and_then(to_js)
        })
    }

    /// Merge an incoming item into an existing one rather than storing a duplicate
    /// (SPEC §3.1).
    #[wasm_bindgen(js_name = mergeDuplicate)]
    pub fn merge_duplicate(&self, existing: String, input: JsValue) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            let input: misty::dto::NewItemInput = serde_wasm_bindgen::from_value(input)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            f.merge_duplicate(existing, input)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
    }

    /// Approve a pending enrollment after the user has compared the confirmation code
    /// out of band (SPEC §6.3).
    #[wasm_bindgen(js_name = approveEnrollment)]
    pub fn approve_enrollment(
        &self,
        enroll_id: String,
        typed_code: String,
        server_url: String,
        enrolled_at: i64,
    ) -> js_sys::Promise {
        let f = self.inner.clone();
        future_to_promise(async move {
            f.approve_enrollment(enroll_id, typed_code, server_url, enrolled_at)
                .await
                .map(|()| JsValue::UNDEFINED)
                .map_err(err_to_js)
        })
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

/// Lower an owned DTO to a plain JS object (SPEC §11.7.2).
///
/// `None` crosses as `null`, not `undefined`, and that is a deliberate departure from
/// `serde_wasm_bindgen`'s default. Three reasons, in increasing order of how much they
/// would hurt:
///
/// * `undefined` collapses "the key is absent" and "the value is empty" into one
///   observation. §11.2 makes that distinction load-bearing — `ClearableField` exists
///   precisely because clearing a field is not the same as leaving it alone — so the
///   boundary should not discard it on the way out.
/// * `JSON.stringify` drops `undefined` properties entirely. A DTO captured for a test
///   fixture, a bug report, or a log would silently lose its optional fields.
/// * UniFFI lowers `Option<T>` to a real nullable (`T?`), so `null` is what keeps the
///   two bindings carrying the same value rather than merely the same field names.
fn to_js<T: serde::Serialize>(value: T) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_missing_as_null(true);
    value
        .serialize(&serializer)
        .map_err(|e| JsValue::from_str(&e.to_string()))
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
