// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The browser transport: `fetch`, and an honest account of what it cannot do.
//!
//! # There is no certificate pinning here, and there cannot be
//!
//! `fetch` gives no access to the TLS session, the peer certificate chain, or the
//! verification decision. The browser validates the certificate against its own
//! trust store and reports success or a network error; a page cannot inspect,
//! override or add to that. There is no Web API that would let it — not
//! `SubtleCrypto`, not Service Workers, not `WebTransport`. So the honest position
//! is that **threat model `A2`'s certificate pinning is absent on wasm**, and this
//! module says so rather than implementing something adjacent and calling it done.
//!
//! What holds the line instead:
//!
//! * Payloads are end-to-end encrypted and Ed25519-signed by a rostered device
//!   (SPEC §2.4). A network attacker who defeats TLS — by way of a mis-issued
//!   certificate the browser accepts — sees opaque envelopes, cannot forge one,
//!   and cannot get one merged.
//! * `/v1/time` is verified against a key pinned in the client bundle
//!   (SPEC §6.5), so the one thing a TLS attacker could otherwise do — walk the
//!   clock — is still refused.
//! * The change feed's `seq` monotonicity, the `deleted` flag being advisory, and
//!   the `409` attribution rule are all enforced above the transport, so they hold
//!   here identically.
//!
//! What is genuinely lost is traffic confidentiality against a mis-issued
//! certificate: sizes, item ids and write timing, which SPEC §1 `A1` already
//! accepts as visible to the server. The residual risk on wasm is therefore
//! "visible to a successful TLS attacker as well as to the server", which is a
//! real widening and is recorded as such in `README.md`.
//!
//! # `mode: cors`, deliberately
//!
//! `no-cors` would make responses opaque — no status, no body — which is useless
//! here. `cors` means the server must send the right `Access-Control-*` headers;
//! that is a deployment requirement, and failing loudly beats reading nothing.

use wasm_bindgen::JsCast as _;
use wasm_bindgen_futures::JsFuture;

use crate::error::{Result, SyncError, TransportKind};
use crate::limits;
use crate::transport::{SyncRequest, SyncResponse, Transport};

/// A transport backed by the browser's `fetch`.
#[derive(Clone, Debug)]
pub struct FetchTransport {
    origin: String,
}

impl FetchTransport {
    /// A transport to `origin`, for example `https://sync.example`.
    ///
    /// # Errors
    ///
    /// [`SyncError::BadServerUrl`] if `origin` is not an `https` origin. Checked
    /// with a string comparison rather than a URL parser, because pulling a URL
    /// parser into the wasm bundle to answer one question is not worth the bytes,
    /// and the browser will reject anything malformed at `fetch` time anyway.
    pub fn new(origin: &str) -> Result<Self> {
        let trimmed = origin.trim().trim_end_matches('/');
        if !trimmed.starts_with("https://") || trimmed.len() <= "https://".len() {
            return Err(SyncError::BadServerUrl);
        }
        Ok(Self {
            origin: trimmed.to_owned(),
        })
    }

    /// The origin this transport talks to.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// `window` in a page, `self` in a worker. The extension's service worker is the
/// latter, so both have to work.
fn global_fetch(request: &web_sys::Request) -> Result<js_sys::Promise> {
    let global = js_sys::global();
    if let Some(window) = global.dyn_ref::<web_sys::Window>() {
        return Ok(window.fetch_with_request(request));
    }
    if let Some(scope) = global.dyn_ref::<web_sys::WorkerGlobalScope>() {
        return Ok(scope.fetch_with_request(request));
    }
    Err(SyncError::Transport {
        operation: "fetch",
        kind: TransportKind::Environment,
    })
}

fn environment(operation: &'static str) -> SyncError {
    SyncError::Transport {
        operation,
        kind: TransportKind::Environment,
    }
}

impl Transport for FetchTransport {
    async fn request(&self, request: SyncRequest) -> Result<SyncResponse> {
        const OP: &str = "fetch";
        let init = web_sys::RequestInit::new();
        init.set_method(request.method.as_str());
        init.set_mode(web_sys::RequestMode::Cors);
        if let Some(body) = &request.body {
            init.set_body(&js_sys::Uint8Array::from(body.as_slice()).into());
        }

        let headers = web_sys::Headers::new().map_err(|_| environment(OP))?;
        for (name, value) in &request.headers {
            headers.set(name, value).map_err(|_| environment(OP))?;
        }
        init.set_headers(&headers);

        let url = format!("{}{}", self.origin, request.path);
        let js_request =
            web_sys::Request::new_with_str_and_init(&url, &init).map_err(|_| environment(OP))?;
        let response = JsFuture::from(global_fetch(&js_request)?)
            .await
            .map_err(|_| SyncError::Transport {
                operation: OP,
                // `fetch` collapses DNS failure, connection refusal, a TLS
                // rejection and a CORS refusal into one opaque `TypeError`. The
                // browser will not say which, so neither will this.
                kind: TransportKind::Connect,
            })?;
        let response: web_sys::Response = response.dyn_into().map_err(|_| environment(OP))?;

        let status = response.status();
        let buffer = JsFuture::from(response.array_buffer().map_err(|_| environment(OP))?)
            .await
            .map_err(|_| SyncError::Transport {
                operation: OP,
                kind: TransportKind::Protocol,
            })?;
        let bytes = js_sys::Uint8Array::new(&buffer);
        // `fetch` has no streaming read here, so the cap is checked on the length
        // before the copy: the browser has already buffered it, but this crate has
        // not, and the allocation this refuses is the one it would make.
        if bytes.length() as usize > limits::MAX_RESPONSE_BODY_LEN {
            return Err(SyncError::ResponseTooLarge {
                operation: OP,
                max: limits::MAX_RESPONSE_BODY_LEN,
            });
        }
        Ok(SyncResponse {
            status,
            headers: Vec::new(),
            body: bytes.to_vec(),
        })
    }
}

/// A sleeper backed by `setTimeout`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BrowserSleeper;

impl crate::backoff::Sleeper for BrowserSleeper {
    async fn sleep_ms(&self, ms: u64) {
        let millis = i32::try_from(ms).unwrap_or(i32::MAX);
        let promise = js_sys::Promise::new(&mut |resolve, _reject| {
            let global = js_sys::global();
            if let Some(window) = global.dyn_ref::<web_sys::Window>() {
                let _ =
                    window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis);
            } else if let Some(scope) = global.dyn_ref::<web_sys::WorkerGlobalScope>() {
                let _ =
                    scope.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis);
            } else {
                // No timer available. Resolve immediately rather than hang: a
                // retry that happens too soon is recoverable, a sync that never
                // resumes is not.
                let _ = resolve.call0(&wasm_bindgen::JsValue::UNDEFINED);
            }
        });
        let _ = JsFuture::from(promise).await;
    }
}
