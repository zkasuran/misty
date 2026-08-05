// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP, behind a trait, because there is no single HTTP client for the targets
//! Misty ships to.
//!
//! `hyper`'s connection stack does not exist in a browser — it needs sockets,
//! DNS and a TLS implementation, none of which `wasm32-unknown-unknown` has —
//! and the browser's `fetch` does not exist natively. SPEC §0 requires one core
//! for every platform, so the split has to be below the protocol rather than
//! above it:
//!
//! ```text
//! SyncEngine ─ SyncClient ─┬─ NativeTransport   hyper + rustls + a pinned verifier
//!                          ├─ FetchTransport    the browser's fetch()
//!                          └─ MockTransport     an in-process server, every target
//! ```
//!
//! **Every line of protocol logic sits above this trait.** Roster verification,
//! `seq` monotonicity, `409` resolution, the queue, the backoff, the `/v1/time`
//! signature check — none of it is duplicated per transport, so the
//! hostile-server suite in `tests/hostile_server.rs` exercises the real code
//! paths on whatever target it is compiled for.
//!
//! # Why the future is not `Send`
//!
//! [`Transport::request`] is an `async fn` in a trait with no `Send` bound. A
//! browser `Promise` is bound to its JavaScript thread and
//! `wasm_bindgen_futures::JsFuture` is `!Send`, so requiring `Send` would make
//! the wasm transport unimplementable. Native callers therefore drive sync on a
//! current-thread runtime, a `tokio::task::LocalSet`, or
//! [`crate::runtime::block_on`], rather than `tokio::spawn`. A sync engine is one
//! sequential conversation with one server; there is nothing here that wants to
//! move between worker threads mid-request.

use crate::error::Result;

#[cfg(target_arch = "wasm32")]
mod fetch;
mod mock;
#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
mod pin;

#[cfg(target_arch = "wasm32")]
pub use fetch::{BrowserSleeper, FetchTransport};
pub use mock::{Faults, MockServer, MockTransport, RequestLog};
#[cfg(not(target_arch = "wasm32"))]
pub use native::NativeTransport;
#[cfg(not(target_arch = "wasm32"))]
pub use pin::{CertificatePin, PinSet, PIN_LEN};

/// The HTTP methods SPEC §6.1 uses. There are no others, and a transport that
/// cannot express one of these cannot speak the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
}

impl Method {
    /// The wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// One request, as the protocol layer describes it.
///
/// `path` is origin-relative and always begins with `/`. The origin lives in the
/// transport, which is what makes certificate pinning a property of the
/// transport rather than something every call site has to remember.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncRequest {
    /// The method.
    pub method: Method,
    /// Origin-relative path, query string included.
    pub path: String,
    /// Headers, in the order they were added.
    pub headers: Vec<(String, String)>,
    /// Request body, if any.
    pub body: Option<Vec<u8>>,
}

impl SyncRequest {
    /// A request with no headers and no body.
    #[must_use]
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// Attaches a JSON body and the matching `Content-Type`.
    #[must_use]
    pub fn json(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self.headers
            .push(("content-type".to_owned(), "application/json".to_owned()));
        self
    }

    /// The first value for `name`, matched case-insensitively.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One response, as the protocol layer reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncResponse {
    /// The HTTP status.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body, already bounded by
    /// [`MAX_RESPONSE_BODY_LEN`](crate::limits::MAX_RESPONSE_BODY_LEN).
    pub body: Vec<u8>,
}

impl SyncResponse {
    /// A response with a status and a body and no headers.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    /// Whether the status is in `200..300`.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// The first value for `name`, matched case-insensitively.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Something that can carry one request to one origin and bring the answer back.
///
/// An implementation is responsible for exactly three things: reaching the
/// origin, enforcing whatever transport security it can (TLS 1.3 and
/// certificate pinning natively — see [`crate::transport::PinSet`] — and
/// nothing at all in a browser, where the platform owns TLS), and refusing to
/// read more than
/// [`MAX_RESPONSE_BODY_LEN`](crate::limits::MAX_RESPONSE_BODY_LEN) bytes. It
/// MUST NOT interpret a status code, retry, follow a redirect, or parse a body:
/// all of that is protocol, and protocol lives above this line.
///
/// A non-2xx status is **not** an error here. Returning `Ok` for a `409` is what
/// lets the conflict path read the body the server attached to it.
///
/// Written as `-> impl Future` rather than `async fn` only so that the returned
/// future carries no implicit `Send` bound and the compiler does not warn about
/// it; an implementation is free to write `async fn request`. See the module docs
/// for why `Send` is deliberately absent.
pub trait Transport {
    /// Performs one request.
    ///
    /// # Errors
    ///
    /// [`SyncError::Transport`](crate::SyncError::Transport) if the exchange did
    /// not complete, or
    /// [`SyncError::ResponseTooLarge`](crate::SyncError::ResponseTooLarge) if the
    /// body exceeded the cap.
    fn request(
        &self,
        request: SyncRequest,
    ) -> impl core::future::Future<Output = Result<SyncResponse>>;
}

impl<T: Transport + ?Sized> Transport for &T {
    fn request(
        &self,
        request: SyncRequest,
    ) -> impl core::future::Future<Output = Result<SyncResponse>> {
        (**self).request(request)
    }
}
