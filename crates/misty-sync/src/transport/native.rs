// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The native transport: `hyper` over `rustls`, TLS 1.3 only, pinned.
//!
//! Three properties are structural here rather than configured, which is the
//! point:
//!
//! * **TLS 1.2 does not exist.** `rustls` and `hyper-rustls` are both built
//!   without their `tls12` features, so SPEC §9's "TLS 1.3 only" is not a setting
//!   that could be changed by accident — the code is not compiled in.
//! * **There is no root certificate store.** No `webpki-roots`, no platform
//!   verifier. The only trust anchor is the [`PinSet`], so a mis-issuing CA has
//!   nothing to mis-issue into. A deployment that wants chain validation as well
//!   supplies its own roots (see [`super::pin`]).
//! * **`native-tls` and `openssl` are unreachable.** `cargo deny` bans all three
//!   of `native-tls`, `openssl` and `libsodium-sys` for the whole workspace, and
//!   the `ring` provider is pure enough to satisfy it.
//!
//! Response bodies are read frame by frame against
//! [`MAX_RESPONSE_BODY_LEN`](crate::limits::MAX_RESPONSE_BODY_LEN), so a server
//! that promises a small body and then streams gigabytes is cut off rather than
//! allocated for. Every request is wrapped in a timeout, because `hyper-util`'s
//! pooling client has none of its own and a sync that hangs forever is worse than
//! one that fails.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::error::{Result, SyncError, TransportKind};
use crate::limits;
use crate::transport::pin::{PinSet, PinnedVerifier};
use crate::transport::{SyncRequest, SyncResponse, Transport};

/// How long one request may take before it is abandoned.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

/// A pinned HTTPS transport.
#[derive(Debug, Clone)]
pub struct NativeTransport {
    client: HttpsClient,
    origin: String,
    verifier: Arc<PinnedVerifier>,
    timeout: Duration,
}

impl NativeTransport {
    /// A transport to `origin`, accepting only certificates in `pins`.
    ///
    /// `origin` is a scheme, host and optional port — `https://sync.example` — and
    /// must be `https`. A plaintext origin is refused rather than downgraded,
    /// because a client that silently spoke HTTP would defeat `A2` while looking
    /// like it worked.
    ///
    /// # Errors
    ///
    /// [`SyncError::BadServerUrl`] if `origin` is not an `https` origin or the pin
    /// set is empty. An empty pin set is a configuration error, not a permissive
    /// default: it would accept nothing, and failing here says so.
    pub fn pinned(origin: &str, pins: PinSet) -> Result<Self> {
        if pins.is_empty() {
            return Err(SyncError::BadPin {
                expected: crate::transport::PIN_LEN,
                found: 0,
            });
        }
        Self::with_verifier(origin, PinnedVerifier::new(pins))
    }

    /// A transport with a verifier the caller configured — pins plus roots, say.
    ///
    /// # Errors
    ///
    /// [`SyncError::BadServerUrl`] if `origin` is not an `https` origin.
    pub fn with_verifier(origin: &str, verifier: PinnedVerifier) -> Result<Self> {
        let origin = normalise_origin(origin)?;
        let verifier = Arc::new(verifier);
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        // Only TLS 1.3 is offered, and only TLS 1.3 is compiled in.
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| SyncError::BadServerUrl)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&verifier) as Arc<_>)
        .with_no_client_auth();

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config)
            // No plaintext fallback exists on this connector at all.
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(https),
            origin,
            verifier,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Replaces the per-request timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The origin this transport talks to.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Classifies a connect failure, refining it to a pin mismatch when the
    /// verifier says that is what happened.
    fn connect_error(&self, operation: &'static str) -> SyncError {
        let kind = if self.verifier.take_pin_mismatch() {
            TransportKind::PinMismatch
        } else {
            TransportKind::Connect
        };
        SyncError::Transport { operation, kind }
    }

    async fn perform(&self, request: SyncRequest) -> Result<SyncResponse> {
        const OP: &str = "http request";
        let uri = format!("{}{}", self.origin, request.path);
        let mut builder = hyper::Request::builder()
            .method(request.method.as_str())
            .uri(uri);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        // A header this client could not build is a header it must not send. The
        // shapes are already validated where they arrive (`ServerVersion::parse`,
        // `decode_tokens`), so reaching here means a bug rather than a hostile
        // server — and it still fails closed.
        let http_request = builder
            .body(Full::new(Bytes::from(request.body.unwrap_or_default())))
            .map_err(|_| SyncError::Transport {
                operation: OP,
                kind: TransportKind::Protocol,
            })?;

        let response = self.client.request(http_request).await.map_err(|error| {
            if error.is_connect() {
                self.connect_error(OP)
            } else {
                SyncError::Transport {
                    operation: OP,
                    kind: TransportKind::Protocol,
                }
            }
        })?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();

        // `content-length` is the server's claim, so it is used only to reject
        // early. The real bound is applied while reading.
        if response
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|len| len > limits::MAX_RESPONSE_BODY_LEN)
        {
            return Err(SyncError::ResponseTooLarge {
                operation: OP,
                max: limits::MAX_RESPONSE_BODY_LEN,
            });
        }

        let mut body = response.into_body();
        let mut collected: Vec<u8> = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| SyncError::Transport {
                operation: OP,
                kind: TransportKind::Protocol,
            })?;
            if let Some(data) = frame.data_ref() {
                if collected.len().saturating_add(data.len()) > limits::MAX_RESPONSE_BODY_LEN {
                    return Err(SyncError::ResponseTooLarge {
                        operation: OP,
                        max: limits::MAX_RESPONSE_BODY_LEN,
                    });
                }
                collected.extend_from_slice(data);
            }
        }
        Ok(SyncResponse {
            status,
            headers,
            body: collected,
        })
    }
}

impl Transport for NativeTransport {
    async fn request(&self, request: SyncRequest) -> Result<SyncResponse> {
        match tokio::time::timeout(self.timeout, self.perform(request)).await {
            Ok(result) => result,
            Err(_) => Err(SyncError::Transport {
                operation: "http request",
                kind: TransportKind::Timeout,
            }),
        }
    }
}

/// Checks that an origin is `https` and strips any trailing slash.
fn normalise_origin(origin: &str) -> Result<String> {
    let trimmed = origin.trim().trim_end_matches('/');
    let uri: hyper::Uri = trimmed.parse().map_err(|_| SyncError::BadServerUrl)?;
    if uri.scheme_str() != Some("https") {
        return Err(SyncError::BadServerUrl);
    }
    if uri.host().is_none_or(str::is_empty) {
        return Err(SyncError::BadServerUrl);
    }
    if uri.path() != "/" && !uri.path().is_empty() {
        // A path prefix would silently change every endpoint's address, so it is
        // refused rather than joined. SPEC §6.1's paths are absolute.
        return Err(SyncError::BadServerUrl);
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::pin::CertificatePin;

    #[test]
    fn only_an_https_origin_is_accepted() {
        assert_eq!(
            normalise_origin("https://sync.example/").expect("origin"),
            "https://sync.example"
        );
        assert_eq!(
            normalise_origin("  https://sync.example:8443  ").expect("origin"),
            "https://sync.example:8443"
        );
        for bad in [
            "http://sync.example",
            "sync.example",
            "",
            "https://",
            // A path prefix would silently relocate every endpoint.
            "https://sync.example/api",
            "ftp://sync.example",
        ] {
            assert!(normalise_origin(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_transport_without_pins_is_refused() {
        let error = NativeTransport::pinned("https://sync.example", PinSet::new())
            .expect_err("an empty pin set is a configuration error");
        assert!(
            matches!(error, SyncError::BadPin { found: 0, .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_pinned_transport_builds() {
        let pins = PinSet::new().with(CertificatePin::from_bytes([9; 32]));
        let transport = NativeTransport::pinned("https://sync.example", pins).expect("transport");
        assert_eq!(transport.origin(), "https://sync.example");
        assert_eq!(
            transport.with_timeout(Duration::from_secs(5)).timeout,
            Duration::from_secs(5)
        );
    }
}
