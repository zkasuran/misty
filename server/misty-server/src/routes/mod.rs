// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The HTTP surface: SPEC §6.1, one module per group of endpoints.
//!
//! # Endpoint map
//!
//! | Method | Path | Auth | SPEC |
//! |---|---|---|---|
//! | `POST` | `/v1/auth/challenge` | none | §6.1 |
//! | `POST` | `/v1/auth/verify` | challenge signature | §6.1 |
//! | `POST` | `/v1/auth/refresh` | refresh token | added, see below |
//! | `POST` | `/v1/vaults/{vid}/devices` | access token | added, see below |
//! | `GET` | `/v1/vaults/{vid}/changes` | access token | §6.1 |
//! | `PUT` | `/v1/vaults/{vid}/items/{item_id}` | access token | §6.1 |
//! | `DELETE` | `/v1/vaults/{vid}/items/{item_id}` | access token | §6.1 |
//! | `GET` | `/v1/time` | none | §6.1, §6.5 |
//! | `POST` | `/v1/enroll/begin` | none | §6.3 |
//! | `GET` | `/v1/enroll/poll/{enroll_id}` | none | §6.3 |
//! | `POST` | `/v1/enroll/complete` | none | §6.3 |
//! | `GET` | `/v1/quota` | access token | §6.1 |
//! | `GET` | `/healthz` | none | operational |
//!
//! Two endpoints are additions, both because SPEC §6.1 is incomplete rather than
//! because something more was wanted:
//!
//! * `POST /v1/auth/refresh` — §6.1 issues a `refresh_token` from
//!   `/v1/auth/verify` and then never says how to redeem one.
//! * `POST /v1/vaults/{vid}/devices` — §6.3 step 4 ends with "and registers with
//!   the server", but §6.1 lists no endpoint that does it. Without one, the
//!   server would have to accept any device that turns up with a key, which would
//!   hand write access to anyone who learned a `vault_id`.
//!
//! # Wire encoding (SPEC §6.1.1)
//!
//! Normative, and settled after this server and `misty-sync` shipped two
//! defensible, non-interoperating readings of the same document:
//!
//! * ids, nonces, signatures, public keys — **lowercase hex**
//! * envelopes and sealed blobs — **standard base64, padded**
//! * `version` — an opaque printable-ASCII token, never a JSON number
//! * `seq`, `unix_ms`, counts — JSON numbers
//!
//! Hex rather than base64 for the short fields because a hex string is *also*
//! well-formed base64, so a variable-width field cannot be encoding-agnostic; and
//! because standard base64's `+` arrives as a space under query-string form
//! decoding, which is what previously pushed `/v1/time` into a third alphabet.
//! With hex there is no query-string variant to have.
//!
//! # What never reaches a log
//!
//! The request-logging middleware records the **sanitised** path
//! ([`sanitise_path`]), never the raw one, because the raw path of a `PUT`
//! contains an `item_id`. No handler logs an envelope, a length, or an address.
//! `tests/logging.rs` asserts it against a live request.

pub mod auth;
pub mod enroll;
pub mod items;
pub mod meta;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, FromRequestParts, Request};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::Router;
use serde::de::DeserializeOwned;

use crate::error::{ApiError, ApiResult};
use crate::ids::VaultId;
use crate::rate_limit::RateLimiter;
use crate::store::{Precondition, Session, Store};
use crate::time_key::TimeKey;
use crate::Config;

/// Everything a handler needs, cheap to clone.
#[derive(Clone)]
pub struct AppState {
    /// Storage, behind the trait so Postgres can be added later.
    pub store: Arc<dyn Store>,
    /// Immutable configuration.
    pub config: Arc<Config>,
    /// The `/v1/time` signing key.
    pub time_key: Arc<TimeKey>,
    /// Rate-limit buckets. The only place an IP address exists.
    pub limiter: Arc<RateLimiter>,
}

impl AppState {
    /// Assembles state from its parts.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, config: Config, time_key: TimeKey) -> Self {
        let limiter = Arc::new(RateLimiter::new(&config));
        Self {
            store,
            config: Arc::new(config),
            time_key: Arc::new(time_key),
            limiter,
        }
    }
}

/// Builds the router.
///
/// The body limit is applied as a layer rather than checked in each handler so
/// that an oversized body is refused from its `Content-Length` before a byte is
/// read. A declared 4 GB body therefore costs one response, not 4 GB.
pub fn router(state: AppState) -> Router {
    let body_limit = state.config.max_body_bytes;
    Router::new()
        .route("/healthz", get(meta::healthz))
        .route("/v1/time", get(meta::time))
        .route("/v1/quota", get(meta::quota))
        .route("/v1/auth/challenge", post(auth::challenge))
        .route("/v1/auth/verify", post(auth::verify))
        .route("/v1/auth/refresh", post(auth::refresh))
        .route("/v1/vaults/{vid}/devices", post(auth::add_device))
        .route("/v1/vaults/{vid}/changes", get(items::changes))
        .route(
            "/v1/vaults/{vid}/items/{item_id}",
            put(items::put).delete(items::delete),
        )
        .route("/v1/enroll/begin", post(enroll::begin))
        .route("/v1/enroll/poll/{enroll_id}", get(enroll::poll))
        .route("/v1/enroll/complete", post(enroll::complete))
        .fallback(unmatched)
        .method_not_allowed_fallback(wrong_method)
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(axum::middleware::from_fn_with_state(state.clone(), observe))
        .with_state(state)
}

async fn unmatched() -> ApiError {
    ApiError::NotFound
}

async fn wrong_method() -> ApiError {
    ApiError::MethodNotAllowed
}

/// Serves `state` on `listener` until `shutdown` resolves, then finishes
/// in-flight requests.
///
/// Connect info is always attached, because the per-IP rate limiter needs the
/// peer address and silently losing it would silently lose the limit.
///
/// # Errors
///
/// Whatever the accept loop returns.
pub async fn serve<F>(
    listener: tokio::net::TcpListener,
    state: AppState,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// Runs a blocking storage call off the runtime.
///
/// `rusqlite` is blocking and the store serialises on one mutex; holding either
/// on a runtime thread would stall every other connection. This is the single
/// place that boundary is crossed.
///
/// # Errors
///
/// [`ApiError::Internal`] if the storage task panics, otherwise whatever the
/// store returned.
pub async fn blocking<T, F>(f: F) -> ApiResult<T>
where
    F: FnOnce() -> crate::store::Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| ApiError::Internal("storage task failed".into()))?
        .map_err(ApiError::from)
}

/// Rate-limits by address, refuses an oversized declared body, and logs the
/// request.
///
/// The log line carries no address and no raw path.
async fn observe(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let route = sanitise_path(request.uri().path());

    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip());
    if let Some(address) = client_ip(&state, request.headers(), peer) {
        if let Err(error) = state.limiter.check_ip(address) {
            let status = error.status();
            let response = axum::response::IntoResponse::into_response(error);
            tracing::warn!(
                target: "misty_server::http",
                %method, route, status = status.as_u16(),
                "rate limited",
            );
            return response;
        }
    }

    // A declared length over the cap is refused here, from the header, before a
    // byte of body is read. `DefaultBodyLimit` alone would let a client with a
    // 4 GB `Content-Length` hold a connection open while the limit was
    // discovered frame by frame; this makes the answer immediate and the cost one
    // response. `DefaultBodyLimit` remains the backstop for a chunked body that
    // declares no length at all.
    if let Some(declared) = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<u64>().ok())
    {
        if declared > state.config.max_body_bytes as u64 {
            let error = ApiError::PayloadTooLarge {
                max: state.config.max_body_bytes as u64,
            };
            let status = error.status();
            let response = axum::response::IntoResponse::into_response(error);
            tracing::info!(
                target: "misty_server::http",
                %method, route, status = status.as_u16(),
                "declared body over the cap",
            );
            return response;
        }
    }

    let started = std::time::Instant::now();
    let response = next.run(request).await;
    tracing::info!(
        target: "misty_server::http",
        %method,
        route,
        status = response.status().as_u16(),
        duration_ms = started.elapsed().as_millis(),
        "request",
    );
    response
}

/// Replaces every 32-hex path segment with `{id}`.
///
/// This is what makes the access log safe: an `item_id` is exactly a 32-hex
/// segment, so it cannot survive. Applying it to *all* such segments rather than
/// only the ones we expect means a future route cannot leak one by being added
/// without a matching change here.
#[must_use]
pub fn sanitise_path(path: &str) -> String {
    // Every byte pushed below is ASCII — a segment is either replaced by an ASCII
    // placeholder or verified `is_ascii_graphic` — so the `truncate` at the end
    // cannot land inside a character. See `clip` for the case where that is not
    // true by construction.
    let mut out = String::with_capacity(path.len().min(256));
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            out.push('/');
        }
        let hex_id = segment.len() == 32 && segment.bytes().all(|b| b.is_ascii_hexdigit());
        if hex_id {
            out.push_str("{id}");
        } else if segment.len() > 32 || !segment.bytes().all(|b| b.is_ascii_graphic()) {
            // An unmatched route with a hostile path must not be able to write
            // arbitrary bytes into a log line either.
            out.push_str("{other}");
        } else {
            out.push_str(segment);
        }
        if out.len() > 256 {
            out.truncate(256);
            break;
        }
    }
    out
}

fn client_ip(state: &AppState, headers: &HeaderMap, peer: Option<IpAddr>) -> Option<IpAddr> {
    if state.config.trust_forwarded_for {
        // With exactly one trusted reverse proxy, the trustworthy element is the
        // *last* one — the address that proxy observed. Earlier elements are
        // whatever the client chose to claim.
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(last) = value.rsplit(',').next().map(str::trim) {
                if let Ok(address) = last.parse::<IpAddr>() {
                    return Some(address);
                }
                if let Ok(address) = last.parse::<SocketAddr>() {
                    return Some(address.ip());
                }
            }
        }
    }
    peer
}

/// A [`Duration`](std::time::Duration) as milliseconds, saturating.
///
/// Every expiry on this surface is `now.saturating_add(ttl_ms(…))`. An absurd
/// configured TTL — `MISTY_REFRESH_TOKEN_TTL_SECS=999999999999999999` — would
/// otherwise overflow `i64` on the add, which panics in a debug build and, with
/// the workspace's `panic = "abort"` release profile, would be fatal. Saturating
/// turns a misconfiguration into "expires at the end of time" rather than a crash
/// on the first request.
#[must_use]
pub fn ttl_ms(ttl: std::time::Duration) -> i64 {
    i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX)
}

/// Shortens `text` to at most `max` bytes without splitting a character.
///
/// `String::truncate` panics when the byte offset lands inside a multi-byte
/// character, and the strings clipped here are framework rejection messages that
/// quote attacker-chosen JSON field names and path segments. With the workspace's
/// `panic = "abort"` release profile that panic is a process-level denial of
/// service reachable by anyone who can post a body, not a `500`.
/// `tests/hostile_input.rs` sends a 900-byte field name of 3-byte characters.
fn clip(mut text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push('…');
    text
}

/// A request body that maps every rejection onto [`ApiError`].
///
/// axum's own rejections are perfectly good, but they return plain text, and a
/// client that has to parse prose to tell "malformed JSON" from "body too large"
/// will get it wrong. Everything on this surface answers with the same JSON
/// shape.
pub struct JsonBody<T>(pub T);

impl<T> FromRequest<AppState> for JsonBody<T>
where
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(request, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(match rejection.status() {
                StatusCode::PAYLOAD_TOO_LARGE => ApiError::PayloadTooLarge {
                    // The body limit is what was exceeded here, not the envelope
                    // cap; `decode_blob` is what reports that one.
                    max: state.config.max_body_bytes as u64,
                },
                StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::UnsupportedMediaType,
                // Clipped because the message can quote an attacker-chosen field
                // name, and an unbounded echo is an amplifier.
                _ => ApiError::BadRequest(clip(rejection.body_text(), 200)),
            }),
        }
    }
}

/// A path capture that maps every rejection onto [`ApiError`].
///
/// Needed for the same reason as [`JsonBody`]: axum's own `Path` rejection is
/// plain text, and a hostile path — one whose percent-escapes do not decode to
/// UTF-8, say — would be the one response on this surface a client could not
/// parse. Every capture on these routes is a 32-hex identifier, so the only
/// rejection reachable in practice is a decoding failure.
pub struct PathParams<T>(pub T);

impl<T> FromRequestParts<AppState> for PathParams<T>
where
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(value)) => Ok(Self(value)),
            Err(rejection) => Err(ApiError::BadRequest(clip(rejection.body_text(), 200))),
        }
    }
}

/// An authenticated session, extracted from `Authorization: Bearer …`.
///
/// Extraction also charges the request to the vault's rate-limit bucket, so
/// every authenticated endpoint is covered by exactly one call site.
pub struct Authenticated(pub Session);

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or(ApiError::Unauthorized)?
            .trim();
        let hash = crate::token::TokenHash::parse_presented(token)?;

        let store = Arc::clone(&state.store);
        let now = crate::time_key::now_unix_ms();
        let session = blocking(move || store.access_token(*hash.as_bytes(), now))
            .await?
            .ok_or(ApiError::Unauthorized)?;
        state.limiter.check_vault(session.vault_id)?;
        Ok(Self(session))
    }
}

impl Authenticated {
    /// Checks that the token's vault matches the one in the path.
    ///
    /// SPEC §6.1 does not say this explicitly, which it should: without the
    /// check, a token for vault A reads and writes vault B, and every other
    /// protection in the document becomes irrelevant.
    ///
    /// # Errors
    ///
    /// [`ApiError::Forbidden`] on a mismatch.
    pub fn for_vault(&self, vault_id: VaultId) -> ApiResult<Session> {
        if self.0.vault_id != vault_id {
            return Err(ApiError::Forbidden);
        }
        Ok(self.0)
    }
}

/// Reads the write precondition from `If-Match` / `If-None-Match`.
///
/// # Errors
///
/// * [`ApiError::PreconditionRequired`] if neither header is present. A write
///   with no precondition is a blind overwrite, and offering one would make the
///   optimistic-concurrency contract optional.
/// * [`ApiError::BadRequest`] for both headers at once, a weak validator, or
///   `If-Match: *`.
pub fn precondition(headers: &HeaderMap) -> ApiResult<Precondition> {
    let if_match = headers.get(header::IF_MATCH);
    let if_none_match = headers.get(header::IF_NONE_MATCH);

    if if_match.is_some() && if_none_match.is_some() {
        return Err(ApiError::BadRequest(
            "send either If-Match or If-None-Match, not both".into(),
        ));
    }

    if let Some(value) = if_none_match {
        let text = value
            .to_str()
            .map_err(|_| ApiError::BadRequest("If-None-Match is not ASCII".into()))?
            .trim();
        if text != "*" {
            return Err(ApiError::BadRequest(
                "If-None-Match must be exactly * on this surface".into(),
            ));
        }
        return Ok(Precondition(0));
    }

    let Some(value) = if_match else {
        return Err(ApiError::PreconditionRequired);
    };
    let text = value
        .to_str()
        .map_err(|_| ApiError::BadRequest("If-Match is not ASCII".into()))?
        .trim();
    if text == "*" {
        return Err(ApiError::BadRequest(
            "If-Match: * would be a blind overwrite; send the version you last saw, \
             or If-None-Match: * to create"
                .into(),
        ));
    }
    if text.starts_with("W/") {
        return Err(ApiError::BadRequest(
            "a weak validator cannot gate a write; send a strong If-Match".into(),
        ));
    }
    let digits = text
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(text);
    // SPEC §6.1.1 makes `version` an opaque printable-ASCII token, so this parses
    // the token *this server* issues rather than asserting a shape on all
    // possible tokens. A client echoes back what it was given; it never has to
    // know that the token happens to be a decimal integer, and the error message
    // deliberately does not tell it.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::BadRequest(
            "If-Match must be a version token this server issued, optionally quoted".into(),
        ));
    }
    let version: u64 = digits.parse().map_err(|_| {
        ApiError::BadRequest("If-Match is not a version token this server issued".into())
    })?;
    Ok(Precondition(version))
}

/// Renders an internal version counter as SPEC §6.1.1's opaque token.
///
/// The counter is a `u64` and always will be, but nothing outside this crate is
/// told that. §6.1.1 makes `version` "an opaque printable-ASCII token; clients
/// MUST NOT parse it", and it travels in an `ETag` header regardless — so a JSON
/// number invites a client to compute `version + 1`, which is a client that breaks
/// the day the representation changes. Version `0` still means "no such item",
/// which is a property of the *protocol*, not of the encoding.
#[must_use]
pub fn version_token(version: u64) -> String {
    version.to_string()
}

/// Extracts one query parameter, percent-decoded.
///
/// A hand-rolled reader rather than a `serde` form deserialiser: the three
/// parameters on this surface have tight alphabets, and every rejection needs to
/// name the parameter it is about.
#[must_use]
pub fn query_value(query: Option<&str>, name: &str) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(key) == name {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes.get(index) {
            Some(b'%') => {
                let high = bytes.get(index + 1).copied().and_then(from_hex);
                let low = bytes.get(index + 2).copied().and_then(from_hex);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        out.push(high << 4 | low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            Some(b'+') => {
                out.push(b' ');
                index += 1;
            }
            Some(byte) => {
                out.push(*byte);
                index += 1;
            }
            None => break,
        }
    }
    // Lossy on purpose: a non-UTF-8 query value is hostile input, and the
    // caller's alphabet check will reject the replacement characters.
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes a base64 envelope or sealed blob under a length cap.
///
/// The cap is checked against the *decoded* length, and the encoded length is
/// pre-checked so an oversized value is refused before it is decoded.
///
/// # Errors
///
/// [`ApiError::BadRequest`] for anything that is not canonical base64,
/// [`ApiError::PayloadTooLarge`] past the cap.
pub fn decode_blob(field: &str, text: &str, max: u64) -> ApiResult<Vec<u8>> {
    // 4 encoded characters per 3 bytes; refuse before allocating.
    let ceiling = max.saturating_mul(4) / 3 + 4;
    if text.len() as u64 > ceiling {
        return Err(ApiError::PayloadTooLarge { max });
    }
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.as_bytes())
        .map_err(|_| {
            ApiError::BadRequest(format!(
                "{field} must be canonical base64 (standard alphabet, padded)"
            ))
        })?;
    if bytes.len() as u64 > max {
        return Err(ApiError::PayloadTooLarge { max });
    }
    if bytes.is_empty() {
        return Err(ApiError::BadRequest(format!("{field} must not be empty")));
    }
    Ok(bytes)
}

/// Decodes a lowercase-hex field that must be exactly `N` bytes.
///
/// SPEC §6.1.1 puts every nonce, signature, and public key in lowercase hex, and
/// this is the only decoder for them. It does **not** fall back to base64.
/// §6.1.1 notes that a fixed-width field would survive accepting both — at 16, 32,
/// and 64 bytes, hex and the two base64 alphabets are three different string
/// lengths — and then says that is "a reason the mistake is survivable, not a
/// reason to make it". One canonical spelling per field.
///
/// # Errors
///
/// [`ApiError::BadRequest`] for anything that is not exactly `2 * N` lowercase hex
/// characters.
pub fn decode_hex_fixed<const N: usize>(field: &str, text: &str) -> ApiResult<[u8; N]> {
    let bad = || {
        ApiError::BadRequest(format!(
            "{field} must be {} lowercase hex characters for {N} bytes",
            N * 2
        ))
    };
    if text.len() != N * 2 || !is_lower_hex(text) {
        return Err(bad());
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out).map_err(|_| bad())?;
    Ok(out)
}

/// Decodes a variable-width lowercase-hex field under a byte cap.
///
/// Used for the one variable-width hex field on this surface, `/v1/auth/verify`'s
/// echoed `nonce`. The cap is checked against the encoded length first, so an
/// absurd value costs a comparison rather than an allocation.
///
/// # Errors
///
/// [`ApiError::BadRequest`] for a wrong alphabet, an odd length, an empty value,
/// or more than `max` decoded bytes.
pub fn decode_hex(field: &str, text: &str, max: usize) -> ApiResult<Vec<u8>> {
    let bad = || ApiError::BadRequest(format!("{field} must be lowercase hex for 1..={max} bytes"));
    if text.is_empty() || text.len() > max * 2 || text.len() % 2 != 0 || !is_lower_hex(text) {
        return Err(bad());
    }
    hex::decode(text).map_err(|_| bad())
}

/// Encodes bytes as lowercase hex, SPEC §6.1.1's form for short fields.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn is_lower_hex(text: &str) -> bool {
    // Uppercase is rejected rather than folded, for the same reason
    // `ids::parse` rejects it: two spellings of one value mean two cache keys and
    // two plausible readings of a log line. §6.1.1 says lowercase.
    text.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Encodes a blob for a response body.
#[must_use]
pub fn encode_blob(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn clipping_never_splits_a_character() {
        for filler in ["日", "é", "🔐", "a"] {
            let text = filler.repeat(300);
            let clipped = clip(text.clone(), 200);
            assert!(clipped.len() <= 200 + '…'.len_utf8());
            assert!(clipped.ends_with('…'));
            // The assertion that matters is that this did not panic, and that the
            // result is still valid UTF-8 — which it is by type.
            assert!(text.starts_with(clipped.trim_end_matches('…')));
        }
        assert_eq!(clip("short".into(), 200), "short");
        assert_eq!(clip(String::new(), 0), "");
        // A single character wider than the budget clips to nothing but the
        // ellipsis, rather than panicking.
        assert_eq!(clip("🔐".into(), 2), "…");
    }

    #[test]
    fn hex_fields_accept_one_spelling_only() {
        let bytes = [0xabu8; 32];
        let text = encode_hex(&bytes);
        assert_eq!(text.len(), 64);
        assert_eq!(decode_hex_fixed::<32>("k", &text).unwrap(), bytes);

        // Uppercase is not folded, and neither base64 alphabet is accepted — the
        // divergence §6.1.1 was written to end.
        assert!(decode_hex_fixed::<32>("k", &text.to_ascii_uppercase()).is_err());
        assert!(decode_hex_fixed::<32>("k", &encode_blob(&bytes)).is_err());
        assert!(decode_hex_fixed::<32>("k", "").is_err());
        assert!(decode_hex_fixed::<64>("k", &text).is_err());
        assert!(decode_hex_fixed::<32>("k", &"z".repeat(64)).is_err());
        assert!(decode_hex_fixed::<32>("k", &"a".repeat(4096)).is_err());
    }

    #[test]
    fn variable_width_hex_is_bounded_and_even() {
        assert_eq!(decode_hex("nonce", "00ff", 32).unwrap(), vec![0x00, 0xff]);
        assert!(decode_hex("nonce", "0", 32).is_err(), "odd length");
        assert!(decode_hex("nonce", "", 32).is_err());
        assert!(
            decode_hex("nonce", &"ab".repeat(33), 32).is_err(),
            "over cap"
        );
        assert!(decode_hex("nonce", "00FF", 32).is_err(), "uppercase");
        // Refused by a length comparison, not by decoding a megabyte.
        assert!(decode_hex("nonce", &"a".repeat(1024 * 1024), 32).is_err());
    }

    #[test]
    fn a_version_is_rendered_as_a_token_not_a_number() {
        assert_eq!(version_token(0), "0");
        assert_eq!(version_token(7), "7");
        assert_eq!(version_token(u64::MAX), "18446744073709551615");
        // Round-trips through the header form the client echoes back.
        for version in [0u64, 1, 42, u64::MAX] {
            let token = version_token(version);
            let headers = headers(&[("if-match", &format!("\"{token}\""))]);
            assert_eq!(precondition(&headers).unwrap(), Precondition(version));
        }
    }

    #[test]
    fn an_item_id_cannot_survive_the_path_sanitiser() {
        let id = "0123456789abcdef0123456789abcdef";
        let sanitised = sanitise_path(&format!("/v1/vaults/{id}/items/{id}"));
        assert_eq!(sanitised, "/v1/vaults/{id}/items/{id}");
        assert!(!sanitised.contains(id));
    }

    #[test]
    fn the_sanitiser_bounds_and_scrubs_a_hostile_path() {
        let long = "a".repeat(4096);
        let sanitised = sanitise_path(&format!("/{long}"));
        assert!(sanitised.len() <= 256);
        assert_eq!(sanitise_path("/\u{7}\u{1b}[2J"), "/{other}");
    }

    #[test]
    fn preconditions_map_onto_one_integer() {
        assert_eq!(
            precondition(&headers(&[("if-match", "\"7\"")])).unwrap(),
            Precondition(7)
        );
        assert_eq!(
            precondition(&headers(&[("if-match", "7")])).unwrap(),
            Precondition(7)
        );
        assert_eq!(
            precondition(&headers(&[("if-none-match", "*")])).unwrap(),
            Precondition(0)
        );
        assert_eq!(
            precondition(&headers(&[("if-match", "0")])).unwrap(),
            Precondition(0)
        );
    }

    #[test]
    fn a_write_without_a_precondition_is_refused() {
        assert!(matches!(
            precondition(&HeaderMap::new()),
            Err(ApiError::PreconditionRequired)
        ));
    }

    #[test]
    fn a_blind_overwrite_is_refused_with_a_reason() {
        let error = precondition(&headers(&[("if-match", "*")])).expect_err("refuse");
        assert!(error.to_string().contains("blind overwrite"));
    }

    #[test]
    fn hostile_preconditions_are_rejected() {
        for value in [
            "W/\"7\"",
            "\"\"",
            "seven",
            "-1",
            "1.0",
            "18446744073709551616",
        ] {
            assert!(
                precondition(&headers(&[("if-match", value)])).is_err(),
                "accepted {value:?}"
            );
        }
        assert!(precondition(&headers(&[("if-none-match", "\"7\"")])).is_err());
        assert!(precondition(&headers(&[("if-match", "1"), ("if-none-match", "*")])).is_err());
    }

    #[test]
    fn query_values_are_percent_decoded() {
        assert_eq!(
            query_value(Some("since=7&limit=9"), "since").as_deref(),
            Some("7")
        );
        assert_eq!(
            query_value(Some("since=7&limit=9"), "limit").as_deref(),
            Some("9")
        );
        assert_eq!(query_value(Some("a=%2B%2f"), "a").as_deref(), Some("+/"));
        assert_eq!(query_value(Some("flag"), "flag").as_deref(), Some(""));
        assert_eq!(query_value(Some("a=1"), "b"), None);
        assert_eq!(query_value(None, "a"), None);
        // A truncated escape is passed through rather than treated as an error;
        // the caller's alphabet check is what rejects it.
        assert_eq!(query_value(Some("a=%2"), "a").as_deref(), Some("%2"));
    }

    #[test]
    fn blobs_round_trip_and_reject_the_hostile_cases() {
        let bytes = vec![1u8, 2, 3];
        let text = encode_blob(&bytes);
        assert_eq!(decode_blob("envelope", &text, 16).unwrap(), bytes);

        assert!(matches!(
            decode_blob("envelope", "!!!!", 16),
            Err(ApiError::BadRequest(_))
        ));
        // Unpadded is not canonical for this field.
        assert!(decode_blob("envelope", "AQID", 16).is_ok());
        assert!(decode_blob("envelope", "AQI", 16).is_err());
        assert!(matches!(
            decode_blob("envelope", &encode_blob(&[0u8; 64]), 16),
            Err(ApiError::PayloadTooLarge { max: 16 })
        ));
        assert!(matches!(
            decode_blob("envelope", "", 16),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn an_oversized_encoded_blob_is_refused_before_decoding() {
        let huge = "A".repeat(10 * 1024 * 1024);
        assert!(matches!(
            decode_blob("envelope", &huge, 1024),
            Err(ApiError::PayloadTooLarge { max: 1024 })
        ));
    }
}
