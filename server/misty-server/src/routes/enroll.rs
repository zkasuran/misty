// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The enrollment relay (SPEC §6.3).
//!
//! The server is a dead drop. It holds two opaque blobs against an `enroll_id`
//! for a few minutes and hands each out once. It cannot read either — the sealing
//! key is `HKDF-SHA512(X25519(…), salt = enroll_id, info = "misty/enroll/v1" ‖
//! both public keys)`, and the server holds no private half — and it cannot add a
//! device, because membership is decided by the client-signed roster (SPEC §6.2).
//!
//! # Why these endpoints are unauthenticated, deliberately
//!
//! The new device has no credentials yet, so `begin` and `poll` cannot be
//! authenticated. `complete` *could* be: the approving device is an existing,
//! admitted device. It is left unauthenticated on purpose, because requiring a
//! token would tell the server which `vault_id` an `enroll_id` belongs to —
//! information the sealed payload otherwise hides from it. Authenticating
//! `complete` would trade a metadata leak for no security gain: an attacker who
//! posts a bogus response produces a blob the new device cannot unseal, and
//! `AlreadyAnswered` stops a race from displacing a legitimate one.
//!
//! `enroll_id` is therefore a **bearer capability**: whoever can read the QR code
//! can drive the relay. That is the same population that can read the 6-digit
//! confirmation code, and SPEC §6.3 step 2 requires a human to compare that code
//! out of band before approval.
//!
//! # Single-use, both ways
//!
//! The sealed request is delivered once, to the approving device. The sealed
//! response is delivered once, to the new device, and collecting it destroys the
//! record — so a later reader, including the operator, finds nothing. A dropped
//! connection costs a retry with a fresh QR, which is the right trade for a
//! one-shot user-initiated flow.

use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use super::{blocking, AppState, JsonBody, PathParams};
use crate::error::{ApiError, ApiResult};
use crate::ids::EnrollId;
use crate::store::{EnrollBegin, EnrollComplete, EnrollRequest, EnrollResponse};
use crate::time_key::now_unix_ms;

/// `POST /v1/enroll/begin` request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginRequest {
    /// The enrollment id from the QR code.
    pub enroll_id: EnrollId,
    /// The new device's ephemeral X25519 public key, lowercase hex
    /// (SPEC §6.1.1). Opaque to the server, which never performs an agreement.
    pub x25519_pub: String,
    /// The enrollment request, standard base64.
    ///
    /// **Not** `sealed_request`, and not sealed. SPEC §6.3 retired that name as
    /// incoherent: the sealing key is derived from the *approver's* ephemeral
    /// X25519 key, which does not exist until step 3, so at step 1 there is
    /// nothing to seal to. The blob is authenticated by the 6-digit confirmation
    /// code the user compares out of band, not encrypted. It is opaque to this
    /// server either way.
    pub enroll_request: String,
}

/// `POST /v1/enroll/begin` response.
#[derive(Debug, Serialize)]
pub struct BeginResponse {
    /// Unix milliseconds after which the record is swept.
    pub expires_at: i64,
}

/// `POST /v1/enroll/begin` — the new device posts its enrollment request.
///
/// # Errors
///
/// [`ApiError::Conflict`] if the `enroll_id` is already in use. Refusing rather
/// than overwriting matters: the id travels in a QR code, so whoever can read the
/// QR must not be able to swap the sealed request underneath it.
pub async fn begin(
    State(state): State<AppState>,
    JsonBody(request): JsonBody<BeginRequest>,
) -> ApiResult<(StatusCode, Json<BeginResponse>)> {
    let x25519_pub = fixed32("x25519_pub", &request.x25519_pub)?;
    let sealed = super::decode_blob(
        "enroll_request",
        &request.enroll_request,
        state.config.max_sealed_bytes,
    )?;
    let now = now_unix_ms();
    let expires_at = now.saturating_add(super::ttl_ms(state.config.enroll_ttl));
    let enroll_id = request.enroll_id;

    let store = Arc::clone(&state.store);
    let outcome =
        blocking(move || store.enroll_begin(enroll_id, x25519_pub, sealed, expires_at, now))
            .await?;
    match outcome {
        EnrollBegin::Created => Ok((StatusCode::CREATED, Json(BeginResponse { expires_at }))),
        EnrollBegin::Exists => Err(ApiError::AlreadyExists { what: "enrollment" }),
    }
}

/// `GET /v1/enroll/poll/{enroll_id}` response.
///
/// One shape covers both roles so a client has one thing to parse. Exactly one of
/// the two blob fields is ever populated.
#[derive(Debug, Serialize)]
pub struct PollResponse {
    /// Whether the field the caller asked for is present.
    pub ready: bool,
    /// The new device's X25519 public key, lowercase hex. Only for
    /// `?want=request`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x25519_pub: Option<String>,
    /// The enrollment request, standard base64. Only for `?want=request`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enroll_request: Option<String>,
    /// The sealed response. Only for `?want=response`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_response: Option<String>,
}

/// `GET /v1/enroll/poll/{enroll_id}?want=request|response`.
///
/// SPEC §6.1 lists one poll endpoint, but §6.3 has two readers with two different
/// needs: the approving device collects the sealed *request*, the new device waits
/// for the sealed *response*. Overloading one endpoint without saying which blob
/// is wanted would make "single-use retrieval" ambiguous — the new device's
/// polling loop would consume the request it never asked for. `?want=` names the
/// role; it defaults to `response`, which is the SPEC-literal reading.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the record is unknown, expired, or already
/// collected; [`ApiError::BadRequest`] for an unrecognised `want`.
pub async fn poll(
    State(state): State<AppState>,
    PathParams(enroll): PathParams<String>,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<PollResponse>> {
    let enroll_id = EnrollId::parse(&enroll)?;
    let want = super::query_value(query.as_deref(), "want").unwrap_or_else(|| "response".into());
    let now = now_unix_ms();
    let store = Arc::clone(&state.store);

    match want.as_str() {
        "request" => match blocking(move || store.enroll_take_request(enroll_id, now)).await? {
            EnrollRequest::Ready {
                x25519_pub,
                enroll_request,
            } => Ok(Json(PollResponse {
                ready: true,
                x25519_pub: Some(super::encode_hex(&x25519_pub)),
                enroll_request: Some(super::encode_blob(&enroll_request)),
                sealed_response: None,
            })),
            EnrollRequest::Gone => Err(ApiError::NotFound),
        },
        "response" => match blocking(move || store.enroll_take_response(enroll_id, now)).await? {
            EnrollResponse::Ready(sealed) => Ok(Json(PollResponse {
                ready: true,
                x25519_pub: None,
                enroll_request: None,
                sealed_response: Some(super::encode_blob(&sealed)),
            })),
            EnrollResponse::Pending => Ok(Json(PollResponse {
                ready: false,
                x25519_pub: None,
                enroll_request: None,
                sealed_response: None,
            })),
            EnrollResponse::Gone => Err(ApiError::NotFound),
        },
        _ => Err(ApiError::BadRequest(
            "want must be \"request\" or \"response\"".into(),
        )),
    }
}

/// `POST /v1/enroll/complete` request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteRequest {
    /// Which enrollment.
    pub enroll_id: EnrollId,
    /// The opaque sealed response, standard base64.
    pub sealed_response: String,
}

/// `POST /v1/enroll/complete` response. Empty on purpose: there is nothing to
/// say that the status code does not.
#[derive(Debug, Serialize)]
pub struct CompleteResponse {}

/// `POST /v1/enroll/complete` — the approving device posts its sealed response.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the enrollment is unknown or expired,
/// [`ApiError::Conflict`] if a response is already recorded.
pub async fn complete(
    State(state): State<AppState>,
    JsonBody(request): JsonBody<CompleteRequest>,
) -> ApiResult<(StatusCode, Json<CompleteResponse>)> {
    let sealed = super::decode_blob(
        "sealed_response",
        &request.sealed_response,
        state.config.max_sealed_bytes,
    )?;
    let now = now_unix_ms();
    let enroll_id = request.enroll_id;
    let store = Arc::clone(&state.store);

    match blocking(move || store.enroll_complete(enroll_id, sealed, now)).await? {
        EnrollComplete::Stored => Ok((StatusCode::OK, Json(CompleteResponse {}))),
        EnrollComplete::Missing => Err(ApiError::NotFound),
        EnrollComplete::AlreadyAnswered => Err(ApiError::AlreadyExists {
            what: "enrollment response",
        }),
    }
}

fn fixed32(field: &str, text: &str) -> ApiResult<[u8; 32]> {
    super::decode_hex_fixed::<32>(field, text)
}
