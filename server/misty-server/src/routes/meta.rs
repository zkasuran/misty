// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Signed time, quota, and health.
//!
//! # `/v1/time` (SPEC §6.5)
//!
//! A signed timestamp with no challenge is replayable forever: record one
//! response, serve it back, and the client's effective clock is pinned to that
//! instant — which is exactly the attack §6.5 says the signature exists to
//! prevent. So the nonce is **required** and is covered by the signature. See
//! [`crate::time_key`] for the payload layout.
//!
//! The nonce and the signature are lowercase hex, per SPEC §6.1.1. An earlier
//! version of this endpoint used base64url for the query nonce and standard base64
//! for the signature, which is two base64 variants in one protocol; the reason for
//! the second one — standard base64's `+` becoming a space under query-string form
//! decoding — disappears entirely with hex.
//!
//! # `/v1/quota` has no vault in its path
//!
//! SPEC §6.1 writes it as `GET /v1/quota`, with the vault implied by the access
//! token. That is kept verbatim, and it is the better design: with no vault id in
//! the path there is no mismatch between path and token to get wrong, so the
//! confused-deputy bug cannot be written.

use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::Json;
use serde::Serialize;

use super::{blocking, AppState, Authenticated};
use crate::error::{ApiError, ApiResult};
use crate::ids::VaultId;
use crate::time_key::{now_unix_ms, MAX_NONCE_BYTES, MIN_NONCE_BYTES};

/// `GET /v1/time` response.
#[derive(Debug, Serialize)]
pub struct TimeResponse {
    /// The server's clock, unix milliseconds.
    pub unix_ms: i64,
    /// The nonce, echoed as lowercase hex. Compare the *decoded bytes* against
    /// what you sent: a response whose nonce differs is a replay.
    pub nonce: String,
    /// Ed25519 signature over `"misty/time/v1" || LE32(len) || nonce ||
    /// LE64(unix_ms)`, lowercase hex. Verify against the pinned public key.
    pub sig: String,
}

/// `GET /v1/time?nonce=…`.
///
/// The nonce must be lowercase hex and must decode to between [`MIN_NONCE_BYTES`]
/// and [`MAX_NONCE_BYTES`] bytes. It must be freshly random per request; reusing
/// one makes the response replayable again.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if the nonce is missing, unparseable, or out of range.
pub async fn time(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> ApiResult<Json<TimeResponse>> {
    let raw = super::query_value(query.as_deref(), "nonce").ok_or_else(|| {
        ApiError::BadRequest(
            "?nonce= is required: an unbound signed timestamp is replayable forever".into(),
        )
    })?;
    let nonce = decode_nonce(&raw)?;

    let unix_ms = now_unix_ms();
    let signature = state.time_key.sign_time(&nonce, unix_ms);

    Ok(Json(TimeResponse {
        unix_ms,
        nonce: super::encode_hex(&nonce),
        sig: super::encode_hex(&signature),
    }))
}

/// The ceilings an operator has configured, so a client can plan rather than
/// discover them by being refused.
#[derive(Debug, Serialize)]
pub struct QuotaLimits {
    /// Largest single envelope.
    pub max_envelope_bytes: u64,
    /// Most rows one vault may hold, tombstones included.
    pub max_items_per_vault: u64,
    /// Most envelope bytes one vault may hold.
    pub max_vault_bytes: u64,
    /// Largest accepted `limit` on the changes feed.
    pub max_changes_limit: u32,
}

/// `GET /v1/quota` response.
#[derive(Debug, Serialize)]
pub struct QuotaResponse {
    /// Total stored envelope bytes.
    pub bytes_used: u64,
    /// Rows that still hold an envelope.
    pub item_count: u64,
    /// All rows, including reclaimed ones. This is what
    /// `limits.max_items_per_vault` counts.
    pub row_count: u64,
    /// The configured ceilings.
    pub limits: QuotaLimits,
}

/// `GET /v1/quota` — usage for the token's vault.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] without a live token.
pub async fn quota(
    State(state): State<AppState>,
    session: Authenticated,
) -> ApiResult<Json<QuotaResponse>> {
    let vault_id = session.0.vault_id;
    let store = Arc::clone(&state.store);
    let usage = blocking(move || store.usage(vault_id)).await?;
    Ok(Json(QuotaResponse {
        bytes_used: usage.bytes_used,
        item_count: usage.item_count,
        row_count: usage.row_count,
        limits: QuotaLimits {
            max_envelope_bytes: state.config.max_envelope_bytes,
            max_items_per_vault: state.config.max_items_per_vault,
            max_vault_bytes: state.config.max_vault_bytes,
            max_changes_limit: state.config.max_changes_limit,
        },
    }))
}

/// `GET /healthz` response.
#[derive(Debug, Serialize)]
pub struct Health {
    /// `"ok"`, or the request would not have succeeded.
    pub status: &'static str,
}

/// `GET /healthz` — liveness *and* readiness.
///
/// Deliberately touches storage. A health check that only proves the process is
/// scheduled will report healthy while the database is unwritable, which is the
/// failure an operator most needs to hear about. The query reads a vault id of
/// all zeros, which no CSPRNG will produce, so it exercises the connection and
/// the `items` schema without depending on any data existing.
///
/// The response says nothing else: no version, no counts, no build id. A health
/// endpoint is reachable by anyone who can reach the socket.
///
/// # Errors
///
/// [`ApiError::Internal`] if storage is unreachable.
pub async fn healthz(State(state): State<AppState>) -> ApiResult<Json<Health>> {
    let store = Arc::clone(&state.store);
    blocking(move || store.usage(VaultId::from_bytes([0u8; 16]))).await?;
    Ok(Json(Health { status: "ok" }))
}

fn decode_nonce(raw: &str) -> ApiResult<Vec<u8>> {
    let bad = || {
        ApiError::BadRequest(format!(
            "nonce must be lowercase hex for {MIN_NONCE_BYTES}..={MAX_NONCE_BYTES} bytes"
        ))
    };
    // Lowercase hex, and nothing else. This endpoint is why §6.1.1 exists: a
    // signature bound to "whichever alphabet the decoder guessed" is bound to
    // nothing, and the nonce here is deliberately variable-width, so guessing is
    // unavoidable if two alphabets are accepted — 64 characters of `[0-9a-f]` are
    // simultaneously 32 bytes of hex and 48 bytes of base64, both in range.
    //
    // Hex also removes the reason this endpoint previously used base64url at all:
    // standard base64's `+` arrives as a space under query-string form decoding,
    // so a query-safe variant was needed. Hex needs no variant.
    let decoded = super::decode_hex("nonce", raw, MAX_NONCE_BYTES)?;
    if decoded.len() < MIN_NONCE_BYTES {
        return Err(bad());
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_decodes_from_lowercase_hex_and_nothing_else() {
        // 0xab so the hex form contains letters: `[7u8; 32]` hex-encodes to digits
        // only, where "reject uppercase" is vacuous.
        let bytes = [0xabu8; 32];
        assert_eq!(decode_nonce(&hex::encode(bytes)).unwrap(), bytes);

        // Every pre-§6.1.1 form is now refused. The base64url one is the
        // interesting case: it was this server's own encoding, and accepting both
        // is exactly the ambiguity §6.1.1 forbids.
        use base64::Engine as _;
        for wrong in [
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
            base64::engine::general_purpose::URL_SAFE.encode(bytes),
            base64::engine::general_purpose::STANDARD.encode(bytes),
            hex::encode(bytes).to_ascii_uppercase(),
        ] {
            assert!(decode_nonce(&wrong).is_err(), "accepted {wrong}");
        }
    }

    #[test]
    fn hex_needs_no_query_string_variant() {
        // The whole reason this endpoint once used base64url: standard base64's
        // `+` arrives as a space under form decoding, so a query-safe alphabet was
        // needed and the protocol ended up with two base64 variants. Hex has no
        // character a query string touches, so there is nothing to vary.
        let bytes: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(251)).collect();
        let text = hex::encode(&bytes);
        assert!(text.bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_eq!(decode_nonce(&text).unwrap(), bytes);
    }

    #[test]
    fn a_short_or_missing_nonce_is_refused() {
        assert!(decode_nonce(&hex::encode([1u8; 8])).is_err());
        assert!(decode_nonce("").is_err());
        // An odd number of hex characters is half a byte, not a nonce.
        assert!(decode_nonce(&"a".repeat(33)).is_err());
    }

    #[test]
    fn an_oversized_nonce_is_refused_before_decoding() {
        let huge = "a".repeat(1024 * 1024);
        assert!(decode_nonce(&huge).is_err());
        assert!(decode_nonce(&hex::encode([1u8; 65])).is_err());
    }

    #[test]
    fn hostile_nonces_are_typed_errors() {
        for hostile in ["!!!!", "%%%%", "../../etc/passwd", "\u{0}\u{0}"] {
            assert!(
                matches!(decode_nonce(hostile), Err(ApiError::BadRequest(_))),
                "accepted {hostile:?}"
            );
        }
    }
}
