// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The change feed and item writes (SPEC §6.1).
//!
//! # The server does not understand the payload
//!
//! An envelope arrives as base64, is decoded to `Vec<u8>`, and is handed to the
//! store. Nothing here parses it, measures anything but its total length against
//! a cap, or derives a single stored value from its contents. On a `409` the
//! current bytes are returned verbatim so the *client* can merge and retry. That
//! is not laziness: the moment the server can read an envelope, a full server
//! compromise leaks plaintext, and adversary `A1` is no longer mitigated.
//!
//! # `deleted` is advisory
//!
//! SPEC §6.1 is emphatic and this implementation depends on it: a client that
//! acted on the `deleted` flag would let a hostile server erase a vault it cannot
//! read, making deletion the one destructive operation available to an attacker
//! holding the database and no keys. Real deletion is a signed tombstone inside
//! the encrypted payload (SPEC §4). `DELETE` here reclaims bytes and nothing more.
//!
//! # Preconditions
//!
//! SPEC §6.1 names only `If-Match: {version}`, which leaves creation undefined —
//! a new item has no version to match. This surface therefore accepts
//! `If-None-Match: *` (create) and `If-Match: "{version}"` (update), treats
//! `If-Match: "0"` as a synonym for the former, and refuses a write with neither.
//! A conflict answers `409` with the current version and envelope, where version
//! `0` means "no such item"; `412` is deliberately not used because SPEC's
//! conflict response has to carry a body the client can merge from.

use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::{blocking, encode_blob, AppState, Authenticated, JsonBody, PathParams};
use crate::error::{ApiError, ApiResult};
use crate::ids::{ItemId, VaultId};
use crate::store::{Limits, WriteOutcome};
use crate::time_key::now_unix_ms;

/// One entry of the change feed.
#[derive(Debug, Serialize)]
pub struct ChangeEntry {
    /// Which item.
    pub item_id: ItemId,
    /// Server-assigned per-vault sequence number. A JSON number (SPEC §6.1.1).
    pub seq: u64,
    /// The item's concurrency token. An **opaque printable-ASCII string**, never a
    /// number (SPEC §6.1.1): echo it back in `If-Match`, do not parse it, and do
    /// not compute a successor from it.
    pub version: String,
    /// The opaque envelope, standard base64, or `null` if the bytes were
    /// reclaimed.
    ///
    /// Always **present**, never omitted. A reclaimed row still carries a version
    /// a client must record, so `null` here has to be distinguishable from "the
    /// server did not tell me".
    pub envelope: Option<String>,
    /// Advisory only. See the module documentation.
    pub deleted: bool,
}

/// `GET /v1/vaults/{vid}/changes` response.
#[derive(Debug, Serialize)]
pub struct ChangesResponse {
    /// Entries in ascending `seq` order.
    pub changes: Vec<ChangeEntry>,
    /// Pass this back as `since` on the next call. Equals `since` when the feed
    /// is empty, so a caller that polls forever never rewinds.
    pub next_seq: u64,
    /// Whether more entries are waiting past `next_seq`.
    pub has_more: bool,
}

/// `GET /v1/vaults/{vid}/changes?since={seq}&limit={n}`.
///
/// # Errors
///
/// [`ApiError::BadRequest`] for a malformed `since` or `limit`,
/// [`ApiError::Forbidden`] for a token belonging to another vault.
pub async fn changes(
    State(state): State<AppState>,
    PathParams(vault): PathParams<String>,
    RawQuery(query): RawQuery,
    session: Authenticated,
) -> ApiResult<Json<ChangesResponse>> {
    let vault_id = VaultId::parse(&vault)?;
    session.for_vault(vault_id)?;

    let query = query.as_deref();
    let since = parse_since(super::query_value(query, "since").as_deref())?;
    let limit = parse_limit(
        super::query_value(query, "limit").as_deref(),
        state.config.default_changes_limit,
        state.config.max_changes_limit,
    )?;

    let store = Arc::clone(&state.store);
    let (rows, has_more) = blocking(move || store.changes(vault_id, since, limit)).await?;

    let next_seq = rows.last().map_or(since, |row| row.seq);
    let changes = rows
        .into_iter()
        .map(|row| ChangeEntry {
            item_id: row.item_id,
            seq: row.seq,
            version: super::version_token(row.version),
            envelope: row.envelope.as_deref().map(encode_blob),
            deleted: row.deleted,
        })
        .collect();

    Ok(Json(ChangesResponse {
        changes,
        next_seq,
        has_more,
    }))
}

/// `PUT` request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutRequest {
    /// The opaque envelope, standard base64.
    pub envelope: String,
}

/// The body of a successful write.
#[derive(Debug, Serialize)]
pub struct WriteResponse {
    /// The newly allocated per-vault sequence number.
    pub seq: u64,
    /// The item's new concurrency token, also returned as a strong `ETag`.
    ///
    /// A string, not a number. It travels in an HTTP header regardless, and
    /// exposing it as an integer invites a client to compute `version + 1` — which
    /// works until the representation changes and then fails silently.
    pub version: String,
}

/// `PUT /v1/vaults/{vid}/items/{item_id}` with `If-Match` or `If-None-Match`.
///
/// # Errors
///
/// [`ApiError::Conflict`] with the current envelope when the precondition fails,
/// [`ApiError::PayloadTooLarge`] past the envelope cap,
/// [`ApiError::QuotaExceeded`] when the vault is full.
pub async fn put(
    State(state): State<AppState>,
    PathParams((vault, item)): PathParams<(String, String)>,
    session: Authenticated,
    headers: HeaderMap,
    JsonBody(request): JsonBody<PutRequest>,
) -> ApiResult<Response> {
    let vault_id = VaultId::parse(&vault)?;
    let item_id = ItemId::parse(&item)?;
    session.for_vault(vault_id)?;
    let precondition = super::precondition(&headers)?;

    let envelope = super::decode_blob(
        "envelope",
        &request.envelope,
        state.config.max_envelope_bytes,
    )?;
    let limits = Limits {
        max_rows: state.config.max_items_per_vault,
        max_bytes: state.config.max_vault_bytes,
    };
    let now = now_unix_ms();

    let store = Arc::clone(&state.store);
    let outcome =
        blocking(move || store.put_item(vault_id, item_id, precondition, envelope, limits, now))
            .await?;
    render(outcome)
}

/// `DELETE /v1/vaults/{vid}/items/{item_id}` with `If-Match`.
///
/// Reclaims the envelope bytes. The row survives so `version` stays monotonic,
/// which is what stops a stale `If-Match` from ever winning; the row itself is
/// purged after SPEC §4's 90-day tombstone horizon.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the item was never stored, [`ApiError::Conflict`]
/// if `If-Match` does not hold.
pub async fn delete(
    State(state): State<AppState>,
    PathParams((vault, item)): PathParams<(String, String)>,
    session: Authenticated,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let vault_id = VaultId::parse(&vault)?;
    let item_id = ItemId::parse(&item)?;
    session.for_vault(vault_id)?;
    let precondition = super::precondition(&headers)?;
    if precondition.expects_absent() {
        return Err(ApiError::BadRequest(
            "DELETE needs the version you last saw in If-Match".into(),
        ));
    }
    let now = now_unix_ms();

    let store = Arc::clone(&state.store);
    let outcome = blocking(move || store.delete_item(vault_id, item_id, precondition, now)).await?;
    render(outcome)
}

fn render(outcome: WriteOutcome) -> ApiResult<Response> {
    match outcome {
        WriteOutcome::Ok(written) => {
            let token = super::version_token(written.version);
            let mut response = Json(WriteResponse {
                seq: written.seq,
                version: token.clone(),
            })
            .into_response();
            if let Ok(etag) = HeaderValue::from_str(&format!("\"{token}\"")) {
                response.headers_mut().insert(header::ETAG, etag);
            }
            *response.status_mut() = StatusCode::OK;
            Ok(response)
        }
        WriteOutcome::Conflict { version, envelope } => Err(ApiError::Conflict {
            version: super::version_token(version),
            envelope: envelope.as_deref().map(encode_blob),
        }),
        WriteOutcome::ItemLimit => Err(ApiError::QuotaExceeded { what: "item count" }),
        WriteOutcome::ByteLimit => Err(ApiError::QuotaExceeded {
            what: "total bytes",
        }),
        WriteOutcome::Missing => Err(ApiError::NotFound),
    }
}

fn parse_since(raw: Option<&str>) -> ApiResult<u64> {
    let Some(text) = raw else { return Ok(0) };
    if text.is_empty() {
        return Ok(0);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::BadRequest(
            "since must be a non-negative decimal integer".into(),
        ));
    }
    let value: u64 = text
        .parse()
        .map_err(|_| ApiError::BadRequest("since does not fit in 64 bits".into()))?;
    // `seq` is stored as a SQLite INTEGER, so anything above `i64::MAX` cannot
    // name a row. Rejecting is better than silently clamping: a client that
    // computed an absurd cursor has a bug, and hiding it would mean it silently
    // reads nothing forever.
    if value > i64::MAX as u64 {
        return Err(ApiError::BadRequest(
            "since is beyond any sequence number this server can assign".into(),
        ));
    }
    Ok(value)
}

fn parse_limit(raw: Option<&str>, default: u32, max: u32) -> ApiResult<u32> {
    let Some(text) = raw else { return Ok(default) };
    if text.is_empty() {
        return Ok(default);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::BadRequest(
            "limit must be a positive decimal integer".into(),
        ));
    }
    let value: u32 = text
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("limit must be in 1..={max}")))?;
    if value == 0 || value > max {
        return Err(ApiError::BadRequest(format!("limit must be in 1..={max}")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_defaults_to_zero_and_accepts_plain_integers() {
        assert_eq!(parse_since(None).unwrap(), 0);
        assert_eq!(parse_since(Some("")).unwrap(), 0);
        assert_eq!(parse_since(Some("0")).unwrap(), 0);
        assert_eq!(parse_since(Some("41")).unwrap(), 41);
    }

    #[test]
    fn absurd_since_values_are_typed_errors() {
        for hostile in [
            "-1",
            "1e9",
            "0x10",
            " 1",
            "18446744073709551616",
            "9223372036854775808", // i64::MAX + 1
            "99999999999999999999999999",
            "٣",
            "NaN",
        ] {
            assert!(
                matches!(parse_since(Some(hostile)), Err(ApiError::BadRequest(_))),
                "accepted {hostile:?}"
            );
        }
        assert_eq!(
            parse_since(Some("9223372036854775807")).unwrap(),
            i64::MAX as u64
        );
    }

    #[test]
    fn limit_is_bounded_at_both_ends() {
        assert_eq!(parse_limit(None, 100, 500).unwrap(), 100);
        assert_eq!(parse_limit(Some("7"), 100, 500).unwrap(), 7);
        assert!(parse_limit(Some("0"), 100, 500).is_err());
        assert!(parse_limit(Some("501"), 100, 500).is_err());
        assert!(parse_limit(Some("4294967296"), 100, 500).is_err());
        assert!(parse_limit(Some("-3"), 100, 500).is_err());
    }

    #[test]
    fn a_conflict_carries_the_current_envelope_so_the_client_can_merge() {
        let error = render(WriteOutcome::Conflict {
            version: 3,
            envelope: Some(vec![9, 9, 9]),
        })
        .expect_err("conflict");
        match error {
            ApiError::Conflict { version, envelope } => {
                assert_eq!(version, "3", "an opaque token, not a number");
                assert_eq!(envelope.as_deref(), Some("CQkJ"));
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn version_zero_in_a_conflict_means_absent() {
        let error = render(WriteOutcome::Conflict {
            version: 0,
            envelope: None,
        })
        .expect_err("conflict");
        match error {
            ApiError::Conflict { version, envelope } => {
                assert_eq!(version, "0");
                assert!(envelope.is_none());
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_successful_write_renders_its_version_as_a_string_and_an_etag() {
        let response = render(WriteOutcome::Ok(crate::store::Written {
            seq: 9,
            version: 4,
        }))
        .expect("ok");
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some("\"4\"")
        );
        assert_eq!(response.status(), StatusCode::OK);
    }
}
