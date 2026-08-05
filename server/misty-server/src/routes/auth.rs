// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ed25519 challenge-response, token rotation, and device admission (SPEC §6.1).
//!
//! There is no password grant, no email, no recovery flow, and no account
//! lookup. A caller proves it holds a device's Ed25519 private key, or it gets
//! nothing.
//!
//! # What the device signs — a gap in SPEC §6.1
//!
//! §6.1 specifies `POST /v1/auth/verify {vault_id, device_id, sig}` without ever
//! saying what `sig` covers. That is not a detail an implementation may choose:
//! two implementations would not interoperate, and the obvious reading — "sign
//! the nonce" — is insecure. A bare nonce names neither the vault nor the device,
//! so a signature captured from a device that belongs to two vaults, or issued by
//! a server that reuses a nonce across vaults, would transfer. This
//! implementation signs
//!
//! ```text
//! "misty/server/auth/v1"
//! vault_id[16]
//! device_id[16]
//! LE32(nonce_len) || nonce
//! ```
//!
//! and the constant belongs in SPEC §6.6's table.
//!
//! # The nonce travels in the verify body — also an addition
//!
//! §6.1's verify body carries no nonce, which leaves the server to guess which
//! challenge is being answered when a device has more than one outstanding.
//! Sending it makes single-use exact.
//!
//! # Encoding
//!
//! Every field here is lowercase hex, per SPEC §6.1.1: the challenge nonce, the
//! echoed nonce, the signature, and both public keys. This crate emitted standard
//! base64 first, `misty-sync` implemented the spec, and neither noticed until an
//! interop test ran the two halves against each other. Hex is the ruling, and the
//! reason it is the right one is that a hex string is *also* well-formed base64 —
//! so for a variable-width field like a nonce, "accept either" silently accepts
//! the wrong bytes.
//!
//! # Challenges are bound, single-use, and say nothing
//!
//! A challenge is stored against the `(vault_id, device_id)` that asked for it
//! and is redeemable by no other pair. It is deleted on the first verify attempt
//! whatever the outcome, so a failed attempt cannot be retried against the same
//! nonce. Issuing one never reveals whether the vault or the device exists —
//! otherwise the endpoint would be the enumeration oracle this whole design
//! exists to avoid.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{blocking, ttl_ms, AppState, Authenticated, JsonBody, PathParams};
use crate::error::{ApiError, ApiResult};
use crate::ids::{DeviceId, VaultId};
use crate::store::{Admission, RefreshOutcome, Session};
use crate::time_key::{now_unix_ms, MAX_NONCE_BYTES};
use crate::token::{random_array, Secret, TokenHash, NONCE_BYTES};

/// Domain separator for challenge signatures. Wire-visible; belongs in
/// SPEC §6.6.
pub const AUTH_SIGNING_CONTEXT: &[u8] = b"misty/server/auth/v1";

/// The exact bytes a device signs to authenticate.
#[must_use]
pub fn auth_payload(vault_id: VaultId, device_id: DeviceId, nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTH_SIGNING_CONTEXT.len() + 36 + nonce.len());
    out.extend_from_slice(AUTH_SIGNING_CONTEXT);
    out.extend_from_slice(vault_id.as_bytes());
    out.extend_from_slice(device_id.as_bytes());
    out.extend_from_slice(&u32::try_from(nonce.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(nonce);
    out
}

/// `POST /v1/auth/challenge` request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    /// Which vault.
    pub vault_id: VaultId,
    /// Which device.
    pub device_id: DeviceId,
}

/// `POST /v1/auth/challenge` response.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// 32 random bytes, lowercase hex (SPEC §6.1.1).
    pub nonce: String,
    /// Unix milliseconds after which the nonce is dead.
    pub expires_at: i64,
}

/// `POST /v1/auth/challenge` — issues a nonce bound to `(vault_id, device_id)`.
///
/// # Errors
///
/// [`ApiError::RateLimited`], [`ApiError::Internal`]. Never a 404: the response
/// is identical for a vault that exists and one that does not.
pub async fn challenge(
    State(state): State<AppState>,
    JsonBody(request): JsonBody<ChallengeRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    // Charged to the vault bucket even though the caller is unauthenticated;
    // otherwise this endpoint would be an un-metered way to make the server
    // write rows.
    state.limiter.check_vault(request.vault_id)?;

    let nonce = random_array::<NONCE_BYTES>()?;
    let hash = TokenHash::of(&nonce);
    let expires_at = now_unix_ms().saturating_add(ttl_ms(state.config.challenge_ttl));

    let store = Arc::clone(&state.store);
    blocking(move || {
        store.put_challenge(
            *hash.as_bytes(),
            request.vault_id,
            request.device_id,
            expires_at,
        )
    })
    .await?;

    Ok(Json(ChallengeResponse {
        nonce: super::encode_hex(&nonce),
        expires_at,
    }))
}

/// `POST /v1/auth/verify` request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    /// Which vault.
    pub vault_id: VaultId,
    /// Which device.
    pub device_id: DeviceId,
    /// The nonce from `/v1/auth/challenge`, lowercase hex, echoed exactly.
    pub nonce: String,
    /// Ed25519 signature over [`auth_payload`], lowercase hex.
    pub sig: String,
    /// The device's Ed25519 public key, lowercase hex.
    ///
    /// Required only when bootstrapping a vault's **first** device: for any
    /// device the server already knows, the stored key is used and a mismatching
    /// one is refused. Sending it never overwrites anything.
    #[serde(default)]
    pub ed25519_pub: Option<String>,
}

/// A minted token pair.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// Bearer token for every authenticated endpoint.
    pub access_token: String,
    /// Single-use token for `POST /v1/auth/refresh`.
    pub refresh_token: String,
    /// Access-token lifetime in seconds. SPEC §6.1: 15 minutes.
    pub expires_in: u64,
    /// Always `"Bearer"`.
    pub token_type: &'static str,
    /// Echoed so a client can assert it authenticated to the vault it meant to.
    pub vault_id: VaultId,
    /// Echoed for the same reason.
    pub device_id: DeviceId,
}

/// `POST /v1/auth/verify` — redeems a challenge for a token pair.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] for any failure of the challenge or signature —
/// deliberately the same answer for "no such challenge", "wrong device", and
/// "bad signature". [`ApiError::Forbidden`] if the instance is closed to new
/// vaults or the device needs a sponsor. [`ApiError::QuotaExceeded`] if the
/// instance is at its vault limit.
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody<VerifyRequest>,
) -> ApiResult<Json<TokenResponse>> {
    state.limiter.check_vault(request.vault_id)?;

    let nonce = super::decode_hex("nonce", &request.nonce, MAX_NONCE_BYTES)?;
    let signature = decode_hex_fixed::<64>("sig", &request.sig)?;
    let now = now_unix_ms();

    // Consumed first, and consumed whatever happens next.
    let store = Arc::clone(&state.store);
    let nonce_hash = *TokenHash::of(&nonce).as_bytes();
    let challenge = blocking(move || store.take_challenge(nonce_hash, now))
        .await?
        .ok_or(ApiError::Unauthorized)?;

    // The binding check. A challenge issued for one device is not redeemable by
    // another, and one issued for vault A is not redeemable against vault B.
    if challenge.vault_id != request.vault_id || challenge.device_id != request.device_id {
        return Err(ApiError::Unauthorized);
    }

    let store = Arc::clone(&state.store);
    let (vault_id, device_id) = (request.vault_id, request.device_id);
    let known = blocking(move || store.device(vault_id, device_id)).await?;

    let public_key = match (&known, &request.ed25519_pub) {
        // A known device authenticates with the key the server holds. A
        // presented key must agree with it; otherwise re-presenting a device id
        // with a fresh key would be a takeover.
        (Some(device), None) => device.ed25519_pub,
        (Some(device), Some(presented)) => {
            let presented = decode_hex_fixed::<32>("ed25519_pub", presented)?;
            if presented != device.ed25519_pub {
                return Err(ApiError::Unauthorized);
            }
            device.ed25519_pub
        }
        (None, Some(presented)) => decode_hex_fixed::<32>("ed25519_pub", presented)?,
        (None, None) => {
            return Err(ApiError::BadRequest(
                "ed25519_pub is required for a device this server has not seen".into(),
            ))
        }
    };

    verify_signature(&public_key, vault_id, device_id, &nonce, &signature)?;

    if known.is_none() {
        // Admission, not authentication. Gate it on the instance's registration
        // secret first, so that the Bootstrapped/NeedsSponsor distinction — the
        // one place this surface reveals that a vault exists — is visible only to
        // a caller that already holds that secret.
        check_registration(&state, &headers)?;

        let store = Arc::clone(&state.store);
        let max_vaults = state.config.max_vaults;
        let admission = blocking(move || {
            store.admit_device(vault_id, device_id, public_key, None, now, max_vaults)
        })
        .await?;
        match admission {
            Admission::Bootstrapped => {
                tracing::info!(
                    target: "misty_server::auth",
                    vault = %vault_id.log_prefix(),
                    "vault bootstrapped by its first device",
                );
            }
            Admission::AlreadyPresent | Admission::Admitted => {}
            Admission::KeyMismatch => return Err(ApiError::Unauthorized),
            Admission::NeedsSponsor => {
                // The vault exists and this device is not in it. Admission is an
                // existing device's decision, never the server's (SPEC §6.2).
                return Err(ApiError::Forbidden);
            }
            Admission::VaultLimit => {
                return Err(ApiError::QuotaExceeded {
                    what: "instance vault",
                })
            }
        }
    }

    let session = Session {
        vault_id,
        device_id,
        family: random_array::<16>()?,
    };
    issue(&state, session).await.map(Json)
}

/// `POST /v1/auth/refresh` request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshRequest {
    /// The refresh token from the previous `verify` or `refresh`.
    pub refresh_token: String,
}

/// `POST /v1/auth/refresh` — rotates a refresh token.
///
/// Not in SPEC §6.1, which issues refresh tokens and defines no way to use one.
///
/// Rotation is unconditional and reuse is fatal to the whole chain: presenting an
/// already-consumed token means either the client replayed or an attacker holds a
/// copy, and the server cannot tell which. Revoking the family costs the honest
/// client one device-key authentication and costs the attacker everything.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] for an unknown, expired, revoked, or replayed
/// token.
pub async fn refresh(
    State(state): State<AppState>,
    JsonBody(request): JsonBody<RefreshRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let hash = TokenHash::parse_presented(&request.refresh_token)?;
    let now = now_unix_ms();
    let store = Arc::clone(&state.store);
    let outcome = blocking(move || store.consume_refresh_token(*hash.as_bytes(), now)).await?;

    match outcome {
        RefreshOutcome::Rotated(session) => {
            state.limiter.check_vault(session.vault_id)?;
            issue(&state, session).await.map(Json)
        }
        RefreshOutcome::ReuseDetected(session) => {
            tracing::warn!(
                target: "misty_server::auth",
                vault = %session.vault_id.log_prefix(),
                "refresh token reuse detected; session family revoked",
            );
            Err(ApiError::Unauthorized)
        }
        RefreshOutcome::Rejected => Err(ApiError::Unauthorized),
    }
}

/// `POST /v1/vaults/{vid}/devices` request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddDeviceRequest {
    /// The new device's id, as it appears in the enrollment QR (SPEC §6.3).
    pub device_id: DeviceId,
    /// The new device's Ed25519 public key, lowercase hex (SPEC §6.1.1).
    pub ed25519_pub: String,
}

/// `POST /v1/vaults/{vid}/devices` response.
#[derive(Debug, Serialize)]
pub struct AddDeviceResponse {
    /// The device that was admitted.
    pub device_id: DeviceId,
    /// `"created"` or `"already_present"`.
    pub result: &'static str,
}

/// `POST /v1/vaults/{vid}/devices` — an admitted device vouches for a new one.
///
/// Not in SPEC §6.1. SPEC §6.3 step 4 requires it: without an authenticated
/// admission step the server would have to accept any device that presents a key,
/// and anyone who learned a `vault_id` could write to the vault. The writes would
/// still be rejected by every client (SPEC §6.2), but they would consume the
/// user's quota, which is a denial of service the design does not have to accept.
///
/// This does **not** add anyone to the roster. The roster is a client-signed vault
/// item and the server cannot produce one; `tests/hostile_server.rs` proves a row
/// here buys an attacker nothing.
///
/// # Errors
///
/// [`ApiError::Forbidden`] if the token is for another vault,
/// [`ApiError::Conflict`] if the device id is taken by a different key.
pub async fn add_device(
    State(state): State<AppState>,
    PathParams(vault): PathParams<String>,
    session: Authenticated,
    JsonBody(request): JsonBody<AddDeviceRequest>,
) -> ApiResult<(StatusCode, Json<AddDeviceResponse>)> {
    let vault_id = VaultId::parse(&vault)?;
    let sponsor = session.for_vault(vault_id)?;
    let public_key = decode_hex_fixed::<32>("ed25519_pub", &request.ed25519_pub)?;
    let device_id = request.device_id;
    let now = now_unix_ms();

    let store = Arc::clone(&state.store);
    let admission = blocking(move || {
        store.admit_device(
            vault_id,
            device_id,
            public_key,
            Some(sponsor.device_id),
            now,
            None,
        )
    })
    .await?;

    match admission {
        Admission::Admitted | Admission::Bootstrapped => {
            tracing::info!(
                target: "misty_server::auth",
                vault = %vault_id.log_prefix(),
                "device admitted by an existing device",
            );
            Ok((
                StatusCode::CREATED,
                Json(AddDeviceResponse {
                    device_id,
                    result: "created",
                }),
            ))
        }
        Admission::AlreadyPresent => Ok((
            StatusCode::OK,
            Json(AddDeviceResponse {
                device_id,
                result: "already_present",
            }),
        )),
        Admission::KeyMismatch => Err(ApiError::AlreadyExists { what: "device" }),
        Admission::NeedsSponsor | Admission::VaultLimit => Err(ApiError::Forbidden),
    }
}

async fn issue(state: &AppState, session: Session) -> ApiResult<TokenResponse> {
    let access = Secret::generate()?;
    let refresh_secret = Secret::generate()?;
    let now = now_unix_ms();
    let access_expires = now.saturating_add(ttl_ms(state.config.access_token_ttl));
    let refresh_expires = now.saturating_add(ttl_ms(state.config.refresh_token_ttl));

    let store = Arc::clone(&state.store);
    let access_hash = *access.hash().as_bytes();
    let refresh_hash = *refresh_secret.hash().as_bytes();
    blocking(move || {
        store.put_access_token(access_hash, session, access_expires)?;
        store.put_refresh_token(refresh_hash, session, refresh_expires)
    })
    .await?;

    Ok(TokenResponse {
        access_token: access.to_wire(),
        refresh_token: refresh_secret.to_wire(),
        expires_in: state.config.access_token_ttl.as_secs(),
        token_type: "Bearer",
        vault_id: session.vault_id,
        device_id: session.device_id,
    })
}

fn verify_signature(
    public_key: &[u8; 32],
    vault_id: VaultId,
    device_id: DeviceId,
    nonce: &[u8],
    signature: &[u8; 64],
) -> ApiResult<()> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| ApiError::Unauthorized)?;
    // `verify_strict` rejects small-order and non-canonical keys, which
    // `verify` does not. On a surface where the key can be attacker-chosen, the
    // difference is between a signature check and a formality.
    key.verify_strict(
        &auth_payload(vault_id, device_id, nonce),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| ApiError::Unauthorized)
}

fn check_registration(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let Some(expected) = state.config.registration_token.as_deref() else {
        return Ok(());
    };
    let presented = headers
        .get("x-misty-registration")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if crate::token::secret_str_eq(presented, expected) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

fn decode_hex_fixed<const N: usize>(field: &str, text: &str) -> ApiResult<[u8; N]> {
    super::decode_hex_fixed::<N>(field, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signed_payload_names_the_vault_and_the_device() {
        let vault_a = VaultId::from_bytes([1; 16]);
        let vault_b = VaultId::from_bytes([2; 16]);
        let device = DeviceId::from_bytes([3; 16]);
        assert_ne!(
            auth_payload(vault_a, device, b"nonce"),
            auth_payload(vault_b, device, b"nonce"),
            "a signature must not transfer between vaults",
        );
        assert_ne!(
            auth_payload(vault_a, device, b"nonce"),
            auth_payload(vault_a, DeviceId::from_bytes([4; 16]), b"nonce"),
            "a signature must not transfer between devices",
        );
    }

    #[test]
    fn the_nonce_is_length_prefixed_so_framing_is_unambiguous() {
        let vault = VaultId::from_bytes([0; 16]);
        let device = DeviceId::from_bytes([0; 16]);
        assert_ne!(
            auth_payload(vault, device, b"ab"),
            auth_payload(vault, device, b"a")
        );
        assert_eq!(
            auth_payload(vault, device, b"ab").len(),
            AUTH_SIGNING_CONTEXT.len() + 16 + 16 + 4 + 2
        );
    }

    #[test]
    fn fixed_width_fields_reject_the_wrong_length_and_the_wrong_alphabet() {
        let thirty_two = super::super::encode_hex(&[7u8; 32]);
        assert!(decode_hex_fixed::<32>("k", &thirty_two).is_ok());
        assert!(decode_hex_fixed::<64>("k", &thirty_two).is_err());
        assert!(decode_hex_fixed::<32>("k", "!!!").is_err());
        // The pre-§6.1.1 form is now refused outright, which is the point: a
        // field with two accepted spellings is a field two implementations
        // disagree about.
        assert!(decode_hex_fixed::<32>("k", &super::super::encode_blob(&[7u8; 32])).is_err());
    }
}
