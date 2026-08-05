// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SPEC §6.1's endpoints, one method each, over a [`Transport`].
//!
//! This layer knows about paths, headers, status codes and the JSON in
//! [`crate::wire`]. It does not know about queues, cursors, merges or retries:
//! that is [`crate::engine`]. Keeping the split means the hostile-server tests
//! can drive either half.
//!
//! # What the auth signature covers (SPEC §6.1.1)
//!
//! An earlier §6.1 gave `POST /v1/auth/verify {vault_id, device_id, sig}` without
//! saying what `sig` covered, and the natural reading — sign the server's nonce —
//! hands the server a **signing oracle for the device identity key**. That key
//! also signs every envelope (§2.4) and every roster (§6.2), over messages with no
//! domain prefix at all. §6.1.1 now fixes it byte-exactly:
//!
//! ```text
//! "misty/server/auth/v1" ‖ vault_id[16] ‖ device_id[16] ‖ LE32(nonce.len()) ‖ nonce
//! ```
//!
//! The `/server/` segment separates authenticating to a server from the same key's
//! two other jobs. Binding the vault and the device stops a challenge from being
//! relayed into another vault or presented by another device. The LE32 prefix stops
//! a future appended field from making two different messages encode identically.
//!
//! # Two endpoints §6.1 originally left out
//!
//! `POST /v1/auth/refresh` rotates the token pair; §6.1 used to issue a
//! `refresh_token` and define nothing that consumed one. Reuse revokes the whole
//! family, so a client keeps exactly the newest token and never retries a
//! refresh — the request path falls back to a full challenge-response instead,
//! which always works because it holds the device key.
//!
//! `POST /v1/vaults/{vid}/devices` admits a device. §6.3 step 4 ends with "and
//! registers with the server" and §6.1 listed no endpoint that did it; without one
//! the server would have to accept any device that presented a key, and anyone who
//! learned a `vault_id` could burn the user's quota. The first device for a vault
//! bootstraps on `verify`; every later one is admitted by an already-admitted
//! device, which is why [`SyncEngine::approve_enrollment`](crate::SyncEngine::approve_enrollment)
//! calls this before it seals a grant.

use misty_crypto::identity::DeviceIdentity;
use misty_crypto::{DeviceId, EnrollId, ItemId, VaultId};

use crate::error::{Result, SyncError};
use crate::limits;
use crate::time::verify_time;
use crate::transport::{Method, SyncRequest, SyncResponse, Transport};
use crate::wire::{
    self, Challenge, ChangeFeed, EnrollmentPoll, PutOutcome, Quota, ServerVersion, Tokens, Want,
};

/// Domain separator for the challenge-response signature (SPEC §6.6).
pub const AUTH_SIGNING_CONTEXT: &[u8] = b"misty/server/auth/v1";

/// The exact bytes an authentication signature covers (SPEC §6.1.1).
///
/// ```text
/// "misty/server/auth/v1" ‖ vault_id[16] ‖ device_id[16] ‖ LE32(nonce.len()) ‖ nonce
/// ```
#[must_use]
pub fn auth_signing_bytes(vault: &VaultId, device: &DeviceId, nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTH_SIGNING_CONTEXT.len() + 36 + nonce.len());
    out.extend_from_slice(AUTH_SIGNING_CONTEXT);
    out.extend_from_slice(vault.as_bytes());
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(&u32::try_from(nonce.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(nonce);
    out
}

/// What a client needs to know before it can talk to a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncConfig {
    /// The vault's address. The server has no other handle on the user
    /// (SPEC §6).
    pub vault_id: VaultId,
    /// The pinned Ed25519 key that signs `/v1/time` (SPEC §6.5). Pinned rather
    /// than fetched, because a key the server hands you signs whatever the server
    /// wants.
    pub time_public_key: [u8; 32],
    /// Changes to ask for per page.
    pub page_limit: u32,
}

impl SyncConfig {
    /// A configuration with the default page size.
    #[must_use]
    pub fn new(vault_id: VaultId, time_public_key: [u8; 32]) -> Self {
        Self {
            vault_id,
            time_public_key,
            page_limit: limits::DEFAULT_PAGE_LIMIT,
        }
    }
}

/// A live session.
#[derive(Debug)]
struct Session {
    access_token: String,
    /// The newest refresh token. Single-use and rotating: SPEC §6.1 says reuse
    /// revokes the family, so this is replaced on every rotation and never
    /// presented twice.
    refresh_token: Option<String>,
}

/// SPEC §6.1's endpoints, over one transport.
#[derive(Debug)]
pub struct SyncClient<T: Transport> {
    transport: T,
    config: SyncConfig,
    identity: DeviceIdentity,
    session: Option<Session>,
    requests: usize,
}

impl<T: Transport> SyncClient<T> {
    /// A client that has not authenticated yet.
    #[must_use]
    pub fn new(transport: T, config: SyncConfig, identity: DeviceIdentity) -> Self {
        Self {
            transport,
            config,
            identity,
            session: None,
            requests: 0,
        }
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &SyncConfig {
        &self.config
    }

    /// The transport, for a caller that wants to inspect a mock.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// This device's id.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.identity.device_id()
    }

    /// This device's identity.
    ///
    /// Exposed because roster signing (SPEC §6.2) and envelope sealing need it,
    /// and the alternative — passing a `&DeviceIdentity` into every roster call —
    /// invites a caller to pass a *different* one than the session authenticated
    /// with, which would produce a roster no peer can chain to.
    #[must_use]
    pub const fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// How many requests this client has issued, successful or not.
    #[must_use]
    pub const fn requests(&self) -> usize {
        self.requests
    }

    /// Whether a session is held.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }

    /// Drops the session, so the next call re-authenticates.
    pub fn forget_session(&mut self) {
        self.session = None;
    }

    /// Sends a request with no `Authorization` header.
    ///
    /// For `/v1/time` and the enrollment endpoints: a device mid-enrollment is
    /// not in the roster yet and therefore has no session to present.
    async fn send_open(
        &mut self,
        operation: &'static str,
        request: SyncRequest,
    ) -> Result<SyncResponse> {
        self.requests = self.requests.saturating_add(1);
        let response = self.transport.request(request).await?;
        if response.status == 401 || response.status == 403 {
            return Err(SyncError::AuthRefused { operation });
        }
        Ok(response)
    }

    /// Sends a request with the bearer token, refreshing or re-authenticating
    /// exactly once on a `401`.
    ///
    /// The recovery order is refresh, then challenge-response. A refresh is one
    /// round trip against two, and if it fails the fall-through costs nothing —
    /// but it is tried *once* and the token is dropped whatever happens, because
    /// SPEC §6.1 says presenting a consumed refresh token revokes the family. A
    /// client that retried a refresh would lock itself out.
    ///
    /// Once, not "until it works": a server that keeps answering `401` to a
    /// signature it just accepted is broken or hostile, and a loop there is a
    /// self-inflicted denial of service against our own server.
    async fn send(
        &mut self,
        operation: &'static str,
        request: SyncRequest,
    ) -> Result<SyncResponse> {
        if self.session.is_none() {
            self.authenticate().await?;
        }
        let response = self.send_authenticated(request.clone()).await?;
        if response.status != 401 {
            return Ok(response);
        }
        self.reauthenticate().await?;
        let retry = self.send_authenticated(request).await?;
        if retry.status == 401 || retry.status == 403 {
            return Err(SyncError::AuthRefused { operation });
        }
        Ok(retry)
    }

    /// Gets a fresh session, by rotation if a refresh token is held and by
    /// challenge-response otherwise.
    async fn reauthenticate(&mut self) -> Result<()> {
        let refresh_token = self
            .session
            .take()
            .and_then(|session| session.refresh_token);
        if let Some(token) = refresh_token {
            // Consumed, and consumed whether or not it works.
            if self.refresh(&token).await.is_ok() {
                return Ok(());
            }
        }
        self.authenticate().await
    }

    async fn send_authenticated(&mut self, request: SyncRequest) -> Result<SyncResponse> {
        let token = self
            .session
            .as_ref()
            .map(|session| session.access_token.clone())
            .unwrap_or_default();
        self.requests = self.requests.saturating_add(1);
        self.transport
            .request(request.header("authorization", format!("Bearer {token}")))
            .await
    }

    /// Runs SPEC §6.1's challenge-response and stores the session.
    ///
    /// # Errors
    ///
    /// [`SyncError::AuthRefused`] if the server rejects the signature,
    /// [`SyncError::Server`] for any other non-2xx status, or
    /// [`SyncError::Malformed`] for a response that is not the right shape.
    pub async fn authenticate(&mut self) -> Result<()> {
        const OP: &str = "authenticate";
        let body = wire::challenge_body(&self.config.vault_id, &self.identity.device_id())?;
        let response = self
            .send_open(
                OP,
                SyncRequest::new(Method::Post, "/v1/auth/challenge").json(body),
            )
            .await?;
        if !response.is_success() {
            return Err(SyncError::Server {
                operation: OP,
                status: response.status,
            });
        }
        let Challenge {
            nonce,
            encoded_nonce,
            ..
        } = wire::decode_challenge(&response.body)?;

        let signature = self.identity.sign(&auth_signing_bytes(
            &self.config.vault_id,
            &self.identity.device_id(),
            &nonce,
        ));
        let body = wire::verify_body(
            &self.config.vault_id,
            &self.identity.device_id(),
            &encoded_nonce,
            &signature,
            &self.identity.ed25519_public(),
        )?;
        let response = self
            .send_open(
                OP,
                SyncRequest::new(Method::Post, "/v1/auth/verify").json(body),
            )
            .await?;
        if !response.is_success() {
            return Err(SyncError::Server {
                operation: OP,
                status: response.status,
            });
        }
        let Tokens {
            access_token,
            refresh_token,
            ..
        } = wire::decode_tokens(&response.body)?;
        self.session = Some(Session {
            access_token,
            refresh_token,
        });
        Ok(())
    }

    /// `POST /v1/auth/refresh` — rotates the token pair.
    ///
    /// Single-use: SPEC §6.1 says presenting a consumed refresh token revokes the
    /// whole family, so a caller must never retry with the same token. The session
    /// is cleared before the request is sent, so a failure leaves nothing that
    /// could be presented twice.
    ///
    /// # Errors
    ///
    /// [`SyncError::AuthRefused`] if the token is unknown, expired, revoked or
    /// replayed, or [`SyncError::Server`] for any other non-2xx status.
    pub async fn refresh(&mut self, refresh_token: &str) -> Result<()> {
        const OP: &str = "auth refresh";
        self.session = None;
        let body = wire::refresh_body(refresh_token)?;
        let response = self
            .send_open(
                OP,
                SyncRequest::new(Method::Post, "/v1/auth/refresh").json(body),
            )
            .await?;
        if !response.is_success() {
            return Err(SyncError::Server {
                operation: OP,
                status: response.status,
            });
        }
        let Tokens {
            access_token,
            refresh_token,
            ..
        } = wire::decode_tokens(&response.body)?;
        self.session = Some(Session {
            access_token,
            refresh_token,
        });
        Ok(())
    }

    /// `POST /v1/vaults/{vid}/devices` — vouches for a device so it may
    /// authenticate.
    ///
    /// The server's device table is an access-control cache, never a source of
    /// trust: this admits a device to the *quota*, and says nothing about whether
    /// any client should accept what it writes. That decision is SPEC §6.2's signed
    /// roster and nothing here can influence it.
    ///
    /// `409` means the id is already taken by a different key, which is a device-id
    /// collision or an impostor; either way it is not something to retry.
    ///
    /// # Errors
    ///
    /// [`SyncError::Server`] for a non-2xx status other than `200`/`201`.
    pub async fn admit_device(&mut self, device: &DeviceId, ed25519_pub: &[u8; 32]) -> Result<()> {
        const OP: &str = "admit device";
        let path = format!("/v1/vaults/{}/devices", self.config.vault_id.to_hex());
        let body = wire::add_device_body(device, ed25519_pub)?;
        let response = self
            .send(OP, SyncRequest::new(Method::Post, path).json(body))
            .await?;
        if response.is_success() {
            return Ok(());
        }
        Err(SyncError::Server {
            operation: OP,
            status: response.status,
        })
    }

    /// `GET /v1/vaults/{vid}/changes?since={seq}&limit={n}`.
    ///
    /// `since` of `None` starts at the beginning of the feed.
    ///
    /// # Errors
    ///
    /// [`SyncError::Server`] for a non-2xx status, or anything
    /// [`wire::decode_change_feed`] rejects.
    pub async fn changes(&mut self, since: Option<i64>, limit: u32) -> Result<ChangeFeed> {
        const OP: &str = "changes";
        let path = format!(
            "/v1/vaults/{}/changes?since={}&limit={}",
            self.config.vault_id.to_hex(),
            since.unwrap_or(0),
            limit.max(1),
        );
        let response = self.send(OP, SyncRequest::new(Method::Get, path)).await?;
        if !response.is_success() {
            return Err(SyncError::Server {
                operation: OP,
                status: response.status,
            });
        }
        wire::decode_change_feed(&response.body)
    }

    /// `PUT /v1/vaults/{vid}/items/{item_id}`, with `If-Match` when a version is
    /// held and `If-None-Match: *` when one is not.
    ///
    /// SPEC §6.1 spells the update precondition `If-Match: "{version}"`, quoted, as
    /// a strong validator; [`ServerVersion::to_if_match`] adds the quotes so the
    /// token itself never has to carry them. A write with neither header is `428`,
    /// which is why there is no third case here.
    ///
    /// # Errors
    ///
    /// [`SyncError::EnvelopeTooLarge`] if the envelope is over the cap or the
    /// server says it is, [`SyncError::QuotaExhausted`] if the vault is full,
    /// [`SyncError::Server`] for any other unexpected status, or anything the
    /// decoders reject.
    pub async fn put_item(
        &mut self,
        item_id: &ItemId,
        envelope: &[u8],
        version: Option<&ServerVersion>,
    ) -> Result<PutOutcome> {
        const OP: &str = "put item";
        if envelope.len() > limits::MAX_ENVELOPE_LEN {
            return Err(SyncError::EnvelopeTooLarge {
                len: envelope.len(),
                max: limits::MAX_ENVELOPE_LEN,
            });
        }
        let path = format!(
            "/v1/vaults/{}/items/{}",
            self.config.vault_id.to_hex(),
            item_id.to_hex(),
        );
        let mut request = SyncRequest::new(Method::Put, path).json(wire::envelope_body(envelope)?);
        request = match version {
            Some(version) => request.header("if-match", version.to_if_match()),
            None => request.header("if-none-match", "*"),
        };
        let response = self.send(OP, request).await?;
        match response.status {
            200 | 201 | 204 => wire::decode_put_applied(&response.body),
            409 => wire::decode_conflict(&response.body),
            413 => Err(SyncError::EnvelopeTooLarge {
                len: envelope.len(),
                max: limits::MAX_ENVELOPE_LEN,
            }),
            // SPEC §6.1: `507`, not `413`, when the *vault* is full. Distinct from
            // a retriable failure on purpose — waiting does not free space, and a
            // client that backed off in a loop would never tell the user why.
            507 => Err(SyncError::QuotaExhausted { operation: OP }),
            status => Err(SyncError::Server {
                operation: OP,
                status,
            }),
        }
    }

    /// `DELETE /v1/vaults/{vid}/items/{item_id}`.
    ///
    /// The only caller is the tombstone purge: an ordinary delete in Misty is a
    /// signed tombstone inside the payload (SPEC §4), and this endpoint drops the
    /// row after that tombstone has had its 90 days to propagate.
    ///
    /// A `404` is success: the row this call exists to remove is already gone.
    ///
    /// # Errors
    ///
    /// [`SyncError::Server`] for any other non-2xx status.
    pub async fn delete_item(
        &mut self,
        item_id: &ItemId,
        version: Option<&ServerVersion>,
    ) -> Result<()> {
        const OP: &str = "delete item";
        let path = format!(
            "/v1/vaults/{}/items/{}",
            self.config.vault_id.to_hex(),
            item_id.to_hex(),
        );
        let mut request = SyncRequest::new(Method::Delete, path);
        if let Some(version) = version {
            request = request.header("if-match", version.to_if_match());
        }
        let response = self.send(OP, request).await?;
        if response.is_success() || response.status == 404 || response.status == 410 {
            return Ok(());
        }
        Err(SyncError::Server {
            operation: OP,
            status: response.status,
        })
    }

    /// `GET /v1/time?nonce=…`, verified against the pinned key (SPEC §6.5).
    ///
    /// Returns the server's Unix milliseconds. Unauthenticated on purpose: a
    /// device whose clock is wrong may not be able to authenticate, and the
    /// signature is what makes the answer trustworthy, not the session.
    ///
    /// # Errors
    ///
    /// [`SyncError::TimeNonceMismatch`] for a replayed response,
    /// [`SyncError::TimeSignatureInvalid`] for one signed by another key,
    /// [`SyncError::Server`] for a non-2xx status, or [`SyncError::Malformed`].
    pub async fn signed_time(&mut self) -> Result<i64> {
        const OP: &str = "time";
        let nonce = misty_crypto::random::array::<{ limits::TIME_NONCE_LEN }>()?;
        // base64url, unpadded. SPEC §6.1.1 puts nonces in hex and `misty-server`
        // requires base64url here (`routes/meta.rs:156`); see `crate::encoding`.
        // In a query string base64url is also the only base64 that survives, since
        // standard base64's `+` arrives as a space.
        let path = format!("/v1/time?nonce={}", crate::encoding::to_hex(&nonce));
        let response = self
            .send_open(OP, SyncRequest::new(Method::Get, path))
            .await?;
        if !response.is_success() {
            return Err(SyncError::Server {
                operation: OP,
                status: response.status,
            });
        }
        let (unix_ms, echoed, signature) = wire::decode_time(&response.body)?;
        verify_time(
            &self.config.time_public_key,
            &nonce,
            &echoed,
            unix_ms,
            &signature,
        )?;
        Ok(unix_ms)
    }

    /// `GET /v1/quota`.
    ///
    /// # Errors
    ///
    /// [`SyncError::Server`] for a non-2xx status, or [`SyncError::Malformed`].
    pub async fn quota(&mut self) -> Result<Quota> {
        const OP: &str = "quota";
        let response = self
            .send(OP, SyncRequest::new(Method::Get, "/v1/quota"))
            .await?;
        if !response.is_success() {
            return Err(SyncError::Server {
                operation: OP,
                status: response.status,
            });
        }
        wire::decode_quota(&response.body)
    }

    /// `POST /v1/enroll/begin` — the new device publishes its request.
    ///
    /// # SPEC §6.1's `sealed_request` could not be sealed, and is now
    /// `enroll_request`
    ///
    /// An earlier §6.1 listed `{enroll_id, x25519_pub, sealed_request}`. There is
    /// nothing to seal it *to*: the sealing key is derived from the *approver's*
    /// ephemeral X25519 key, which does not exist until §6.3 step 3, and the same
    /// payload is displayed as a QR code on the new device's screen. §6.3 now says
    /// so — "authenticated, not confidential — and it cannot be otherwise" — and
    /// the field is `enroll_request`, carrying unsealed CBOR.
    ///
    /// What protects it is the 6-digit confirmation code, which is BLAKE2b over the
    /// whole request; the approver recomputes it over what the *server* delivered
    /// and the user compares it out of band before approving.
    ///
    /// # One fallback, and why
    ///
    /// `misty-server` still calls the field `sealed_request`
    /// (`routes/enroll.rs:59`) and enforces `deny_unknown_fields`, so the canonical
    /// name is refused with a `400`. This sends the spec's name first and retries
    /// once with the legacy one, so the client is correct per §6.1 and compatible
    /// with the server that exists. The retry disappears when the server is renamed.
    ///
    /// # Errors
    ///
    /// [`SyncError::Server`] for a non-2xx status from both attempts.
    pub async fn enroll_begin(
        &mut self,
        enroll_id: &EnrollId,
        x25519_pub: &[u8; 32],
        enroll_request: &[u8],
    ) -> Result<()> {
        const OP: &str = "enroll begin";
        let canonical = wire::enroll_begin_body(enroll_id, x25519_pub, enroll_request)?;
        let response = self
            .send_open(
                OP,
                SyncRequest::new(Method::Post, "/v1/enroll/begin").json(canonical),
            )
            .await?;
        if response.is_success() {
            return Ok(());
        }
        if response.status != 400 {
            return Err(SyncError::Server {
                operation: OP,
                status: response.status,
            });
        }
        let legacy = wire::legacy_enroll_begin_body(enroll_id, x25519_pub, enroll_request)?;
        let response = self
            .send_open(
                OP,
                SyncRequest::new(Method::Post, "/v1/enroll/begin").json(legacy),
            )
            .await?;
        if response.is_success() {
            return Ok(());
        }
        Err(SyncError::Server {
            operation: OP,
            status: response.status,
        })
    }

    /// `GET /v1/enroll/poll/{enroll_id}?want=request|response`.
    ///
    /// SPEC §6.1 has one poll endpoint and two devices that need it: the approving
    /// device collects the request, the new device waits for the grant. Retrieval is
    /// **single-use per blob**, so the role has to be named — a client that polled
    /// for "whatever is there" would consume the request it never asked for and
    /// strand the approver.
    ///
    /// A `404` is "unknown, expired, or already collected", which is indistinguishable
    /// from "not yet" to a caller that has not been given the blob, so it comes back
    /// as a not-ready answer rather than an error.
    ///
    /// # Errors
    ///
    /// [`SyncError::Server`] for a non-2xx status other than `404`, or
    /// [`SyncError::Malformed`].
    pub async fn enroll_poll(
        &mut self,
        enroll_id: &EnrollId,
        want: Want,
    ) -> Result<EnrollmentPoll> {
        const OP: &str = "enroll poll";
        let path = format!(
            "/v1/enroll/poll/{}?want={}",
            enroll_id.to_hex(),
            want.as_str()
        );
        let response = self
            .send_open(OP, SyncRequest::new(Method::Get, path))
            .await?;
        if response.status == 404 {
            return Ok(EnrollmentPoll::default());
        }
        if !response.is_success() {
            return Err(SyncError::Server {
                operation: OP,
                status: response.status,
            });
        }
        wire::decode_enrollment_poll(&response.body)
    }

    /// `POST /v1/enroll/complete`.
    ///
    /// # Errors
    ///
    /// [`SyncError::Server`] for a non-2xx status.
    pub async fn enroll_complete(&mut self, enroll_id: &EnrollId, sealed: &[u8]) -> Result<()> {
        const OP: &str = "enroll complete";
        let body = wire::enroll_complete_body(enroll_id, sealed)?;
        let response = self
            .send_open(
                OP,
                SyncRequest::new(Method::Post, "/v1/enroll/complete").json(body),
            )
            .await?;
        if !response.is_success() {
            return Err(SyncError::Server {
                operation: OP,
                status: response.status,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_auth_message_binds_the_context_the_vault_and_the_device() {
        let vault = VaultId::from_bytes([1; 16]);
        let device = DeviceId::from_bytes([2; 16]);
        let bytes = auth_signing_bytes(&vault, &device, b"nonce");
        assert!(bytes.starts_with(AUTH_SIGNING_CONTEXT));
        assert_eq!(bytes.len(), AUTH_SIGNING_CONTEXT.len() + 16 + 16 + 4 + 5);
        assert!(bytes.ends_with(b"nonce"));
        // SPEC §6.1.1's LE32 length prefix: ("ab", "") and ("a", "b") must not
        // encode identically once another field is appended.
        assert_ne!(
            auth_signing_bytes(&vault, &device, b"ab"),
            auth_signing_bytes(&vault, &device, b"a")
        );
        assert_eq!(AUTH_SIGNING_CONTEXT, b"misty/server/auth/v1");

        // A challenge answered for one vault is not an answer for another, which is
        // what stops a relayed challenge.
        let elsewhere = VaultId::from_bytes([3; 16]);
        assert_ne!(bytes, auth_signing_bytes(&elsewhere, &device, b"nonce"));
        let someone_else = DeviceId::from_bytes([4; 16]);
        assert_ne!(bytes, auth_signing_bytes(&vault, &someone_else, b"nonce"));
    }

    #[test]
    fn the_context_is_not_shared_with_any_other_construction() {
        // SPEC §6.6: two constructions must not share a context string.
        for other in [
            misty_crypto::identity::ROSTER_SIGNING_CONTEXT,
            misty_crypto::enrollment::REQUEST_CONTEXT,
            misty_crypto::enrollment::SEAL_CONTEXT,
            misty_crypto::derive::EPOCH_SALT,
            misty_crypto::derive::ENROLLMENT_INFO_PREFIX,
            crate::time::TIME_SIGNING_CONTEXT,
            crate::roster::ROSTER_ID_SALT,
            crate::state::FINGERPRINT_SALT,
        ] {
            assert_ne!(AUTH_SIGNING_CONTEXT, other);
        }
    }

    #[test]
    fn a_default_config_asks_for_the_default_page_size() {
        let config = SyncConfig::new(VaultId::from_bytes([0; 16]), [0; 32]);
        assert_eq!(config.page_limit, limits::DEFAULT_PAGE_LIMIT);
    }
}
