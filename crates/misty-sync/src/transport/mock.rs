// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! An in-process SPEC §6.1 server, and the switches that make it hostile.
//!
//! This is the crate's primary test instrument, and it ships in the library
//! rather than in `tests/` for two reasons. It compiles for
//! `wasm32-unknown-unknown`, so the protocol suite is not quietly native-only.
//! And the layers above it — the UI phase, the bindings phase — need a server to
//! develop against that is not a network.
//!
//! It is a *blob store that knows nothing*, exactly as SPEC §6 requires: it never
//! decrypts, never inspects an envelope, never merges. It assigns `seq`, hands out
//! `version` tokens, checks `If-Match`, and verifies Ed25519 challenge-responses
//! against the public keys it was told about. That last part is deliberate — the
//! authentication path is real here, so a client that signed the wrong bytes fails
//! against this mock rather than in production.
//!
//! # The [`Faults`] switches are the point
//!
//! Each one is a specific thing a compromised server or a network attacker can
//! do, and each has a test in `tests/hostile_server.rs` asserting the client's
//! answer. They are grouped here rather than scattered through the tests so that
//! "what have we actually defended against" is one struct to read.
//!
//! Nothing wires a fault to a real transport: [`MockTransport`] speaks to memory.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use misty_crypto::identity::DeviceIdentity;
use misty_crypto::{DeviceId, EnrollId, ItemId, SignatureBytes, VaultId};

use crate::client::auth_signing_bytes;
use crate::error::{Result, SyncError, TransportKind};
use crate::signature::verify_detached;
use crate::time::time_signing_bytes;
use crate::transport::{Method, SyncRequest, SyncResponse, Transport};
use crate::wire::to_base64;

/// Hostile behaviours a [`MockServer`] can be told to exhibit.
///
/// Every field is something an attacker who holds the database, or who sits on
/// the wire, can actually do. None of them requires a key.
///
/// Not `#[non_exhaustive]`, unlike the rest of this crate's public types: a test
/// writes `Faults { rollback_seq: true, ..Faults::default() }`, and a
/// non-exhaustive struct cannot be built that way from another crate. A new
/// field here breaking a downstream test that was constructing the struct by
/// hand is the correct outcome — it means someone should look at whether the new
/// fault applies to them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Faults {
    /// Flip one byte of the ciphertext of every envelope the feed serves.
    pub tamper_envelopes: bool,
    /// Serve `seq` values at or below what the client asked to resume after, and
    /// a `next_seq` below its cursor.
    pub rollback_seq: bool,
    /// Set `deleted: true` on every change-feed entry, with no tombstone in any
    /// payload. SPEC §6.1 makes the flag advisory; this proves it.
    pub force_deleted_flag: bool,
    /// Serve the first `/v1/time` answer forever, nonce and all.
    pub replay_time: bool,
    /// Sign `/v1/time` with a key the client has not pinned.
    pub wrong_time_key: bool,
    /// Report server time this far behind its real value, so a signed response
    /// walks the client's clock backwards.
    pub time_offset_ms: i64,
    /// Answer every `PUT` with `409`, forever, offering back whatever it already
    /// holds.
    pub conflict_forever: bool,
    /// Answer every `409` with a fresh `version`, so a client that only bounds
    /// "same state twice" would spin.
    pub conflict_rotates_version: bool,
    /// Claim `has_more` on every page, forever.
    pub endless_feed: bool,
    /// Claim `has_more` on every page while delivering nothing and leaving
    /// `next_seq` where it was — the benign version of the same lie, which a
    /// client must survive rather than error on.
    pub stalled_feed: bool,
    /// Emit a page in descending `seq` order.
    pub descending_page: bool,
    /// Answer with a `next_seq` far outside the plausible range.
    pub absurd_next_seq: bool,
    /// Put a CR-LF in the `version` token, aiming at the next `If-Match`.
    pub inject_header_in_version: bool,
    /// Answer the change feed with these bytes and a `200`, whatever the vault
    /// actually holds. The hostile-input suite's way in.
    pub feed_body: Option<Vec<u8>>,
    /// Once this many requests have been served, answer with this status and this
    /// body.
    pub status_after: Option<(usize, u16, Vec<u8>)>,
    /// Fail the transport from this request index onwards, as if the network
    /// vanished.
    pub offline_after: Option<usize>,
}

/// One request the mock served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestLog {
    /// The method.
    pub method: Method,
    /// The path, query string included.
    pub path: String,
    /// The status the mock answered with, or `None` if the transport failed.
    pub status: Option<u16>,
}

/// An enrollment in flight: the new device's ephemeral key and public request,
/// then the approver's sealed grant. Each half is `take`n once, because SPEC §6.1
/// makes retrieval single-use per blob.
type EnrollmentSlot = (Option<([u8; 32], Vec<u8>)>, Option<Vec<u8>>);

/// One stored row. The mock never looks inside `envelope`.
///
/// `envelope` is `None` for a row whose bytes a `DELETE` reclaimed. The row itself
/// survives, because `version` has to stay monotonic or a stale `If-Match` would
/// eventually win — which is exactly what the real server does.
#[derive(Clone, Debug)]
struct Row {
    seq: i64,
    version: String,
    envelope: Option<Vec<u8>>,
    deleted: bool,
}

/// Everything the mock remembers.
#[derive(Debug)]
struct State {
    vault_id: VaultId,
    rows: BTreeMap<ItemId, Row>,
    next_seq: i64,
    next_version: u64,
    devices: BTreeMap<DeviceId, [u8; 32]>,
    challenges: BTreeMap<DeviceId, Vec<u8>>,
    tokens: BTreeMap<String, DeviceId>,
    refresh_tokens: BTreeMap<String, DeviceId>,
    enrollments: BTreeMap<EnrollId, EnrollmentSlot>,
    time_ms: i64,
    replayed_time: Option<Vec<u8>>,
    log: Vec<RequestLog>,
    faults: Faults,
}

/// An in-process SPEC §6.1 server.
///
/// Cheap to clone: every clone shares one state, which is how two simulated
/// devices talk to one server.
#[derive(Clone, Debug)]
pub struct MockServer {
    state: Arc<Mutex<State>>,
    time_key: Arc<DeviceIdentity>,
    other_key: Arc<DeviceIdentity>,
}

impl MockServer {
    /// A server holding an empty vault.
    ///
    /// # Errors
    ///
    /// [`SyncError::Crypto`] if the CSPRNG fails while generating the two
    /// `/v1/time` signing keys.
    pub fn new(vault_id: VaultId) -> Result<Self> {
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                vault_id,
                rows: BTreeMap::new(),
                next_seq: 0,
                next_version: 0,
                devices: BTreeMap::new(),
                challenges: BTreeMap::new(),
                tokens: BTreeMap::new(),
                refresh_tokens: BTreeMap::new(),
                enrollments: BTreeMap::new(),
                time_ms: 1_800_000_000_000,
                replayed_time: None,
                log: Vec::new(),
                faults: Faults::default(),
            })),
            time_key: Arc::new(DeviceIdentity::generate()?),
            other_key: Arc::new(DeviceIdentity::generate()?),
        })
    }

    /// A transport handle onto this server.
    #[must_use]
    pub fn transport(&self) -> MockTransport {
        MockTransport {
            server: self.clone(),
        }
    }

    /// The key a client should pin for `/v1/time` (SPEC §6.5).
    #[must_use]
    pub fn time_public_key(&self) -> [u8; 32] {
        self.time_key.ed25519_public()
    }

    /// A second, unrelated key, for the test that a client refuses a `/v1/time`
    /// response signed by the wrong one.
    #[must_use]
    pub fn other_public_key(&self) -> [u8; 32] {
        self.other_key.ed25519_public()
    }

    /// Runs `f` against the locked state, recovering the guard if a previous test
    /// panicked while holding it.
    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        match self.state.lock() {
            Ok(mut guard) => f(&mut guard),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }

    /// Tells the server a device's public key, so its challenge-responses verify.
    pub fn register(&self, identity: &DeviceIdentity) {
        self.with(|state| {
            state
                .devices
                .insert(identity.device_id(), identity.ed25519_public());
        });
    }

    /// Replaces the fault set.
    pub fn set_faults(&self, faults: Faults) {
        self.with(|state| state.faults = faults);
    }

    /// Clears every fault.
    pub fn heal(&self) {
        self.set_faults(Faults::default());
    }

    /// Sets the time the server reports, in Unix milliseconds.
    pub fn set_time_ms(&self, unix_ms: i64) {
        self.with(|state| {
            state.time_ms = unix_ms;
            state.replayed_time = None;
        });
    }

    /// Every request served, in order.
    #[must_use]
    pub fn log(&self) -> Vec<RequestLog> {
        self.with(|state| state.log.clone())
    }

    /// How many requests have been served.
    #[must_use]
    pub fn requests(&self) -> usize {
        self.with(|state| state.log.len())
    }

    /// Forgets the request log.
    pub fn clear_log(&self) {
        self.with(|state| state.log.clear());
    }

    /// How many `PUT`s the server has seen for one item.
    #[must_use]
    pub fn puts_for(&self, item_id: &ItemId) -> usize {
        let needle = format!("/items/{}", item_id.to_hex());
        self.with(|state| {
            state
                .log
                .iter()
                .filter(|entry| entry.method == Method::Put && entry.path.contains(&needle))
                .count()
        })
    }

    /// The envelope the server holds for an item, or `None` if there is no row or
    /// its bytes have been reclaimed.
    #[must_use]
    pub fn envelope_of(&self, item_id: &ItemId) -> Option<Vec<u8>> {
        self.with(|state| state.rows.get(item_id).and_then(|row| row.envelope.clone()))
    }

    /// Every item the server still holds an envelope for.
    ///
    /// Rows whose bytes a `DELETE` reclaimed are excluded: they exist only to keep
    /// `version` monotonic and there is nothing to compare.
    #[must_use]
    pub fn snapshot(&self) -> BTreeMap<ItemId, Vec<u8>> {
        self.with(|state| {
            state
                .rows
                .iter()
                .filter_map(|(id, row)| row.envelope.clone().map(|bytes| (*id, bytes)))
                .collect()
        })
    }

    /// Writes a row without going through the protocol, for a test that needs the
    /// server to hold something no honest client would have written.
    pub fn inject(&self, item_id: ItemId, envelope: Vec<u8>) {
        self.with(|state| {
            state.next_seq = state.next_seq.saturating_add(1);
            state.next_version = state.next_version.saturating_add(1);
            let version = format!("v{}", state.next_version);
            let seq = state.next_seq;
            state.rows.insert(
                item_id,
                Row {
                    seq,
                    version,
                    envelope: Some(envelope),
                    deleted: false,
                },
            );
        });
    }

    /// Serves one request, applying the fault set.
    fn serve(&self, request: &SyncRequest) -> Result<SyncResponse> {
        let (index, faults) = self.with(|state| (state.log.len(), state.faults.clone()));
        if faults.offline_after.is_some_and(|after| index >= after) {
            self.with(|state| {
                state.log.push(RequestLog {
                    method: request.method,
                    path: request.path.clone(),
                    status: None,
                });
            });
            return Err(SyncError::Transport {
                operation: "mock",
                kind: TransportKind::Connect,
            });
        }

        let response = match &faults.status_after {
            Some((after, status, body)) if index >= *after => {
                SyncResponse::new(*status, body.clone())
            }
            _ => self.route(request, &faults),
        };
        self.with(|state| {
            state.log.push(RequestLog {
                method: request.method,
                path: request.path.clone(),
                status: Some(response.status),
            });
        });
        Ok(response)
    }

    fn route(&self, request: &SyncRequest, faults: &Faults) -> SyncResponse {
        let (path, query) = split_query(&request.path);
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        match (request.method, parts.as_slice()) {
            (Method::Post, ["v1", "auth", "challenge"]) => self.challenge(request),
            (Method::Post, ["v1", "auth", "verify"]) => self.verify(request),
            (Method::Post, ["v1", "auth", "refresh"]) => self.refresh(request),
            (Method::Get, ["v1", "time"]) => self.time(query, faults),
            (Method::Post, ["v1", "enroll", "begin"]) => self.enroll_begin(request),
            (Method::Get, ["v1", "enroll", "poll", id]) => {
                self.enroll_poll(id, query_param(query, "want").unwrap_or("response"))
            }
            (Method::Post, ["v1", "enroll", "complete"]) => self.enroll_complete(request),
            (Method::Get, ["v1", "quota"]) => self.guarded(request, |server| server.quota()),
            (Method::Post, ["v1", "vaults", vault, "devices"]) => {
                let vault = (*vault).to_owned();
                let body = request.body.clone().unwrap_or_default();
                self.guarded(request, move |server| server.add_device(&vault, &body))
            }
            (Method::Get, ["v1", "vaults", vault, "changes"]) => {
                let vault = (*vault).to_owned();
                let query = query.unwrap_or_default().to_owned();
                self.guarded(request, move |server| {
                    server.changes(&vault, &query, faults)
                })
            }
            (Method::Put, ["v1", "vaults", vault, "items", item]) => {
                let vault = (*vault).to_owned();
                let item = (*item).to_owned();
                let body = request.body.clone().unwrap_or_default();
                let if_match = request.header_value("if-match").map(str::to_owned);
                let if_none_match = request.header_value("if-none-match").map(str::to_owned);
                self.guarded(request, move |server| {
                    server.put_item(
                        &vault,
                        &item,
                        &body,
                        if_match.as_deref(),
                        if_none_match.as_deref(),
                        faults,
                    )
                })
            }
            (Method::Delete, ["v1", "vaults", vault, "items", item]) => {
                let vault = (*vault).to_owned();
                let item = (*item).to_owned();
                let if_match = request.header_value("if-match").map(str::to_owned);
                self.guarded(request, move |server| {
                    server.delete_item(&vault, &item, if_match.as_deref())
                })
            }
            _ => SyncResponse::new(404, Vec::new()),
        }
    }

    /// Wraps a handler that needs a session.
    fn guarded(
        &self,
        request: &SyncRequest,
        handler: impl FnOnce(&Self) -> SyncResponse,
    ) -> SyncResponse {
        let token = request
            .header_value("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default()
            .to_owned();
        if !self.with(|state| state.tokens.contains_key(&token)) {
            return SyncResponse::new(401, Vec::new());
        }
        handler(self)
    }

    /// Emits SPEC §6.1.1's forms throughout: lowercase hex for the challenge nonce,
    /// `/v1/time`'s nonce and signature, and every id and public key; standard base64
    /// only for envelopes and sealed blobs.
    ///
    /// This mock and `misty-server` once disagreed here, each following its own reading
    /// of an underspecified §6.1, and both suites passed while the halves could not
    /// talk. They agree now, and `tests/interop_server.rs` is what keeps them honest —
    /// a mock that drifts from the real peer is worse than no mock, because it
    /// manufactures confidence.
    fn challenge(&self, request: &SyncRequest) -> SyncResponse {
        let Some(body) = parse_json(request) else {
            return SyncResponse::new(400, Vec::new());
        };
        let Some(device) = field_id::<16>(&body, "device_id").map(DeviceId::from_bytes) else {
            return SyncResponse::new(400, Vec::new());
        };
        let (nonce, expires_at) = self.with(|state| {
            state.next_version = state.next_version.saturating_add(1);
            let mut nonce = state.next_version.to_le_bytes().to_vec();
            nonce.extend_from_slice(&[0xab; 24]);
            state.challenges.insert(device, nonce.clone());
            (nonce, state.time_ms.saturating_add(60_000))
        });
        json_response(
            200,
            &serde_json::json!({
                "nonce": crate::encoding::to_hex(&nonce),
                "expires_at": expires_at,
            }),
        )
    }

    fn verify(&self, request: &SyncRequest) -> SyncResponse {
        let Some(body) = parse_json(request) else {
            return SyncResponse::new(400, Vec::new());
        };
        let (Some(vault), Some(device), Some(sig)) = (
            field_id::<16>(&body, "vault_id").map(VaultId::from_bytes),
            field_id::<16>(&body, "device_id").map(DeviceId::from_bytes),
            field_fixed::<64>(&body, "sig"),
        ) else {
            return SyncResponse::new(400, Vec::new());
        };
        // The nonce the client echoed must be the one that was issued. SPEC §6.1:
        // "`verify` carries the `nonce` it is answering, so the server does not have
        // to guess which outstanding challenge a signature belongs to."
        let echoed = body
            .get("nonce")
            .and_then(serde_json::Value::as_str)
            .and_then(crate::encoding::challenge_nonce_from_wire);
        let Some((public_key, nonce)) = self.with(|state| {
            let key = state
                .devices
                .get(&device)
                .copied()
                .or_else(|| field_fixed::<32>(&body, "ed25519_pub"));
            let nonce = state.challenges.remove(&device);
            key.zip(nonce)
        }) else {
            return SyncResponse::new(401, Vec::new());
        };
        if echoed.as_deref() != Some(nonce.as_slice()) {
            return SyncResponse::new(401, Vec::new());
        }
        if verify_detached(
            &public_key,
            &auth_signing_bytes(&vault, &device, &nonce),
            &sig,
            SyncError::AuthRefused { operation: "mock" },
        )
        .is_err()
        {
            return SyncResponse::new(401, Vec::new());
        }
        // Trust on first use for a vault's first device (SPEC §6.1), so an
        // enrollment can complete without the test having to register anyone.
        self.with(|state| state.devices.insert(device, public_key));
        self.issue(device)
    }

    /// `POST /v1/auth/refresh`. Rotating and single-use: reuse revokes the family,
    /// which is what makes a client that retries a refresh lock itself out.
    fn refresh(&self, request: &SyncRequest) -> SyncResponse {
        let Some(body) = parse_json(request) else {
            return SyncResponse::new(400, Vec::new());
        };
        let Some(token) = body
            .get("refresh_token")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
        else {
            return SyncResponse::new(400, Vec::new());
        };
        let outcome = self.with(|state| state.refresh_tokens.remove(&token));
        match outcome {
            Some(device) => self.issue(device),
            None => SyncResponse::new(401, Vec::new()),
        }
    }

    /// `POST /v1/vaults/{vid}/devices` — an admitted device vouches for another.
    fn add_device(&self, vault_hex: &str, body: &[u8]) -> SyncResponse {
        if !self.vault_matches(vault_hex) {
            return SyncResponse::new(404, Vec::new());
        }
        let Some(body) = parse_json_bytes(body) else {
            return SyncResponse::new(400, Vec::new());
        };
        let (Some(device), Some(key)) = (
            field_id::<16>(&body, "device_id").map(DeviceId::from_bytes),
            field_fixed::<32>(&body, "ed25519_pub"),
        ) else {
            return SyncResponse::new(400, Vec::new());
        };
        let conflict = self.with(|state| match state.devices.get(&device) {
            Some(existing) if *existing != key => true,
            Some(_) => false,
            None => {
                state.devices.insert(device, key);
                false
            }
        });
        if conflict {
            return SyncResponse::new(409, Vec::new());
        }
        json_response(
            201,
            &serde_json::json!({ "device_id": device.to_hex(), "result": "created" }),
        )
    }

    fn issue(&self, device: DeviceId) -> SyncResponse {
        let (access, refresh) = self.with(|state| {
            state.next_version = state.next_version.saturating_add(1);
            let access = format!("tok-{}", state.next_version);
            let refresh = format!("ref-{}", state.next_version);
            state.tokens.insert(access.clone(), device);
            state.refresh_tokens.insert(refresh.clone(), device);
            (access, refresh)
        });
        json_response(
            200,
            &serde_json::json!({
                "access_token": access,
                "refresh_token": refresh,
                "expires_in": 900,
            }),
        )
    }

    fn time(&self, query: Option<&str>, faults: &Faults) -> SyncResponse {
        let Some(raw_nonce) = query_param(query, "nonce") else {
            return SyncResponse::new(400, Vec::new());
        };
        // §6.1.1: nonces travel as lowercase hex, in a body and in a query string
        // alike. Hex is what makes the query-string case work without a second base64
        // alphabet, since standard base64's `+` arrives as a space.
        let Some(nonce) =
            crate::encoding::fixed_from_wire::<{ crate::limits::TIME_NONCE_LEN }>(raw_nonce)
        else {
            return SyncResponse::new(400, Vec::new());
        };
        let nonce = nonce.to_vec();
        if faults.replay_time {
            if let Some(cached) = self.with(|state| state.replayed_time.clone()) {
                return SyncResponse::new(200, cached);
            }
        }
        let unix_ms = self.with(|state| state.time_ms.saturating_add(faults.time_offset_ms));
        let key: &DeviceIdentity = if faults.wrong_time_key {
            &self.other_key
        } else {
            &self.time_key
        };
        let signature: SignatureBytes = key.sign(&time_signing_bytes(&nonce, unix_ms));
        let response = json_response(
            200,
            &serde_json::json!({
                "unix_ms": unix_ms,
                "nonce": hex::encode(&nonce),
                "sig": signature.to_hex(),
            }),
        );
        if faults.replay_time {
            self.with(|state| state.replayed_time = Some(response.body.clone()));
        }
        response
    }

    fn quota(&self) -> SyncResponse {
        let (bytes, live, rows) = self.with(|state| {
            (
                state
                    .rows
                    .values()
                    .filter_map(|row| row.envelope.as_ref())
                    .map(Vec::len)
                    .sum::<usize>() as u64,
                state
                    .rows
                    .values()
                    .filter(|row| row.envelope.is_some())
                    .count() as u64,
                state.rows.len() as u64,
            )
        });
        json_response(
            200,
            &serde_json::json!({
                "bytes_used": bytes,
                "item_count": live,
                "row_count": rows,
                "limits": {
                    "max_envelope_bytes": 64 * 1024,
                    "max_items_per_vault": 10_000,
                    "max_vault_bytes": 10_000_000,
                    "max_changes_limit": 500,
                },
            }),
        )
    }

    fn changes(&self, vault_hex: &str, query: &str, faults: &Faults) -> SyncResponse {
        if !self.vault_matches(vault_hex) {
            return SyncResponse::new(404, Vec::new());
        }
        if let Some(body) = &faults.feed_body {
            return SyncResponse::new(200, body.clone());
        }
        let since: i64 = query_param(Some(query), "since")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let limit: usize = query_param(Some(query), "limit")
            .and_then(|value| value.parse().ok())
            .unwrap_or(64)
            .clamp(1, 512);

        let (mut page, has_more, mut next_seq) = self.with(|state| {
            let mut rows: Vec<(ItemId, Row)> = state
                .rows
                .iter()
                .filter(|(_, row)| row.seq > since)
                .map(|(id, row)| (*id, row.clone()))
                .collect();
            rows.sort_by_key(|(id, row)| (row.seq, *id));
            let total = rows.len();
            rows.truncate(limit);
            let next = rows.last().map_or(since, |(_, row)| row.seq);
            (rows, total > limit, next)
        });

        if faults.rollback_seq {
            for (_, row) in &mut page {
                row.seq = row.seq.saturating_sub(1_000).max(0);
            }
            next_seq = next_seq.saturating_sub(1_000).max(0);
        }
        if faults.absurd_next_seq {
            next_seq = i64::MAX;
        }
        if faults.endless_feed && page.is_empty() {
            // An endless feed that also *advances* is the version that costs the
            // client something: a server that claims `has_more` while standing
            // still is caught by the no-progress guard after one extra page, so
            // this walks the cursor forward one step at a time forever instead.
            next_seq = next_seq.saturating_add(1);
        }
        if faults.descending_page {
            page.reverse();
        }

        let entries: Vec<serde_json::Value> = page
            .into_iter()
            .map(|(id, row)| {
                let envelope = row.envelope.map(|mut envelope| {
                    if faults.tamper_envelopes {
                        // One bit in the ciphertext. The header and signature stay
                        // intact, so this is the case where only the AEAD tag or the
                        // Ed25519 check can catch it.
                        if let Some(byte) = envelope.get_mut(130) {
                            *byte ^= 0x01;
                        }
                    }
                    to_base64(&envelope)
                });
                let version = if faults.inject_header_in_version {
                    format!("{}\r\nX-Injected: 1", row.version)
                } else {
                    row.version
                };
                serde_json::json!({
                    "item_id": id.to_hex(),
                    "seq": row.seq,
                    "version": version,
                    "envelope": envelope,
                    "deleted": faults.force_deleted_flag || row.deleted,
                })
            })
            .collect();

        let (changes, next_seq, has_more) = if faults.stalled_feed {
            (Vec::new(), since, true)
        } else {
            (entries, next_seq, has_more || faults.endless_feed)
        };
        json_response(
            200,
            &serde_json::json!({
                "changes": changes,
                "next_seq": next_seq,
                "has_more": has_more,
            }),
        )
    }

    fn put_item(
        &self,
        vault_hex: &str,
        item_hex: &str,
        body: &[u8],
        if_match: Option<&str>,
        if_none_match: Option<&str>,
        faults: &Faults,
    ) -> SyncResponse {
        if !self.vault_matches(vault_hex) {
            return SyncResponse::new(404, Vec::new());
        }
        // SPEC §6.1: a mutating request with neither precondition is `428`, not a
        // guess about what the caller meant.
        if if_match.is_none() && if_none_match.is_none() {
            return SyncResponse::new(428, Vec::new());
        }
        let (Some(item_id), Some(envelope)) = (
            parse_item_id(item_hex),
            parse_json_bytes(body).as_ref().and_then(body_envelope),
        ) else {
            return SyncResponse::new(400, Vec::new());
        };

        let existing = self.with(|state| state.rows.get(&item_id).cloned());
        if faults.conflict_forever {
            let (version, held) = match existing {
                Some(row) => (row.version, row.envelope),
                None => (String::from("v0"), Some(envelope)),
            };
            let version = if faults.conflict_rotates_version {
                self.with(|state| {
                    state.next_version = state.next_version.saturating_add(1);
                    format!("v{}", state.next_version)
                })
            } else {
                version
            };
            return json_response(
                409,
                &serde_json::json!({
                    "version": version,
                    "envelope": held.as_deref().map(to_base64),
                }),
            );
        }

        match &existing {
            // A create against a row that exists is a conflict, whatever the row
            // holds.
            Some(row)
                if if_none_match.is_some()
                    || if_match.map(unquote) != Some(row.version.as_str()) =>
            {
                return json_response(
                    409,
                    &serde_json::json!({
                        "version": row.version,
                        "envelope": row.envelope.as_deref().map(to_base64),
                    }),
                );
            }
            // An update against a row that does not exist. SPEC §6.1 has no
            // envelope to return, so `version: 0` says "there is none" and the
            // client retries as a create.
            None if if_none_match.is_none() => {
                return json_response(
                    409,
                    &serde_json::json!({ "version": 0, "envelope": serde_json::Value::Null }),
                );
            }
            _ => {}
        }

        let (seq, version) = self.with(|state| {
            state.next_seq = state.next_seq.saturating_add(1);
            state.next_version = state.next_version.saturating_add(1);
            let seq = state.next_seq;
            let version = format!("v{}", state.next_version);
            state.rows.insert(
                item_id,
                Row {
                    seq,
                    version: version.clone(),
                    envelope: Some(envelope),
                    deleted: false,
                },
            );
            (seq, version)
        });
        json_response(200, &serde_json::json!({ "seq": seq, "version": version }))
    }

    /// `DELETE` reclaims the envelope and **keeps the row**, which is what the real
    /// server does (`routes/items.rs:176`) and for the reason it gives: `version`
    /// has to stay monotonic or a stale `If-Match` would eventually win.
    fn delete_item(&self, vault_hex: &str, item_hex: &str, if_match: Option<&str>) -> SyncResponse {
        if !self.vault_matches(vault_hex) {
            return SyncResponse::new(404, Vec::new());
        }
        let Some(item_id) = parse_item_id(item_hex) else {
            return SyncResponse::new(400, Vec::new());
        };
        self.with(|state| {
            let Some(row) = state.rows.get(&item_id).cloned() else {
                return SyncResponse::new(404, Vec::new());
            };
            if if_match.is_none() {
                return SyncResponse::new(428, Vec::new());
            }
            if if_match.map(unquote) != Some(row.version.as_str()) {
                return json_response(
                    409,
                    &serde_json::json!({
                        "version": row.version,
                        "envelope": row.envelope.as_deref().map(to_base64),
                    }),
                );
            }
            state.next_seq = state.next_seq.saturating_add(1);
            state.next_version = state.next_version.saturating_add(1);
            let seq = state.next_seq;
            let version = format!("v{}", state.next_version);
            state.rows.insert(
                item_id,
                Row {
                    seq,
                    version,
                    envelope: None,
                    deleted: true,
                },
            );
            SyncResponse::new(204, Vec::new())
        })
    }

    fn vault_matches(&self, vault_hex: &str) -> bool {
        self.with(|state| state.vault_id.to_hex() == vault_hex)
    }

    fn enroll_begin(&self, request: &SyncRequest) -> SyncResponse {
        let Some(body) = parse_json(request) else {
            return SyncResponse::new(400, Vec::new());
        };
        // §6.1's field name only. The client sends it first and the legacy fallback
        // is exercised against the real server, not here.
        let (Some(enroll_id), Some(payload), Some(x25519_pub)) = (
            field_id::<16>(&body, "enroll_id").map(EnrollId::from_bytes),
            field_base64(&body, "enroll_request"),
            field_fixed::<32>(&body, "x25519_pub"),
        ) else {
            return SyncResponse::new(400, Vec::new());
        };
        let created = self.with(|state| match state.enrollments.get(&enroll_id) {
            // Create-only: the id travels in a QR code, so whoever can read the QR
            // must not be able to swap the request underneath it.
            Some(_) => false,
            None => {
                state
                    .enrollments
                    .insert(enroll_id, (Some((x25519_pub, payload)), None));
                true
            }
        });
        if created {
            json_response(201, &serde_json::json!({ "expires_at": 0 }))
        } else {
            SyncResponse::new(409, Vec::new())
        }
    }

    /// `GET /v1/enroll/poll/{id}?want=request|response`, single-use per blob.
    fn enroll_poll(&self, enroll_hex: &str, want: &str) -> SyncResponse {
        let Some(enroll_id) = parse_enroll_id(enroll_hex) else {
            return SyncResponse::new(400, Vec::new());
        };
        if !matches!(want, "request" | "response") {
            return SyncResponse::new(400, Vec::new());
        }
        self.with(|state| {
            let Some(slot) = state.enrollments.get_mut(&enroll_id) else {
                return SyncResponse::new(404, Vec::new());
            };
            if want == "request" {
                // Taken, not read: SPEC §6.1 makes retrieval single-use, which is
                // why the caller has to name the blob it wants.
                return match slot.0.take() {
                    None => SyncResponse::new(404, Vec::new()),
                    Some((x25519_pub, payload)) => json_response(
                        200,
                        &serde_json::json!({
                            "ready": true,
                            "x25519_pub": crate::encoding::to_hex(&x25519_pub),
                            "enroll_request": to_base64(&payload),
                        }),
                    ),
                };
            }
            match slot.1.take() {
                None => json_response(200, &serde_json::json!({ "ready": false })),
                Some(sealed) => json_response(
                    200,
                    &serde_json::json!({
                        "ready": true,
                        "sealed_response": to_base64(&sealed),
                    }),
                ),
            }
        })
    }

    fn enroll_complete(&self, request: &SyncRequest) -> SyncResponse {
        let Some(body) = parse_json(request) else {
            return SyncResponse::new(400, Vec::new());
        };
        let (Some(enroll_id), Some(payload)) = (
            field_id::<16>(&body, "enroll_id").map(EnrollId::from_bytes),
            field_base64(&body, "sealed_response"),
        ) else {
            return SyncResponse::new(400, Vec::new());
        };
        let stored = self.with(|state| match state.enrollments.get_mut(&enroll_id) {
            None => false,
            Some(slot) if slot.1.is_some() => false,
            Some(slot) => {
                slot.1 = Some(payload);
                true
            }
        });
        if stored {
            SyncResponse::new(200, Vec::new())
        } else {
            SyncResponse::new(404, Vec::new())
        }
    }
}

/// A transport handle onto a [`MockServer`].
#[derive(Clone, Debug)]
pub struct MockTransport {
    server: MockServer,
}

impl MockTransport {
    /// The server behind this handle.
    #[must_use]
    pub const fn server(&self) -> &MockServer {
        &self.server
    }
}

impl Transport for MockTransport {
    async fn request(&self, request: SyncRequest) -> Result<SyncResponse> {
        // Synchronous on purpose. A mock that yielded would be testing the
        // executor rather than the protocol, and the protocol is what has to be
        // interruptible — which it is tested for by failing requests, not by
        // suspending them.
        self.server.serve(&request)
    }
}

// --- small helpers ----------------------------------------------------------

/// Strips one pair of surrounding quotes from a precondition header.
///
/// SPEC §6.1 writes the update precondition as `If-Match: "{version}"`, a strong
/// validator, so the quotes are the framing and not the token. The real server
/// accepts both forms (`routes/mod.rs:479`); so does this.
fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
}

fn split_query(path: &str) -> (&str, Option<&str>) {
    match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    }
}

fn query_param<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then_some(value)
    })
}

fn parse_json(request: &SyncRequest) -> Option<serde_json::Value> {
    parse_json_bytes(request.body.as_deref().unwrap_or_default())
}

fn parse_json_bytes(body: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice(body).ok()
}

fn field_id<const N: usize>(body: &serde_json::Value, field: &str) -> Option<[u8; N]> {
    let text = body.get(field)?.as_str()?;
    let mut out = [0u8; N];
    hex::decode_to_slice(text.as_bytes(), &mut out).ok()?;
    Some(out)
}

/// A fixed-width nonce, signature or key, in whichever encoding arrived.
fn field_fixed<const N: usize>(body: &serde_json::Value, field: &str) -> Option<[u8; N]> {
    crate::encoding::fixed_from_wire::<N>(body.get(field)?.as_str()?)
}

fn field_base64(body: &serde_json::Value, field: &str) -> Option<Vec<u8>> {
    crate::encoding::blob_from_wire(body.get(field)?.as_str()?)
}

fn body_envelope(body: &serde_json::Value) -> Option<Vec<u8>> {
    field_base64(body, "envelope")
}

fn parse_item_id(hex_text: &str) -> Option<ItemId> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(hex_text.as_bytes(), &mut out).ok()?;
    Some(ItemId::from_bytes(out))
}

fn parse_enroll_id(hex_text: &str) -> Option<EnrollId> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(hex_text.as_bytes(), &mut out).ok()?;
    Some(EnrollId::from_bytes(out))
}

fn json_response(status: u16, value: &serde_json::Value) -> SyncResponse {
    SyncResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: serde_json::to_vec(value).unwrap_or_default(),
    }
}
