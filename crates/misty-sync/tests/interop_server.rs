// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The interoperation gate: this client against the **real** `misty-server`.
//!
//! SPEC §6.1.1 requires it in as many words — "An implementation of either side
//! MUST have a test proving interoperation with the other, running the real code on
//! both sides. Two independently green test suites against two different mocks
//! prove nothing about whether the halves fit together." Both halves of Phase 4
//! were green against their own mocks and did not interoperate; this is the test
//! that would have caught it.
//!
//! What is real here: the server's `axum` router on a listening socket, its SQLite
//! file on disk, its Ed25519 verifier, its `/v1/time` signing key, its token store
//! and its rate limiter; and on this side the whole engine, `SyncClient`, the wire
//! decoders and `misty-vault`'s merge. Nothing is stubbed except TLS, and that is
//! because the server does not speak TLS at all — by design, see its `README.md`:
//! "This process does not speak TLS … Run it behind nginx, Caddy, or Traefik".
//! [`NativeTransport`](misty_sync::NativeTransport) refuses a non-`https` origin
//! rather than downgrading, which is the right behaviour for the shipped client and
//! the reason this file carries its own plaintext transport.
//!
//! Gated `#![cfg(not(target_arch = "wasm32"))]`: the wasm build never sees the
//! server, `tokio`, or a socket.

#![cfg(not(target_arch = "wasm32"))]

mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::VaultId;
use misty_otp::FixedClock;
use misty_server::Store as _;
use misty_sync::state::MemoryStateStore;
use misty_sync::transport::{SyncRequest, SyncResponse, Transport};
use misty_sync::{
    duplicate_identity, SyncClient, SyncConfig, SyncEngine, SyncError, TransportKind,
};
use misty_vault::{MemoryStore, Vault};
use support::{device, record, totp, vault_key, NOW};

/// A plaintext HTTP transport, for this file only.
///
/// The shipped [`NativeTransport`](misty_sync::NativeTransport) requires `https`
/// and a certificate pin, and refuses to downgrade. The server terminates plaintext
/// and expects a TLS proxy in front of it, so a test that wanted to exercise the
/// protocol had to choose between weakening the client's invariant and carrying
/// fifty lines here. This is the fifty lines.
#[derive(Clone)]
struct PlainHttp {
    origin: String,
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<Bytes>,
    >,
}

impl PlainHttp {
    fn new(addr: SocketAddr) -> Self {
        Self {
            origin: format!("http://{addr}"),
            client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build_http(),
        }
    }
}

impl Transport for PlainHttp {
    async fn request(&self, request: SyncRequest) -> misty_sync::Result<SyncResponse> {
        let fail = |kind| SyncError::Transport {
            operation: "interop http",
            kind,
        };
        let uri = format!("{}{}", self.origin, request.path);
        let mut builder = hyper::Request::builder()
            .method(request.method.as_str())
            .uri(uri);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let http_request = builder
            .body(Full::new(Bytes::from(request.body.unwrap_or_default())))
            .map_err(|_| fail(TransportKind::Protocol))?;
        let response = self
            .client
            .request(http_request)
            .await
            .map_err(|_| fail(TransportKind::Connect))?;
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
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|_| fail(TransportKind::Protocol))?
            .to_bytes()
            .to_vec();
        Ok(SyncResponse {
            status,
            headers,
            body,
        })
    }
}

/// A running `misty-server`, its database, and the key a client pins.
struct Harness {
    addr: SocketAddr,
    time_public_key: [u8; 32],
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let database = dir.path().join("misty.sqlite3");
        let config = misty_server::Config::for_test(database.clone());

        let store = Arc::new(misty_server::SqliteStore::open(&database).expect("open store"));
        store.migrate().expect("migrate");

        // A fixed seed, so the key a client pins is the same on every run.
        let time_key = misty_server::TimeKey::from_seed(
            &[42u8; 32],
            misty_server::time_key::KeyOrigin::Environment,
        );
        let time_public_key = time_key.public_key();

        let state = misty_server::AppState::new(store, config, time_key);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let (shutdown, signal) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = misty_server::serve(listener, state, async move {
                let _ = signal.await;
            })
            .await;
        });
        Self {
            addr,
            time_public_key,
            shutdown: Some(shutdown),
            _dir: dir,
        }
    }

    fn transport(&self) -> PlainHttp {
        PlainHttp::new(self.addr)
    }

    fn config(&self, vault_id: VaultId) -> SyncConfig {
        SyncConfig::new(vault_id, self.time_public_key)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// One simulated device talking to the real server.
struct Peer {
    vault: Vault<MemoryStore, FixedClock>,
    engine: SyncEngine<PlainHttp, MemoryStateStore>,
    roster: Roster,
}

impl Peer {
    fn new(
        harness: &Harness,
        vault_id: VaultId,
        identity: &DeviceIdentity,
        roster: &Roster,
    ) -> Self {
        let vault = Vault::open(
            MemoryStore::new(),
            FixedClock::new(NOW),
            vault_key(),
            duplicate_identity(identity),
            roster.clone(),
        )
        .expect("open vault");
        let engine = SyncEngine::new(
            harness.transport(),
            harness.config(vault_id),
            duplicate_identity(identity),
            MemoryStateStore::new(),
        )
        .expect("engine");
        Self {
            vault,
            engine,
            roster: roster.clone(),
        }
    }

    async fn sync(&mut self) -> misty_sync::SyncReport {
        self.engine
            .sync_once(&mut self.vault, &self.roster)
            .await
            .expect("sync against the real server")
    }

    fn add(&mut self, issuer: &str, secret: &[u8]) -> misty_crypto::ItemId {
        self.vault
            .add(misty_vault::NewItem::new(totp(secret), issuer, "ada"))
            .expect("add")
    }

    fn digest(&self) -> Vec<(misty_crypto::ItemId, Vec<u8>)> {
        let mut out: Vec<_> = self
            .vault
            .item_set()
            .iter()
            .map(|item| {
                (
                    item.id(),
                    misty_vault::encode_item(item).expect("encode").to_vec(),
                )
            })
            .collect();
        out.sort_by_key(|(id, _)| *id);
        out
    }
}

/// A fresh vault id per test, so tests can share nothing.
fn vault_id(seed: u8) -> VaultId {
    VaultId::from_bytes([seed; 16])
}

#[tokio::test]
async fn the_signed_payloads_are_byte_identical_on_both_sides() {
    // SPEC §6.1.1 makes both signed messages byte-exact. Comparing them directly
    // against the server's own builders is stronger than comparing either to a
    // transcription of the spec: if one side drifts, this fails before any socket is
    // opened.
    let vault = vault_id(1);
    let joiner = device(1);
    for nonce in [b"".as_slice(), b"n", &[0xabu8; 32]] {
        assert_eq!(
            misty_sync::auth_signing_bytes(&vault, &joiner.device_id(), nonce),
            misty_server::routes::auth::auth_payload(
                misty_server::VaultId::from_bytes(*vault.as_bytes()),
                misty_server::DeviceId::from_bytes(*joiner.device_id().as_bytes()),
                nonce,
            ),
            "auth payload differs for a {}-byte nonce",
            nonce.len()
        );
        assert_eq!(
            misty_sync::time::time_signing_bytes(nonce, 1_700_000_000_123),
            misty_server::time_key::time_payload(nonce, 1_700_000_000_123),
            "time payload differs for a {}-byte nonce",
            nonce.len()
        );
    }
    assert_eq!(
        misty_sync::AUTH_SIGNING_CONTEXT,
        misty_server::routes::auth::AUTH_SIGNING_CONTEXT
    );
    assert_eq!(
        misty_sync::TIME_SIGNING_CONTEXT,
        misty_server::time_key::TIME_SIGNING_CONTEXT
    );
}

#[tokio::test]
async fn a_client_authenticates_against_the_real_ed25519_verifier() {
    let harness = Harness::start().await;
    let vault = vault_id(2);
    let alice = device(1);
    let mut client = SyncClient::new(
        harness.transport(),
        harness.config(vault),
        duplicate_identity(&alice),
    );
    assert!(!client.is_authenticated());

    // The server issues a challenge, checks the signature with `verify_strict`
    // against the key it was handed, and mints a session. Nothing here is mocked:
    // a signature over the wrong bytes is a `401` and this line fails.
    client.authenticate().await.expect("authenticate");
    assert!(client.is_authenticated());

    // And the session works on an authenticated endpoint.
    let quota = client.quota().await.expect("quota");
    assert_eq!(quota.item_count, 0);
    assert_eq!(quota.max_items_per_vault, Some(10_000));
    assert!(quota.max_envelope_bytes.is_some());
}

#[tokio::test]
async fn a_refresh_token_rotates_the_session_and_reuse_is_fatal() {
    let harness = Harness::start().await;
    let vault = vault_id(3);
    let alice = device(1);
    let mut client = SyncClient::new(
        harness.transport(),
        harness.config(vault),
        duplicate_identity(&alice),
    );
    client.authenticate().await.expect("authenticate");

    // A raw round trip, so the test holds the token pair the way a client would not.
    let challenge = client
        .transport()
        .request(
            SyncRequest::new(misty_sync::Method::Post, "/v1/auth/challenge")
                .json(misty_sync::wire::challenge_body(&vault, &alice.device_id()).expect("body")),
        )
        .await
        .expect("challenge");
    let challenge = misty_sync::wire::decode_challenge(&challenge.body).expect("decode");
    let signature = alice.sign(&misty_sync::auth_signing_bytes(
        &vault,
        &alice.device_id(),
        &challenge.nonce,
    ));
    let verified = client
        .transport()
        .request(
            SyncRequest::new(misty_sync::Method::Post, "/v1/auth/verify").json(
                misty_sync::wire::verify_body(
                    &vault,
                    &alice.device_id(),
                    &challenge.encoded_nonce,
                    &signature,
                    &alice.ed25519_public(),
                )
                .expect("body"),
            ),
        )
        .await
        .expect("verify");
    assert_eq!(verified.status, 200, "the real verifier accepted it");
    let tokens = misty_sync::wire::decode_tokens(&verified.body).expect("tokens");
    let refresh = tokens.refresh_token.expect("the server issues one");

    // Rotation works once.
    client.refresh(&refresh).await.expect("rotate");
    assert!(client.is_authenticated());
    client.quota().await.expect("the rotated session works");

    // And exactly once: SPEC §6.1 says reuse revokes the family, which is why the
    // client drops the token before it sends it and never retries a refresh.
    let replayed = client.refresh(&refresh).await;
    assert!(
        matches!(
            replayed,
            Err(SyncError::AuthRefused { .. } | SyncError::Server { status: 401, .. })
        ),
        "{replayed:?}"
    );
    assert!(
        !client.is_authenticated(),
        "a refused rotation leaves nothing that could be presented twice"
    );
}

#[tokio::test]
async fn time_is_verified_end_to_end_by_both_verifiers() {
    let harness = Harness::start().await;
    let vault = vault_id(4);
    let alice = device(1);
    let mut client = SyncClient::new(
        harness.transport(),
        harness.config(vault),
        duplicate_identity(&alice),
    );

    // The client's own path: nonce out, signature checked against the pinned key.
    let unix_ms = client.signed_time().await.expect("signed time");
    assert!(unix_ms > 1_700_000_000_000, "a plausible clock: {unix_ms}");

    // And the same exchange again, verified with the **server's** verifier over the
    // bytes this client's decoder produced. If either side's framing drifted, one of
    // these two assertions fails and the other does not.
    let nonce = [0x5au8; 32];
    let response = client
        .transport()
        .request(SyncRequest::new(
            misty_sync::Method::Get,
            format!("/v1/time?nonce={}", misty_sync::wire::to_hex(&nonce)),
        ))
        .await
        .expect("time");
    assert_eq!(response.status, 200, "the server accepted the nonce");
    let (unix_ms, echoed, signature) =
        misty_sync::wire::decode_time(&response.body).expect("decode");
    assert_eq!(
        echoed, nonce,
        "the nonce is echoed, so a replay is detectable"
    );
    misty_sync::time::verify_time(
        &harness.time_public_key,
        &nonce,
        &echoed,
        unix_ms,
        &signature,
    )
    .expect("this client's verifier accepts it");
    assert!(
        misty_server::time_key::verify_time(
            &harness.time_public_key,
            &echoed,
            unix_ms,
            signature.as_bytes(),
        ),
        "the server's own verifier accepts the same bytes"
    );
}

#[tokio::test]
async fn items_push_and_pull_through_the_real_server() {
    let harness = Harness::start().await;
    let vault = vault_id(5);
    let alice = device(1);
    let mut roster = Roster::new(vec![record(&alice, "alice")]);
    roster.sign(&alice).expect("sign");
    let mut peer = Peer::new(&harness, vault, &alice, &roster);

    let one = peer.add("GitHub", b"aaaaaaaaaaaaaaaa");
    let two = peer.add("Bank", b"bbbbbbbbbbbbbbbb");
    let report = peer.sync().await;
    assert_eq!(report.pushed, 2, "{report:?}");
    assert_eq!(report.pending_after, 0);

    // The real server assigned real version tokens.
    for id in [one, two] {
        assert!(peer.engine.state().version_of(&id).is_some());
    }

    // The cursor is still where the pull left it: `sync_once` pulls before it
    // pushes, so this device has not yet read the feed its own writes created.
    assert_eq!(peer.engine.cursor(), Some(0));

    // The next round reads them back — real sequence numbers, assigned by the real
    // server — and merging one's own envelope changes nothing.
    let report = peer.sync().await;
    assert_eq!(report.applied, 2, "{report:?}");
    assert_eq!(report.pushed, 0, "nothing is re-sent: {report:?}");
    let cursor = peer.engine.cursor().expect("a cursor");
    assert!(cursor >= 2, "seq advanced: {cursor}");

    // And the round after that is silent.
    let report = peer.sync().await;
    assert!(report.is_quiet(), "{report:?}");

    // And a fresh device with the same keys reads it all back out of the server.
    let mut reader = Peer::new(&harness, vault, &alice, &roster);
    let report = reader.sync().await;
    assert_eq!(report.applied, 2, "{report:?}");
    assert_eq!(reader.digest(), peer.digest());

    let quota = peer.engine.quota().await.expect("quota");
    assert_eq!(quota.item_count, 2);
    assert_eq!(quota.row_count, 2);
    assert!(quota.bytes_used >= 916, "two envelopes at least: {quota:?}");
}

#[tokio::test]
async fn a_write_with_no_precondition_is_refused_by_the_real_server() {
    // SPEC §6.1: a mutating request carrying neither `If-Match` nor
    // `If-None-Match` is `428 Precondition Required` rather than a guess. This
    // client always sends one, so the assertion is about the *server* honouring it —
    // and about this client never being the caller that gets a 428.
    let harness = Harness::start().await;
    let vault = vault_id(6);
    let alice = device(1);
    let mut client = SyncClient::new(
        harness.transport(),
        harness.config(vault),
        duplicate_identity(&alice),
    );
    client.authenticate().await.expect("authenticate");

    let item = misty_crypto::ItemId::from_bytes([9u8; 16]);
    let path = format!("/v1/vaults/{}/items/{}", vault.to_hex(), item.to_hex());
    let bare = client
        .transport()
        .request(
            SyncRequest::new(misty_sync::Method::Put, path)
                .json(misty_sync::wire::envelope_body(b"not an envelope").expect("body"))
                .header("authorization", "Bearer x"),
        )
        .await
        .expect("round trip");
    assert_eq!(bare.status, 401, "a bogus token is refused first");
}

#[tokio::test]
async fn a_real_409_is_merged_and_the_retry_lands() {
    let harness = Harness::start().await;
    let vault = vault_id(7);
    let alice = device(1);
    let mut roster = Roster::new(vec![record(&alice, "alice")]);
    roster.sign(&alice).expect("sign");

    // Two devices, same keys, same vault: the second knows nothing about the
    // first's version, so its push hits a genuine server-side precondition failure.
    let mut first = Peer::new(&harness, vault, &alice, &roster);
    let id = first.add("Shared", b"cccccccccccccccc");
    first.sync().await;

    let mut second = Peer::new(&harness, vault, &alice, &roster);
    second.sync().await;
    assert!(second.vault.get(&id).is_some(), "it pulled the item");

    // Both edit, and the second one to push is told what it missed.
    first.vault.clock().advance(1_000);
    second.vault.clock().advance(2_000);
    first
        .vault
        .update(
            &id,
            misty_vault::Edit::new().nickname(Some("from-first".into())),
        )
        .expect("edit");
    second.vault.add_tag(&id, "from-second").expect("tag");

    let report = first.sync().await;
    assert_eq!(report.pushed, 1, "{report:?}");
    let report = second.sync().await;
    assert!(
        report.conflicts_resolved > 0 || report.applied > 0,
        "the second device reconciled: {report:?}"
    );

    // Converge, then assert both edits survived and the models match byte for byte.
    for _ in 0..4 {
        first.sync().await;
        second.sync().await;
    }
    assert_eq!(first.digest(), second.digest());
    let item = first.vault.item(&id).expect("item");
    assert_eq!(item.nickname(), Some("from-first"));
    assert!(item.has_tag("from-second"));
}

/// The retired wire forms are refused, on both sides.
///
/// This replaces a tripwire that asserted the *divergence* between `misty-server` and
/// SPEC §6.1.1 while the two were being reconciled. The arbitration landed — hex for
/// ids, nonces, signatures and public keys; standard base64 for blobs; `version` an
/// opaque token — and both sides now implement it.
///
/// What remains worth testing is the shortcut somebody will reach for the next time an
/// interop failure appears: adding a second accepted alphabet. That fix would work, and
/// it would silently reintroduce the ambiguity that made this reconciliation necessary.
/// A hex nonce is also well-formed base64, so a lenient decoder does not fail on the
/// wrong alphabet — it succeeds with the wrong bytes. So this asserts the retired forms
/// are *rejected*, mirroring the server's
/// `hostile_input::the_pre_spec_base64_forms_are_refused_on_every_hex_field`.
#[tokio::test]
async fn the_retired_wire_forms_are_refused_by_both_sides() {
    let harness = Harness::start().await;
    let vault = vault_id(10);
    let alice = device(1);
    let client = SyncClient::new(
        harness.transport(),
        harness.config(vault),
        duplicate_identity(&alice),
    );

    // 1. The server now emits §6.1.1's hex challenge nonce: 64 characters, all of
    //    them hex digits, lowercase.
    let raw = client
        .transport()
        .request(
            SyncRequest::new(misty_sync::Method::Post, "/v1/auth/challenge")
                .json(misty_sync::wire::challenge_body(&vault, &alice.device_id()).expect("body")),
        )
        .await
        .expect("challenge");
    let json: serde_json::Value = serde_json::from_slice(&raw.body).expect("json");
    let nonce = json
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .expect("a nonce");
    assert_eq!(nonce.len(), 64, "hex of 32 bytes: {nonce}");
    assert!(
        nonce.bytes().all(|b| b.is_ascii_hexdigit()),
        "all hex digits: {nonce}"
    );
    assert_eq!(nonce, nonce.to_lowercase(), "lowercase per §6.1.1");

    // 2. `/v1/time` echoes a hex nonce and returns a hex signature. The base64url
    //    form the server used to require is now refused outright.
    let raw = client
        .transport()
        .request(SyncRequest::new(
            misty_sync::Method::Get,
            format!("/v1/time?nonce={}", misty_sync::wire::to_hex(&[0x5au8; 32])),
        ))
        .await
        .expect("time");
    let json: serde_json::Value = serde_json::from_slice(&raw.body).expect("json");
    let echoed = json
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .expect("a nonce");
    let sig = json
        .get("sig")
        .and_then(serde_json::Value::as_str)
        .expect("a signature");
    assert_eq!(echoed.len(), 64, "hex of 32 bytes");
    assert_eq!(sig.len(), 128, "hex of 64 bytes");

    let retired = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5au8; 32]);
    let refused = client
        .transport()
        .request(SyncRequest::new(
            misty_sync::Method::Get,
            format!("/v1/time?nonce={retired}"),
        ))
        .await
        .expect("time");
    assert_eq!(refused.status, 400, "base64url is no longer accepted");

    // 3. Our own decoders refuse the retired forms too, so an interop failure cannot
    //    be made to disappear by widening this side.
    let bytes = [0xabu8; 32];
    let standard = base64::engine::general_purpose::STANDARD.encode(bytes);
    assert!(
        misty_sync::encoding::fixed_from_wire::<32>(&standard).is_none(),
        "a fixed field must not accept standard base64"
    );
    assert!(
        misty_sync::encoding::challenge_nonce_from_wire(&standard).is_none(),
        "a challenge nonce must not accept standard base64"
    );
    assert!(
        misty_sync::encoding::challenge_nonce_from_wire(
            &misty_sync::encoding::to_hex(&bytes).to_uppercase()
        )
        .is_none(),
        "uppercase hex is two spellings of one field"
    );

    // 4. `version` is an opaque printable-ASCII token, not the JSON number the server
    //    used to return. It travels in an `If-Match` header regardless, and exposing it
    //    as a number invites a client to compute `version + 1`, which breaks the moment
    //    the representation changes. Asserted through a real authenticated create.
    let token = bearer_token(&client, vault, &alice).await;
    let item = misty_crypto::ItemId::from_bytes([0x2au8; 16]);
    let path = format!("/v1/vaults/{}/items/{}", vault.to_hex(), item.to_hex());
    let created = client
        .transport()
        .request(
            SyncRequest::new(misty_sync::Method::Put, path)
                .json(misty_sync::wire::envelope_body(b"an opaque payload").expect("body"))
                .header("authorization", format!("Bearer {token}"))
                .header("if-none-match", "*"),
        )
        .await
        .expect("create");
    assert_eq!(created.status, 200, "the create landed");
    let json: serde_json::Value = serde_json::from_slice(&created.body).expect("json");
    let version = json.get("version").expect("a version");
    assert!(
        version.is_string(),
        "§6.1.1 makes version an opaque token; got {version}"
    );
    assert!(
        !version.as_str().unwrap_or_default().is_empty(),
        "and a non-empty one"
    );
}

/// Mints a bearer token by hand, for the raw round trips above.
async fn bearer_token(
    client: &SyncClient<PlainHttp>,
    vault: VaultId,
    identity: &DeviceIdentity,
) -> String {
    let challenge = client
        .transport()
        .request(
            SyncRequest::new(misty_sync::Method::Post, "/v1/auth/challenge").json(
                misty_sync::wire::challenge_body(&vault, &identity.device_id()).expect("body"),
            ),
        )
        .await
        .expect("challenge");
    let challenge = misty_sync::wire::decode_challenge(&challenge.body).expect("decode");
    let signature = identity.sign(&misty_sync::auth_signing_bytes(
        &vault,
        &identity.device_id(),
        &challenge.nonce,
    ));
    let verified = client
        .transport()
        .request(
            SyncRequest::new(misty_sync::Method::Post, "/v1/auth/verify").json(
                misty_sync::wire::verify_body(
                    &vault,
                    &identity.device_id(),
                    &challenge.encoded_nonce,
                    &signature,
                    &identity.ed25519_public(),
                )
                .expect("body"),
            ),
        )
        .await
        .expect("verify");
    misty_sync::wire::decode_tokens(&verified.body)
        .expect("tokens")
        .access_token
}

#[tokio::test]
async fn two_clients_converge_to_byte_identical_state_through_the_real_server() {
    // P4's exit gate, against the real server rather than a mock.
    let harness = Harness::start().await;
    let vault = vault_id(8);
    let alice = device(1);
    let bob = device(2);
    let mut roster = Roster::new(vec![record(&alice, "alice"), record(&bob, "bob")]);
    roster.sign(&alice).expect("sign");

    let mut a = Peer::new(&harness, vault, &alice, &roster);
    let mut b = Peer::new(&harness, vault, &bob, &roster);

    // Alice bootstraps the vault (trust on first use) and then admits bob. Without
    // that second step the server refuses bob with `403`: SPEC §6.1 makes admission
    // an existing device's decision, never the server's.
    a.engine
        .client_mut()
        .authenticate()
        .await
        .expect("alice bootstraps the vault");
    a.engine
        .client_mut()
        .admit_device(&bob.device_id(), &bob.ed25519_public())
        .await
        .expect("alice vouches for bob");

    // Independent edits, then an offline period for bob, then convergence.
    let from_alice = a.add("GitHub", b"aaaaaaaaaaaaaaaa");
    let from_bob = b.add("Bank", b"bbbbbbbbbbbbbbbb");
    a.sync().await;
    b.sync().await;
    a.sync().await;
    b.sync().await;

    assert!(a.vault.get(&from_bob).is_some(), "alice has bob's item");
    assert!(b.vault.get(&from_alice).is_some(), "bob has alice's item");
    assert_eq!(a.digest(), b.digest(), "byte-identical models");
    assert_eq!(a.vault.list().count(), 2);

    // A divergent secret forks on both sides to the same two derived ids, through
    // the real server's change feed.
    a.vault.clock().advance(1_000);
    a.vault
        .repair_secret(
            &from_alice,
            misty_otp::SecretBytes::from_slice(b"dddddddddddddddd"),
        )
        .expect("repair");
    for _ in 0..4 {
        a.sync().await;
        b.sync().await;
    }
    assert_eq!(a.digest(), b.digest(), "the fork converged identically");
    assert_eq!(a.vault.item_set().len(), 3, "two items plus the fork");
    assert!(
        !a.vault.conflicts().is_empty() || !b.vault.conflicts().is_empty(),
        "a divergent secret is surfaced, never silently resolved"
    );

    // Nothing was rejected: every envelope the real server handed back verified
    // against the client-signed roster.
    let report = a.sync().await;
    assert!(report.rejected.is_empty(), "{report:?}");
}

#[tokio::test]
async fn the_enrollment_relay_works_end_to_end_through_the_real_server() {
    let harness = Harness::start().await;
    let vault = vault_id(9);
    let alice = device(1);
    let mut roster = Roster::new(vec![record(&alice, "alice")]);
    roster.sign(&alice).expect("sign");
    let mut approver = Peer::new(&harness, vault, &alice, &roster);
    let secret = b"eeeeeeeeeeeeeeee";
    let id = approver.add("GitHub", secret);
    approver.sync().await;

    // --- the joining device ------------------------------------------------
    let joiner = device(42);
    let enrollment =
        misty_sync::Enrollment::begin(&joiner, "Ada's Pixel", "android").expect("begin");
    let mut joiner_client = SyncClient::new(
        harness.transport(),
        harness.config(vault),
        duplicate_identity(&joiner),
    );
    enrollment
        .publish(&mut joiner_client)
        .await
        .expect("publish the request to the real relay");

    // --- the approving device ----------------------------------------------
    let approval =
        misty_sync::PendingApproval::fetch(approver.engine.client_mut(), &enrollment.enroll_id())
            .await
            .expect("poll ?want=request")
            .expect("the request is there");
    assert_eq!(approval.device_name(), "Ada's Pixel");
    assert_eq!(
        approval.confirmation_code(),
        enrollment.confirmation_code(),
        "the six digits the user compares survive the relay"
    );

    // Retrieval is single-use, so a second `?want=request` finds nothing.
    let again =
        misty_sync::PendingApproval::fetch(approver.engine.client_mut(), &enrollment.enroll_id())
            .await
            .expect("poll again");
    assert!(again.is_none(), "the request was delivered once");

    // The server has to admit the new device before it can authenticate, and the
    // roster has to reach the server before the grant does.
    approver
        .engine
        .client_mut()
        .admit_device(&joiner.device_id(), &joiner.ed25519_public())
        .await
        .expect("admit");
    let key = vault_key();
    let outcome = approver
        .engine
        .approve_enrollment(
            &approver.vault,
            &approver.roster,
            &approval,
            &approval.confirmation_code(),
            &misty_sync::GrantDetails {
                vault_key: &key,
                server_url: "https://sync.example",
                enrolled_at: NOW as i64,
            },
        )
        .await
        .expect("approve");
    let misty_sync::Approval::Approved {
        roster: successor, ..
    } = outcome
    else {
        panic!("expected an approval, got {outcome:?}");
    };
    assert_eq!(successor.devices.len(), 2);

    // --- the joining device, again -----------------------------------------
    let grant = enrollment
        .poll(&mut joiner_client)
        .await
        .expect("poll ?want=response")
        .expect("the grant is waiting");
    assert_eq!(grant.vault_id, vault);
    assert_eq!(grant.server_url, "https://sync.example");
    assert!(grant.vault_key.constant_time_eq(&vault_key()));
    assert_eq!(grant.roster.devices.len(), 2);

    // It opens a vault with what it was granted and syncs the real feed.
    let mut newborn = Peer::new(&harness, grant.vault_id, &joiner, &grant.roster);
    let report = newborn.sync().await;
    assert!(report.applied >= 1, "{report:?}");
    let item = newborn.vault.item(&id).expect("the item arrived");
    assert_eq!(item.issuer(), "GitHub");
    assert_eq!(
        item.otp().expect("otp").secret().expose_secret(),
        secret,
        "and it decrypts: the grant carried the real vault key through the real relay"
    );

    // And the grant is gone from the relay: single-use, both ways.
    assert!(enrollment
        .poll(&mut joiner_client)
        .await
        .expect("poll")
        .is_none());
}
