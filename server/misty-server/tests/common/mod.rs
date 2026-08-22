// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared test harness: a real server, a real SQLite file, and a raw HTTP client.
//!
//! Every integration test here talks to a listening socket. Nothing is mocked and
//! the router is never driven directly, because half the properties being proved
//! are about the HTTP layer itself — a declared `Content-Length`, a path that
//! never reaches a route, a header that is not valid ASCII. A `oneshot` against an
//! in-process `Router` cannot express any of those.
//!
//! The client is hand-rolled over `TcpStream` for the same reason: a well-behaved
//! HTTP library refuses to send most of what `hostile_input.rs` needs to send.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use misty_crypto::envelope::{self, EnvelopeKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::keys::VaultKey;
use misty_crypto::{derive, ItemId as CryptoItemId};
use misty_server::routes::auth::auth_payload;
use misty_server::store::Store;
use misty_server::time_key::KeyOrigin;
use misty_server::{AppState, Config, DeviceId, SqliteStore, TimeKey, VaultId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Nothing in this suite should take a second; a hang is a bug, not slowness.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A running server plus the pieces a test needs to poke at it.
pub struct Harness {
    /// Where it listens.
    pub addr: SocketAddr,
    /// The `/v1/time` public key, as a client would have pinned it.
    pub time_public_key: [u8; 32],
    /// The store, so a test can act with the operator's full powers.
    pub store: Arc<SqliteStore>,
    /// The database file, so a test can assert it exists and is a real file.
    pub database: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    _dir: tempfile::TempDir,
}

impl Harness {
    /// Starts a server with test defaults: real file, ephemeral port, limits
    /// high enough not to interfere.
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// Starts a server, letting the caller adjust the configuration first.
    pub async fn start_with(tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let database = dir.path().join("misty.sqlite3");
        let mut config = Config::for_test(database.clone());
        tweak(&mut config);

        let store = Arc::new(SqliteStore::open(&database).expect("open store"));
        store.migrate().expect("migrate");

        // A fixed seed so a test can assert against a stable public key.
        let time_key = TimeKey::from_seed(&[42u8; 32], KeyOrigin::Environment);
        let time_public_key = time_key.public_key();

        let state = AppState::new(store.clone(), config, time_key);
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
            store,
            database,
            shutdown: Some(shutdown),
            _dir: dir,
        }
    }

    /// Sends a request built from parts.
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Reply {
        let mut raw = Vec::new();
        raw.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
        raw.extend_from_slice(b"Host: misty.test\r\nConnection: close\r\n");
        for (name, value) in headers {
            raw.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        if let Some(body) = body {
            raw.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        if let Some(body) = body {
            raw.extend_from_slice(body);
        }
        self.send_raw(&raw).await
    }

    /// Sends a JSON request body with the right `Content-Type`.
    pub async fn json(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &serde_json::Value,
    ) -> Reply {
        let encoded = serde_json::to_vec(body).expect("encode");
        let mut all = vec![("Content-Type", "application/json")];
        all.extend_from_slice(headers);
        self.send(method, path, &all, Some(&encoded)).await
    }

    /// Sends bytes verbatim. The only way to express a hostile request line.
    ///
    /// Panics if the peer resets without answering at all; use
    /// [`send_raw_tolerating_reset`](Self::send_raw_tolerating_reset) where that is a
    /// legitimate outcome.
    pub async fn send_raw(&self, bytes: &[u8]) -> Reply {
        self.exchange(bytes)
            .await
            .expect("the server answered rather than resetting the connection")
    }

    /// Like [`send_raw`](Self::send_raw), but returns `None` when the peer reset the
    /// connection instead of answering.
    ///
    /// A malformed request line legitimately provokes that, and whether the response
    /// survives the reset is platform-dependent (see [`read_until_close`]). A test
    /// asserting "this is refused and the server survives" must accept both.
    pub async fn send_raw_tolerating_reset(&self, bytes: &[u8]) -> Option<Reply> {
        self.exchange(bytes).await
    }

    /// One request/response over a fresh connection. `None` means the peer reset before
    /// a single byte of response arrived.
    async fn exchange(&self, bytes: &[u8]) -> Option<Reply> {
        let work = async {
            let mut stream = TcpStream::connect(self.addr).await.expect("connect");
            // The write can fail outright when the server has already rejected the
            // request line and closed: BSD answers a write to a reset socket with
            // EPIPE/ECONNRESET rather than swallowing it.
            match stream.write_all(bytes).await {
                Ok(()) => {}
                Err(error) if is_peer_gone(&error) => return Vec::new(),
                Err(error) => panic!("write: {error:?}"),
            }
            let _ = stream.flush().await;
            read_until_close(&mut stream).await
        };
        let buffer = tokio::time::timeout(IO_TIMEOUT, work)
            .await
            .expect("server answered within the timeout");
        (!buffer.is_empty()).then(|| Reply::parse(&buffer))
    }
}

/// Whether an IO error means "the peer is gone", as opposed to a real failure.
fn is_peer_gone(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    )
}

/// Reads until the stream ends, treating a peer **reset** as an ordinary end of stream.
///
/// This is a platform difference, not a flake, and it is worth stating because it cost a
/// red CI run to find. `Connection: close` means the server closes once it has answered,
/// so reading to EOF is exactly the response and needs no framing logic — on Linux. But
/// several of these tests make the server answer *without* consuming the request: a
/// declared four-gigabyte body is refused from the header, an over-limit chunked body is
/// refused while it streams, a malformed request line is refused by hyper before any
/// route runs. Closing a socket whose receive queue still holds unread data makes a BSD
/// kernel send RST instead of FIN, so on macOS the client's next `read` returns
/// `ECONNRESET` (errno 54) — sometimes after the response bytes have already been
/// delivered, sometimes instead of them. Linux delivers the buffered response and then
/// EOF, which is why `read_to_end(..).expect("read")` passed for the whole of P4 and
/// failed the first time the suite ran on a macOS runner.
///
/// Treating the reset as end-of-stream keeps what did arrive. Whether *anything* arrived
/// is then the caller's business.
async fn read_until_close(stream: &mut TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            Err(error) if is_peer_gone(&error) => break,
            Err(error) => panic!("read: {error:?}"),
        }
    }
    buffer
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// A parsed HTTP response.
#[derive(Debug)]
pub struct Reply {
    /// Status code.
    pub status: u16,
    /// Headers, lowercased names, in wire order.
    pub headers: Vec<(String, String)>,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl Reply {
    fn parse(bytes: &[u8]) -> Self {
        let split = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap_or_else(|| {
                panic!(
                    "no header terminator in {:?}",
                    String::from_utf8_lossy(bytes)
                )
            });
        let head = String::from_utf8_lossy(&bytes[..split]).into_owned();
        let body = bytes[split + 4..].to_vec();

        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let status = status_line
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no status in {status_line:?}"));
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();

        Self {
            status,
            headers,
            body,
        }
    }

    /// The body as JSON. Panics if it is not JSON, which is itself an assertion:
    /// every response on this surface is JSON.
    pub fn value(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "body is not JSON ({error}): {:?}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    /// The `error` field, for a failed request.
    pub fn error_code(&self) -> String {
        self.value()["error"]
            .as_str()
            .unwrap_or_else(|| panic!("no error code in {:?}", self.value()))
            .to_owned()
    }

    /// One header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Asserts the status, printing the body when it does not match — otherwise
    /// a failure says `404 != 200` and nothing about why.
    pub fn expect_status(&self, expected: u16) -> &Self {
        assert_eq!(
            self.status,
            expected,
            "body was {:?}",
            String::from_utf8_lossy(&self.body)
        );
        self
    }
}

/// A client device: its real Ed25519/X25519 identity plus its server session.
pub struct Client {
    /// The real cryptographic identity, from `misty-crypto`.
    pub identity: DeviceIdentity,
    /// The vault it belongs to.
    pub vault: VaultId,
    /// Server-side device id, matching `identity.device_id()`.
    pub device: DeviceId,
    /// Current access token.
    pub access: String,
    /// Current refresh token.
    pub refresh: String,
}

impl Client {
    /// The `Authorization` header value.
    pub fn bearer(&self) -> String {
        format!("Bearer {}", self.access)
    }
}

/// Bootstraps a brand-new vault with a brand-new first device.
pub async fn bootstrap(harness: &Harness) -> Client {
    let identity = DeviceIdentity::generate().expect("identity");
    let vault = VaultId::from_bytes(random16());
    join(harness, vault, identity, &[]).await
}

/// Authenticates `identity` against `vault`, presenting its public key.
pub async fn join(
    harness: &Harness,
    vault: VaultId,
    identity: DeviceIdentity,
    headers: &[(&str, &str)],
) -> Client {
    let device = DeviceId::from_bytes(*identity.device_id().as_bytes());
    let tokens = authenticate(harness, vault, device, &identity, true, headers).await;
    tokens.expect_status(200);
    let value = tokens.value();
    Client {
        identity,
        vault,
        device,
        access: value["access_token"].as_str().expect("access").to_owned(),
        refresh: value["refresh_token"].as_str().expect("refresh").to_owned(),
    }
}

/// Has `sponsor` vouch for `newcomer` via `POST /v1/vaults/{vid}/devices`.
pub async fn admit(harness: &Harness, sponsor: &Client, newcomer: &DeviceIdentity) -> Reply {
    harness
        .json(
            "POST",
            &format!("/v1/vaults/{}/devices", sponsor.vault.to_hex()),
            &[("Authorization", &sponsor.bearer())],
            &serde_json::json!({
                "device_id": hex::encode(newcomer.device_id().as_bytes()),
                "ed25519_pub": hex::encode(newcomer.ed25519_public()),
            }),
        )
        .await
}

/// Admits a second device into `sponsor`'s vault and authenticates it.
pub async fn join_admitted(
    harness: &Harness,
    sponsor: &Client,
    identity: DeviceIdentity,
) -> Client {
    admit(harness, sponsor, &identity).await.expect_status(201);
    join(harness, sponsor.vault, identity, &[]).await
}

/// Runs challenge then verify, returning the raw verify reply.
pub async fn authenticate(
    harness: &Harness,
    vault: VaultId,
    device: DeviceId,
    identity: &DeviceIdentity,
    send_public_key: bool,
    headers: &[(&str, &str)],
) -> Reply {
    let nonce = challenge(harness, vault, device).await;
    verify(
        harness,
        vault,
        device,
        identity,
        &nonce,
        send_public_key,
        headers,
    )
    .await
}

/// Asks for a challenge and returns the raw nonce bytes.
pub async fn challenge(harness: &Harness, vault: VaultId, device: DeviceId) -> Vec<u8> {
    let reply = harness
        .json(
            "POST",
            "/v1/auth/challenge",
            &[],
            &serde_json::json!({ "vault_id": vault.to_hex(), "device_id": device.to_hex() }),
        )
        .await;
    reply.expect_status(200);
    // SPEC §6.1.1: nonces are lowercase hex.
    hex_decode(reply.value()["nonce"].as_str().expect("nonce"))
}

/// Signs a challenge and posts it.
pub async fn verify(
    harness: &Harness,
    vault: VaultId,
    device: DeviceId,
    identity: &DeviceIdentity,
    nonce: &[u8],
    send_public_key: bool,
    headers: &[(&str, &str)],
) -> Reply {
    let signature = identity.sign(&auth_payload(vault, device, nonce));
    let mut body = serde_json::json!({
        "vault_id": vault.to_hex(),
        "device_id": device.to_hex(),
        "nonce": hex::encode(nonce),
        "sig": hex::encode(signature.as_bytes()),
    });
    if send_public_key {
        body["ed25519_pub"] = serde_json::Value::String(hex::encode(identity.ed25519_public()));
    }
    harness
        .json("POST", "/v1/auth/verify", headers, &body)
        .await
}

/// A vault's client-side cryptographic state: the key, the epoch, the roster.
///
/// Tests use this to build *real* envelopes, so "a client rejects this" is a fact
/// about the shipping crypto core rather than a property of a mock.
pub struct Vault {
    /// The vault key. Never leaves the test process, exactly as on a device.
    pub key: VaultKey,
    /// Which epoch items are sealed under.
    pub epoch: u32,
    /// The client-signed device roster (SPEC §6.2) — the only source of trust.
    pub roster: Roster,
}

impl Vault {
    /// A fresh vault whose roster contains exactly `owner`, signed by it.
    pub fn new(owner: &DeviceIdentity) -> Self {
        let mut roster = Roster::new(vec![owner
            .record("test device", "linux", 0, None)
            .expect("record")]);
        roster.sign(owner).expect("sign roster");
        Self {
            key: VaultKey::generate().expect("vault key"),
            epoch: 0,
            roster,
        }
    }

    /// Seals `payload` as an item envelope signed by `signer`.
    pub fn seal(
        &self,
        item: &misty_server::ItemId,
        payload: &[u8],
        signer: &DeviceIdentity,
    ) -> Vec<u8> {
        let epoch_key = derive::epoch_key(&self.key, self.epoch).expect("epoch key");
        let item_id = CryptoItemId::from_bytes(*item.as_bytes());
        envelope::seal(
            EnvelopeKind::Item,
            self.epoch,
            &item_id,
            payload,
            &epoch_key,
            signer,
        )
        .expect("seal")
    }

    /// Opens an envelope exactly as a client would: signature and roster
    /// membership first, decryption only if both hold (SPEC §2.4).
    pub fn open(
        &self,
        item: &misty_server::ItemId,
        sealed: &[u8],
    ) -> Result<Vec<u8>, misty_crypto::Error> {
        let epoch_key = derive::epoch_key(&self.key, self.epoch)?;
        let item_id = CryptoItemId::from_bytes(*item.as_bytes());
        envelope::open(sealed, &item_id, &epoch_key, &self.roster).map(|opened| opened.to_vec())
    }
}

/// 16 random bytes, for ids a test does not care about.
pub fn random16() -> [u8; 16] {
    let mut out = [0u8; 16];
    fill_pseudo(&mut out);
    out
}

/// 32 random bytes.
pub fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    fill_pseudo(&mut out);
    out
}

fn fill_pseudo(out: &mut [u8]) {
    // Tests do not need the OS CSPRNG choke point; they need ids that do not
    // collide across a run. A counter mixed with the clock gives that with no
    // dependency and no `unsafe`.
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    let ticks = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0x1234_5678, |d| d.as_nanos() as u64);
    let mut seed = ticks ^ COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    for byte in out.iter_mut() {
        // xorshift64*: deterministic, adequate, dependency-free.
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        *byte = (seed.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8;
    }
}

/// Standard base64, as every JSON binary field on this surface uses.
pub fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decodes standard base64, panicking on malformed input.
pub fn b64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text.as_bytes())
        .unwrap_or_else(|error| panic!("not base64 ({error}): {text:?}"))
}

/// Decodes lowercase hex, as SPEC §6.1.1 requires for ids, nonces, signatures and
/// public keys.
pub fn hex_decode(text: &str) -> Vec<u8> {
    assert!(
        text.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "§6.1.1 asks for lowercase hex; got {text:?}"
    );
    hex::decode(text).unwrap_or_else(|error| panic!("not hex ({error}): {text:?}"))
}
