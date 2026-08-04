# Misty — Authoritative Specification

**Status:** v0.1 DRAFT. Every crate implements against this document. If code and
spec disagree, that is a bug in one of them — fix both in the same change.
On-disk and on-wire formats freeze at tag `spec-v1`; until then breaking changes
are allowed but MUST bump the relevant `*_FORMAT_VERSION` constant.

`MUST` / `SHOULD` / `MAY` are RFC 2119 keywords.

---

## 0. Settled decisions

| Area | Choice | Rationale |
|---|---|---|
| Core | Rust, `#![forbid(unsafe_code)]`, `no_std`-friendly where practical | one implementation for every platform |
| Targets | native (x86_64/aarch64 linux, windows, macos, android, ios) + `wasm32-unknown-unknown` | web app and browser extension run the same core |
| Crypto | pure-Rust (RustCrypto) | libsodium cannot cheaply target `wasm32-unknown-unknown`; a C dep would fork the core |
| UI | SvelteKit, shared by Tauri 2 (desktop + mobile), web app, extension | one UI surface reaches every device |
| Identity | per-device Ed25519 keypair. No email, phone, username, or password ever sent to a server | nothing to phish, SIM-swap, or enumerate |
| Recovery | offline Recovery Kit (24 words / Base32 / QR) held by the user | no server-side escrow to compel or breach |
| Server | zero-knowledge versioned blob store | a full server compromise MUST leak no plaintext and MUST NOT be able to forge or silently add devices |
| Sync | per-item CRDT, merged client-side after decrypt | correct offline multi-device editing; server stays dumb |
| Storage | SQLite (WAL, `synchronous=FULL`), **every** field encrypted | metadata (which services you use) is as sensitive as the seed |
| Telemetry | none. No analytics SDK, no crash reporter that can see vault memory | non-negotiable |

**v1 non-goals:** storing passwords, acting as a passkey *provider*,
push-to-approve partner integrations, any network fetch of issuer icons.

---

## 1. Threat model

### Assets
1. **OTP secrets** — long-lived shared secrets; disclosure is permanent until the
   user re-enrolls at every service. Highest value.
2. **Vault metadata** — issuer, account name, notes, groups. Reveals the user's
   entire service footprint; treated as equally sensitive.
3. **Device roster** — which devices exist; enables targeting.
4. **Usage timing** — which token was used when.

### Adversaries and required mitigations

| ID | Adversary | Required mitigation | Residual risk |
|---|---|---|---|
| A1 | Full compromise of our sync server (or a malicious operator) | Client-side E2EE; server sees only opaque envelopes, random 16-byte ids, sizes, and `seq`. Envelopes are Ed25519-signed by the writing device; clients reject signers absent from the client-signed device list | Sizes, item count, and write timing leak. Accept, and pad payloads to 256-byte buckets to blunt it |
| A2 | Network attacker / MITM | TLS 1.3 + certificate pinning in first-party clients; payloads are E2EE independent of TLS; signed `/v1/time` responses so clock skew cannot be induced | Traffic analysis |
| A3 | Thief with a locked device | Vault Key at rest wrapped by an OS-keystore key requiring user auth (Secure Enclave / StrongBox / TPM / libsecret); auto-lock; optional wipe after N failed attempts | Cold-boot / evil-maid on an unlocked device |
| A4 | Unprivileged malware in the same user account | No plaintext secret on disk; secrets `Zeroize`d after use; screenshot/recording blocked; clipboard auto-clear; per-item biometric reveal gate | Cannot be fully defeated. Documented honestly, not hand-waved |
| A5 | Root / jailbreak malware | Hardware-backed keys where available; integrity signals surfaced to the user, never used to lock them out of their own data | Out of scope for full defense |
| A6 | Attacker who obtains server DB **and** tries to enroll a device | Device roster is an encrypted, client-signed vault item. A device not signed into the roster by an already-trusted device is rejected by every client, whatever the server says | Requires an existing device's approval — by design |
| A7 | Supply chain | Pinned deps + `Cargo.lock` committed; `cargo-deny` + `cargo-audit` gate CI; minimal dependency count; reproducible builds; signed releases with a public transparency log; SBOM per release | A compromised upstream crate before audit lands |
| A8 | Exfiltration of a cloud/file backup | Backups are independently encrypted with an Argon2id-derived key and a **separate** passphrase; provider security is never relied on | Weak user passphrase |
| A9 | Shoulder surfing, screen recording | Codes hidden until tapped (opt-in default), blur on app background, no code text in notifications or window titles | Physical observation of a deliberate reveal |
| A10 | Coercion | Opt-in duress PIN that opens a decoy vault; opt-in hidden items | Coercer who knows the feature exists |
| A11 | Phishing (the actual real-world 2FA killer) | Extension autofill is origin-bound; items carry an `origins` list and the UI warns on issuer/origin mismatch; users are nudged toward passkeys where the service supports them | User overrides the warning |

### Explicit non-defenses
A compromised OS kernel, a hardware implant, and a user who types a code into an
attacker's site are all out of scope. The app MUST NOT claim otherwise in any
user-facing copy.

---

## 2. Cryptographic design

### 2.1 Primitives (fixed — do not substitute without a spec change)

| Purpose | Algorithm | Crate |
|---|---|---|
| AEAD | XChaCha20-Poly1305 (24-byte nonce) | `chacha20poly1305` |
| Password KDF | Argon2id, RFC 9106 | `argon2` |
| Key derivation | HKDF-SHA-512 | `hkdf` + `sha2` |
| Hashing | BLAKE2b-256 (internal), SHA-256 (interop) | `blake2`, `sha2` |
| Signatures | Ed25519 | `ed25519-dalek` |
| Key agreement | X25519 | `x25519-dalek` |
| OTP HMAC | HMAC-SHA1 / SHA-256 / SHA-512 (interop only) | `hmac`, `sha1`, `sha2` |
| CSPRNG | OS entropy (`getrandom`) — never a userspace PRNG for key material | `getrandom` |
| Constant-time compare | `subtle::ConstantTimeEq` — `==` on secrets is a review-blocking bug | `subtle` |

24-byte nonces are chosen so random nonce generation is safe for the lifetime of
a vault; nonces MUST be freshly random per encryption, never counters.

### 2.2 Key hierarchy

```
Recovery Key (RK)      32B random. Shown ONCE at setup. Wraps VK. Never stored
                       unwrapped, never leaves the device, never sent anywhere.
Vault Key (VK)         32B random. Root of all item encryption.
Epoch Key (EK_n)       HKDF-SHA512(ikm=VK, salt="misty/epoch/v1", info=LE32(n))
                       Rotating the epoch re-wraps 48-byte item keys, not payloads.
Item Key (IK)          32B random per item. Wrapped by EK_current.
Device Storage Key     Held by the OS keystore, user-auth gated. Wraps VK at rest.
Passphrase KEK         Argon2id(passphrase, salt, tier). Optional local unlock
                       factor and the only key for backup files.
Device Identity (DID)  Ed25519. Private key in the OS keystore, non-exportable
                       where the platform allows. Signs envelopes and server auth.
Device Exchange Key    X25519, ephemeral, used only for device enrollment.
```

`wrap(outer, inner, ctx) = XChaCha20Poly1305(key=outer, nonce=random24, pt=inner, aad=ctx)`

### 2.3 Argon2id tiers

| Tier | Memory | Iterations | Parallelism | Used on |
|---|---|---|---|---|
| `Interactive` | 64 MiB | 3 | 4 | low-memory mobile |
| `Moderate` | 256 MiB | 3 | 4 | default |
| `Sensitive` | 1 GiB | 4 | 4 | desktop, backup files |

The chosen tier and its parameters MUST be stored in cleartext in the relevant
header so any device can decrypt regardless of its own memory budget.

### 2.4 Envelope format (`ENVELOPE_FORMAT_VERSION = 1`)

Every encrypted object — vault item, device roster, settings blob — uses exactly
this layout. All integers little-endian.

```
Header (74 bytes, authenticated but not encrypted)
  off  len  field
    0    4  magic = b"MSTY"
    4    1  format_version = 1
    5    1  kind: 1=Item 2=DeviceRoster 3=Settings 4=Group 5=CustomIcon
    6    4  epoch: u32
   10   16  signer_device_id
   26   24  wik_nonce
   50   24  payload_nonce

Body
   74   48  wrapped_item_key
             = XChaCha20Poly1305(key=EK_epoch, nonce=wik_nonce,
                                 pt=IK[32], aad=Header || item_id[16])
  122   ..  ciphertext
             = XChaCha20Poly1305(key=IK, nonce=payload_nonce,
                                 pt=pad(CBOR(payload)), aad=Header || item_id[16])
  ..   64  signature
             = Ed25519(signer_priv, Header || item_id || wrapped_item_key || ciphertext)
```

`item_id` is **not** stored inside the envelope — it is the storage key — but it
is bound by the AAD, so an envelope cannot be relocated to another item.

`pad(x) = LE32(x.len()) || x || 0x00 * k`, where `k` is the least value making the
total a multiple of **256 bytes**. This blunts size-based fingerprinting of which
issuer an item belongs to.

Decryption order is mandatory and non-negotiable: **verify the signature and the
signer's roster membership first**, then unwrap `IK`, then decrypt. A client MUST
NOT decrypt an envelope signed by an unknown device.

### 2.5 Backup file (`BACKUP_FORMAT_VERSION = 1`, extension `.mistybak`)

```
  off  len  field
    0    8  magic = b"MISTYBAK"
    8    1  format_version = 1
    9    1  kdf_id = 1 (Argon2id)
   10    4  argon2_memory_kib: u32
   14    4  argon2_iterations: u32
   18    4  argon2_parallelism: u32
   22   16  salt
   38   24  nonce
   62    8  reserved, MUST be zero
   70   ..  XChaCha20Poly1305(key=Argon2id(passphrase, salt, params),
                              nonce, pt=deflate(CBOR(VaultExport)), aad=Header)
```

Compression is DEFLATE via `miniz_oxide` (pure Rust) rather than zstd, because the
core MUST build for `wasm32-unknown-unknown` and the `zstd` crate carries C.
Same reason `getrandom` needs its `js` feature on wasm targets.

A plaintext JSON export MUST also exist — users need an escape hatch and lock-in
is a feature we are explicitly refusing to build — but it MUST require a typed
confirmation phrase plus a fresh biometric/PIN check, and the file MUST carry a
loud header comment.

### 2.6 Recovery Kit

The Recovery Key (32 B) is rendered in three interchangeable encodings of the
same bytes:

- **Words** — BIP-39 English wordlist, 24 words (256 bits + 8-bit SHA-256
  checksum). The wordlist and checksum construction are reused purely because
  they are proven transcribable by hand; a Misty kit is **not** a wallet seed and
  the UI MUST say so.
- **Compact** — Crockford Base32 of `RK || CRC32(RK)`, grouped in 8s.
- **QR** — `misty-recovery:v1:<compact>`.

`recovery_blob = wrap(RK, VK, "misty/recovery/v1")` is stored locally and MAY be
stored on the server; it is inert without the kit.

The kit MUST be shown exactly once, MUST require the user to confirm they stored
it (re-entering 3 random words from it), and MUST NOT be recoverable from the app
afterwards. Losing the kit with no enrolled device means permanent loss — the UI
MUST state that in plain language at setup, not in a footnote.

---

## 3. Data model

Ids are 16 random bytes from the CSPRNG. **Not** UUIDv7 — the timestamp prefix
would leak creation order to the server.

```rust
struct Item {
    id: ItemId,                       // [u8; 16]
    otp: OtpConfig,
    issuer: String,                   // "GitHub"
    account: String,                  // "ada@example.com"
    nickname: Option<String>,         // user label; disambiguates same-site accounts
    note: Option<String>,
    groups: Vec<GroupId>,
    tags: Vec<String>,
    icon: IconRef,                    // Bundled(slug) | Custom(BlobId) | Initials { color }
    color: Option<u32>,               // ARGB override
    favorite: bool,
    manual_order: Option<i64>,
    usage: UsageCounter,              // per-device G-counter, see §4
    last_used_at: Option<i64>,        // unix ms
    created_at: i64,
    archived: bool,
    hidden: bool,                     // excluded from the default list
    requires_reveal_auth: bool,       // per-item biometric gate
    origins: Vec<String>,             // domains for extension autofill + mismatch warning
    deleted: Option<Tombstone>,
}
```

```rust
enum OtpKind { Totp, Hotp, Steam, Motp, Blizzard, Yandex }

struct OtpConfig {
    kind: OtpKind,
    secret: SecretBytes,     // Zeroizing<Vec<u8>>, Debug prints "[redacted]"
    algorithm: HashAlg,      // Sha1 (default) | Sha256 | Sha512
    digits: u8,              // 1..=10, default 6
    period: u16,             // seconds, 1..=3600, default 30
    counter: u64,            // HOTP only
    pin: Option<SecretBytes>,// mOTP only
}
```

`SecretBytes` MUST: implement `Zeroize` + `ZeroizeOnDrop`, implement `Debug` and
`Display` as `[redacted]`, and MUST NOT implement `Serialize` except through the
explicit vault-encryption path. A secret reaching a log line is a release blocker.

### 3.1 Multiple accounts on the same site — a first-class requirement

Authy and Google Authenticator both render two accounts at the same issuer
identically, which is the single most common cause of users pasting the wrong
code. Misty MUST:

1. Detect at add-time that an `(issuer, account)` pair collides with an existing
   item, and require the user to set a distinguishing `nickname` before saving —
   never silently create an ambiguous duplicate.
2. Render same-issuer items as a visually grouped cluster with the `account` and
   `nickname` always visible, never truncated to the issuer alone.
3. Allow a per-item `color` and custom icon so the distinction survives a glance.
4. Surface `last_used_at` on same-issuer clusters ("used 2m ago") so the right one
   is obvious in the common case.
5. Treat identical `(issuer, account, secret)` as a genuine duplicate and offer to
   merge; treat identical `(issuer, account)` with a *different* secret as two real
   accounts and keep both.

---

## 4. CRDT and merge rules

Every device has a random 16-byte `device_id`. Mutable fields carry a hybrid
logical clock:

```rust
struct Hlc { wall_ms: u64, counter: u16, device_id: [u8; 16] }  // Ord = lexicographic
```

`counter` increments on same-millisecond writes; `device_id` is the final,
deterministic tiebreak so all devices converge on the same winner.

| Field | Merge rule | Why not LWW |
|---|---|---|
| `issuer`, `account`, `nickname`, `note`, `icon`, `color`, `favorite`, `archived`, `hidden`, `requires_reveal_auth`, `manual_order`, `algorithm`, `digits`, `period` | LWW by `Hlc` | plain user edits |
| `otp.counter` (HOTP) | **max wins**, monotonic | a lower counter would replay a consumed code and desync the server |
| `usage` | per-device G-counter, merge = per-key max, read = sum | LWW would lose counts from offline devices |
| `groups`, `tags`, `origins` | OR-Set: per-element add/remove `Hlc`, add wins on tie | LWW on the whole vector loses concurrent additions |
| `deleted` | tombstone wins if its `Hlc` > every field edit; purge after 90 days | resurrection-by-edit is worse than a stale delete, but a delete MUST NOT beat a *later* edit |
| `otp.secret` | **immutable.** If two devices hold different secrets for one `item_id`, keep BOTH as separate items and raise a user-visible conflict | silently picking one can destroy the only working token. Never guess with a credential |

Deleted items go to a Trash with a 30-day retention before the tombstone is
written, so a sync-propagated delete is recoverable.

Merge MUST be commutative, associative, and idempotent. This is enforced by
`proptest`: for any set of concurrent operations, every application order MUST
produce byte-identical state. That test is the gate on the whole crate.

---

## 5. Storage

- SQLite via `rusqlite` (bundled), `journal_mode=WAL`, `synchronous=FULL`,
  `foreign_keys=ON`. One writer, serialized through the vault handle.
- Schema stores **only** `(item_id, kind, seq, version, envelope BLOB, hlc_max)`.
  No searchable plaintext column exists, so there is nothing to leak via indexes.
- Search, sort, and filter operate on the decrypted in-memory model. Vaults are
  small (< 10k items); a full in-memory model after unlock is simpler and leaks
  less than any encrypted-index scheme.
- Every merge is a single transaction. A crash mid-sync MUST leave the vault at
  its pre-merge state. Crash-injection tests are required, not optional.
- Migrations are forward-only, versioned, and MUST be tested against a fixture DB
  from every prior released schema version.

---

## 6. Sync protocol

The server is a versioned blob store that knows nothing. It never holds a key,
never sees a plaintext field, and cannot enumerate users — a vault is addressed by
a random 16-byte `vault_id`, and no email, phone, or username exists in its schema.

### 6.1 Endpoints

```
POST   /v1/auth/challenge      {vault_id, device_id}         -> {nonce, expires_at}
POST   /v1/auth/verify         {vault_id, device_id, sig}    -> {access_token 15m, refresh_token}
GET    /v1/vaults/{vid}/changes?since={seq}&limit={n}
                               -> {changes:[{item_id, seq, version, envelope, deleted}],
                                   next_seq, has_more}
PUT    /v1/vaults/{vid}/items/{item_id}   If-Match: {version}
                               -> 200 {seq, version} | 409 {version, envelope}
DELETE /v1/vaults/{vid}/items/{item_id}   If-Match: {version}
GET    /v1/time                -> {unix_ms, sig}   Ed25519 over the timestamp
POST   /v1/enroll/begin        {enroll_id, x25519_pub, sealed_request}
GET    /v1/enroll/poll/{enroll_id}
POST   /v1/enroll/complete     {enroll_id, sealed_response}
GET    /v1/quota               -> {bytes_used, item_count, limits}
```

- Auth is Ed25519 challenge-response over the device key. No password grant exists.
- `PUT` uses `If-Match` for optimistic concurrency; `409` returns the current
  envelope so the client can merge locally and retry. The server never merges.
- `seq` is a server-assigned monotonic integer per vault, giving clients a cheap
  ordered change feed without the server understanding any content.
- Server-side rate limits per `vault_id` and per IP. IPs live only in ephemeral
  rate-limit buckets and MUST NOT be written to durable logs.

### 6.2 Device roster

The roster is itself an encrypted vault item (`kind = 2`) whose payload is a list
of `{device_id, ed25519_pub, name, platform, enrolled_at, enrolled_by}`, signed by
an already-trusted device. Clients trust **the roster**, never the server's device
table. A server that injects a device gets a blob it cannot decrypt and writes that
every client rejects as unsigned-by-a-known-device.

### 6.3 Enrollment (device to device)

1. New device generates its Ed25519 identity + an ephemeral X25519 pair, then shows
   a QR of `{x25519_pub, enroll_id, ed25519_pub, name, platform}` plus a 6-digit
   code = truncated BLAKE2b of that payload.
2. Existing device scans the QR (or the user types the 6-digit code on the existing
   device for a camera-less path) and MUST display the new device's name, platform,
   and the 6-digit code for the user to compare out of band before approving.
3. On approval, the existing device does X25519 + HKDF, seals
   `{vault_id, VK, epoch, server_url, roster}` to the new device, adds the new
   device to the roster, signs it, and pushes both.
4. New device polls, unseals, verifies the roster signature chains to a device it
   was told to trust, and registers with the server.

### 6.4 Revocation and key rotation

Revoking a device removes it from the roster, re-signs, and bumps `epoch`. New
`EK_epoch` is derived from the same `VK`, so rotation re-wraps 48-byte item keys
rather than re-encrypting payloads — a full rotation of a 1000-item vault is
~48 KB of writes. Items carry their `epoch`, so rotation can proceed lazily and be
interrupted safely.

Rotating `VK` itself (the response to a suspected `VK` compromise) is a separate,
heavier operation that re-encrypts everything and invalidates the Recovery Kit; the
UI MUST issue a new kit as part of that flow.

### 6.5 Time

TOTP is only as correct as the clock, and a wrong clock looks like a broken app.

- On sync, compare the local clock against signed `/v1/time` and store the offset.
- Apply the stored offset when generating codes; never mutate the system clock.
- Warn in the UI when `|offset| > 10s`, with a one-tap "trust server time" action.
- With no network, fall back to the device clock and say so if drift was last
  measured more than 7 days ago.
- The signature on `/v1/time` exists so a network attacker cannot walk a client's
  effective clock into a window where old codes validate.

---

## 7. OTP engine

MUST be exactly correct against published vectors — this is the one place where
"probably right" is worthless.

| Variant | Requirement |
|---|---|
| HOTP | RFC 4226, all Appendix D vectors |
| TOTP | RFC 6238, all Appendix B vectors (SHA-1, SHA-256, SHA-512) |
| Digits | 1..=10, including the 7- and 8-digit issuers Authy handles |
| Period | 1..=3600s, not just 30 |
| Steam | 5-char alphabet `23456789BCDFGHJKMNPQRTVWXY`, 30s |
| mOTP | `md5(epoch/10 || secret || pin)[..6]`, 10s |
| Blizzard / Yandex | 8-digit variants |
| Base32 | RFC 4648, case-insensitive, tolerate missing padding, whitespace, and hyphens — real-world QR payloads are sloppy |

`otpauth://` URIs MUST round-trip: parse → model → serialize → parse yields an
identical model. Parsing MUST reject rather than guess on malformed input, and MUST
never panic — this parser handles hostile QR codes and is a required fuzz target.

---

## 8. Import / export

No lock-in, in either direction. Required importers:

`otpauth://` and `otpauth-migration://` (Google Authenticator protobuf), Aegis
(plain + encrypted JSON), 2FAS, andOTP (plain + encrypted), FreeOTP and FreeOTP+,
Bitwarden Authenticator, KeePassXC/KDBX TOTP entries, Ente Auth, Raivo, Microsoft
Authenticator (where exportable), LastPass Authenticator, Proton Pass, Twilio Authy
(documented as best-effort — Authy deliberately blocks export), and generic
CSV/JSON with a column-mapping UI.

Every importer MUST: run fully offline, be a fuzz target, report per-row failures
without aborting the batch, and preview what it will add before writing anything.

Exports: encrypted `.mistybak`, per-item `otpauth://` QR sheet as printable PDF,
plaintext JSON behind the confirmation gate in §2.5, and optional SLIP-39/Shamir
splitting of the Recovery Key across N-of-M shares.

---

## 9. Client hardening requirements

| Requirement | Notes |
|---|---|
| Auto-lock | on background, on timeout (default 60s), on screen lock, on device sleep |
| Unlock factors | OS biometric, PIN/passphrase, optional YubiKey HMAC-SHA1 challenge-response, optional WebAuthn PRF |
| Failed attempts | exponential backoff, optional wipe after N |
| Screen capture | blocked on Android (`FLAG_SECURE`) and iOS; blurred on background everywhere |
| Clipboard | auto-clear after 20s, marked sensitive/no-history on Android and Windows |
| Memory | `Zeroize` on all key and secret types; no secret in a `String`; no secret in a panic message |
| Logging | a `tracing` layer that panics in debug builds if a redacted type is formatted |
| Network | TLS 1.3 only, certificate pinning, no third-party endpoint, no icon CDN, no analytics |
| Process | RELRO/PIE/stack-protector on native builds; CSP with no `unsafe-inline` on web and extension |
| Extension | MV3, no remote code, minimum permissions, origin-bound autofill only |
| Builds | reproducible, SBOM published, releases signed, hashes in a public transparency log |
| Backup safety | vault DB is checkpointed and integrity-checked before any destructive migration |

---

## 10. Engineering rules

These are CI gates, not aspirations. A change that fails any of them does not land.

1. `#![forbid(unsafe_code)]` in every crate. No exceptions in v1.
2. `cargo clippy --all-targets --all-features -- -D warnings`.
3. `cargo fmt --check`.
4. `cargo test --workspace` — including the RFC vector suites and the CRDT
   convergence property tests.
5. `cargo deny check` and `cargo audit`.
6. Core crates build for `wasm32-unknown-unknown`.
7. Fuzz targets exist and run in CI for: `otpauth` URI, `otpauth-migration`
   protobuf, envelope decode, backup header, and every importer.
8. No `unwrap()`/`expect()`/`panic!()` on any path reachable from parsed input or
   FFI. Tests may use them freely.
9. Public API is documented; `#![warn(missing_docs)]` on library crates.
10. `Cargo.lock` is committed and dependency additions are justified in the commit
    message. Every crate we add is attack surface.









