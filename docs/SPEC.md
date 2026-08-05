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
                       Rotating the epoch re-seals items; see §6.4 for why it cannot
                       be a re-wrap of the item key alone.
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

Parameters outside the accepted range MUST be **rejected, not clamped**. Clamping an
attacker-supplied 64 GiB memory cost down to something survivable derives a
*different* key, so the user is told their passphrase is wrong when the real problem
is a malformed header — a bug that is close to impossible to diagnose from the
outside. Reject with an error that names the parameter.

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
                                 pt=pad(payload), aad=Header || item_id[16])
  ..   64  signature
             = Ed25519(signer_priv, Header || item_id || wrapped_item_key || ciphertext)
```

`item_id` is **not** stored inside the envelope — it is the storage key — but it
is bound by the AAD, so an envelope cannot be relocated to another item.

The envelope layer treats `payload` as **opaque bytes** and MUST NOT know how it is
encoded. CBOR is the vault layer's concern; keeping the split means the envelope can
carry a roster, a settings blob, or a future format without a change here.

`pad(x) = LE32(x.len()) || x || 0x00 * k`, where `k` is the least value making the
total a multiple of **256 bytes**. This blunts size-based fingerprinting of which
issuer an item belongs to.

Parsing MUST be strict, because every one of these is a silent-misinterpretation
risk rather than a harmless oddity. Reject, with a distinct typed error:

- a length prefix inconsistent with the buffer
- non-minimal padding (more filler than the 256-byte rule requires)
- non-zero padding filler
- a ciphertext length that is not `256n + 16`
- an unknown `kind`
- an unknown `format_version`

Decryption order is mandatory and non-negotiable: **verify the signature and the
signer's roster membership first**, then unwrap `IK`, then decrypt. A client MUST
NOT decrypt an envelope signed by an unknown device. This ordering MUST be proved by
a test that counts AEAD invocations and asserts **zero** decryption attempts for an
unknown signer, a tampered header, a tampered ciphertext, a tampered signature, a
wrong `item_id`, and a wrong epoch — asserting the error type alone does not
establish that no decryption was attempted.


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
    origins: Vec<String>,             // origins the extension may autofill into; §9.1
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
| `issuer`, `account`, `nickname`, `note`, `icon`, `color`, `favorite`, `archived`, `hidden`, `requires_reveal_auth`, `manual_order`, `algorithm`, `digits`, `period`, `otp.kind` | LWW by `Hlc` | plain user edits |
| `otp.counter` (HOTP) | **max wins**, monotonic | a lower counter would replay a consumed code and desync the server |
| `last_used_at` | **max wins** | LWW is wrong here, not merely suboptimal: a device that generated a code at 12:00 while offline, syncing after a device that generated one at 11:00, would report 11:00 as the last use |
| `created_at` | **min wins** | the earliest observation is the truth; an item cannot have been created later than it was first seen |
| `usage` | per-device G-counter, merge = per-key max, read = sum | LWW would lose counts from offline devices |
| `groups`, `tags`, `origins` | OR-Set: per-element add/remove `Hlc`, add wins on tie | LWW on the whole vector loses concurrent additions |
| `deleted` | tombstone wins if its `Hlc` > every field edit; purge after 90 days | resurrection-by-edit is worse than a stale delete, but a delete MUST NOT beat a *later* edit |
| `otp.pin` (mOTP) | LWW, **and** raise a user-visible conflict | a PIN is user-chosen and re-typable, so forking on every typo correction would manufacture phantom duplicates. Divergence is still worth surfacing, because one of the two is generating wrong codes |
| `otp.secret` | **immutable.** If two devices hold different secrets for one `item_id`, keep BOTH as separate items and raise a user-visible conflict | silently picking one can destroy the only working token. Never guess with a credential. Unlike a PIN, a secret is issuer-issued and unrecoverable |

### 4.1 Bounding the clock

`Hlc.wall_ms` MUST be bounded to `[2020-01-01, 2100-01-01)`. Unbounded, a single write
stamped in the year 2200 — from a broken clock or a malicious peer — wins every
subsequent LWW comparison forever, and no later honest edit can displace it.

The window is **absolute, not relative to the reading device's clock**, so that merge
stays a pure function of its inputs. A relative window would make the result depend on
when it ran, which breaks convergence between devices whose clocks differ.

Clamp on write, reject on read.

### 4.2 Forked items need a derived id

When divergent secrets fork an item, the new item's id MUST be derived, not random,
so that every device independently computes the same id and the fork converges:

```
fork_id = HKDF-SHA512(ikm = VK, salt = "misty/vault/fork-id/v1",
                      info = original_item_id ‖ secret)[0..16]
```

Keying on `VK` is load-bearing, not incidental. Item ids are stored **in the clear** on
the server, so a truncated `H(secret)` would hand anyone holding the database an
offline oracle: guess a secret, hash it, check whether that id exists. Keying on the
vault key makes the derivation useless to anyone without it.


Deleted items go to a Trash with a 30-day retention before the tombstone is
written, so a sync-propagated delete is recoverable.

Merge MUST be commutative, associative, and idempotent. This is enforced by
`proptest`: for any set of concurrent operations, every application order MUST
produce byte-identical state. That test is the gate on the whole crate.

---

## 5. Storage

Storage is behind a trait, because SQLite cannot follow the core to the web.
`rusqlite`'s bundled SQLite is C, and C does not compile to
`wasm32-unknown-unknown`. The vault's model, CRDT, and merge logic MUST therefore be
backend-agnostic and MUST build for wasm32 with default features:

```rust
trait VaultStore {
    fn load_all(&self) -> Result<Vec<StoredEnvelope>>;
    fn put(&mut self, row: &StoredEnvelope) -> Result<()>;
    fn transaction<R>(&mut self, f: impl FnOnce(&mut Self) -> Result<R>) -> Result<R>;
    // ...
}

/// One row of the schema below. `put` takes this rather than loose arguments,
/// because the schema has six columns and a signature that names three of them
/// cannot write it.
struct StoredEnvelope {
    item_id: ItemId,
    kind: EnvelopeKind,
    seq: Option<u64>,
    version: u64,
    envelope: Vec<u8>,
    hlc_max: Hlc,
}
```

The SQLite backend is a **target-conditional dependency**, not an off-by-default
feature — native builds get it automatically and wasm builds never try to compile it:

```toml
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
rusqlite = { version = "...", features = ["bundled"] }
```

Web and extension builds supply their own backend (IndexedDB) through the same trait.
An in-memory backend MUST exist for tests on every target.

- SQLite settings: `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`. One
  writer, serialized through the vault handle.
- Schema stores **only** `(item_id, kind, seq, version, envelope BLOB, hlc_max)`.
  No searchable plaintext column exists, so there is nothing to leak via indexes.
- Search, sort, and filter operate on the decrypted in-memory model. Vaults are
  small (< 10k items); a full in-memory model after unlock is simpler and leaks
  less than any encrypted-index scheme.
- Every merge is a single transaction. A crash mid-sync MUST leave the vault at
  its pre-merge state. Crash-injection tests are required, not optional.
- Migrations are forward-only, versioned, and MUST be tested against a fixture DB
  from every prior released schema version.
- The vault layer owns CBOR encoding. `misty-crypto`'s envelope takes opaque bytes;
  this is the layer that decides they are CBOR.


---

## 6. Sync protocol

The server is a versioned blob store that knows nothing. It never holds a key,
never sees a plaintext field, and cannot enumerate users — a vault is addressed by
a random 16-byte `vault_id`, and no email, phone, or username exists in its schema.

### 6.1 Endpoints

```
POST   /v1/auth/challenge      {vault_id, device_id}
                               -> {nonce, expires_at}
POST   /v1/auth/verify         {vault_id, device_id, nonce, sig}
                               -> {access_token 15m, refresh_token}
POST   /v1/auth/refresh        {refresh_token}
                               -> {access_token, refresh_token}   rotates; reuse revokes the family
POST   /v1/vaults/{vid}/devices  {device_id, ed25519_pub}   authenticated by an admitted device
                               -> 201 | 409 if the id is known with a different key
GET    /v1/vaults/{vid}/changes?since={seq}&limit={n}
                               -> {changes:[{item_id, seq, version, envelope|null, deleted}],
                                   next_seq, has_more}
PUT    /v1/vaults/{vid}/items/{item_id}
         If-Match: "{version}"  update
         If-None-Match: *       create
                               -> 200 {seq, version} | 409 {version, envelope} | 428 if neither header
DELETE /v1/vaults/{vid}/items/{item_id}   If-Match: "{version}"
GET    /v1/time?nonce={nonce}  -> {unix_ms, nonce, sig}
POST   /v1/enroll/begin        {enroll_id, x25519_pub, enroll_request}   create-only
GET    /v1/enroll/poll/{enroll_id}?want=request|response                 single-use per blob
POST   /v1/enroll/complete     {enroll_id, sealed_response}              create-only
GET    /v1/quota               -> {bytes_used, item_count, limits}
GET    /healthz
```

**What `sig` covers.** Signing a bare nonce is insecure: the nonce names neither the
vault nor the device, so a signature captured in one context can be presented in
another. The signed message is:

```
"misty/server/auth/v1" ‖ vault_id[16] ‖ device_id[16] ‖ LE32(nonce.len()) ‖ nonce
```

`verify` carries the `nonce` it is answering, so the server does not have to guess
which outstanding challenge a signature belongs to. A challenge is single-use, expires,
and is bound to the `(vault_id, device_id)` that requested it — presenting it from
another device MUST fail.

**A vault must have a way to gain its first device and its later ones.** §6.3 step 4
requires the new device to register, so an endpoint has to exist; without one the
server would have to accept any device that presents a key, and anyone who learned a
`vault_id` could write to it. Those writes would be client-rejected, but they would
consume the user's quota. So: the first device for a vault bootstraps on `verify`
(trust on first use), and every later device is admitted only by an already-admitted
device. The server's device table is an access-control cache, never a source of
trust — §6.2's signed roster is the truth.

**`/v1/time` MUST take a caller nonce and sign it.** A signature over a timestamp
alone is recordable and replayable forever, which is precisely the clock-walking
attack §6.5 exists to prevent. Signed message:

```
"misty/time/v1" ‖ LE32(nonce.len()) ‖ nonce ‖ LE64(unix_ms)
```

**Preconditions and status codes.** Creation has no version to match, so
`If-None-Match: *` creates and `If-Match: "0"` is an accepted synonym; a mutating
request carrying neither header is `428 Precondition Required` rather than a guess.

A failed precondition is **`409`, not `412`**, because the response body must carry
the current envelope for the client to merge from, and `412` conventionally has no
body. An exhausted **vault** quota is **`507`, not `413`**: `413` tells a client to
retry with a smaller request, which is wrong advice when the request was the right
size and the vault is full. `413` remains correct for a genuinely oversized envelope
or body. Both carry `Retry-After`.

- The `{vid}` in the path MUST match the vault the presented token was issued for.
  Stating this is not pedantry: omitting the check is how a token for vault A ends up
  reading vault B.
- `PUT` uses `If-Match` for optimistic concurrency; `409` returns the current
  envelope so the client can merge locally and retry. The server never merges, never
  parses an envelope, and never validates its contents beyond a length cap. Refusing
  to understand the payload is the security property, not laziness.
- `seq` is a server-assigned monotonic integer per vault, giving clients a cheap
  ordered change feed without the server understanding any content.
- **`envelope` is nullable, in the feed and in a `409` body.** A `DELETE` reclaims the
  bytes but keeps the row, because dropping it would let `version` go backwards and
  break every subsequent `If-Match`. So a row can legitimately have a version and no
  bytes. A client MUST record the version from such a row — otherwise its next
  `If-Match` is wrong — while treating the item as still pending, so it offers its own
  copy back rather than accepting a server-side erasure. This is the same principle as
  the `deleted` flag below: the server may forget bytes, but only a signed tombstone
  deletes an item.
- The `deleted` flag in a change feed entry is **advisory only and MUST NOT be acted
  on**. A client that honoured it would let a hostile server erase a vault it cannot
  read — deletion would become the one destructive operation available to an attacker
  who holds the database but no keys. Real deletion is a signed tombstone inside the
  encrypted payload (§4). Treat the flag as a hint that a payload is worth fetching,
  nothing more.
- 256-byte payload bucketing (A1) is a **client** invariant. The server cannot verify
  it without understanding the envelope format, which is the one thing it must not
  know. A client that skips padding silently weakens A1 and no server check will
  catch it.
- Server-side rate limits per `vault_id` and per IP. IPs live only in ephemeral
  rate-limit buckets and MUST NOT be written to durable logs. **Audit the web
  framework's default features for this** — `axum`'s defaults enable `tracing`, which
  logs the accepted connection's peer address as soon as an operator raises the log
  level. A test that captures logs at the most verbose level is the only way this gets
  noticed.
- A vault that exists and one that does not MUST be indistinguishable in every
  response, including timing where practical. There is no user table to enumerate;
  do not reintroduce enumeration through error codes.

#### 6.1.1 On-the-wire encoding — normative

Left unspecified, this section produced two independent, incompatible
implementations of the same protocol from the same document. Both were defensible.
Neither interoperated. So:

| Field kind | Encoding |
|---|---|
| `vault_id`, `device_id`, `item_id`, `enroll_id`, nonces | lowercase hex |
| signatures, public keys | lowercase hex |
| envelopes, sealed blobs | standard base64 with padding (**not** base64url) |
| `version` | an opaque printable-ASCII token; clients MUST NOT parse it, and MUST reject one containing CR, LF, or a quote |
| `seq`, `unix_ms`, counts | JSON numbers, integer-valued |

**Why hex and not base64 for the short fields.** Two reasons, both learned by getting it
wrong first.

A hex string is *also* a syntactically valid base64 string — every character of
`[0-9a-f]` is in the base64 alphabet — so for a **variable-length** field like a nonce,
accepting both encodings is unsound rather than merely untidy. Hex of any even *N* is
well-formed base64 of *3N/2* bytes, and standard base64 of 129 zero bytes is 172 `A`s,
which is well-formed hex for 86 bytes. No decode order gets both cases right, so a
protocol that tries to be liberal here silently accepts the wrong bytes.

And base64 is not query-string safe: standard base64's `+` arrives as a space under
form decoding, which is what pushes an implementation toward base64url for
`GET /v1/time?nonce=` and leaves two base64 variants in one protocol. Hex is
unambiguous in a JSON body and in a query string, and doubling 32 bytes to 64 characters
costs nothing worth defending.

Base64 stays for envelopes and sealed blobs, which are large, and which appear **only**
in JSON bodies — never in a query string.

Fixed-width fields would survive either choice: at 16, 32, and 64 bytes, hex, padded
base64, and unpadded base64url are three different string lengths, so they are
distinguishable. That is a reason the mistake is survivable, not a reason to make it.

A client MUST **ignore unknown response fields** so the server can add one without a
flag day. This is the opposite of the at-rest rule — §2.4 requires strict rejection of
unknown envelope `kind`s and non-minimal padding — and the asymmetry is deliberate:
at rest, an unexpected field means corruption or attack, while on the wire it means a
newer peer.

The signed messages are byte-exact and MUST be implemented as written:

```
auth:  "misty/server/auth/v1" ‖ vault_id[16] ‖ device_id[16] ‖ LE32(nonce.len()) ‖ nonce
time:  "misty/time/v1"        ‖ LE32(nonce.len()) ‖ nonce ‖ LE64(unix_ms)
```

The length prefixes are not decoration. Without them, appending any future field makes
the encoding ambiguous, and a signature scheme that becomes ambiguous later is a
signature scheme that gets confused later.

An implementation of either side MUST have a test proving interoperation with the
other, running the real code on both sides. Two independently green test suites
against two different mocks prove nothing about whether the halves fit together.




### 6.2 Device roster

The roster is itself an encrypted vault item (`kind = 2`) whose payload is a list
of `{device_id, ed25519_pub, name, platform, enrolled_at, enrolled_by}`, signed by
an already-trusted device. Clients trust **the roster**, never the server's device
table. A server that injects a device gets a blob it cannot decrypt and writes that
every client rejects as unsigned-by-a-known-device.

### 6.3 Enrollment (device to device)

1. New device generates its `device_id`, its Ed25519 identity, and an ephemeral
   X25519 pair, then shows a QR of
   `{device_id, x25519_pub, enroll_id, ed25519_pub, name, platform}` plus a 6-digit
   code = truncated BLAKE2b of that payload. `device_id` is in the QR because §6.2's
   roster record requires one and devices generate their own; the confirmation code
   covers it, so a substituted id cannot go unnoticed.
2. Existing device scans the QR (or the user types the 6-digit code on the existing
   device for a camera-less path) and MUST display the new device's name, platform,
   and the 6-digit code for the user to compare out of band before approving.
3. On approval, the existing device derives the sealing key as
   `HKDF-SHA512(ikm = X25519(existing_eph_priv, new_x25519_pub), salt = enroll_id,
   info = "misty/enroll/v1" ‖ new_x25519_pub ‖ existing_eph_pub)`. Binding both
   public keys into `info` is what stops a relayed handshake from being reused
   against a different device. It then seals
   `{vault_id, VK, epoch, server_url, roster}`, adds the new device to the roster,
   signs it, and pushes both.
4. New device polls, unseals, verifies the roster signature chains to a device it
   was told to trust, and registers with the server.

**`enroll_request` is authenticated, not confidential — and it cannot be otherwise.**
An earlier draft called this field `sealed_request`, which was incoherent: the sealing
key is derived from the *approver's* ephemeral X25519 key, and that key does not exist
until step 3, so at step 1 the new device has nothing to seal to. The field carries
public data — a device id, two public keys, a name, a platform — and exists only for
the camera-less path, where the approving device fetches what it could not scan.

What protects it is the 6-digit confirmation code, so the approver **MUST** recompute
that code over the fetched payload and display it for out-of-band comparison before
approving. Skipping that check is what turns this relay into a device-injection
vector: substituting the payload becomes undetectable. The server sees this data
regardless and learns nothing useful from it, but it must never be able to change it
without the user noticing.

### 6.4 Revocation and key rotation

**Bumping the epoch is not a read revocation, and an earlier draft implied it was.**
`EK_n = HKDF(VK, salt, LE32(n))`, so a revoked device that kept `VK` derives every
future epoch key. Epoch rotation therefore provides **no** cryptographic forward
secrecy against a device that retains `VK`; the only barriers left are the server's
access control and §6.2's write check, neither of which helps against an attacker who
also holds the server database or a cached copy of the envelopes.

So: **revoking a device MUST be followed by a `VK` rotation.** That invalidates the
Recovery Kit, so the UI MUST issue a new one as part of the same flow. Presenting
"remove device" as a cheap, instant action while the real protection needs the heavier
operation would be the security theatre this section previously invited.

**Retired device keys stay in the roster, for verification only.** §6.2 has clients
reject any envelope whose signer is absent from the roster, and `Vault::open` checks
every stored row. Drop a revoked device's key outright and the vault holds rows nobody
in the roster signed — so it refuses to open until rotation finishes, which makes lazy
rotation impossible in exactly the situation where it is most needed. The roster
therefore carries two lists:

- **active** — may be admitted by the server and may write.
- **retired** — may not write and may not be admitted, but its public key still
  *verifies* envelopes it signed before revocation.

That keeps the property that matters — no envelope from a device the user never
approved — while letting the vault open throughout a partial rotation. A retired device
could still forge a new envelope that verifies, which is exactly why the mandatory `VK`
rotation above is not optional: after it, the forgery cannot produce a wrapped item key
the new epoch accepts.

Rotation **re-seals each item**: decrypt, then encrypt again under the new epoch. An
earlier draft of this spec claimed rotation could re-wrap the 48-byte item key alone
and leave payloads untouched, at ~48 KB for a 1000-item vault. That was wrong, and
the reason is worth recording so nobody re-derives it. The payload's AAD is
`Header || item_id`, and `Header` carries `epoch` at offset 6 — so changing the epoch
changes the AAD and invalidates the payload's Poly1305 tag. A re-wrap alone would
produce an envelope that no longer authenticates. Real cost is roughly 500 KB per
1000 items.

Do **not** "fix" this by removing `epoch` from the payload AAD. Saving ~450 KB of
writes is not worth a format where some header bytes are authenticated in one place
and not another — that asymmetry is the kind of subtlety implementations get
inconsistently wrong, and inconsistent AAD is how confusion attacks start. Rotation
stays lazy and interruptible either way, which is the property that actually matters:
items carry their own `epoch`, so a partially-rotated vault is valid.


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

### 6.6 Domain separation constants

Every one of these is wire-visible and part of the frozen format. Changing any of
them changes derived keys and invalidates existing vaults, so they belong in the spec
rather than only in the code.

| Constant | Value |
|---|---|
| envelope magic | `b"MSTY"` |
| backup magic | `b"MISTYBAK"` |
| backup extension | `mistybak` |
| epoch key salt | `b"misty/epoch/v1"` |
| recovery wrap context | `b"misty/recovery/v1"` |
| recovery QR prefix | `"misty-recovery:v1:"` |
| roster signing context | `b"misty/roster/v1"` |
| enrollment HKDF info prefix | `b"misty/enroll/v1"` |
| enrollment request context | `b"misty/enroll-request/v1"` |
| enrollment seal context | `b"misty/enroll-seal/v1"` |
| forked-item id derivation | `b"misty/vault/fork-id/v1"` |
| server auth signature | `b"misty/server/auth/v1"` |
| signed time response | `b"misty/time/v1"` |
| roster item id derivation | `b"misty/roster-id/v1"` |
| enrollment QR prefix | `"misty-enroll:v1:"` |

Two constructions MUST NOT share a context string. The reason for the `/v1` suffix on
each is that rotating one construction later should not force rotating the others.

---

## 7. OTP engine

MUST be exactly correct against published vectors — this is the one place where
"probably right" is worthless.

| Variant | Requirement |
|---|---|
| HOTP | RFC 4226, all Appendix D vectors including the published HMAC and truncation columns |
| TOTP | RFC 6238, all Appendix B vectors — SHA-1, SHA-256, SHA-512, each with its own Appendix A seed of 20 / 32 / 64 bytes. Reusing one seed across all three is the classic silent bug; the test MUST assert the seed lengths |
| Digits | 1..=10, including the 7- and 8-digit issuers Authy handles |
| Period | 1..=3600s, not just 30 |
| Steam | 5-char alphabet `23456789BCDFGHJKMNPQRTVWXY`, 30s |
| mOTP | `md5(epoch/10 ‖ hex(secret) ‖ pin)[..6]`, 10s. The secret is **hex** in `otpauth://motp/`, following mOTP tradition |
| Yandex | 8 digits, URI type `yaotp` (`yandex` accepted as an alias), PIN base32-encoded in the URI, and only the **first 16 bytes** of the secret are used — the 26-byte printed form is 16 key bytes plus a checksum |
| Blizzard | 8-digit SHA-1 TOTP. Identical to TOTP by construction, so it is a **preset, not a wire type** — see below |
| Base32 | RFC 4648, case-insensitive, tolerate missing padding, whitespace, and hyphens — real-world QR payloads are sloppy |

### 7.1 Wire types carry algorithm information or they do not exist

`steam`, `motp`, and `yaotp` are non-standard `otpauth://` types, and they are
justified: the algorithm genuinely differs and no parser can infer it from the
parameters. Blizzard is byte-identical to SHA-1 8-digit TOTP, so a `blizzard` URI
type would carry no information while guaranteeing that every other authenticator
fails to import our export.

Therefore a `Blizzard` config MUST serialize as
`otpauth://totp/...?digits=8&algorithm=SHA1`, with both parameters emitted
explicitly rather than left to a parser's defaults. `blizzard` MAY be accepted on
parse as an alias. This is the one documented exception to the round-trip rule
below: Blizzard normalizes to `Totp` on export, and the test asserting it MUST
verify behavioural equivalence — identical codes at identical timestamps — rather
than model equality.

Do not invent a wire-visible string without this justification. It is the one class
of decision that cannot be quietly revised later.

### 7.2 Round-tripping and hostile input

`otpauth://` URIs MUST round-trip: parse → model → serialize → parse yields an
identical model, with the single exception in §7.1. HOTP URIs MUST require an
explicit `counter`; defaulting it would silently desynchronize a token.

Parsing MUST reject rather than guess on malformed input, and MUST never panic —
this parser handles hostile QR codes and is a required fuzz target.

Rejection MUST be precise about what is actually hostile. **Non-ASCII issuer and
account names are valid and MUST be accepted**: `日本銀行` is a real bank, and
rejecting it is a correctness bug, not a hardening measure. What MUST be rejected is
adversarial text — control characters, embedded NUL, bidirectional overrides,
zero-width characters, a BOM, and lone surrogates.

Because a canonical URI can be longer than its input once percent-encoding is
applied, a parser MUST reject input whose canonical form would exceed the length cap
rather than accepting something it could not re-emit. Required caps, which exist to
bound allocation on hostile input:

| Cap | Value |
|---|---|
| `MAX_SECRET_LEN` | 1024 bytes |
| `MAX_URI_LEN` | 4096 bytes |
| base32 `MAX_INPUT_CHARS` | 4096 |
| `MAX_RESYNC_WINDOW` | 1000 counters |

### 7.3 Vector provenance MUST be labelled

No vendor publishes test vectors for Steam, mOTP, Yandex, or Blizzard. Where a
vector comes from a third-party implementation, the test MUST name that
implementation in a comment; where it was generated by our own code, it MUST say so.
Implying authority we do not have is worse than admitting the gap.


---

## 8. Import / export

No lock-in, in either direction. Required importers:

`otpauth://` and `otpauth-migration://` (Google Authenticator protobuf), Aegis
(plain + encrypted JSON), 2FAS, andOTP (plain + encrypted), FreeOTP and FreeOTP+,
Bitwarden Authenticator, KeePassXC **XML and CSV exports**, Ente Auth, Raivo,
LastPass Authenticator, Proton Pass, Twilio Authy (best-effort — Authy deliberately
blocks export), and generic CSV/JSON with a column-mapping UI.

Two formats are deliberately out:

- **KDBX binary is not read.** A KDBX4 reader needs Argon2id and AES-KDF, AES-256-CBC
  and ChaCha20, an HMAC-SHA-256 block chain, an inner stream cipher, and gzip before
  it reaches XML we already parse. That is a large new cryptographic attack surface to
  replace two clicks in KeePassXC's own export menu. Revisit only if users actually
  cannot reach that menu.
- **Microsoft Authenticator is infeasible, not merely unimplemented.** It exposes no
  export of TOTP secrets at any layer. An earlier draft of this section said
  "where exportable", which in practice means nowhere; saying so plainly is more
  useful than leaving a reader to discover it.

### 8.1 Vendor quirks that silently produce wrong codes

These are correctness landmines, not trivia. Each one imports cleanly and then fails
to log the user in, which is the worst failure mode this crate has.

- **FreeOTP stores an HOTP counter one behind the `otpauth://` convention.** It
  persists the counter last *used*; an `otpauth://` `counter` is the *next* one to use.
  An importer MUST add one. (Aegis's own FreeOTP importer reads it raw and is off by
  one — being bug-compatible with a competitor is not a goal.)
- **Authy's own tokens are 7 digits on a 10-second step**, not 6 on 30. Detect via
  `account_type == "authy"` or a hex `secretSeed`; third-party rows in the same file
  keep 6/30. Neither row states its period, so both MUST be flagged as assumed
  defaults rather than presented as read from the file.

### 8.2 Layering

An importer emits a transport type carrying OTP configuration and vendor-supplied
names — **not** SPEC §3's `Item`. Minting `ItemId`, `GroupId`, `Hlc`, and
`UsageCounter` is the vault's job. This keeps the importer independent of the vault,
usable from the browser extension, and testable without a database.

Exports: encrypted `.mistybak` (produced by `misty-crypto`, not reimplemented),
`otpauth://` label/URI pairs for a QR sheet, plaintext JSON behind the confirmation
gate in §2.5, and optional SLIP-39/Shamir splitting of the Recovery Key. Rendering a
QR sheet to PDF belongs to the app layer: a font stack and a PDF serializer have no
place in a crate that must compile to `wasm32`.

Every importer MUST: run fully offline, be a fuzz target, report per-row failures
without aborting the batch, apply §7.2's text rules to every format rather than only
to URIs, and preview what it will add before writing anything.

Fixtures MUST use obvious dummy secrets — this is a public repository. A generated
fixture MUST carry a test that reproduces it from its recipe, so "how was this made"
is answerable by running the suite rather than by trusting a comment.


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
| Extension | MV3, no remote code, minimum permissions, origin-bound autofill only — see §9.1 |
| Builds | reproducible, SBOM published, releases signed, hashes in a public transparency log |
| Backup safety | vault DB is checkpointed and integrity-checked before any destructive migration |

### 9.1 The browser extension

The extension gets its own section because it is the highest-risk client surface in
the product. It is the only component that runs inside arbitrary web pages, and it is
the only mitigation for A11 — phishing, which is the attack that actually costs people
their accounts. A bug here does not leak metadata; it hands a code to an attacker's
site at the moment the user is being attacked.

**The extension is a device, not an accessory.** It generates its own Ed25519 identity,
enrolls through the §6.3 QR flow like any other device, appears in the roster, and can
be revoked. No new trust concept is introduced, and it works standalone without a
desktop app installed. Pairing to a local desktop app over native messaging — so the
extension holds no key material at rest at all — is a worthwhile P10 enhancement, not
the v1 architecture, because requiring a companion app excludes the users most likely
to want an extension.

**MV3's service worker lifecycle collides with auto-lock, and the collision must be
resolved deliberately.** Chrome terminates an idle service worker after roughly 30
seconds. Three consequences:

- The unwrapped Vault Key MUST live in `chrome.storage.session` (memory-only, cleared
  on browser close, never written to disk), not in worker globals. Keeping it in
  worker memory means the vault re-locks every time Chrome reaps the worker, which
  trains users to disable auto-lock — a security control that annoys its way into
  being turned off has failed.
- It MUST NOT live in `chrome.storage.local`, `IndexedDB`, or any disk-backed store in
  unwrapped form. Ever.
- Auto-lock MUST be an **absolute deadline timestamp** checked on every worker wake,
  never a `setTimeout`. A killed worker loses its timers, so a timer-based lock simply
  stops locking. Worker death and user idleness are different events and conflating
  them breaks both properties.

**Argon2id does not belong in the service worker.** The `Moderate` tier's 256 MiB
exceeds what an MV3 worker can be relied on to allocate. Run key derivation in an
offscreen document, and default the extension to the `Interactive` tier. §2.3 already
requires KDF parameters to be stored in the header precisely so a memory-constrained
device can still open what a desktop wrote.

#### Origin matching — the whole anti-phishing claim rests here

`Item.origins` is the list of origins an item may be filled into. Its semantics were
previously left as "domains", which is not a specification. They are:

- **Compare origins, not strings.** Scheme MUST be `https` (only `http://localhost` is
  exempt, for development). Compare the host as an **A-label** — punycode, after IDNA
  normalization — so a homograph domain cannot match a legitimate one. A homograph
  attack is exactly the attack A11 is about, so naive Unicode string comparison here
  defeats the purpose of the whole feature.
- **Exact host by default.** `login.example.com` does not match `example.com`. A
  subdomain pattern is opt-in per item and MUST be recorded explicitly, never inferred.
- **Never suffix-match raw strings.** `evil-example.com` MUST NOT match `example.com`,
  and `example.com.evil.com` MUST NOT match it either. Registrable-domain comparison
  uses the Public Suffix List; the list MUST be vendored, because fetching it would
  break the no-network rule and a stale list fails toward over-matching.
- No wildcard except a leading `*.` on an opt-in subdomain pattern. No wildcards
  elsewhere, at all.
- Non-default ports MUST be stated explicitly; a default port and an absent port are
  the same origin.

#### Autofill rules

- **Never fill without an explicit user gesture.** No fill on page load, no fill on
  focus, no heuristic "this looks like a 2FA page" fill. The user acts, then a code
  moves.
- Never fill into a frame whose own origin is not in `origins` — the top-level page
  matching is not sufficient, because a cross-origin iframe is the standard way to
  smuggle a form onto a trusted-looking page.
- The popup MUST show the issuer and the resolved origin together, so a mismatch is
  visible at the moment of decision rather than discoverable afterwards.
- When origins do not match, the extension MUST warn and MUST NOT offer a one-click
  fill. Making the dangerous action require more effort than the safe one is the entire
  mechanism.
- Codes MUST NOT be written to the clipboard as part of autofill; clipboard is a
  separate, explicit action with the §9 auto-clear.

#### Isolation and permissions

- Content scripts stay in the isolated world. The core, the vault, and any key MUST
  NOT be reachable from page JavaScript. Messaging goes over `chrome.runtime`, never
  `window.postMessage`.
- `activeTab` plus `scripting`, granted per user action. No `<all_urls>`, no broad host
  permissions, no `tabs` permission for URL reading when `activeTab` suffices.
- No remote code — MV3 forbids it, and we would forbid it anyway. Everything ships in
  the package, including the WASM core and the Public Suffix List.
- Strict CSP with no `unsafe-inline` and no `unsafe-eval`.

#### Residual risks, stated rather than buried

- **Certificate pinning is impossible in an extension**, as it is in the web app: the
  browser owns TLS. Payloads are E2EE independently of TLS, which is what makes the
  gap survivable, and it is listed in the README rather than implied away.
- Extension storage is readable by anything with access to the browser profile, which
  is why nothing unwrapped is ever persisted there.
- Safari requires an Xcode wrapper, so Safari packaging needs a macOS runner — the same
  constraint as iOS, and it belongs in the same CI job.
- A user who overrides an origin-mismatch warning has defeated the mitigation. The UI
  can make that expensive; it cannot make it impossible.

---

## 10. Engineering rules

These are CI gates, not aspirations. A change that fails any of them does not land.

1. `#![forbid(unsafe_code)]` in every crate. No exceptions in v1.
2. `cargo clippy --all-targets --all-features -- -D warnings`.
3. `cargo fmt --check`.
4. `cargo test --workspace` — including the RFC vector suites and the CRDT
   convergence property tests.
5. `cargo deny check` — advisories, bans, licenses, and sources. Its advisories
   check reads the RustSec database, so it subsumes `cargo audit`; running both in CI
   would query one database twice and prove nothing extra. `cargo audit` remains a
   fine local equivalent.
6. Core crates build for `wasm32-unknown-unknown`.
7. Fuzz targets exist and run in CI for: `otpauth` URI, `otpauth-migration`
   protobuf, envelope decode, backup header, and every importer.
8. No `unwrap()`/`expect()`/`panic!()` on any path reachable from parsed input or
   FFI. Tests may use them freely.

   For the server this is an availability requirement, not a style preference. The
   release profile sets `panic = "abort"`, so a single reachable panic is not a `500`
   — it kills the process, and an attacker who finds one takes the sync service down
   for everyone, repeatedly. Clippy's lints do not catch the interesting cases: a
   `String::truncate` at a fixed byte offset panics on a multi-byte boundary, and an
   arithmetic conversion of a configured duration overflows. Both were found by
   hostile-input tests rather than by lints, which is why those tests are mandatory
   for anything that parses a request.

   `panic = "abort"` stays because clients hold secrets and failing closed beats
   continuing in an unknown state, and because offline-first clients keep working while
   the sync server restarts.
9. Public API is documented; `#![warn(missing_docs)]` on library crates.
10. `Cargo.lock` is committed and dependency additions are justified in the commit
    message. Every crate we add is attack surface.









