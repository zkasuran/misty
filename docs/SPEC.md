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
| access and refresh tokens | opaque printable-ASCII, server-chosen; no peer decodes them, so their encoding is unconstrained and MUST NOT be relied on |
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
  constraint as the iOS `.xcframework`, and it belongs in the same CI job (the `apple`
  job; see §11.7.1 on which Apple work does and does not need that runner).
- A user who overrides an origin-mismatch warning has defeated the mitigation. The UI
  can make that expensive; it cannot make it impossible.

---

## 10. Engineering rules

These are CI gates, not aspirations. A change that fails any of them does not land.

1. `#![forbid(unsafe_code)]` in every crate. The **one** exception is
   `crates/misty-ffi`: UniFFI and wasm-bindgen both *generate* `unsafe` at the binding
   edge, so the shim cannot forbid it. This is survivable precisely because §11.7
   confines that crate to generated marshalling — no vault, sync, crypto, or lock
   logic lives there — so its `unsafe` is the toolchains', not ours. It uses
   `#![deny(unsafe_op_in_unsafe_fn)]` and adds no hand-written `unsafe`.
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

---

## 11. The facade and the FFI boundary

Four consumers — the web app and the browser extension (both
`wasm32-unknown-unknown`), and desktop and mobile (Tauri 2, native) — build against
one core. §0 committed to "one UI surface reaches every device"; this section is the
seam that makes that literally true. Everything above §11 is target-agnostic Rust
that never names a foreign runtime, a garbage collector, or a `Promise`. §11 defines
the two crates that do, and pins the contract they present so that the four consumers
cannot drift apart.

- **`crates/misty` — the facade.** Pure Rust, `#![forbid(unsafe_code)]`, builds for
  every target in §0 including `wasm32`. It **owns** the live `Vault` and
  `SyncEngine`, monomorphizes away their generic parameters, and presents one API
  expressed entirely in owned, non-generic, `'static` values. It is the *only* crate
  a binding is allowed to see.
- **`crates/misty-ffi` — the binding layer.** UniFFI scaffolding for Kotlin/Swift on
  native; `wasm-bindgen` shims for JS on wasm. It contains **no domain logic** — only
  the mechanical lowering of the facade's owned types onto each toolchain, plus each
  target's concrete backend choices.

We learned the cost of leaving this unspecified once already. §6.1.1 records two
independently green protocol implementations that did not interoperate; the same trap
re-appears one layer up, where four bindings each wrap the core "reasonably" and
diverge. So the rule from §6.1.1 is promoted to the facade: an implementation MUST
have a test proving interoperation **running the real code on both sides**, and there
is no second "mock facade." The UI mock **is** `crates/misty` compiled with
`MemoryStore` + `MockTransport` (§11.8), and **every binding MUST run one shared
conformance suite** against that same facade. Two green suites against two different
mocks prove nothing about whether the halves fit together.

### 11.1 What these crates are, and what they are not

The facade owns the two stateful objects the core exposes only as generics, and
erases every generic parameter at the boundary:

| Object (core type) | Generic params to erase | Native monomorphization | wasm monomorphization |
|---|---|---|---|
| `Vault<S: VaultStore, C: Clock>` | store `S`, clock `C` | `Vault<SqliteStore, SystemClock>` | `Vault<IndexedDbStore, HostClock>` |
| `SyncEngine<T: Transport, S: StateStore>` | transport `T`, state store `S` | `SyncEngine<NativeTransport, FileStateStore>` | `SyncEngine<FetchTransport, MemoryStateStore>` |

`SqliteStore` is `cfg(not(target_arch = "wasm32"))`. The persistent web/extension
backend is an IndexedDB-backed `VaultStore` (`IndexedDbStore`, §5), supplied through
the same trait. `MemoryStore` is the in-memory backend §5 reserves for tests; it is
the store the mock configuration and the shared conformance suite compile in (§11.8),
and it is **never** the persistent wasm store — a vault that does not persist violates
§5. Because the store generic is **erased at the boundary**, which concrete
`VaultStore` is compiled in changes no facade type and no DTO, so swapping the
IndexedDB store in for a `MemoryStore` mock is invisible above the boundary. On wasm
the clock is **host-provided**: `SystemClock` is absent on `wasm32` and `std`'s clock
does not run there, so the facade takes the monotonic clock as an injected host
capability (`HostClock`, fed by `performance.now()` / `Date`) and MUST NOT call
`std::time` directly (the auto-lock deadline in §11.5 depends on this).

This is what the two crates **are not**:

- **Not a second home for domain logic.** Merge, CRDT resolution, validation,
  encoding, and code generation stay in the core. The facade wraps and marshals; it
  does not re-derive rules. In particular, minting `ItemId`, `GroupId`, `Hlc`, and
  `UsageCounter` **is the vault's job** (§8.2) — the facade and the bindings MUST NOT
  fabricate ids or clock values.
- **Not a generic surface.** No generic, lifetime, borrow, `impl Trait`, or trait
  object crosses the boundary. The monomorphized `Vault`/`SyncEngine` handles, the
  `VaultStore`/`Clock`/`Transport`/`StateStore`/`Sleeper` trait objects, and every
  `&Item`/`&Group`/`impl Iterator` reader stay **inside** the facade.
- **Not a place that can weaken §10 rule 8.** No `unwrap()`/`expect()`/`panic!()` on
  any path reachable from FFI or parsed input. Every fallible boundary call returns a
  `Result` mapped to the flat facade error type (§11.3); `panic = "abort"` means a
  single reachable panic kills the process holding the vault.
- **Not a security boundary that can widen the core's.** `#![forbid(unsafe_code)]`
  holds in both crates, and **no secret ever becomes a facade-owned DTO field** (the
  redaction rule in §11.2, and the boundary gap in §11.6).

Two toolchain limits shape everything below, and both are non-negotiable:

1. **UniFFI requires owned, non-generic types, forbids `&mut self` on exported
   interfaces, and requires every exported future *and its returned value* to be
   `Send + 'static`.** Records must be an owned UniFFI-supported type directly — no
   references, no smart pointers; generics are rejected at compile time. (We do **not**
   design around UniFFI's `wasm-unstable-single-threaded` escape hatch — it is
   unstable, and native is genuinely multi-threaded.)
2. **`wasm-bindgen` has no `std` clock and cannot carry data-carrying enums** — only
   C-style (fieldless) enums cross natively (wasm-bindgen #2407). Data-carrying
   variants must be lowered to plain `serde` objects.

The intersection of these two is the entire contract: **owned, `serde`-(de)serializable,
non-generic, `'static` values.** That is the DTO layer.

### 11.2 The DTO layer

A DTO (Data Transfer Object) is a facade-owned value that crosses the boundary by
copy. Every DTO in this section is declared in `crates/misty`, and:

- **MUST** be owned and `'static`: no borrow, no lifetime, no generic, no `impl Trait`.
- **MUST** unwrap every CRDT wrapper — `Lww<T>`, `OrSet<T>`, `MaxWins<T>`,
  `MinWins<T>`, `UsageCounter` — to its inner owned value. No wrapper type crosses.
- **MUST** derive `Clone, Debug, Serialize, Deserialize`. The `serde` form is the
  single representation both toolchains agree on: a UniFFI record/enum and its
  `serde-wasm-bindgen` object MUST be field-identical, and the conformance suite
  (§11.8) asserts exactly that.
- **MUST NOT** carry secret material — see the redaction rule at the end of this
  subsection.

Where a DTO name matches a core type it is a **field-for-field owned mirror**,
re-declared in the facade so it can carry the `#[derive(uniffi::…)]` / `serde`
annotations the core type deliberately omits (§3: `SecretBytes` is intentionally not
`Serialize`), and so the boundary owns a shape that is stable independent of the
core's internal `#[non_exhaustive]` churn.

**Id encoding.** Every 16-byte id (`ItemId`, `GroupId`, `BlobId`, `DeviceId`) crosses
as a **lowercase-hex `String`** (32 hex chars), matching §6.1.1's on-the-wire rule for
the same fields. The facade converts via the ids' `to_hex()`; ids are **not**
renumbered and carry no timestamp (§3). A raw `[u8; 16]` is never a DTO field.

**Enums.** Fieldless value enums cross as native C-style enums on both toolchains;
data-carrying enums cross only as `serde`-tagged objects (the wasm-bindgen limit named
in §11.1).

```rust
// --- fieldless: native enum on both toolchains ---
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpKind { Totp, Hotp, Steam, Motp, Blizzard, Yandex } // mirrors misty_otp::OtpKind

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlg { Sha1, Sha256, Sha512 }                      // mirrors misty_otp::HashAlg

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TombstoneReason { User, TrashExpired }                // mirrors model::TombstoneReason

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortKey { Manual, Issuer, LastUsed, MostUsed, Created } // input to sorted(); mirrors vault::SortKey

// --- data-carrying: serde-tagged object on wasm, sealed class / assoc-value enum on native ---
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IconRef {                     // mirrors model::IconRef
    Bundled { slug: String },          // IconRef::Bundled(String) -> named field
    Custom  { blob_id: String },       // IconRef::Custom(BlobId)  -> hex string
    Initials { color: u32 },           // IconRef::Initials { color }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Conflict {                    // mirrors vault::Conflict (core is #[non_exhaustive])
    DivergentSecret { kept: String, forked: String }, // ItemIds -> hex
    DivergentPin    { item: String },                 // ItemId  -> hex
    Unknown         { item: String },  // see note
}
```

Tuple variants become **named-field** variants (`Bundled(String)` → `Bundled { slug }`)
so the `serde` object has stable keys and UniFFI can name the field. Because core
`Conflict` is `#[non_exhaustive]`, the facade's mapping match is forced to include a
catch-all arm; that arm **MUST** map to `Conflict::Unknown { item }` (built from
`Conflict::item()`), never drop the conflict — a future variant we do not yet render
must surface as "there is a conflict here," not vanish silently.

**The composite snapshots.** These mirror the *public read surface* of the live
objects — their accessors — not their private CRDT fields.

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HlcView {                 // mirrors §4 Hlc; read-only, opaque to the consumer
    pub wall_ms: u64,                //   Hlc.wall_ms   (§4 bounds [2020-01-01, 2100-01-01))
    pub counter: u16,                //   Hlc.counter
    pub device_id: String,           //   Hlc.device_id: DeviceId -> hex
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TombstoneView {           // mirrors model::Tombstone (both fields public)
    pub hlc: HlcView,
    pub reason: TombstoneReason,
}
```

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemView {                // owned snapshot of one Item; carries NO secret
    pub id: String,                  // Item::id()                 ItemId -> hex
    // OTP parameters, flattened out of OtpConfig; the secret and PIN bytes are absent
    pub kind: OtpKind,               // Item::kind()   — the TRUE kind, never the Blizzard->Totp wire alias
    pub algorithm: HashAlg,          // Item::algorithm()
    pub digits: u8,                  // Item::digits()
    pub period: u16,                 // Item::period()
    pub hotp_counter: u64,           // Item::hotp_counter()
    pub has_pin: bool,               // Item::pin().is_some()      — the only trace of a PIN
    // identity / labels
    pub issuer: String,              // Item::issuer()             &str -> owned
    pub account: String,             // Item::account()
    pub nickname: Option<String>,    // Item::nickname()
    pub note: Option<String>,        // Item::note()
    // sets — each collected from impl Iterator<Item = &_> into an owned Vec
    pub groups: Vec<String>,         // Item::groups()             GroupId -> hex
    pub tags: Vec<String>,           // Item::tags()
    pub origins: Vec<String>,        // Item::origins()            §9.1 autofill origins
    // presentation
    pub icon: IconRef,               // Item::icon()               &IconRef -> owned
    pub color: Option<u32>,          // Item::color()              ARGB
    pub favorite: bool,              // Item::favorite()
    pub manual_order: Option<i64>,   // Item::manual_order()
    pub archived: bool,              // Item::archived()
    pub hidden: bool,                // Item::hidden()
    pub requires_reveal_auth: bool,  // Item::requires_reveal_auth() §3, §9
    // usage / timestamps
    pub use_count: u64,              // Item::use_count()          UsageCounter G-counter total, flattened
    pub last_used_at: Option<i64>,   // Item::last_used_at()       unix ms
    pub created_at: i64,             // Item::created_at()         unix ms
    pub trashed_at: Option<i64>,     // Item::trashed_at()         unix ms
    // liveness — the §4 predicates surfaced verbatim so no consumer re-derives them
    pub is_live: bool,               // Item::is_live()
    pub is_trashed: bool,            // Item::is_trashed()
    pub is_deleted: bool,            // Item::is_deleted()
    pub deleted: Option<TombstoneView>, // Item::tombstone()       &Tombstone -> owned
}
```

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupView {               // owned snapshot of one Group
    pub id: String,                  // Group::id()                GroupId -> hex
    pub name: String,                // Group::name()              &str -> owned
    pub color: Option<u32>,          // Group::color()
    pub manual_order: Option<i64>,   // Group::manual_order()
    pub created_at: i64,             // Group::created_at()
    pub is_deleted: bool,            // Group::is_deleted()
    pub deleted: Option<TombstoneView>, // Group::tombstone()
}
```

`ItemView.kind` reports the kind the user chose. The core's `OtpKind::serializes_as`
collapses `Blizzard` to `Totp` for one specific wire form; that collapse is a core
serialization detail and **MUST NOT** leak into the DTO — the view is lossless.
`HlcView` is **read-only**: a consumer MUST NOT construct or reorder one, because
minting an `Hlc` is the vault's job (§8.2); it appears only *inside* a snapshot the
facade produced.

**Input and report DTOs.** The read snapshots above are matched by owned *input* DTOs
(host → core) and *report* DTOs (core → host) that the actor commands in §11.4 carry.
Input DTOs obey the same owned / non-generic / `'static` rules; a secret-bearing input
field is an **owned byte buffer** the facade zeroizes on the Rust side the instant it
is consumed (§11.6 rule 2), never a `String`. Report DTOs flatten every tuple and
mirror every `#[non_exhaustive]` core enum the way `Conflict` is mirrored above, so a
future core field cannot silently vanish.

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewItemInput {            // -> misty_vault add path (OtpConfig + labels)
    // OTP parameters -> OtpConfig
    pub kind: OtpKind,
    pub algorithm: HashAlg,
    pub digits: u8,
    pub period: u16,
    pub hotp_counter: u64,
    pub secret: Vec<u8>,             // raw secret bytes -> SecretBytes; zeroized after use (§11.6)
    pub pin: Option<Vec<u8>>,        // mOTP/Yandex PIN -> SecretBytes; zeroized after use (§11.6)
    // labels / presentation
    pub issuer: String,
    pub account: String,
    pub nickname: Option<String>,
    pub note: Option<String>,
    pub groups: Vec<String>,         // GroupId hex
    pub tags: Vec<String>,
    pub origins: Vec<String>,        // §9.1 autofill origins
    pub icon: Option<IconRef>,
    pub color: Option<u32>,
    pub favorite: bool,
}
```

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClearableField { Nickname, Note, Color, ManualOrder, Pin } // nullable fields an edit may reset

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EditInput {               // -> misty_vault::Edit builder; a None field = leave unchanged
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub nickname: Option<String>,
    pub note: Option<String>,
    pub groups: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub origins: Option<Vec<String>>,
    pub icon: Option<IconRef>,
    pub color: Option<u32>,
    pub manual_order: Option<i64>,
    pub favorite: Option<bool>,
    pub archived: Option<bool>,
    pub hidden: Option<bool>,
    pub requires_reveal_auth: Option<bool>,
    pub pin: Option<Vec<u8>>,        // set/replace a PIN -> SecretBytes; zeroized after use (§11.6)
    pub clear: Vec<ClearableField>,  // reset these nullable fields to absent
}
```

A `None` field leaves the current value unchanged; naming a field in `clear` resets a
nullable field to absent. The `clear` list — not an `Option<Option<T>>` — expresses
"unset this field," because UniFFI does not lower nested options cleanly (§11.1). A
secret is **not** editable in place through `EditInput`; rotating a secret goes through
a dedicated `repair_secret` call that takes owned bytes zeroized per §11.6.

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeView {                // the OTP-code egress exception (§11.6 rule 4)
    pub code: String,                // formatted digits; a platform String for <= one period
    pub valid_until_ms: i64,         // CodeWindow.valid_until_ms — the host expires the code here
    pub period_ms: i64,              // window length, so the host can render a countdown
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RosterUpdateView {        // flattens SyncReport.roster_update: Option<(ItemId, Vec<u8>)>
    pub item_id: String,             // ItemId -> hex
    pub envelope: Vec<u8>,           // opaque ciphertext — not a secret (§11.6)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncReportView {          // owned form derived from misty_sync::SyncReport
    pub conflicts: Vec<Conflict>,    // SyncReport.conflicts, via the Conflict mirror above
    pub roster_update: Option<RosterUpdateView>,
    pub pulled: u32,                 // summary counters, derived from the report
    pub pushed: u32,
    pub applied: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MergeReportView {         // owned form of a local merge outcome (MergeReport.conflicts)
    pub conflicts: Vec<Conflict>,
    pub merged: u32,
}
```

Every report DTO is a point-in-time owned value built inside the call, holding no
back-reference into the vault (the ownership rule below). `CodeView.code` is the one
secret-derived string the boundary emits, produced only through a `generate` call under
the §11.6 rule-4 discipline; it is **not** vault state and is never cached across the
boundary.

**How a borrowing reader becomes an owned snapshot.** Every core reader hands out data
borrowed from the live vault (`&Item`, `Vec<&Item>`, `impl Iterator<Item = &Item>`,
`&[Conflict]`). The facade takes that borrow **inside the call**, walks the owned
accessors above to build the DTO, and returns the DTO; the borrow's lifetime never
outlives the call, and nothing lazy or referenced crosses. A `Vec<&Item>` maps
element-by-element into `Vec<ItemView>`; an `impl Iterator` is **fully consumed and
collected** before returning.

| Core reader (borrows / lazy) | Facade method (owned, `'static`) |
|---|---|
| `Vault::get(&ItemId) -> Option<&Item>` | `get(id: String) -> Option<ItemView>` |
| `Vault::item(&ItemId) -> Result<&Item>` | `item(id: String) -> Result<ItemView, FacadeError>` |
| `Vault::list() -> impl Iterator<Item = &Item>` | `list() -> Vec<ItemView>` |
| `Vault::trash() -> Vec<&Item>` | `trash() -> Vec<ItemView>` |
| `Vault::search(&str) -> Vec<&Item>` | `search(query: String) -> Vec<ItemView>` |
| `Vault::sorted(SortKey) -> Vec<&Item>` | `sorted(key: SortKey) -> Vec<ItemView>` |
| `Vault::same_site_cluster(&str, &str) -> Vec<&Item>` | `same_site_cluster(issuer: String, account: String) -> Vec<ItemView>` |
| `Vault::groups() -> Vec<&Group>` | `groups() -> Vec<GroupView>` |
| `Vault::group(&GroupId) -> Result<&Group>` | `group(id: String) -> Result<GroupView, FacadeError>` |
| `Vault::conflicts() -> &[Conflict]` / `take_conflicts() -> Vec<Conflict>` | `conflicts() -> Vec<Conflict>` |
| `Item::groups()/tags()/origins() -> impl Iterator<Item = &_>` | collected into the `Vec<String>` fields of `ItemView` |

**Ownership and lifetime rule.**

- The facade is the **sole owner** of the live `Vault<…>` and `SyncEngine<…>`. No
  reference to either — nor to any `Item`, `Group`, or `Conflict` they own — crosses
  the boundary.
- Every value returned across the boundary is **owned and `'static`**, deep-copied
  (`clone` / `to_hex` / `collect`) from the vault's data, holding **no back-reference**
  into it.
- A DTO is a **point-in-time snapshot**, valid as of the read. It does not observe
  later mutations; a consumer needing current state re-reads. Mutating a DTO on the
  foreign side edits a copy and **MUST NOT** be assumed to change the vault — the vault
  changes only through explicit mutator commands (§11.4), because UniFFI forbids
  `&mut self` on an exported interface and the vault's mutators are all `&mut self`.

**Secret-redaction rule and the residual gap.** No DTO field is, or is derived from,
`SecretBytes`. `Item::secret()` and `Item::pin()` have **no image in `ItemView`**; the
only trace of a PIN is `has_pin`. This is §3's rule (`SecretBytes` MUST NOT implement
`Serialize` except through the explicit vault-encryption path) enforced at the
boundary: a DTO is `serde`-serializable by construction, so admitting a secret field
would serialize a secret — therefore no such field exists, and the conformance suite
(§11.8) asserts that no DTO type carries a secret-typed field. Generated codes are
**not** vault state and are **not** part of any snapshot DTO; they are produced on
demand as a `CodeView` by a separate, explicitly short-lived call (§11.6 rule 4).

> **A one-time code, a recovery word, or a passphrase that crosses into JS, Kotlin, or
> Swift becomes an unzeroizable platform `String`.** The Rust side can hand out a
> `Zeroizing<String>`, but the moment UniFFI copies it into a Kotlin `String` or
> `wasm-bindgen` into a JS string, the core's `Zeroize`/`ZeroizeOnDrop` guarantee
> (§3, §9) ends and the runtime's garbage collector, not us, decides when the bytes
> disappear. The structural reason is that neither UniFFI nor `wasm-bindgen` exposes a
> zeroizable owned-byte string type on the managed side. The compensating control is to
> keep every secret-bearing surface **out of the DTO layer entirely** — vault state
> crosses only as the redacted `ItemView`/`GroupView` above. §11.6 states the full
> boundary contract for the few unavoidable secret-derived crossings.

### 11.3 Flattened error taxonomy

The facade sits above five source error enums — `misty_otp::OtpError` (with nested
`Base32Error`, `UriError`), `misty_crypto::Error`, `misty_vault::VaultError`,
`misty_sync::SyncError` (with `TransportKind`, `RosterRejection`, `VaultFailure`), and
`misty_importers::{ImportError, RowError}` (with nested `ProtobufError`), plus
`ExportError`. Between them they carry well over a hundred variants; **four of the five
top-level source enums are `#[non_exhaustive]`** (every one except `OtpError`), as are
several nested enums (`RowError`, `ProtobufError`, `TransportKind`, `RosterRejection`,
`ExportError`); and several transparently wrap each other (`VaultError::Crypto`,
`SyncError::Vault`, `RowError::Otp`). None of that can be a stable ABI. An earlier
instinct — let each crate's error cross the boundary as-is — is wrong twice over, and
the reasons are worth recording so nobody re-derives them: a `#[non_exhaustive]` enum
has no frozen discriminant a binding can switch on, and **wasm-bindgen cannot carry a
data-carrying enum at all** (only C-style/fieldless enums cross). So §11 collapses every
source error into one flat facade error whose stability lives in an explicit string
`code`, never in a discriminant.

#### 11.3.1 One error crosses the boundary — normative

Every fallible facade or FFI call MUST return `Result<T, FacadeError>` — UniFFI throws
it, wasm rejects the `Promise` with it. There is no second failure channel. Conflicts,
per-row skips, and warnings are **not** errors: they ride inside owned DTOs
(`MergeReportView.conflicts`, `SyncReportView.conflicts`, `RowOutcome::{Skipped,
Failed}`, `ImportWarning`) and MUST NOT be raised as a `FacadeError`. Only a source
`Result::Err` becomes one.

The stable contract is `ErrorCode` — a fieldless enum, so it crosses both toolchains
identically, and it serializes by its `UPPER_SNAKE` name:

```rust
/// The frozen, machine-readable failure vocabulary. UPPER_SNAKE. This — not the
/// message, not the numeric discriminant — is the contract bindings branch on.
#[non_exhaustive]
pub enum ErrorCode {
    // lifecycle / internal (facade-originated, no source variant)
    VaultLocked, UnsupportedOnTarget, Internal,
    // vault lookup / conflict
    NotFound, AlreadyExists, DuplicateAccount, AmbiguousAccount,
    // input validation (write path)
    InvalidField, OtpInvalidSecret, OtpInvalidParam, UriMalformed,
    // otp runtime / resource ceilings
    OtpGenerationFailed, ResourceExhausted,
    // merge / clock
    MergeFailed,
    // crypto & integrity, at rest and in transit
    DecryptFailed, SignatureInvalid, UntrustedSigner, DeviceRevoked,
    CorruptData, KdfRejected, VersionUnsupported, EpochMismatch,
    // recovery / enrollment user input
    RecoveryInputInvalid, ConfirmationCodeMismatch, EnrollIdMismatch,
    // sync / network / server
    Network, TlsError, ServerError, AuthFailed, QuotaExhausted,
    ProtocolViolation, TimeUntrusted, ConfigInvalid, StorageFailed,
    // import / export
    ImportUnrecognized, ImportMalformed, ImportPassphraseRequired,
    ImportEncryptedUnsupported, ConfirmationRequired,
}

impl ErrorCode {
    /// e.g. `ErrorCode::VaultLocked` -> `"VAULT_LOCKED"`. The frozen token.
    pub const fn as_str(self) -> &'static str;
    /// Derived and frozen per code (§11.3.3).
    pub const fn retryable(self) -> bool;
}
```

The raised error carries exactly a `code` and a human `message`; `retryable` is
derived from `code`:

```rust
#[non_exhaustive]
pub struct FacadeError {
    pub code: ErrorCode, // stable — the only thing bindings switch on
    pub message: String, // English, redacted, NON-normative — never parsed or matched
}
impl FacadeError { pub fn retryable(&self) -> bool; } // == self.code.retryable()
```

Both projections expose exactly these three, so the same failure is indistinguishable
across toolchains: UniFFI exports `FacadeError` as the thrown error enum
(`code`/`message`/`retryable` readable on the caught value); wasm rejects with the
serde object `{ code, message, retryable }`. Because `code` is serialized by name, the
discriminant never enters the contract, and variants MAY be reordered between releases.

This subsection is a direct consequence of **§10 rule 8**: no
`unwrap()`/`expect()`/`panic!()` on any path reachable from parsed input or FFI. The
release profile is `panic = "abort"`, so an escaped panic is process death, not a
catchable exception — and `std::panic::catch_unwind` does nothing under `abort`. The
facade therefore MUST NOT panic in the first place: every fallible boundary call maps
its source `Err` per §11.3.6, and any internally-detected impossible state that would
otherwise panic MUST be surfaced as `INTERNAL` rather than allowed to unwind. A call
that arrives after the auto-lock deadline (§11.5) MUST return `VAULT_LOCKED`, never
hang and never panic; UniFFI has no future-drop cancellation, so lock/abort is an
explicit checked state, not a dropped future.

#### 11.3.2 Branch on codes, never messages — normative

UI and bindings MUST branch on `code` (and MAY consult `retryable`). They MUST NOT
parse, match, or assert on `message`. `message` is English, host-editable, and
localized downstream; matching it breaks on translation and on any wording change, and
it is the one field allowed to vary between builds. The shared conformance suite
(§11.8) induces a fixed corpus of failures on every binding and asserts on the `code`
string only — never on `message`.

Because `ErrorCode` is `#[non_exhaustive]`, new codes MAY be added without a
format-version bump, exactly as the source enums grow. Every binding's
`switch`/`when`/`match` on `code` MUST therefore carry a default arm that treats an
unrecognized code as a non-retryable failure. This mirrors the on-wire rule in §6.1.1
(a client MUST ignore unknown *response* fields): a newer core is a newer peer, not
corruption.

#### 11.3.3 Retryability — normative

`retryable == true` MUST mean that a bare retry of the identical call, with no change
to inputs or vault state, MAY succeed — transient conditions only. It is a **pure
function of `code`** and is itself frozen. Exactly two codes are retryable:

| Retryable | Codes |
|---|---|
| `true` | `NETWORK`, `SERVER_ERROR` (5xx; honor `Retry-After`) |
| `false` | every other code |

Everything else is `false` on purpose: the caller or the user MUST change something —
the input, a passphrase, the roster, the app version — or accept a terminal condition.
Failing closed beats looping. `QUOTA_EXHAUSTED` is not retryable even though the server
sends `Retry-After`, because a full vault (`507`, §6.1) does not drain on its own; the
user must delete items. `TLS_ERROR` is not retryable because a pin mismatch is a
possible MITM (A2), not a blip.

#### 11.3.4 Redaction and enumeration — normative

`message` MUST NOT contain secret material: no secret bytes, no OTP code, no
passphrase, no envelope plaintext, no recovery words. This restates §3 (`SecretBytes`
is `Zeroize`/`[redacted]`), §9 ("no secret in a `String`; no secret in a panic
message"), and the `misty-sync` whole-crate guarantee that no error names a secret. Ids
(16 bytes, hex per §6.1.1) and field *names* are non-secret and MAY appear. A secret
reaching a `message` is a release blocker.

The facade MUST NOT reintroduce vault enumeration through codes (§6.1). A server
response that would distinguish a vault that exists from one that does not MUST map to
the same code as the generic case; the facade never mints a code whose presence leaks
the existence of a `vault_id` to a caller that could not otherwise learn it.

#### 11.3.5 The code catalog

| Code | Meaning | Retryable | Action |
|---|---|---|---|
| `VAULT_LOCKED` | call needs an unlocked vault; the handle is locked (deadline passed or explicit lock, §11.5) | no | unlock |
| `UNSUPPORTED_ON_TARGET` | operation absent on this build's target (e.g. `SqliteStore` path or cert pinning on `wasm32`) | no | caller: use the target-appropriate call |
| `INTERNAL` | a caught impossible state, a CSPRNG/AEAD failure, or an unmapped `#[non_exhaustive]` variant | no | report a bug |
| `NOT_FOUND` | no item or group with that id | no | caller: id is stale |
| `ALREADY_EXISTS` | id or device already present | no | — |
| `DUPLICATE_ACCOUNT` | same `(issuer, account, secret)` already stored (§3.1) | no | user: drop, or `merge_duplicate` |
| `AMBIGUOUS_ACCOUNT` | same `(issuer, account)`, different secret; needs a distinguishing nickname (§3.1) | no | user: set a nickname |
| `INVALID_FIELD` | a label/field failed validation on a write | no | user: fix the field |
| `OTP_INVALID_SECRET` | the OTP secret is empty, mis-encoded, or over `MAX_SECRET_LEN` | no | user: re-enter the secret |
| `OTP_INVALID_PARAM` | digits/period out of range, or a required PIN is missing | no | user: fix the setup |
| `URI_MALFORMED` | an `otpauth://` URI failed to parse or exceeds `MAX_URI_LEN` | no | user/source: fix the URI |
| `OTP_GENERATION_FAILED` | code could not be produced (clock out of range, internal) | no | — |
| `RESOURCE_EXHAUSTED` | a monotonic ceiling was hit: HLC, epoch counter, or HOTP counter | no | terminal; report a bug |
| `MERGE_FAILED` | a merge could not settle (id/kind/secret disagreement, clock collision, loop) | no | — |
| `DECRYPT_FAILED` | an envelope, backup, recovery blob, or enrollment would not open | no | user-actionable when a passphrase/recovery key was supplied (wrong passphrase) |
| `SIGNATURE_INVALID` | an Ed25519 signature or a verifying key failed verification (tamper) | no | — |
| `UNTRUSTED_SIGNER` | the writer/approver is not in the signed roster (§6.2) | no | — |
| `DEVICE_REVOKED` | this device is absent from the roster (revoked, or never enrolled) | no | user: re-enroll (§6.3) |
| `CORRUPT_DATA` | a stored or received blob will not decode (bad magic, padding, CBOR, HLC out of window, zip-bomb) | no | — |
| `KDF_REJECTED` | Argon2id id/params outside the accepted range | no | — |
| `VERSION_UNSUPPORTED` | a format/schema/state/export version newer than this build | no | user: update the app |
| `EPOCH_MISMATCH` | the epoch key does not match the envelope's epoch | no | caller: sync, then `rotate_step` until `remaining == 0` |
| `RECOVERY_INPUT_INVALID` | recovery words/compact/QR mistyped, wrong length, or bad checksum | no | user: re-enter or re-scan |
| `CONFIRMATION_CODE_MISMATCH` | the typed 6-digit enrollment code is wrong (`CONFIRMATION_CODE_DIGITS`) | no | user: re-type |
| `ENROLL_ID_MISMATCH` | an enrollment blob's `enroll_id` does not match | no | user: use the correct QR |
| `NETWORK` | the request never reached a well-formed response (connect, timeout, framing, offline) | **yes** | retry with backoff |
| `TLS_ERROR` | TLS handshake failed or a certificate pin did not match (A2; possible MITM) | no | — |
| `SERVER_ERROR` | server returned `5xx` | **yes** | retry, honor `Retry-After` |
| `AUTH_FAILED` | challenge/verify/refresh was refused | no | re-authenticate; may indicate revocation |
| `QUOTA_EXHAUSTED` | the vault is full (`507`, §6.1) | no | user: delete items or raise the limit |
| `PROTOCOL_VIOLATION` | the server broke a protocol invariant (seq rollback, out-of-order feed, missing `409` envelope, unparseable `version` token, oversized envelope) | no | — |
| `TIME_UNTRUSTED` | signed `/v1/time` failed to verify, replayed a nonce, or went backwards (§6.5) | no | — |
| `CONFIG_INVALID` | server URL not `https`/malformed, or a pin set with the wrong byte length | no | caller: fix configuration |
| `STORAGE_FAILED` | the SQLite/state backend reported a failure | no | — |
| `IMPORT_UNRECOGNIZED` | no importer matched, or the input is empty | no | user: pick the format |
| `IMPORT_MALFORMED` | the file is broken, too large, too many rows, or lacks a usable header | no | user: check the export |
| `IMPORT_PASSPHRASE_REQUIRED` | an encrypted export needs a passphrase | no | user: supply passphrase, retry |
| `IMPORT_ENCRYPTED_UNSUPPORTED` | this vendor's encryption is not supported | no | user: decrypt in the source app (advice in `message`) |
| `CONFIRMATION_REQUIRED` | plaintext export attempted without the exact `PLAINTEXT_EXPORT_CONFIRMATION` phrase and a fresh biometric/PIN check (§2.5) | no | user: type the phrase and re-auth |

#### 11.3.6 Source-variant mapping

**Delegation rule.** A transparent or `#[from]` wrapper variant carries no code of its
own: the facade unwraps it and maps the inner error. This applies to
`VaultError::{Crypto, Otp}`, `SyncError::{Crypto, Vault}` (the latter through
`VaultFailure::get()` on its `Box<VaultError>`), `RowError::{Otp, Protobuf}`, and
`ImportError::Protobuf`, and to the nested `OtpError::{Base32, Uri}`.

**Context rule.** Several `VaultError` variants fire on two paths. On a *write* path
(`add`, `update`, `merge_duplicate`, importer intake) they are user-actionable input
validation → `INVALID_FIELD` / `OTP_*`. On a *decode/merge/open* path (`stored`,
`merge_remote`, envelope/codec decode) the same variant means tamper, damage, or
version skew → `CORRUPT_DATA`. The facade assigns the code by the call it exposes, not
by the variant alone.

`misty_otp::OtpError` (and nested)

| Source variant | Code | When |
|---|---|---|
| `InvalidDigits` / `InvalidPeriod` | `OTP_INVALID_PARAM` | outside `[MIN_DIGITS, MAX_DIGITS]` / `[MIN_PERIOD, MAX_PERIOD]` |
| `MissingPin` | `OTP_INVALID_PARAM` | mOTP/Yandex kind, no PIN supplied |
| `EmptySecret` / `InvalidHexSecret` / `SecretTooLong` | `OTP_INVALID_SECRET` | empty, non-hex, or over `MAX_SECRET_LEN` |
| `Base32(InvalidChar\|PaddingInMiddle\|InvalidLength\|TooLong)` | `OTP_INVALID_SECRET` | base32 secret malformed |
| `Uri(TooLong\|CanonicalTooLong)` | `URI_MALFORMED` | URI over `MAX_URI_LEN` |
| `Uri(NotOtpauth\|UnknownKind\|MigrationUri)` | `URI_MALFORMED` | not `otpauth://`, unknown kind, or a migration URI (route to the Google importer) |
| `Uri(MissingParam\|DuplicateParam\|InvalidParam\|BadPercentEscape\|NotUtf8\|ControlChar\|MalformedQuery)` | `URI_MALFORMED` | URI parse failure |
| `TimeOutOfRange` / `Internal` | `OTP_GENERATION_FAILED` | clock unrepresentable / internal invariant |
| `CounterExhausted` | `RESOURCE_EXHAUSTED` | HOTP counter at `u64::MAX` (terminal) |

`misty_crypto::Error`

| Source variant | Code | When |
|---|---|---|
| `Random` / `AeadEncrypt` | `INTERNAL` | CSPRNG or AEAD-encrypt failure (environment) |
| `Truncated` / `BadEnvelopeMagic` / `BadBackupMagic` / `UnknownEnvelopeKind` / `ReservedNotZero` / `MalformedBody` / `BadPaddingLength` / `BadPadding` / `PayloadTooLarge` / `Cbor` / `Inflate` / `InflateLimit` / `RecoveryBlobMalformed` | `CORRUPT_DATA` | a blob will not decode; `InflateLimit` = past `MAX_DECOMPRESSED_LEN` |
| `UnsupportedFormatVersion` | `VERSION_UNSUPPORTED` | envelope/backup written by a newer build |
| `EpochMismatch` | `EPOCH_MISMATCH` | epoch key does not match envelope epoch |
| `UnknownSigner` / `RosterUnsigned` / `RosterSignerNotInRoster` / `EnrollmentApproverUnknown` | `UNTRUSTED_SIGNER` | signer/approver not in the roster |
| `SignatureInvalid` / `RosterSignatureInvalid` / `EnrollmentSignatureInvalid` / `BadVerifyingKey` / `NonContributoryKeyExchange` | `SIGNATURE_INVALID` | signature/key verification failed (tamper) |
| `ItemKeyUnwrapFailed` / `PayloadDecryptFailed` / `BackupDecryptFailed` / `RecoveryUnwrapFailed` / `EnrollmentUnsealFailed` | `DECRYPT_FAILED` | decryption failed; backup/recovery paths ⇒ user (wrong passphrase/key) |
| `UnknownKdfId` / `KdfParamsRejected` / `Kdf` | `KDF_REJECTED` | Argon2id id/params rejected |
| `WrongWordCount` / `UnknownWord` / `WordChecksumMismatch` / `BadCompactLength` / `BadCompactChar` / `BadCompactPadding` / `Crc32Mismatch` / `BadQrPrefix` | `RECOVERY_INPUT_INVALID` | recovery words/compact/QR entry is wrong (user) |
| `DuplicateDevice` | `ALREADY_EXISTS` | device already in the roster |
| `DeviceNotInRoster` | `DEVICE_REVOKED` | device absent from the roster |
| `ConfirmationCodeMismatch` | `CONFIRMATION_CODE_MISMATCH` | typed 6-digit code is wrong (user) |
| `EnrollIdMismatch` | `ENROLL_ID_MISMATCH` | enrollment blob addressed to another `enroll_id` |
| `StringTooLong` | `INVALID_FIELD` / `CORRUPT_DATA` | write path / decode path (context rule) |

`misty_vault::VaultError`

| Source variant | Code | When |
|---|---|---|
| `Crypto` / `Otp` | *(delegate)* | map the inner `misty_crypto::Error` / `OtpError` |
| `NoSuchItem` / `NoSuchGroup` | `NOT_FOUND` | id not present |
| `ItemExists` | `ALREADY_EXISTS` | id already taken |
| `DuplicateAccount` | `DUPLICATE_ACCOUNT` | same credential twice (§3.1) |
| `AmbiguousAccount` | `AMBIGUOUS_ACCOUNT` | same `(issuer, account)`, needs a nickname (§3.1) |
| `EmptyField` | `INVALID_FIELD` | a required label was blank |
| `DisallowedCharacter` / `StringTooLong` / `TooManyElements` | `INVALID_FIELD` / `CORRUPT_DATA` | write path / decode path (context rule) |
| `Cbor` / `PayloadTooLarge` / `UnknownEnumValue` / `HlcOutOfRange` / `DuplicateKey` / `CorruptRecord` | `CORRUPT_DATA` | decode of stored/remote data (`HlcOutOfRange` = reject on read, §4.1) |
| `UnsupportedFormatVersion` / `SchemaTooNew` | `VERSION_UNSUPPORTED` | payload/schema newer than this build (§5) |
| `IdMismatch` / `KindMismatch` / `SecretIsImmutable` / `MergeDidNotSettle` / `ClockCollision` | `MERGE_FAILED` | a merge invariant broke (§4) |
| `ClockExhausted` / `EpochExhausted` | `RESOURCE_EXHAUSTED` | HLC or epoch counter at ceiling |
| `DeviceNotInRoster` | `DEVICE_REVOKED` | vault opened by an untrusted device (§6.2) |
| `Storage` | `STORAGE_FAILED` | backend reported a failure |
| `NoTransaction` | `INTERNAL` | commit/rollback without an open transaction (caller bug) |

`misty_sync::SyncError` (with `TransportKind`, `RosterRejection`)

| Source variant | Code | When | Retry |
|---|---|---|---|
| `Crypto` | *(delegate)* | map inner `misty_crypto::Error` | — |
| `Vault` | *(delegate)* | unwrap `VaultFailure` → map inner `VaultError` | — |
| `Transport{Connect\|Timeout\|Protocol\|Environment}` | `NETWORK` | request did not complete | **yes** |
| `Transport{Tls\|PinMismatch}` | `TLS_ERROR` | handshake failed / pin mismatch (A2) | no |
| `Server{status}`, `500..=599` | `SERVER_ERROR` | server fault | **yes** |
| `Server{status}`, `400..=499` | `PROTOCOL_VIOLATION` | server rejected a valid, authed request (map `404`/absent-vault identically, §11.3.4) | no |
| `Server{status}`, any other value | `PROTOCOL_VIOLATION` | a well-formed response carrying an unexpected status (`1xx`/`2xx`/`3xx`, none valid here) is a protocol fault | no |
| `AuthRefused` | `AUTH_FAILED` | challenge/verify/refresh refused | no |
| `Malformed` / `ResponseTooLarge` / `SeqRollback` / `FeedOutOfOrder` / `SeqOutOfRange` / `FeedTooLong` / `ConflictWithoutEnvelope` / `UnusableVersionToken` / `EnvelopeTooLarge` | `PROTOCOL_VIOLATION` | server broke a §6.1/§6.1.1 invariant (`UnusableVersionToken` = CR/LF/quote in `version`) | no |
| `UnknownSigner` | `UNTRUSTED_SIGNER` | envelope signer absent from roster | no |
| `RosterRejected{Unsigned\|SignerNotTrusted}` | `UNTRUSTED_SIGNER` | roster envelope not from a trusted signer | no |
| `RosterRejected{SignatureInvalid}` | `SIGNATURE_INVALID` | roster signature failed | no |
| `RosterRejected{WrongAddress\|WrongKind}` | `CORRUPT_DATA` | roster envelope addressed/typed wrong | no |
| `Revoked` | `DEVICE_REVOKED` | this device was revoked | no |
| `TimeSignatureInvalid` / `TimeNonceMismatch` / `TimeWentBackwards` | `TIME_UNTRUSTED` | signed-time verification failed (§6.5) | no |
| `ConflictLoop` | `MERGE_FAILED` | merge did not converge within the bound | no |
| `QuotaExhausted` | `QUOTA_EXHAUSTED` | vault full (`507`) | no |
| `StateStore` | `STORAGE_FAILED` | state store failed | no |
| `StateTooNew` | `VERSION_UNSUPPORTED` | sync state written by a newer build | no |
| `BadServerUrl` / `BadPin` | `CONFIG_INVALID` | URL not `https`/malformed; pin bytes wrong length | no |

`SyncError::Server` carries the raw HTTP `status: u16`; the three `Server{status}` rows
partition every possible value, so no status falls through unmapped. Server responses
that map to a dedicated meaning — `507` (quota) and a refused challenge — arrive as the
`QuotaExhausted` / `AuthRefused` variants, not as `Server`, so there is no overlap.

`misty_importers::ImportError` (whole-file; raised)

| Source variant | Code | When |
|---|---|---|
| `UnrecognizedFormat` / `Empty` | `IMPORT_UNRECOGNIZED` | no importer matched / empty input |
| `InputTooLarge` / `NotUtf8` / `Json` / `Xml` / `Base64` / `Hex` / `MissingField` / `InvalidField` / `MappingRequired` / `MappedColumnMissing` / `TooManyRows` / `RowTooLarge` | `IMPORT_MALFORMED` | the file is broken, oversized, or lacks a usable header |
| `Protobuf` | *(delegate)* | map `ProtobufError` → `IMPORT_MALFORMED` |
| `UnsupportedVersion` | `VERSION_UNSUPPORTED` | export version newer than supported |
| `PassphraseRequired` | `IMPORT_PASSPHRASE_REQUIRED` | encrypted export, no passphrase given |
| `EncryptedNotSupported` | `IMPORT_ENCRYPTED_UNSUPPORTED` | vendor encryption unsupported (`advice` → `message`) |
| `DecryptionFailed` | `DECRYPT_FAILED` | wrong passphrase or damaged file |
| `KdfParam` | `KDF_REJECTED` | KDF parameter out of range |

`misty_importers::RowError` (per-row) surfaces **inside** `RowOutcome::Failed { error }`,
not as a raised `FacadeError`; the facade still stamps each failed row with a `code`
from this catalog so the report DTO is branchable the same way.

| Source variant | Code |
|---|---|
| `MissingField` / `InvalidField` / `FieldTooLong` / `WrongShape` / `NotUtf8` | `INVALID_FIELD` |
| `Otp` | *(delegate)* → `OTP_*` / `URI_MALFORMED` |
| `Protobuf` | *(delegate)* → `IMPORT_MALFORMED` |

`ProtobufError` (nested) — every variant (`Truncated`, `VarintOverflow`,
`LengthTooLarge`, `ZeroField`, `UnsupportedWireType`, `NotUtf8`, `WrongType`, `TooDeep`)
→ `IMPORT_MALFORMED`.

`misty_importers::export::ExportError` — `ConfirmationRequired` → `CONFIRMATION_REQUIRED`
(plaintext export attempted without the exact `PLAINTEXT_EXPORT_CONFIRMATION` phrase and
the fresh biometric/PIN check §2.5 requires).

#### 11.3.7 The test that proves the rule

The binding conformance suite (§11.8) MUST induce at least one failure per `ErrorCode` —
on native through UniFFI and in the browser through wasm — and assert that the caught
error's `code` string and `retryable` flag match across both, and that no `message` is
asserted on. This is the same discipline §6.1.1 imposes on the wire: two independently
green suites against two mocks prove nothing about whether the halves agree. The taxonomy
is a contract only if one suite runs the real facade on both sides and checks the codes.

### 11.4 Concurrency model — the single-owner actor

Three facts from the core crates collide, and the collision is what this section
resolves rather than papers over:

- `SyncEngine`'s loop is generic over three parameters at once —
  `run<VS: VaultStore, C: Clock, K: Sleeper>`, `sync_once<VS, C>`, `pending<VS, C>` —
  and it drives a `Vault<S: VaultStore, C: Clock>` that is itself two-generic. Neither
  type can cross a UniFFI or wasm-bindgen boundary; the facade MUST monomorphize both
  and own the concrete handle.
- `Transport::request` returns `impl Future` with **no `Send` bound**, deliberately, so
  a browser `fetch`/`JsFuture` (`!Send`) can implement it. The engine's `async` methods
  therefore produce `!Send` futures on wasm.
- The vault has exactly one writer: every mutator takes `&mut self`, and
  `SyncEngine::sync_once` / `run` / `revoke_device` / `rotate_step` all take
  `&mut Vault<VS, C>`. There is no interior mutability and no lock inside `misty-vault`.

A shared-mutable handle wrapped in a `Mutex` does not survive contact with these three:
UniFFI forbids `&mut self` on exported interfaces and requires every exported future to
be `Send + 'static`, while wasm's `!Send` transport future cannot be made `Send` to
satisfy it. The resolution is an **actor**: a single task owns the `Vault` and the
`SyncEngine` outright, and every FFI call becomes a message.

#### 11.4.1 The owning task — normative

The facade MUST run exactly one long-lived task that owns the monomorphized vault and
engine by value. Nothing outside that task holds a reference to either. Concretely, the
facade wraps:

```rust
// native build (crates/misty)
struct Core {
    vault:  Vault<SqliteStore, SystemClock>,             // misty-vault
    engine: SyncEngine<NativeTransport, FileStateStore>, // misty-sync
    roster: Roster,                                      // misty-crypto; used by push_roster/revoke_device
    vault_key: VaultKey,                                 // held; MUST NOT leave the task
    lock: Lifecycle<SqliteStore, SystemClock>,           // §11.5
}

// wasm build (crates/misty): Vault<IndexedDbStore, HostClock>,
// SyncEngine<FetchTransport, MemoryStateStore>, HostClock feeds the §11.5 deadline.
```

The two identities that `Vault::open` and `SyncEngine::new` each need are produced from
one device key with `misty_sync::duplicate_identity(&DeviceIdentity)`; the task owns
both copies.

Every method the four consumers can reach is a variant of one command enum, carried
into the task over a bounded channel; the reply, an **owned** DTO (§11.2) or a flat
error (§11.3), returns on a per-call oneshot:

```rust
enum Command {
    // reads: reply carries owned DTOs, never a borrow of the vault
    ListItems      { reply: oneshot<Result<Vec<ItemView>, FacadeError>> },
    GenerateCode   { id: String, reply: oneshot<Result<CodeView, FacadeError>> },
    // writes: exclusive &mut Vault happens inside the task
    AddItem        { input: NewItemInput, reply: oneshot<Result<String, FacadeError>> },
    // async: the engine's future is awaited inside the task, not by the caller
    SyncOnce       { reply: oneshot<Result<SyncReportView, FacadeError>> },
    Unlock         { key_material: Zeroizing<Vec<u8>>, reply: oneshot<Result<(), FacadeError>> },
    Lock           { reply: oneshot<()> },
    Shutdown       { reply: oneshot<()> },
    // ...one variant per facade method
}
```

Rules:

- Command payloads and reply DTOs MUST be owned, non-generic, and `'static`. No variant
  may carry `&Item`, `impl Iterator`, `impl Into<String>`, a `Vault`/`SyncEngine`
  handle, or a closure — the borrow- and generic-returning readers are collected into
  owned DTOs (§11.2) *before* the reply is sent.
- A **synchronous** command (every read and every non-async mutator) runs to completion
  while the task holds `&mut self.vault`, then yields; the task processes these one at a
  time, so the exclusive borrow lasts exactly one command and no consumer-visible lock
  is needed.
- An **async** command (`SyncOnce`, `run`, `rotate_step`) holds `&mut self.vault` across
  `.await` points and is therefore governed by the preemption rule in §11.4.2, not left
  to block the task opaquely.
- The task MUST NOT expose a `cancel` by dropping a future from the foreign side —
  UniFFI has no drop-cancellation. Cancellation, lock, and shutdown are explicit
  `Command`s.

#### 11.4.2 Command processing and preemption — normative

A read or a synchronous mutator completes in bounded time, so the task processes those
strictly one at a time; the exclusive `&mut self.vault` they need lasts exactly the span
of one command, which is the whole serialization mechanism. An **async** command is
different: `sync_once`/`run`/`rotate_step` `.await` network I/O while holding
`&mut self.vault`, and a sync can take tens of seconds. Processing an async command
strictly one-at-a-time would block `Lock`, `Shutdown`, and the auto-lock deadline check
behind a slow round-trip — yet §11.5 *requires* the facade to drop an in-flight sync
when a lock fires. The two are reconcilable only if the loop can preempt, so the model
MUST be pinned rather than left to each implementer:

- The task runs its command loop as a `select!` over the in-flight async operation (if
  any) and the command channel. At most **one** async operation is in flight at a time.
- Because `sync_once`/`run`/`rotate_step` borrow `&mut Vault` for their whole duration —
  not merely at each `.await` — commands that also touch the vault (reads, mutators, and
  further async ops) MUST queue behind the in-flight async operation rather than
  interleave with it; the queue is the bounded command channel. A facade MUST NOT claim
  to service vault reads "in the gaps" of a sync, because the borrow spans the gaps.
- `Lock`, `Shutdown`, and a fired auto-lock deadline (§11.5) MUST preempt the in-flight
  async operation by **dropping its future** at its current `.await`, then perform the
  lock/shutdown, then fail the preempted caller with `VAULT_LOCKED`. This is the single
  place a future is dropped, and it is safe because an aborted sync loses only the
  uncommitted page (§11.5). Preemption is what keeps a slow sync from blocking a lock.
- The §11.5 deadline check runs before dispatching every command; while an async
  operation is in flight, an arriving `Lock`/lifecycle-lock event or a crossed deadline
  preempts it as above, so a sync can never extend the unlocked window past the deadline.

Two implementers who read only "one command at a time" would build incompatible cores —
one blocking every call behind a slow sync, the other not, and only one able to honor a
lock mid-sync. This subsection removes that freedom.

#### 11.4.3 `!Send` futures stay inside the task — normative

The engine's `async` methods are awaited **inside** the owning task, so their `!Send`
wasm futures are never named in any exported signature. What the FFI layer exports is
only the outer "send a `Command`, await a oneshot reply" future, whose payloads are
owned `Send + 'static` DTOs. That outer future is `Send + 'static` on native and
satisfies UniFFI's mandatory bound on exported futures and their returns; the `!Send`
transport future is sealed behind the channel and never crosses the boundary.

How the task is driven differs by target, and the difference is confined to the facade:

| Target | Task is driven by | Transport | Sleeper |
|---|---|---|---|
| native | `tokio::spawn` of the task (a `Send + 'static` loop); calls touching tokio timers/IO use `#[uniffi::export(async_runtime = "tokio")]` | `NativeTransport` (`Send`) | `TokioSleeper` |
| wasm | `wasm_bindgen_futures::spawn_local` — runs the `!Send` task on the current thread (`F: Future + 'static`, no `Send`) | `FetchTransport` (`!Send`) | `BrowserSleeper` |

`misty_sync::block_on` is **native-only** (its module is
`#![cfg(not(target_arch = "wasm32"))]`) and is a bare current-thread executor with no
timer; it is admissible only in tests that pair `MockTransport` with `MockSleeper`. It
MUST NOT drive a production task, on either target: on wasm it does not exist, and on
native it cannot make `NativeTransport`/`TokioSleeper` progress. Production drives the
task with `tokio::spawn` (native) or `spawn_local` (wasm), never `block_on`.

The facade MUST NOT require the engine's future to be `Send`. Attempting to
`tokio::spawn` a `FetchTransport`-backed future, or adding a `Send` bound anywhere on
the sync path, reintroduces exactly the constraint `Transport::request` was written to
avoid.

#### 11.4.4 Exclusive `&mut Vault` without a lock in consumer code — normative

Because the `Vault` lives *by value* inside the task and is reached only through the
command channel, the single-writer invariant is enforced by ownership, not by a mutex
the UI could forget to take. Consumer code (SvelteKit, Tauri, the extension) never holds
a `Vault`, a `&Vault`, or any lock guarding it; it holds only a channel sender. The
`&mut self.vault` needed by every mutator and by `sync_once`/`run`/`rotate_step` exists
solely inside the task.

- The facade MUST NOT wrap the `Vault` in a `Mutex`/`RwLock` and hand clones of a shared
  handle to consumers. That would move the "one writer" rule out of the type system and
  into a runtime discipline, and it does not compose with the `!Send` wasm task anyway.
  (Where §11.7 speaks of "interior mutability," it means the channel to this actor —
  never a lock around the `Vault` value.)
- `Vault::lock(self) -> S` consumes the vault by value. It is expressible only from
  inside the task, where the owned value exists; it is reached through a `Lock` command,
  never a method on a shared handle.

#### 11.4.5 The deadline is checked inside the task — normative

Auto-lock is a stored absolute deadline the task evaluates on every wake; §11.5 is its
normative home (states, transitions, the injected clock, and why it is a deadline rather
than a timer). Here only the actor's obligation is stated: the task MUST evaluate the
§11.5 deadline as the first step of dispatching every command and whenever an in-flight
async operation yields (§11.4.2); if it has passed the task relocks — dropping the
working key material so `ZeroizeOnDrop` fires — before serving the command. A call
arriving on a locked vault returns `FacadeError` with `code = VAULT_LOCKED` (§11.3),
never a panic and never a block.

#### 11.4.6 `crates/misty-ffi` is a thin message-passing shim — normative

`crates/misty-ffi` contains no vault, sync, crypto, or lock logic. Its only jobs are to
marshal owned DTOs across the UniFFI/wasm-bindgen boundary and to move `Command`s and
oneshot replies to and from the actor task in `crates/misty`.

- Every exported function MUST reduce to: build the owned request DTO, send one
  `Command`, `await` (or, in the native test harness only, block on) the oneshot reply,
  and return the owned reply DTO or the flat `FacadeError`. No business rule, no secret
  handling, and no borrow of core state lives in `misty-ffi`.
- `misty-ffi` MUST NOT introduce generics, lifetimes, borrows, `&mut self` interfaces,
  or data-carrying enums on the exported surface (§11.2, §11.3). It is the only crate
  that names UniFFI and wasm-bindgen; `misty` and everything beneath it stay
  binding-agnostic, which is what lets one shared conformance suite (§11.8) run the
  *real* actor — `Vault<MemoryStore, HostClock>` + `MockTransport` — behind both
  bindings and the SvelteKit mock alike.

### 11.5 Lifecycle state machine

The facade is the sole owner of lock state. There is exactly one lock decision in
Misty, it lives in `crates/misty`, and the four app shells (web/wasm, extension,
desktop, mobile) do not get a vote. §9.1 already worked this out for the extension —
"auto-lock MUST be an **absolute deadline timestamp** checked on every worker wake,
never a `setTimeout`" — and the reason generalizes: a shell that owns its own timer
re-derives the MV3 service-worker bug on every platform that can suspend a process. An
idle iOS app, a slept laptop, and a reaped MV3 worker are the same event to the vault,
and a fired timer is exactly the mechanism that does not survive any of them. So the
lock *decision* is a deadline the facade checks whenever it is next poked; §11.5.4 adds
the one piece §9.1 did not need — how a live, event-quiet process gets poked at all.

The facade holds exactly one of two states. This type is internal — it names the
non-boundary `Vault<S, C>` and is generic over the monomorphized store and clock
(§11.1): `SqliteStore` + `SystemClock` on native, `IndexedDbStore` + `HostClock` on
wasm. It **MUST NOT** cross the FFI boundary; only the erased, owned DTO
`LockState { locked: bool }` does.

```rust
enum Lifecycle<S: VaultStore, C: Clock> {
    // Ciphertext only. No VaultKey, no plaintext Item in memory.
    Locked   { store: S },
    // Live vault owns the VaultKey; deadline is an injected-clock timestamp.
    Unlocked { vault: Vault<S, C>, deadline: Deadline },
}
```

`Locked` retains only the store `S`, whose `StoredEnvelope.envelope` bytes are
ciphertext, and holds no `VaultKey`. `Unlocked` owns a live `Vault<S, C>` produced by
`Vault::open(store, clock, vault_key, device, roster)`, which took the `VaultKey`,
`DeviceIdentity`, and `Roster` by value; the vault is the only in-memory holder of the
unwrapped `VaultKey`.

#### 11.5.1 Transitions — normative

`now()` is the injected host clock (§11.5.4), never `std::time`. `AUTO_LOCK_TIMEOUT_MS`
defaults to `60_000` (§9, "default 60s").

| Event | From | To | Effect |
|---|---|---|---|
| unlock succeeds (passphrase → KDF → `VaultKey`, or biometric / WebAuthn PRF / OS keystore → `VaultKey`) | `Locked` | `Unlocked` | `Vault::open(store, clock, vault_key, device, roster)`; record `deadline = now() + AUTO_LOCK_TIMEOUT_MS` |
| unlock fails | `Locked` | `Locked` | remain locked; exponential backoff (§9); the `VaultKey` candidate, if any, is dropped so `ZeroizeOnDrop` fires |
| `lock()` (explicit, host- or user-initiated) | `Unlocked` | `Locked` | cancel in-flight sync (§11.5.3), then `Vault::lock(self) -> S`; the returned `S` becomes the `Locked` store, and the consumed `VaultKey`, `DeviceIdentity`, and `Roster` are dropped — `VaultKey`'s `ZeroizeOnDrop` clears it |
| auto-lock: `now() >= deadline`, observed at a wake | `Unlocked` | `Locked` | identical to `lock()` |
| `backgrounded` / `screen_locked` / `will_sleep` (shell event) | `Unlocked` | `Locked` | identical to `lock()`, **immediately**, regardless of `deadline` |
| `user_activity` (shell event) | `Unlocked` | `Unlocked` | `deadline = now() + AUTO_LOCK_TIMEOUT_MS` |
| fail-closed error | `Unlocked` | `Locked` | identical to `lock()` |

**"Error" means an unknown-state error, not any error.** A fail-closed lock fires only
when the in-memory vault may be inconsistent — the same philosophy as §10 rule 8's
`panic = "abort"` ("failing closed beats continuing in an unknown state"). Routine
`VaultError`/`SyncError` values (`NoSuchItem`, `DuplicateAccount`, a validation
rejection, a `Transport` failure) are returned to the caller and **MUST NOT** lock the
vault; locking on every `NoSuchItem` is the security control annoying its way into being
disabled that §9.1 warns about.

#### 11.5.2 Operations permitted per state — normative

- In `Unlocked`: every vault reader and mutator, code generation, sync, enrollment,
  roster, and rotation operation is available (each surfaced as owned DTOs per §11.2).
  Every such call, and every reported lifecycle event, **MUST** evaluate the deadline
  (the wake check, §11.5.4) *before* doing its work.
- In `Locked`: `unlock(...)`, lifecycle-event reporting, and the `LockState` query
  **MUST** be available. Stateless helpers that touch no vault plaintext — importer
  format sniffing, `otpauth://` URI parsing — **MAY** be available. Every operation that
  reads or writes the vault, generates a code, or needs the `VaultKey` **MUST** return
  `FacadeError` with `code = VAULT_LOCKED` (§11.3). It **MUST NOT** panic and **MUST
  NOT** block waiting for an unlock (§10 rule 8).

#### 11.5.3 In-flight sync on lock — normative

`SyncEngine::sync_once`/`run` borrow `&mut Vault<VS, C>`, and `Vault::lock(self)`
consumes the vault by value, so the borrow checker already forbids locking while a sync
borrow is live. The facade **MUST** therefore drop the in-flight sync future at its
current `.await` before calling `lock(self)` — the preemption the actor loop provides
(§11.4.2). This drop is internal to the facade's owning task, not a foreign-side
cancellation: UniFFI has no future-drop cancellation, so `lock` is an explicit command,
never reliance on the host dropping a `Promise`/`suspend fun`.

Aborting mid-sync is safe and **MUST** lose no committed state: every applied page is
written under `VaultStore::transaction` (atomic), and progress is persisted through the
`StateStore` cursor, so a dropped `sync_once` re-pulls from `SyncState.cursor` on the
next unlock. At most the uncommitted current page is discarded; no envelope is
half-written and no plaintext is exposed. The resumable `rotate_step` loop is unaffected
— rotation resumes from `RewrapProgress.remaining` after the next unlock.

#### 11.5.4 The clock is injected; the deadline is checked on wake — normative

There is no usable `std` clock on `wasm32-unknown-unknown` — `Instant::now()` does not
work in the browser — so the facade **MUST NOT** call `std::time::Instant::now()` or
`SystemTime::now()` directly. `now()` is an **injected host capability** (`HostClock`):
`performance.now()` / `Date.now()` on wasm, `Instant` / `SystemTime` on native. The
deadline check compares injected-clock readings only.

- The injected clock **MUST** continue to advance while the host is suspended, so a
  reading taken at wake reflects real elapsed wall time including the sleep. A clock
  that pauses during suspend would let a sleeping device outlast its deadline, which is
  precisely the failure §9.1 forbids.
- The facade evaluates `now() >= deadline` at every **wake** — defined as: before it
  processes any FFI command, whenever a lifecycle event is reported, and whenever a
  driven future (e.g. sync) is re-polled or yields (§11.4.2). If the deadline has
  passed, it transitions to `Locked` **before** doing anything else the wake was for.
  **A suspended device that wakes past its deadline is already `Locked`; it never
  briefly serves a code from an expired session.**
- If the clock appears to move **backwards** between readings, the facade **MUST** treat
  it as a fail-closed lock, not clamp and continue. A rewound clock is either tampering
  or a bug, and either way the safe reading of the deadline is "expired".

**A lock timer is forbidden; a wake-only poll is required.** The deadline above is the
sole *authority* for the lock decision and the *backstop* for suspended or killed
contexts — that is what makes worker death and device sleep safe, and it is why no shell
may own a lock timer (a fired timer decides the lock and dies with the process, reviving
the MV3 bug). But "checked on wake" only fires the lock when *something* pokes the
facade, and a long-lived, event-quiet process — a desktop app left open, a foreground
mobile app the user walked away from — may receive no FFI call and no OS event for far
longer than the timeout, leaving the `VaultKey` resident in RAM past the deadline. To
close that, on any target with a live event loop the **facade** (never the shell)
**MUST** schedule a recurring **wake-only poll** — a timer whose *only* effect is to
re-invoke the deadline check — at an interval `≤ AUTO_LOCK_TIMEOUT_MS`. Because the poll
carries no lock state and makes no lock decision, losing it (a reaped MV3 worker, a
suspended process) is harmless: the deadline still locks on the next real wake. That
distinction is the whole point — a shell-owned *lock* timer is forbidden; a
facade-owned *wake-only* poll that merely re-runs the deadline check is required — so
that on a live idle process the `VaultKey` is dropped and zeroized within one interval
of expiry, while §9.1's survive-worker-death property is preserved intact.

The three OS signals (`backgrounded`, `screen_locked`, `will_sleep`) lock immediately on
receipt; the deadline is the backstop for the idle timeout and for the case where a
signal is never delivered because the process was killed or suspended without warning.
All three mechanisms — immediate signals, the wake-checked deadline, and the wake-only
poll — are required; none subsumes the others.

#### 11.5.5 The shell's minimal responsibility — normative

The shells report events; they do not decide. Each shell **MUST** forward the lifecycle
events its platform exposes and **MUST NOT** implement its own lock timer, the wake-only
poll (§11.5.4 puts that in the facade), any lock decision, hold the `VaultKey`, or
persist any unwrapped state:

| Shell signal | Reported as | Facade action |
|---|---|---|
| app moved to background / tab hidden | `backgrounded` | lock now |
| OS screen lock engaged | `screen_locked` | lock now |
| device entering sleep | `will_sleep` | lock now |
| user interaction (keypress, tap, foreground) | `user_activity` | extend deadline |

A shell **MUST NOT** infer a lock without an event (no "this looks idle" heuristic), and
it **MUST** treat a missed event as survivable, because the deadline backstop and the
facade poll cover it. The facade owns the transition, the `VaultKey`, and the clock
comparison; the shell owns nothing but the messenger role and the OS hooks that fire it.

#### 11.5.6 Residual risk, stated rather than buried

- **A compromised host clock can defeat auto-lock**, because the monotonic clock is
  necessarily injected — the core cannot read a trustworthy clock on
  `wasm32-unknown-unknown`, so it must trust the value the shell supplies. A host that
  reports a frozen `now()` keeps an unlocked vault unlocked. The gap is survivable
  because a host that can lie about time can already read process memory, so this grants
  no capability an attacker at that privilege level lacks; the compensating control is
  that the `VaultKey` is dropped and zeroized on every real lock path, so the exposure
  window is bounded by the shortest genuine lifecycle event that does fire. It is
  disclosed in the README's threat notes rather than implied away.

### 11.6 Secrets crossing the FFI boundary — stated rather than implied away

The facade (`crates/misty`) and its bindings (`crates/misty-ffi`) are the one place in
the system where secrets leave Rust's control. UniFFI copies values by value into a
Kotlin/Swift `data class`/`String`; wasm-bindgen hands a JS `string` or a plain object.
This subsection states the gap that creates, what it touches, and the contract that
keeps it survivable.

**A secret that crosses into a host `String` cannot be zeroized, and no care on the Rust
side changes that.** `misty_otp::SecretBytes` and every key type — `VaultKey`,
`ItemKey`, `RecoveryKey`, `KdfKey`, `EpochKey` — implement `Zeroize` + `ZeroizeOnDrop`
(§2.2, §3), but those destructors govern only memory Rust owns. A platform `String` (JS,
Kotlin, Swift) is immutable and GC-managed: the runtime may intern it, copy it on
concatenation, and free it whenever it chooses, with no destructor we control.
`Zeroize` stops at the boundary. This is in direct tension with §9's `Memory` rule —
"no secret in a `String`" — which we enforce inside the core but cannot enforce in the
host runtime. What makes the gap survivable is keeping every crossing small, brief, and
low-value: the core holds the durable secrets, only non-secret DTOs and short-lived
display values ever leave it, and any secret buffer entering the core is zeroized on the
Rust side the instant it is consumed. A leaked 6–8 digit code is worthless once its
window closes (`MAX_PERIOD = 3600` s, default 30 s); a passphrase is never held as a
`String` on our side to leak. Like the extension's certificate-pinning gap (§9.1), this
is listed in the README rather than implied away.

The affected values, by exact source type and direction (`in` = host→core, `out` =
core→host, `—` = MUST NOT cross):

| Value | Concrete type | Dir | Ruling |
|---|---|---|---|
| Backup / KDF passphrase | `passphrase: &[u8]` in `misty_crypto::backup::{seal,open}`, `KdfParams::derive_key` — no `Passphrase` newtype exists | in | Cross as an owned `Vec<u8>`; `Zeroizing`-wrap and drop before the call returns |
| Vault PIN / item secret | `misty_otp::SecretBytes` via `Edit::pin`, `NewItem::new` (inside `OtpConfig`), `Vault::repair_secret` | in | Become `SecretBytes` at the first opportunity; never retain the host copy |
| Imported credential bytes | importer input `&[u8]`; `ImportedItem` is deliberately not `Serialize` | in | Bytes cross once, become `OtpConfig`/`SecretBytes` inside the core |
| Generated OTP code | `misty_otp::Code` (`value() -> &str`, `into_value() -> Zeroizing<String>`), window from `CodeWindow.valid_until_ms` | out | Allowed; the accepted exception, see rule 4 |
| Recovery kit | `misty_crypto::recovery::RecoveryKit` — `words: Vec<&'static str>` (the *order* is the secret), `compact: String`, `qr: String` | out | One-time display exception, see rule 5 |
| Vault / item / kdf / epoch keys | `VaultKey`, `ItemKey`, `KdfKey`, `EpochKey` (`expose_secret() -> &[u8; KEY_LEN]`) | — | MUST NOT cross in any encoding |
| Recovery Key raw bytes | `RecoveryKey::expose_secret()` (§2: "never leaves the device") | — | MUST NOT cross as raw bytes (only the encoded kit above may) |
| Device identity secrets | `DeviceIdentity::{export_ed25519_secret,export_x25519_secret}() -> Zeroizing<[u8;32]>`, `diffie_hellman(&self, their_public: &[u8;32]) -> Result<Zeroizing<[u8;32]>>` (§2: private key non-exportable) | — | MUST NOT cross |
| Cleartext secret-string helpers | `SecretBytes::{to_base32,to_hex,expose_secret}`, `OtpUri::to_uri() -> Zeroizing<String>`, `ImportedItem::to_uri()`, `misty_importers::export::{uri_list,plaintext_json}`, `misty_vault::encode_item()`, `ItemSet::fingerprint()`, `misty_otp::raw::*` | — | MUST stay inside the core; not exposed as facade methods — except `plaintext_json` behind the §2.5 plaintext-export gate (rule 5) |

Ciphertext is not a secret. Sealed envelopes (`StoredEnvelope.envelope`,
`RemoteChange.envelope`), the wrapped-key recovery blob (`recovery::wrap_vault_key ->
Vec<u8>`), and backup files (`backup::seal -> Vec<u8>`) are E2EE outputs and cross
freely as opaque `Vec<u8>` (base64 per §6.1.1). This rule governs cleartext key and
secret material, never the vault's encrypted output.

#### 11.6.1 The mitigation — normative

1. **Minimize.** The facade MUST hold the durable secrets — `VaultKey`, the `Roster`,
   `DeviceIdentity`, and every `Item.secret` — inside the owned, monomorphized core and
   MUST NOT expose any accessor that returns them. Every value crossing to the host MUST
   be either a non-secret DTO or one of the short-lived display values named above. The
   item DTO the facade returns is the redacted `ItemView` (§11.2) — which carries
   `has_pin` and **no** secret or PIN field — **never** the core `Item` or the
   importer's `ImportedItem`, both of which carry `SecretBytes`.

2. **Passphrases enter as owned buffers, zeroized on our side.** Every facade entry
   point taking a passphrase MUST accept an owned byte buffer (`Vec<u8>`), MUST NOT
   accept a `String`, and MUST zeroize it (`Zeroizing`, or explicit `zeroize()`)
   immediately after the KDF/seal/open call that consumes it returns — on both the
   success and error paths. The binding SHOULD collect the passphrase into a mutable
   byte/char buffer (Swift `[UInt8]`, Kotlin `CharArray`, JS `Uint8Array`) rather than a
   `String` and clear it after the call. The text-input widget's backing `String` is
   beyond our reach; **that residue is the irreducible core of this gap.**

3. **Never return long-lived key material.** The facade MUST NOT return raw `VaultKey`,
   `ItemKey`, `RecoveryKey`, `KdfKey`, `EpochKey`, or any `DeviceIdentity` secret
   (`export_ed25519_secret`, `export_x25519_secret`, `diffie_hellman`) across the
   boundary in any encoding. Key material leaves the device only as ciphertext, through
   the existing sealed-blob paths.

4. **Displayed OTP codes are the accepted exception.** A generated `Code` MUST be handed
   out only as a `CodeView` — its formatted digits plus its `CodeWindow` (so the host
   can expire it) — MUST be produced on demand rather than pre-computed and cached across
   the boundary, and the host SHOULD release the reference once `valid_until_ms` has
   passed. We accept that this code lives in a platform `String` for at most one period
   (`MAX_PERIOD = 3600` s, default 30 s). This is the only steady-state secret egress,
   and it is stated here rather than hidden.

5. **The recovery kit and a plaintext export are one-time, gated exceptions.**
   `RecoveryKit.words` / `compact` / `qr` MAY cross only at kit-generation time, MUST be
   presented for the single write-it-down / scan step, and the host SHOULD discard every
   string it built the moment the user dismisses that screen; the raw `RecoveryKey`
   bytes still MUST NOT cross (rule 3). A `plaintext_json` export — the whole vault in
   cleartext, the largest single secret egress — MAY cross only behind the §2.5 gate
   (the exact `PLAINTEXT_EXPORT_CONFIRMATION` phrase **and** a fresh biometric/PIN
   check), MUST be streamed to the user's chosen destination rather than retained, and
   the host SHOULD discard the string the moment the write completes.

6. **Conformance.** The shared binding-conformance suite (§11.8) MUST assert that no
   exported facade method returns a forbidden type from the table's `—` rows — the
   boundary surfaces DTOs, not secret-bearing core types — so a regression that widens
   the gap fails CI rather than shipping.

### 11.7 Bindings realization

`crates/misty` is the one Rust API; `crates/misty-ffi` is the thin crate that lowers it
to the two foreign toolchains. UniFFI generates the Kotlin and Swift shells from
`crates/misty-ffi`; wasm-bindgen exposes the *same* facade to the web app and the
extension. Neither toolchain, and no foreign consumer, ever sees `misty-vault`,
`misty-sync`, `misty-otp`, `misty-crypto`, or `misty-importers` directly — every one of
those crates is quarantined behind the facade, which is the only place the boundary
types (§11.2's owned DTOs, the §11.3 error taxonomy, the §11.4 owning actor) exist. This
keeps §0's promise of one implementation for every platform and satisfies §10 rule 8:
nothing reachable from FFI may `panic!`.

The two toolchains do not accept the same Rust shapes, and the differences are
load-bearing. The facade layer MUST reduce to constructs both accept:

| Facade construct | UniFFI (Kotlin / Swift) | wasm-bindgen (JS / TS) | What MUST hold |
|---|---|---|---|
| Owned record DTO | `record` → `data class` / `struct` | serde-serialized plain object (`serde-wasm-bindgen` / Tsify) | DTOs MUST be owned, non-generic, `'static`, serde-(de)serializable. No `&Item`, `Vec<&Item>`, `impl Iterator`, or `Vault<S, C>` may appear. |
| Data-carrying enum (flattened error, `Conflict`, sync outcomes) | sealed class / enum with associated values — **supported** | fielded enums **not supported** (only C-style; wasm-bindgen #2407) | Every fielded enum MUST lower to a plain object with a discriminant string field. The taxonomy stays flat so a UniFFI enum and a JSON object represent it identically. |
| Error → failure | error `enum` (impl `std::error::Error`) → thrown exception | rejected `Promise` carrying a `{ code, … }` `JsValue`; no native error-enum concept | Stability lives in an explicit `code` field, **never** the enum discriminant — neither toolchain guarantees discriminant stability and wasm-bindgen will not carry it at all. |
| `async fn` | `suspend fun` / Swift `async`; exported future + returned DTO MUST be `Send + 'static` | `Promise` (resolve = `Ok`, reject = `Err`); future may be `!Send`, driven by `spawn_local` | FFI-exported futures and their reply DTOs are `Send + 'static`; the `!Send` browser `fetch` future is confined to the wasm actor task. |
| The vault handle | `Arc`-heap interface, MUST be `Send + Sync`, MUST NOT expose `&mut self` | opaque handle or module-level actor | The handle is fronted by a channel to the owning actor (§11.4.4), never a `Mutex`/`RwLock` around the `Vault` value; `lock(self) -> S`, `&mut Vault`, and `impl Into<String>`/`impl FnOnce` arguments are erased into commands. |
| Monotonic clock | `Instant` / `SystemTime` (native) | **no `std::time` clock exists** on `wasm32-unknown-unknown` | Time MUST be an injected host capability (`HostClock`, §11.5); the facade MUST NOT call `std::time::Instant::now()`. |

The facade owns the vault and erases both generic parameters of
`Vault<S: VaultStore, C: Clock>` before anything foreign is generated:

```rust
// crates/misty erases the generics; crates/misty-ffi never names one.
// native:  Vault<SqliteStore, SystemClock>       // SqliteStore is cfg(not(wasm32)); SystemClock absent on wasm
// wasm:    Vault<IndexedDbStore, HostClock>       // HostClock (facade-defined) fed by the injected §11.5 clock
// mock  (§11.8 Rule 1): Vault<MemoryStore, HostClock> + MockTransport + MockSleeper
```

#### 11.7.1 UniFFI → Kotlin and Swift — the mobile and desktop-shell path

`crates/misty-ffi` annotates the erased facade with UniFFI and generates Kotlin
(Android) and Swift (iOS / macOS). Records MUST use only owned UniFFI types — no
references, smart pointers, generics, or lifetimes — which is why the facade wraps a
concrete monomorphization (`Vault<SqliteStore, SystemClock>` on native) rather than
exposing the generic handle, and returns owned DTOs (§11.2) cloned out of the
borrow-returning readers.

- Exported interfaces are heap-allocated behind `Arc` and MUST be `Send + Sync`, and
  MUST NOT expose a `&mut self` method — it will not compile. The one-writer rule that
  `misty-vault` enforces with `&mut self` is therefore re-expressed as the actor's
  channel (§11.4.4), not carried across the boundary.
- Every exported future and the DTO it resolves to **MUST be `Send + 'static`**. UniFFI
  requires this because the foreign runtime may poll `rust_future_*` from different
  threads; it is not optional. The contract MUST NOT be designed around UniFFI's
  `wasm-unstable-single-threaded` escape hatch — it is explicitly unstable, and native
  is genuinely multi-threaded.
- Any native facade call that touches tokio timers or IO (the `NativeTransport` /
  `TokioSleeper` path) MUST be exported with `#[uniffi::export(async_runtime = "tokio")]`
  so a tokio context is live while the foreign executor polls.
- UniFFI has **no future-drop cancellation**. Shutdown, auto-lock, and abort MUST be
  explicit facade commands or a checked flag — never reliance on dropping a future
  (§11.4.2). This is the same reason §9.1's auto-lock is a wake-checked deadline rather
  than a timer.
- Generics are rejected by `uniffi::export` at compile time, which is the compiler
  enforcing the erase-the-generics rule for us.
- **The boundary DTOs MUST NOT be re-declared in `crates/misty-ffi`.** They are registered
  with `#[uniffi::remote(Record)]` / `#[uniffi::remote(Enum)]`, which makes UniFFI emit
  scaffolding for `crates/misty`'s own type and no copy of it. A hand-written mirror
  record plus a `From` conversion would work and MUST NOT be used: it is a second
  definition of the contract, it can drift from the facade while both compile, and it
  would let the UniFFI leg and the wasm leg carry *different* values from the same call —
  which is precisely the §11.8 failure mode, reintroduced inside the crate whose job is to
  prevent it. The remote declaration is checked against the real type, so a field added,
  removed, renamed, or retyped upstream fails this crate's build. `crates/misty` still
  names neither toolchain (§11.7).
- The **error MUST cross as a single-variant enum** whose payload is a record carrying
  `code`, `message`, and `retryable`, with `code` as the frozen `UPPER_SNAKE` string
  (§11.3.1). Not one variant per `ErrorCode`: `ErrorCode` is `#[non_exhaustive]` and
  grows, a foreign enum is closed, and the flat shape is what makes the thrown UniFFI
  value and the rejected wasm object the same fixture.
- The three fields **MUST live on a nested record, not directly on the error variant**,
  and the reason is a platform collision rather than taste. UniFFI lowers a Kotlin error
  enum to a subclass of `kotlin.Exception`, which already declares `message`; a variant
  field of that name produces `conflicting declarations: val message` and the generated
  Kotlin does not compile. Renaming the field per-platform is the alternative and is
  worse — JavaScript would branch on `message` while Kotlin and Swift branched on
  something else, and §11.3.2's contract is that all of them read the same vocabulary.
  The cost is one access step on the native bindings (`error.detail.code`); the wasm
  rejection object is unaffected and stays flat, because JavaScript has no error-enum
  concept for the payload to collide with (§11.7.2).

  This was found by *compiling* the generated Kotlin. Generation succeeded on code that
  does not build, which is the entire argument for §11.8.2's requirement that every
  binding **run** the suite.

##### Apple targets — what actually needs macOS

Two separable things have been conflated before and MUST be kept apart, because doing so
decides how much of this contract is testable per pull request:

| Needs | Runner | Gate |
|---|---|---|
| Compiling and **running** the generated Swift | any platform with a Swift toolchain — swift.org ships Linux builds | runs on every pull request |
| The Apple **platform artifact**: `.xcframework` slices for `aarch64-apple-ios`, the two simulator architectures, and the two `*-apple-darwin` architectures | macOS — `xcodebuild -create-xcframework` and the iOS SDKs exist only there | `main`, and PRs labelled `apple` |

The Swift leg of the §11.8.2 suite MUST therefore run on the cheap runner. Deferring it to
a macOS job would mean an API break in the Swift binding stays invisible until P7/P8 opens
Xcode, which is the P4 mistake (§6.1.1) with a longer fuse.

The Apple artifact MUST be a **static** archive (`crate-type = ["staticlib", …]`), not a
dynamic framework: a dynamic framework on iOS has to be embedded and signed, and the
generated Swift API layer MUST be shipped as *source* compiled into the consumer rather
than frozen inside the binary, so its `async` methods keep Swift's calling convention.
Bindings MUST be generated in `--library` mode from a slice that was actually built, so
the metadata comes from the artifact that ships.

#### 11.7.2 wasm-bindgen → web app and extension

The identical facade compiled to `wasm32-unknown-unknown` is exposed to JS by
wasm-bindgen: `async fn` becomes a `Promise` (a resolved value for `Ok`, a thrown
`JsValue` for `Err`), and the deliberately-`!Send` `fetch` transport future
(`FetchTransport`, `BrowserSleeper`) is driven by `wasm_bindgen_futures::spawn_local` on
the current thread. DTOs MUST cross as serde-lowered plain objects, **not** as opaque
`#[wasm_bindgen]` handle classes with a `.free()` lifecycle, so JS receives the same
copied-by-value records UniFFI produces.

Two wasm-only toolchain limits are real and are stated here rather than discovered later:

- **wasm-bindgen cannot carry a data-carrying enum** (#2407 — only C-style/fieldless
  variants cross). The flattened error (§11.3), `Conflict`, and the sync-outcome enums
  therefore MUST be lowered to plain objects with an explicit discriminant field and a
  separate stable `code`. There is no way to close this in the toolchain; the mitigation
  is that the taxonomy is kept flat and object-shaped on both sides so the UniFFI enum
  and the JS object are the same fixture (§11.8). The stability contract lives in `code`,
  so the discriminant never needs to survive.
- **There is no usable `std::time` clock on `wasm32-unknown-unknown`** — `Instant::now()`
  does not function in the browser, and `misty_otp::SystemClock` is absent on that
  target. Time is the injected `HostClock` of §11.5, and the §9.1 auto-lock deadline (an
  absolute timestamp checked on every worker wake, plus the facade wake-only poll) is
  compared against injected-clock values only. This is the structural reason the
  extension's killed-worker auto-lock in §9.1 works at all.

The secrets-boundary gap for a code or passphrase entering JS is stated once,
normatively, in §11.6; it applies to this target unchanged.

### 11.8 The conformance gate — one suite, every binding

P4 shipped a client and a server that each passed their own suite against their own mock
and then did not interoperate: they had silently disagreed on the signing context, nonce
length-prefixing, enrollment-poll disambiguation, and a field name. §6.1.1 records the
fix — the wire encoding was made normative, and an implementation of either side "MUST
have a test proving interoperation with the other, running the real code on both sides."
P5 has the same geometry with twice the blast radius: one contract consumed by four
shells through two toolchains, with P6 scheduled to start against a "mock core" the
moment the facade is declared done. The two rules below apply the §6.1.1 discipline
ahead of time.

#### 11.8.1 Rule 1 — the mock core is a build configuration, not a reimplementation

The "mock core" that P6 and every binding develops against MUST be `crates/misty`
itself, compiled with `misty_vault::MemoryStore` as its `VaultStore` and
`misty_sync::MockTransport` (backed by the in-process `MockServer`, driven by
`MockSleeper`) as its transport. All three already exist, are re-exported at their crate
roots, and are available on every target including `wasm32`. A hand-written TypeScript,
Kotlin, or Swift mock MUST NOT be introduced.

- The rationale is the P4 failure mode restated: a separate mock can drift from the real
  core while both sides stay green, so their agreement proves nothing. A
  `MemoryStore`/`MockTransport` build cannot drift — it *is* the core, exercising the
  real merge, the real envelope layer, and the real sync state machine, only with the
  disk and network swapped for deterministic in-memory doubles.
- `MockServer` is the SPEC §6.1 server in-process; it is cheap to clone (shared state),
  lets two simulated devices talk to one server for the enroll and revoke steps (with
  `duplicate_identity` handing one device's keys to both `Vault::open` and
  `SyncEngine::new`), and exposes `set_time_ms` so signed time is fixed. `MockSleeper`
  removes real delays from the sync loop. These are the properties that let one scripted
  flow produce identical results in three places (Rule 2).

#### 11.8.2 Rule 2 — one shared conformance suite, run by every binding

P5's exit gate is a single conformance suite, authored once as a scripted flow plus
fixtures, that MUST execute against the Rust facade and through **every** generated
binding, asserting identical results against identical fixtures. The scripted flow is:

```
enroll → add → generate → sync → lock → unlock → revoke
```

- The suite MUST run in the headless-browser wasm bundle (covering the web app and the
  extension), through the generated Kotlin, and through the generated Swift — and
  against the native Rust facade directly, which is the surface the Tauri desktop shell
  links. Same fixtures, same order, same asserted outputs on each.
- Each leg MUST exercise the **binding surface**, not the Rust facade underneath it. A
  wasm leg that awaits `misty::Facade` futures and reads Rust structs tests nothing the
  native leg does not already cover: the serde lowering, the `Promise` wrapping, and the
  `err_to_js` rejection object all go unexecuted, so a break in any of them ships green.
  The wasm leg therefore awaits `Promise`s and reads properties, and builds its input as
  a plain object — which is also the only way the serde *enum* forms (`kind: "Totp"`)
  are checked at all. The same rule is why the UniFFI legs drive
  `native::MistyFacade` rather than the facade it wraps.
- **Generating a binding is not running one, and CI MUST NOT accept the former as the
  latter.** Asserting that `uniffi-bindgen` produced a file proves the toolchain lowered
  the API; it does not prove the result compiles, and it certainly does not prove the
  answers match. Generation reported success on Kotlin that failed to build (see
  §11.7.1's note on the `message` collision). Every leg compiles and executes.
- Assertions MUST be on DTO values and on the stable error `code` field — never on
  message text — so localization and wording can change without breaking the gate, and
  so the flat error object and the UniFFI error enum are checked to represent the same
  thing (§11.3, §11.7).
- **Expected outputs MUST be literals in each leg, not values the core hands over.** The
  *inputs* MAY be served to foreign code at runtime (`mock_fixtures()`), and SHOULD be, so
  no foreign language re-derives a device id or a key and then re-derives it differently.
  The expected outputs MUST NOT be: a suite that asks the core what to expect asserts the
  core against itself and would stay green through any change they all inherit. They are
  written down once (`crates/misty-ffi/conformance/fixtures.json`) and pinned as literals
  in every leg, so changing one means changing all of them — which is the review moment
  this section exists to create.
- `generate` MUST be asserted as an **exact code value**, not a digit count. The clock is
  pinned, so the value is determined; a binding that lowered the secret or the algorithm
  wrongly would still produce six digits and pass a length assertion. This is the same
  reason §6.1.1 requires byte-identical signed payloads rather than "a signature verified".

- The flow MUST be deterministic across all runtimes, and the driver differs by target:
  the native Rust-facade run MAY use `block_on` with `MockSleeper`; the wasm run — where
  `block_on` does not exist (§11.4.3) — MUST be driven by `spawn_local` on the headless
  browser's real event loop, with `MockSleeper` collapsing every sync delay to nothing so
  no wall-clock time passes; the Swift and Kotlin runs are driven by the foreign
  runtime's own executor over the tokio runtime the exported object owns (§11.7.1). On all
  of them, the clock is pinned (an injected fixed `HostClock`;
  `misty_otp::FixedClock` / `MockServer::set_time_ms` on the Rust side), so `generate`
  yields the same `Code` value everywhere. Fixtures follow §8's discipline — obvious
  dummy secrets, since this is a public repository, each reproducible from its recipe by
  the suite.
- This **supersedes** the roadmap's original P5 gate ("WASM bundle loads in a browser,
  UniFFI generates Kotlin + Swift"). That the bundle loads and the bindings generate
  proves the toolchain wired up; it says nothing about whether the four consumers compute
  the same answer from the same input. The ROADMAP P5 row is updated to this gate.

This is §6.1.1's rule — prove interoperation by running the real code on both sides, not
two green suites against two mocks — with the "both sides" widened to the Rust facade and
each of its generated bindings. It is the P4 interop lesson applied to a four-consumer
phase before the consumers are built, rather than after they have quietly disagreed.









