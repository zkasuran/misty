<!--
SPDX-FileCopyrightText: 2026 The Misty Authors

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# `misty-server` — the sync service that is worthless to whoever steals it

Implements [`docs/SPEC.md`](../../docs/SPEC.md) §6: a versioned blob store that
holds opaque envelopes keyed by a random 16-byte `vault_id`.

There is **no user table**. No email, no phone, no username, no password hash.
There is nothing to enumerate and nothing to phish, and every design decision in
this crate was checked against one question:

> What does an attacker with a full database dump **and** the `/v1/time` signing
> key learn?

The answer, which `tests/` exists to keep true: envelope sizes bucketed to 256
bytes, item counts, and write timing. Nothing else.

One binary, one SQLite file, no daemon to operate. AGPL-3.0-or-later — this is the
component people run as a service, so the network clause is the point.

## Quickstart

```sh
# A signing key for /v1/time. Publish the public half; clients pin it (SPEC §6.5).
export MISTY_TIME_SIGNING_KEY="$(openssl rand -base64 32)"
export MISTY_DB=/var/lib/misty/misty.sqlite3
export MISTY_BIND=127.0.0.1:8080
# Optional but strongly recommended on anything reachable from the internet:
export MISTY_REGISTRATION_TOKEN="$(openssl rand -hex 16)"

cargo run --release -p misty-server
```

The first log line prints `time_public_key`. That hex string is what a client
pins; if you lose it, every client's signed-time check breaks until they re-pin.

Or with Docker, built from the repository root:

```sh
docker build -f server/misty-server/Dockerfile -t misty-server .
docker run -p 8080:8080 -v misty-data:/var/lib/misty \
  -e MISTY_TIME_SIGNING_KEY="$(openssl rand -base64 32)" \
  misty-server
```

### TLS terminates somewhere else

This process does not speak TLS, and that is deliberate rather than unfinished.
Terminating TLS here would mean a certificate store, an ACME client, and a rustls
stack inside the one component whose whole selling point is that it holds nothing
worth stealing. Run it behind nginx, Caddy, or Traefik with TLS 1.3, and bind it
to loopback or a private interface.

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Forwarded-For $remote_addr;  # needs MISTY_TRUST_FORWARDED_FOR=1
}
```

Set `MISTY_TRUST_FORWARDED_FOR=1` **only** when a proxy you control is the sole
path to the socket. Without a proxy, the header is client-controlled and believing
it lets anyone pick which rate-limit bucket they land in. The value used is the
*last* element of `X-Forwarded-For` — the address your proxy observed — not the
first, which is whatever the client claimed.

## Endpoints

### Wire encoding (SPEC §6.1.1)

| Field kind | Encoding |
|---|---|
| ids (`vault_id`, `device_id`, `item_id`, `enroll_id`), nonces | lowercase hex |
| signatures, public keys | lowercase hex |
| envelopes, enrollment blobs | standard base64, padded |
| `version` | opaque printable-ASCII token — a JSON **string**, never a number |
| `seq`, `unix_ms`, counts | JSON numbers |

Uppercase hex is rejected rather than folded, and neither base64 alphabet is
accepted for a hex field. One field, one spelling.

Hex for the short fields is not a taste call. A hex string is *also* well-formed
base64 — every character of `[0-9a-f]` is in the base64 alphabet — so for a
**variable-length** field like a nonce, accepting both is unsound rather than
untidy: 64 characters of `[0-9a-f]` are simultaneously 32 bytes of hex and 48 bytes
of base64, and a signature bound to "whichever the decoder guessed" is bound to
nothing. Standard base64 is also not query-string safe, since its `+` arrives as a
space under form decoding — which is what previously pushed `/v1/time` into a third
alphabet. Hex needs no query-string variant. Base64 stays for envelopes and
enrollment blobs, which are large and appear only in JSON bodies.

This server originally emitted standard base64 for the short fields and base64url
for the `/v1/time` nonce. `misty-sync` implemented §6.1.1. Two independently green
test suites, two mocks, no interoperation — which is why §6.1.1 now also requires a
test that runs the real code on both sides.

Bearer tokens stay unpadded base64url. §6.1.1's table does not cover them, and they
are opaque handles no peer ever decodes; the `version` row sets the precedent for
"opaque printable-ASCII token".

| Method | Path | Auth | Success | SPEC |
|---|---|---|---|---|
| `POST` | `/v1/auth/challenge` | none | `200 {nonce, expires_at}` | §6.1 |
| `POST` | `/v1/auth/verify` | challenge signature | `200 {access_token, refresh_token, expires_in, token_type, vault_id, device_id}` | §6.1 |
| `POST` | `/v1/auth/refresh` | refresh token | as `verify` | §6.1 |
| `POST` | `/v1/vaults/{vid}/devices` | access token | `201 \| 200 {device_id, result}` | §6.1 |
| `GET` | `/v1/vaults/{vid}/changes?since={seq}&limit={n}` | access token | `200 {changes[], next_seq, has_more}` | §6.1 |
| `PUT` | `/v1/vaults/{vid}/items/{item_id}` | access token | `200 {seq, version}` + `ETag` | §6.1 |
| `DELETE` | `/v1/vaults/{vid}/items/{item_id}` | access token | `200 {seq, version}` | §6.1 |
| `GET` | `/v1/time?nonce={hex}` | none | `200 {unix_ms, nonce, sig}` | §6.1, §6.5 |
| `POST` | `/v1/enroll/begin` | none | `201 {expires_at}` | §6.3 |
| `GET` | `/v1/enroll/poll/{enroll_id}?want=request\|response` | none | `200 {ready, …}` | §6.3 |
| `POST` | `/v1/enroll/complete` | none | `200 {}` | §6.3 |
| `GET` | `/v1/quota` | access token | `200 {bytes_used, item_count, row_count, limits}` | §6.1 |
| `GET` | `/healthz` | none | `200 {status}` | operational |

Every failure *this crate produces* is the same JSON shape, so a client never has
to parse prose:

```json
{ "error": "conflict", "message": "version conflict", "version": "2", "envelope": "…" }
```

The exception is a request malformed at the HTTP level — an invalid request
target, a request line longer than hyper's limit — which hyper answers itself,
before any Misty code runs, with an empty body and a `4xx` status.

`error` is a stable machine-readable code: `bad_request`, `unauthorized`,
`forbidden`, `not_found`, `method_not_allowed`, `conflict`,
`precondition_required`, `payload_too_large`, `unsupported_media_type`,
`rate_limited`, `quota_exceeded`, `internal`.

`conflict` covers two shapes. A `409` on an **item** carries `version` and
`envelope`; a `409` on a create-only resource (`/v1/enroll/begin`,
`/v1/enroll/complete`, a device id taken by a different key) carries neither,
because it has neither. An earlier version answered the second case with
`version: 0`, which a client could reasonably have misread as "no such item".

### Authenticating

1. `POST /v1/auth/challenge {vault_id, device_id}` → `{nonce}`, 64 lowercase hex
   characters. This answers identically for a vault that exists and one that does
   not; it is not an existence oracle.
2. Sign, with the device's Ed25519 key:

   ```text
   "misty/server/auth/v1" ‖ vault_id[16] ‖ device_id[16] ‖ LE32(nonce_len) ‖ nonce
   ```

   over the **decoded** nonce bytes, not the hex string.
3. `POST /v1/auth/verify {vault_id, device_id, nonce, sig, ed25519_pub?}`, all hex,
   with `nonce` echoed exactly as it arrived. `ed25519_pub` is required only for a
   device the server has never seen; for a known device the stored key is used and
   a mismatching one is refused.

Access tokens last 15 minutes. Refresh tokens rotate on every use, and presenting
a consumed one revokes the entire chain — see below.

### Writing an item

```http
PUT /v1/vaults/{vid}/items/{item_id}
Authorization: Bearer …
If-None-Match: *            # create; or If-Match: "{version}" to update
Content-Type: application/json

{"envelope": "<standard base64>"}
```

A failed precondition is `409` with the current `version` and `envelope`, so the
client merges locally and retries. Version `"0"` in a `409` means "no such item".
The server never merges and never looks inside an envelope.

`version` is opaque: echo it back in `If-Match` and do not parse it. It happens to
be a decimal counter today, and a client that computed `version + 1` would work
until it did not.

### `envelope` is nullable, and the `null` is deliberate

A `DELETE` reclaims an item's bytes but **keeps the row**, because dropping it
would let `version` go backwards and break every subsequent `If-Match`. So a row
can legitimately have a version and no bytes, and both the change feed and a `409`
body serialise that as an explicit `"envelope": null` — present, never omitted,
never an empty string. A client must record the version from such a row or its next
`If-Match` is wrong, so it has to be able to tell "no bytes" from "this server did
not answer". Same principle as the `deleted` flag: the server may forget bytes, but
only a signed tombstone deletes an item.

## What the operator can and cannot see

### Can see

| Visible | Why it is unavoidable |
|---|---|
| A random 16-byte `vault_id` per vault, and `device_id`s within it | It is the storage key. It maps to no person. |
| The number of items in a vault, and how many are tombstones | A row count is not hideable by a blob store. |
| Each envelope's **length** | The client has already padded every payload to a 256-byte bucket (SPEC §2.4), so this is bucket granularity and no finer. `tests/schema_zero_knowledge.rs` proves a 2-byte and a 200-byte payload store identically. |
| When each item was written, to the millisecond | `updated_at` and `seq`. Write timing is the accepted residual in threat model `A1`. |
| Each device's Ed25519 **public** key | Needed to check the auth signature. |
| Which `enroll_id`s are in flight, and for a few minutes their two opaque blobs | The relay has to hold them. It cannot read either. |

### Cannot see

* **Any plaintext.** Not an OTP secret, not an issuer, not an account name, not a
  note, not a group. `tests/migrations.rs` dumps every value of every column in a
  live database and asserts that not even an 8-byte fragment of a known plaintext
  is present.
* **Which devices a vault trusts.** The `devices` table is an *access-control
  cache*. Trust is the client-signed roster, an ordinary encrypted vault item
  (SPEC §6.2). A row invented by the operator produces writes every client
  rejects, and `tests/hostile_server.rs` proves it against the real
  `misty-crypto`.
* **A usable bearer token.** Only BLAKE2b-256 hashes of tokens are stored.
* **A client IP address, in anything durable.** Addresses exist only in in-memory
  rate-limit buckets, are dropped when a caller goes idle, and are never
  formatted into a log line. `tests/logging.rs` captures at `TRACE` and greps.
* **An `item_id` in a log line.** The access log records a sanitised path in
  which every 32-hex segment becomes `{id}`.
* **The vault key it relays during enrollment.** `tests/hostile_server.rs` carries
  a real §6.3 grant through the relay and asserts the key's bytes are not in what
  the server stored.

### What the operator *can* do, and why it does not matter

Delete rows. That is the only destructive power a hostile operator has, and it is
survivable for two reasons: SPEC §6.1 forbids clients from acting on the `deleted`
flag, so a server cannot make a client forget anything; and `version` is monotonic
per item, so a client that still holds the plaintext simply re-uploads. Tested.

It can also inject a device, forge a roster, tamper with a byte of an envelope, or
move an envelope to a different `item_id`. Every one of those is detected
client-side before any decryption is attempted, and each has a test.

## What an auditor should look at first

In this order. Each item is a place where a mistake would be quiet.

1. **`src/store/sqlite.rs`, the `MIGRATIONS` constant.** Every column, with a
   comment saying which of the four harmless categories it belongs to (a
   server-assigned id, a client-chosen random id, a server-clock timestamp, or the
   opaque blob). If a column is not in one of those categories, the zero-knowledge
   claim is false. `tests/schema_zero_knowledge.rs` pins the list.
2. **`routes/mod.rs`'s encoding helpers.** `decode_hex`, `decode_hex_fixed`, and
   `decode_blob` are the only decoders on this surface, and none of them falls back
   to a second alphabet. §6.1.1 notes that a *fixed*-width field would survive
   accepting both and then says that is "a reason the mistake is survivable, not a
   reason to make it" — so if a `.or_else(...)` appears in one of them, that is the
   regression.
3. **Anywhere `envelope` is touched.** `grep -n envelope src/` should show it only
   being moved: decoded from base64, passed to the store, read back, encoded. No
   parse, no hash, no length recorded beyond the blob's own. The crate does not
   depend on `misty-crypto` outside dev-dependencies, so it *could not* interpret
   an envelope.
4. **`routes/auth.rs`, `auth_payload`.** What a device signs. If it did not name
   both the vault and the device, a signature would transfer between them. The
   signature covers the **decoded** nonce bytes, not the hex string — a peer that
   signed the string would interoperate right up until an encoding changed.
5. **`store/sqlite.rs`, `allocate_seq` and its callers.** `seq` allocation and the
   row write share one transaction. If they did not, a reader could see `seq = n`
   committed while `n - 1` was in flight, and a client would silently never learn
   about one item. `tests/concurrency.rs` walks the feed one row at a time after 24
   concurrent writes.
6. **`consume_refresh_token`.** Reuse detection and family revocation, in one
   transaction. A version that revoked outside the transaction would have a window.
7. **`routes/mod.rs`, `sanitise_path` and `observe`.** The access log's only path
   source. Note that `axum`'s `tracing` feature is disabled in `Cargo.toml`: with
   it on, `axum::serve` logs `connection {peer} accepted` at `TRACE`, which puts a
   client IP in a durable log the moment an operator raises the log level.
8. **`rate_limit.rs`.** The only place an `IpAddr` exists. `Key`'s `Debug` is
   redacted so a future `tracing::debug!(?key)` cannot leak one.
9. **`Precondition` and `version_token`.** One integer for both HTTP forms, with
   `0` meaning "absent", rendered to the wire as an opaque string. The subtle part
   is that `DELETE` never resets `version`, which is what stops a stale `If-Match`
   from winning after a delete — and which is why `envelope` has to be nullable.

Two known sharp edges, stated rather than hidden:

* The workspace release profile sets `panic = "abort"`, so a reachable panic in a
  handler is a process-level denial of service, not a `500`. The crate therefore
  denies `unwrap`, `expect`, `panic!`, and slice indexing outside tests via clippy
  lints in `src/lib.rs`. There is no `CatchPanicLayer`, because with `abort` there
  would be nothing to catch. Two panic sources those lints do **not** cover were
  found and closed, and both are worth checking after any edit: `String::truncate`
  on a byte offset (see `clip` in `routes/mod.rs`) and `i64` addition on a
  configured TTL (see `ttl_ms`). `tests/hostile_input.rs` covers the first with a
  900-byte JSON field name made of 3-byte characters.
* `ApiError::Internal` logs a `detail` string that originates from `rusqlite`. It
  carries no vault or item identifier, but it is the one log field this crate does
  not fully control the contents of.

## Where this deviates from SPEC §6, and why

SPEC §6 has been through one round of arbitration with this crate. Everything
below is either a gap the spec has since closed — in which case the server now
conforms and the entry records what was wrong and who moved — or a place where the
document is still incomplete.

### Where this server was wrong, and changed

SPEC §6.1.1 did not exist when this crate was written; the encoding of every short
field was left to the implementation, and this one chose standard base64 while
`misty-sync` chose hex. Both were defensible. Neither interoperated, and neither
test suite could tell, because each ran against its own mock. §6.1.1 is now
normative and **the server moved**:

| Field | Was | Now |
|---|---|---|
| `/v1/auth/challenge` → `nonce` | standard base64 | lowercase hex |
| `/v1/auth/verify` ← `nonce`, `sig`, `ed25519_pub` | standard base64 | lowercase hex |
| `/v1/vaults/{vid}/devices` ← `ed25519_pub` | standard base64 | lowercase hex |
| `/v1/time?nonce=` and → `nonce` | base64url, unpadded | lowercase hex |
| `/v1/time` → `sig` | standard base64 | lowercase hex |
| `/v1/enroll/begin` ← `x25519_pub`, `/v1/enroll/poll` → `x25519_pub` | standard base64 | lowercase hex |
| `version`, everywhere it appears | JSON number | opaque string token |
| `/v1/enroll/begin` ← `sealed_request` | that name | `enroll_request` |

The `/v1/time` case is the one worth remembering: this endpoint reached for
base64url *because* standard base64's `+` becomes a space in a query string, which
left the protocol with two base64 variants and one hex-encoded id space. Hex has no
query-string variant to need.

### Endpoints SPEC §6.1 was missing, and has since gained

* **`POST /v1/auth/refresh`.** §6.1 issued a `refresh_token` from `/v1/auth/verify`
  and never said how to redeem one.
* **`POST /v1/vaults/{vid}/devices`.** §6.3 step 4 ends with "and registers with
  the server", but §6.1 listed no endpoint that does it. Without one, the server
  would have to accept any device that turns up with a key, handing write access to
  anyone who learned a `vault_id`. Those writes would still be rejected by every
  client (§6.2), but they would consume the user's quota. So: a vault's **first**
  device bootstraps on `verify`; every later device must be vouched for by an
  already-admitted one.

Both are now in §6.1 as written here.

### Things SPEC §6.1 specified incompletely

* **What `sig` covers was undefined.** §6.1 said `{vault_id, device_id, sig}` and
  never said what is signed. That is not an implementation detail — two
  implementations would not interoperate — and the obvious reading, "sign the
  nonce", is insecure, because a bare nonce names neither the vault nor the device.
  Now normative: `"misty/server/auth/v1" ‖ vault_id ‖ device_id ‖ LE32(len) ‖
  nonce`.
* **`/v1/time` had no nonce, so it was replayable forever.** §6.5 says the signature
  exists so a network attacker cannot walk a client's effective clock — but a
  signature over a timestamp alone can be recorded once and served back
  indefinitely, which is exactly that attack. `?nonce=` is **required** and covered
  by the signature, under `"misty/time/v1"`.
* **`verify` carried no nonce**, leaving the server to guess which of a device's
  outstanding challenges is being answered. Sending it makes single-use exact.
* **Creation had no defined precondition.** §6.1 named only `If-Match: {version}`,
  and a new item has no version. `If-None-Match: *` creates, `If-Match: "0"` is
  accepted as a synonym, and a write with neither header is refused with `428`
  rather than silently becoming a blind overwrite.
* **The path/token vault match was never stated.** §6.1 did not say the `{vid}` in
  a path must equal the token's vault. It must, or a token for vault A reads vault
  B, and every other protection in the document is irrelevant. Enforced with `403`.
* **One `poll` endpoint has two readers.** §6.1 listed a single
  `GET /v1/enroll/poll/{enroll_id}`, but §6.3 has the approving device collecting
  the *request* and the new device waiting for the sealed *response*. With
  "single-use retrieval", overloading them is ambiguous: the new device's polling
  loop would consume the request it never asked for. `?want=request|response`
  names the role and defaults to `response`, the SPEC-literal reading.
* **`sealed_request` could not actually be sealed**, so it is now `enroll_request`.
  §6.3 derives the sealing key from the approver's ephemeral X25519 key, which does
  not exist until step 3 — at step 1 the new device has nothing to seal to. The blob
  is authenticated by the 6-digit confirmation code the user compares out of band,
  not encrypted. It is opaque to this server either way, but a client MUST NOT treat
  it as confidential, and an approver MUST recompute the confirmation code over the
  fetched payload before approving.
* **`envelope`'s nullability was not admitted.** A row can carry a version and no
  bytes, because `DELETE` keeps the row to keep `version` monotonic. Now normative in
  §6.1, and serialised as an explicit `null` in both the feed and a `409`.

### Status codes chosen against the obvious reading

* A failed precondition is **`409`, not `412`**, because SPEC §6.1 requires the
  response to carry the current envelope so the client can merge. `412` has no body
  contract here, and a client that got one would need a second round trip.
* An exhausted vault quota is **`507`, not `413`**. `413` tells a client to send
  less data; the actual problem is that the vault is full, and shrinking the item
  will not help. `413` is used for a single oversized envelope or body, where it is
  true. Both carry `Retry-After` (`0` for `507`: there is nothing to wait for).

### Deliberate non-changes

* **`/v1/quota` keeps its vault-free path.** The vault comes from the token. With
  no vault id in the path there is no path/token mismatch to get wrong, so the
  confused-deputy bug cannot be written.
* **`/v1/enroll/complete` stays unauthenticated**, even though the approving device
  has a token. Requiring one would tell the server which `vault_id` an `enroll_id`
  belongs to — metadata the sealed grant otherwise hides from it. The trade buys
  nothing: an attacker who posts a bogus response produces a blob the new device
  cannot unseal, and a second `complete` is refused with `409` so a race cannot
  displace a legitimate answer.
* **The server does not verify that envelopes are padded to 256-byte buckets**,
  even though `A1`'s mitigation depends on it. Checking would require knowing the
  envelope format, which is the one thing this crate refuses to know, and would
  break the day a new `kind` has a different header. §6.1 now says this in as many
  words: bucketing is a client invariant and no server check will catch a client
  that skips it.
* **Bearer tokens stay unpadded base64url.** §6.1.1's table does not cover them and
  no peer decodes them; they are opaque handles, like `version`.

## Configuration

Every value comes from the environment. A malformed value is a hard startup
failure, never a silent default: a server quietly running with a 1-byte envelope
cap would look healthy while being useless.

| Variable | Default | Notes |
|---|---|---|
| `MISTY_BIND` | `127.0.0.1:8080` | A non-loopback bind logs a warning about TLS. |
| `MISTY_DB` | `misty.sqlite3` | WAL, `synchronous=FULL`. |
| `MISTY_TIME_SIGNING_KEY` | *(generated)* | 32 bytes as hex or base64. Unset means an **ephemeral** key and a loud warning: every restart breaks every client's pin. |
| `MISTY_TIME_SIGNING_KEY_FILE` | — | Same, from a file. Preferred: the key never reaches a process listing. |
| `MISTY_REGISTRATION_TOKEN` | *(none)* | Required in `X-Misty-Registration` to bootstrap a **new** vault. Existing devices never present it. |
| `MISTY_MAX_VAULTS` | `0` (unlimited) | Instance-wide ceiling. |
| `MISTY_MAX_ENVELOPE_BYTES` | `65536` | Minimum 512. |
| `MISTY_MAX_BODY_BYTES` | derived | Defaults to the envelope cap plus base64 inflation and framing, so the two cannot drift apart. |
| `MISTY_MAX_SEALED_BYTES` | `8192` | Per enrollment blob. |
| `MISTY_MAX_ITEMS_PER_VAULT` | `10000` | Counts **rows**, tombstones included; a row is what keeps `version` monotonic. Slots are released by the tombstone sweep. |
| `MISTY_MAX_VAULT_BYTES` | `67108864` | Sum of stored envelope lengths. |
| `MISTY_DEFAULT_CHANGES_LIMIT` | `100` | |
| `MISTY_MAX_CHANGES_LIMIT` | `500` | A larger `limit` is a `400`, not a clamp. |
| `MISTY_ACCESS_TOKEN_TTL_SECS` | `900` | SPEC §6.1's 15 minutes. |
| `MISTY_REFRESH_TOKEN_TTL_SECS` | `2592000` | 30 days. |
| `MISTY_CHALLENGE_TTL_SECS` | `60` | |
| `MISTY_ENROLL_TTL_SECS` | `600` | |
| `MISTY_TOMBSTONE_RETENTION_SECS` | `7776000` | 90 days, matching SPEC §4's tombstone purge. |
| `MISTY_SWEEP_INTERVAL_SECS` | `60` | Also when idle rate-limit buckets — and therefore addresses — are forgotten. |
| `MISTY_RATE_LIMIT_VAULT_PER_MINUTE` | `120` | |
| `MISTY_RATE_LIMIT_IP_PER_MINUTE` | `600` | |
| `MISTY_RATE_LIMIT_BURST` | `60` | Bucket depth. `0` on a rate disables that limit. |
| `MISTY_TRUST_FORWARDED_FOR` | `false` | See the proxy note above. |
| `MISTY_LOG` | `info` | `tracing` filter. Even at `trace`, no address is logged. |
| `MISTY_LOG_FORMAT` | `json` | `text` for a human. |

## Operating it

* **Backups**: stop the process or use `sqlite3 misty.sqlite3 ".backup out.db"`.
  Copying the file while it is open under WAL can capture a torn state.
* **Shutdown**: `SIGINT` or `SIGTERM` drains in-flight requests before exiting. A
  server that ignored one of them would be killed mid-transaction by whichever it
  ignored.
* **Migrations** are forward-only and tracked in `PRAGMA user_version`. A database
  written by a newer binary is refused at startup rather than downgraded.
* **Rotating the `/v1/time` key** invalidates every client's pin. Publish the new
  public key before restarting.

## Tests

```sh
export CARGO_TARGET_DIR=target/agent-server
cargo test -p misty-server --all-features
```

| File | What it holds the line on |
|---|---|
| `tests/hostile_server.rs` | Injected device, forged roster, tampered byte, relocated envelope, stale/replayed write, cross-device challenge, device takeover, refresh reuse, `/v1/time` replay, recoverable deletion, two-device convergence, epoch rotation, relayed vault key |
| `tests/hostile_input.rs` | 4 GB declared body, oversized chunked body, oversized envelope, malformed base64 and JSON, deep nesting, non-UTF-8, path traversal, absurd `since`/`limit`, bad preconditions, wrong method, hostile `Authorization`, hostile nonces, and a regression guard that the pre-§6.1.1 base64 forms stay refused on every hex field |
| `tests/concurrency.rs` | Exactly one winner per race; `seq` unique, gap-free, and never rewinding under 24 concurrent writers |
| `tests/schema_zero_knowledge.rs` | The column allowlist, the forbidden vocabulary, the absence of any user-identity column, size bucketing |
| `tests/migrations.rs` | A full database dump contains no plaintext fragment and no usable token; forward-only migrations |
| `tests/logging.rs` | A live request cycle captured at `TRACE` contains no envelope byte, `item_id`, token, or address |
| `tests/limits.rs` | Rate limits with `Retry-After`, item and byte quotas, registration token, vault ceiling, sweeper |
| `tests/endpoints.rs` | Every SPEC §6.1 endpoint, happy path, over a real socket, plus the `envelope: null` shape for a reclaimed row in both the feed and a `409` |

There is no fuzz target. The CI fuzz job globs `crates/*/fuzz`, so one under
`server/misty-server/fuzz` would never run, and changing the workflow is outside
this crate's scope. The parsers this crate owns are small and total — id parsing,
percent-decoding, `If-Match`, `since`/`limit`, nonce decoding, path sanitising —
and each has an explicit hostile-input case list. Everything larger (JSON, base64)
is upstream and fuzzed there.





