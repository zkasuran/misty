<!--
SPDX-FileCopyrightText: 2026 The Misty Authors

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Misty

A cross-platform, end-to-end-encrypted TOTP/HOTP authenticator. Every device, real
sync, no phone number, no lock-in.

Misty is a Rust core compiled natively for desktop and mobile and to WebAssembly for
the web, wrapped in one SvelteKit UI shipped through Tauri 2. Its sync server is a
zero-knowledge versioned blob store: it holds opaque, client-signed envelopes keyed by
a random vault id and has no user table to breach. Device identity is a per-device
Ed25519 keypair; the trusted-device roster is an encrypted, client-signed vault item,
so a hostile server cannot add a device. Recovery is an offline kit, not an escrow.

> **Status: pre-alpha, unaudited. Do not put a real secret in this yet.** There is no
> release, no external audit, and no migration guarantee until the `spec-v1` tag. See
> [Status](#status).

The name is checked clear where it has to be: `misty` is unclaimed on crates.io and in
the Debian package namespace. The facade crate is published as plain `misty` rather
than `misty-core`, because an unrelated project already holds that name.

## Table of contents

- [Why another authenticator](#why-another-authenticator)
- [Design](#design)
- [What Misty defends, and what it does not](#what-misty-defends-and-what-it-does-not)
- [Repository layout](#repository-layout)
- [The crates in detail](#the-crates-in-detail)
- [The sync server](#the-sync-server)
- [The UI](#the-ui)
- [Supported OTP types and import formats](#supported-otp-types-and-import-formats)
- [Building and testing](#building-and-testing)
- [Roadmap and status](#roadmap-and-status)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Why another authenticator

| | Authy | Google Auth | Aegis | 2FAS | Ente Auth | **Misty** |
|---|---|---|---|---|---|---|
| Desktop app | discontinued | no | no | no | yes | yes |
| Web + browser extension | no | no | no | extension only | web | yes |
| E2EE sync (not just backup) | encrypted backup | opt-in | no | cloud file | yes | yes |
| Export your own seeds | **no** | QR only | yes | yes | yes | yes |
| No phone number / email required | requires phone | Google account | n/a | optional | email | **none** |
| Same-site accounts distinguishable | poorly | poorly | yes | partial | partial | **first-class** |
| Self-hostable sync | no | no | n/a | no | yes | yes |
| Steam / mOTP / 7–8 digit | partial | no | yes | partial | yes | yes |
| Hardware-key-protected vault | no | no | no | no | no | yes |

The two design decisions that fall out of that table and drive everything below:

- **No lock-in.** Misty reads every competitor's export and writes an export every
  competitor can read. Refusing to build that is a decision the project has already
  made against itself — see [`crates/misty-importers`](crates/misty-importers).
- **Real end-to-end-encrypted sync, not "encrypted backup."** The server is a blind
  relay. It never sees a plaintext, a secret, an issuer, or which devices a vault
  trusts.

## Design

Read [`docs/SPEC.md`](docs/SPEC.md) before writing code — it is the authoritative
contract every crate implements against: threat model, key hierarchy, byte-exact
on-disk and on-wire formats, CRDT merge rules, and the engineering gates.
[`docs/ROADMAP.md`](docs/ROADMAP.md) has the phase plan and the exit gate for each
phase.

The shape of the system:

```
        one SvelteKit UI  (apps/ui)
                │  loads the core as …
    ┌───────────┴────────────┐
  wasm bundle              native lib
 (web, extension)      (desktop, mobile)
    │  both go through the same binding shim  │
    └───────────┬────────────┘
         crates/misty-ffi         wasm-bindgen (JS)  ·  UniFFI (Kotlin/Swift)
                │
          crates/misty            the facade: one owned, non-generic, 'static API
                │
   ┌────────────┼─────────────┬───────────────┬──────────────┐
misty-otp   misty-crypto   misty-vault    misty-sync    misty-importers
 (codes)    (envelopes,    (item model,   (offline-first (every rival's
            keys, KDF)     CRDT, SQLite)  sync client)   export format)
                                              │
                                    server/misty-server
                              zero-knowledge blob store (axum)
```

Every crate compiles to `wasm32-unknown-unknown` (the browser extension has no SQLite
and no native network, so this is a hard gate), except `misty-server`. Every crate is
`#![forbid(unsafe_code)]` with the single documented exception of `misty-ffi`, where
`wasm-bindgen` and UniFFI generate the `unsafe` at the edge.

Three properties hold across the whole workspace, enforced by lints and tests rather
than by convention:

- **No `unwrap`/`expect`/`panic!`/slice-indexing** on any path reachable from parsed
  input or FFI. Tests may use them freely.
- **Secrets are redacted and zeroized.** Any type that can hold key material is
  `Zeroize + ZeroizeOnDrop` and renders `[redacted]` in both `Debug` and `Display`,
  with a test asserting the rendering contains neither the bytes nor their encoding.
- **Formats are pinned to frozen golden bytes,** and every parser has both a
  hostile-input corpus that runs on stable and a `cargo-fuzz` target.

## What Misty defends, and what it does not

The one question every design decision was checked against:

> What does an attacker with a full sync-server database dump **and** the `/v1/time`
> signing key learn?

The answer, which the server's test suite exists to keep true: **envelope sizes
bucketed to 256 bytes, item counts, and write timing. Nothing else.** No plaintext, no
secret, no issuer, no account name, no note, no group, no user identity (there is no
user table), no usable bearer token, no client IP in anything durable, and not even
which devices a vault trusts.

A hostile server also **cannot** get an unverified envelope merged, delete an item,
rewind or reorder the change feed, add a trusted device, or walk a client's clock —
every one of those is refused client-side before any decryption, and each has a named
test in [`crates/misty-sync`](crates/misty-sync) and
[`server/misty-server`](server/misty-server).

What is honestly **not** defended is stated plainly in [`SECURITY.md`](SECURITY.md) —
including the parts that cannot be, such as certificate pinning on the web
(`fetch` gives a page no access to the TLS session), and screen-capture blocking in a
browser tab.

## Repository layout

```
crates/misty-otp        RFC 4226 / 6238 HOTP+TOTP, plus Steam, mOTP, Battle.net, Yandex
crates/misty-crypto     envelope format, KDF tiers, key hierarchy, recovery kit, roster
crates/misty-vault      item model, CRDT merge engine, encrypted SQLite storage
crates/misty-importers  every competitor's export format, in and out
crates/misty-sync       offline-first sync client (the half that trusts nothing)
crates/misty            the facade: the one owned, non-generic API the UI builds against
crates/misty-ffi        the binding shim: lowers the facade to wasm-bindgen + UniFFI
server/misty-server     zero-knowledge versioned blob store (axum)
apps/ui                 SvelteKit UI, shared by every target
docs/                   SPEC.md (the contract), ROADMAP.md, LICENSING.md
ci/                     gate checks: binding parity, license split, phase gates
```

Every crate carries its own detailed `README.md` — those are the authoritative
reference for that component, and each ends with a "what an auditor should look at
first" section. The tables below summarize them.

## The crates in detail

### `misty-otp` — the one-time-password engine

`MIT OR Apache-2.0` (the one permissively-licensed crate; see [License](#license)).
Turns `(secret, moving factor)` into a displayable code and converts between that
configuration and an `otpauth://` URI. No I/O, no global state, no clock of its own,
no allocation before an input is length-checked.

- RFC 4226 (HOTP) and RFC 6238 (TOTP) with **no deviations**, tested against the RFC
  Appendix vectors including the intermediate HMAC and truncated integer, not just the
  final code.
- Vendor variants real users have: **Steam**, **mOTP**, **Battle.net**, and
  **Yandex.Key** — each reproducing a published third-party implementation (quirks
  included, such as Yandex dropping a zero sign-byte and using only the first 16
  bytes of the secret), with the reasoning documented per variant.
- An `otpauth://` parser liberal about shape (case, padding, spacing, unknown params)
  and strict about meaning (a repeated known parameter is an error, not a coin flip),
  with a `parse → to_uri → parse` round-trip property proven by tests and a fuzz
  target.

### `misty-crypto` — the cryptographic core

The only place in Misty where cryptography happens. Implements SPEC §2 byte for byte;
pure Rust, no C, so it builds for `wasm32`. No `ed25519-dalek`/`argon2`/etc. type
appears in the public API, so a dependency bump is never a breaking change for callers.

- **Key hierarchy:** Recovery Key → Vault Key → per-epoch Epoch Keys → per-item Item
  Keys, with Argon2id KDF tiers (Interactive / Moderate / Sensitive). Attacker-supplied
  KDF parameters are **rejected, not clamped** — clamping would derive a different key
  and report "wrong passphrase" for a merely unusual file.
- **Envelope format:** XChaCha20-Poly1305 payload under a wrapped item key, Ed25519
  signature over the header, item id bound into both AEAD contexts so an envelope
  cannot be relocated to another item. Decryption is *unreachable by the type system*
  before the roster and signature checks pass.
- **Backup file** (`.mistybak`), **Recovery Kit** (24 BIP-39 words / Crockford Base32 /
  QR), device **identity, roster, and enrollment**.
- Authoritative vectors (RFC 9106 Argon2id, RFC 8032 Ed25519, BIP-39, …) are labeled as
  authoritative; self-generated ones are labeled as regression-only and cross-checked
  against independent implementations (libsodium, PyNaCl, argon2-cffi) before freezing.

### `misty-vault` — item model, CRDT merge, encrypted storage

A consumer of `misty-crypto` and `misty-otp`, not a re-implementer of either. Owns the
CBOR encoding of an item payload, the merge rules over it, and the encrypted SQLite
rows it lands in (SPEC §3–§5).

- **Every mutable field carries a hybrid logical clock** and merges by an explicit,
  documented rule: last-writer-wins, max-wins (HOTP counters never regress), OR-Set
  (concurrent tag adds are never lost), per-device G-counters for usage, min-wins for
  creation time, and a tombstone that wins only over strictly earlier edits.
- **Divergent secrets are never resolved by guessing** — the item forks and *both* are
  kept, with the forked id derived (not drawn) under the vault key so every device
  reaches the same split.
- **The schema has no searchable plaintext column and no index over anything but the
  primary key**, so its shape cannot answer "does this vault have an account at
  `binance.com`". Search runs over the decrypted in-memory model.
- CRDT convergence (commutativity, associativity, idempotence) and crash-injection
  (a failure at every write position leaves the vault at its pre-merge state) are both
  property-tested.

### `misty-importers` — read every rival's export, write one everyone can read

`#![forbid(unsafe_code)]`, no network code, no C dependency (the extension imports files
too). Its central safety property is **per-row failure isolation**: one malformed row is
one failed outcome, the batch continues, and a user importing 200 accounts never loses
199 to one bad line.

- **Preview before write** shares the exact import code path (it imports and drops the
  items), so the two cannot disagree, and the preview holds no secrets.
- **No secret in any error, ever** — asserted over every importer, every fixture, and
  every hostile input, in base32, hex, and raw-decimal renderings.
- Verified corrections other importers get wrong (e.g. FreeOTP's HOTP counter is one
  behind the `otpauth://` convention; Authy's own tokens are 7 digits on a 10-second
  step), each checked by reading the vendor's source.
- Encrypted formats that could not be verified against a real vault are **refused with
  a clear message rather than half-implemented**, because an unverified decryptor tells
  a user with the correct password that it is wrong.

### `misty-sync` — the offline-first sync client

Implements the client half of SPEC §6. Emits **no log records at all**; what happened
comes back as a report, what went wrong as an error that names no secret, envelope
byte, or item id in `Display` or `Debug`.

- **A write is never lost:** the outbound queue is *derived* from what the vault stores
  versus what the server last confirmed, so the vault's commit *is* the enqueue — there
  is no window where a write exists locally and is not queued.
- **A write is never applied twice** (every push carries `If-Match`), **progress is
  committed before it is claimed** (a page is merged, then the cursor is saved), and
  **nothing unverified is merged.**
- A large table of hostile-server behaviors — tampered envelope, rewound `seq`,
  descending page, endless feed, replayed `/v1/time`, forged roster, `409` loops — each
  with the client's response and the test that proves it.
- TLS 1.3 with **certificate pinning on native builds** (no root store at all — the pin
  is the only trust anchor). On wasm, pinning is **absent and cannot exist**; the
  residual risk is stated plainly.

### `misty` — the facade

The one owned, non-generic, `'static` API the four consumers (web/wasm, extension,
desktop, mobile) build against (SPEC §11). It owns the live vault and sync engine,
monomorphizes their generics away, and presents everything as owned DTOs and one flat
error whose stability lives in a machine-readable code string. A **single-owner actor**
holds the vault by value; every call is a command on a channel.

### `misty-ffi` — the binding shim

Lowers the facade to two foreign toolchains and holds **no logic of its own**: web and
extension via `wasm-bindgen` (each method returns a `Promise`), mobile and desktop via
UniFFI → Kotlin + Swift. DTOs are not re-declared here — UniFFI generates scaffolding
for the facade's *own* types via `#[uniffi::remote(..)]`, so there is no conversion
layer to drift. One shared conformance suite runs the same
`enroll → add → generate → sync → lock → unlock → revoke` flow through five legs
(native Rust, exported UniFFI object, generated Swift, generated Kotlin, and the wasm
bundle in headless Chrome) asserting identical DTOs and error codes against identical
fixtures.

## The sync server

[`server/misty-server`](server/misty-server) — one binary, one SQLite file, no daemon
to operate. A versioned blob store that holds opaque envelopes keyed by a random 16-byte
vault id, with **no user table**: nothing to enumerate and nothing to phish.

```sh
# A signing key for /v1/time. Publish the public half; clients pin it (SPEC §6.5).
export MISTY_TIME_SIGNING_KEY="$(openssl rand -base64 32)"
export MISTY_DB=/var/lib/misty/misty.sqlite3
export MISTY_BIND=127.0.0.1:8080
# Optional but strongly recommended on anything reachable from the internet:
export MISTY_REGISTRATION_TOKEN="$(openssl rand -hex 16)"

cargo run --release -p misty-server
```

Or with Docker, built from the repository root:

```sh
docker build -f server/misty-server/Dockerfile -t misty-server .
docker run -p 8080:8080 -v misty-data:/var/lib/misty \
  -e MISTY_TIME_SIGNING_KEY="$(openssl rand -base64 32)" \
  misty-server
```

**The server does not speak TLS, on purpose** — terminating TLS in the one component
whose selling point is that it holds nothing worth stealing would add a certificate
store and an ACME client for no benefit. Run it behind nginx, Caddy, or Traefik with
TLS 1.3, bound to loopback or a private interface. See its README for the full endpoint
table, the wire encoding rules, every configuration variable, and the "what the
operator can and cannot see" breakdown.

## The UI

[`apps/ui`](apps/ui) — SvelteKit, one surface shared by the web app, the browser
extension, and the Tauri desktop and mobile shells. **The core it runs against is not a
mock:** `scripts/build-core.sh` compiles `misty-ffi` to wasm and the tab loads the real
vault, real CRDT merge, real envelope layer, and real sync state machine, with
`MemoryStore` + `MockTransport` standing in for disk and network. That cannot drift from
the core, because it *is* the core.

```sh
cd apps/ui
npm install
npm run dev        # builds the core, then vite dev
npm run check      # svelte-check over types and templates
npm test           # release build, then the full flow and a11y suites
```

Everything is tested against the **production build** (the SPEC §9 CSP with no
`unsafe-inline` only exists in built output), with an axe-core WCAG 2.2 AA audit over
every route in **both** light and dark themes. Two gaps are stated honestly rather than
papered over — there is no passphrase/biometric unlock yet (the facade exposes no KDF
call), and `otpauth://` intake is not yet a facade call — both because the honest thing
was to stop rather than ship something that looks finished. See the app README.

## Supported OTP types and import formats

**Generation** — HOTP (RFC 4226), TOTP (RFC 6238, SHA-1/256/512, 1–10 digits,
1–3600s period), Steam, mOTP, Battle.net, and Yandex.Key.

**Import** — `otpauth://` and `otpauth-migration://` (Google Authenticator), Aegis
(plain + encrypted), 2FAS, andOTP (plain + encrypted), FreeOTP and FreeOTP+, Bitwarden
Authenticator, Ente Auth, Raivo, LastPass Authenticator, Proton Pass, KeePassXC (XML +
CSV export), generic CSV and JSON, plus best-effort Twilio Authy. Encrypted formats that
could not be verified against a genuine vault, and formats with no export at all
(Microsoft Authenticator), are refused with an explanation rather than half-supported.
See the [`misty-importers` README](crates/misty-importers) for the full per-format
status table and the caveats on each.

**Export** — `otpauth://` URI list, printable QR-sheet data, and a gated plaintext JSON
export.

## Building and testing

Prerequisites: a Rust toolchain (pinned in `rust-toolchain.toml`) and the wasm target.
No other system dependency is required for the Rust core.

```sh
git clone https://github.com/zkasuran/misty
cd misty
rustup target add wasm32-unknown-unknown
cargo test --workspace
```

The CI gates, which every change must pass (see [`CONTRIBUTING.md`](CONTRIBUTING.md)):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
cargo deny check                                  # bans openssl, native-tls, libsodium-sys, …
cargo build -p misty-otp -p misty-crypto --target wasm32-unknown-unknown
reuse lint                                        # every file has machine-readable license info
python3 ci/check-otp-permissive.py                # misty-otp's dependency closure stays permissive
```

CI additionally runs the wasm build for every core crate, the five-leg binding
conformance suite (including generated Swift and Kotlin on Linux, and the wasm bundle in
headless Chrome), the UI flow and a11y suites against the production build, a bounded
fuzz smoke run over every target, and — on `main` and PRs labeled `apple` — the macOS
`.xcframework` build. Fuzz targets live in per-crate `fuzz/` sub-workspaces and need a
nightly toolchain:

```sh
cargo install cargo-fuzz
cd crates/misty-crypto && cargo +nightly fuzz run envelope_open
```

`ci/check-gates.sh` verifies each roadmap phase's *specific* exit gate, naming the test
that carries it, and reports `SKIP` (never a pass) for anything a plain checkout cannot
verify.

## Roadmap and status

**Pre-alpha, unaudited. Do not put a real secret in this yet.** There is no release, no
external audit, and no migration guarantee until the `spec-v1` tag.

Phases build in order, each with an explicit exit gate (full detail in
[`docs/ROADMAP.md`](docs/ROADMAP.md)):

| Phase | Scope | Status |
|---|---|---|
| P0 | Foundation: workspace, spec, CI | met |
| P1 | OTP engine + crypto core | met |
| P2 | Vault: model, CRDT, storage | met |
| P3 | Importers / interop | met |
| P4 | Sync client + server | met |
| P5 | Facade + FFI bindings | **met** — one conformance suite across five legs |
| P6 | UI | **met** — full flows + a11y against the mock core |
| P7 | Desktop (Tauri) | Apple packaging landed early; shell remains |
| P8 | Mobile (Android) | pending |
| P9 | Web app + browser extension | pending |
| P10 | Platform depth: autofill, CLI, YubiKey, … | pending |
| P11 | Release hardening: reproducible builds, SBOM, signed release | pending |

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the setup, the CI gates, and the testing bar.
Read [`docs/SPEC.md`](docs/SPEC.md) first — it is the contract, and if code and spec
disagree that is a bug in one of them, to be fixed in the same change. Highlights:

- **Tests are the deliverable, not the receipt.** Published vectors must be used where
  they exist; format code needs frozen golden bytes; parsers need a hostile-input corpus
  *and* a fuzz target; merge logic needs property tests; secrets must be provably
  redacted.
- **No telemetry, analytics, or crash-reporting SDK. Ever.** A PR that adds one is
  closed rather than reviewed.
- **No C dependencies in the core**, which must keep compiling to wasm.
- Sign off commits (`git commit -s`, DCO). There is no CLA. One logical change per PR;
  prefix the subject with the area (`otp:`, `crypto:`, `vault:`, `sync:`, `ui:`,
  `docs:`, `ci:`, `deps:`).

Found a vulnerability? Report it privately — see [`SECURITY.md`](SECURITY.md), not the
issue tracker.

## License

Two licenses, on purpose. Full map and reasoning in
[`docs/LICENSING.md`](docs/LICENSING.md).

- **`crates/misty-otp`** — [MIT](LICENSES/MIT.txt) OR
  [Apache-2.0](LICENSES/Apache-2.0.txt). Take it. A correct, exhaustively vectored
  RFC 4226/6238 implementation is worth more to the ecosystem shared than hoarded, and
  every authenticator reimplementing it from scratch is a worse outcome for users than
  one implementation with the RFC vectors actually wired up.
- **Everything else** — [AGPL-3.0-or-later](LICENSE). Anyone may run, audit, fork, and
  self-host. Anyone offering Misty as a service owes their users the source — and since
  Misty ships a web app, that clause is doing real work here, not decoration.

Apache-2.0 is one-way compatible with AGPL-3.0, so the arrow points inward: the AGPL
crates consume the permissive one and never the reverse, and `misty-otp` must never gain
a copyleft dependency (including any other `misty-*` crate). CI enforces both directions.

The repository is [REUSE 3.3](https://reuse.software/spec-3.3/) compliant, so every
file's license is machine-readable rather than a matter of interpretation.
