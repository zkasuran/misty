# Changelog

All notable changes are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

On-disk and on-wire formats are versioned independently of the app; a change to
either is called out explicitly with its migration path.

## [Unreleased]

### Added
- Workspace foundation, CI gates, and supply-chain policy (`cargo-deny`).
- `docs/SPEC.md`: authoritative threat model, key hierarchy, byte-exact envelope and
  backup formats, CRDT merge rules, sync protocol, and engineering gates.
- `docs/ROADMAP.md`: eleven phases with explicit exit gates.
- Open-source project scaffolding: security policy, contribution guide, issue and PR
  templates.
- `docs/LICENSING.md` and REUSE 3.3 compliance, so every file's license is
  machine-readable rather than a matter of interpretation.
- `ci/check-otp-permissive.py`: walks the `misty-otp` dependency closure and fails
  the build if it ever gains a copyleft dependency.

### Added
- **`crates/misty-sync`** (`AGPL-3.0-or-later`) — offline-first sync client. The
  outbound queue is *derived*, not remembered: an item is pending exactly when the
  envelope the vault stores differs from the one the server last confirmed, so the
  vault's commit is the enqueue and no crash window exists between writing and
  queuing. Transport is behind a trait — `hyper` + `hyper-rustls` natively, `fetch` on
  wasm, a mock everywhere — with certificate pinning on native and the browser gap
  documented rather than implied away. TLS 1.3 only, as a property of the build:
  `tls12` is not compiled in.
- **`server/misty-server`** (`AGPL-3.0-or-later`) — the zero-knowledge blob store. Its
  normal dependency closure contains no Misty crate at all, so it cannot open an
  envelope even by accident; `misty-crypto` is a dev-dependency for building real
  envelopes in tests. Zero-knowledge is an executable check, not a promise:
  `the_schema_is_exactly_the_allowlist`, `there_is_no_user_table_to_enumerate`,
  `no_column_is_named_after_a_property_of_an_envelope`.
- **`crates/misty-sync/tests/interop_server.rs`** — the gate SPEC §6.1.1 now requires:
  the real client against the real server over a real socket, including two clients
  converging to byte-identical state and both signed payloads asserted byte-identical
  against the *server's* own functions rather than a transcription of the spec.
- **`docs/SPEC.md` §11 — the facade/FFI contract** P5 builds against, written before the
  code: owned, non-generic, `'static` DTOs that erase `Vault<S, C>`; one flattened
  `FacadeError` taxonomy with stable machine-readable `code`s mapping every source-crate
  error; a single-owner actor that seals the deliberately-`!Send` sync future and
  enforces exclusive `&mut Vault` without a consumer-visible lock; a `Locked`/`Unlocked`
  machine whose auto-lock is a wake-checked absolute deadline plus a facade-owned
  wake-only poll, so a live but idle process still zeroizes its key; the
  secrets-crossing-the-boundary gap stated with its mitigation; and the UniFFI /
  wasm-bindgen realization.
- **`docs/ROADMAP.md` P5 gate strengthened** to one shared conformance suite
  (`enroll → add → generate → sync → lock → unlock → revoke`) run through the wasm
  bundle, the generated Kotlin, the generated Swift, and the native facade against
  identical fixtures; the "mock core" is fixed as a `MemoryStore` + `MockTransport`
  build of the real facade, not a hand-written mock that can drift (SPEC §11.8). This
  is the P4 interop lesson (§6.1.1) applied ahead of a four-consumer phase.
- **`crates/misty`** (`AGPL-3.0-or-later`) — the P5 facade, built against SPEC §11. A
  single-owner actor owns the `Vault` and `SyncEngine` by value and turns every call
  into a channel message, so the engine's `!Send` browser future stays inside the task
  and the vault's exclusive `&mut` needs no consumer-visible lock. It presents owned,
  non-generic, `'static` DTOs (`ItemView`/`GroupView`/… carry no secret), one flattened
  `FacadeError` with a stable `ErrorCode` mapping every source-crate error, and a
  `Locked`/`Unlocked` lifecycle whose auto-lock is a wake-checked absolute deadline plus
  a facade-owned wake-only poll. Builds native and for `wasm32-unknown-unknown`;
  `tests/conformance.rs` drives two devices to code agreement through one in-process
  `MockServer` — the native slice of the §11.8 gate. Enrollment, revocation, the
  §11.4.2 preemption model, and the remaining mutators are the next increment, as is
  `crates/misty-ffi`.
- **`crates/misty`** grew to the full SPEC §11 surface: the §11.4.2 preemption model
  (a `Lock`/`Shutdown`/deadline drops an in-flight sync), device revocation + epoch
  rotation (§6.4), live device enrollment (§6.3), and the remaining mutators
  (`update`, trash/restore/delete, groups, hotp counters, `repair_secret`,
  `merge_duplicate`, sweep/purge). The native conformance suite now runs the whole
  flow: enroll → add → generate → sync → lock → unlock → revoke.
- **`crates/misty-ffi`** (`AGPL-3.0-or-later`) — the binding shim (SPEC §11.7). On
  `wasm32` it exposes the facade to JavaScript through `wasm-bindgen` (async → Promise,
  DTOs as serde objects, errors as `{ code, message, retryable }`); `wasm-bindgen`
  generates the `MistyFacade` JS + `.d.ts`. The wasm leg of the §11.8 gate passes: the
  real facade, compiled to `wasm32` with the mock core, runs the flow in headless
  Chrome (`tests/web.rs`). The UniFFI (Kotlin/Swift) leg is wired but needs CI runners
  — a JVM, and macOS for Apple — so it is not run here. *(Superseded below: both legs
  now run, and neither needed the runner it was said to need.)*
- **`crates/misty-ffi` — the UniFFI leg, and the Apple artifact** (SPEC §11.7.1).
  `native::MistyFacade` exposes the full facade to Kotlin and Swift as an `Arc`-heap,
  `Send + Sync` object with no `&mut self`: `async fn` becomes `suspend fun` / Swift
  `async`, and a failure is thrown as a flat `{ code, message, retryable }` carrying the
  same frozen `UPPER_SNAKE` code string the wasm leg rejects with. The boundary DTOs are
  **not** re-declared — every one is registered with `#[uniffi::remote(..)]`, so UniFFI
  generates scaffolding for `crates/misty`'s own types and there is no conversion layer
  that could drift, and no way for the two bindings to carry different values from the
  same call. A mirror-record-plus-`From` design was rejected for exactly that reason and
  §11.7.1 now forbids it.
- **The Swift leg of the §11.8 gate is live, and it does not need a Mac.** "Needs macOS"
  had been recorded as one claim when it was two. The Swift *language* toolchain ships for
  Linux, so `conformance/run-swift.sh` builds the library, generates Swift from that
  artifact, compiles it against `conformance/ConformanceFlow.swift`, and runs
  `enroll → add → generate → sync → lock → unlock → revoke` on the ordinary CI runner, on
  every pull request. What genuinely needs macOS is the Apple *platform* artifact, and
  `apple/build-xcframework.sh` now produces it: five static slices (iOS device, both
  simulator architectures, both `*-apple-darwin` architectures) assembled into
  `Misty.xcframework` with a SwiftPM `Package.swift` pairing that binary target with the
  generated Swift API layer. New `bindings` (Linux, always) and `apple` (macOS, gated) CI
  jobs. Deferring the Swift leg to the macOS job would have hidden a binding break until
  P7/P8 opened Xcode — the P4 mistake (§6.1.1) with a longer fuse.
- **P5's exit gate is met: the §11.8.2 suite now runs on all five legs.** The native Rust
  facade and the exported UniFFI object were already covered; the generated **Swift** and
  the generated **Kotlin** now compile and execute the flow (`conformance/run-swift.sh`,
  `conformance/run-kotlin.sh`), and the **wasm bundle** runs it in headless Chrome
  (`conformance/run-wasm.sh`). Each script fetches its own toolchain into `target/` and
  installs nothing, so a developer and CI run byte-identical commands. New
  `wasm-conformance` CI job; the `bindings` job now runs both foreign legs.
- **"The bindings generate" was accepted as a gate, and it was not one.** CI asserted that
  `uniffi-bindgen` had emitted a Kotlin file. It had, and the file did not compile: the
  error payload's `message` field collides with `kotlin.Exception.message`, which UniFFI
  lowers every error enum onto. The three fields moved to a nested record, so the
  vocabulary stays `code`/`message`/`retryable` on every binding rather than being renamed
  per platform; the wasm rejection object is unchanged, since JavaScript has no error enum
  to collide with. §11.7.1 records the constraint and §11.8.2 now requires every leg to
  *run*, not merely to be produced.
- **The wasm leg was testing the wrong layer.** It awaited `misty::Facade` futures and read
  Rust structs, so `future_to_promise`, the serde lowering, and the `err_to_js` rejection
  object — everything the wasm projection actually does — went unexecuted. It now awaits
  `Promise`s, reads properties with `Reflect::get`, and builds its input as a plain JS
  object, which is also the only way the serde enum forms (`kind: "Totp"`) are checked.
  §11.8.2 makes "each leg exercises the binding surface, not the facade underneath it" a
  rule.
- **The Apple job has now actually run, on `macos-26-arm64`, and passes.** It was the last
  claim in this phase resting on inspection rather than execution. All three steps are
  green: the workspace builds and its 64 suites pass on macOS, the generated Swift runs
  the §11.8.2 flow on a genuine Apple toolchain (26 assertions), and
  `Misty.xcframework` assembles with exactly the three slices intended —
  `ios-arm64`, `ios-arm64_x86_64-simulator`, `macos-arm64_x86_64` — and uploads as a
  build artifact. Nothing about the design changed; it simply had not been demonstrated,
  and one thing it found had to be fixed first (see the harness note under Fixed).
- **The conformance suite became one suite in fact rather than in intent.**
  `conformance/fixtures.json` records the contract; inputs reach foreign code through
  `mock_fixtures()` so nothing is re-derived, while expected outputs are pinned as literals
  in all three legs — `tests/native.rs` (the exported UniFFI object), the Swift flow, and
  `tests/web.rs` — because a suite that asks the core what to expect asserts the core
  against itself. `generate` is now asserted as an exact code rather than a digit count:
  the clock is pinned, and six digits of the wrong value passes a length check. The mock
  roster gained a second signed device so every leg exercises the `revoke` step and its
  epoch rotation. The wasm binding gained the surface the shared flow needs (`item`,
  `search`, `poll`, `reportLifecycle`, `revokeDevice`, `shutdown`, `mockFixtures`), so both
  bindings run the identical script. §11.8.2 now requires both of these rules.
- **`docs/SPEC.md`** §10 rule 1 gains its one exception: `crates/misty-ffi` cannot
  `forbid(unsafe_code)` because the binding toolchains generate `unsafe`; it adds none
  of its own. §11.4.2's over-promise about servicing reads mid-sync was corrected.

### Fixed
- `crates/misty-importers/src/interop.rs` imported `aes_gcm::aead::Aead` twice — once at
  module scope and again inside the test module, which reaches it through `use super::*`.
  The redundant import failed `clippy -D warnings`, so the `check` job was red on `main`.
- The two halves of Phase 4 did not interoperate. Both were built against §6, both
  noticed it never specified its own encoding, both invented something defensible, and
  the two differed on the auth signing context, on whether either signed message
  length-prefixes its nonce, on how the enrollment poll disambiguates, and on one field
  name. Both suites were green throughout, against two different mocks. §6.1.1 is now
  normative and the interop test is mandatory.
- Wire encoding is hex for ids, nonces, signatures and public keys; standard base64 for
  blobs. A liberal decoder here does not fail loudly — a 64-character hex nonce is also
  well-formed base64 of 48 bytes, so it returns the wrong bytes and the damage surfaces
  as a `401` that reads like a signature bug.
- Revoking a device now requires a `VK` rotation. `EK_n` derives from `VK`, so bumping
  the epoch gave no forward secrecy against a device that kept it.
- Retired device keys stay in the roster for verification only. Dropping them left the
  vault holding rows no roster device had signed, so it refused to open until rotation
  finished — making lazy rotation impossible exactly when it is most needed.

  SHA-1/256/512, 1–10 digits, 1–3600s periods), Steam, mOTP, Yandex, Blizzard, a
  hostile-input-hardened `otpauth://` parser and canonical serializer, injectable
  clocks with skew correction, and bounded HOTP counter resync. 133 tests: every RFC
  4226 Appendix D and RFC 6238 Appendix B vector including the published intermediate
  HMAC and truncation columns, third-party vectors for the proprietary variants with
  their sources named, a hostile-input corpus, property tests, and a fuzz target.
- **`crates/misty-crypto`** (`AGPL-3.0-or-later`) — the key hierarchy, the
  XChaCha20-Poly1305 envelope, Argon2id tiers, `.mistybak` backups, the three
  Recovery Kit encodings with single-word typo repair, device identity, the signed
  roster, and enrollment sealing. 135 tests: authoritative KATs from RFC 9106,
  RFC 8032, RFC 5869, and draft-irtf-cfrg-xchacha-03, frozen golden bytes for both
  formats, and negative paths for every rejection.
- Fuzzing CI job discovering every target under `crates/*/fuzz/`, and a wasm job that
  derives its crate list from the workspace so a rename cannot turn it into a
  silently-passing no-op.

### Fixed
- `otpauth://` round-tripping was not actually guaranteed. Found by fuzzing: an input
  just under the length cap whose label was dense with reserved characters parsed
  successfully, then percent-encoding grew the canonical form past the cap, so
  `to_uri()` emitted a URI the same parser rejected. The cap is now checked against
  the canonical form.
- Non-ASCII issuer names were specified as invalid. They are not — `日本銀行` is a
  real issuer. Only genuinely adversarial text is rejected: control characters,
  embedded NUL, bidi overrides, zero-width characters, a BOM, lone surrogates.
- Argon2 parameters outside the accepted range are rejected rather than clamped.
  Clamping derives a different key, which surfaces as "wrong passphrase" for what is
  really a malformed header.

### Changed
- Renamed the project from Totem to **Misty**. The old name collided twice: `totem`
  is already taken on crates.io, and it is the Debian and Fedora package name for
  GNOME Videos, which would have been a real conflict for a `.deb`. `misty` is
  unclaimed in both namespaces. The facade crate is plain `misty` rather than
  `misty-core`, which an unrelated project already holds.
- Blizzard no longer has its own `otpauth://` type. It is byte-identical to SHA-1
  8-digit TOTP, so the marker carried no algorithmic information while guaranteeing
  every other authenticator failed to import our exports. It now serializes as
  `otpauth://totp/` with `digits`, `algorithm`, and `period` explicit — byte-identical
  to the equivalent TOTP URI, asserted directly — and remains a preset in the API with
  `blizzard` still accepted on parse.

- Format constants changed with the rename: envelope magic `TOTM` → `MSTY`, backup
  magic `TOTEMBAK` → `MISTYBAK`, backup extension `.totembak` → `.mistybak`,
  key-derivation domain strings `totem/*` → `misty/*`, recovery QR prefix
  `totem-recovery:v1:` → `misty-recovery:v1:`. Pre-alpha, so no migration is owed —
  but every derived key and every golden-byte vector changes, so vectors must be
  regenerated rather than hand-edited.
- `crates/misty-otp` is licensed `MIT OR Apache-2.0` rather than
  `AGPL-3.0-or-later`, so other authenticators can adopt it. Everything else stays
  AGPL. Apache-2.0 is one-way compatible with AGPL-3.0, so the dependency arrow
  points inward only.
- Workspace members are listed explicitly instead of globbed. A cargo glob that
  matches nothing is a hard error, and `server/*` broke the entire workspace before
  the server crate existed.



### Security
- Formats are unfrozen until the `spec-v1` tag. `ENVELOPE_FORMAT_VERSION` and
  `BACKUP_FORMAT_VERSION` must be bumped on any breaking change before then.

[Unreleased]: https://github.com/zkasuran/misty/compare/main...HEAD
