<!--
SPDX-FileCopyrightText: 2026 The Misty Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# misty-ffi

The binding shim (SPEC §11.7): it lowers the [`misty`](../misty) facade to the two
foreign toolchains and holds **no logic of its own** — every call reduces to a facade
method, and the only types it names are the facade's owned DTOs and its flat error.

## What crosses

- **Web / extension (`wasm32`, `wasm-bindgen`).** [`web::MistyFacade`] exposes the
  facade to JavaScript: each method returns a `Promise` that resolves with an owned DTO
  (a plain serde object) or rejects with `{ code, message, retryable }` — bindings
  branch on the stable `code`, never the message (§11.3.2, §11.7.2). Build and generate
  the bundle with:

  ```sh
  cargo build -p misty-ffi --target wasm32-unknown-unknown
  wasm-bindgen target/wasm32-unknown-unknown/debug/misty_ffi.wasm \
      --out-dir pkg --target web
  ```

  This emits `misty_ffi.js`, `misty_ffi_bg.wasm`, and a `.d.ts` with the `MistyFacade`
  class — the web app and extension load it directly.

- **Mobile / desktop (native, UniFFI → Kotlin + Swift).** [`native::MistyFacade`] is the
  same facade as an `Arc`-heap UniFFI object: `async fn` becomes `suspend fun` / Swift
  `async`, DTOs cross as `data class`/`struct` values, and a failure is thrown carrying
  the same `{ code, message, retryable }` triple the wasm leg rejects with (§11.7.1).

  ```sh
  cargo build -p misty-ffi
  cargo run -p misty-ffi --features cli --bin uniffi-bindgen -- \
      generate --library target/debug/libmisty_ffi.so \
      --language swift --out-dir target/bindings/swift    # or --language kotlin
  ```

  **The DTOs are not re-declared here.** Every boundary type is registered with
  `#[uniffi::remote(..)]`, so UniFFI generates scaffolding for `misty`'s *own* type and
  emits no copy. There is no conversion layer to drift, and no second definition to keep
  in step with the wasm leg — the two bindings carry the identical values, which is what
  makes one shared conformance suite meaningful. Change a facade DTO and this crate stops
  compiling; that is the design. `crates/misty` still never names UniFFI.

## Running the legs

Each script builds the library, generates bindings from *that artifact*, compiles them
with the flow, and runs it. They fetch their own toolchains into `target/` and install
nothing system-wide.

```sh
crates/misty-ffi/conformance/run-swift.sh    # swift  conformance (SPEC §11.8.2): 26 assertions passed
crates/misty-ffi/conformance/run-kotlin.sh   # kotlin conformance (SPEC §11.8.2): 26 assertions passed
crates/misty-ffi/conformance/run-wasm.sh     # test the_js_binding_runs_the_conformance_flow ... ok
cargo test -p misty-ffi --test native        # the exported UniFFI object, in Rust
cargo test -p misty --test conformance       # the native Rust facade
```

### No Apple hardware required for Swift, no Android SDK for Kotlin

Both foreign legs run on Linux, on every pull request. Neither toolchain is
platform-locked for this purpose: swift.org ships Linux Swift, and UniFFI's Kotlin output
binds through JNA, so a compiler plus two jars off Maven Central plus the `cdylib` on
`jna.library.path` is the whole Kotlin harness — no Android SDK, no Gradle. Earlier notes
in this file claimed both legs needed CI runners we did not have; that conflated the
language toolchains with the platform ones.

What *does* need macOS is the Apple **platform artifact**: `xcodebuild
-create-xcframework` and the iOS SDKs ship only there. `apple/build-xcframework.sh`
produces it — five static slices (iOS device, both simulator architectures, both macOS
architectures) lipo'd into an `.xcframework`, plus a SwiftPM `Package.swift` pairing that
binary target with the generated Swift API layer. That script refuses to run off macOS
and is driven by the `apple` CI job. P8 (`apps/mobile`) wraps the same generated Kotlin in
an Android project, which is packaging rather than a precondition for asserting anything.

That job has run on `macos-26-arm64` and passes: the workspace's 64 suites on macOS, the
Swift flow on a genuine Apple toolchain, and an `.xcframework` carrying exactly
`ios-arm64`, `ios-arm64_x86_64-simulator`, and `macos-arm64_x86_64`. It is gated to `main`
and to pull requests labelled `apple`, so request it with the label when you touch the
binding layer — the workflow listens for `labeled`, so adding it triggers the run.

### "The bindings generate" is not a gate

CI used to assert that `uniffi-bindgen` had produced a Kotlin file. It had — and the file
did not compile: the error payload's `message` field collided with
`kotlin.Exception.message`, which UniFFI lowers every error enum onto. Generation is a
statement about the toolchain, not about the code it emitted, and never about whether the
answers match. Every leg now compiles and executes; §11.7.1 records the fix (the payload
moved into a nested record) and §11.8.2 records the rule.

## One suite, three legs (§11.8.2)

The same scripted flow — `enroll → add → generate → sync → lock → unlock → revoke` — runs
in three places against the same fixtures and asserts the same literals:

| Leg | Where | Surface under test | Driven by |
|---|---|---|---|
| Native Rust facade | `../misty/tests/conformance.rs` | `misty::Facade` | a local executor |
| Exported UniFFI object | `tests/native.rs` | `native::MistyFacade` | `tokio` |
| Generated Swift | `conformance/ConformanceFlow.swift` | the generated `MistyFacade` | Swift `async`, any platform |
| Generated Kotlin | `conformance/ConformanceFlow.kt` | the generated `MistyFacade` | `runBlocking` on any JVM |
| wasm bundle, headless browser | `tests/web.rs` | `web::MistyFacade` | `spawn_local` on the real event loop |

Each leg drives the **binding**, not the facade underneath it. That distinction is the
value: a wasm test that awaited `misty::Facade` futures and read Rust structs — which is
what this file used to do — never executes `future_to_promise`, the serde lowering, or
`err_to_js`, so a break in any of them ships green. The wasm leg therefore awaits
`Promise`s, reads properties with `Reflect::get`, and builds its input as a plain object,
which is also the only way the serde enum forms (`kind: "Totp"`) get checked at all.

`conformance/fixtures.json` is where the contract is written down. Inputs also reach
foreign code at runtime through `mock_fixtures()`, so no suite re-derives a device id or
a key. Expected **outputs** are deliberately *not* served that way — a suite that asked
the core what to expect would be asserting the core against itself — so they are literals
in each leg, and changing one means changing all three. That is the review moment §11.8
wants.

`generate` is asserted as an exact code (`746722`), not a digit count: the clock is
pinned, so a binding that computed six digits of the wrong value would sail through a
length check. Failures are asserted on the stable `code` string only, never on `message`
(§11.3.2), so wording and localization stay free to change.

## The mock core is a build configuration (§11.8.1)

The binding is constructed over the real facade compiled with `misty_vault::MemoryStore`
+ `misty_sync::MockTransport` — the same "mock core" the UI develops against, not a
hand-written mock. A production build swaps the store, transport, and clock; nothing on
the JS/Kotlin/Swift side changes, because the generics are erased at the facade (§11.1).

The mock roster holds **two** signed devices rather than one, so the flow's `revoke` step
(§6.4) has something to revoke and every leg exercises epoch rotation. `enroll` is
represented by that pre-signed roster: the joining half of a live §6.3 handshake needs
core types (`Enrollment`, `SyncClient`) that are quarantined behind the facade and have no
FFI projection, and it is covered in Rust by `crates/misty/tests/conformance.rs`.

## Unsafe

This is the one crate that does not `#![forbid(unsafe_code)]` (SPEC §10 rule 1's sole
exception): `wasm-bindgen` and UniFFI *generate* `unsafe` at the edge. It adds none of
its own and, per §11.7, contains no domain logic — so the `unsafe` is the toolchains',
not ours.
