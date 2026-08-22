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

## Running the Swift leg — no Apple hardware required

`conformance/run-swift.sh` builds the library, generates Swift from *that artifact*,
compiles it with `conformance/ConformanceFlow.swift`, and runs the §11.8.2 flow:

```sh
crates/misty-ffi/conformance/run-swift.sh
# swift conformance (SPEC §11.8.2): 23 assertions passed
```

This works on Linux. The Swift *language* toolchain is not Apple-only — swift.org ships
Linux builds — so the generated bindings can be compiled and executed on an ordinary dev
box and on the cheap CI runner, on every pull request. An earlier note in this file
claimed the Swift leg needed a macOS runner; that conflated two different things.

What *does* need macOS is the Apple **platform artifact**: `xcodebuild
-create-xcframework` and the iOS SDKs ship only there. `apple/build-xcframework.sh`
produces it — five static slices (iOS device, both simulator architectures, both macOS
architectures) lipo'd into an `.xcframework`, plus a SwiftPM `Package.swift` pairing that
binary target with the generated Swift API layer. That script refuses to run off macOS
and is driven by the `apple` CI job.

The Kotlin leg generates in CI. *Running* it needs JNA plus the native library on the JVM
library path, which is P8's (`apps/mobile`) job to stand up; until then CI asserts that
the facade still lowers to Kotlin, which catches an API break at the right moment.

## One suite, three legs (§11.8.2)

The same scripted flow — `enroll → add → generate → sync → lock → unlock → revoke` — runs
in three places against the same fixtures and asserts the same literals:

| Leg | Where | Driven by |
|---|---|---|
| Exported UniFFI object, in Rust | `tests/native.rs` | `tokio` |
| Generated Swift | `conformance/ConformanceFlow.swift` | `swiftc`, any platform |
| wasm bundle, headless browser | `tests/web.rs` | `spawn_local` on the real event loop |

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
