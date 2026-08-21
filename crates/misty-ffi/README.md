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

- **Mobile / desktop (native, UniFFI → Kotlin + Swift).** The same facade is intended
  to lower to Kotlin and Swift through UniFFI. Generating the Kotlin/Swift source needs
  `uniffi-bindgen`; **running** the generated bindings needs a JVM (Kotlin) and a macOS
  runner (Swift/Apple, per the roadmap) — so that leg of the §11.8 conformance suite
  lives in CI, not on a Linux dev box. This crate is wired so those bindings can be
  added without touching `crates/misty`.

## The mock core is a build configuration (§11.8.1)

The binding is constructed over the real facade compiled with `misty_vault::MemoryStore`
+ `misty_sync::MockTransport` — the same "mock core" the UI develops against, not a
hand-written mock. A production build swaps the store, transport, and clock; nothing on
the JS/Kotlin/Swift side changes, because the generics are erased at the facade (§11.1).

## Unsafe

This is the one crate that does not `#![forbid(unsafe_code)]` (SPEC §10 rule 1's sole
exception): `wasm-bindgen` and UniFFI *generate* `unsafe` at the edge. It adds none of
its own and, per §11.7, contains no domain logic — so the `unsafe` is the toolchains',
not ours.
