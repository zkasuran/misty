<!--
SPDX-FileCopyrightText: 2026 The Misty Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# misty

The facade: the one owned, non-generic, `'static` API the four consumers (web/wasm,
browser extension, desktop, mobile) build against. It is the concrete realization of
[`docs/SPEC.md`](../../docs/SPEC.md) §11.

This crate **owns** the live [`Vault`](misty_vault::Vault) and
[`SyncEngine`](misty_sync::SyncEngine), monomorphizes away their generic parameters,
and presents everything as owned [`dto`] values and one flat [`FacadeError`]. No
generic, lifetime, borrow, or trait object crosses out of it — which is what lets
`crates/misty-ffi` lower the same API to UniFFI (Kotlin/Swift) and wasm-bindgen (JS)
without either toolchain seeing `misty-vault`, `misty-sync`, `misty-otp`,
`misty-crypto`, or `misty-importers`.

## Shape

- **Single-owner actor (§11.4).** One task owns the vault and the engine by value;
  every call is a [`Command`] on a channel and the reply is an owned DTO or a
  `FacadeError`. The engine's deliberately-`!Send` browser `fetch` future never leaves
  the task, and the vault's exclusive `&mut` access needs no consumer-visible lock.
- **Flattened errors (§11.3).** Five source error enums collapse into one
  [`FacadeError`] whose stability lives in a machine-readable [`ErrorCode`] string,
  never a discriminant. Bindings branch on the code, never the message.
- **Owned DTOs (§11.2).** `ItemView`/`GroupView`/… are field-for-field owned mirrors
  that carry no secret; `ItemView` exposes `has_pin`, never the secret or PIN.
- **Lifecycle (§11.5).** A `Locked`/`Unlocked` machine whose auto-lock is a
  wake-checked absolute deadline plus a facade-owned wake-only poll, so a live but idle
  process still drops and zeroizes its `VaultKey`. The shells report events; the facade
  decides.

## Driving the actor

[`spawn`] returns the [`Facade`] handle and a task future. Drive it with
`tokio::spawn` on native, `wasm_bindgen_futures::spawn_local` on wasm, or a local
executor in tests — never a production `block_on` (§11.4.3). The task starts locked;
call [`Facade::unlock`] to open the vault.

## The mock core is a build configuration (§11.8.1)

There is no hand-written mock. The "mock core" is this crate compiled with
`misty_vault::MemoryStore` + `misty_sync::MockTransport`; `tests/conformance.rs` drives
two devices converging through one in-process `MockServer` and asserts they agree on a
generated code — the native slice of the shared conformance gate.

## Not yet in this cut

- The §11.4.2 preemption model (a `Lock` dropping an in-flight sync future) is a
  follow-up; async commands are currently awaited inline, one at a time.
- The command surface is a subset (unlock/lock/lifecycle/add/read/generate/sync);
  enrollment, revocation, groups, and the remaining mutators land next.
- The wasm leg of the conformance run needs a headless browser and a matching
  chromedriver, so it lives in `crates/misty-ffi` rather than here. The UniFFI legs are
  there too and both are live: the generated Swift runs the flow on any platform with a
  Swift toolchain (`crates/misty-ffi/conformance/run-swift.sh`), and the Kotlin bindings
  are generated in CI pending the JVM harness P8 stands up. Only the Apple *platform*
  artifact — the `.xcframework` — needs a macOS runner.
