# Roadmap

Each phase has an explicit exit gate. A phase is not "done" until its gate passes
on a clean checkout. Phases build in order; agents working in parallel within a
phase own disjoint directories.

| # | Phase | Owns | Exit gate |
|---|---|---|---|
| P0 | Foundation | workspace, `docs/SPEC.md`, CI | `cargo metadata` clean, spec merged |
| P1 | OTP engine | `crates/misty-otp` | every RFC 4226/6238 vector green, `otpauth` round-trip property test green, fuzz target runs |
| P1 | Crypto core | `crates/misty-crypto` | envelope + backup + recovery-kit round-trips green, KAT vectors green, builds for `wasm32` |
| P2 | Vault | `crates/misty-vault` | CRDT convergence property test green, crash-injection tests green |
| P3 | Interop | `crates/misty-importers` | fixture file per format imports byte-exactly, all fuzz targets run |
| P4 | Sync | `crates/misty-sync`, `server/misty-server` | two simulated clients converge through the real server; hostile-server tests rejected |
| P5 | Bindings | `crates/misty`, `crates/misty-ffi` | one shared conformance suite (`enroll → add → generate → sync → lock → unlock → revoke`) passes against the native facade, the wasm bundle in a headless browser, and the generated Kotlin + Swift, asserting identical DTOs and error `code`s against identical fixtures (SPEC §11.8) — which subsumes "WASM bundle loads, UniFFI generates Kotlin + Swift" |
| P6 | UI | `apps/ui` | full flows against a mock core, a11y audit clean, light + dark |
| P7 | Desktop | `apps/desktop` | Linux AppImage/deb + Windows build, real vault end to end |
| P8 | Mobile | `apps/mobile` | Android APK with camera QR scan, biometric unlock, auto-lock |
| P9 | Web + extension | `apps/web`, `apps/extension` | every §9.1 rule holds: fill only on an exact-origin match after a user gesture, homograph and suffix-match attempts rejected by test, no unwrapped key outside `chrome.storage.session`, auto-lock survives a killed service worker, web app runs the WASM core offline |
| P10 | Platform depth | native modules, `apps/cli` | OS autofill providers, widgets, watch, CLI, YubiKey, and native-messaging pairing so the extension can hold no key at rest when a desktop app is present (§9.1) |
| P11 | Release hardening | `fuzz/`, release tooling | reproducible builds, SBOM, signed release, audit-ready |

## Sequencing notes

- **P1 crates are independent** — `misty-otp` has no crypto dependency beyond
  HMAC, and `misty-crypto` knows nothing about OTP. Build both at once.
- **P2 depends on P1 crypto** (envelope) and **P3 depends on P1 otp** (the model it
  imports into). They can run in parallel once P1 is green.
- **P4 server can start alongside P4 client** — the protocol in SPEC §6 is the
  contract between them.
- **P6 UI can start as soon as P5 defines the facade API** (SPEC §11), against the
  mock core — which is `crates/misty` compiled with `MemoryStore` + `MockTransport`, a
  build configuration and **not** a hand-written mock that can drift (SPEC §11.8.1).
- **P5's exit gate is one shared conformance suite** run through the wasm bundle, the
  generated Kotlin, the generated Swift, and the native facade against identical
  fixtures (SPEC §11.8.2). "The bundle loads and UniFFI generates" proves the toolchain,
  not the API; this is the P4 interop failure (SPEC §6.1.1) fixed ahead of a
  four-consumer phase.
- **"Needs macOS" was two claims, and only one of them is true.** The Swift *language*
  toolchain is not Apple-only — swift.org ships Linux builds — so the generated Swift
  bindings compile and run the §11.8.2 flow on an ordinary Linux dev box and on the cheap
  CI runner (`crates/misty-ffi/conformance/run-swift.sh`, the `bindings` job). What
  genuinely requires a macOS runner is the Apple **platform artifact**: `xcodebuild
  -create-xcframework` and the `ios`/`macos` SDKs exist only there
  (`crates/misty-ffi/apple/build-xcframework.sh`, the `apple` job, gated to `main` and to
  PRs labelled `apple` because a macOS runner costs ten times a Linux one). Keeping the
  two apart is what lets an API break in the Swift binding fail on every pull request
  instead of waiting for someone to open Xcode in P7/P8.
- The Kotlin leg generates on every pull request; *running* it needs JNA and the native
  library on the JVM library path, which P8 (`apps/mobile`) stands up.

## What we are deliberately doing later

Push-to-approve partner integrations (Authy's differentiator) need per-service
server relationships and are not a v1 feature. Acting as a system passkey provider
is a separate product surface. Neither blocks anything above.
