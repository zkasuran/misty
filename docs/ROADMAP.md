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
| P5 | Bindings | `crates/misty`, `crates/misty-ffi` | WASM bundle loads in a browser, UniFFI generates Kotlin + Swift |
| P6 | UI | `apps/ui` | full flows against a mock core, a11y audit clean, light + dark |
| P7 | Desktop | `apps/desktop` | Linux AppImage/deb + Windows build, real vault end to end |
| P8 | Mobile | `apps/mobile` | Android APK with camera QR scan, biometric unlock, auto-lock |
| P9 | Web + extension | `apps/web`, `apps/extension` | MV3 extension autofills origin-bound, web app runs the WASM core |
| P10 | Platform depth | native modules, `apps/cli` | OS autofill providers, widgets, watch, CLI |
| P11 | Release hardening | `fuzz/`, release tooling | reproducible builds, SBOM, signed release, audit-ready |

## Sequencing notes

- **P1 crates are independent** — `misty-otp` has no crypto dependency beyond
  HMAC, and `misty-crypto` knows nothing about OTP. Build both at once.
- **P2 depends on P1 crypto** (envelope) and **P3 depends on P1 otp** (the model it
  imports into). They can run in parallel once P1 is green.
- **P4 server can start alongside P4 client** — the protocol in SPEC §6 is the
  contract between them.
- **P6 UI can start as soon as P5 defines the facade API**, against a mock.
- Apple targets (`macos`, `ios`) require a macOS runner; they are wired in CI in
  P7/P8 but cannot be built on the Linux dev box.

## What we are deliberately doing later

Push-to-approve partner integrations (Authy's differentiator) need per-service
server relationships and are not a v1 feature. Acting as a system passkey provider
is a separate product surface. Neither blocks anything above.
