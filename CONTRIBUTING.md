# Contributing to Misty

Contributions are welcome. This is security software, so the bar for review is
higher than the code volume suggests — please read this before opening a PR.

## Read the spec first

[`docs/SPEC.md`](docs/SPEC.md) is the authoritative contract every crate implements
against: threat model, key hierarchy, byte-exact on-disk and on-wire formats, CRDT
merge rules, and the engineering gates. If code and spec disagree, that is a bug in
one of them — fix both in the same change and say which one was wrong.

[`docs/ROADMAP.md`](docs/ROADMAP.md) has the phase plan and the exit gate for each
phase. If you want to help, picking something from the current or next phase is far
more useful than starting a later one.

## Setup

```bash
git clone https://github.com/zkasuran/misty
cd misty
rustup target add wasm32-unknown-unknown   # the core must build for the web
cargo test --workspace
```

The toolchain is pinned in `rust-toolchain.toml`. No other system dependency is
required for the Rust core — that is deliberate, and adding one needs a good reason.

## The gates

These are CI gates, not suggestions. A change that fails any of them does not land.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
cargo deny check
cargo build -p misty-otp -p misty-crypto --target wasm32-unknown-unknown
```

Additionally, from `docs/SPEC.md` §10:

- `#![forbid(unsafe_code)]` in every crate. No exceptions.
- No `unwrap()`, `expect()`, or `panic!()` on any path reachable from parsed input
  or from FFI. Tests may use them freely.
- Public API is documented.

## Testing expectations

Tests are the deliverable, not the receipt. Specifically:

- **Anything with a published test vector must use it.** RFC 4226 Appendix D, RFC
  6238 Appendix B (all three algorithms), RFC 9106 for Argon2id, RFC 8032 for
  Ed25519. If no authoritative vector exists for a construction, freeze a
  self-generated regression vector and label it as self-generated in a comment.
  Do not imply authority you do not have.
- **Format code needs frozen golden bytes.** Envelope and backup encoding are
  tested against exact hex with fixed keys and nonces. These are what catch silent
  format drift six months from now.
- **Parsers need a hostile-input corpus** that runs under `cargo test` on stable,
  plus a `cargo-fuzz` target. Empty, enormous, truncated, wrong-encoding,
  absurd-parameter, and embedded-NUL inputs must all return an error and none may
  panic.
- **Merge logic needs property tests.** CRDT merge must be commutative,
  associative, and idempotent; every application order of the same operations must
  produce byte-identical state.
- **Secrets must be provably redacted.** If a type can hold key material, test that
  its `Debug` output contains neither the bytes nor their encoding.

## Dependencies

Every crate we add is attack surface, and the core must keep compiling to
`wasm32-unknown-unknown`.

- No C dependencies in the core. `cargo-deny` rejects `openssl`, `native-tls`, and
  `libsodium-sys` by design.
- New dependencies need a justification in the commit message: what it does, why
  the alternative of writing it is worse, and how widely it is used.
- `Cargo.lock` is committed. Keep it that way.
- Never add an analytics, telemetry, or crash-reporting SDK. This is not negotiable
  and a PR that adds one will be closed rather than reviewed.

## Licensing

The repository is not licensed uniformly, and the split is enforced rather than
documented-and-hoped-for. Read [`docs/LICENSING.md`](docs/LICENSING.md) before adding
a file or a dependency.

The short version: `crates/misty-otp` is `MIT OR Apache-2.0` so other authenticators
can use it, everything else is `AGPL-3.0-or-later`, and `misty-otp` must never gain a
copyleft dependency — including another `misty-*` crate. `ci/check-otp-permissive.py`
fails the build if it does.

Contributions are accepted under the license already governing the path you are
editing, certified by a DCO sign-off (`git commit -s`). There is no CLA and no
copyright assignment.

## Commits and PRs

- Sign off your commits (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/).
- One logical change per PR. A 2000-line PR touching crypto will sit unreviewed
  and that is a bad outcome for both of us.
- Describe what an attacker could do before the change and cannot after, if the
  change is security-relevant.
- Prefix the subject with the area: `otp:`, `crypto:`, `vault:`, `sync:`, `ui:`,
  `docs:`, `ci:`, `deps:`.

## Security issues

Do not open a public issue. See [`SECURITY.md`](SECURITY.md) for private reporting.

