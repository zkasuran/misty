# Misty

A cross-platform, end-to-end-encrypted TOTP/HOTP authenticator. Every device, real
sync, no phone number, no lock-in.

The name is checked clear where it has to be: `misty` is unclaimed on crates.io and
in the Debian package namespace. The facade crate is published as plain `misty`
rather than `misty-core`, because an unrelated project already holds that name.

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

## Design

Read [`docs/SPEC.md`](docs/SPEC.md) before writing code — it is the contract every
crate implements against. [`docs/ROADMAP.md`](docs/ROADMAP.md) has the phase plan
and exit gates.

Short version: a Rust core (`crates/`) compiled natively for desktop and mobile and
to WASM for the web, wrapped in one SvelteKit UI shipped through Tauri 2. The sync
server is a zero-knowledge versioned blob store — it holds opaque envelopes keyed by
a random vault id and has no user table to breach. Device identity is a per-device
Ed25519 keypair; the trusted device roster is an encrypted, client-signed vault item,
so a hostile server cannot add a device. Recovery is an offline kit, not an escrow.

## Layout

```
crates/misty-otp         RFC 4226 / 6238 + Steam, mOTP, Blizzard, Yandex
crates/misty-crypto      envelope, KDF tiers, recovery kit, key hierarchy
crates/misty-vault       item model, CRDT merge, encrypted SQLite
crates/misty-importers   every competitor's export format
crates/misty-sync        offline-first sync client
crates/misty             facade the UI talks to
server/misty-server      zero-knowledge blob store (axum)
apps/ui                  SvelteKit UI, shared by every target
apps/{desktop,mobile}    Tauri 2 shells
apps/{web,extension}     WASM core
```

## Status

**Pre-alpha, unaudited. Do not put a real secret in this yet.**

The core crates are under active construction against the spec above. There is no
release, no external audit, and no migration guarantee until the `spec-v1` tag.
[`SECURITY.md`](SECURITY.md) states plainly what is and is not defended — including
the parts that cannot be.

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the setup, the CI gates, and the testing
bar. Read [`docs/SPEC.md`](docs/SPEC.md) first; it is the contract. Found a
vulnerability? Report it privately — see [`SECURITY.md`](SECURITY.md), not the
issue tracker.

## License

Two licenses, on purpose. Full map and reasoning in
[`docs/LICENSING.md`](docs/LICENSING.md).

- **`crates/misty-otp`** — [MIT](LICENSES/MIT.txt) OR
  [Apache-2.0](LICENSES/Apache-2.0.txt). Take it. A correct, exhaustively vectored
  RFC 4226/6238 implementation is worth more to the ecosystem shared than hoarded,
  and every authenticator reimplementing it from scratch is a worse outcome for
  users than one implementation with the RFC vectors actually wired up.
- **Everything else** — [AGPL-3.0-or-later](LICENSE). Anyone may run, audit, fork,
  and self-host. Anyone offering Misty as a service owes their users the source —
  and since Misty ships a web app, that clause is doing real work here, not
  decoration.

Apache-2.0 is one-way compatible with AGPL-3.0, so the arrow points inward: the AGPL
crates consume the permissive one and never the reverse. CI enforces it.

The repository is [REUSE 3.3](https://reuse.software/spec-3.3/) compliant, so every
file's license is machine-readable rather than a matter of interpretation.


