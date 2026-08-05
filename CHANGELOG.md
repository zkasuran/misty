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
- **`crates/misty-otp`** (`MIT OR Apache-2.0`) — HOTP (RFC 4226), TOTP (RFC 6238,
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
