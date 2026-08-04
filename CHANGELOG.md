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

### Changed
- Renamed the project from Totem to **Misty**. The old name collided twice: `totem`
  is already taken on crates.io, and it is the Debian and Fedora package name for
  GNOME Videos, which would have been a real conflict for a `.deb`. `misty` is
  unclaimed in both namespaces. The facade crate is plain `misty` rather than
  `misty-core`, which an unrelated project already holds.
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
