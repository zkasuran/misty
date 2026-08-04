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
- Open-source project scaffolding: AGPL-3.0-or-later license, security policy,
  contribution guide, issue and PR templates.

### Security
- Formats are unfrozen until the `spec-v1` tag. `ENVELOPE_FORMAT_VERSION` and
  `BACKUP_FORMAT_VERSION` must be bumped on any breaking change before then.

[Unreleased]: https://github.com/zkasuran/totem/compare/main...HEAD
