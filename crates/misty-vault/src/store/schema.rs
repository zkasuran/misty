// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SQLite schema, and forward-only migrations over it.
//!
//! # Forward only, and versioned by `PRAGMA user_version`
//!
//! `user_version` is a 32-bit integer in the SQLite file header. Using it rather
//! than a `schema_version` table means the version cannot be out of step with the
//! schema it describes: it is updated inside the same transaction as the DDL, and
//! there is no table to be missing on a half-created database.
//!
//! [`MIGRATIONS`] is indexed by the version it upgrades *from*, so applying every
//! script from `user_version` onwards is the whole algorithm. A file whose
//! `user_version` is higher than [`SCHEMA_VERSION`] is **refused**
//! ([`VaultError::SchemaTooNew`]) rather than opened: an older binary that guessed
//! at a newer schema would write rows a newer binary then has to repair, and
//! SPEC §9 requires the database to be checkpointed and integrity-checked before
//! any destructive migration — which an old binary cannot know how to do.
//!
//! # The fixture harness exists before it is needed
//!
//! `tests/fixtures/schema_v1.sql` is a frozen copy of v1's DDL. The migration test
//! builds a database from it, populates it, and opens it with the current code.
//! Today that proves the v1 path is a no-op; the moment a v2 lands it proves the
//! upgrade, and it will fail loudly if someone edits `MIGRATIONS[0]` in place
//! instead of adding a step — which is the mistake that silently breaks every
//! existing install.

/// Schema version this build implements.
pub const SCHEMA_VERSION: u32 = 1;

/// Migration scripts, indexed by the `user_version` each one upgrades from.
///
/// **Append only.** Editing an existing entry changes what a database that has
/// already been migrated looks like, without changing its recorded version, and
/// nothing will notice until a user's vault stops opening.
pub const MIGRATIONS: &[&str] = &[V0_TO_V1];

/// v0 → v1: the initial schema.
const V0_TO_V1: &str = "
CREATE TABLE items (
    item_id  BLOB    PRIMARY KEY NOT NULL,
    kind     INTEGER NOT NULL,
    seq      INTEGER,
    version  BLOB,
    envelope BLOB    NOT NULL,
    hlc_max  BLOB    NOT NULL
) WITHOUT ROWID;

CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
) WITHOUT ROWID;
";

/// `meta` key holding the current epoch, as a little-endian `u32`.
pub(crate) const META_EPOCH: &str = "epoch";

/// Pragmas applied on every open, before any statement runs.
///
/// * `journal_mode=WAL` — a reader never blocks the single writer, and a crash
///   recovers from the log rather than from a rolled-back page image.
/// * `synchronous=FULL` — SPEC §5 requires it. WAL's default of `NORMAL` can lose
///   the tail of the log on a power cut, which for a vault means losing an item the
///   user watched the app say it had saved.
/// * `foreign_keys=ON` — SPEC §5 requires it. There is no foreign key in v1; it is
///   set anyway because SQLite defaults it *off* per connection, so a future table
///   that needs it would otherwise silently not get it.
/// * `busy_timeout` — the vault serialises its own writes, but a second process
///   (a CLI run against an open desktop app) should wait rather than fail.
pub(crate) const OPEN_PRAGMAS: &str = "
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
";
