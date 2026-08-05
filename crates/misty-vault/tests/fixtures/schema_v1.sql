-- SPDX-FileCopyrightText: 2026 The Misty Authors
--
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- A frozen copy of schema version 1, exactly as `store::schema::MIGRATIONS[0]`
-- created it, plus the `user_version` a migrated database carries.
--
-- This is the fixture SPEC §5 asks for: "migrations are forward-only, versioned,
-- and MUST be tested against a fixture DB from every prior released schema
-- version." It exists before it is needed on purpose. Today it proves that
-- opening a v1 database is a no-op; the day a v2 lands it proves the upgrade, and
-- it fails immediately if someone edits `MIGRATIONS[0]` in place instead of
-- appending a step — which is the mistake that silently breaks every install that
-- already migrated.
--
-- Text rather than a binary `.sqlite`: a checked-in database file cannot be
-- reviewed in a diff, and the interesting content here is the DDL.

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

PRAGMA user_version=1;
