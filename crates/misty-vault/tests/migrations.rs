// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Forward-only, versioned migrations, tested against a frozen fixture (SPEC §5).
//!
//! The harness is built now rather than when it is first needed. A migration test
//! written at the same time as the migration it covers tends to test the migration
//! the author just wrote; one that already exists tests whatever the next author
//! does to it.

#![cfg(not(target_arch = "wasm32"))]

mod support;

use misty_otp::FixedClock;
use misty_vault::{
    MemoryStore, SqliteStore, StoredEnvelope, Vault, VaultError, VaultStore, SCHEMA_VERSION,
};
use support::{device, new_item, roster, vault_key, NOW};

const FIXTURE_V1: &str = include_str!("fixtures/schema_v1.sql");

/// SQL with comments and whitespace collapsed, so two spellings of one schema
/// compare equal and a real change does not.
fn normalise(sql: &str) -> String {
    sql.lines()
        .map(|line| line.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// A fresh database is at the current version and has the tables the code expects.
#[test]
fn a_fresh_database_is_at_the_current_version() {
    let store = SqliteStore::open_in_memory().expect("open");
    assert_eq!(store.schema_version().expect("version"), SCHEMA_VERSION);
    // The schema is exercised rather than introspected: a `SELECT` that runs is a
    // stronger statement than a name in `sqlite_master`.
    assert!(store.load_all().expect("load_all").is_empty());
    assert_eq!(store.epoch().expect("epoch"), 0);
}

/// The frozen v1 fixture is still what `MIGRATIONS[0]` produces.
///
/// This is the guard against editing a released migration in place. If this fails
/// and the schema was changed deliberately, the fix is to *append* a step and bump
/// [`SCHEMA_VERSION`], not to update the fixture.
#[test]
fn the_frozen_fixture_matches_the_released_migration() {
    let fixture = normalise(&FIXTURE_V1.replace("PRAGMA user_version=1;", ""));
    let released = normalise(misty_vault::store::MIGRATIONS[0]);
    assert_eq!(fixture, released);
}

/// A v1 database, populated by hand, opens under the current code with no migration
/// and reads back exactly what was put in it.
#[test]
fn a_v1_database_opens_and_reads_back() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault.sqlite");

    // Build the database from the frozen DDL, without going through this crate's
    // migration code at all.
    let raw = rusqlite::Connection::open(&path).expect("open");
    raw.execute_batch(FIXTURE_V1).expect("apply v1");
    let row = StoredEnvelope {
        item_id: misty_crypto::ItemId::from_bytes([0x11; 16]),
        kind: misty_crypto::envelope::EnvelopeKind::Item,
        seq: Some(7),
        version: Some(b"etag-7".to_vec()),
        envelope: vec![0xab; 64],
        hlc_max: misty_vault::Hlc::new(NOW, 3, misty_crypto::DeviceId::from_bytes([0x22; 16]))
            .expect("hlc"),
    };
    raw.execute(
        "INSERT INTO items (item_id, kind, seq, version, envelope, hlc_max)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            row.item_id.as_bytes().as_slice(),
            1i64,
            row.seq,
            row.version.as_deref(),
            row.envelope.as_slice(),
            row.hlc_max.to_sort_bytes().as_slice(),
        ],
    )
    .expect("insert");
    raw.execute(
        "INSERT INTO meta (key, value) VALUES ('epoch', ?1)",
        [3u32.to_le_bytes().as_slice()],
    )
    .expect("epoch");
    drop(raw);

    let store = SqliteStore::open(&path).expect("open");
    assert_eq!(store.schema_version().expect("version"), SCHEMA_VERSION);
    assert_eq!(store.load_all().expect("load_all"), vec![row.clone()]);
    assert_eq!(store.get(&row.item_id).expect("get"), Some(row));
    assert_eq!(store.epoch().expect("epoch"), 3);
}

/// Opening twice does not re-run a migration, and does not disturb the rows.
#[test]
fn opening_twice_is_a_no_op() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault.sqlite");
    {
        let mut store = SqliteStore::open(&path).expect("first open");
        store.set_epoch(4).expect("epoch");
    }
    for _ in 0..3 {
        let store = SqliteStore::open(&path).expect("reopen");
        assert_eq!(store.schema_version().expect("version"), SCHEMA_VERSION);
        assert_eq!(store.epoch().expect("epoch"), 4);
    }
}

/// A file written by a newer build is refused, not guessed at. SPEC §9 requires a
/// checkpoint and an integrity check before any destructive migration, and an older
/// binary cannot know how to perform one it has never heard of.
#[test]
fn a_newer_schema_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault.sqlite");
    let raw = rusqlite::Connection::open(&path).expect("open");
    raw.execute_batch(FIXTURE_V1).expect("apply v1");
    raw.execute_batch("PRAGMA user_version=99;").expect("bump");
    drop(raw);

    let error = SqliteStore::open(&path).expect_err("must refuse");
    assert!(
        matches!(
            error,
            VaultError::SchemaTooNew {
                found: 99,
                supported
            } if supported == SCHEMA_VERSION
        ),
        "{error:?}"
    );
}

/// The pragmas SPEC §5 requires are actually in force, not merely written down.
#[test]
fn the_required_pragmas_are_set() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault.sqlite");
    let store = SqliteStore::open(&path).expect("open");
    // `journal_mode` is persisted in the file header; the other two are
    // per-connection, so they are read back through the connection that set them.
    assert_eq!(store.journal_mode().expect("journal_mode"), "wal");
    assert_eq!(store.synchronous().expect("synchronous"), 2, "must be FULL");
    assert!(store.foreign_keys().expect("foreign_keys"));
}

/// An in-memory database cannot do WAL and says so rather than pretending.
#[test]
fn an_in_memory_database_reports_its_real_journal_mode() {
    let store = SqliteStore::open_in_memory().expect("open");
    assert_eq!(store.journal_mode().expect("journal_mode"), "memory");
}

/// The whole vault, through the real SQL engine and a real file: add, lock, reopen.
#[test]
fn a_vault_survives_a_real_file_round_trip() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("vault.sqlite");
    let identity = device(1);
    let signed = roster(&[&identity]);

    let id = {
        let mut vault = Vault::open(
            SqliteStore::open(&path).expect("open"),
            FixedClock::new(NOW),
            vault_key(),
            device(1),
            signed.clone(),
        )
        .expect("open vault");
        let id = vault
            .add(new_item("GitHub", "ada@example.com", b"aaaaaaaaaa").tag("dev"))
            .expect("add");
        vault.record_use(&id).expect("use");
        drop(vault.lock());
        id
    };

    let vault = Vault::open(
        SqliteStore::open(&path).expect("reopen"),
        FixedClock::new(NOW),
        vault_key(),
        identity,
        signed,
    )
    .expect("reopen vault");
    let item = vault.item(&id).expect("item");
    assert_eq!(item.issuer(), "GitHub");
    assert_eq!(item.use_count(), 1);
    assert_eq!(item.tags().map(String::as_str).collect::<Vec<_>>(), ["dev"]);
}

/// The two backends implement the same contract, so the same sequence of calls has
/// to produce the same observable state in both.
#[test]
fn both_backends_agree() {
    fn exercise<S: VaultStore>(mut store: S) -> (Vec<StoredEnvelope>, u32) {
        let row = |byte: u8| StoredEnvelope {
            item_id: misty_crypto::ItemId::from_bytes([byte; 16]),
            kind: misty_crypto::envelope::EnvelopeKind::Item,
            seq: Some(i64::from(byte)),
            version: None,
            envelope: vec![byte; 48],
            hlc_max: misty_vault::Hlc::new(NOW, 0, misty_crypto::DeviceId::from_bytes([byte; 16]))
                .expect("hlc"),
        };
        store.put(&row(1)).expect("put");
        store.put(&row(2)).expect("put");
        store.set_epoch(2).expect("epoch");
        store.remove(&row(1).item_id).expect("remove");
        // An overwrite of an existing key keeps one row, not two.
        store.put(&row(2)).expect("put again");
        let mut rows = store.load_all().expect("load_all");
        rows.sort_by_key(|row| row.item_id);
        (rows, store.epoch().expect("epoch"))
    }

    assert_eq!(
        exercise(MemoryStore::new()),
        exercise(SqliteStore::open_in_memory().expect("open"))
    );
}
