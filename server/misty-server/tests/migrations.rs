// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Forward-only migrations, and what the database file looks like to whoever
//! steals it.
//!
//! This is the only test file that opens the SQLite file directly. It does so on
//! purpose: the strongest form of the zero-knowledge claim is "grep every byte of
//! every column for the secret and find nothing", and that cannot be expressed
//! through the [`Store`] trait.

mod common;

use common::{b64_encode, bootstrap, Harness, Vault};
use misty_server::store::Store;
use misty_server::{ItemId, SqliteStore};

/// Every value of every column, rendered as bytes, from an attacker's viewpoint.
fn dump(path: &std::path::Path) -> Vec<Vec<u8>> {
    let connection = rusqlite::Connection::open(path).expect("open the stolen file");
    let tables: Vec<String> = {
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap();
        rows.map(Result::unwrap).collect()
    };

    let mut values = Vec::new();
    for table in tables {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM \"{table}\""))
            .unwrap();
        let columns = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for index in 0..columns {
                let value: rusqlite::types::Value = row.get(index).unwrap();
                values.push(match value {
                    rusqlite::types::Value::Null => Vec::new(),
                    rusqlite::types::Value::Integer(n) => n.to_string().into_bytes(),
                    rusqlite::types::Value::Real(n) => n.to_string().into_bytes(),
                    rusqlite::types::Value::Text(t) => t.into_bytes(),
                    rusqlite::types::Value::Blob(b) => b,
                });
            }
        }
    }
    values
}

#[tokio::test]
async fn a_full_database_dump_contains_no_plaintext_and_no_usable_token() {
    const SECRET: &[u8] = b"JBSWY3DPEHPK3PXP is the seed and GitHub is the issuer";

    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);
    let item = ItemId::from_bytes(common::random16());
    let envelope = vault.seal(&item, SECRET, &client.identity);

    harness
        .json(
            "PUT",
            &format!(
                "/v1/vaults/{}/items/{}",
                client.vault.to_hex(),
                item.to_hex()
            ),
            &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&envelope) }),
        )
        .await
        .expect_status(200);

    let values = dump(&harness.database);
    assert!(!values.is_empty(), "the dump found nothing at all");

    // Not the plaintext, nor any eight-byte run of it: a partial leak is a leak.
    for value in &values {
        for window in SECRET.windows(8) {
            assert!(
                !value.windows(8).any(|w| w == window),
                "a fragment of the plaintext is in the database"
            );
        }
    }
    for fragment in [
        &b"JBSWY3DPEHPK3PXP"[..],
        &b"GitHub"[..],
        &b"issuer"[..],
        &b"seed"[..],
    ] {
        assert!(
            !values
                .iter()
                .any(|v| v.windows(fragment.len()).any(|w| w == fragment)),
            "{:?} is in the database",
            String::from_utf8_lossy(fragment)
        );
    }

    // Nor a usable credential: only token *hashes* are stored.
    for token in [client.access.as_bytes(), client.refresh.as_bytes()] {
        assert!(
            !values.iter().any(|v| v
                .windows(token.len().min(v.len().max(1)))
                .any(|w| w == token)),
            "a bearer token is stored verbatim"
        );
    }

    // The envelope itself *is* there, byte for byte — that is the service.
    assert!(
        values.iter().any(|value| value == &envelope),
        "the opaque envelope should be stored unchanged"
    );
}

#[tokio::test]
async fn migrations_are_idempotent_and_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("misty.sqlite3");

    let store = SqliteStore::open(&path).unwrap();
    let first = store.schema_columns().unwrap();
    // `open` already migrated; doing it again must be a no-op rather than an
    // error, because the binary calls it explicitly at startup.
    store.migrate().unwrap();
    store.migrate().unwrap();
    assert_eq!(store.schema_columns().unwrap(), first);
    drop(store);

    let reopened = SqliteStore::open(&path).unwrap();
    assert_eq!(reopened.schema_columns().unwrap(), first);
}

#[tokio::test]
async fn a_database_from_a_future_version_is_refused_rather_than_downgraded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("misty.sqlite3");
    SqliteStore::open(&path).unwrap();

    // Pretend a later release wrote this file.
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA user_version = 99")
            .unwrap();
    }

    let error = SqliteStore::open(&path).expect_err("a future schema must be refused");
    let message = error.to_string();
    assert!(
        message.contains("newer than this binary"),
        "unhelpful message: {message}"
    );
    // Running old code against a new schema is how data gets silently dropped,
    // so the failure has to be at startup and it has to be loud.
    assert!(message.contains("refusing to run"));
}

#[tokio::test]
async fn an_in_memory_store_satisfies_the_same_schema() {
    // Used by unit tests and by anything that wants to check a configuration
    // without touching a disk. It must not drift from the file-backed schema.
    let memory = SqliteStore::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = SqliteStore::open(&dir.path().join("misty.sqlite3")).unwrap();
    assert_eq!(
        memory.schema_columns().unwrap(),
        file.schema_columns().unwrap()
    );
}
