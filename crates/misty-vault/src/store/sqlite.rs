// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SQLite backend (SPEC §5). Absent from `wasm32` builds by construction: the
//! whole module is behind `cfg(not(target_arch = "wasm32"))`, and so is the
//! `rusqlite` dependency that would drag C into the build.

use std::path::Path;

use misty_crypto::envelope::EnvelopeKind;
use misty_crypto::ItemId;
use rusqlite::{Connection, OptionalExtension};

use crate::error::{Result, VaultError};
use crate::hlc::Hlc;
use crate::store::schema::{META_EPOCH, MIGRATIONS, OPEN_PRAGMAS, SCHEMA_VERSION};
use crate::store::{StoredEnvelope, VaultStore};

/// A vault stored in a SQLite database.
///
/// Holds the connection by value and exposes no `Clone` and no interior
/// mutability, so SPEC §5's "one writer, serialized through the vault handle" is
/// enforced by the borrow checker rather than by a lock.
pub struct SqliteStore {
    connection: Connection,
    depth: usize,
}

/// Turns a `rusqlite` failure into a vault error.
///
/// The message can name a table, a column or a file path. None of those is
/// secret: a backend never sees a plaintext field, only opaque envelopes.
fn storage(context: &'static str) -> impl Fn(rusqlite::Error) -> VaultError {
    move |error| VaultError::Storage {
        detail: format!("{context}: {error}"),
    }
}

impl SqliteStore {
    /// Opens or creates the database at `path`, applying pragmas and migrations.
    ///
    /// # Errors
    ///
    /// [`VaultError::Storage`] if SQLite fails, or
    /// [`VaultError::SchemaTooNew`] if the file was written by a newer build.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path).map_err(storage("open"))?;
        Self::from_connection(connection)
    }

    /// Opens a private in-memory database. For tests that want the real SQL
    /// engine without a file.
    ///
    /// # Errors
    ///
    /// As [`SqliteStore::open`].
    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().map_err(storage("open in memory"))?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        // Pragmas first: `journal_mode` cannot be changed inside a transaction,
        // and the migration below runs in one.
        connection
            .execute_batch(OPEN_PRAGMAS)
            .map_err(storage("pragmas"))?;
        let mut store = Self {
            connection,
            depth: 0,
        };
        store.migrate()?;
        Ok(store)
    }

    /// The journal mode SQLite actually settled on. An in-memory database cannot
    /// do WAL and reports `memory`; a file database must report `wal`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Storage`] if the pragma cannot be read.
    pub fn journal_mode(&self) -> Result<String> {
        self.connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(storage("journal_mode"))
    }

    /// The schema version recorded in the file header.
    ///
    /// # Errors
    ///
    /// [`VaultError::Storage`] if the pragma cannot be read.
    pub fn schema_version(&self) -> Result<u32> {
        let version: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(storage("user_version"))?;
        u32::try_from(version).map_err(|_| VaultError::Storage {
            detail: format!("user_version {version} is not a valid schema version"),
        })
    }

    /// The `synchronous` level in force. SPEC §5 requires `FULL`, which SQLite
    /// reports as `2`.
    ///
    /// A per-connection setting, so it is only meaningful read back through the
    /// connection that set it — which is what this does.
    ///
    /// # Errors
    ///
    /// [`VaultError::Storage`] if the pragma cannot be read.
    pub fn synchronous(&self) -> Result<i64> {
        self.connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .map_err(storage("synchronous"))
    }

    /// Whether foreign-key enforcement is on. Also per-connection, and off by
    /// default in SQLite, which is why it is set explicitly on every open.
    ///
    /// # Errors
    ///
    /// [`VaultError::Storage`] if the pragma cannot be read.
    pub fn foreign_keys(&self) -> Result<bool> {
        let on: i64 = self
            .connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .map_err(storage("foreign_keys"))?;
        Ok(on != 0)
    }

    fn migrate(&mut self) -> Result<()> {
        let found = self.schema_version()?;
        if found > SCHEMA_VERSION {
            return Err(VaultError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found == SCHEMA_VERSION {
            return Ok(());
        }
        self.transaction(|store| {
            let start = usize::try_from(found).map_err(|_| VaultError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            })?;
            for step in MIGRATIONS.iter().skip(start) {
                store
                    .connection
                    .execute_batch(step)
                    .map_err(storage("migration"))?;
            }
            store
                .connection
                .execute_batch(&format!("PRAGMA user_version={SCHEMA_VERSION};"))
                .map_err(storage("set user_version"))?;
            Ok(())
        })
    }
}

/// The six `items` columns, in `SELECT` order, before any of them is validated.
type Columns = (Vec<u8>, i64, Option<i64>, Option<Vec<u8>>, Vec<u8>, Vec<u8>);

/// Reads one row of `items` into its raw columns.
fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Columns> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

/// Converts the raw column tuple into a record, validating the two encoded
/// columns. A corrupt `kind` byte or a short `hlc_max` is a storage error, not a
/// panic.
fn record_from_columns(columns: Columns) -> Result<StoredEnvelope> {
    let (item_id, kind, seq, version, envelope, hlc_max) = columns;
    let kind = u8::try_from(kind)
        .map_err(|_| VaultError::Storage {
            detail: format!("kind {kind} is out of range"),
        })
        .and_then(|byte| Ok(EnvelopeKind::from_u8(byte)?))?;
    Ok(StoredEnvelope {
        item_id: ItemId::from_slice(&item_id)?,
        kind,
        seq,
        version,
        envelope,
        hlc_max: Hlc::from_slice(&hlc_max)?,
    })
}

const SELECT_COLUMNS: &str = "item_id, kind, seq, version, envelope, hlc_max";

impl VaultStore for SqliteStore {
    fn load_all(&self) -> Result<Vec<StoredEnvelope>> {
        let mut statement = self
            .connection
            .prepare(&format!("SELECT {SELECT_COLUMNS} FROM items"))
            .map_err(storage("prepare load_all"))?;
        let rows = statement
            .query_map([], row_to_record)
            .map_err(storage("query load_all"))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(record_from_columns(row.map_err(storage("read row"))?)?);
        }
        Ok(out)
    }

    fn get(&self, item_id: &ItemId) -> Result<Option<StoredEnvelope>> {
        let columns = self
            .connection
            .query_row(
                &format!("SELECT {SELECT_COLUMNS} FROM items WHERE item_id = ?1"),
                [item_id.as_bytes().as_slice()],
                row_to_record,
            )
            .optional()
            .map_err(storage("get"))?;
        columns.map(record_from_columns).transpose()
    }

    fn put(&mut self, record: &StoredEnvelope) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO items (item_id, kind, seq, version, envelope, hlc_max)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(item_id) DO UPDATE SET
                     kind = excluded.kind,
                     seq = excluded.seq,
                     version = excluded.version,
                     envelope = excluded.envelope,
                     hlc_max = excluded.hlc_max",
                rusqlite::params![
                    record.item_id.as_bytes().as_slice(),
                    i64::from(record.kind.as_u8()),
                    record.seq,
                    record.version.as_deref(),
                    record.envelope.as_slice(),
                    record.hlc_max.to_sort_bytes().as_slice(),
                ],
            )
            .map_err(storage("put"))?;
        Ok(())
    }

    fn remove(&mut self, item_id: &ItemId) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM items WHERE item_id = ?1",
                [item_id.as_bytes().as_slice()],
            )
            .map_err(storage("remove"))?;
        Ok(())
    }

    fn epoch(&self) -> Result<u32> {
        let stored: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [META_EPOCH],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage("epoch"))?;
        let Some(bytes) = stored else { return Ok(0) };
        let array: [u8; 4] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Storage {
                detail: format!("stored epoch is {} bytes, expected 4", bytes.len()),
            })?;
        Ok(u32::from_le_bytes(array))
    }

    fn set_epoch(&mut self, epoch: u32) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![META_EPOCH, epoch.to_le_bytes().as_slice()],
            )
            .map_err(storage("set_epoch"))?;
        Ok(())
    }

    fn begin(&mut self) -> Result<()> {
        // `BEGIN IMMEDIATE` rather than the default deferred begin: the write lock
        // is taken up front, so a second process cannot make a merge fail half way
        // through with `SQLITE_BUSY` after it has already written rows.
        let sql = if self.depth == 0 {
            "BEGIN IMMEDIATE".to_owned()
        } else {
            format!("SAVEPOINT vault_{}", self.depth)
        };
        self.connection
            .execute_batch(&sql)
            .map_err(storage("begin"))?;
        self.depth += 1;
        Ok(())
    }

    fn commit(&mut self) -> Result<()> {
        let depth = self.depth.checked_sub(1).ok_or(VaultError::NoTransaction)?;
        let sql = if depth == 0 {
            "COMMIT".to_owned()
        } else {
            format!("RELEASE vault_{depth}")
        };
        self.connection
            .execute_batch(&sql)
            .map_err(storage("commit"))?;
        self.depth = depth;
        Ok(())
    }

    fn rollback(&mut self) -> Result<()> {
        let depth = self.depth.checked_sub(1).ok_or(VaultError::NoTransaction)?;
        let sql = if depth == 0 {
            "ROLLBACK".to_owned()
        } else {
            format!("ROLLBACK TO vault_{depth}; RELEASE vault_{depth}")
        };
        self.connection
            .execute_batch(&sql)
            .map_err(storage("rollback"))?;
        self.depth = depth;
        Ok(())
    }
}

impl core::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SqliteStore")
            .field("open_transactions", &self.depth)
            .finish_non_exhaustive()
    }
}
