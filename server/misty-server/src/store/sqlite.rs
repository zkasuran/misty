// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SQLite backend: one binary, one file, no daemon.
//!
//! # Why one connection behind a mutex
//!
//! SPEC §6.1 promises clients a *gap-free* ordered change feed: fetch
//! `seq > since`, remember `next_seq`, repeat, and never miss a write. That holds
//! only if no reader can observe `seq = n` committed while `seq = n - 1` is still
//! in flight. A connection pool would allow exactly that interleaving, and the
//! resulting lost write would be silent — a client would simply never learn about
//! one item, forever.
//!
//! So every statement goes through one connection guarded by a mutex, and
//! `seq` allocation happens in the same transaction as the row write.
//! Serialisation is not a performance compromise reluctantly accepted here; it is
//! the mechanism that makes the feed correct. SQLite permits one writer anyway,
//! and a vault is one person's data.
//!
//! Handlers must not hold this mutex on a runtime thread; see
//! [`crate::routes::blocking`].
//!
//! # Migrations
//!
//! Forward-only, tracked in `PRAGMA user_version`, each one a transaction. A
//! database from a future version is refused rather than downgraded: running old
//! code against a new schema is how data gets silently dropped.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, Transaction};

use super::{
    Admission, Challenge, Change, Device, EnrollBegin, EnrollComplete, EnrollRequest,
    EnrollResponse, Limits, Precondition, RefreshOutcome, Result, Session, Store, StoreError,
    Swept, Usage, WriteOutcome, Written,
};
use crate::ids::{DeviceId, EnrollId, ItemId, VaultId};

/// Forward-only schema steps. Index `n` moves `user_version` from `n` to `n + 1`.
///
/// Never edit a released entry — append. The comment on each column below is
/// part of the zero-knowledge argument: every one is either an identifier the
/// server assigned, a server-clock timestamp, or the opaque blob itself.
const MIGRATIONS: &[&str] = &[
    // --- v1 --------------------------------------------------------------
    r#"
    CREATE TABLE vaults (
      vault_id   BLOB NOT NULL PRIMARY KEY,  -- 16 client-random bytes; the only user handle
      next_seq   INTEGER NOT NULL,           -- next per-vault sequence number to hand out
      created_at INTEGER NOT NULL            -- server clock, unix ms
    ) WITHOUT ROWID;

    CREATE TABLE devices (
      vault_id    BLOB NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
      device_id   BLOB NOT NULL,             -- 16 client-random bytes
      ed25519_pub BLOB NOT NULL,             -- 32 bytes; access control only, never trust
      admitted_at INTEGER NOT NULL,          -- server clock, unix ms
      admitted_by BLOB,                      -- sponsoring device, NULL for the first
      PRIMARY KEY (vault_id, device_id)
    ) WITHOUT ROWID;

    CREATE TABLE items (
      vault_id   BLOB NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
      item_id    BLOB NOT NULL,              -- 16 client-random bytes; the storage key
      seq        INTEGER NOT NULL,           -- server-assigned, per-vault monotonic
      version    INTEGER NOT NULL,           -- server-assigned, per-item monotonic
      envelope   BLOB,                       -- OPAQUE. Never parsed, hashed, or measured
      deleted    INTEGER NOT NULL,           -- advisory only (SPEC 6.1)
      updated_at INTEGER NOT NULL,           -- server clock at write, unix ms
      PRIMARY KEY (vault_id, item_id),
      -- The flag and the blob cannot disagree. Redundant state that can drift is
      -- a bug farm; a CHECK makes the redundancy safe.
      CHECK ((deleted = 0 AND envelope IS NOT NULL) OR (deleted = 1 AND envelope IS NULL))
    ) WITHOUT ROWID;

    -- The change feed's index. UNIQUE because two rows sharing a seq would make
    -- `seq > since` skip one of them.
    CREATE UNIQUE INDEX items_by_seq ON items(vault_id, seq);

    -- No foreign key to vaults, deliberately: a challenge is issued for any
    -- (vault_id, device_id) whether or not they exist, so that the endpoint is
    -- not an existence oracle.
    CREATE TABLE challenges (
      nonce_hash BLOB NOT NULL PRIMARY KEY,  -- BLAKE2b-256 of the nonce
      vault_id   BLOB NOT NULL,
      device_id  BLOB NOT NULL,
      expires_at INTEGER NOT NULL
    ) WITHOUT ROWID;

    CREATE TABLE access_tokens (
      token_hash BLOB NOT NULL PRIMARY KEY,  -- BLAKE2b-256; the token itself is never stored
      vault_id   BLOB NOT NULL,
      device_id  BLOB NOT NULL,
      family     BLOB NOT NULL,              -- rotation chain this token belongs to
      expires_at INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE INDEX access_tokens_by_family ON access_tokens(family);

    CREATE TABLE refresh_tokens (
      token_hash  BLOB NOT NULL PRIMARY KEY,
      vault_id    BLOB NOT NULL,
      device_id   BLOB NOT NULL,
      family      BLOB NOT NULL,
      expires_at  INTEGER NOT NULL,
      consumed_at INTEGER                    -- NULL until rotated; a second use is theft
    ) WITHOUT ROWID;
    CREATE INDEX refresh_tokens_by_family ON refresh_tokens(family);

    CREATE TABLE revoked_families (
      family     BLOB NOT NULL PRIMARY KEY,
      revoked_at INTEGER NOT NULL
    ) WITHOUT ROWID;

    CREATE TABLE enrollments (
      enroll_id       BLOB NOT NULL PRIMARY KEY,  -- 16 client-random bytes; a bearer capability
      x25519_pub      BLOB NOT NULL,              -- 32 bytes, as posted; opaque to the server
      enroll_request  BLOB NOT NULL,              -- OPAQUE to this server (SPEC 6.3: authenticated, not sealed)
      request_taken   INTEGER NOT NULL,           -- single-use retrieval flag
      sealed_response BLOB,                       -- OPAQUE
      expires_at      INTEGER NOT NULL
    ) WITHOUT ROWID;
    "#,
];

/// SQLite-backed [`Store`].
pub struct SqliteStore {
    connection: Mutex<Connection>,
}

impl core::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // No path, no statement cache, no row counts: a `Debug` of the store must
        // not become a second way for something about a vault to reach a log.
        f.write_str("SqliteStore")
    }
}

impl SqliteStore {
    /// Opens (creating if absent) the database at `path` and applies migrations.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the file cannot be opened, a pragma is refused, or a
    /// migration fails.
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path).map_err(db)?;
        Self::configure(&connection)?;
        let store = Self {
            connection: Mutex::new(connection),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Opens a private in-memory database. Tests and `--dry-run` style checks.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().map_err(db)?;
        Self::configure(&connection)?;
        let store = Self {
            connection: Mutex::new(connection),
        };
        store.migrate()?;
        Ok(store)
    }

    fn configure(connection: &Connection) -> Result<()> {
        // WAL and synchronous=FULL match SPEC §5's client-side settings: a
        // torn write here is a client's lost item. `busy_timeout` is belt and
        // braces given the single-connection design.
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;\
                 PRAGMA synchronous=FULL;\
                 PRAGMA foreign_keys=ON;\
                 PRAGMA busy_timeout=5000;",
            )
            .map_err(db)
    }

    fn locked(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| StoreError::Database("store lock poisoned by an earlier panic".into()))
    }
}

fn db(error: rusqlite::Error) -> StoreError {
    StoreError::Database(error.to_string())
}

fn id16(bytes: &[u8], what: &'static str) -> Result<[u8; 16]> {
    <[u8; 16]>::try_from(bytes).map_err(|_| StoreError::Corrupt(what))
}

fn key32(bytes: &[u8], what: &'static str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).map_err(|_| StoreError::Corrupt(what))
}

fn as_u64(value: i64, what: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt(what))
}

fn as_i64(value: u64, what: &'static str) -> Result<i64> {
    i64::try_from(value).map_err(|_| StoreError::Corrupt(what))
}

/// The current state of one item row, as the write path needs it.
struct Current {
    seq: u64,
    version: u64,
    envelope: Option<Vec<u8>>,
    deleted: bool,
}

fn read_current(
    tx: &Transaction<'_>,
    vault_id: VaultId,
    item_id: ItemId,
) -> Result<Option<Current>> {
    tx.query_row(
        "SELECT seq, version, envelope, deleted FROM items WHERE vault_id = ?1 AND item_id = ?2",
        rusqlite::params![
            vault_id.as_bytes().as_slice(),
            item_id.as_bytes().as_slice()
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )
    .optional()
    .map_err(db)?
    .map(|(seq, version, envelope, deleted)| {
        Ok(Current {
            seq: as_u64(seq, "items.seq")?,
            version: as_u64(version, "items.version")?,
            envelope,
            deleted: deleted != 0,
        })
    })
    .transpose()
}

/// Allocates the next per-vault `seq` inside the caller's transaction.
///
/// Allocation and the row write share one transaction, which is what makes the
/// change feed gap-free.
fn allocate_seq(tx: &Transaction<'_>, vault_id: VaultId) -> Result<u64> {
    let seq: i64 = tx
        .query_row(
            "SELECT next_seq FROM vaults WHERE vault_id = ?1",
            [vault_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(db)?;
    tx.execute(
        "UPDATE vaults SET next_seq = next_seq + 1 WHERE vault_id = ?1",
        [vault_id.as_bytes().as_slice()],
    )
    .map_err(db)?;
    as_u64(seq, "vaults.next_seq")
}

fn revoke_family_in(tx: &Transaction<'_>, family: [u8; 16], now_ms: i64) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO revoked_families (family, revoked_at) VALUES (?1, ?2)",
        rusqlite::params![family.as_slice(), now_ms],
    )
    .map_err(db)?;
    // Deleting the access tokens makes revocation take effect on the next
    // request rather than at the next sweep.
    tx.execute(
        "DELETE FROM access_tokens WHERE family = ?1",
        [family.as_slice()],
    )
    .map_err(db)?;
    Ok(())
}

impl Store for SqliteStore {
    fn migrate(&self) -> Result<()> {
        let mut guard = self.locked()?;
        let current: i64 = guard
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(db)?;
        let current = usize::try_from(current).map_err(|_| StoreError::Corrupt("user_version"))?;
        if current > MIGRATIONS.len() {
            return Err(StoreError::Database(format!(
                "database schema version {current} is newer than this binary understands \
                 ({}); refusing to run rather than risk dropping data",
                MIGRATIONS.len()
            )));
        }
        for (index, sql) in MIGRATIONS.iter().enumerate().skip(current) {
            let tx = guard.transaction().map_err(db)?;
            tx.execute_batch(sql).map_err(db)?;
            // `PRAGMA user_version` takes no parameters, hence the format. The
            // value is a loop index, not input.
            tx.execute_batch(&format!("PRAGMA user_version = {}", index + 1))
                .map_err(db)?;
            tx.commit().map_err(db)?;
            tracing::info!(target: "misty_server::store", version = index + 1, "applied migration");
        }
        Ok(())
    }

    fn put_challenge(
        &self,
        nonce_hash: [u8; 32],
        vault_id: VaultId,
        device_id: DeviceId,
        expires_at_ms: i64,
    ) -> Result<()> {
        self.locked()?
            .execute(
                "INSERT OR REPLACE INTO challenges (nonce_hash, vault_id, device_id, expires_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    nonce_hash.as_slice(),
                    vault_id.as_bytes().as_slice(),
                    device_id.as_bytes().as_slice(),
                    expires_at_ms
                ],
            )
            .map(|_| ())
            .map_err(db)
    }

    fn take_challenge(&self, nonce_hash: [u8; 32], now_ms: i64) -> Result<Option<Challenge>> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;
        let row = tx
            .query_row(
                "SELECT vault_id, device_id, expires_at FROM challenges WHERE nonce_hash = ?1",
                [nonce_hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(db)?;
        // Deleted whatever happens next. A challenge that survived a failed
        // verification would be an online guessing oracle, and one that survived
        // a successful one would be replayable.
        tx.execute(
            "DELETE FROM challenges WHERE nonce_hash = ?1",
            [nonce_hash.as_slice()],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;

        let Some((vault, device, expires_at)) = row else {
            return Ok(None);
        };
        if expires_at <= now_ms {
            return Ok(None);
        }
        Ok(Some(Challenge {
            vault_id: VaultId::from_bytes(id16(&vault, "challenges.vault_id")?),
            device_id: DeviceId::from_bytes(id16(&device, "challenges.device_id")?),
        }))
    }

    fn device(&self, vault_id: VaultId, device_id: DeviceId) -> Result<Option<Device>> {
        let stored: Option<Vec<u8>> = self
            .locked()?
            .query_row(
                "SELECT ed25519_pub FROM devices WHERE vault_id = ?1 AND device_id = ?2",
                rusqlite::params![
                    vault_id.as_bytes().as_slice(),
                    device_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        stored
            .map(|bytes| {
                Ok(Device {
                    device_id,
                    ed25519_pub: key32(&bytes, "devices.ed25519_pub")?,
                })
            })
            .transpose()
    }

    fn admit_device(
        &self,
        vault_id: VaultId,
        device_id: DeviceId,
        ed25519_pub: [u8; 32],
        sponsor: Option<DeviceId>,
        now_ms: i64,
        max_vaults: Option<u64>,
    ) -> Result<Admission> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;

        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT ed25519_pub FROM devices WHERE vault_id = ?1 AND device_id = ?2",
                rusqlite::params![
                    vault_id.as_bytes().as_slice(),
                    device_id.as_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        if let Some(bytes) = existing {
            let outcome = if key32(&bytes, "devices.ed25519_pub")? == ed25519_pub {
                Admission::AlreadyPresent
            } else {
                // Re-presenting a device id with a new key would be a takeover.
                Admission::KeyMismatch
            };
            tx.commit().map_err(db)?;
            return Ok(outcome);
        }

        let vault_exists: bool = tx
            .query_row(
                "SELECT 1 FROM vaults WHERE vault_id = ?1",
                [vault_id.as_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map_err(db)?
            .is_some();

        if !vault_exists {
            if sponsor.is_some() {
                // Nothing to sponsor into.
                return Ok(Admission::NeedsSponsor);
            }
            if let Some(max) = max_vaults {
                let count: i64 = tx
                    .query_row("SELECT COUNT(*) FROM vaults", [], |row| row.get(0))
                    .map_err(db)?;
                if as_u64(count, "vaults count")? >= max {
                    return Ok(Admission::VaultLimit);
                }
            }
            tx.execute(
                "INSERT INTO vaults (vault_id, next_seq, created_at) VALUES (?1, 1, ?2)",
                rusqlite::params![vault_id.as_bytes().as_slice(), now_ms],
            )
            .map_err(db)?;
        } else if sponsor.is_none() {
            // The vault exists and this device is unknown to it. Admission has
            // to be vouched for by an already-admitted device, or anyone who
            // learned a vault_id could start writing to it.
            return Ok(Admission::NeedsSponsor);
        }

        tx.execute(
            "INSERT INTO devices (vault_id, device_id, ed25519_pub, admitted_at, admitted_by) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                vault_id.as_bytes().as_slice(),
                device_id.as_bytes().as_slice(),
                ed25519_pub.as_slice(),
                now_ms,
                sponsor.map(|s| s.as_bytes().to_vec())
            ],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(if vault_exists {
            Admission::Admitted
        } else {
            Admission::Bootstrapped
        })
    }

    fn put_access_token(
        &self,
        token_hash: [u8; 32],
        session: Session,
        expires_at_ms: i64,
    ) -> Result<()> {
        self.locked()?
            .execute(
                "INSERT OR REPLACE INTO access_tokens \
                 (token_hash, vault_id, device_id, family, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    token_hash.as_slice(),
                    session.vault_id.as_bytes().as_slice(),
                    session.device_id.as_bytes().as_slice(),
                    session.family.as_slice(),
                    expires_at_ms
                ],
            )
            .map(|_| ())
            .map_err(db)
    }

    fn access_token(&self, token_hash: [u8; 32], now_ms: i64) -> Result<Option<Session>> {
        let row = self
            .locked()?
            .query_row(
                "SELECT vault_id, device_id, family FROM access_tokens \
                 WHERE token_hash = ?1 AND expires_at > ?2",
                rusqlite::params![token_hash.as_slice(), now_ms],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(db)?;
        row.map(|(vault, device, family)| {
            Ok(Session {
                vault_id: VaultId::from_bytes(id16(&vault, "access_tokens.vault_id")?),
                device_id: DeviceId::from_bytes(id16(&device, "access_tokens.device_id")?),
                family: id16(&family, "access_tokens.family")?,
            })
        })
        .transpose()
    }

    fn put_refresh_token(
        &self,
        token_hash: [u8; 32],
        session: Session,
        expires_at_ms: i64,
    ) -> Result<()> {
        self.locked()?
            .execute(
                "INSERT OR REPLACE INTO refresh_tokens \
                 (token_hash, vault_id, device_id, family, expires_at, consumed_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                rusqlite::params![
                    token_hash.as_slice(),
                    session.vault_id.as_bytes().as_slice(),
                    session.device_id.as_bytes().as_slice(),
                    session.family.as_slice(),
                    expires_at_ms
                ],
            )
            .map(|_| ())
            .map_err(db)
    }

    fn consume_refresh_token(&self, token_hash: [u8; 32], now_ms: i64) -> Result<RefreshOutcome> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;
        let row = tx
            .query_row(
                "SELECT vault_id, device_id, family, expires_at, consumed_at \
                 FROM refresh_tokens WHERE token_hash = ?1",
                [token_hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(db)?;

        let Some((vault, device, family, expires_at, consumed_at)) = row else {
            return Ok(RefreshOutcome::Rejected);
        };
        let session = Session {
            vault_id: VaultId::from_bytes(id16(&vault, "refresh_tokens.vault_id")?),
            device_id: DeviceId::from_bytes(id16(&device, "refresh_tokens.device_id")?),
            family: id16(&family, "refresh_tokens.family")?,
        };

        let revoked: bool = tx
            .query_row(
                "SELECT 1 FROM revoked_families WHERE family = ?1",
                [session.family.as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map_err(db)?
            .is_some();
        if revoked {
            return Ok(RefreshOutcome::Rejected);
        }

        if consumed_at.is_some() {
            // Reuse. Either the legitimate client replayed or an attacker holds
            // a copy, and the server cannot tell which — so neither keeps the
            // session. Both parties re-authenticate with the device key, which
            // only the legitimate device has.
            revoke_family_in(&tx, session.family, now_ms)?;
            tx.commit().map_err(db)?;
            return Ok(RefreshOutcome::ReuseDetected(session));
        }
        if expires_at <= now_ms {
            return Ok(RefreshOutcome::Rejected);
        }

        tx.execute(
            "UPDATE refresh_tokens SET consumed_at = ?2 WHERE token_hash = ?1",
            rusqlite::params![token_hash.as_slice(), now_ms],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(RefreshOutcome::Rotated(session))
    }

    fn revoke_family(&self, family: [u8; 16], now_ms: i64) -> Result<()> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;
        revoke_family_in(&tx, family, now_ms)?;
        tx.commit().map_err(db)
    }

    fn changes(&self, vault_id: VaultId, since: u64, limit: u32) -> Result<(Vec<Change>, bool)> {
        // One row over the limit answers `has_more` without a second COUNT, and
        // the extra row is discarded rather than returned.
        let probe = i64::from(limit).saturating_add(1);
        let guard = self.locked()?;
        let mut statement = guard
            .prepare_cached(
                "SELECT item_id, seq, version, envelope, deleted FROM items \
                 WHERE vault_id = ?1 AND seq > ?2 ORDER BY seq ASC LIMIT ?3",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                rusqlite::params![
                    vault_id.as_bytes().as_slice(),
                    as_i64(since, "since")?,
                    probe
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .map_err(db)?;

        let mut changes = Vec::new();
        let mut has_more = false;
        for row in rows {
            let (item, seq, version, envelope, deleted) = row.map_err(db)?;
            if changes.len() >= limit as usize {
                has_more = true;
                break;
            }
            changes.push(Change {
                item_id: ItemId::from_bytes(id16(&item, "items.item_id")?),
                seq: as_u64(seq, "items.seq")?,
                version: as_u64(version, "items.version")?,
                envelope,
                deleted: deleted != 0,
            });
        }
        Ok((changes, has_more))
    }

    fn put_item(
        &self,
        vault_id: VaultId,
        item_id: ItemId,
        precondition: Precondition,
        envelope: Vec<u8>,
        limits: Limits,
        now_ms: i64,
    ) -> Result<WriteOutcome> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;
        let current = read_current(&tx, vault_id, item_id)?;

        let previous_len = match (&current, precondition) {
            (None, p) if p.expects_absent() => 0u64,
            (None, _) => {
                // No such item, but the client expected a version. Version 0
                // says "absent" without a second response shape.
                return Ok(WriteOutcome::Conflict {
                    version: 0,
                    envelope: None,
                });
            }
            (Some(row), p) if p.0 == row.version => {
                row.envelope.as_ref().map_or(0, |e| e.len() as u64)
            }
            (Some(row), _) => {
                return Ok(WriteOutcome::Conflict {
                    version: row.version,
                    envelope: row.envelope.clone(),
                });
            }
        };

        let (rows, bytes) = tx
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(envelope)), 0) FROM items \
                 WHERE vault_id = ?1",
                [vault_id.as_bytes().as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(db)?;
        let rows = as_u64(rows, "items count")?;
        let bytes = as_u64(bytes, "items bytes")?;

        if current.is_none() && rows >= limits.max_rows {
            return Ok(WriteOutcome::ItemLimit);
        }
        let projected = bytes
            .saturating_sub(previous_len)
            .saturating_add(envelope.len() as u64);
        if projected > limits.max_bytes {
            return Ok(WriteOutcome::ByteLimit);
        }

        let seq = allocate_seq(&tx, vault_id)?;
        let version = current.as_ref().map_or(0, |row| row.version) + 1;
        tx.execute(
            "INSERT INTO items (vault_id, item_id, seq, version, envelope, deleted, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6) \
             ON CONFLICT(vault_id, item_id) DO UPDATE SET \
               seq = excluded.seq, version = excluded.version, \
               envelope = excluded.envelope, deleted = 0, updated_at = excluded.updated_at",
            rusqlite::params![
                vault_id.as_bytes().as_slice(),
                item_id.as_bytes().as_slice(),
                as_i64(seq, "seq")?,
                as_i64(version, "version")?,
                envelope,
                now_ms
            ],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(WriteOutcome::Ok(Written { seq, version }))
    }

    fn delete_item(
        &self,
        vault_id: VaultId,
        item_id: ItemId,
        precondition: Precondition,
        now_ms: i64,
    ) -> Result<WriteOutcome> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;
        let Some(current) = read_current(&tx, vault_id, item_id)? else {
            return Ok(WriteOutcome::Missing);
        };
        if precondition.0 != current.version {
            return Ok(WriteOutcome::Conflict {
                version: current.version,
                envelope: current.envelope,
            });
        }
        if current.deleted {
            // Idempotent: the bytes are already gone, so burning a `seq` would
            // only make every client re-fetch a row that has not changed.
            return Ok(WriteOutcome::Ok(Written {
                seq: current.seq,
                version: current.version,
            }));
        }
        let seq = allocate_seq(&tx, vault_id)?;
        let version = current.version + 1;
        tx.execute(
            "UPDATE items SET seq = ?3, version = ?4, envelope = NULL, deleted = 1, \
             updated_at = ?5 WHERE vault_id = ?1 AND item_id = ?2",
            rusqlite::params![
                vault_id.as_bytes().as_slice(),
                item_id.as_bytes().as_slice(),
                as_i64(seq, "seq")?,
                as_i64(version, "version")?,
                now_ms
            ],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(WriteOutcome::Ok(Written { seq, version }))
    }

    fn usage(&self, vault_id: VaultId) -> Result<Usage> {
        let (rows, items, bytes) = self
            .locked()?
            .query_row(
                "SELECT COUNT(*), COUNT(envelope), COALESCE(SUM(LENGTH(envelope)), 0) \
                 FROM items WHERE vault_id = ?1",
                [vault_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .map_err(db)?;
        Ok(Usage {
            bytes_used: as_u64(bytes, "items bytes")?,
            item_count: as_u64(items, "items live")?,
            row_count: as_u64(rows, "items rows")?,
        })
    }

    fn enroll_begin(
        &self,
        enroll_id: EnrollId,
        x25519_pub: [u8; 32],
        enroll_request: Vec<u8>,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<EnrollBegin> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;
        // An expired record is not a collision; reclaim it first so a retried
        // enrollment is not blocked by a stale id.
        tx.execute(
            "DELETE FROM enrollments WHERE enroll_id = ?1 AND expires_at <= ?2",
            rusqlite::params![enroll_id.as_bytes().as_slice(), now_ms],
        )
        .map_err(db)?;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO enrollments \
                 (enroll_id, x25519_pub, enroll_request, request_taken, sealed_response, expires_at) \
                 VALUES (?1, ?2, ?3, 0, NULL, ?4)",
                rusqlite::params![
                    enroll_id.as_bytes().as_slice(),
                    x25519_pub.as_slice(),
                    enroll_request,
                    expires_at_ms
                ],
            )
            .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(if inserted == 1 {
            EnrollBegin::Created
        } else {
            EnrollBegin::Exists
        })
    }

    fn enroll_take_request(&self, enroll_id: EnrollId, now_ms: i64) -> Result<EnrollRequest> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;
        let row = tx
            .query_row(
                "SELECT x25519_pub, enroll_request FROM enrollments \
                 WHERE enroll_id = ?1 AND expires_at > ?2 AND request_taken = 0",
                rusqlite::params![enroll_id.as_bytes().as_slice(), now_ms],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(db)?;
        let Some((x25519_pub, enroll_request)) = row else {
            return Ok(EnrollRequest::Gone);
        };
        tx.execute(
            "UPDATE enrollments SET request_taken = 1 WHERE enroll_id = ?1",
            [enroll_id.as_bytes().as_slice()],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(EnrollRequest::Ready {
            x25519_pub: key32(&x25519_pub, "enrollments.x25519_pub")?,
            enroll_request,
        })
    }

    fn enroll_complete(
        &self,
        enroll_id: EnrollId,
        sealed_response: Vec<u8>,
        now_ms: i64,
    ) -> Result<EnrollComplete> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;
        let state: Option<bool> = tx
            .query_row(
                "SELECT sealed_response IS NOT NULL FROM enrollments \
                 WHERE enroll_id = ?1 AND expires_at > ?2",
                rusqlite::params![enroll_id.as_bytes().as_slice(), now_ms],
                |row| row.get::<_, i64>(0).map(|v| v != 0),
            )
            .optional()
            .map_err(db)?;
        let outcome = match state {
            None => EnrollComplete::Missing,
            Some(true) => EnrollComplete::AlreadyAnswered,
            Some(false) => {
                tx.execute(
                    "UPDATE enrollments SET sealed_response = ?2 WHERE enroll_id = ?1",
                    rusqlite::params![enroll_id.as_bytes().as_slice(), sealed_response],
                )
                .map_err(db)?;
                EnrollComplete::Stored
            }
        };
        tx.commit().map_err(db)?;
        Ok(outcome)
    }

    fn enroll_take_response(&self, enroll_id: EnrollId, now_ms: i64) -> Result<EnrollResponse> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;
        let row: Option<Option<Vec<u8>>> = tx
            .query_row(
                "SELECT sealed_response FROM enrollments \
                 WHERE enroll_id = ?1 AND expires_at > ?2",
                rusqlite::params![enroll_id.as_bytes().as_slice(), now_ms],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        let outcome = match row {
            None => EnrollResponse::Gone,
            Some(None) => EnrollResponse::Pending,
            Some(Some(sealed)) => {
                // Terminal: the record is destroyed so a second reader — or the
                // operator, later — gets nothing.
                tx.execute(
                    "DELETE FROM enrollments WHERE enroll_id = ?1",
                    [enroll_id.as_bytes().as_slice()],
                )
                .map_err(db)?;
                EnrollResponse::Ready(sealed)
            }
        };
        tx.commit().map_err(db)?;
        Ok(outcome)
    }

    fn sweep(&self, now_ms: i64, tombstone_horizon_ms: i64) -> Result<Swept> {
        let mut guard = self.locked()?;
        let tx = guard.transaction().map_err(db)?;
        let challenges = tx
            .execute("DELETE FROM challenges WHERE expires_at <= ?1", [now_ms])
            .map_err(db)?;
        let access = tx
            .execute("DELETE FROM access_tokens WHERE expires_at <= ?1", [now_ms])
            .map_err(db)?;
        let refresh = tx
            .execute(
                "DELETE FROM refresh_tokens WHERE expires_at <= ?1",
                [now_ms],
            )
            .map_err(db)?;
        // A revocation record is needed only while a token in its family could
        // still be presented.
        let families = tx
            .execute(
                "DELETE FROM revoked_families WHERE family NOT IN \
                 (SELECT family FROM refresh_tokens)",
                [],
            )
            .map_err(db)?;
        let enrollments = tx
            .execute("DELETE FROM enrollments WHERE expires_at <= ?1", [now_ms])
            .map_err(db)?;
        // SPEC §4: tombstones purge after 90 days. Removing the row releases the
        // item slot; any client still holding a version this old will conflict
        // with "absent" rather than silently overwrite.
        let tombstones = tx
            .execute(
                "DELETE FROM items WHERE envelope IS NULL AND updated_at <= ?1",
                [tombstone_horizon_ms],
            )
            .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(Swept {
            challenges: challenges as u64,
            tokens: (access + refresh + families) as u64,
            enrollments: enrollments as u64,
            tombstones: tombstones as u64,
        })
    }

    fn schema_columns(&self) -> Result<Vec<(String, String)>> {
        let guard = self.locked()?;
        let mut statement = guard
            .prepare(
                "SELECT m.name, p.name FROM sqlite_master m \
                 JOIN pragma_table_info(m.name) p \
                 WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%' \
                 ORDER BY m.name, p.cid",
            )
            .map_err(db)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(db)?);
        }
        Ok(out)
    }
}
