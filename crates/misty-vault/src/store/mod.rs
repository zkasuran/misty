// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Storage, behind a trait because SQLite cannot follow the core to the web.
//!
//! SPEC §5: `rusqlite`'s bundled SQLite is C, and C does not compile to
//! `wasm32-unknown-unknown`. So the model, the CRDT and the merge logic are
//! backend-agnostic, the SQLite backend is a **target-conditional dependency**
//! rather than an off-by-default feature — native builds get it automatically and
//! a wasm build never sees it — and web builds supply an IndexedDB backend
//! through the same trait. [`MemoryStore`] exists on every target, including wasm.
//!
//! # What the schema does *not* contain
//!
//! ```text
//! items(item_id, kind, seq, version, envelope BLOB, hlc_max)
//! ```
//!
//! There is no issuer column, no account column, no tag table, and no index over
//! anything but the primary key. That is the point: an index is a data structure
//! whose *shape* answers questions about its contents, and "does this vault
//! contain an entry for `binance.com`" is exactly the question threat model `A1`
//! spends the whole envelope format refusing to answer. Search, sort and filter
//! run over the decrypted in-memory model instead (SPEC §5); vaults are under
//! 10 000 items, so that is both simpler and quieter than any encrypted-index
//! scheme.
//!
//! `hlc_max` is the one derived value stored in the clear, and it is stored as the
//! 26 big-endian bytes of [`Hlc::to_sort_bytes`], so SQLite's own `memcmp`
//! ordering of the blob is the [`Hlc`] ordering. It exists so a sync layer can
//! order changes without decrypting anything, and it leaks only what `seq` already
//! does: that something changed, and roughly when.
//!
//! # One writer
//!
//! SPEC §5 requires writes to be serialised through the vault handle. Here that is
//! the borrow checker's job rather than a mutex's: every mutating method takes
//! `&mut self`, [`Vault`](crate::Vault) owns its store by value, and there is no
//! `Clone` and no interior mutability anywhere in a backend. Two concurrent
//! writers do not compile.
//!
//! # Transactions
//!
//! [`VaultStore::transaction`] is a provided method over
//! [`begin`](VaultStore::begin), [`commit`](VaultStore::commit) and
//! [`rollback`](VaultStore::rollback). Splitting it that way is what makes a
//! *wrapper* backend possible — the crash-injection store in
//! `tests/crash_injection.rs` fails the Nth write and delegates the rest — which
//! would be impossible if `transaction` were the only primitive, because a wrapper
//! cannot hand its inner store a closure that expects the wrapper.

mod memory;
#[cfg(not(target_arch = "wasm32"))]
mod schema;
#[cfg(not(target_arch = "wasm32"))]
mod sqlite;

pub use memory::MemoryStore;
#[cfg(not(target_arch = "wasm32"))]
pub use schema::{MIGRATIONS, SCHEMA_VERSION};
#[cfg(not(target_arch = "wasm32"))]
pub use sqlite::SqliteStore;

use misty_crypto::envelope::EnvelopeKind;
use misty_crypto::ItemId;

use crate::error::Result;
use crate::hlc::Hlc;

/// One row: an opaque envelope and the handful of columns a backend may see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEnvelope {
    /// Storage key. Bound into the envelope's AAD but not stored inside it
    /// (SPEC §2.4), which is why it is a column.
    pub item_id: ItemId,
    /// What the envelope holds. Redundant with the envelope header, and stored
    /// anyway so a backend can answer "give me the groups" without decrypting.
    pub kind: EnvelopeKind,
    /// The server's monotonic sequence number for this item, once it has been
    /// pushed. `None` for an item this device has not synced.
    pub seq: Option<i64>,
    /// The server's optimistic-concurrency token, used as `If-Match` (SPEC §6.1).
    /// Opaque here: the sync layer owns its meaning, and the vault stores it
    /// verbatim so a crash cannot lose it.
    pub version: Option<Vec<u8>>,
    /// The sealed envelope, exactly as `misty_crypto::envelope::seal` produced it.
    pub envelope: Vec<u8>,
    /// The greatest [`Hlc`] anywhere in the payload.
    pub hlc_max: Hlc,
}

/// What the vault needs from a storage backend.
///
/// SPEC §5 sketches this trait with a `put(&mut self, id, env, hlc)`. The
/// signature here takes a whole [`StoredEnvelope`] instead, because the schema in
/// the same section has six columns and a three-argument `put` cannot write
/// `kind`, `seq` or `version` — a sync layer that could not persist the
/// concurrency token it just received would have to re-fetch after every crash.
pub trait VaultStore {
    /// Every row, in no particular order.
    ///
    /// # Errors
    ///
    /// [`VaultError::Storage`](crate::VaultError::Storage) if the backend fails.
    fn load_all(&self) -> Result<Vec<StoredEnvelope>>;

    /// One row, if it exists.
    ///
    /// # Errors
    ///
    /// As [`load_all`](VaultStore::load_all).
    fn get(&self, item_id: &ItemId) -> Result<Option<StoredEnvelope>>;

    /// Writes a row, replacing any row with the same `item_id`.
    ///
    /// # Errors
    ///
    /// As [`load_all`](VaultStore::load_all).
    fn put(&mut self, record: &StoredEnvelope) -> Result<()>;

    /// Deletes a row outright. Only the tombstone purge does this: an ordinary
    /// delete is a signed tombstone *inside* an envelope, so it can be replicated
    /// and so a hostile server cannot forge one by dropping a row.
    ///
    /// # Errors
    ///
    /// As [`load_all`](VaultStore::load_all).
    fn remove(&mut self, item_id: &ItemId) -> Result<()>;

    /// The current key epoch (SPEC §2.2).
    ///
    /// # Errors
    ///
    /// As [`load_all`](VaultStore::load_all).
    fn epoch(&self) -> Result<u32>;

    /// Records a new current epoch.
    ///
    /// # Errors
    ///
    /// As [`load_all`](VaultStore::load_all).
    fn set_epoch(&mut self, epoch: u32) -> Result<()>;

    /// Opens a transaction, or a nested savepoint inside one.
    ///
    /// # Errors
    ///
    /// As [`load_all`](VaultStore::load_all).
    fn begin(&mut self) -> Result<()>;

    /// Commits the innermost open transaction.
    ///
    /// # Errors
    ///
    /// [`VaultError::NoTransaction`](crate::VaultError::NoTransaction) if none is
    /// open, or a backend failure.
    fn commit(&mut self) -> Result<()>;

    /// Discards the innermost open transaction.
    ///
    /// # Errors
    ///
    /// As [`commit`](VaultStore::commit).
    fn rollback(&mut self) -> Result<()>;

    /// Runs `f` inside a transaction, committing on `Ok` and rolling back on
    /// `Err`.
    ///
    /// This is how SPEC §5's "every merge is a single transaction. A crash
    /// mid-sync MUST leave the vault at its pre-merge state" is met on the storage
    /// side. The in-memory model is rolled back separately, by
    /// [`Vault`](crate::Vault) applying merges to a copy and only adopting it once
    /// this returns `Ok`.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns, or a backend failure from the transaction control
    /// itself. If the rollback *also* fails, the rollback's error is returned in
    /// place of `f`'s: a store that cannot roll back is a more serious problem
    /// than whatever asked it to.
    fn transaction<R>(&mut self, f: impl FnOnce(&mut Self) -> Result<R>) -> Result<R>
    where
        Self: Sized,
    {
        self.begin()?;
        match f(self) {
            Ok(value) => {
                self.commit()?;
                Ok(value)
            }
            Err(error) => {
                self.rollback()?;
                Err(error)
            }
        }
    }
}
