// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The backend that works on every target, including `wasm32-unknown-unknown`.

use std::collections::BTreeMap;

use misty_crypto::ItemId;

use crate::error::{Result, VaultError};
use crate::store::{StoredEnvelope, VaultStore};

/// An in-memory vault store.
///
/// Required by SPEC §5 ("an in-memory backend MUST exist for tests on every
/// target"), and it is not only for tests: it is the reference implementation of
/// the transaction contract, and a wasm build has it before it has IndexedDB.
///
/// Transactions are snapshots. That is O(n) in the number of rows on `begin`,
/// which for a sub-10 000-item vault of ~500-byte envelopes is a few megabytes and
/// microseconds — and it buys an exactly-correct rollback with no journal to get
/// wrong. Nested transactions push a second snapshot, so a savepoint behaves the
/// same way it does in SQLite.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    rows: BTreeMap<ItemId, StoredEnvelope>,
    epoch: u32,
    snapshots: Vec<(BTreeMap<ItemId, StoredEnvelope>, u32)>,
}

impl MemoryStore {
    /// An empty store at epoch 0.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many rows. Test-facing; the vault counts items, not rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the store holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// How many transactions are open. Used by tests to prove that a failed
    /// merge left nothing dangling.
    #[must_use]
    pub fn open_transactions(&self) -> usize {
        self.snapshots.len()
    }
}

impl VaultStore for MemoryStore {
    fn load_all(&self) -> Result<Vec<StoredEnvelope>> {
        Ok(self.rows.values().cloned().collect())
    }

    fn get(&self, item_id: &ItemId) -> Result<Option<StoredEnvelope>> {
        Ok(self.rows.get(item_id).cloned())
    }

    fn put(&mut self, record: &StoredEnvelope) -> Result<()> {
        self.rows.insert(record.item_id, record.clone());
        Ok(())
    }

    fn remove(&mut self, item_id: &ItemId) -> Result<()> {
        self.rows.remove(item_id);
        Ok(())
    }

    fn epoch(&self) -> Result<u32> {
        Ok(self.epoch)
    }

    fn set_epoch(&mut self, epoch: u32) -> Result<()> {
        self.epoch = epoch;
        Ok(())
    }

    fn begin(&mut self) -> Result<()> {
        self.snapshots.push((self.rows.clone(), self.epoch));
        Ok(())
    }

    fn commit(&mut self) -> Result<()> {
        self.snapshots
            .pop()
            .map(|_| ())
            .ok_or(VaultError::NoTransaction)
    }

    fn rollback(&mut self) -> Result<()> {
        let (rows, epoch) = self.snapshots.pop().ok_or(VaultError::NoTransaction)?;
        self.rows = rows;
        self.epoch = epoch;
        Ok(())
    }
}
