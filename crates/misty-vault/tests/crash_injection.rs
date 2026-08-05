// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SPEC §5: "Every merge is a single transaction. A crash mid-sync MUST leave the
//! vault at its pre-merge state. Crash-injection tests are required, not optional."
//!
//! A store wrapper fails the Nth write, and the assertion is made for **every** N
//! across a multi-item merge — not just the first and last, because the interesting
//! failure is the one in the middle, where some rows have landed and some have not.
//!
//! Two things are checked at every position, and both matter:
//!
//! 1. the **database** is byte-identical to its pre-merge state, which is the
//!    transaction's job;
//! 2. the **in-memory model** is byte-identical too, which is the vault's job. A
//!    rolled-back database behind a model that already adopted the merge is the
//!    worse of the two bugs: the user sees the change, and it silently vanishes on
//!    the next restart.

mod support;

use std::cell::Cell;
use std::rc::Rc;

use misty_crypto::ItemId;
use misty_otp::FixedClock;
use misty_vault::{
    Edit, MemoryStore, RemoteChange, Result, StoredEnvelope, Vault, VaultError, VaultStore,
};
use support::{changes, device, new_item, peer, roster, vault_key, NOW};

/// The knob the test turns, shared with the store the vault owns.
#[derive(Clone, Default)]
struct Fuse {
    fail_at: Rc<Cell<Option<usize>>>,
    writes: Rc<Cell<usize>>,
}

impl Fuse {
    fn arm(&self, nth: usize) {
        self.writes.set(0);
        self.fail_at.set(Some(nth));
    }

    fn disarm(&self) {
        self.fail_at.set(None);
    }

    fn writes(&self) -> usize {
        self.writes.get()
    }
}

/// A store that fails the Nth write and delegates everything else.
///
/// This is what [`VaultStore`]'s split into `begin`/`commit`/`rollback` plus a
/// provided `transaction` buys: a wrapper cannot hand its inner store a closure
/// that expects the wrapper, so with `transaction` as the only primitive this test
/// would be impossible to write.
struct FailingStore {
    inner: MemoryStore,
    fuse: Fuse,
}

impl FailingStore {
    fn new(fuse: Fuse) -> Self {
        Self {
            inner: MemoryStore::new(),
            fuse,
        }
    }

    fn tick(&self) -> Result<()> {
        let count = self.fuse.writes.get() + 1;
        self.fuse.writes.set(count);
        if self.fuse.fail_at.get() == Some(count) {
            return Err(VaultError::Storage {
                detail: format!("injected failure at write {count}"),
            });
        }
        Ok(())
    }
}

impl VaultStore for FailingStore {
    fn load_all(&self) -> Result<Vec<StoredEnvelope>> {
        self.inner.load_all()
    }

    fn get(&self, item_id: &ItemId) -> Result<Option<StoredEnvelope>> {
        self.inner.get(item_id)
    }

    fn put(&mut self, record: &StoredEnvelope) -> Result<()> {
        self.tick()?;
        self.inner.put(record)
    }

    fn remove(&mut self, item_id: &ItemId) -> Result<()> {
        self.tick()?;
        self.inner.remove(item_id)
    }

    fn epoch(&self) -> Result<u32> {
        self.inner.epoch()
    }

    fn set_epoch(&mut self, epoch: u32) -> Result<()> {
        self.inner.set_epoch(epoch)
    }

    fn begin(&mut self) -> Result<()> {
        self.inner.begin()
    }

    fn commit(&mut self) -> Result<()> {
        self.inner.commit()
    }

    fn rollback(&mut self) -> Result<()> {
        self.inner.rollback()
    }
}

type Peer = Vault<FailingStore, FixedClock>;

fn failing_vault(fuse: Fuse, seeds: &[u8]) -> Peer {
    let identities: Vec<_> = seeds.iter().copied().map(device).collect();
    let refs: Vec<_> = identities.iter().collect();
    Vault::open(
        FailingStore::new(fuse),
        FixedClock::new(NOW),
        vault_key(),
        device(seeds[0]),
        roster(&refs),
    )
    .expect("open")
}

/// Rows, sorted, as the bytes a restart would read back.
fn rows(vault: &Peer) -> Vec<StoredEnvelope> {
    let mut out = vault.store().load_all().expect("load_all");
    out.sort_by_key(|row| row.item_id);
    out
}

fn model(vault: &Peer) -> Vec<u8> {
    vault
        .item_set()
        .fingerprint()
        .expect("fingerprint")
        .to_vec()
}

/// Builds a peer holding `count` items, and a change feed from another device that
/// updates every one of them plus adds one more.
fn scenario(count: usize) -> (Vec<RemoteChange>, Vec<ItemId>) {
    let seeds = [1u8, 2];
    let mut other = peer(2, &seeds, NOW);
    let ids: Vec<ItemId> = (0..count)
        .map(|index| {
            other
                .add(new_item(
                    &format!("issuer {index}"),
                    &format!("account {index}"),
                    &[0x40 + u8::try_from(index).expect("small"); 10],
                ))
                .expect("add")
        })
        .collect();
    (changes(&other), ids)
}

/// The required test: for every write position N in a multi-item merge, a failure
/// at N leaves both the database and the model exactly as they were.
#[test]
fn a_failure_at_every_write_position_leaves_the_vault_untouched() {
    const ITEMS: usize = 5;
    let (feed, _) = scenario(ITEMS);

    // How many writes a clean merge performs, so the loop covers every position
    // rather than a guess.
    let probe = Fuse::default();
    let mut clean = failing_vault(probe.clone(), &[1, 2]);
    // Give the vault some prior state, so "unchanged" is a non-trivial claim.
    let local = clean
        .add(new_item("Local", "ada", b"zzzzzzzzzz"))
        .expect("add");
    clean.add_tag(&local, "keep").expect("tag");
    probe.arm(usize::MAX);
    let report = clean.merge_remote(&feed).expect("clean merge");
    let total_writes = probe.writes();
    assert_eq!(report.items_written.len(), ITEMS);
    assert!(
        total_writes >= ITEMS,
        "{total_writes} writes for {ITEMS} items"
    );

    for nth in 1..=total_writes {
        let fuse = Fuse::default();
        let mut vault = failing_vault(fuse.clone(), &[1, 2]);
        let local = vault
            .add(new_item("Local", "ada", b"zzzzzzzzzz"))
            .expect("add");
        vault.add_tag(&local, "keep").expect("tag");
        // Captured per iteration: item ids and envelope nonces are random, so the
        // baseline is only meaningful against the vault it came from.
        let before_rows = rows(&vault);
        let before_model = model(&vault);

        fuse.arm(nth);
        let error = vault.merge_remote(&feed).expect_err("merge must fail");
        fuse.disarm();

        assert!(
            matches!(error, VaultError::Storage { .. }),
            "N={nth}: unexpected error {error:?}"
        );
        assert_eq!(rows(&vault), before_rows, "N={nth}: database changed");
        assert_eq!(model(&vault), before_model, "N={nth}: model changed");
        assert_eq!(
            vault.store().inner.open_transactions(),
            0,
            "N={nth}: a transaction was left open"
        );
        assert_eq!(vault.list().count(), 1, "N={nth}: an item leaked in");

        // And the vault is still usable: the same merge succeeds afterwards.
        let report = vault.merge_remote(&feed).expect("retry");
        assert_eq!(report.items_written.len(), ITEMS);
        assert_eq!(vault.list().count(), ITEMS + 1);
    }
}

/// A single-item write is a transaction too, and the same guarantee applies to it.
#[test]
fn a_failed_local_edit_changes_nothing() {
    let fuse = Fuse::default();
    let mut vault = failing_vault(fuse.clone(), &[1]);
    let id = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    let before_rows = rows(&vault);
    let before_model = model(&vault);

    fuse.arm(1);
    let error = vault
        .update(&id, Edit::new().nickname(Some("work".into())))
        .expect_err("must fail");
    fuse.disarm();

    assert!(matches!(error, VaultError::Storage { .. }));
    assert_eq!(rows(&vault), before_rows);
    assert_eq!(model(&vault), before_model);
    assert_eq!(vault.item(&id).expect("item").nickname(), None);
    assert_eq!(vault.store().inner.open_transactions(), 0);
}

/// A failed purge must not drop the item from the model either — the model and the
/// rows have to agree in both directions.
#[test]
fn a_failed_purge_keeps_the_row_and_the_model() {
    let fuse = Fuse::default();
    let mut vault = failing_vault(fuse.clone(), &[1]);
    let id = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    vault.delete_item(&id).expect("delete");
    vault.clock().set(NOW + 91 * 24 * 60 * 60 * 1000);
    let before_rows = rows(&vault);
    let before_model = model(&vault);

    fuse.arm(1);
    let error = vault.purge_tombstones().expect_err("must fail");
    fuse.disarm();

    assert!(matches!(error, VaultError::Storage { .. }));
    assert_eq!(rows(&vault), before_rows);
    assert_eq!(model(&vault), before_model);
    assert!(vault.get(&id).is_some());

    // Retried, it succeeds and both sides move together.
    assert_eq!(vault.purge_tombstones().expect("purge"), vec![id]);
    assert!(vault.get(&id).is_none());
    assert!(rows(&vault).is_empty());
}

/// The same guarantee, through the real SQL engine rather than the snapshotting
/// memory store: `BEGIN IMMEDIATE` plus `ROLLBACK` has to give the same answer as a
/// cloned map, or the two backends do not implement the same contract.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn sqlite_rolls_back_a_failed_batch() {
    use misty_vault::SqliteStore;

    let mut store = SqliteStore::open_in_memory().expect("open");
    let record = |byte: u8| StoredEnvelope {
        item_id: ItemId::from_bytes([byte; 16]),
        kind: misty_crypto::envelope::EnvelopeKind::Item,
        seq: Some(i64::from(byte)),
        version: Some(vec![byte]),
        envelope: vec![byte; 32],
        hlc_max: misty_vault::Hlc::new(NOW, 0, misty_crypto::DeviceId::from_bytes([byte; 16]))
            .expect("hlc"),
    };
    store.put(&record(1)).expect("first row");

    let outcome: Result<()> = store.transaction(|store| {
        store.put(&record(2))?;
        store.put(&record(3))?;
        Err(VaultError::Storage {
            detail: "injected".to_owned(),
        })
    });
    assert!(outcome.is_err());

    let rows = store.load_all().expect("load_all");
    assert_eq!(rows, vec![record(1)]);

    // A nested savepoint rolls back on its own without taking the outer
    // transaction with it.
    store
        .transaction(|store| {
            store.put(&record(4))?;
            let inner: Result<()> = store.transaction(|store| {
                store.put(&record(5))?;
                Err(VaultError::Storage {
                    detail: "injected".to_owned(),
                })
            });
            assert!(inner.is_err());
            Ok(())
        })
        .expect("outer commits");
    let mut ids: Vec<[u8; 16]> = store
        .load_all()
        .expect("load_all")
        .into_iter()
        .map(|row| *row.item_id.as_bytes())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, vec![[1; 16], [4; 16]]);
}
