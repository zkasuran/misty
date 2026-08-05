// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Interruption: kill the sync at every point it can be killed, and prove that no
//! write is lost and none is applied twice.
//!
//! A sync's await points are the requests it makes and the durable saves it
//! performs, so "kill it at every await point" is enumerated by failing the *n*-th
//! request for every *n*, and then the *n*-th state save for every *n*. Both sweeps
//! run over a multi-item batch, and after each interruption the engine is rebuilt
//! from the bytes the store had actually persisted — a real restart, not a clone of
//! a live object.
//!
//! What is asserted after each one:
//!
//! * every item the client wrote is on the server, and
//! * the server's envelope for each item is the one the client currently holds, and
//! * the peer converges to a byte-identical model.
//!
//! The second is the "not applied twice" half. A resend after an interruption
//! carries the same `If-Match` as the send that may already have landed, so the
//! server either applies it once or answers `409` — and a `409` is resolved by a
//! merge, which is idempotent. There is no interleaving that produces two distinct
//! values from one write.

mod support;

use misty_sync::runtime::block_on;
use misty_sync::{PutOutcome, Result, StateStore, SyncError, SyncState};
use support::{converge, Fixture};

/// A state store that fails its `n`-th save and then keeps failing.
///
/// Failing *and then recovering* would test something easier: the interesting case
/// is a process that dies, so once this store has refused a save it never accepts
/// another, and the persisted bytes are exactly what a restart would find.
#[derive(Debug)]
struct FailingStore {
    inner: misty_sync::MemoryStateStore,
    fail_from: usize,
    saves: std::cell::Cell<usize>,
}

impl FailingStore {
    fn new(fail_from: usize) -> Self {
        Self {
            inner: misty_sync::MemoryStateStore::new(),
            fail_from,
            saves: std::cell::Cell::new(0),
        }
    }

    fn persisted(&self) -> Option<Vec<u8>> {
        self.inner.persisted().map(<[u8]>::to_vec)
    }
}

impl StateStore for FailingStore {
    fn load(&self) -> Result<SyncState> {
        self.inner.load()
    }

    fn save(&mut self, state: &SyncState) -> Result<()> {
        let index = self.saves.get();
        self.saves.set(index + 1);
        if index >= self.fail_from {
            return Err(SyncError::StateStore { operation: "save" });
        }
        self.inner.save(state)
    }
}

/// How many items each sweep pushes. Enough that a failure can land before the
/// batch, inside it, and after it.
const ITEMS: u8 = 5;

#[test]
fn a_transport_failure_at_every_request_index_loses_no_write() {
    // 0 is "the network was never there"; 24 is well past the last request an
    // honest run makes, so the sweep covers before, during and after the batch.
    for kill_at in 0..24usize {
        let fixture = Fixture::new(2);
        let mut alice = fixture.peer(0);
        let mut bob = fixture.peer(1);

        let mut ids = Vec::new();
        for index in 0..ITEMS {
            ids.push(alice.add(&format!("Issuer {index}"), "ada", &[b'a' + index; 16]));
        }

        fixture.server.set_faults(misty_sync::Faults {
            offline_after: Some(kill_at),
            ..misty_sync::Faults::default()
        });
        // Either it finished before the kill point or it did not; both are valid
        // starting states for the recovery.
        let _ = alice.sync();

        fixture.server.heal();
        let mut alice = fixture.restart(alice, 0);
        converge(&mut alice, &mut bob);

        let held = fixture.server.snapshot();
        assert_eq!(
            held.len(),
            usize::from(ITEMS),
            "killed at request {kill_at}: every write reached the server"
        );
        for id in &ids {
            let local = alice
                .vault
                .stored(id)
                .expect("read the row")
                .expect("alice still holds it")
                .envelope;
            assert_eq!(
                held.get(id),
                Some(&local),
                "killed at request {kill_at}: the server holds exactly what alice holds"
            );
            assert!(bob.vault.get(id).is_some(), "killed at request {kill_at}");
        }
        assert_eq!(
            alice.digest(),
            bob.digest(),
            "killed at request {kill_at}: converged"
        );
        assert_eq!(
            alice.engine.pending(&alice.vault).expect("pending").len(),
            0
        );
    }
}

#[test]
fn a_state_save_failure_at_every_index_loses_no_write() {
    // A durable save is the only other await-shaped step: the vault has committed,
    // the server has answered, and the bookkeeping is what dies. That is precisely
    // the window in which a *remembered* outbound queue loses a write, and the
    // window a derived one does not have.
    for kill_at in 0..12usize {
        let fixture = Fixture::new(2);
        let mut alice = fixture.peer_with_store(0, FailingStore::new(kill_at));
        let mut bob = fixture.peer(1);

        let mut ids = Vec::new();
        for index in 0..ITEMS {
            ids.push(alice.add(&format!("Issuer {index}"), "ada", &[b'a' + index; 16]));
        }
        let _ = alice.sync();

        // Resume from what the store actually wrote, not from the engine's memory:
        // after a failed save those two differ, and that difference is the bug this
        // sweep is looking for.
        let persisted = alice.engine.store().persisted();
        let mut alice = fixture.resume(alice, 0, persisted.as_deref());
        converge(&mut alice, &mut bob);

        assert_eq!(
            fixture.server.snapshot().len(),
            usize::from(ITEMS),
            "save killed at {kill_at}: every write reached the server"
        );
        for id in &ids {
            assert!(bob.vault.get(id).is_some(), "save killed at {kill_at}");
            let local = alice
                .vault
                .stored(id)
                .expect("read the row")
                .expect("alice still holds it")
                .envelope;
            assert_eq!(
                fixture.server.envelope_of(id).as_ref(),
                Some(&local),
                "save killed at {kill_at}: no divergent second value"
            );
        }
        assert_eq!(alice.digest(), bob.digest(), "save killed at {kill_at}");
    }
}

#[test]
fn a_resumed_sync_learns_the_version_from_the_feed_rather_than_resending() {
    // The `PUT` landed, the save that would have recorded its `version` did not.
    // On resume the change feed hands the write straight back — it is the client's
    // own envelope, byte for byte — so the fingerprint matches, the item is not
    // pending, and nothing is sent again.
    //
    // Save index 1 is the one after the first push: index 0 is the change-feed
    // cursor written at the end of the pull.
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer_with_store(0, FailingStore::new(1));
    let mut bob = fixture.peer(1);
    let id = alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");

    let error = alice.sync().expect_err("the save after the push fails");
    assert!(matches!(error, SyncError::StateStore { .. }), "{error:?}");
    assert!(
        fixture.server.envelope_of(&id).is_some(),
        "the write did land on the server"
    );
    let persisted = alice.engine.store().persisted();
    let recorded = match &persisted {
        None => SyncState::new(),
        Some(bytes) => SyncState::from_cbor(bytes).expect("decode"),
    };
    assert!(
        recorded.version_of(&id).is_none(),
        "the concurrency token was never recorded"
    );

    let mut alice = fixture.resume(alice, 0, persisted.as_deref());
    converge(&mut alice, &mut bob);

    assert_eq!(
        fixture.server.puts_for(&id),
        1,
        "the pull reconciled it; the write was not sent twice"
    );
    assert_eq!(fixture.server.snapshot().len(), 1, "one row, not two");
    assert!(alice.engine.state().version_of(&id).is_some());
    assert_eq!(alice.vault.item_set().len(), 1);
    assert_eq!(bob.vault.item_set().len(), 1);
    assert_eq!(alice.digest(), bob.digest());
}

#[test]
fn a_resend_with_a_stale_token_is_refused_rather_than_applied_twice() {
    // The mechanism underneath the property, asserted directly: the same envelope
    // sent twice, the second time with the token the client held before the first
    // landed. SPEC §6.1's `If-Match` is what makes the second a `409` instead of a
    // second write.
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    let id = alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");
    alice.sync_ok();

    let envelope = alice
        .vault
        .stored(&id)
        .expect("read the row")
        .expect("row")
        .envelope;
    let before = fixture.server.envelope_of(&id);

    // No `If-Match` at all is the strongest form of stale: "I have no idea what
    // you hold, write this anyway."
    let outcome = block_on(alice.engine.client_mut().put_item(&id, &envelope, None))
        .expect("the server answers");
    assert!(
        matches!(outcome, PutOutcome::Conflict { .. }),
        "a blind write is refused: {outcome:?}"
    );
    assert_eq!(
        fixture.server.envelope_of(&id),
        before,
        "and nothing was overwritten"
    );

    // With the right token it lands, once.
    let version = alice
        .engine
        .state()
        .version_of(&id)
        .cloned()
        .expect("a version was recorded");
    let outcome = block_on(
        alice
            .engine
            .client_mut()
            .put_item(&id, &envelope, Some(&version)),
    )
    .expect("the server answers");
    assert!(matches!(outcome, PutOutcome::Applied { .. }), "{outcome:?}");
    assert_eq!(fixture.server.snapshot().len(), 1);
}

#[test]
fn the_derived_queue_is_empty_exactly_when_the_server_is_current() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    assert_eq!(
        alice.engine.pending(&alice.vault).expect("pending").len(),
        0
    );

    let id = alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");
    assert_eq!(
        alice.engine.pending(&alice.vault).expect("pending").len(),
        1,
        "the vault's own commit is the enqueue"
    );

    alice.sync_ok();
    assert_eq!(
        alice.engine.pending(&alice.vault).expect("pending").len(),
        0
    );

    alice.rename(&id, "edited");
    assert_eq!(
        alice.engine.pending(&alice.vault).expect("pending").len(),
        1,
        "an edit re-seals, so the fingerprint no longer matches"
    );
    alice.sync_ok();
    assert_eq!(
        alice.engine.pending(&alice.vault).expect("pending").len(),
        0
    );
}
