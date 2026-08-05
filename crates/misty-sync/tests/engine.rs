// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The engine's remaining moving parts: the retry loop, the server-side delete
//! that follows a tombstone purge, and the guard that keeps that delete away from
//! the roster.
//!
//! The delete path is the only place this crate destroys anything on the server, so
//! it gets two tests: one that it happens when it should, and one that it does not
//! happen to the one object whose loss would take the vault's trust anchor with it.

mod support;

use misty_sync::runtime::block_on;
use misty_sync::transport::Faults;
use misty_sync::{Backoff, Jitter, MockSleeper, PendingAction};
use support::{converge, vault_key, Fixture};

#[test]
fn run_retries_on_a_transport_failure_and_sleeps_the_schedule() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");

    // The first two attempts find no network; the third succeeds. `Jitter::None`
    // makes the schedule assertable without a stopwatch.
    fixture.server.set_faults(Faults {
        offline_after: Some(0),
        ..Faults::default()
    });
    let sleeper = MockSleeper::new();
    let mut engine = fixture.peer(0).engine.with_backoff(Backoff {
        base_ms: 100,
        max_ms: 1_000,
        multiplier: 2,
        jitter: Jitter::None,
    });

    let error = block_on(engine.run(&mut alice.vault, &alice.roster, &sleeper, 3))
        .expect_err("the network never came back");
    assert!(
        matches!(error, misty_sync::SyncError::Transport { .. }),
        "{error:?}"
    );
    assert_eq!(
        sleeper.slept(),
        vec![100, 200, 400],
        "one sleep per failed attempt, doubling"
    );

    // Once the network is back, the same call succeeds and the write lands.
    fixture.server.heal();
    let report =
        block_on(engine.run(&mut alice.vault, &alice.roster, &sleeper, 3)).expect("it works now");
    assert_eq!(report.pushed, 1);
    assert_eq!(
        sleeper.slept().len(),
        3,
        "a successful attempt does not sleep"
    );
}

#[test]
fn a_non_transient_failure_is_not_retried() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    // A lie about the feed's shape is not going to fix itself, and retrying it would
    // hide it behind a delay.
    fixture.server.set_faults(Faults {
        feed_body: Some(b"{".to_vec()),
        ..Faults::default()
    });
    let sleeper = MockSleeper::new();
    let error = block_on(
        alice
            .engine
            .run(&mut alice.vault, &alice.roster, &sleeper, 5),
    )
    .expect_err("malformed feed");
    assert!(
        matches!(error, misty_sync::SyncError::Malformed { .. }),
        "{error:?}"
    );
    assert!(sleeper.slept().is_empty(), "it did not wait to fail again");
}

#[test]
fn a_purged_tombstone_is_deleted_server_side() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    let id = alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");
    converge(&mut alice, &mut bob);
    assert!(fixture.server.envelope_of(&id).is_some());

    // A tombstone, then SPEC §4's ninety days, then the purge that drops the row.
    alice.vault.delete_item(&id).expect("tombstone");
    alice.sync_ok();
    alice.vault.clock().advance(91 * 24 * 60 * 60 * 1000);
    assert_eq!(
        alice.vault.purge_tombstones().expect("purge"),
        vec![id],
        "the row is gone locally"
    );

    // The server row is now owed a delete, and only a delete: there is no envelope
    // left to push.
    let pending = alice.engine.pending(&alice.vault).expect("pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending.first().map(|write| write.action),
        Some(PendingAction::Delete)
    );

    let report = alice.sync_ok();
    assert_eq!(report.deleted, 1);
    assert_eq!(report.pushed, 0);
    assert!(fixture.server.envelope_of(&id).is_none());
    assert_eq!(
        alice.engine.pending(&alice.vault).expect("pending").len(),
        0
    );
}

#[test]
fn a_roster_row_is_never_deleted_server_side() {
    // The roster has no vault row by design — `misty-vault` models items and groups
    // and nothing else — so a delete rule that fired on "the server has it and the
    // vault does not" would erase the trust anchor on the first sync after it was
    // published. `KnownRow::is_deletable` is the guard, and this is the test that
    // would fail if it were removed.
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    let (address, envelope) =
        misty_sync::roster::seal_roster(&alice.roster, &vault_key(), 0, fixture.identity(0))
            .expect("seal roster");
    fixture.server.inject(address, envelope);

    let report = alice.sync_ok();
    assert!(report.roster_update.is_some(), "it was read: {report:?}");
    assert!(
        alice.vault.stored(&address).expect("read").is_none(),
        "and it is not a vault row"
    );
    assert!(
        alice
            .engine
            .state()
            .known
            .get(&address)
            .is_some_and(|row| !row.is_deletable()),
        "it is recorded, and recorded as undeletable"
    );

    assert!(
        alice
            .engine
            .pending(&alice.vault)
            .expect("pending")
            .is_empty(),
        "nothing is owed to the server"
    );
    alice.sync_ok();
    assert!(
        fixture.server.envelope_of(&address).is_some(),
        "the roster is still there"
    );
}

#[test]
fn quota_is_reported() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");
    alice.sync_ok();

    let quota = block_on(alice.engine.quota()).expect("quota");
    assert_eq!(quota.item_count, 1);
    assert!(quota.bytes_used >= 458, "one envelope at least: {quota:?}");
    assert_eq!(quota.max_items_per_vault, Some(10_000));
    assert_eq!(quota.row_count, 1);
}
