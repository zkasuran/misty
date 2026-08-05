// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Two simulated clients, one mock server, and the property the whole crate
//! exists for: **whatever order the writes and the network failures happen in,
//! both devices end up holding the same thing.**
//!
//! State is compared as the CBOR `misty-vault` would write for every item, not as
//! envelope bytes. Envelopes carry fresh nonces on every re-seal, so two devices
//! holding an identical item hold different ciphertext by design; the model is
//! what has to match, and its CBOR encoding is deterministic and frozen by
//! `misty-vault`'s own `wire_format.rs`.

mod support;

use misty_otp::SecretBytes;
use misty_sync::transport::Faults;
use misty_sync::{Rejection, SyncError};
use support::{converge, Fixture};

#[test]
fn independent_edits_on_two_devices_converge() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);

    let github = alice.add("GitHub", "ada@example.com", b"aaaaaaaaaaaaaaaa");
    let bank = bob.add("Bank", "ada", b"bbbbbbbbbbbbbbbb");

    converge(&mut alice, &mut bob);

    assert_eq!(alice.digest(), bob.digest());
    assert_eq!(alice.vault.list().count(), 2);
    assert!(alice.vault.get(&bank).is_some());
    assert!(bob.vault.get(&github).is_some());
}

#[test]
fn an_offline_period_does_not_lose_a_write() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);

    // Alice writes while the network is gone. The write is committed to her vault
    // and is therefore queued by construction: nothing had to remember it.
    fixture.server.set_faults(Faults {
        offline_after: Some(0),
        ..Faults::default()
    });
    let offline_item = alice.add("Offline", "ada", b"cccccccccccccccc");
    let error = alice.sync().expect_err("no network");
    assert!(matches!(error, SyncError::Transport { .. }), "{error:?}");
    assert_eq!(
        alice.engine.pending(&alice.vault).expect("pending").len(),
        1,
        "the write is still owed to the server"
    );

    fixture.server.heal();
    converge(&mut alice, &mut bob);

    assert!(bob.vault.get(&offline_item).is_some());
    assert_eq!(alice.digest(), bob.digest());
}

#[test]
fn an_interrupted_batch_resumes_and_converges() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);

    // Nine items, so the push loop is well into the batch when the network dies.
    let mut ids = Vec::new();
    for index in 0..9u8 {
        ids.push(alice.add(&format!("Issuer {index}"), "ada", &[b'a' + index; 16]));
    }

    fixture.server.set_faults(Faults {
        offline_after: Some(6),
        ..Faults::default()
    });
    let error = alice.sync().expect_err("network dies mid-batch");
    assert!(matches!(error, SyncError::Transport { .. }), "{error:?}");
    let landed = fixture.server.snapshot().len();
    assert!(landed > 0 && landed < 9, "partial batch, got {landed}");

    fixture.server.heal();
    let mut alice = fixture.restart(alice, 0);
    converge(&mut alice, &mut bob);

    assert_eq!(fixture.server.snapshot().len(), 9);
    for id in &ids {
        assert!(bob.vault.get(id).is_some(), "item {id} reached bob");
    }
    assert_eq!(alice.digest(), bob.digest());
}

#[test]
fn a_conflict_on_the_same_item_is_merged_and_retried() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);

    let id = alice.add("Shared", "ada", b"dddddddddddddddd");
    converge(&mut alice, &mut bob);

    // Both edit the same item with no network in between, so both hold a version
    // the server will not accept from the second of them.
    alice.vault.clock().advance(1_000);
    bob.vault.clock().advance(2_000);
    alice.rename(&id, "from-alice");
    bob.vault
        .add_tag(&id, "from-bob")
        .expect("bob tags the item");

    let first = alice.sync_ok();
    assert_eq!(first.pushed, 1);
    let second = bob.sync_ok();
    assert!(
        second.conflicts_resolved > 0 || second.applied > 0,
        "bob had to reconcile: {second:?}"
    );

    converge(&mut alice, &mut bob);
    assert_eq!(alice.digest(), bob.digest());

    // Both edits survived: the merge is a join, not a choice.
    let item = alice.vault.item(&id).expect("item");
    assert_eq!(item.nickname(), Some("from-alice"));
    assert!(item.has_tag("from-bob"));
}

#[test]
fn a_divergent_secret_fork_converges_to_the_same_two_items() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);

    let id = alice.add("Issuer", "ada", b"eeeeeeeeeeeeeeee");
    converge(&mut alice, &mut bob);

    // Alice re-scans the issuer's QR and finds the stored secret was wrong. Bob has
    // not seen the repair, so the next merge holds two credentials for one id —
    // SPEC §4 says keep both.
    alice.vault.clock().advance(1_000);
    alice
        .vault
        .repair_secret(&id, SecretBytes::from_slice(b"ffffffffffffffff"))
        .expect("repair");

    converge(&mut alice, &mut bob);

    assert_eq!(
        alice.digest(),
        bob.digest(),
        "both devices forked the same way"
    );
    assert_eq!(
        alice.vault.item_set().len(),
        2,
        "the fork produced two items"
    );
    assert!(
        !alice.vault.conflicts().is_empty() || !bob.vault.conflicts().is_empty(),
        "a divergent secret is surfaced, never silently resolved"
    );
}

#[test]
fn a_hotp_counter_never_regresses_through_sync() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);

    let id = alice.add("Issuer", "ada", b"gggggggggggggggg");
    converge(&mut alice, &mut bob);

    alice.vault.set_hotp_counter(&id, 7).expect("advance");
    bob.vault.set_hotp_counter(&id, 3).expect("advance");
    converge(&mut alice, &mut bob);

    assert_eq!(alice.vault.item(&id).expect("item").hotp_counter(), 7);
    assert_eq!(bob.vault.item(&id).expect("item").hotp_counter(), 7);
    assert_eq!(alice.digest(), bob.digest());
}

#[test]
fn nothing_is_rejected_when_the_server_behaves() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    alice.add("A", "a", b"hhhhhhhhhhhhhhhh");
    bob.add("B", "b", b"iiiiiiiiiiiiiiii");
    converge(&mut alice, &mut bob);
    for peer in [&alice, &bob] {
        assert_eq!(peer.vault.item_set().len(), 2);
    }
    assert_eq!(alice.sync_ok().rejected_count(Rejection::UnknownSigner), 0);
}
