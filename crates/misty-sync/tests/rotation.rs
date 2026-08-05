// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Revocation and epoch rotation (SPEC §6.4).
//!
//! Rotation **re-seals** — it does not re-wrap item keys alone — because SPEC §2.4
//! binds `epoch` into the payload's AAD. §6.4 already records that correction and
//! `misty-vault` implements it; this suite is about the properties §6.4 asks for on
//! top of it: lazy, resumable, and safe to interrupt.
//!
//! Two findings are pinned here rather than only written down. `revocation_is_not_a_read_revocation`
//! demonstrates that a revoked device holding `VK` can still derive the new epoch
//! key, and `a_vault_will_not_reopen_under_the_successor_until_rotation_finishes`
//! demonstrates the interaction between §6.2's "reject signers absent from the
//! roster" and §6.4's laziness: a vault holding rows the revoked device signed
//! refuses to open under the new roster until every one of them has been re-sealed.

mod support;

use misty_crypto::derive;
use misty_crypto::envelope::Envelope;
use misty_otp::FixedClock;
use misty_sync::duplicate_identity;
use misty_sync::runtime::block_on;
use misty_sync::Revocation;
use misty_vault::{Vault, VaultStore};
use support::{converge, vault_key, Fixture, NOW};

/// Every distinct epoch the vault's rows are sealed under.
fn epochs<S: VaultStore>(store: &S) -> Vec<u32> {
    let mut out: Vec<u32> = store
        .load_all()
        .expect("rows")
        .iter()
        .map(|row| {
            Envelope::parse(&row.envelope)
                .expect("parse")
                .header()
                .epoch
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[test]
fn revoking_a_device_bumps_the_epoch_and_publishes_the_successor_roster() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    for index in 0..4u8 {
        alice.add(&format!("Issuer {index}"), "ada", &[b'a' + index; 16]);
    }
    converge(&mut alice, &mut bob);
    assert_eq!(alice.vault.epoch(), 0);

    let bob_id = fixture.identity(1).device_id();
    let outcome = block_on(alice.engine.revoke_device(
        &mut alice.vault,
        &alice.roster,
        &bob_id,
        &vault_key(),
    ))
    .expect("revoke");
    let Revocation::Revoked {
        removed,
        roster,
        epoch,
    } = outcome
    else {
        panic!("expected a revocation, got {outcome:?}");
    };
    assert!(removed);
    assert_eq!(epoch, 1);
    assert_eq!(roster.devices.len(), 1);
    assert!(roster.contains(&bob_id).is_none());
    assert_eq!(
        alice.engine.rotation().map(|state| state.target_epoch),
        Some(1)
    );

    // The successor is on the server, sealed at the address every device derives.
    let address = misty_sync::roster::roster_item_id(&vault_key()).expect("address");
    let sealed = fixture.server.envelope_of(&address).expect("the roster");
    let fetched = misty_sync::roster::open_roster(&sealed, &address, &vault_key(), &alice.roster)
        .expect("it chains to the roster we already trust");
    assert_eq!(fetched.devices.len(), 1);
}

#[test]
fn rotation_is_lazy_resumable_and_leaves_a_mixed_epoch_vault_readable() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    let mut ids = Vec::new();
    for index in 0..5u8 {
        ids.push(alice.add(&format!("Issuer {index}"), "ada", &[b'a' + index; 16]));
    }
    converge(&mut alice, &mut bob);

    let bob_id = fixture.identity(1).device_id();
    block_on(
        alice
            .engine
            .revoke_device(&mut alice.vault, &alice.roster, &bob_id, &vault_key()),
    )
    .expect("revoke");

    // One object at a time. Between any two steps the vault holds a mix of epochs
    // and every item still reads, which is the property that makes the laziness
    // safe rather than merely cheap.
    let mut steps = 0;
    loop {
        let before = epochs(alice.vault.store());
        assert!(
            before.iter().all(|epoch| *epoch <= 1),
            "no object is at an epoch that does not exist: {before:?}"
        );
        for id in &ids {
            assert!(alice.vault.get(id).is_some(), "readable mid-rotation");
        }
        let progress = alice.engine.rotate_step(&mut alice.vault, 1).expect("step");
        steps += 1;
        if progress.remaining == 0 {
            break;
        }
        assert!(steps < 20, "rotation should finish");
    }
    assert_eq!(epochs(alice.vault.store()), vec![1]);
    assert_eq!(
        alice.engine.rotation(),
        None,
        "the rotation state clears when it finishes"
    );

    // Every re-sealed object became pending by construction, so the next sync
    // publishes them without anything having kept a list.
    assert_eq!(
        alice.engine.pending(&alice.vault).expect("pending").len(),
        ids.len()
    );
    alice.sync_ok();
    assert_eq!(
        alice.engine.pending(&alice.vault).expect("pending").len(),
        0
    );
    for id in &ids {
        let local = alice.vault.stored(id).expect("row").expect("row").envelope;
        assert_eq!(fixture.server.envelope_of(id), Some(local));
    }
}

#[test]
fn an_interrupted_rotation_resumes_from_where_it_stopped() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    for index in 0..6u8 {
        alice.add(&format!("Issuer {index}"), "ada", &[b'a' + index; 16]);
    }
    converge(&mut alice, &mut bob);
    let bob_id = fixture.identity(1).device_id();
    block_on(
        alice
            .engine
            .revoke_device(&mut alice.vault, &alice.roster, &bob_id, &vault_key()),
    )
    .expect("revoke");

    let first = alice.engine.rotate_step(&mut alice.vault, 2).expect("step");
    assert_eq!(first.rewrapped, 2);
    assert_eq!(first.remaining, 4);

    // "Interrupted" here is a restart: the engine is rebuilt from what was
    // persisted, and rotation needs nothing from memory to carry on.
    let mut alice = fixture.restart(alice, 0);
    assert_eq!(
        alice.engine.rotation().map(|state| state.target_epoch),
        Some(1),
        "an unfinished rotation survives the restart"
    );
    let second = alice
        .engine
        .rotate_step(&mut alice.vault, 100)
        .expect("step");
    assert_eq!(second.rewrapped, 4);
    assert_eq!(second.remaining, 0);
    assert_eq!(epochs(alice.vault.store()), vec![1]);
}

#[test]
fn a_vault_will_not_reopen_under_the_successor_until_rotation_finishes() {
    // The interaction SPEC §6.4 does not mention. `Vault::open` verifies every
    // stored row's signer against the roster (SPEC §6.2), and a vault that has been
    // syncing with the revoked device holds rows that device signed.
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    alice.add("Alice's", "ada", b"aaaaaaaaaaaaaaaa");
    bob.add("Bob's", "ada", b"bbbbbbbbbbbbbbbb");
    converge(&mut alice, &mut bob);

    let bob_id = fixture.identity(1).device_id();
    let Revocation::Revoked { roster, .. } = block_on(alice.engine.revoke_device(
        &mut alice.vault,
        &alice.roster,
        &bob_id,
        &vault_key(),
    ))
    .expect("revoke") else {
        panic!("expected a revocation");
    };

    // Before rotation, at least one row is signed by the device just removed, and
    // that row does not verify under the successor. `Vault::open` verifies every
    // row, so it would refuse the whole vault.
    let signed_by_bob: Vec<_> = alice
        .vault
        .store()
        .load_all()
        .expect("rows")
        .into_iter()
        .filter(|row| {
            Envelope::parse(&row.envelope)
                .expect("parse")
                .header()
                .signer
                == bob_id
        })
        .collect();
    assert!(!signed_by_bob.is_empty(), "bob really did write a row");
    for row in &signed_by_bob {
        let epoch = Envelope::parse(&row.envelope)
            .expect("parse")
            .header()
            .epoch;
        let key = derive::epoch_key(&vault_key(), epoch).expect("epoch key");
        let refused = misty_crypto::envelope::open(&row.envelope, &row.item_id, &key, &roster)
            .expect_err("the signer is gone");
        assert!(
            matches!(refused, misty_crypto::Error::UnknownSigner { .. }),
            "{refused:?}"
        );
    }

    // Finish the rotation with the *old* roster still in use.
    while alice
        .engine
        .rotate_step(&mut alice.vault, 100)
        .expect("step")
        .remaining
        != 0
    {}
    assert!(
        alice
            .vault
            .store()
            .load_all()
            .expect("rows")
            .iter()
            .all(|row| {
                Envelope::parse(&row.envelope)
                    .expect("parse")
                    .header()
                    .signer
                    != bob_id
            }),
        "no row is signed by the revoked device any more"
    );

    // Only now does the vault open under the successor. `lock` gives the store back
    // by value, which is the only way to hand the same rows to a second `Vault`.
    let store = alice.vault.lock();
    Vault::open(
        store,
        FixedClock::new(NOW),
        vault_key(),
        duplicate_identity(fixture.identity(0)),
        roster,
    )
    .expect("every row is now signed by a device the successor roster lists");
}

#[test]
fn revocation_is_not_a_read_revocation() {
    // `EK_n = HKDF(VK, "misty/epoch/v1", LE32(n))`. A revoked device that still
    // holds `VK` derives the new epoch key exactly as easily as a trusted one, so
    // bumping the epoch does not take reading away from it. What it takes away is
    // the ability to *write* something other devices will accept.
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    let id = alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");
    converge(&mut alice, &mut bob);

    let bob_id = fixture.identity(1).device_id();
    let Revocation::Revoked { roster, .. } = block_on(alice.engine.revoke_device(
        &mut alice.vault,
        &alice.roster,
        &bob_id,
        &vault_key(),
    ))
    .expect("revoke") else {
        panic!("expected a revocation");
    };
    while alice
        .engine
        .rotate_step(&mut alice.vault, 100)
        .expect("step")
        .remaining
        != 0
    {}
    alice.sync_ok();

    // Bob, holding only `VK`, opens the freshly re-sealed envelope. The roster he
    // is checked against here is the *old* one — he still has a copy of it — which
    // is precisely the point: nothing about the epoch bump kept him out.
    let sealed = fixture.server.envelope_of(&id).expect("the item");
    let epoch = Envelope::parse(&sealed).expect("parse").header().epoch;
    assert_eq!(epoch, 1, "it really was re-sealed under the new epoch");
    let key = derive::epoch_key(&vault_key(), epoch).expect("epoch key");
    misty_crypto::envelope::open(&sealed, &id, &key, &alice.roster)
        .expect("anyone with VK reads epoch 1: revocation is a write revocation");

    // What bob has lost: a device that has adopted the successor roster will not
    // merge anything he signs.
    fixture.server.inject(
        id,
        support::seal(
            misty_crypto::envelope::EnvelopeKind::Item,
            &id,
            b"still trying",
            fixture.identity(1),
        ),
    );
    let mut carol = fixture.peer_with_roster(0, roster);
    // Two rounds: the first stops at the roster change, because a change of trust
    // anchor must be adopted before anything after it is judged.
    let first = carol.sync_ok();
    assert!(first.roster_update.is_some(), "{first:?}");
    let second = carol.sync_ok();
    assert_eq!(
        first.applied + second.applied,
        0,
        "nothing bob wrote is merged: {first:?} then {second:?}"
    );
    assert_eq!(
        first.rejected_count(misty_sync::Rejection::UnknownSigner)
            + second.rejected_count(misty_sync::Rejection::UnknownSigner),
        1
    );
}
