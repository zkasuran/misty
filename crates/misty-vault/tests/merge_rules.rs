// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One test per row of SPEC §4's merge table, plus the cases where the rows
//! interact.
//!
//! These run through the real stack: two vaults, each with its own device
//! identity, exchanging real sealed envelopes. A rule that held for the merge
//! function but not through encode → seal → open → decode would still be a bug.

mod support;

use misty_otp::SecretBytes;
use misty_vault::{Conflict, Edit, NewItem, VaultError};
use support::{change_for, hotp, new_item, peer, sync, NOW};

/// [`NOW`] as the `i64` the model stores timestamps in.
const NOW_I64: i64 = NOW as i64;

/// SPEC §4 row 2: `otp.counter` is max-wins, monotonic. A lower counter would
/// replay a code the issuer has already consumed.
#[test]
fn a_hotp_counter_never_regresses_under_any_interleaving() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);

    let id = a
        .add(NewItem::new(
            hotp(b"12345678901234567890", 0),
            "Bank",
            "ada",
        ))
        .expect("add");
    sync(&a, &mut b);

    // A advances the counter three times; B advances it once. Both are offline.
    for _ in 0..3 {
        a.advance_hotp_counter(&id).expect("advance");
    }
    b.advance_hotp_counter(&id).expect("advance");
    assert_eq!(a.item(&id).expect("item").hotp_counter(), 3);
    assert_eq!(b.item(&id).expect("item").hotp_counter(), 1);

    // Whichever way round they sync, and however many times, the counter is 3.
    sync(&b, &mut a);
    assert_eq!(a.item(&id).expect("item").hotp_counter(), 3);
    sync(&a, &mut b);
    assert_eq!(b.item(&id).expect("item").hotp_counter(), 3);
    sync(&b, &mut a);
    sync(&a, &mut b);
    assert_eq!(a.item(&id).expect("item").hotp_counter(), 3);
    assert_eq!(b.item(&id).expect("item").hotp_counter(), 3);

    // And an explicit rewind is refused rather than applied.
    assert_eq!(a.set_hotp_counter(&id, 1).expect("set"), 3);
}

/// SPEC §4 row 5: a tombstone wins only over *earlier* edits. A delete on one
/// device must not swallow a rename made afterwards on another.
#[test]
fn a_delete_loses_to_a_later_edit() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    sync(&a, &mut b);

    // A deletes at NOW. B, which has not seen it, renames one millisecond later.
    a.delete_item(&id).expect("delete");
    assert!(a.item(&id).expect("item").is_deleted());
    b.clock().set(NOW + 1);
    b.update(&id, Edit::new().nickname(Some("work".into())))
        .expect("update");

    sync(&b, &mut a);
    sync(&a, &mut b);

    for (name, vault) in [("a", &a), ("b", &b)] {
        let item = vault.item(&id).expect("item");
        assert!(!item.is_deleted(), "{name} lost a later edit to a delete");
        assert_eq!(item.nickname(), Some("work"), "{name}");
        // The tombstone is *kept*, not discarded: dropping it would let a third
        // peer that still holds the delete reapply it.
        assert!(item.tombstone().is_some(), "{name} discarded the tombstone");
    }
}

/// The other direction: an edit that happened *before* the delete does not save
/// the item. Resurrection-by-stale-edit is the failure mode this half prevents.
#[test]
fn a_delete_beats_an_earlier_edit() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    sync(&a, &mut b);

    b.update(&id, Edit::new().nickname(Some("work".into())))
        .expect("update");
    a.clock().set(NOW + 1_000);
    a.delete_item(&id).expect("delete");

    sync(&b, &mut a);
    sync(&a, &mut b);
    assert!(a.item(&id).expect("item").is_deleted());
    assert!(b.item(&id).expect("item").is_deleted());
}

/// SPEC §4 row 4: OR-Set, add wins on tie. Concurrent add and remove of the same
/// tag, and concurrent adds of different tags.
#[test]
fn concurrent_tag_add_and_remove_keeps_both_additions() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    a.add_tag(&id, "shared").expect("tag");
    sync(&a, &mut b);

    // Concurrent, at the same millisecond: A removes `shared` and adds `work`,
    // B adds `personal` and re-adds `shared`.
    a.remove_tag(&id, "shared").expect("untag");
    a.add_tag(&id, "work").expect("tag");
    b.add_tag(&id, "personal").expect("tag");
    b.add_tag(&id, "shared").expect("tag");

    sync(&b, &mut a);
    sync(&a, &mut b);

    let expected = ["personal", "shared", "work"];
    for (name, vault) in [("a", &a), ("b", &b)] {
        let tags: Vec<&str> = vault
            .item(&id)
            .expect("item")
            .tags()
            .map(String::as_str)
            .collect();
        assert_eq!(tags, expected, "{name}");
    }
}

/// A remove that is genuinely later than every add does take the element out, and
/// stays out however many times the two sides sync.
#[test]
fn a_later_tag_removal_sticks() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    a.add_tag(&id, "shared").expect("tag");
    sync(&a, &mut b);

    b.clock().set(NOW + 5_000);
    b.remove_tag(&id, "shared").expect("untag");
    sync(&b, &mut a);
    sync(&a, &mut b);
    sync(&b, &mut a);

    assert!(!a.item(&id).expect("item").has_tag("shared"));
    assert!(!b.item(&id).expect("item").has_tag("shared"));
}

/// SPEC §4 row 3: `usage` is a per-device G-counter. Three offline devices sum.
#[test]
fn usage_counts_from_three_offline_devices_sum() {
    let mut a = peer(1, &[1, 2, 3], NOW);
    let mut b = peer(2, &[1, 2, 3], NOW);
    let mut c = peer(3, &[1, 2, 3], NOW);

    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    sync(&a, &mut b);
    sync(&a, &mut c);

    for _ in 0..4 {
        a.record_use(&id).expect("use");
    }
    for _ in 0..7 {
        b.record_use(&id).expect("use");
    }
    c.record_use(&id).expect("use");

    // Fan in through B, then back out. Any spanning order gives 12.
    sync(&a, &mut b);
    sync(&c, &mut b);
    sync(&b, &mut a);
    sync(&b, &mut c);

    for (name, vault) in [("a", &a), ("b", &b), ("c", &c)] {
        assert_eq!(vault.item(&id).expect("item").use_count(), 12, "{name}");
    }

    // Merging the same feed again must not double-count.
    sync(&b, &mut a);
    sync(&b, &mut a);
    assert_eq!(a.item(&id).expect("item").use_count(), 12);
}

/// SPEC §4 row 6: divergent secrets produce **two items** and a conflict, never
/// one item with a guessed secret.
#[test]
fn divergent_secrets_produce_two_items_and_a_conflict() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    sync(&a, &mut b);

    // B re-scans the issuer's QR code, because the imported secret was wrong.
    b.repair_secret(&id, SecretBytes::from_slice(b"bbbbbbbbbb"))
        .expect("repair");

    let report = a.merge_remote(&[change_for(&b, &id)]).expect("merge");
    let forked = match report.conflicts.as_slice() {
        [Conflict::DivergentSecret { kept, forked }] => {
            assert_eq!(*kept, id);
            *forked
        }
        other => panic!("expected one DivergentSecret, got {other:?}"),
    };

    assert_ne!(forked, id);
    assert_eq!(a.item_set().len(), 2);
    // `a...` sorts below `b...`, so the original id keeps the smaller secret.
    assert_eq!(
        a.item(&id).expect("kept").secret(),
        &SecretBytes::from_slice(b"aaaaaaaaaa")
    );
    assert_eq!(
        a.item(&forked).expect("forked").secret(),
        &SecretBytes::from_slice(b"bbbbbbbbbb")
    );
    // Both items are real, listable items — not a hidden repair record.
    assert_eq!(a.list().count(), 2);

    // B reaches the same two ids from the other side: the split is derived, not
    // drawn, so it is the same on every device.
    let report_b = b.merge_remote(&[change_for(&a, &id)]).expect("merge");
    assert_eq!(report_b.conflicts.len(), 1);
    assert_eq!(b.item_set().len(), 2);
    assert!(b.get(&forked).is_some());
    assert_eq!(
        b.item(&id).expect("kept").secret(),
        &SecretBytes::from_slice(b"aaaaaaaaaa")
    );
}

/// Re-merging a divergence must not fork again: the forked id is a function of the
/// original id and the credential, so the second pass finds the item already there.
#[test]
fn forking_is_idempotent() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    sync(&a, &mut b);
    b.repair_secret(&id, SecretBytes::from_slice(b"bbbbbbbbbb"))
        .expect("repair");

    let change = change_for(&b, &id);
    a.merge_remote(std::slice::from_ref(&change))
        .expect("merge");
    let before = support::fingerprint(&a);
    for _ in 0..3 {
        a.merge_remote(std::slice::from_ref(&change))
            .expect("merge");
    }
    assert_eq!(support::fingerprint(&a), before);
    assert_eq!(a.item_set().len(), 2);
}

/// A divergent PIN is resolved last-writer-wins but still reported, because the
/// surviving value may be the one that does not work.
#[test]
fn a_divergent_pin_is_reported_but_resolved() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let config = misty_otp::OtpConfig::motp(
        SecretBytes::from_slice(b"\x01\x02\x03\x04\x05\x06\x07\x08"),
        SecretBytes::from_slice(b"1234"),
    )
    .expect("motp");
    let id = a.add(NewItem::new(config, "Router", "admin")).expect("add");
    sync(&a, &mut b);

    b.clock().set(NOW + 10);
    b.update(&id, Edit::new().pin(Some(SecretBytes::from_slice(b"9999"))))
        .expect("update");

    let report = a.merge_remote(&support::changes(&b)).expect("merge");
    assert_eq!(report.conflicts, vec![Conflict::DivergentPin { item: id }]);
    assert_eq!(
        a.item(&id).expect("item").pin(),
        Some(&SecretBytes::from_slice(b"9999"))
    );
    // One item, not two: a PIN is re-typable, a secret is not.
    assert_eq!(a.item_set().len(), 1);
}

/// SPEC §4 row 1: plain fields are last-writer-wins, with `device_id` as the final
/// tiebreak so both devices pick the same winner from a same-millisecond tie.
#[test]
fn same_millisecond_edits_resolve_the_same_way_on_both_devices() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    sync(&a, &mut b);

    a.update(&id, Edit::new().nickname(Some("from a".into())))
        .expect("update");
    b.update(&id, Edit::new().nickname(Some("from b".into())))
        .expect("update");

    sync(&b, &mut a);
    sync(&a, &mut b);
    let winner = a.item(&id).expect("item").nickname().map(str::to_owned);
    assert_eq!(winner.as_deref(), b.item(&id).expect("item").nickname());
    // Device 2's id is bytewise greater than device 1's, so B wins the tie.
    assert_eq!(winner.as_deref(), Some("from b"));
}

/// `created_at` travels with the item and is not re-stamped by whoever re-encodes
/// it. The min-wins *merge* is unit-tested in `src/crdt/scalar.rs`: two devices can
/// only disagree about a creation time by way of a fork, so a two-device
/// integration test cannot reach that state.
#[test]
fn created_at_is_not_restamped_by_a_later_writer() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW - 60_000);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    sync(&a, &mut b);
    // B's clock is a minute behind, so its edit carries the earlier creation
    // claim once it re-encodes the item.
    b.update(&id, Edit::new().favorite(true)).expect("update");
    assert_eq!(b.item(&id).expect("item").created_at(), NOW_I64);
    sync(&b, &mut a);
    assert_eq!(a.item(&id).expect("item").created_at(), NOW_I64);
}

/// `last_used_at` is max-wins, not last-writer-wins: a device that used a token an
/// hour ago but syncs later must not overwrite a more recent reading.
#[test]
fn last_used_at_keeps_the_later_reading_not_the_later_writer() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    sync(&a, &mut b);

    a.clock().set(NOW + 3_600_000);
    a.record_use(&id).expect("use");
    // B uses it at an earlier wall time but writes afterwards.
    b.record_use(&id).expect("use");
    sync(&b, &mut a);
    assert_eq!(
        a.item(&id).expect("item").last_used_at(),
        Some(NOW_I64 + 3_600_000)
    );
}

/// A merge is refused wholesale if any payload's own id is not the key it arrived
/// under. Nothing is written.
#[test]
fn a_payload_under_the_wrong_key_is_refused() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let first = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    let second = a
        .add(new_item("GitLab", "ada", b"bbbbbbbbbb"))
        .expect("add");

    let mut change = change_for(&a, &first);
    change.item_id = second;
    let before = support::fingerprint(&b);
    let error = b.merge_remote(&[change]).expect_err("must refuse");
    // The envelope binds `item_id` in its AAD, so relocating it fails to open at
    // all — the crypto layer catches this before the vault's own id check does.
    assert!(matches!(
        error,
        VaultError::Crypto(_) | VaultError::IdMismatch { .. }
    ));
    assert_eq!(support::fingerprint(&b), before);
}
