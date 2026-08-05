// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The rest of the public API: trash, groups, listing, search, and the sweeps.

mod support;

use misty_otp::SecretBytes;
use misty_vault::{Edit, IconRef, SortKey, VaultError};
use support::{new_item, peer, sync, NOW};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// The trash: 30 days of retention before a tombstone is written (SPEC §4), so a
/// delete that has already propagated to three devices is still recoverable.
#[test]
fn trash_retention_runs_for_thirty_days_before_a_tombstone() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");

    vault.trash_item(&id).expect("trash");
    assert!(vault.item(&id).expect("item").is_trashed());
    assert!(!vault.item(&id).expect("item").is_deleted());
    assert_eq!(vault.list().count(), 0);
    assert_eq!(vault.trash().len(), 1);

    // A day short of the window, nothing happens.
    vault.clock().set(NOW + 29 * DAY_MS);
    assert!(vault.sweep_trash().expect("sweep").is_empty());
    assert!(vault.item(&id).expect("item").is_trashed());

    vault.clock().set(NOW + 30 * DAY_MS);
    assert_eq!(vault.sweep_trash().expect("sweep"), vec![id]);
    let item = vault.item(&id).expect("item");
    assert!(item.is_deleted());
    assert_eq!(
        item.tombstone().expect("a tombstone").reason,
        misty_vault::TombstoneReason::TrashExpired
    );
    // The row is still there: a delete has to be a value to be replicable.
    assert!(!vault.store().is_empty());
}

/// A restore takes an item back out, and works even after the tombstone was written —
/// because a restore is a later edit, and SPEC §4 says a delete must not beat one.
#[test]
fn a_restore_works_before_and_after_the_tombstone() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");

    vault.trash_item(&id).expect("trash");
    vault.restore_item(&id).expect("restore");
    assert!(vault.item(&id).expect("item").is_live());
    assert_eq!(vault.list().count(), 1);

    vault.delete_item(&id).expect("delete");
    assert!(vault.item(&id).expect("item").is_deleted());
    vault.clock().set(NOW + 1);
    vault.restore_item(&id).expect("restore");
    let item = vault.item(&id).expect("item");
    assert!(!item.is_deleted(), "a later edit must beat the tombstone");
    assert!(item.is_live());
    // The tombstone is kept, so a peer that still holds the delete cannot reapply
    // it — it loses the comparison rather than being absent from it.
    assert!(item.tombstone().is_some());
}

/// The 90-day purge drops the row. It is the one operation that is not a CRDT join,
/// and it is only reached long after any plausible offline window.
#[test]
fn tombstones_are_purged_after_ninety_days() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    vault.delete_item(&id).expect("delete");

    vault.clock().set(NOW + 89 * DAY_MS);
    assert!(vault.purge_tombstones().expect("purge").is_empty());
    assert!(vault.get(&id).is_some());

    vault.clock().set(NOW + 90 * DAY_MS);
    assert_eq!(vault.purge_tombstones().expect("purge"), vec![id]);
    assert!(vault.get(&id).is_none());
    assert_eq!(vault.store().len(), 0);

    // And a purge does not touch a live item, however old.
    let live = vault
        .add(new_item("GitLab", "ada", b"bbbbbbbbbb"))
        .expect("add");
    vault.clock().set(NOW + 400 * DAY_MS);
    assert!(vault.purge_tombstones().expect("purge").is_empty());
    assert!(vault.get(&live).is_some());
}

/// A trashed item that a peer restored comes back, because the restore is the later
/// write on the same last-writer-wins field.
#[test]
fn a_restore_on_one_device_reaches_the_other() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    a.trash_item(&id).expect("trash");
    sync(&a, &mut b);
    assert!(b.item(&id).expect("item").is_trashed());

    b.clock().set(NOW + 1_000);
    b.restore_item(&id).expect("restore");
    sync(&b, &mut a);
    assert!(a.item(&id).expect("item").is_live());
}

/// Groups are their own objects, so a rename is one write and cannot split the group.
#[test]
fn groups_are_named_once_and_merge_as_one_register() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let group = a.add_group("Wrok").expect("group");
    let item = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    a.add_to_group(&item, group).expect("join");
    sync(&a, &mut b);

    assert_eq!(b.group(&group).expect("group").name(), "Wrok");
    assert!(b.item(&item).expect("item").in_group(&group));

    // Both devices fix the typo, offline, in the same millisecond.
    a.update_group(&group, Some("Work".into()), Some(Some(0xFF11_2233)), None)
        .expect("rename");
    b.update_group(&group, Some("Werk".into()), None, None)
        .expect("rename");
    sync(&b, &mut a);
    sync(&a, &mut b);

    // One group with one name, agreed on by both — not two groups.
    assert_eq!(a.groups().len(), 1);
    assert_eq!(b.groups().len(), 1);
    assert_eq!(
        a.group(&group).expect("group").name(),
        b.group(&group).expect("group").name()
    );
    // The colour came from A and the name from B: last-writer-wins is per field.
    assert_eq!(a.group(&group).expect("group").color(), Some(0xFF11_2233));
    assert_eq!(a.group(&group).expect("group").name(), "Werk");
}

/// Deleting a group leaves its members alone: membership lives on the item side, so
/// an item in a deleted group simply has one fewer group.
#[test]
fn deleting_a_group_does_not_touch_its_members() {
    let mut vault = peer(1, &[1], NOW);
    let group = vault.add_group("Work").expect("group");
    let item = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    vault.add_to_group(&item, group).expect("join");

    vault.delete_group(&group).expect("delete");
    assert!(vault.groups().is_empty());
    assert!(vault.group(&group).expect("still stored").is_deleted());
    // The item is untouched and still lists the group id, which the UI resolves to
    // nothing. Rewriting every member would be a multi-item write with no
    // cross-device transaction.
    assert!(vault.item(&item).expect("item").is_live());
    assert!(vault.item(&item).expect("item").in_group(&group));

    // A group must exist to be joined.
    let missing = misty_vault::GroupId::from_bytes([0xcd; 16]);
    assert!(matches!(
        vault.add_to_group(&item, missing),
        Err(VaultError::NoSuchGroup { .. })
    ));
}

/// Sorting and search run over the decrypted model, and each key does what it says.
#[test]
fn listings_sort_and_search_over_the_model() {
    let mut vault = peer(1, &[1], NOW);
    let github = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa").tag("dev"))
        .expect("add");
    let bank = vault
        .add(new_item("A Bank", "ada@example.com", b"bbbbbbbbbb").note("savings"))
        .expect("add");
    vault.clock().set(NOW + 1_000);
    let zulip = vault
        .add(new_item("Zulip", "ada", b"cccccccccc").origin("zulip.example"))
        .expect("add");

    // Most recently used, then most used.
    vault.record_use(&zulip).expect("use");
    vault.clock().set(NOW + 2_000);
    for _ in 0..5 {
        vault.record_use(&github).expect("use");
    }

    fn ids(
        vault: &misty_vault::Vault<misty_vault::MemoryStore, misty_otp::FixedClock>,
        key: SortKey,
    ) -> Vec<misty_crypto::ItemId> {
        vault
            .sorted(key)
            .into_iter()
            .map(|item| item.id())
            .collect()
    }
    assert_eq!(ids(&vault, SortKey::Issuer), vec![bank, github, zulip]);
    assert_eq!(ids(&vault, SortKey::LastUsed), vec![github, zulip, bank]);
    assert_eq!(ids(&vault, SortKey::MostUsed), vec![github, zulip, bank]);
    assert_eq!(ids(&vault, SortKey::Created), vec![zulip, bank, github]);

    // Manual order first, then the cluster order for everything unplaced.
    vault
        .update(&zulip, Edit::new().manual_order(Some(-1)))
        .expect("order");
    assert_eq!(ids(&vault, SortKey::Manual), vec![zulip, bank, github]);

    // Search covers every user-visible text field, case-insensitively.
    assert_eq!(vault.search("github").len(), 1);
    assert_eq!(vault.search("ADA@example").len(), 1);
    assert_eq!(vault.search("dev").len(), 1);
    assert_eq!(vault.search("savings").len(), 1);
    assert_eq!(vault.search("zulip.EXAMPLE").len(), 1);
    assert_eq!(vault.search("").len(), 3);
    assert_eq!(vault.search("nothing here").len(), 0);

    // Archived and hidden items are still listed; they are display flags, not
    // lifecycle states. Only trash and delete take an item out of `list`.
    vault
        .update(&bank, Edit::new().archived(true))
        .expect("archive");
    vault
        .update(&github, Edit::new().hidden(true))
        .expect("hide");
    assert_eq!(vault.list().count(), 3);
    vault.trash_item(&bank).expect("trash");
    assert_eq!(vault.list().count(), 2);
}

/// The OR-Set mutation limit is enforced, and re-adding something already present
/// still works on a full item.
#[test]
fn the_tag_limit_is_enforced_without_blocking_a_re_add() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    for index in 0..misty_vault::limits::MAX_SET_ENTRIES {
        vault.add_tag(&id, format!("tag{index:04}")).expect("tag");
    }
    assert!(matches!(
        vault.add_tag(&id, "one too many"),
        Err(VaultError::TooManyElements { field: "tags", .. })
    ));
    // Already present, so it changes nothing and is allowed.
    vault.add_tag(&id, "tag0000").expect("re-add");
    // And a hostile tag is refused on the way in, not on the way out.
    assert!(matches!(
        vault.add_tag(&id, "tag\u{202e}"),
        Err(VaultError::DisallowedCharacter { .. })
    ));
}

/// Conflicts accumulate on the vault, deduplicated, until a UI takes them.
#[test]
fn conflicts_are_reported_once_and_can_be_taken() {
    let mut a = peer(1, &[1, 2], NOW);
    let mut b = peer(2, &[1, 2], NOW);
    let id = a
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    sync(&a, &mut b);
    b.repair_secret(&id, SecretBytes::from_slice(b"bbbbbbbbbb"))
        .expect("repair");

    for _ in 0..3 {
        sync(&b, &mut a);
    }
    assert_eq!(a.conflicts().len(), 1, "{:?}", a.conflicts());
    let taken = a.take_conflicts();
    assert_eq!(taken.len(), 1);
    assert!(a.conflicts().is_empty());
}

/// Editing something that is not there is an error rather than a silent no-op.
#[test]
fn missing_items_are_reported() {
    let mut vault = peer(1, &[1], NOW);
    let missing = misty_crypto::ItemId::from_bytes([0xab; 16]);
    assert!(matches!(
        vault.item(&missing),
        Err(VaultError::NoSuchItem { .. })
    ));
    assert!(matches!(
        vault.update(&missing, Edit::new().favorite(true)),
        Err(VaultError::NoSuchItem { .. })
    ));
    assert!(matches!(
        vault.record_use(&missing),
        Err(VaultError::NoSuchItem { .. })
    ));
    assert!(matches!(
        vault.trash_item(&missing),
        Err(VaultError::NoSuchItem { .. })
    ));
    assert!(matches!(
        vault.repair_secret(&missing, SecretBytes::from_slice(b"aaaaaaaaaa")),
        Err(VaultError::NoSuchItem { .. })
    ));
}

/// Everything SPEC §3 lists is readable, and an item created through the builder
/// carries what was asked for.
#[test]
fn every_spec_field_round_trips_through_the_api() {
    let mut vault = peer(1, &[1], NOW);
    let group = vault.add_group("Work").expect("group");
    let id = vault
        .add(
            new_item("GitHub", "ada@example.com", b"aaaaaaaaaa")
                .nickname("work")
                .note("two\nlines")
                .tag("dev")
                .origin("github.com")
                .group(group)
                .icon(IconRef::Bundled("github".into()))
                .color(0xFF00_8080)
                .favorite(true)
                .requires_reveal_auth(true),
        )
        .expect("add");

    let item = vault.item(&id).expect("item");
    assert_eq!(item.id(), id);
    assert_eq!(item.issuer(), "GitHub");
    assert_eq!(item.account(), "ada@example.com");
    assert_eq!(item.nickname(), Some("work"));
    assert_eq!(item.note(), Some("two\nlines"));
    assert_eq!(item.tags().count(), 1);
    assert_eq!(item.origins().count(), 1);
    assert_eq!(item.groups().count(), 1);
    assert_eq!(item.icon(), &IconRef::Bundled("github".into()));
    assert_eq!(item.color(), Some(0xFF00_8080));
    assert!(item.favorite());
    assert!(item.requires_reveal_auth());
    assert!(!item.archived());
    assert!(!item.hidden());
    assert_eq!(item.manual_order(), None);
    assert_eq!(item.created_at(), NOW as i64);
    assert_eq!(item.last_used_at(), None);
    assert_eq!(item.use_count(), 0);
    assert_eq!(item.trashed_at(), None);
    assert!(item.tombstone().is_none());
    assert_eq!(item.kind(), misty_otp::OtpKind::Totp);
    assert_eq!(item.algorithm(), misty_otp::HashAlg::Sha1);
    assert_eq!(item.digits(), 6);
    assert_eq!(item.period(), 30);
    assert_eq!(item.hotp_counter(), 0);
    assert_eq!(item.pin(), None);

    // And the reassembled `OtpConfig` generates a code, which is the whole point.
    let config = item.otp().expect("otp");
    let code = config.generate_at(NOW).expect("code");
    assert_eq!(code.value().len(), 6);
}

/// A vault reports what it is without printing what it holds.
#[test]
fn debug_reports_counts_not_contents() {
    let mut vault = peer(1, &[1], NOW);
    vault
        .add(new_item("SecretBank", "ada@example.com", b"aaaaaaaaaa"))
        .expect("add");
    let rendered = format!("{vault:?}");
    assert!(rendered.contains("items: 1"), "{rendered}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
    assert!(!rendered.contains("SecretBank"), "{rendered}");
    assert!(!rendered.contains("ada@example.com"), "{rendered}");
}
