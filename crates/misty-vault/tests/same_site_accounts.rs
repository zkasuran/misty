// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SPEC §3.1: multiple accounts on the same site, as a first-class requirement.
//!
//! > Authy and Google Authenticator both render two accounts at the same issuer
//! > identically, which is the single most common cause of users pasting the wrong
//! > code.
//!
//! The rule this crate enforces is the weakest one that guarantees a human can name
//! which item they mean: **nicknames within one `(issuer, account)` cluster must be
//! pairwise distinct, with "no nickname" counting as one of the values.** Adding a
//! second unlabelled `ada@example.com` at GitHub therefore fails; adding a second
//! one called "work" succeeds.

mod support;

use misty_otp::SecretBytes;
use misty_vault::{Edit, NewItem, VaultError};
use support::{new_item, peer, totp, NOW};

/// Rule 1: a colliding `(issuer, account)` with no distinguishing nickname is
/// refused, and the error names the item it collides with so the UI can show it.
#[test]
fn a_second_unlabelled_account_at_one_issuer_is_refused() {
    let mut vault = peer(1, &[1], NOW);
    let first = vault
        .add(new_item("GitHub", "ada@example.com", b"aaaaaaaaaa"))
        .expect("add");

    let error = vault
        .add(new_item("GitHub", "ada@example.com", b"bbbbbbbbbb"))
        .expect_err("must refuse");
    assert!(
        matches!(error, VaultError::AmbiguousAccount { existing } if existing == first),
        "{error:?}"
    );
    assert_eq!(vault.list().count(), 1);
}

/// Rule 5, second half: the same pair with a *different* secret is two real
/// accounts, and both are kept once one of them is labelled.
#[test]
fn a_distinguishing_nickname_lets_both_be_kept() {
    let mut vault = peer(1, &[1], NOW);
    let personal = vault
        .add(new_item("GitHub", "ada@example.com", b"aaaaaaaaaa"))
        .expect("add");
    let work = vault
        .add(new_item("GitHub", "ada@example.com", b"bbbbbbbbbb").nickname("work"))
        .expect("add");

    assert_eq!(vault.list().count(), 2);
    let cluster = vault.same_site_cluster("GitHub", "ada@example.com");
    assert_eq!(cluster.len(), 2);
    // Cluster order puts the unlabelled one first, because "" sorts below "work".
    assert_eq!(cluster[0].id(), personal);
    assert_eq!(cluster[1].id(), work);
    assert_eq!(cluster[1].nickname(), Some("work"));

    // A third one needs its own nickname; reusing "work" is refused.
    let error = vault
        .add(new_item("GitHub", "ada@example.com", b"cccccccccc").nickname("work"))
        .expect_err("must refuse");
    assert!(
        matches!(error, VaultError::AmbiguousAccount { existing } if existing == work),
        "{error:?}"
    );
    assert!(vault
        .add(new_item("GitHub", "ada@example.com", b"cccccccccc").nickname("ci"))
        .is_ok());
    assert_eq!(vault.list().count(), 3);
}

/// Rule 5, first half: identical `(issuer, account, secret)` is one credential seen
/// twice, and it gets a different error so the UI can offer to merge rather than
/// demanding a nickname the user cannot meaningfully supply.
#[test]
fn a_true_duplicate_is_reported_as_a_duplicate() {
    let mut vault = peer(1, &[1], NOW);
    let first = vault
        .add(new_item("GitHub", "ada@example.com", b"aaaaaaaaaa"))
        .expect("add");
    let error = vault
        .add(new_item("GitHub", "ada@example.com", b"aaaaaaaaaa").nickname("second copy"))
        .expect_err("must refuse");
    assert!(
        matches!(error, VaultError::DuplicateAccount { existing } if existing == first),
        "{error:?}"
    );
    // Even a distinguishing nickname does not make it a second account: the
    // duplicate check runs first, because the two are the same credential.
    assert_eq!(vault.list().count(), 1);
}

/// The other half of "offer to merge": folding the duplicate's metadata into the
/// item it duplicates, without creating a second row and without blanking a label
/// the user typed.
#[test]
fn merging_a_duplicate_folds_its_metadata_in() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(
            new_item("GitHub", "ada@example.com", b"aaaaaaaaaa")
                .nickname("mine")
                .tag("personal"),
        )
        .expect("add");

    let incoming = NewItem::new(totp(b"aaaaaaaaaa"), "GitHub", "ada@example.com")
        .tag("imported")
        .origin("github.com")
        .note("from the export");
    vault.merge_duplicate(&id, incoming).expect("merge");

    let item = vault.item(&id).expect("item");
    assert_eq!(
        item.tags().map(String::as_str).collect::<Vec<_>>(),
        ["imported", "personal"]
    );
    assert_eq!(
        item.origins().map(String::as_str).collect::<Vec<_>>(),
        ["github.com"]
    );
    assert_eq!(item.note(), Some("from the export"));
    // The nickname the user typed survives, because the import did not set one.
    assert_eq!(item.nickname(), Some("mine"));
    assert_eq!(vault.list().count(), 1);
}

/// Folding is refused when the secrets differ: that is not a duplicate, and both
/// items have to be kept.
#[test]
fn merging_a_non_duplicate_is_refused() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(new_item("GitHub", "ada@example.com", b"aaaaaaaaaa"))
        .expect("add");
    let error = vault
        .merge_duplicate(
            &id,
            NewItem::new(totp(b"bbbbbbbbbb"), "GitHub", "ada@example.com"),
        )
        .expect_err("must refuse");
    assert!(
        matches!(error, VaultError::SecretIsImmutable { item } if item == id),
        "{error:?}"
    );
}

/// A HOTP counter carried by a re-import can only move the stored counter forward.
#[test]
fn folding_a_duplicate_never_rolls_a_counter_back() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(NewItem::new(
            support::hotp(b"12345678901234567890", 40),
            "Bank",
            "ada",
        ))
        .expect("add");
    vault
        .merge_duplicate(
            &id,
            NewItem::new(support::hotp(b"12345678901234567890", 3), "Bank", "ada"),
        )
        .expect("merge");
    assert_eq!(vault.item(&id).expect("item").hotp_counter(), 40);
    vault
        .merge_duplicate(
            &id,
            NewItem::new(support::hotp(b"12345678901234567890", 77), "Bank", "ada"),
        )
        .expect("merge");
    assert_eq!(vault.item(&id).expect("item").hotp_counter(), 77);
}

/// Collision detection folds case and trims whitespace: `GitHub` and ` github ` are
/// one cluster, or the rule would be trivially bypassed by the shift key.
#[test]
fn collision_detection_folds_case_and_whitespace() {
    let mut vault = peer(1, &[1], NOW);
    vault
        .add(new_item("GitHub", "Ada@Example.com", b"aaaaaaaaaa"))
        .expect("add");
    let error = vault
        .add(new_item("  github ", "ada@example.com", b"bbbbbbbbbb"))
        .expect_err("must refuse");
    assert!(
        matches!(error, VaultError::AmbiguousAccount { .. }),
        "{error:?}"
    );

    // And so does the nickname comparison.
    vault
        .add(new_item("github", "ada@example.com", b"bbbbbbbbbb").nickname("Work"))
        .expect("add");
    let error = vault
        .add(new_item("GITHUB", "ADA@EXAMPLE.COM", b"cccccccccc").nickname("  work"))
        .expect_err("must refuse");
    assert!(
        matches!(error, VaultError::AmbiguousAccount { .. }),
        "{error:?}"
    );
}

/// The rule is about the state of the vault, not only about `add`: renaming one
/// item onto another's pair produces exactly the ambiguity rule 1 prevents.
#[test]
fn a_rename_cannot_create_an_ambiguous_pair() {
    let mut vault = peer(1, &[1], NOW);
    let first = vault
        .add(new_item("GitHub", "ada@example.com", b"aaaaaaaaaa"))
        .expect("add");
    let second = vault
        .add(new_item("GitLab", "ada@example.com", b"bbbbbbbbbb"))
        .expect("add");

    let error = vault
        .update(&second, Edit::new().issuer("GitHub"))
        .expect_err("must refuse");
    assert!(
        matches!(error, VaultError::AmbiguousAccount { existing } if existing == first),
        "{error:?}"
    );
    // Refused means unchanged, not half applied.
    assert_eq!(vault.item(&second).expect("item").issuer(), "GitLab");

    // With a nickname in the same edit it goes through.
    vault
        .update(
            &second,
            Edit::new().issuer("GitHub").nickname(Some("work".into())),
        )
        .expect("update");
    assert_eq!(
        vault.same_site_cluster("GitHub", "ada@example.com").len(),
        2
    );
}

/// A trashed or deleted item does not block an add: the cluster is defined over
/// items the user can actually see, and refusing because of something in the bin
/// would be inexplicable.
#[test]
fn a_trashed_item_does_not_block_its_replacement() {
    let mut vault = peer(1, &[1], NOW);
    let first = vault
        .add(new_item("GitHub", "ada@example.com", b"aaaaaaaaaa"))
        .expect("add");
    vault.trash_item(&first).expect("trash");
    let second = vault
        .add(new_item("GitHub", "ada@example.com", b"bbbbbbbbbb"))
        .expect("add");
    assert_eq!(vault.list().count(), 1);
    assert_eq!(vault.trash().len(), 1);

    // Restoring the first one now *does* recreate the ambiguity, and the UI has to
    // deal with it — refusing a restore would be worse, because the alternative is
    // telling the user their item is gone.
    vault.restore_item(&first).expect("restore");
    assert_eq!(
        vault.same_site_cluster("GitHub", "ada@example.com").len(),
        2
    );
    assert_eq!(second, vault.item(&second).expect("item").id());
}

/// Rule 3 and 4: the fields that make a cluster readable are all present and
/// per-item.
#[test]
fn a_cluster_carries_everything_needed_to_tell_the_items_apart() {
    let mut vault = peer(1, &[1], NOW);
    let personal = vault
        .add(
            new_item("GitHub", "ada@example.com", b"aaaaaaaaaa")
                .nickname("personal")
                .color(0xFF00_8080),
        )
        .expect("add");
    let work = vault
        .add(
            new_item("GitHub", "ada@example.com", b"bbbbbbbbbb")
                .nickname("work")
                .icon(misty_vault::IconRef::Bundled("github".into())),
        )
        .expect("add");
    vault.clock().set(NOW + 120_000);
    vault.record_use(&work).expect("use");

    let cluster = vault.same_site_cluster("GitHub", "ada@example.com");
    assert_eq!(cluster.len(), 2);
    assert_eq!(cluster[0].id(), personal);
    assert_eq!(cluster[0].color(), Some(0xFF00_8080));
    assert_eq!(cluster[1].id(), work);
    assert_eq!(
        cluster[1].icon(),
        &misty_vault::IconRef::Bundled("github".into())
    );
    // Rule 4: `last_used_at` is what makes the right one obvious at a glance.
    assert_eq!(cluster[0].last_used_at(), None);
    assert_eq!(cluster[1].last_used_at(), Some(NOW as i64 + 120_000));
}

/// A secret that is not a usable OTP secret is refused before an id is drawn.
#[test]
fn an_unusable_secret_is_refused() {
    let mut vault = peer(1, &[1], NOW);
    let error = misty_otp::OtpConfig::totp(SecretBytes::new(Vec::new()))
        .expect_err("empty secret is not a config");
    assert!(matches!(error, misty_otp::OtpError::EmptySecret));
    // And the vault refuses a blank issuer or account outright.
    for item in [
        new_item("", "ada", b"aaaaaaaaaa"),
        new_item("GitHub", "   ", b"aaaaaaaaaa"),
    ] {
        assert!(matches!(
            vault.add(item),
            Err(VaultError::EmptyField { .. })
        ));
    }
}
