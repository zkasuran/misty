// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The trip through the real [`misty_crypto::envelope`]: encode → seal → store →
//! load → open → decode.
//!
//! The vault's own tests could all pass against a store that kept plaintext. These
//! are the ones that would not.

mod support;

use misty_crypto::envelope::{self, Envelope, EnvelopeKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::{derive, DeviceId, ItemId};
use misty_otp::FixedClock;
use misty_vault::{Edit, MemoryStore, RemoteChange, Vault, VaultError, VaultStore};
use support::{changes, device, new_item, peer, roster, vault_for, vault_key, NOW};

/// Everything written comes back identical after a lock and reopen, and it comes
/// back through signature verification and AEAD rather than around them.
#[test]
fn a_vault_reopens_byte_identically() {
    let mut vault = peer(1, &[1], NOW);
    let first = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    let second = vault
        .add(
            new_item("GitLab", "ada@example.com", b"bbbbbbbbbb")
                .nickname("work")
                .note("line one\nline two")
                .tag("dev")
                .origin("GitLab.com")
                .color(0xFF00_8080),
        )
        .expect("add");
    vault.record_use(&first).expect("use");
    vault.add_group("Work").expect("group");
    let before = support::fingerprint(&vault);
    let groups: Vec<String> = vault.groups().iter().map(|g| g.name().to_owned()).collect();

    let store = vault.lock();
    let reopened = vault_for(&[1], store, FixedClock::new(NOW));

    assert_eq!(support::fingerprint(&reopened), before);
    assert_eq!(reopened.item_set().len(), 2);
    let item = reopened.item(&second).expect("item");
    assert_eq!(item.nickname(), Some("work"));
    assert_eq!(item.note(), Some("line one\nline two"));
    assert_eq!(item.tags().map(String::as_str).collect::<Vec<_>>(), ["dev"]);
    // Origins are folded on the way in, so the round trip is lowercase.
    assert_eq!(
        item.origins().map(String::as_str).collect::<Vec<_>>(),
        ["gitlab.com"]
    );
    assert_eq!(item.color(), Some(0xFF00_8080));
    assert_eq!(reopened.item(&first).expect("item").use_count(), 1);
    assert_eq!(
        reopened
            .groups()
            .iter()
            .map(|g| g.name().to_owned())
            .collect::<Vec<_>>(),
        groups
    );
}

/// Payloads are padded to 256-byte buckets before encryption (SPEC §2.4), so an
/// item's size does not identify its issuer. The vault must not have defeated that
/// by writing an unpadded payload.
#[test]
fn stored_envelopes_are_padded_to_buckets() {
    let mut vault = peer(1, &[1], NOW);
    vault.add(new_item("A", "a", b"aaaaaaaaaa")).expect("add");
    vault
        .add(
            new_item(
                "An issuer with a much longer name",
                "someone@example.com",
                b"bbbbbbbbbb",
            )
            .note("and a note as well"),
        )
        .expect("add");
    for row in vault.store().load_all().expect("load_all") {
        let body = row.envelope.len() - (74 + 48 + 64);
        assert_eq!(body % 256, 16, "ciphertext is not 256n + 16");
    }
}

/// A tampered stored envelope is rejected **on load**, not on first use. One
/// flipped bit anywhere in the body invalidates the Ed25519 signature over
/// `Header || item_id || wrapped_item_key || ciphertext`.
#[test]
fn a_tampered_envelope_is_rejected_on_load() {
    for offset in [0usize, 74, 122, 200] {
        let mut vault = peer(1, &[1], NOW);
        let id = vault
            .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
            .expect("add");
        let mut store = vault.lock();
        let mut row = store.get(&id).expect("get").expect("a row");
        let byte = row.envelope.get_mut(offset).expect("in range");
        *byte ^= 0x01;
        store.put(&row).expect("put");

        let identity = device(1);
        let roster = roster(&[&identity]);
        let error = Vault::open(store, FixedClock::new(NOW), vault_key(), identity, roster)
            .expect_err("must refuse to open");
        match error {
            VaultError::CorruptRecord { item_id, .. } => assert_eq!(item_id, id),
            other => panic!("offset {offset}: expected CorruptRecord, got {other:?}"),
        }
    }
}

/// The `kind` column is plaintext and a hostile server can rewrite it. It is also
/// inside the authenticated header, so the two are cross-checked: relabelling an
/// item as a settings blob would otherwise hide it from every client that trusts
/// the column.
#[test]
fn a_rewritten_kind_column_is_caught() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    let mut store = vault.lock();
    let mut row = store.get(&id).expect("get").expect("a row");
    row.kind = EnvelopeKind::Settings;
    store.put(&row).expect("put");

    let identity = device(1);
    let roster = roster(&[&identity]);
    let error = Vault::open(store, FixedClock::new(NOW), vault_key(), identity, roster)
        .expect_err("must refuse");
    assert!(
        matches!(
            error,
            VaultError::CorruptRecord {
                source: ref inner,
                ..
            } if matches!(**inner, VaultError::KindMismatch { .. })
        ),
        "{error:?}"
    );
}

/// `hlc_max` is the one derived value stored in the clear. A server that rewrote it
/// could reorder a sync, so it is recomputed from the authenticated payload and
/// compared.
#[test]
fn a_rewritten_hlc_max_column_is_caught() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    let mut store = vault.lock();
    let mut row = store.get(&id).expect("get").expect("a row");
    row.hlc_max = misty_vault::Hlc::new(NOW + 999, 7, DeviceId::from_bytes([9; 16])).expect("hlc");
    store.put(&row).expect("put");

    let identity = device(1);
    let roster = roster(&[&identity]);
    let error = Vault::open(store, FixedClock::new(NOW), vault_key(), identity, roster)
        .expect_err("must refuse");
    assert!(
        matches!(error, VaultError::CorruptRecord { .. }),
        "{error:?}"
    );
}

/// A change signed by a device that is not in the roster is refused before anything
/// is decrypted (threat model `A6`), and nothing is written.
#[test]
fn a_change_from_an_unrostered_device_is_refused() {
    let mut stranger = peer(9, &[9], NOW);
    let id = stranger
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    let feed = changes(&stranger);

    let mut vault = peer(1, &[1, 2], NOW);
    let before = support::fingerprint(&vault);
    let error = vault.merge_remote(&feed).expect_err("must refuse");
    assert!(matches!(error, VaultError::Crypto(_)), "{error:?}");
    assert_eq!(support::fingerprint(&vault), before);
    assert!(vault.get(&id).is_none());
}

/// An envelope holding something the vault does not model — a settings blob — is
/// skipped rather than rejected, because its `kind` is authenticated: the *signer*
/// said it was settings, so the vault is not being lied to.
#[test]
fn an_unmodelled_envelope_kind_is_ignored() {
    let identity = device(1);
    let roster = roster(&[&identity]);
    let key = vault_key();
    let epoch_key = derive::epoch_key(&key, 0).expect("epoch key");
    let settings_id = ItemId::from_bytes([0xee; 16]);
    let envelope = envelope::seal(
        EnvelopeKind::Settings,
        0,
        &settings_id,
        b"some settings the vault knows nothing about",
        &epoch_key,
        &identity,
    )
    .expect("seal");

    let mut store = MemoryStore::new();
    store
        .put(&misty_vault::StoredEnvelope {
            item_id: settings_id,
            kind: EnvelopeKind::Settings,
            seq: None,
            version: None,
            envelope: envelope.clone(),
            hlc_max: misty_vault::Hlc::new(NOW, 0, identity.device_id()).expect("hlc"),
        })
        .expect("put");

    let mut vault =
        Vault::open(store, FixedClock::new(NOW), vault_key(), identity, roster).expect("open");
    assert_eq!(vault.item_set().len(), 0);

    // And the same through the merge path, where it is counted rather than dropped
    // silently.
    let report = vault
        .merge_remote(&[RemoteChange {
            item_id: settings_id,
            seq: Some(1),
            version: None,
            envelope,
        }])
        .expect("merge");
    assert_eq!((report.applied, report.ignored), (0, 1));
}

/// An item written under an older epoch still opens after a rotation, and a lazy
/// re-wrap moves it forward without changing a single field.
#[test]
fn mixed_epochs_open_and_rewrap_lazily() {
    let mut vault = peer(1, &[1], NOW);
    let first = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    let second = vault
        .add(new_item("GitLab", "ada", b"bbbbbbbbbb"))
        .expect("add");
    let before = support::fingerprint(&vault);

    assert_eq!(vault.rotate_epoch().expect("rotate"), 1);
    // Nothing has been re-wrapped yet, so both items are still at epoch 0.
    assert_eq!(epochs(&vault), vec![0, 0]);

    let progress = vault.rewrap_to_current_epoch(1).expect("rewrap");
    assert_eq!((progress.rewrapped, progress.remaining), (1, 1));
    let progress = vault.rewrap_to_current_epoch(10).expect("rewrap");
    assert_eq!((progress.rewrapped, progress.remaining), (1, 0));
    assert_eq!(epochs(&vault), vec![1, 1]);

    // The model is untouched: a re-wrap is not a logical write.
    assert_eq!(support::fingerprint(&vault), before);

    // And a further edit at the new epoch still merges against the old state.
    vault
        .update(&first, Edit::new().favorite(true))
        .expect("update");
    let store = vault.lock();
    let reopened = vault_for(&[1], store, FixedClock::new(NOW));
    assert!(reopened.item(&first).expect("item").favorite());
    assert!(!reopened.item(&second).expect("item").favorite());
}

/// The epochs of every stored envelope, in id order.
fn epochs(vault: &Vault<MemoryStore, FixedClock>) -> Vec<u32> {
    let mut rows = vault.store().load_all().expect("load_all");
    rows.sort_by_key(|row| row.item_id);
    rows.iter()
        .map(|row| {
            Envelope::parse(&row.envelope)
                .expect("parse")
                .header()
                .epoch
        })
        .collect()
}

/// A vault cannot be opened by a device the roster does not list, whatever the
/// server says (SPEC §6.2).
#[test]
fn an_unrostered_device_cannot_open_the_vault() {
    let known = device(1);
    let roster = roster(&[&known]);
    let stranger = DeviceIdentity::from_secret_bytes(
        DeviceId::from_bytes([0x77; 16]),
        &[0x78; 32],
        [0x79; 32],
    );
    let error = Vault::open(
        MemoryStore::new(),
        FixedClock::new(NOW),
        vault_key(),
        stranger,
        roster,
    )
    .expect_err("must refuse");
    assert!(
        matches!(error, VaultError::DeviceNotInRoster { .. }),
        "{error:?}"
    );
}

/// An unsigned roster is refused: it is the trust anchor for every other check, so
/// accepting one would mean trusting the server's idea of which devices exist.
#[test]
fn an_unsigned_roster_is_refused() {
    let identity = device(1);
    let unsigned = Roster::new(vec![identity
        .record("laptop", "linux", 1, None)
        .expect("record")]);
    let error = Vault::open(
        MemoryStore::new(),
        FixedClock::new(NOW),
        vault_key(),
        identity,
        unsigned,
    )
    .expect_err("must refuse");
    assert!(matches!(error, VaultError::Crypto(_)), "{error:?}");
}
