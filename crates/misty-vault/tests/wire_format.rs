// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The stored payload schema, pinned.
//!
//! Every one of these assertions is about a *format*, not a behaviour. A rename or a
//! reordering here would not break a single other test, and would silently orphan
//! every item already on disk — so the format is written down twice, once in the
//! code and once here, and the two have to agree.

mod support;

use ciborium::value::Value;
use misty_vault::{encode_group, encode_item, ITEM_FORMAT_VERSION};
use support::{new_item, peer, NOW};

fn keys(payload: &[u8]) -> Vec<String> {
    match ciborium::from_reader::<Value, _>(payload).expect("valid CBOR") {
        Value::Map(entries) => entries
            .into_iter()
            .map(|(key, _)| match key {
                Value::Text(text) => text,
                other => panic!("a non-text key: {other:?}"),
            })
            .collect(),
        other => panic!("a payload is a map, got {other:?}"),
    }
}

/// The item payload's keys, in order. Adding a field means bumping
/// [`ITEM_FORMAT_VERSION`] and updating this list in the same change.
#[test]
fn the_item_key_set_is_frozen() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    let payload = encode_item(vault.item(&id).expect("item")).expect("encode");

    assert_eq!(
        keys(&payload),
        [
            "v", "id", "sec", "knd", "alg", "dig", "per", "pin", "cnt", "isr", "acc", "nck", "nte",
            "grp", "tag", "org", "icn", "col", "fav", "ord", "arc", "hid", "rva", "trs", "usg",
            "lus", "crt", "del",
        ]
    );
    assert_eq!(ITEM_FORMAT_VERSION, 1);
}

/// The group payload's keys, in order.
#[test]
fn the_group_key_set_is_frozen() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault.add_group("Work").expect("group");
    let payload = encode_group(vault.group(&id).expect("group")).expect("encode");
    assert_eq!(
        keys(&payload),
        ["v", "id", "nam", "col", "ord", "crt", "del"]
    );
}

/// Ids and clocks are CBOR **byte strings**, not arrays of integers. An item carries
/// a dozen clocks, so the difference is a padding bucket per item.
#[test]
fn ids_and_clocks_are_byte_strings() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(new_item("GitHub", "ada", b"aaaaaaaaaa"))
        .expect("add");
    let payload = encode_item(vault.item(&id).expect("item")).expect("encode");
    let entries = match ciborium::from_reader::<Value, _>(&payload[..]).expect("valid CBOR") {
        Value::Map(entries) => entries,
        other => panic!("{other:?}"),
    };
    let get = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key == &Value::Text(name.to_owned()))
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("no key {name}"))
    };

    assert!(matches!(get("id"), Value::Bytes(bytes) if bytes.len() == 16));
    assert!(matches!(get("sec"), Value::Bytes(bytes) if bytes.len() == 10));
    // An `Lww` is a two-element array of `[value, clock]`, and the clock is 26
    // bytes: 8 of `wall_ms`, 2 of `counter`, 16 of `device_id`, big-endian.
    match get("fav") {
        Value::Array(parts) => {
            assert_eq!(parts.len(), 2);
            assert_eq!(parts[0], Value::Bool(false));
            assert!(matches!(&parts[1], Value::Bytes(bytes) if bytes.len() == 26));
        }
        other => panic!("fav is not an Lww: {other:?}"),
    }
    // `cnt` is a bare integer: a max-wins register needs no clock.
    assert_eq!(get("cnt"), Value::Integer(0.into()));
}

/// A plain item fits in a small number of padding buckets. Not a guarantee, but a
/// tripwire: a schema change that doubled the payload would show up here rather than
/// in a sync bill.
#[test]
fn a_plain_item_stays_small() {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(new_item("GitHub", "ada@example.com", b"aaaaaaaaaa"))
        .expect("add");
    let payload = encode_item(vault.item(&id).expect("item")).expect("encode");
    assert!(
        payload.len() <= 1024,
        "a plain item is {} bytes, which is {} padding buckets",
        payload.len(),
        payload.len().div_ceil(256)
    );
}
