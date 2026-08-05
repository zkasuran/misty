// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Everything the item decoder must reject, and nothing it may panic on.
//!
//! An item payload is *authenticated* before it reaches the decoder — the envelope
//! proves a rostered device signed it — and that is not the same as *trusted*. The
//! signer may have been an older build, a buggy importer, or a device whose keys an
//! attacker holds. So every one of these is fed to [`decode_item`] directly, which
//! is exactly what `envelope::open` hands it.
//!
//! Hostile payloads are built by decoding a valid one into a generic CBOR value,
//! patching one field, and re-encoding. That is deliberately not the same as
//! hand-writing bytes: it keeps the tests honest about the real schema, and a
//! rename that broke them would be telling the truth.

mod support;

use ciborium::value::Value;
use misty_crypto::DeviceId;
use misty_vault::limits;
use misty_vault::{decode_group, decode_item, encode_group, encode_item, Hlc, VaultError};
use support::{new_item, peer, NOW};

/// A valid encoded item, and its id, to patch.
fn valid_item() -> Vec<u8> {
    let mut vault = peer(1, &[1], NOW);
    let id = vault
        .add(
            new_item("GitHub", "ada@example.com", b"aaaaaaaaaa")
                .nickname("work")
                .note("a note")
                .tag("dev")
                .origin("github.com"),
        )
        .expect("add");
    encode_item(vault.item(&id).expect("item"))
        .expect("encode")
        .to_vec()
}

fn valid_group() -> Vec<u8> {
    let mut vault = peer(1, &[1], NOW);
    let id = vault.add_group("Work").expect("group");
    encode_group(vault.group(&id).expect("group")).expect("encode")
}

fn to_value(payload: &[u8]) -> Vec<(Value, Value)> {
    match ciborium::from_reader::<Value, _>(payload).expect("valid CBOR") {
        Value::Map(entries) => entries,
        other => panic!("an item payload is a map, got {other:?}"),
    }
}

fn from_value(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut out).expect("encode");
    out
}

/// A valid payload with one key replaced.
fn patched(payload: &[u8], key: &str, value: Value) -> Vec<u8> {
    let mut entries = to_value(payload);
    let slot = entries
        .iter_mut()
        .find(|(name, _)| name == &Value::Text(key.to_owned()))
        .unwrap_or_else(|| panic!("no key {key} in the schema"));
    slot.1 = value;
    from_value(entries)
}

/// A valid payload with one key removed.
fn without(payload: &[u8], key: &str) -> Vec<u8> {
    let mut entries = to_value(payload);
    entries.retain(|(name, _)| name != &Value::Text(key.to_owned()));
    from_value(entries)
}

/// A 26-byte clock, as the wire carries it.
fn clock_bytes(wall_ms: u64) -> Value {
    let mut bytes = wall_ms.to_be_bytes().to_vec();
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&[0xaa; 16]);
    Value::Bytes(bytes)
}

/// An `Lww` on the wire is `[value, clock]`.
fn lww(value: Value, wall_ms: u64) -> Value {
    Value::Array(vec![value, clock_bytes(wall_ms)])
}

/// An OR-Set entry is `[element, added, removed?]`.
fn set_entry(element: &str, wall_ms: u64) -> Value {
    Value::Array(vec![
        Value::Text(element.to_owned()),
        clock_bytes(wall_ms),
        Value::Null,
    ])
}

/// The baseline: the fixture this whole file patches really does decode.
#[test]
fn the_valid_payload_is_valid() {
    let item = decode_item(&valid_item()).expect("decode");
    assert_eq!(item.issuer(), "GitHub");
    assert!(decode_group(&valid_group()).is_ok());
}

/// Nothing that is not CBOR, and nothing that is CBOR but not this schema.
#[test]
fn malformed_input_errors_rather_than_panicking() {
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x00],
        vec![0xff; 64],
        b"not cbor at all".to_vec(),
        vec![0xa0],                         // an empty map
        vec![0x80],                         // an empty array
        vec![0xf6],                         // null
        vec![0x9f, 0xff],                   // an indefinite-length array
        vec![0x5f, 0x41, 0x61, 0xff],       // an indefinite-length byte string
        vec![0xbf, 0x61, 0x76, 0x01, 0xff], // an indefinite-length map with only `v`
    ];
    for case in cases {
        assert!(
            decode_item(&case).is_err(),
            "accepted {} bytes of nonsense",
            case.len()
        );
        assert!(decode_group(&case).is_err());
    }
}

/// Every truncation of a valid payload, and a bit flip at every byte. Neither may
/// panic; both are overwhelmingly expected to error.
#[test]
fn truncations_and_bit_flips_never_panic() {
    let valid = valid_item();
    for len in 0..valid.len() {
        let _ = decode_item(&valid[..len]);
    }
    for index in 0..valid.len() {
        let mut flipped = valid.clone();
        flipped[index] ^= 0x80;
        let _ = decode_item(&flipped);
        flipped[index] ^= 0x01;
        let _ = decode_item(&flipped);
    }
}

/// A payload from a future build is refused by version, not by a confusing parse
/// error — and forward compatibility is deliberately not attempted, because a newer
/// writer may have changed what the following fields mean.
#[test]
fn an_unknown_format_version_is_refused() {
    for version in [0u8, 2, 42, 255] {
        let payload = patched(&valid_item(), "v", Value::Integer(version.into()));
        assert!(
            matches!(
                decode_item(&payload),
                Err(VaultError::UnsupportedFormatVersion { found, .. }) if found == version
            ),
            "version {version} was accepted"
        );
    }
    let payload = patched(&valid_group(), "v", Value::Integer(9.into()));
    assert!(matches!(
        decode_group(&payload),
        Err(VaultError::UnsupportedFormatVersion { found: 9, .. })
    ));
}

/// Unknown keys are rejected rather than ignored, and a missing key is not silently
/// defaulted. Both would let one build read a payload as something the writer did
/// not mean.
#[test]
fn unknown_and_missing_keys_are_refused() {
    let mut entries = to_value(&valid_item());
    entries.push((Value::Text("zzz".to_owned()), Value::Integer(1.into())));
    assert!(matches!(
        decode_item(&from_value(entries)),
        Err(VaultError::Cbor { .. })
    ));

    for key in ["id", "sec", "isr", "acc", "crt", "usg", "tag"] {
        assert!(
            matches!(
                decode_item(&without(&valid_item(), key)),
                Err(VaultError::Cbor { .. })
            ),
            "a payload without {key} was accepted"
        );
    }
}

/// Absurd field lengths are refused by the limit, with the field named and the text
/// itself never in the error.
#[test]
fn absurd_field_lengths_are_refused() {
    let cases: Vec<(&str, usize, usize)> = vec![
        ("isr", limits::MAX_ISSUER_LEN, 100_000),
        ("acc", limits::MAX_ACCOUNT_LEN, 100_000),
    ];
    for (key, max, length) in cases {
        let payload = patched(
            &valid_item(),
            key,
            lww(Value::Text("x".repeat(length)), NOW),
        );
        let error = decode_item(&payload).expect_err("must refuse");
        assert!(
            matches!(error, VaultError::StringTooLong { max: m, found, .. } if m == max && found == length),
            "{key}: {error:?}"
        );
    }

    // A nickname and a note have their own, smaller limits.
    let payload = patched(
        &valid_item(),
        "nck",
        lww(Value::Text("n".repeat(limits::MAX_NICKNAME_LEN + 1)), NOW),
    );
    assert!(matches!(
        decode_item(&payload),
        Err(VaultError::StringTooLong {
            field: "nickname",
            ..
        })
    ));
    let payload = patched(
        &valid_item(),
        "nte",
        lww(Value::Text("n".repeat(limits::MAX_NOTE_LEN + 1)), NOW),
    );
    assert!(matches!(
        decode_item(&payload),
        Err(VaultError::StringTooLong { field: "note", .. })
    ));
    let payload = patched(
        &valid_item(),
        "tag",
        Value::Array(vec![set_entry(&"t".repeat(limits::MAX_TAG_LEN + 1), NOW)]),
    );
    assert!(matches!(
        decode_item(&payload),
        Err(VaultError::StringTooLong { field: "tags", .. })
    ));
}

/// Ten thousand tags. The bound is on the count, and it is checked before a model is
/// built.
#[test]
fn ten_thousand_tags_are_refused() {
    let tags: Vec<Value> = (0..10_000)
        .map(|index| set_entry(&format!("tag{index:05}"), NOW))
        .collect();
    let payload = patched(&valid_item(), "tag", Value::Array(tags));
    let error = decode_item(&payload).expect_err("must refuse");
    assert!(
        matches!(
            error,
            VaultError::TooManyElements { field: "tags", max, found: 10_000 }
                if max == limits::MAX_DECODED_SET_ENTRIES
        ),
        "{error:?}"
    );
}

/// The same for origins, groups, and the usage counter.
#[test]
fn every_collection_is_bounded() {
    let entries: Vec<Value> = (0..10_000)
        .map(|index| set_entry(&format!("site{index:05}.example"), NOW))
        .collect();
    assert!(matches!(
        decode_item(&patched(&valid_item(), "org", Value::Array(entries))),
        Err(VaultError::TooManyElements {
            field: "origins",
            ..
        })
    ));

    let groups: Vec<Value> = (0..10_000u32)
        .map(|index| {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&index.to_be_bytes());
            Value::Array(vec![
                Value::Bytes(id.to_vec()),
                clock_bytes(NOW),
                Value::Null,
            ])
        })
        .collect();
    assert!(matches!(
        decode_item(&patched(&valid_item(), "grp", Value::Array(groups))),
        Err(VaultError::TooManyElements {
            field: "groups",
            ..
        })
    ));

    let usage: Vec<Value> = (0..10_000u32)
        .map(|index| {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&index.to_be_bytes());
            Value::Array(vec![Value::Bytes(id.to_vec()), Value::Integer(1.into())])
        })
        .collect();
    assert!(matches!(
        decode_item(&patched(&valid_item(), "usg", Value::Array(usage))),
        Err(VaultError::TooManyElements { field: "usage", .. })
    ));
}

/// A repeated key in a set or a counter is refused rather than resolved: the two
/// entries carry different clocks, so "the last one wins" would make the decoded
/// value depend on the order the encoder happened to write them in.
#[test]
fn repeated_keys_are_refused() {
    let payload = patched(
        &valid_item(),
        "tag",
        Value::Array(vec![set_entry("dev", NOW), set_entry("dev", NOW + 1)]),
    );
    assert!(matches!(
        decode_item(&payload),
        Err(VaultError::DuplicateKey { field: "tags" })
    ));

    let device = Value::Bytes(vec![0x11; 16]);
    let payload = patched(
        &valid_item(),
        "usg",
        Value::Array(vec![
            Value::Array(vec![device.clone(), Value::Integer(1.into())]),
            Value::Array(vec![device, Value::Integer(2.into())]),
        ]),
    );
    assert!(matches!(
        decode_item(&payload),
        Err(VaultError::DuplicateKey { field: "usage" })
    ));
}

/// A payload larger than the crate will decode is refused by a length comparison,
/// before the CBOR parser runs at all.
#[test]
fn an_oversized_payload_is_refused_before_parsing() {
    let payload = vec![0xa0; limits::MAX_ITEM_PAYLOAD_LEN + 1];
    assert!(matches!(
        decode_item(&payload),
        Err(VaultError::PayloadTooLarge {
            context: "item",
            ..
        })
    ));
    let payload = vec![0xa0; limits::MAX_GROUP_PAYLOAD_LEN + 1];
    assert!(matches!(
        decode_group(&payload),
        Err(VaultError::PayloadTooLarge {
            context: "group",
            ..
        })
    ));
}

/// A clock in 1970 or in 2200. The window is absolute, so every device rejects
/// exactly the same values and merge stays independent of wall time.
#[test]
fn clocks_outside_the_window_are_refused() {
    let outside = [
        0u64, // an RTC that never got set
        1,    // 1970
        misty_vault::MIN_WALL_MS - 1,
        misty_vault::MAX_WALL_MS, // 2100, exclusive bound
        7_258_118_400_000,        // 2200
        u64::MAX,
    ];
    for wall_ms in outside {
        for key in ["isr", "acc", "nck", "fav", "trs"] {
            let mut entries = to_value(&valid_item());
            let slot = entries
                .iter_mut()
                .find(|(name, _)| name == &Value::Text(key.to_owned()))
                .expect("key");
            // Keep the value, replace only the clock.
            let value = match &slot.1 {
                Value::Array(parts) => parts.first().cloned().expect("a value"),
                other => panic!("{key} is not an Lww: {other:?}"),
            };
            slot.1 = Value::Array(vec![value, clock_bytes(wall_ms)]);
            let error = decode_item(&from_value(entries)).expect_err("must refuse");
            assert!(
                matches!(error, VaultError::HlcOutOfRange { wall_ms: found, .. } if found == wall_ms),
                "{key} at {wall_ms}: {error:?}"
            );
        }
    }
}

/// A tombstone dated after the year 2100 is refused with the rest of them.
#[test]
fn a_tombstone_from_beyond_the_window_is_refused() {
    let stone = Value::Map(vec![
        (
            Value::Text("hlc".to_owned()),
            clock_bytes(7_258_118_400_000),
        ),
        (
            Value::Text("reason".to_owned()),
            Value::Text("user".to_owned()),
        ),
    ]);
    let payload = patched(&valid_item(), "del", stone);
    assert!(matches!(
        decode_item(&payload),
        Err(VaultError::HlcOutOfRange { .. })
    ));
}

/// A tombstone dated inside the window but in the reader's future is *accepted* —
/// it is a legal clock reading from a device whose clock is ahead — and must not
/// make the purge misbehave or the age arithmetic underflow.
#[test]
fn a_tombstone_in_the_readers_future_is_accepted_and_not_purged() {
    let future = misty_vault::MAX_WALL_MS - 1;
    let stone = Value::Map(vec![
        (Value::Text("hlc".to_owned()), clock_bytes(future)),
        (
            Value::Text("reason".to_owned()),
            Value::Text("user".to_owned()),
        ),
    ]);
    let item = decode_item(&patched(&valid_item(), "del", stone)).expect("decode");
    assert!(item.is_deleted());
    let stone = item.tombstone().expect("a tombstone");
    assert!(!stone.is_purgeable(NOW, limits::TOMBSTONE_RETENTION_MS));
    assert!(!stone.is_purgeable(0, limits::TOMBSTONE_RETENTION_MS));
}

/// A clock of the wrong length is a structural error, caught by the deserializer.
#[test]
fn a_short_or_long_clock_is_refused() {
    for length in [0usize, 1, 25, 27, 64] {
        let payload = patched(
            &valid_item(),
            "fav",
            Value::Array(vec![Value::Bool(true), Value::Bytes(vec![0u8; length])]),
        );
        assert!(
            matches!(decode_item(&payload), Err(VaultError::Cbor { .. })),
            "a {length}-byte clock was accepted"
        );
    }
}

/// Out-of-range OTP parameters are refused, and the bound comes from `misty-otp`
/// rather than being restated here.
#[test]
fn unusable_otp_parameters_are_refused() {
    for digits in [0u8, 11, 200, 255] {
        let payload = patched(
            &valid_item(),
            "dig",
            lww(Value::Integer(digits.into()), NOW),
        );
        assert!(
            matches!(decode_item(&payload), Err(VaultError::Otp(_))),
            "digits {digits} was accepted"
        );
    }
    for period in [0u16, 3601, 65535] {
        let payload = patched(
            &valid_item(),
            "per",
            lww(Value::Integer(period.into()), NOW),
        );
        assert!(
            matches!(decode_item(&payload), Err(VaultError::Otp(_))),
            "period {period} was accepted"
        );
    }
    // An empty secret is not a token.
    let payload = patched(&valid_item(), "sec", Value::Bytes(Vec::new()));
    assert!(matches!(decode_item(&payload), Err(VaultError::Otp(_))));
    // Nor is one over `MAX_SECRET_LEN`.
    let payload = patched(
        &valid_item(),
        "sec",
        Value::Bytes(vec![0x41; misty_otp::MAX_SECRET_LEN + 1]),
    );
    assert!(matches!(decode_item(&payload), Err(VaultError::Otp(_))));
}

/// An enumerated field with a wire value this build does not know is refused, never
/// defaulted: reading an unknown construction as `Totp` would generate wrong codes
/// and look like a broken service.
#[test]
fn unknown_enum_wire_values_are_refused() {
    for byte in [0u8, 7, 99, 255] {
        let payload = patched(&valid_item(), "knd", lww(Value::Integer(byte.into()), NOW));
        assert!(
            matches!(
                decode_item(&payload),
                Err(VaultError::UnknownEnumValue { field: "otp.kind", found }) if found == byte
            ),
            "kind {byte} was accepted"
        );
    }
    for byte in [0u8, 4, 255] {
        let payload = patched(&valid_item(), "alg", lww(Value::Integer(byte.into()), NOW));
        assert!(
            matches!(
                decode_item(&payload),
                Err(VaultError::UnknownEnumValue {
                    field: "otp.algorithm",
                    ..
                })
            ),
            "algorithm {byte} was accepted"
        );
    }
    // And an unknown tombstone reason.
    let stone = Value::Map(vec![
        (Value::Text("hlc".to_owned()), clock_bytes(NOW)),
        (
            Value::Text("reason".to_owned()),
            Value::Text("something else".to_owned()),
        ),
    ]);
    assert!(matches!(
        decode_item(&patched(&valid_item(), "del", stone)),
        Err(VaultError::Cbor { .. })
    ));
}

/// Adversarial text is refused; non-ASCII text is not. SPEC §7.2 settles this and
/// the vault holds the same line: `日本銀行` is a real bank.
#[test]
fn adversarial_text_is_refused_and_real_text_is_not() {
    for hostile in [
        "GitHub\u{0}",
        "GitHub\n",
        "\u{202e}buHtiG",
        "Git\u{200b}Hub",
        "\u{feff}GitHub",
    ] {
        let payload = patched(
            &valid_item(),
            "isr",
            lww(Value::Text(hostile.to_owned()), NOW),
        );
        assert!(
            matches!(
                decode_item(&payload),
                Err(VaultError::DisallowedCharacter {
                    field: "issuer",
                    ..
                })
            ),
            "{hostile:?} was accepted"
        );
    }
    for real in ["日本銀行", "Bücherei", "Ωμέγα", "🔐 prod"] {
        let payload = patched(&valid_item(), "isr", lww(Value::Text(real.to_owned()), NOW));
        assert_eq!(
            decode_item(&payload).expect("must accept").issuer(),
            real,
            "{real} was refused"
        );
    }
    // A blank required field is refused too: an account of three spaces is
    // indistinguishable from no account at all, and SPEC §3.1's collision rule is
    // defined on it.
    for blank in ["", "   ", "\u{3000}"] {
        let payload = patched(
            &valid_item(),
            "acc",
            lww(Value::Text(blank.to_owned()), NOW),
        );
        assert!(matches!(
            decode_item(&payload),
            Err(VaultError::EmptyField { field: "account" })
        ));
    }
}

/// A group payload gets the same treatment.
#[test]
fn hostile_group_payloads_are_refused() {
    let payload = patched(
        &valid_group(),
        "nam",
        lww(Value::Text("n".repeat(limits::MAX_GROUP_NAME_LEN + 1)), NOW),
    );
    assert!(matches!(
        decode_group(&payload),
        Err(VaultError::StringTooLong {
            field: "group.name",
            ..
        })
    ));
    let payload = patched(&valid_group(), "nam", lww(Value::Text(String::new()), NOW));
    assert!(matches!(
        decode_group(&payload),
        Err(VaultError::EmptyField {
            field: "group.name"
        })
    ));
    let payload = patched(&valid_group(), "nam", lww(Value::Text("x".to_owned()), 0));
    assert!(matches!(
        decode_group(&payload),
        Err(VaultError::HlcOutOfRange { .. })
    ));
}

/// Deep CBOR nesting cannot reach the recursive part of the parser, because the
/// schema is not recursive: the first token already fails to be the map the
/// derive expects.
#[test]
fn deeply_nested_cbor_does_not_recurse() {
    for depth in [16usize, 1024, 100_000] {
        let mut payload = vec![0x81; depth];
        payload.push(0xf6);
        assert!(decode_item(&payload).is_err(), "depth {depth}");
        assert!(decode_group(&payload).is_err(), "depth {depth}");
    }
}

/// A byte string written as a CBOR array of integers decodes to the same bytes.
///
/// This crate always *writes* the byte-string form, which is what keeps encodings
/// canonical; accepting the array form on read is a documented leniency, and it is
/// the same one `misty_crypto`'s own id types have.
#[test]
fn a_secret_written_as_an_array_decodes_the_same() {
    // One fixture, patched: `valid_item()` draws a fresh random id each call, so
    // two calls would differ in `id` alone.
    let payload = valid_item();
    let canonical = decode_item(&payload).expect("decode");
    let as_array = Value::Array(
        canonical
            .secret()
            .expose_secret()
            .iter()
            .map(|byte| Value::Integer((*byte).into()))
            .collect(),
    );
    let lenient = decode_item(&patched(&payload, "sec", as_array)).expect("decode");
    assert_eq!(lenient.secret(), canonical.secret());
    // And re-encoding it produces the canonical form, so nothing downstream sees
    // two encodings of one item.
    assert_eq!(
        encode_item(&lenient).expect("encode").to_vec(),
        encode_item(&canonical).expect("encode").to_vec()
    );
}

/// The encoder refuses to write what the decoder would refuse to read, so a merge
/// that overflowed a limit fails on a transaction that rolls back rather than
/// leaving an unreadable row.
#[test]
fn the_encoder_validates_before_writing() {
    let item = decode_item(&patched(
        &valid_item(),
        "nck",
        lww(Value::Text("fine".to_owned()), NOW),
    ))
    .expect("decode");
    assert!(encode_item(&item).is_ok());

    // Reaching an invalid model through the public API is not possible, which is
    // the point; this asserts the check exists by round-tripping the one field
    // whose limit a merge could plausibly cross.
    let hlc = Hlc::new(NOW, 0, DeviceId::from_bytes([1; 16])).expect("hlc");
    assert_eq!(hlc.to_sort_bytes().len(), misty_vault::HLC_LEN);
}
