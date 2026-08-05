// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property tests over the public API.
//!
//! The padding boundaries are the reason this file exists: a payload of 252
//! bytes fills one block exactly, 253 spills into a second, and an
//! off-by-four in the length prefix would only show up at exactly those sizes.
//! `proptest` covers 0..8192 generally; the boundary cases are also asserted
//! explicitly, because a random search is not guaranteed to hit them.

use misty_crypto::derive;
use misty_crypto::envelope::{self, EnvelopeKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::keys::{EpochKey, VaultKey};
use misty_crypto::{DeviceId, ItemId};
use proptest::prelude::*;

const EPOCH: u32 = 5;

fn identity() -> DeviceIdentity {
    DeviceIdentity::from_secret_bytes(DeviceId::from_bytes([0x21; 16]), &[0x22; 32], [0x23; 32])
}

fn roster(identity: &DeviceIdentity) -> Roster {
    let record = identity
        .record("Property Device", "linux", 1_700_000_000_000, None)
        .expect("record");
    let mut roster = Roster::new(vec![record]);
    roster.sign(identity).expect("sign");
    roster
}

fn epoch_key() -> EpochKey {
    derive::epoch_key(&VaultKey::from_bytes([0x24; 32]), EPOCH).expect("epoch key")
}

fn round_trip(payload: &[u8], item_id: &ItemId) {
    let identity = identity();
    let key = epoch_key();
    let sealed =
        envelope::seal(EnvelopeKind::Item, EPOCH, item_id, payload, &key, &identity).expect("seal");

    // Size leaks only in 256-byte buckets.
    let overhead =
        envelope::HEADER_LEN + envelope::WRAPPED_ITEM_KEY_LEN + 16 + envelope::SIGNATURE_LEN;
    let blocks = (payload.len() + 4).div_ceil(envelope::PAD_BLOCK);
    assert_eq!(sealed.len(), overhead + blocks * envelope::PAD_BLOCK);

    let opened = envelope::open(&sealed, item_id, &key, &roster(&identity)).expect("open");
    assert_eq!(opened.as_slice(), payload);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Seal then open, for arbitrary payload lengths up to 8 KiB.
    #[test]
    fn seal_open_round_trip(
        payload in prop::collection::vec(any::<u8>(), 0..8192usize),
        item_id_bytes in any::<[u8; 16]>(),
    ) {
        round_trip(&payload, &ItemId::from_bytes(item_id_bytes));
    }

    /// `pad` then `unpad` is the identity, and the result is always a whole
    /// number of blocks.
    #[test]
    fn pad_unpad_round_trip(payload in prop::collection::vec(any::<u8>(), 0..8192usize)) {
        let padded = envelope::pad(&payload).expect("pad");
        prop_assert_eq!(padded.len() % envelope::PAD_BLOCK, 0);
        prop_assert!(padded.len() >= payload.len() + 4);
        prop_assert!(padded.len() < payload.len() + 4 + envelope::PAD_BLOCK);
        prop_assert_eq!(envelope::unpad(&padded).expect("unpad"), payload.as_slice());
    }

    /// An envelope never opens under an item id other than its own, whatever
    /// the payload and however close the ids are.
    #[test]
    fn envelopes_never_relocate(
        payload in prop::collection::vec(any::<u8>(), 0..512usize),
        flip in 0usize..128,
    ) {
        let identity = identity();
        let key = epoch_key();
        let mut id_bytes = [0x30u8; 16];
        let item_id = ItemId::from_bytes(id_bytes);
        let sealed = envelope::seal(
            EnvelopeKind::Item, EPOCH, &item_id, &payload, &key, &identity,
        ).expect("seal");

        // Flip one bit of the item id: 128 distinct neighbours, none of which
        // may open the envelope.
        let byte = flip / 8;
        if let Some(slot) = id_bytes.get_mut(byte) {
            *slot ^= 1 << (flip % 8);
        }
        let neighbour = ItemId::from_bytes(id_bytes);
        prop_assert!(
            envelope::open(&sealed, &neighbour, &key, &roster(&identity)).is_err()
        );
    }

    /// `unpad` never panics, whatever the buffer.
    #[test]
    fn unpad_never_panics(buffer in prop::collection::vec(any::<u8>(), 0..2048usize)) {
        let _ = envelope::unpad(&buffer);
    }

    /// `Envelope::parse` never panics, whatever the buffer.
    #[test]
    fn parse_never_panics(buffer in prop::collection::vec(any::<u8>(), 0..1024usize)) {
        let _ = envelope::Envelope::parse(&buffer);
    }
}

/// The padding boundaries, explicitly. 252 is the last length that fits in one
/// block once the 4-byte prefix is counted; 508 is the same for two.
#[test]
fn padding_boundaries_round_trip() {
    let item_id = ItemId::from_bytes([0x31; 16]);
    for len in [
        0, 1, 3, 4, 251, 252, 253, 255, 256, 257, 507, 508, 509, 512, 1020, 8192,
    ] {
        let payload: Vec<u8> = (0..len)
            .map(|index| u8::try_from(index % 251).unwrap_or(0))
            .collect();
        round_trip(&payload, &item_id);
    }
}
