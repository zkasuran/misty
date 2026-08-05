// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deletion, and why it is a value rather than an absence.

use serde::{Deserialize, Serialize};

use crate::hlc::Hlc;

/// Why an object was deleted. Not load-bearing for merge; it exists so the UI can
/// say "this was removed because it sat in the trash for 30 days" instead of
/// leaving the user to guess.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TombstoneReason {
    /// The user deleted it outright, skipping the trash.
    User,
    /// The trash retention window expired (SPEC §4: 30 days).
    TrashExpired,
}

/// A record that an object was deleted, and when.
///
/// # A delete is never an absence
///
/// Removing the row would make the delete un-mergeable: any peer still holding
/// the item would re-introduce it on the next sync, forever. So a delete is a
/// value with a clock, and it merges like everything else.
///
/// # A delete does not automatically win
///
/// SPEC §4: the tombstone wins **only if its clock is greater than every field
/// edit**. Resurrection-by-edit is worse than a stale delete, but a delete must
/// not beat a *later* edit — a user who deletes an item on their phone and then
/// renames it on their laptop meant to keep it.
///
/// That comparison is a *derived predicate*
/// ([`Item::is_deleted`](crate::Item::is_deleted)), evaluated fresh from the
/// merged state, never a flag written during merge. Writing a flag would mean
/// throwing away either the tombstone or the edit that beat it, and then the next
/// peer to sync would resurrect the loser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// When the delete was written, and by which device.
    pub hlc: Hlc,
    /// Why.
    pub reason: TombstoneReason,
}

impl Tombstone {
    /// A tombstone written at `hlc`.
    #[must_use]
    pub const fn new(hlc: Hlc, reason: TombstoneReason) -> Self {
        Self { hlc, reason }
    }

    /// Whether this tombstone is old enough to purge, given the current time and
    /// a retention window in milliseconds.
    ///
    /// Uses the tombstone's own `wall_ms`, which is bounded to
    /// `[MIN_WALL_MS, MAX_WALL_MS)` by the decoder — so the subtraction cannot
    /// underflow, and a tombstone dated in the future is simply not yet
    /// purgeable rather than instantly purgeable.
    #[must_use]
    pub fn is_purgeable(&self, now_ms: u64, retention_ms: u64) -> bool {
        now_ms.saturating_sub(self.hlc.wall_ms) >= retention_ms
    }
}

/// Merges two tombstones, keeping the later one.
///
/// Not an implementation of [`Merge`](crate::crdt::Merge) because the field is an
/// `Option` on both sides and "one side has none" is the common case.
pub(crate) fn merge_tombstone(local: &mut Option<Tombstone>, remote: &Option<Tombstone>) {
    match (*local, *remote) {
        (Some(mine), Some(theirs)) if theirs.hlc > mine.hlc => *local = Some(theirs),
        (None, Some(theirs)) => *local = Some(theirs),
        _ => {}
    }
}

/// Whether a tombstone beats the highest field-edit clock beside it.
pub(crate) fn tombstone_wins(tombstone: Option<&Tombstone>, max_field_hlc: Hlc) -> bool {
    tombstone.is_some_and(|stone| stone.hlc > max_field_hlc)
}

/// Type-checks that the reason survives a round trip; called from tests only.
#[cfg(test)]
fn round_trip(reason: TombstoneReason) -> TombstoneReason {
    let mut buf = Vec::new();
    ciborium::into_writer(&reason, &mut buf).unwrap();
    ciborium::from_reader(buf.as_slice()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use misty_crypto::DeviceId;

    const DEV_A: DeviceId = DeviceId::from_bytes([0xaa; 16]);
    const DEV_B: DeviceId = DeviceId::from_bytes([0xbb; 16]);
    const NOW: u64 = 1_800_000_000_000;

    fn stone(wall: u64, device: DeviceId) -> Tombstone {
        Tombstone::new(Hlc::new(wall, 0, device).unwrap(), TombstoneReason::User)
    }

    #[test]
    fn the_later_tombstone_wins_in_either_order() {
        let early = stone(NOW, DEV_A);
        let late = stone(NOW + 1, DEV_B);
        let mut a = Some(early);
        merge_tombstone(&mut a, &Some(late));
        let mut b = Some(late);
        merge_tombstone(&mut b, &Some(early));
        assert_eq!(a, b);
        assert_eq!(a, Some(late));
    }

    #[test]
    fn a_tombstone_arriving_from_one_side_is_adopted() {
        let mut none = None;
        merge_tombstone(&mut none, &Some(stone(NOW, DEV_A)));
        assert_eq!(none, Some(stone(NOW, DEV_A)));

        let mut mine = Some(stone(NOW, DEV_A));
        merge_tombstone(&mut mine, &None);
        assert_eq!(mine, Some(stone(NOW, DEV_A)));
    }

    #[test]
    fn a_tombstone_only_wins_against_earlier_edits() {
        let deleted_at = stone(NOW, DEV_A);
        let earlier_edit = Hlc::new(NOW - 1, 0, DEV_B).unwrap();
        let later_edit = Hlc::new(NOW + 1, 0, DEV_B).unwrap();
        assert!(tombstone_wins(Some(&deleted_at), earlier_edit));
        assert!(!tombstone_wins(Some(&deleted_at), later_edit));
        // Equal clocks cannot happen across devices, but the tie must still
        // resolve one way: the edit keeps the item.
        assert!(!tombstone_wins(Some(&deleted_at), deleted_at.hlc));
        assert!(!tombstone_wins(None, earlier_edit));
    }

    #[test]
    fn purge_uses_the_tombstones_own_clock_and_cannot_underflow() {
        let deleted_at = stone(NOW, DEV_A);
        let ninety_days = 90 * 24 * 60 * 60 * 1000;
        assert!(!deleted_at.is_purgeable(NOW, ninety_days));
        assert!(!deleted_at.is_purgeable(NOW + ninety_days - 1, ninety_days));
        assert!(deleted_at.is_purgeable(NOW + ninety_days, ninety_days));
        // A tombstone dated after "now": not purgeable, and no underflow.
        assert!(!deleted_at.is_purgeable(0, ninety_days));
        assert!(!deleted_at.is_purgeable(NOW - 1, ninety_days));
    }

    #[test]
    fn reasons_round_trip_as_short_strings() {
        for reason in [TombstoneReason::User, TombstoneReason::TrashExpired] {
            assert_eq!(round_trip(reason), reason);
        }
    }
}
