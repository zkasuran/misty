// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-device grow-only counter, the merge rule for `usage`.

use core::fmt;
use std::collections::BTreeMap;

use misty_crypto::DeviceId;

use crate::crdt::Merge;
use crate::error::Result;

/// How many times a token has been used, counted per device.
///
/// SPEC §4: merge is the per-key maximum, and a read is the sum. A single shared
/// integer under last-writer-wins would silently discard everything an offline
/// device counted, which is the one thing this field exists to avoid — usage is
/// what drives "most used" sorting and the "used 2m ago" hint that SPEC §3.1
/// relies on to tell two same-issuer accounts apart.
///
/// Only devices with a non-zero count are stored, so a device that has never
/// generated a code from this item costs nothing.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UsageCounter {
    per_device: BTreeMap<DeviceId, u64>,
}

impl UsageCounter {
    /// An unused item.
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_device: BTreeMap::new(),
        }
    }

    /// The total across every device.
    ///
    /// Saturating rather than wrapping: a count that wrapped to zero would make
    /// a heavily used item look untouched, and a saturated `u64` is already an
    /// impossible number of taps.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.per_device
            .values()
            .fold(0u64, |sum, count| sum.saturating_add(*count))
    }

    /// What one device has counted.
    #[must_use]
    pub fn for_device(&self, device: &DeviceId) -> u64 {
        self.per_device.get(device).copied().unwrap_or(0)
    }

    /// Every device with a non-zero count, in id order.
    pub fn iter(&self) -> impl Iterator<Item = (&DeviceId, u64)> {
        self.per_device
            .iter()
            .map(|(device, count)| (device, *count))
    }

    /// How many devices are named. The count the storage limit applies to.
    #[must_use]
    pub fn len(&self) -> usize {
        self.per_device.len()
    }

    /// Whether no device has used this item.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.per_device.is_empty()
    }

    /// Adds `by` to one device's count, saturating.
    pub fn increment(&mut self, device: DeviceId, by: u64) {
        if by == 0 {
            return;
        }
        let slot = self.per_device.entry(device).or_insert(0);
        *slot = slot.saturating_add(by);
    }

    /// Builds a counter from raw per-device counts, for the decoder.
    pub(crate) fn from_counts(per_device: BTreeMap<DeviceId, u64>) -> Self {
        Self { per_device }
    }
}

impl Merge for UsageCounter {
    /// Per-device maximum. Never a sum: merging twice would double-count.
    fn merge(&mut self, other: &Self, _field: &'static str) -> Result<()> {
        for (device, count) in &other.per_device {
            let slot = self.per_device.entry(*device).or_insert(0);
            *slot = (*slot).max(*count);
        }
        Ok(())
    }
}

impl fmt::Debug for UsageCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UsageCounter(total {})", self.total())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV_A: DeviceId = DeviceId::from_bytes([0xaa; 16]);
    const DEV_B: DeviceId = DeviceId::from_bytes([0xbb; 16]);
    const DEV_C: DeviceId = DeviceId::from_bytes([0xcc; 16]);

    #[test]
    fn three_offline_devices_sum_rather_than_overwrite() {
        let mut a = UsageCounter::new();
        let mut b = UsageCounter::new();
        let mut c = UsageCounter::new();
        for _ in 0..4 {
            a.increment(DEV_A, 1);
        }
        b.increment(DEV_B, 7);
        c.increment(DEV_C, 2);

        let mut merged = a.clone();
        merged.merge(&b, "usage").unwrap();
        merged.merge(&c, "usage").unwrap();
        assert_eq!(merged.total(), 13);

        // And in the other direction.
        let mut other = c;
        other.merge(&b, "usage").unwrap();
        other.merge(&a, "usage").unwrap();
        assert_eq!(other, merged);
    }

    #[test]
    fn merging_the_same_state_twice_does_not_double_count() {
        let mut a = UsageCounter::new();
        a.increment(DEV_A, 5);
        let snapshot = a.clone();
        a.merge(&snapshot, "usage").unwrap();
        a.merge(&snapshot, "usage").unwrap();
        assert_eq!(a.total(), 5);
    }

    #[test]
    fn a_lower_remote_count_never_lowers_a_local_one() {
        let mut local = UsageCounter::new();
        local.increment(DEV_A, 9);
        let mut stale = UsageCounter::new();
        stale.increment(DEV_A, 2);
        local.merge(&stale, "usage").unwrap();
        assert_eq!(local.for_device(&DEV_A), 9);
    }

    #[test]
    fn totals_saturate_instead_of_wrapping() {
        let mut counter = UsageCounter::new();
        counter.increment(DEV_A, u64::MAX);
        counter.increment(DEV_A, 10);
        counter.increment(DEV_B, 5);
        assert_eq!(counter.for_device(&DEV_A), u64::MAX);
        assert_eq!(counter.total(), u64::MAX);
    }

    #[test]
    fn a_zero_increment_does_not_create_a_device_entry() {
        let mut counter = UsageCounter::new();
        counter.increment(DEV_A, 0);
        assert!(counter.is_empty());
        assert_eq!(counter.len(), 0);
    }

    #[test]
    fn debug_reports_the_total_and_not_the_roster() {
        let mut counter = UsageCounter::new();
        counter.increment(DEV_A, 3);
        assert_eq!(format!("{counter:?}"), "UsageCounter(total 3)");
    }
}
