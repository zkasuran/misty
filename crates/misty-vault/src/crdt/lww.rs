// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Last-writer-wins register, the merge rule for plain user-edited fields.

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crdt::Merge;
use crate::error::{Result, VaultError};
use crate::hlc::Hlc;

/// A value together with the [`Hlc`] of the write that produced it.
///
/// SPEC §4 gives this rule to `issuer`, `account`, `nickname`, `note`, `icon`,
/// `color`, `favorite`, `archived`, `hidden`, `requires_reveal_auth`,
/// `manual_order`, `algorithm`, `digits` and `period` — every field where the
/// user's most recent intent is simply the right answer.
///
/// # Equal clocks with different values are an error, not a coin flip
///
/// An [`Hlc`] names a device, a millisecond and a per-millisecond counter, and
/// [`HlcClock`](crate::HlcClock) never issues the same triple twice. So two
/// differing values under one clock cannot arise from writes this crate made,
/// and it cannot arise from a forged envelope either — envelopes are Ed25519
/// signed by a rostered device (SPEC §2.4). It could only come from a writer
/// that reused a clock.
///
/// Resolving it by keeping `self` would make merge non-commutative, which is
/// exactly the property the whole crate rests on, and would hide the writer bug
/// that caused it. So it is reported as
/// [`VaultError::ClockCollision`](crate::VaultError::ClockCollision).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Lww<T> {
    value: T,
    hlc: Hlc,
}

impl<T: Serialize> Serialize for Lww<T> {
    /// A two-element CBOR array, not a map.
    ///
    /// An item carries a dozen of these; spelling `"value"` and `"hlc"` in each
    /// one would add roughly 150 bytes to every payload for no information.
    fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        (&self.value, &self.hlc).serialize(s)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Lww<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        let (value, hlc) = <(T, Hlc)>::deserialize(d)?;
        Ok(Self { value, hlc })
    }
}

impl<T> Lww<T> {
    /// A register holding `value`, written at `hlc`.
    #[must_use]
    pub const fn new(value: T, hlc: Hlc) -> Self {
        Self { value, hlc }
    }

    /// The current value.
    #[must_use]
    pub const fn get(&self) -> &T {
        &self.value
    }

    /// The clock of the write that produced the current value.
    #[must_use]
    pub const fn hlc(&self) -> Hlc {
        self.hlc
    }

    /// Consumes the register and returns its value.
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    /// Mutable access to the value without touching the clock.
    ///
    /// Only for zeroizing a secret out of a transient wire struct: mutating a
    /// value without advancing its clock would produce a register that loses its
    /// next merge for no reason, which is why this is not public.
    pub(crate) fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Records a local write.
    ///
    /// Ignored if `hlc` is not greater than the clock already stored, which is
    /// unreachable for readings from this device's own
    /// [`HlcClock`](crate::HlcClock) but is worth being total about. Returns
    /// whether the write took effect.
    pub fn set(&mut self, value: T, hlc: Hlc) -> bool {
        if hlc > self.hlc {
            self.value = value;
            self.hlc = hlc;
            true
        } else {
            false
        }
    }
}

impl<T: Clone + PartialEq> Merge for Lww<T> {
    fn merge(&mut self, other: &Self, field: &'static str) -> Result<()> {
        match other.hlc.cmp(&self.hlc) {
            core::cmp::Ordering::Greater => {
                self.value = other.value.clone();
                self.hlc = other.hlc;
                Ok(())
            }
            core::cmp::Ordering::Less => Ok(()),
            core::cmp::Ordering::Equal => {
                if self.value == other.value {
                    Ok(())
                } else {
                    Err(VaultError::ClockCollision { field })
                }
            }
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Lww<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}@{}", self.value, self.hlc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misty_crypto::DeviceId;

    const DEV_A: DeviceId = DeviceId::from_bytes([0xaa; 16]);
    const DEV_B: DeviceId = DeviceId::from_bytes([0xbb; 16]);
    const NOW: u64 = 1_800_000_000_000;

    fn hlc(wall: u64, device: DeviceId) -> Hlc {
        Hlc::new(wall, 0, device).unwrap()
    }

    #[test]
    fn the_greater_clock_wins_in_either_order() {
        let early = Lww::new("old", hlc(NOW, DEV_A));
        let late = Lww::new("new", hlc(NOW + 1, DEV_B));

        let mut a = early;
        a.merge(&late, "f").unwrap();
        let mut b = late;
        b.merge(&early, "f").unwrap();

        assert_eq!(*a.get(), "new");
        assert_eq!(a, b);
    }

    #[test]
    fn the_device_id_is_the_final_tiebreak() {
        let from_a = Lww::new("a", hlc(NOW, DEV_A));
        let from_b = Lww::new("b", hlc(NOW, DEV_B));
        let mut merged = from_a;
        merged.merge(&from_b, "f").unwrap();
        // DEV_B > DEV_A bytewise, so B wins — and both devices agree without
        // exchanging anything but the two values.
        assert_eq!(*merged.get(), "b");
    }

    #[test]
    fn a_stale_local_write_is_ignored() {
        let mut reg = Lww::new(1, hlc(NOW, DEV_A));
        assert!(!reg.set(2, hlc(NOW - 1, DEV_A)));
        assert!(!reg.set(3, hlc(NOW, DEV_A)));
        assert_eq!(*reg.get(), 1);
        assert!(reg.set(4, hlc(NOW + 1, DEV_A)));
        assert_eq!(*reg.get(), 4);
    }

    #[test]
    fn identical_clocks_with_different_values_are_reported() {
        let mut a = Lww::new("x", hlc(NOW, DEV_A));
        let b = Lww::new("y", hlc(NOW, DEV_A));
        assert!(matches!(
            a.merge(&b, "issuer"),
            Err(VaultError::ClockCollision { field: "issuer" })
        ));
        // The same clock with the same value is just the same write twice.
        let mut c = Lww::new("x", hlc(NOW, DEV_A));
        assert!(c.merge(&Lww::new("x", hlc(NOW, DEV_A)), "issuer").is_ok());
    }

    #[test]
    fn debug_shows_the_clock_next_to_the_value() {
        let reg = Lww::new(7u8, hlc(NOW, DEV_A));
        assert!(format!("{reg:?}").starts_with("7@1800000000000.0@"));
    }
}
