// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The hybrid logical clock every mutable field carries (SPEC §4).
//!
//! ```text
//! Hlc { wall_ms: u64, counter: u16, device_id: [u8; 16] }   // Ord = lexicographic
//! ```
//!
//! `wall_ms` orders writes the way a human would expect, `counter` orders writes
//! within one millisecond, and `device_id` is the final deterministic tiebreak so
//! that every device picks the same winner without talking to any other device.
//!
//! # A clock that goes backwards MUST NOT produce a regressing `Hlc`
//!
//! An NTP correction, a timezone-confused RTC or a user setting the date by hand
//! all move the wall clock backwards, and a regressing clock would let an *older*
//! edit beat a newer one — silent data loss that no error surfaces. So
//! [`HlcClock::tick`] never emits a value below the last one it emitted: if the
//! wall clock has not advanced, the counter does, and if the counter saturates,
//! `wall_ms` is advanced by one millisecond instead.
//!
//! # The wall clock is bounded, and the bounds are absolute
//!
//! A decoder rejects `wall_ms` outside `[MIN_WALL_MS, MAX_WALL_MS)`. The bounds
//! are fixed constants rather than "now ± skew" on purpose: a merge whose
//! outcome depended on the reader's own clock would not converge, because two
//! devices reading the same pair of writes at different moments would disagree
//! about which one to keep. Fixed bounds keep validation deterministic while
//! still refusing a 1970 clock (a device whose RTC never got set) and a year-2200
//! one (a write engineered to win every future comparison).
//!
//! The write path *clamps* into the window rather than failing, so a device with
//! a broken clock still records its edits — they simply sort low — while the read
//! path rejects, so a corrupt or hostile payload never enters the model.

use core::fmt;

use misty_crypto::DeviceId;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Result, VaultError};

/// Wire length of an [`Hlc`]: 8 bytes of `wall_ms`, 2 of `counter`, 16 of
/// `device_id`.
pub const HLC_LEN: usize = 26;

/// Inclusive lower bound on `wall_ms`: 2020-01-01T00:00:00Z.
///
/// Misty did not exist before 2026; the extra slack is for a device whose clock
/// is merely wrong rather than unset.
pub const MIN_WALL_MS: u64 = 1_577_836_800_000;

/// Exclusive upper bound on `wall_ms`: 2100-01-01T00:00:00Z.
pub const MAX_WALL_MS: u64 = 4_102_444_800_000;

/// A hybrid logical clock reading (SPEC §4).
///
/// Ordering is lexicographic over `(wall_ms, counter, device_id)`, which is what
/// the derived [`Ord`] gives. Do not reorder the fields.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hlc {
    /// Unix milliseconds, as read from the writing device's clock and clamped
    /// into `[MIN_WALL_MS, MAX_WALL_MS)`.
    pub wall_ms: u64,
    /// Distinguishes writes made by one device within one millisecond.
    pub counter: u16,
    /// The writing device. The final, deterministic tiebreak.
    pub device_id: DeviceId,
}

impl Hlc {
    /// Builds a reading, checking the `wall_ms` window.
    ///
    /// # Errors
    ///
    /// [`VaultError::HlcOutOfRange`] if `wall_ms` is outside
    /// `[MIN_WALL_MS, MAX_WALL_MS)`.
    pub fn new(wall_ms: u64, counter: u16, device_id: DeviceId) -> Result<Self> {
        if !(MIN_WALL_MS..MAX_WALL_MS).contains(&wall_ms) {
            return Err(VaultError::HlcOutOfRange {
                wall_ms,
                min: MIN_WALL_MS,
                max: MAX_WALL_MS,
            });
        }
        Ok(Self {
            wall_ms,
            counter,
            device_id,
        })
    }

    /// The lowest reading a device can produce: the bottom of the window.
    #[must_use]
    pub const fn zero(device_id: DeviceId) -> Self {
        Self {
            wall_ms: MIN_WALL_MS,
            counter: 0,
            device_id,
        }
    }

    /// The 26 wire bytes, big-endian, so that **byte order equals [`Ord`]**.
    ///
    /// That equality is what lets the SQLite backend store `hlc_max` as a `BLOB`
    /// and still get a correct `MAX()` or `ORDER BY` out of SQLite's own
    /// memcmp-based comparison, without teaching the database anything about the
    /// vault.
    #[must_use]
    pub fn to_sort_bytes(&self) -> [u8; HLC_LEN] {
        let mut out = [0u8; HLC_LEN];
        let (wall, rest) = out.split_at_mut(8);
        wall.copy_from_slice(&self.wall_ms.to_be_bytes());
        let (counter, device) = rest.split_at_mut(2);
        counter.copy_from_slice(&self.counter.to_be_bytes());
        device.copy_from_slice(self.device_id.as_bytes());
        out
    }

    /// Reads the 26 wire bytes, checking the `wall_ms` window.
    ///
    /// # Errors
    ///
    /// As [`Hlc::new`].
    pub fn from_sort_bytes(bytes: &[u8; HLC_LEN]) -> Result<Self> {
        let mut wall = [0u8; 8];
        let mut counter = [0u8; 2];
        let mut device = [0u8; 16];
        // Split rather than index: this runs on decoded payloads.
        let (wall_src, rest) = bytes.split_at(8);
        let (counter_src, device_src) = rest.split_at(2);
        wall.copy_from_slice(wall_src);
        counter.copy_from_slice(counter_src);
        device.copy_from_slice(device_src);
        Self::new(
            u64::from_be_bytes(wall),
            u16::from_be_bytes(counter),
            DeviceId::from_bytes(device),
        )
    }

    /// Reads the 26 wire bytes from a slice of unknown length.
    ///
    /// # Errors
    ///
    /// [`VaultError::Storage`] if the slice is not exactly [`HLC_LEN`] bytes,
    /// plus anything [`Hlc::from_sort_bytes`] rejects.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: &[u8; HLC_LEN] = bytes.try_into().map_err(|_| VaultError::Storage {
            detail: format!("hlc_max is {} bytes, expected {HLC_LEN}", bytes.len()),
        })?;
        Self::from_sort_bytes(array)
    }
}

impl fmt::Debug for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hlc({}.{}@{})",
            self.wall_ms, self.counter, self.device_id
        )
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}@{}", self.wall_ms, self.counter, self.device_id)
    }
}

impl Serialize for Hlc {
    /// One 26-byte CBOR byte string, not a three-field map.
    ///
    /// Every mutable field on every item carries one of these, so the difference
    /// between 28 bytes and roughly 60 decides whether a typical item needs one
    /// 256-byte padding bucket or two.
    fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.to_sort_bytes())
    }
}

impl<'de> Deserialize<'de> for Hlc {
    /// Checks the length here and **not** the window: a `wall_ms` out of range is
    /// a policy failure, not a structural one, and it is checked by
    /// [`Item::validate`](crate::model::Item::validate) so that it surfaces as
    /// [`VaultError::HlcOutOfRange`] naming the value rather than as an opaque CBOR
    /// error naming a byte offset.
    fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Hlc;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a {HLC_LEN}-byte hybrid logical clock")
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> core::result::Result<Hlc, E> {
                let bytes: &[u8; HLC_LEN] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &self))?;
                let (wall_src, rest) = bytes.split_at(8);
                let (counter_src, device_src) = rest.split_at(2);
                let mut wall = [0u8; 8];
                let mut counter = [0u8; 2];
                let mut device = [0u8; 16];
                wall.copy_from_slice(wall_src);
                counter.copy_from_slice(counter_src);
                device.copy_from_slice(device_src);
                Ok(Hlc {
                    wall_ms: u64::from_be_bytes(wall),
                    counter: u16::from_be_bytes(counter),
                    device_id: DeviceId::from_bytes(device),
                })
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> core::result::Result<Hlc, A::Error> {
                let mut out = [0u8; HLC_LEN];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                self.visit_bytes(&out)
            }
        }
        d.deserialize_bytes(V)
    }
}

/// The clock one device stamps its own writes with.
///
/// Holds the last reading it issued, so it can guarantee monotonicity even when
/// the host clock is not. Also folds in every remote reading it is shown
/// ([`observe`](Self::observe)), which is what makes a local edit made after
/// receiving a remote edit sort *after* it — without that, a device whose clock
/// runs slow could never win a merge.
#[derive(Debug, Clone)]
pub struct HlcClock {
    device_id: DeviceId,
    last: Hlc,
}

impl HlcClock {
    /// A clock for `device_id`, starting at the bottom of the window.
    #[must_use]
    pub const fn new(device_id: DeviceId) -> Self {
        Self {
            device_id,
            last: Hlc::zero(device_id),
        }
    }

    /// A clock for `device_id` that has already issued or seen `last`.
    ///
    /// Used when reopening a vault: the highest [`Hlc`] in storage is folded in
    /// so a restart cannot re-issue a reading that already ordered a write.
    #[must_use]
    pub fn resumed(device_id: DeviceId, last: Hlc) -> Self {
        let mut clock = Self::new(device_id);
        clock.observe(&last);
        clock
    }

    /// Which device this clock stamps writes for.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The most recent reading issued or observed.
    #[must_use]
    pub const fn last(&self) -> Hlc {
        self.last
    }

    /// Issues the next reading, given the host clock's current value.
    ///
    /// Guaranteed to be strictly greater than every reading this clock has
    /// issued or observed, whatever `wall_ms` does. `wall_ms` is clamped into
    /// `[MIN_WALL_MS, MAX_WALL_MS)` rather than rejected, so a device with a
    /// broken clock still records its edits.
    ///
    /// # Errors
    ///
    /// [`VaultError::ClockExhausted`] if the clock is at the top of the window
    /// with a saturated counter — the year-2100 case, and unreachable before
    /// then.
    pub fn tick(&mut self, wall_ms: u64) -> Result<Hlc> {
        let wall = wall_ms.clamp(MIN_WALL_MS, MAX_WALL_MS - 1);
        let next = if wall > self.last.wall_ms {
            Hlc {
                wall_ms: wall,
                counter: 0,
                device_id: self.device_id,
            }
        } else {
            // The host clock did not advance, or it went backwards. Either way
            // the reading must still increase, so the counter carries the order.
            match self.last.counter.checked_add(1) {
                Some(counter) => Hlc {
                    wall_ms: self.last.wall_ms,
                    counter,
                    device_id: self.device_id,
                },
                // 65 536 writes in one millisecond. Borrow a millisecond from
                // the future rather than wrapping the counter, which would let
                // an older reading compare greater.
                None => Hlc::new(self.last.wall_ms.saturating_add(1), 0, self.device_id)
                    .map_err(|_| VaultError::ClockExhausted)?,
            }
        };
        self.last = next;
        Ok(next)
    }

    /// Folds a reading seen from another device into this clock.
    ///
    /// Out-of-window readings are ignored: the decoder rejects them before they
    /// reach the model, and a value the model will never contain must not be
    /// allowed to drag the local clock. `device_id` is deliberately not adopted —
    /// this clock only ever stamps its own device.
    pub fn observe(&mut self, remote: &Hlc) {
        if !(MIN_WALL_MS..MAX_WALL_MS).contains(&remote.wall_ms) {
            return;
        }
        if (remote.wall_ms, remote.counter) > (self.last.wall_ms, self.last.counter) {
            self.last = Hlc {
                wall_ms: remote.wall_ms,
                counter: remote.counter,
                device_id: self.device_id,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV_A: DeviceId = DeviceId::from_bytes([0xaa; 16]);
    const DEV_B: DeviceId = DeviceId::from_bytes([0xbb; 16]);
    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn ordering_is_lexicographic_over_wall_counter_device() {
        let base = Hlc::new(NOW, 0, DEV_A).unwrap();
        assert!(Hlc::new(NOW + 1, 0, DEV_A).unwrap() > base);
        assert!(Hlc::new(NOW, 1, DEV_A).unwrap() > base);
        assert!(Hlc::new(NOW, 0, DEV_B).unwrap() > base);
        // wall_ms dominates the counter, which dominates the device.
        assert!(Hlc::new(NOW + 1, 0, DEV_A).unwrap() > Hlc::new(NOW, u16::MAX, DEV_B).unwrap());
        assert!(Hlc::new(NOW, 1, DEV_A).unwrap() > Hlc::new(NOW, 0, DEV_B).unwrap());
    }

    #[test]
    fn sort_bytes_order_matches_ord() {
        let mut clocks = [
            Hlc::new(NOW, 0, DEV_B).unwrap(),
            Hlc::new(NOW, 0, DEV_A).unwrap(),
            Hlc::new(NOW + 5, 0, DEV_A).unwrap(),
            Hlc::new(NOW, 7, DEV_A).unwrap(),
        ];
        clocks.sort_unstable();
        let mut bytes: Vec<[u8; HLC_LEN]> = clocks.iter().map(Hlc::to_sort_bytes).collect();
        let expected = bytes.clone();
        bytes.sort_unstable();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn sort_bytes_round_trip() {
        let hlc = Hlc::new(NOW, 9, DEV_A).unwrap();
        assert_eq!(Hlc::from_sort_bytes(&hlc.to_sort_bytes()).unwrap(), hlc);
        assert!(Hlc::from_slice(&[0u8; HLC_LEN - 1]).is_err());
    }

    #[test]
    fn window_is_enforced_at_both_ends() {
        assert!(Hlc::new(MIN_WALL_MS, 0, DEV_A).is_ok());
        assert!(Hlc::new(MAX_WALL_MS - 1, 0, DEV_A).is_ok());
        for outside in [0, 1, MIN_WALL_MS - 1, MAX_WALL_MS, u64::MAX] {
            assert!(
                matches!(
                    Hlc::new(outside, 0, DEV_A),
                    Err(VaultError::HlcOutOfRange { .. })
                ),
                "{outside}"
            );
        }
    }

    #[test]
    fn a_clock_that_goes_backwards_still_advances() {
        let mut clock = HlcClock::new(DEV_A);
        let first = clock.tick(NOW).unwrap();
        // A 30-second NTP correction backwards, the classic case.
        let second = clock.tick(NOW - 30_000).unwrap();
        let third = clock.tick(0).unwrap();
        assert!(second > first, "{second:?} !> {first:?}");
        assert!(third > second, "{third:?} !> {second:?}");
        assert_eq!(second.wall_ms, first.wall_ms);
        assert_eq!(second.counter, 1);
        assert_eq!(third.counter, 2);
        // And it recovers as soon as the host clock passes the last reading.
        let fourth = clock.tick(NOW + 1).unwrap();
        assert_eq!((fourth.wall_ms, fourth.counter), (NOW + 1, 0));
    }

    #[test]
    fn same_millisecond_writes_increment_the_counter() {
        let mut clock = HlcClock::new(DEV_A);
        let readings: Vec<Hlc> = (0..5).map(|_| clock.tick(NOW).unwrap()).collect();
        for (i, hlc) in readings.iter().enumerate() {
            assert_eq!(hlc.wall_ms, NOW);
            assert_eq!(usize::from(hlc.counter), i);
        }
    }

    #[test]
    fn a_saturated_counter_borrows_a_millisecond_instead_of_wrapping() {
        let mut clock = HlcClock::resumed(DEV_A, Hlc::new(NOW, u16::MAX, DEV_B).unwrap());
        let next = clock.tick(NOW).unwrap();
        assert_eq!((next.wall_ms, next.counter), (NOW + 1, 0));
        assert!(next > Hlc::new(NOW, u16::MAX, DEV_B).unwrap());
    }

    #[test]
    fn the_clock_is_exhausted_only_at_the_top_of_the_window() {
        let mut clock =
            HlcClock::resumed(DEV_A, Hlc::new(MAX_WALL_MS - 1, u16::MAX, DEV_A).unwrap());
        assert!(matches!(
            clock.tick(MAX_WALL_MS - 1),
            Err(VaultError::ClockExhausted)
        ));
    }

    #[test]
    fn observing_a_remote_reading_makes_the_next_local_write_beat_it() {
        let mut clock = HlcClock::new(DEV_A);
        let remote = Hlc::new(NOW + 60_000, 4, DEV_B).unwrap();
        clock.observe(&remote);
        let next = clock.tick(NOW).unwrap();
        assert!(next > remote, "{next:?} !> {remote:?}");
        assert_eq!(next.device_id, DEV_A, "observe must not adopt a device id");
    }

    #[test]
    fn out_of_window_remote_readings_cannot_drag_the_local_clock() {
        let mut clock = HlcClock::new(DEV_A);
        let before = clock.last();
        // Constructed by hand: `Hlc::new` would refuse both of these, and so
        // does the decoder. This asserts the second line of defence.
        clock.observe(&Hlc {
            wall_ms: u64::MAX,
            counter: 0,
            device_id: DEV_B,
        });
        clock.observe(&Hlc {
            wall_ms: 0,
            counter: 0,
            device_id: DEV_B,
        });
        assert_eq!(clock.last(), before);
    }

    #[test]
    fn debug_and_display_carry_no_content() {
        let hlc = Hlc::new(NOW, 3, DEV_A).unwrap();
        assert_eq!(format!("{hlc}"), format!("{NOW}.3@{DEV_A}"));
        assert_eq!(format!("{hlc:?}"), format!("Hlc({NOW}.3@{DEV_A})"));
    }
}
