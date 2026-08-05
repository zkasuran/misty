// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Registers that need no clock because the value *is* the order.
//!
//! Some fields carry their own ordering, and attaching an [`Hlc`](crate::Hlc) to
//! them would be worse than useless — it would be wrong. A HOTP counter is the
//! obvious case: SPEC §4 makes it max-wins because a lower counter replays a code
//! the issuer has already consumed. `last_used_at` is the same shape for a less
//! dramatic reason: if device A generates a code at 12:00 while offline and
//! device B generates one at 11:00 but syncs first, last-writer-wins would report
//! 11:00, which is simply false.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::crdt::Merge;
use crate::error::Result;

macro_rules! extremum {
    ($(#[$doc:meta])* $name:ident, $keep:ident, $op:tt) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name<T>(T);

        impl<T: Ord + Copy> $name<T> {
            /// A register holding `value`.
            #[must_use]
            pub const fn new(value: T) -> Self {
                Self(value)
            }

            /// The current value.
            #[must_use]
            pub const fn get(&self) -> T {
                self.0
            }

            /// Records a local write. Returns whether anything changed.
            ///
            /// A write in the losing direction is dropped rather than applied:
            /// the whole point of this register is that the value cannot move
            /// that way.
            pub fn set(&mut self, value: T) -> bool {
                if value $op self.0 {
                    self.0 = value;
                    true
                } else {
                    false
                }
            }
        }

        impl<T: Ord + Copy> Merge for $name<T> {
            fn merge(&mut self, other: &Self, _field: &'static str) -> Result<()> {
                self.0 = self.0.$keep(other.0);
                Ok(())
            }
        }

        impl<T: fmt::Debug> fmt::Debug for $name<T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }
    };
}

extremum!(
    /// A register that only ever increases.
    ///
    /// SPEC §4 uses this for `otp.counter` (HOTP) and, by the argument in the
    /// [`crdt` module docs](crate::crdt), for `last_used_at`.
    MaxWins,
    max,
    >
);

extremum!(
    /// A register that only ever decreases.
    ///
    /// Used for `created_at`. Two devices should never disagree about when an
    /// item was created, but if they do, the earlier claim is the one that can
    /// actually be true, and "earliest wins" is a join, so it converges.
    MinWins,
    min,
    <
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hotp_counter_never_regresses() {
        let mut counter = MaxWins::new(42u64);
        assert!(!counter.set(41));
        assert!(!counter.set(42));
        assert_eq!(counter.get(), 42);
        assert!(counter.set(43));
        assert_eq!(counter.get(), 43);
    }

    #[test]
    fn max_wins_merges_in_either_order() {
        let low = MaxWins::new(3u64);
        let high = MaxWins::new(9u64);
        let mut a = low;
        a.merge(&high, "otp.counter").unwrap();
        let mut b = high;
        b.merge(&low, "otp.counter").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.get(), 9);
    }

    #[test]
    fn min_wins_merges_in_either_order() {
        let early = MinWins::new(100i64);
        let late = MinWins::new(200i64);
        let mut a = early;
        a.merge(&late, "created_at").unwrap();
        let mut b = late;
        b.merge(&early, "created_at").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.get(), 100);
    }

    #[test]
    fn option_orders_absence_below_any_value() {
        // `None < Some(_)`, so max-wins over `Option` promotes "used at some
        // point" over "never used" without a special case.
        let mut never = MaxWins::new(None::<i64>);
        never.merge(&MaxWins::new(Some(5)), "last_used_at").unwrap();
        assert_eq!(never.get(), Some(5));
    }

    #[test]
    fn transparent_serialisation_adds_no_wrapper() {
        let mut buf = Vec::new();
        ciborium::into_writer(&MaxWins::new(7u64), &mut buf).unwrap();
        assert_eq!(buf, vec![0x07]);
    }
}
