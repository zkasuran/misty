// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Time sources.
//!
//! The engine never reads the system clock on its own and never writes it
//! (SPEC 6.5). It is handed a [`Clock`], and clock *correction* is expressed as
//! an offset applied by [`SkewedClock`] rather than by touching the host clock.
//!
//! ```
//! use misty_otp::{Clock, FixedClock};
//!
//! // Server said the real time is 4 seconds ahead of ours.
//! let device = FixedClock::new(1_000_000_000_000);
//! let corrected = FixedClock::new(1_000_000_000_000).with_skew_ms(4_000);
//! assert_eq!(device.now_unix_ms(), 1_000_000_000_000);
//! assert_eq!(corrected.now_unix_ms(), 1_000_000_004_000);
//! ```

use core::sync::atomic::{AtomicU64, Ordering};

/// A source of Unix time in milliseconds.
///
/// Implement this to feed the engine a clock it can trust: on `wasm32` that is
/// `Date.now()` from the host, on native it is [`SystemClock`], and in tests it
/// is [`FixedClock`].
pub trait Clock {
    /// Milliseconds since the Unix epoch, ignoring leap seconds.
    fn now_unix_ms(&self) -> u64;

    /// Wrap this clock so every reading is shifted by `offset_ms`.
    ///
    /// `offset_ms` is `true_time - local_time`, the sign convention SPEC 6.5
    /// stores after comparing against a signed `/v1/time` response: positive
    /// means the device is running slow.
    #[must_use]
    fn with_skew_ms(self, offset_ms: i64) -> SkewedClock<Self>
    where
        Self: Sized,
    {
        SkewedClock::new(self, offset_ms)
    }
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now_unix_ms(&self) -> u64 {
        (**self).now_unix_ms()
    }
}

/// The host clock.
///
/// Absent on `wasm32-unknown-unknown`, where `std::time::SystemTime::now()`
/// panics: a browser build must pass in a clock backed by `Date.now()`. Making
/// that a compile error rather than a runtime panic is deliberate (SPEC 10.8).
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemClock;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Clock for SystemClock {
    /// Saturates rather than panicking if the host clock is set before 1970 or
    /// implausibly far in the future.
    fn now_unix_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// A clock that reports whatever it was told, for tests and for replaying
/// vectors at a fixed instant.
///
/// Interior mutability so it can be shared behind `&` the way a real clock is.
#[derive(Debug, Default)]
pub struct FixedClock(AtomicU64);

impl FixedClock {
    /// A clock frozen at `unix_ms`.
    #[must_use]
    pub fn new(unix_ms: u64) -> Self {
        Self(AtomicU64::new(unix_ms))
    }

    /// Jump to `unix_ms`.
    pub fn set(&self, unix_ms: u64) {
        self.0.store(unix_ms, Ordering::Relaxed);
    }

    /// Move forward by `delta_ms`, saturating at [`u64::MAX`].
    pub fn advance(&self, delta_ms: u64) {
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |now| {
                Some(now.saturating_add(delta_ms))
            });
    }
}

impl Clock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Clone for FixedClock {
    fn clone(&self) -> Self {
        Self::new(self.now_unix_ms())
    }
}

/// A clock with a signed millisecond correction applied to every reading.
///
/// This is how Misty honours a measured server offset without ever mutating the
/// host clock (SPEC 6.5). Readings saturate at the ends of the `u64` range
/// instead of wrapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkewedClock<C> {
    inner: C,
    offset_ms: i64,
}

impl<C: Clock> SkewedClock<C> {
    /// Wrap `inner`, shifting every reading by `offset_ms`
    /// (`true_time - local_time`).
    #[must_use]
    pub fn new(inner: C, offset_ms: i64) -> Self {
        Self { inner, offset_ms }
    }

    /// The correction being applied, in milliseconds.
    #[must_use]
    pub fn offset_ms(&self) -> i64 {
        self.offset_ms
    }

    /// Replace the correction, e.g. after a fresh `/v1/time` measurement.
    pub fn set_offset_ms(&mut self, offset_ms: i64) {
        self.offset_ms = offset_ms;
    }

    /// The wrapped clock.
    #[must_use]
    pub fn inner(&self) -> &C {
        &self.inner
    }

    /// Whether the correction exceeds the SPEC 6.5 warning threshold of 10
    /// seconds, at which point the UI must tell the user their clock is wrong.
    #[must_use]
    pub fn exceeds_warning_threshold(&self) -> bool {
        self.offset_ms.saturating_abs() > 10_000
    }
}

impl<C: Clock> Clock for SkewedClock<C> {
    fn now_unix_ms(&self) -> u64 {
        self.inner
            .now_unix_ms()
            .saturating_add_signed(self.offset_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_moves_only_when_told() {
        let clock = FixedClock::new(1_000);
        assert_eq!(clock.now_unix_ms(), 1_000);
        clock.advance(500);
        assert_eq!(clock.now_unix_ms(), 1_500);
        clock.set(7);
        assert_eq!(clock.now_unix_ms(), 7);
        clock.advance(u64::MAX);
        assert_eq!(clock.now_unix_ms(), u64::MAX);
    }

    #[test]
    fn skew_applies_in_both_directions_and_saturates() {
        let base = 1_700_000_000_000;
        assert_eq!(
            FixedClock::new(base).with_skew_ms(-1_500).now_unix_ms(),
            base - 1_500
        );
        assert_eq!(
            FixedClock::new(base).with_skew_ms(1_500).now_unix_ms(),
            base + 1_500
        );
        assert_eq!(FixedClock::new(10).with_skew_ms(-1_000).now_unix_ms(), 0);
        assert_eq!(
            FixedClock::new(u64::MAX - 1)
                .with_skew_ms(1_000)
                .now_unix_ms(),
            u64::MAX
        );
    }

    #[test]
    fn warning_threshold_matches_spec() {
        let clock = FixedClock::new(0);
        assert!(!clock
            .clone()
            .with_skew_ms(10_000)
            .exceeds_warning_threshold());
        assert!(clock
            .clone()
            .with_skew_ms(10_001)
            .exceeds_warning_threshold());
        assert!(clock.with_skew_ms(-10_001).exceeds_warning_threshold());
    }

    #[test]
    fn borrowed_clocks_are_clocks() {
        let clock = FixedClock::new(42);
        let borrowed: &dyn Clock = &clock;
        assert_eq!(borrowed.now_unix_ms(), 42);
        fn takes_clock<C: Clock>(clock: C) -> u64 {
            clock.now_unix_ms()
        }
        assert_eq!(takes_clock(&clock), 42);
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn system_clock_is_plausible() {
        // After 2024-01-01 and before 2100.
        let now = SystemClock.now_unix_ms();
        assert!(now > 1_704_067_200_000, "{now}");
        assert!(now < 4_102_444_800_000, "{now}");
    }
}
