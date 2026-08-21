// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The injected monotonic host clock (SPEC §11.5.4).
//!
//! There is no usable `std::time` clock on `wasm32-unknown-unknown`, so the facade
//! never reads a clock directly for its auto-lock deadline — the host supplies one.
//! This is distinct from the OTP [`misty_otp::Clock`], which supplies wall-clock time
//! for code generation: a wall clock may jump, but the lock deadline must not.

use core::sync::atomic::{AtomicI64, Ordering};

extern crate alloc;
use alloc::sync::Arc;

/// A monotonic clock the host injects into the facade (SPEC §11.5.4).
///
/// The reading is in milliseconds from an arbitrary fixed epoch; only differences
/// are meaningful. Implementations MUST be monotonic in real elapsed wall time and
/// MUST keep advancing while the device is suspended, so a machine that wakes past
/// its auto-lock deadline is already locked rather than briefly serving a code. A
/// clock that pauses during suspend re-introduces exactly the failure §9.1 forbids.
pub trait HostClock {
    /// Milliseconds from an arbitrary fixed epoch. Monotonic; suspend-inclusive.
    fn now_ms(&self) -> i64;
}

/// A host clock the caller drives by hand.
///
/// This is the clock the conformance suite (SPEC §11.8) and unit tests use to make
/// the auto-lock deadline deterministic: time only moves when the test moves it. It
/// is cheap to clone and shares one backing value, so a test holds one handle while
/// the facade owns another.
#[derive(Clone, Debug, Default)]
pub struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    /// A clock reading `now_ms` until [`set`](Self::set) or [`advance`](Self::advance).
    #[must_use]
    pub fn new(now_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now_ms)))
    }

    /// Jump the clock to an absolute reading.
    pub fn set(&self, now_ms: i64) {
        self.0.store(now_ms, Ordering::Relaxed);
    }

    /// Move the clock forward (or, with a negative delta, backward — to exercise the
    /// §11.5.4 rewound-clock rule).
    pub fn advance(&self, delta_ms: i64) {
        self.0.fetch_add(delta_ms, Ordering::Relaxed);
    }
}

impl HostClock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// The default native host clock, backed by [`std::time::Instant`].
///
/// `Instant` is monotonic but, on some platforms, does not advance while the machine
/// is suspended — the residual risk §11.5.6 records. A shell that can read a
/// boot-time clock (`CLOCK_BOOTTIME`, `mach_continuous_time`) SHOULD supply its own
/// [`HostClock`] instead; this exists so the native desktop build and the tests have
/// a working default.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug)]
pub struct InstantClock {
    base: std::time::Instant,
}

#[cfg(not(target_arch = "wasm32"))]
impl InstantClock {
    /// A clock whose zero is the moment of construction.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: std::time::Instant::now(),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for InstantClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl HostClock for InstantClock {
    fn now_ms(&self) -> i64 {
        // Saturating so a pathological uptime cannot wrap into a past reading.
        i64::try_from(self.base.elapsed().as_millis()).unwrap_or(i64::MAX)
    }
}
