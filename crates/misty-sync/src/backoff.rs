// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Retry pacing, and the clock that implements the waiting.
//!
//! Two separate things, deliberately:
//!
//! * [`Backoff`] decides *how long*. [`Backoff::delay_ms`] is a pure function of
//!   the attempt number and one `u64` of entropy, so the whole schedule —
//!   including the jitter — is testable without waiting for anything.
//! * [`Sleeper`] does the waiting. `wasm32-unknown-unknown` has no timer in
//!   `std`, and a test that actually slept for the schedule below would take
//!   half a minute, so the wait is behind a trait like the transport is.

use crate::error::Result;

/// How much randomness to mix into a retry delay.
///
/// Jitter exists so that many clients failing at once do not retry in lockstep.
/// For a personal authenticator the herd is small, but the cost of jitter is
/// nothing and the cost of a synchronised retry storm against a small server is
/// an outage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Jitter {
    /// No randomness. For tests that want a fixed schedule.
    None,
    /// Uniform over `0..=ceiling`.
    ///
    /// Spreads the herd best, and can return zero — which retries immediately
    /// against a server that has just failed. That is why it is not the default.
    Full,
    /// Uniform over `ceiling / 2 ..= ceiling`.
    ///
    /// Keeps the exponential floor while still spreading. The default.
    #[default]
    Equal,
}

/// An exponential retry schedule with jitter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// Delay before the first retry, in milliseconds.
    pub base_ms: u64,
    /// Ceiling on the delay, in milliseconds.
    pub max_ms: u64,
    /// Growth factor per attempt.
    pub multiplier: u32,
    /// How much randomness to apply.
    pub jitter: Jitter,
}

impl Default for Backoff {
    /// 500 ms, doubling, capped at 5 minutes, with equal jitter.
    ///
    /// The cap is what makes an offline device cheap: a phone in a tunnel for an
    /// hour wakes twelve times rather than three thousand.
    fn default() -> Self {
        Self {
            base_ms: 500,
            max_ms: 5 * 60 * 1000,
            multiplier: 2,
            jitter: Jitter::Equal,
        }
    }
}

impl Backoff {
    /// The un-jittered delay for `attempt`, where attempt `0` is the first
    /// retry.
    ///
    /// Saturating throughout: an attempt count large enough to overflow the
    /// exponent produces [`max_ms`](Self::max_ms), which is the answer the cap
    /// would have given anyway.
    #[must_use]
    pub fn ceiling_ms(&self, attempt: u32) -> u64 {
        let mut delay = self.base_ms;
        for _ in 0..attempt {
            delay = delay.saturating_mul(u64::from(self.multiplier));
            if delay >= self.max_ms {
                return self.max_ms;
            }
        }
        delay.min(self.max_ms)
    }

    /// The delay for `attempt`, jittered with `entropy`.
    ///
    /// Pure, so the schedule is a property test rather than a stopwatch.
    #[must_use]
    pub fn delay_ms(&self, attempt: u32, entropy: u64) -> u64 {
        let ceiling = self.ceiling_ms(attempt);
        match self.jitter {
            Jitter::None => ceiling,
            // `% (ceiling + 1)` so the ceiling itself is reachable. The modulo
            // bias is at most one part in 2^64 / ceiling and irrelevant here:
            // this is scheduling, not key material.
            Jitter::Full => entropy % ceiling.saturating_add(1),
            Jitter::Equal => {
                let half = ceiling / 2;
                half.saturating_add(entropy % (ceiling - half).saturating_add(1))
            }
        }
    }

    /// The delay for `attempt`, drawing entropy from the OS CSPRNG.
    ///
    /// The CSPRNG is heavier than jitter needs, and it is the only randomness
    /// `misty-crypto` exposes; a second, weaker generator in the tree would be a
    /// worse trade than a few wasted bytes.
    ///
    /// # Errors
    ///
    /// [`SyncError::Crypto`](crate::SyncError::Crypto) if the CSPRNG fails.
    pub fn next_delay_ms(&self, attempt: u32) -> Result<u64> {
        if self.jitter == Jitter::None {
            return Ok(self.ceiling_ms(attempt));
        }
        let entropy = u64::from_le_bytes(misty_crypto::random::array::<8>()?);
        Ok(self.delay_ms(attempt, entropy))
    }
}

/// Something that can wait.
///
/// The engine never calls this itself unless asked to: [`crate::SyncEngine::run`]
/// takes a sleeper, and [`crate::SyncEngine::sync_once`] does not, so an app with
/// its own scheduler can drive the retries and ignore this entirely.
///
/// `-> impl Future` rather than `async fn` for the same reason as
/// [`Transport`](crate::Transport): a browser timer's future is not `Send`, and
/// spelling the signature out means no implicit bound to warn about. An
/// implementation may still write `async fn sleep_ms`.
pub trait Sleeper {
    /// Waits approximately `ms` milliseconds.
    fn sleep_ms(&self, ms: u64) -> impl core::future::Future<Output = ()>;
}

impl<S: Sleeper + ?Sized> Sleeper for &S {
    fn sleep_ms(&self, ms: u64) -> impl core::future::Future<Output = ()> {
        (**self).sleep_ms(ms)
    }
}

/// A sleeper that records what it was asked for and returns immediately.
#[derive(Debug, Default)]
pub struct MockSleeper {
    slept: std::sync::Mutex<Vec<u64>>,
}

impl MockSleeper {
    /// A fresh recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every duration asked for, in order.
    ///
    /// Returns an empty vector if the lock was poisoned, which can only happen
    /// if a test panicked while holding it — at which point the test has already
    /// failed.
    #[must_use]
    pub fn slept(&self) -> Vec<u64> {
        self.slept.lock().map(|log| log.clone()).unwrap_or_default()
    }
}

impl Sleeper for MockSleeper {
    async fn sleep_ms(&self, ms: u64) {
        if let Ok(mut log) = self.slept.lock() {
            log.push(ms);
        }
    }
}

/// A sleeper backed by `tokio::time`.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokioSleeper;

#[cfg(not(target_arch = "wasm32"))]
impl Sleeper for TokioSleeper {
    async fn sleep_ms(&self, ms: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn the_ceiling_doubles_and_then_stops() {
        let backoff = Backoff {
            base_ms: 100,
            max_ms: 1_000,
            multiplier: 2,
            jitter: Jitter::None,
        };
        assert_eq!(backoff.ceiling_ms(0), 100);
        assert_eq!(backoff.ceiling_ms(1), 200);
        assert_eq!(backoff.ceiling_ms(2), 400);
        assert_eq!(backoff.ceiling_ms(3), 800);
        assert_eq!(backoff.ceiling_ms(4), 1_000);
        // Saturating, not wrapping: an absurd attempt count is still the cap.
        assert_eq!(backoff.ceiling_ms(u32::MAX), 1_000);
    }

    #[test]
    fn no_jitter_is_exactly_the_ceiling() {
        let backoff = Backoff {
            jitter: Jitter::None,
            ..Backoff::default()
        };
        for attempt in 0..8 {
            assert_eq!(
                backoff.delay_ms(attempt, 12_345),
                backoff.ceiling_ms(attempt)
            );
            assert_eq!(
                backoff.next_delay_ms(attempt).expect("no entropy needed"),
                backoff.ceiling_ms(attempt)
            );
        }
    }

    #[test]
    fn the_default_schedule_is_the_documented_one() {
        let backoff = Backoff::default();
        assert_eq!(backoff.ceiling_ms(0), 500);
        assert_eq!(backoff.ceiling_ms(1), 1_000);
        assert_eq!(backoff.ceiling_ms(10), 300_000);
    }

    #[test]
    fn a_zero_ceiling_does_not_divide_by_zero() {
        let backoff = Backoff {
            base_ms: 0,
            max_ms: 0,
            multiplier: 2,
            jitter: Jitter::Full,
        };
        assert_eq!(backoff.delay_ms(0, u64::MAX), 0);
        let backoff = Backoff {
            jitter: Jitter::Equal,
            ..backoff
        };
        assert_eq!(backoff.delay_ms(0, u64::MAX), 0);
    }

    proptest! {
        /// Whatever entropy arrives, the delay stays inside the band its jitter
        /// mode promises. This is the property a retry storm depends on.
        #[test]
        fn jitter_stays_within_its_band(
            attempt in 0u32..24,
            entropy in any::<u64>(),
            base in 1u64..10_000,
            max in 1u64..1_000_000,
        ) {
            for jitter in [Jitter::None, Jitter::Full, Jitter::Equal] {
                let backoff = Backoff { base_ms: base, max_ms: max, multiplier: 2, jitter };
                let ceiling = backoff.ceiling_ms(attempt);
                let delay = backoff.delay_ms(attempt, entropy);
                prop_assert!(delay <= ceiling, "{delay} > {ceiling}");
                if jitter == Jitter::Equal {
                    prop_assert!(delay >= ceiling / 2, "{delay} < {}", ceiling / 2);
                }
                if jitter == Jitter::None {
                    prop_assert_eq!(delay, ceiling);
                }
            }
        }
    }
}
