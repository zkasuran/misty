// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Time drift (SPEC §6.5).
//!
//! TOTP is only as correct as the clock, and a wrong clock looks like a broken
//! app. So the client measures the server's clock, stores the offset, and applies
//! it when generating codes. It **never** writes the system clock: that would be
//! a privileged, global side effect to fix a local, per-vault problem.
//!
//! # SPEC §6.1's `/v1/time` was replayable as originally specified
//!
//! An earlier §6.1 said `GET /v1/time -> {unix_ms, sig}`, "Ed25519 over the
//! timestamp", and §6.5 said the signature "exists so a network attacker cannot
//! walk a client's effective clock into a window where old codes validate". A
//! signature over the timestamp alone cannot do that. It is a static bearer token
//! for that instant: a network attacker records one valid response and serves it
//! back forever, pinning every client that reaches it to a fixed past moment —
//! exactly the attack the signature is named for.
//!
//! §6.1.1 now fixes the exchange, byte-exactly, and this is it:
//!
//! ```text
//! GET /v1/time?nonce=<nonce>
//! -> { unix_ms, nonce, sig }
//! sig = Ed25519(server_priv, "misty/time/v1" ‖ LE32(nonce.len()) ‖ nonce ‖ LE64(unix_ms))
//! ```
//!
//! The length prefix is not decoration: without it, appending any future field
//! makes the encoding ambiguous, and a signature scheme that becomes ambiguous
//! later is one that gets confused later.
//!
//! Two checks, not one. The nonce is what makes a replay impossible; the
//! monotonicity check in [`DriftTracker::accept`] is what makes it *harmless*
//! even against a server that cooperates with the nonce protocol and then lies,
//! because server time is not allowed to go backwards past a small tolerance.

use misty_crypto::SignatureBytes;

use crate::error::{Result, SyncError};
use crate::limits;
use crate::signature::verify_detached;
use crate::state::TimeSample;

/// Domain separator for the `/v1/time` signature (SPEC §6.6).
pub const TIME_SIGNING_CONTEXT: &[u8] = b"misty/time/v1";

/// How far server time may appear to move backwards between two measurements
/// before it is refused, in milliseconds.
///
/// Not zero, because a server behind a load balancer can answer from two hosts
/// whose clocks differ by a few milliseconds, and refusing that would make
/// drift measurement fail at random. One second is far below any window that
/// would let a consumed TOTP code validate again — a 30-second step needs 30 000
/// ms of rollback to replay a code.
pub const BACKWARDS_TOLERANCE_MS: i64 = 1_000;

/// The exact bytes a `/v1/time` signature covers (SPEC §6.1.1).
///
/// ```text
/// "misty/time/v1" ‖ LE32(nonce.len()) ‖ nonce ‖ LE64(unix_ms)
/// ```
#[must_use]
pub fn time_signing_bytes(nonce: &[u8], unix_ms: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(TIME_SIGNING_CONTEXT.len() + 4 + nonce.len() + 8);
    out.extend_from_slice(TIME_SIGNING_CONTEXT);
    out.extend_from_slice(&u32::try_from(nonce.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&unix_ms.to_le_bytes());
    out
}

/// Verifies a `/v1/time` response against the pinned server key and the nonce
/// this client sent.
///
/// # Errors
///
/// [`SyncError::TimeNonceMismatch`] if the response answers a different request,
/// or [`SyncError::TimeSignatureInvalid`] if the signature does not verify under
/// `server_public_key`.
pub fn verify_time(
    server_public_key: &[u8; 32],
    sent_nonce: &[u8; limits::TIME_NONCE_LEN],
    echoed_nonce: &[u8],
    unix_ms: i64,
    signature: &SignatureBytes,
) -> Result<()> {
    // Nonce first. It is a plain comparison of two public values, and getting it
    // wrong is the difference between "this answers my question" and "this
    // answered someone else's, once".
    if echoed_nonce != sent_nonce.as_slice() {
        return Err(SyncError::TimeNonceMismatch);
    }
    verify_detached(
        server_public_key,
        &time_signing_bytes(sent_nonce, unix_ms),
        signature.as_bytes(),
        SyncError::TimeSignatureInvalid,
    )
}

/// The measured offset between this device's clock and the server's, and what
/// the UI should say about it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Drift {
    sample: Option<TimeSample>,
}

impl Drift {
    /// Wraps a measurement, or the absence of one.
    #[must_use]
    pub const fn new(sample: Option<TimeSample>) -> Self {
        Self { sample }
    }

    /// The last verified measurement.
    #[must_use]
    pub const fn sample(&self) -> Option<TimeSample> {
        self.sample
    }

    /// `true_time - local_time`, in milliseconds. Zero when never measured,
    /// which is the same thing as "trust the device clock".
    #[must_use]
    pub fn offset_ms(&self) -> i64 {
        self.sample.map_or(0, |sample| sample.offset_ms)
    }

    /// Whether the offset passes SPEC §6.5's 10-second warning threshold.
    #[must_use]
    pub fn exceeds_warning_threshold(&self) -> bool {
        self.offset_ms().saturating_abs() > limits::DRIFT_WARNING_MS
    }

    /// Whether drift was last measured more than seven days ago, or never.
    ///
    /// SPEC §6.5: with no network, fall back to the device clock and *say so* if
    /// the measurement is this old. A clock the app silently believes is worse
    /// than one it admits it has not checked.
    #[must_use]
    pub fn is_stale(&self, local_now_ms: i64) -> bool {
        match self.sample {
            None => true,
            Some(sample) => {
                local_now_ms.saturating_sub(sample.measured_at_ms) > limits::DRIFT_STALE_MS
            }
        }
    }

    /// The corrected time for `local_now_ms`, without touching any clock.
    ///
    /// Feed this to
    /// [`OtpConfig::generate_at`](misty_otp::OtpConfig::generate_at), or wrap the
    /// device clock with
    /// [`Clock::with_skew_ms(self.offset_ms())`](misty_otp::Clock::with_skew_ms),
    /// which is the same arithmetic expressed once.
    #[must_use]
    pub fn effective_now_ms(&self, local_now_ms: i64) -> i64 {
        local_now_ms.saturating_add(self.offset_ms())
    }
}

/// Accepts or refuses a new measurement.
///
/// Separate from [`Drift`] so the rule that a measurement may be *refused* is a
/// function with a test rather than a branch inside a getter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriftTracker {
    previous: Option<TimeSample>,
}

impl DriftTracker {
    /// A tracker holding whatever was persisted.
    #[must_use]
    pub const fn new(previous: Option<TimeSample>) -> Self {
        Self { previous }
    }

    /// Turns a verified reading into a sample, refusing a rollback.
    ///
    /// # Errors
    ///
    /// [`SyncError::TimeWentBackwards`] if `server_ms` is more than
    /// [`BACKWARDS_TOLERANCE_MS`] below the previous reading.
    pub fn accept(&self, local_now_ms: i64, server_ms: i64) -> Result<TimeSample> {
        if let Some(previous) = self.previous {
            if server_ms < previous.server_ms.saturating_sub(BACKWARDS_TOLERANCE_MS) {
                return Err(SyncError::TimeWentBackwards {
                    offered: server_ms,
                    previous: previous.server_ms,
                });
            }
        }
        Ok(TimeSample {
            measured_at_ms: local_now_ms,
            server_ms,
            offset_ms: server_ms.saturating_sub(local_now_ms),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misty_crypto::identity::DeviceIdentity;

    fn nonce(byte: u8) -> [u8; limits::TIME_NONCE_LEN] {
        [byte; limits::TIME_NONCE_LEN]
    }

    #[test]
    fn the_signed_message_is_context_length_nonce_then_le64() {
        let bytes = time_signing_bytes(&nonce(1), 0x0102_0304_0506_0708);
        assert!(bytes.starts_with(TIME_SIGNING_CONTEXT));
        assert_eq!(bytes.len(), TIME_SIGNING_CONTEXT.len() + 4 + 32 + 8);
        // The LE32 length prefix SPEC §6.1.1 requires: without it, appending a
        // field later would make two different messages encode identically.
        assert_eq!(
            bytes.get(TIME_SIGNING_CONTEXT.len()..TIME_SIGNING_CONTEXT.len() + 4),
            Some([32u8, 0, 0, 0].as_slice())
        );
        assert_eq!(
            bytes.get(bytes.len() - 8..),
            Some([8u8, 7, 6, 5, 4, 3, 2, 1].as_slice()),
            "little-endian, like every other integer in this format"
        );
    }

    #[test]
    fn an_honest_response_verifies_and_a_replayed_one_does_not() {
        let server = DeviceIdentity::generate().expect("key");
        let sent = nonce(9);
        let signature = server.sign(&time_signing_bytes(&sent, 1_700_000_000_000));
        verify_time(
            &server.ed25519_public(),
            &sent,
            &sent,
            1_700_000_000_000,
            &signature,
        )
        .expect("verifies");

        // The same signed answer offered against a different question. This is the
        // whole reason the nonce exists: without it the signature would still be
        // valid and the client would believe an old timestamp forever.
        let error = verify_time(
            &server.ed25519_public(),
            &nonce(10),
            &sent,
            1_700_000_000_000,
            &signature,
        )
        .expect_err("a replay");
        assert!(matches!(error, SyncError::TimeNonceMismatch), "{error:?}");
    }

    #[test]
    fn a_response_from_another_key_or_with_another_timestamp_does_not_verify() {
        let server = DeviceIdentity::generate().expect("key");
        let other = DeviceIdentity::generate().expect("key");
        let sent = nonce(9);
        let signature = server.sign(&time_signing_bytes(&sent, 1_700_000_000_000));

        for (key, unix_ms) in [
            (other.ed25519_public(), 1_700_000_000_000),
            (server.ed25519_public(), 1_700_000_000_001),
        ] {
            let error =
                verify_time(&key, &sent, &sent, unix_ms, &signature).expect_err("does not verify");
            assert!(
                matches!(error, SyncError::TimeSignatureInvalid),
                "{error:?}"
            );
        }
    }

    #[test]
    fn a_tracker_allows_a_small_jitter_and_refuses_a_rollback() {
        let first = DriftTracker::new(None)
            .accept(1_000, 1_500)
            .expect("first reading");
        assert_eq!(first.offset_ms, 500);

        let tracker = DriftTracker::new(Some(first));
        // Within tolerance: two hosts behind one load balancer.
        assert!(tracker
            .accept(2_000, 1_500 - BACKWARDS_TOLERANCE_MS)
            .is_ok());
        let error = tracker
            .accept(2_000, 1_500 - BACKWARDS_TOLERANCE_MS - 1)
            .expect_err("a rollback");
        assert!(
            matches!(error, SyncError::TimeWentBackwards { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn drift_with_no_sample_is_zero_stale_and_harmless() {
        let drift = Drift::default();
        assert_eq!(drift.offset_ms(), 0);
        assert!(!drift.exceeds_warning_threshold());
        assert!(drift.is_stale(0));
        assert_eq!(drift.effective_now_ms(1_234), 1_234);
    }

    #[test]
    fn the_warning_threshold_is_ten_seconds_exactly() {
        let at = |offset_ms| {
            Drift::new(Some(TimeSample {
                measured_at_ms: 0,
                server_ms: offset_ms,
                offset_ms,
            }))
        };
        assert!(!at(10_000).exceeds_warning_threshold());
        assert!(at(10_001).exceeds_warning_threshold());
        assert!(at(-10_001).exceeds_warning_threshold());
    }
}
