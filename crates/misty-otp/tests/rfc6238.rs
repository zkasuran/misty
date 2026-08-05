// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 6238 Appendix B — every published TOTP value, for all three hashes.
//!
//! All vectors in this file are **authoritative**: the codes and time steps are
//! transcribed from RFC 6238 (May 2011), Appendix B, Table 1, and the three
//! per-algorithm seeds from the reference implementation in Appendix A.
//!
//! The seeds are the trap in this test suite. Appendix B's prose says the shared
//! secret is the 20-byte ASCII string `12345678901234567890`, but the published
//! SHA-256 and SHA-512 codes were generated with the 32- and 64-byte seeds in
//! Appendix A: the same ASCII digits, repeated to the hash's block size. An
//! implementation that uses the 20-byte seed for all three modes will match the
//! SHA-1 column and fail the other two.
//!
//! <https://www.rfc-editor.org/rfc/rfc6238#appendix-B>

use misty_otp::{Clock, FixedClock, HashAlg, OtpConfig, SecretBytes};

/// RFC 6238 Appendix A `seed`, 20 bytes.
const SEED_SHA1: &[u8] = b"12345678901234567890";
/// RFC 6238 Appendix A `seed32`, 32 bytes.
const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
/// RFC 6238 Appendix A `seed64`, 64 bytes.
const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

/// `(unix seconds, value of T, SHA-1 code, SHA-256 code, SHA-512 code)`, all
/// 8 digits with `T0 = 0` and `X = 30`.
const APPENDIX_B: [(u64, u64, &str, &str, &str); 6] = [
    (
        59,
        0x0000_0000_0000_0001,
        "94287082",
        "46119246",
        "90693936",
    ),
    (
        1_111_111_109,
        0x0000_0000_0235_23EC,
        "07081804",
        "68084774",
        "25091201",
    ),
    (
        1_111_111_111,
        0x0000_0000_0235_23ED,
        "14050471",
        "67062674",
        "99943326",
    ),
    (
        1_234_567_890,
        0x0000_0000_0273_EF07,
        "89005924",
        "91819424",
        "93441116",
    ),
    (
        2_000_000_000,
        0x0000_0000_03F9_40AA,
        "69279037",
        "90698825",
        "38618901",
    ),
    (
        20_000_000_000,
        0x0000_0000_27BC_86AA,
        "65353130",
        "77737706",
        "47863826",
    ),
];

fn seed(algorithm: HashAlg) -> &'static [u8] {
    match algorithm {
        HashAlg::Sha1 => SEED_SHA1,
        HashAlg::Sha256 => SEED_SHA256,
        HashAlg::Sha512 => SEED_SHA512,
    }
}

fn config(algorithm: HashAlg) -> OtpConfig {
    OtpConfig::totp_with(SecretBytes::from_slice(seed(algorithm)), algorithm, 8, 30).unwrap()
}

/// `(algorithm, expected code)` for one row.
fn row(
    vector: (u64, u64, &'static str, &'static str, &'static str),
) -> [(HashAlg, &'static str); 3] {
    let (_, _, sha1, sha256, sha512) = vector;
    [
        (HashAlg::Sha1, sha1),
        (HashAlg::Sha256, sha256),
        (HashAlg::Sha512, sha512),
    ]
}

#[test]
fn appendix_b_all_modes() {
    for vector in APPENDIX_B {
        let (unix_secs, _, _, _, _) = vector;
        for (algorithm, expected) in row(vector) {
            let code = config(algorithm).generate_at(unix_secs * 1_000).unwrap();
            assert_eq!(
                code.value(),
                expected,
                "T={unix_secs} {algorithm} should be {expected}"
            );
            assert_eq!(code.len(), 8);
        }
    }
}

#[test]
fn appendix_b_time_steps() {
    for vector in APPENDIX_B {
        let (unix_secs, expected_t, _, _, _) = vector;
        for (algorithm, _) in row(vector) {
            assert_eq!(
                config(algorithm).counter_at(unix_secs * 1_000).unwrap(),
                expected_t,
                "value of T at {unix_secs}"
            );
        }
    }
}

/// The published code must hold for every millisecond of its window, and must
/// change the millisecond after.
#[test]
fn codes_are_stable_across_their_whole_window() {
    for vector in APPENDIX_B {
        let (unix_secs, _, _, _, _) = vector;
        for (algorithm, expected) in row(vector) {
            let config = config(algorithm);
            let start_ms = (unix_secs / 30) * 30_000;

            for offset_ms in [0, 1, 15_000, 29_998, 29_999] {
                let code = config.generate_at(start_ms + offset_ms).unwrap();
                assert_eq!(code.value(), expected, "at +{offset_ms}ms");
                assert_eq!(code.valid_from_ms(), Some(start_ms));
                assert_eq!(code.valid_until_ms(), Some(start_ms + 30_000));
                assert_eq!(code.remaining_ms(), Some(30_000 - offset_ms));
            }
            assert_ne!(
                config.generate_at(start_ms + 30_000).unwrap().value(),
                expected,
                "the next window must produce a different code"
            );
        }
    }
}

#[test]
fn seeds_have_the_documented_lengths() {
    assert_eq!(SEED_SHA1.len(), 20);
    assert_eq!(SEED_SHA256.len(), 32);
    assert_eq!(SEED_SHA512.len(), 64);
    // Each is the same ASCII digit pattern, truncated to the hash's block size.
    assert!(SEED_SHA256.starts_with(SEED_SHA1));
    assert!(SEED_SHA512.starts_with(SEED_SHA256));
}

#[test]
fn window_arithmetic_is_exact() {
    let config = config(HashAlg::Sha1);
    let code = config.generate_at(59_000).unwrap();
    assert_eq!(code.valid_from_ms(), Some(30_000));
    assert_eq!(code.valid_until_ms(), Some(60_000));
    assert_eq!(code.remaining_ms(), Some(1_000));
    let progress = code.progress().unwrap();
    assert!((progress - 29.0 / 30.0).abs() < 1e-6, "{progress}");

    let start = config.generate_at(30_000).unwrap();
    assert_eq!(start.remaining_ms(), Some(30_000));
    assert_eq!(start.progress(), Some(0.0));
}

#[test]
fn next_code_is_the_following_window() {
    let config = config(HashAlg::Sha1);
    for vector in APPENDIX_B {
        let (unix_secs, _, _, _, _) = vector;
        let now_ms = unix_secs * 1_000;
        let current = config.generate_at(now_ms).unwrap();
        let peeked = config.next_code_at(now_ms).unwrap();
        let expected = config.generate_at((unix_secs / 30 + 1) * 30_000).unwrap();

        assert_eq!(peeked.value(), expected.value());
        assert_ne!(peeked.value(), current.value());
        // The peeked window is the next one, seen from its start.
        assert_eq!(peeked.valid_from_ms(), current.valid_until_ms());
        assert_eq!(peeked.remaining_ms(), Some(30_000));
        assert_eq!(peeked.progress(), Some(0.0));
    }
}

#[test]
fn generation_through_a_clock_matches_generation_at_an_instant() {
    for vector in APPENDIX_B {
        let (unix_secs, _, _, _, _) = vector;
        for (algorithm, expected) in row(vector) {
            let config = config(algorithm);
            let clock = FixedClock::new(unix_secs * 1_000);
            assert_eq!(config.generate(&clock).unwrap().value(), expected);

            // A skewed clock must reach the same window from the wrong side of
            // it: the engine applies the offset, never the system clock.
            let slow = FixedClock::new(unix_secs * 1_000 - 5_000).with_skew_ms(5_000);
            assert_eq!(slow.now_unix_ms(), unix_secs * 1_000);
            assert_eq!(config.generate(&slow).unwrap().value(), expected);

            let fast = FixedClock::new(unix_secs * 1_000 + 5_000).with_skew_ms(-5_000);
            assert_eq!(config.generate(&fast).unwrap().value(), expected);
        }
    }
}

/// Derived, **not** published: RFC 6238 tabulates 8 digits only. A 6-digit code
/// is by definition the last 6 digits of the same truncation, which is worth
/// pinning because 6 digits is what almost every issuer actually uses.
#[test]
fn six_digit_codes_are_the_tail_of_the_published_eight() {
    for vector in APPENDIX_B {
        let (unix_secs, _, _, _, _) = vector;
        for (algorithm, expected) in row(vector) {
            let config =
                OtpConfig::totp_with(SecretBytes::from_slice(seed(algorithm)), algorithm, 6, 30)
                    .unwrap();
            let code = config.generate_at(unix_secs * 1_000).unwrap();
            assert_eq!(code.value(), &expected[2..], "T={unix_secs} {algorithm}");
        }
    }
}

/// Non-30-second periods are not in the RFC. SPEC 3 requires 1..=3600, so pin
/// the arithmetic: a period of 60 at time `t` must equal a period of 30 at a
/// time with the same step index.
#[test]
fn non_default_periods_use_the_same_construction() {
    let secret = SecretBytes::from_slice(SEED_SHA1);
    for period in [1u16, 7, 15, 45, 60, 90, 3600] {
        let config = OtpConfig::totp_with(secret.clone(), HashAlg::Sha1, 8, period).unwrap();
        let unix_secs = 1_234_567_890;
        let step = unix_secs / u64::from(period);
        let code = config.generate_at(unix_secs * 1_000).unwrap();

        // The same step index under a 1-second period is the raw counter, so
        // HOTP at that counter must agree.
        let equivalent = OtpConfig::hotp_with(secret.clone(), HashAlg::Sha1, 8, step).unwrap();
        assert_eq!(
            code.value(),
            equivalent.generate_at(0).unwrap().value(),
            "period {period}"
        );
        assert_eq!(
            code.remaining_ms(),
            Some(
                u64::from(period) * 1_000 - (unix_secs * 1_000 - step * u64::from(period) * 1_000)
            )
        );
    }
}

#[test]
fn extreme_timestamps_do_not_panic() {
    let config = config(HashAlg::Sha1);
    assert!(config.generate_at(0).is_ok());
    assert!(config.generate_at(1).is_ok());
    // The last representable window still generates; one period later does not
    // exist, and must be an error rather than a wrap or a panic.
    assert!(config.generate_at(u64::MAX - 30_000).is_ok());
    assert!(config.generate_at(u64::MAX).is_err());
    assert!(config.next_code_at(u64::MAX - 30_000).is_err());
}
