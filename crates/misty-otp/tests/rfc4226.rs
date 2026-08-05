// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 4226 Appendix D — every published HOTP value, including the intermediate
//! HMAC and truncation columns.
//!
//! All vectors in this file are **authoritative**: they are transcribed from
//! RFC 4226 (December 2005), Appendix D, Tables 1 and 2. Checking only the final
//! codes would let an implementation that is wrong in two cancelling ways pass,
//! so the HMAC and the truncated integer are checked too.
//!
//! <https://www.rfc-editor.org/rfc/rfc4226#appendix-D>

use hex_literal::hex;
use misty_otp::{hotp, raw, HashAlg, OtpConfig, OtpKind, SecretBytes};

/// RFC 4226 Appendix D: `Secret = 0x3132...3930`, the ASCII digits 1-9 then 0,
/// twice.
const SECRET: &[u8; 20] = b"12345678901234567890";

/// `(count, HMAC-SHA-1(secret, count), truncated decimal, 6-digit HOTP)`
const APPENDIX_D: [(u64, [u8; 20], u32, &str); 10] = [
    (
        0,
        hex!("cc93cf18508d94934c64b65d8ba7667fb7cde4b0"),
        1_284_755_224,
        "755224",
    ),
    (
        1,
        hex!("75a48a19d4cbe100644e8ac1397eea747a2d33ab"),
        1_094_287_082,
        "287082",
    ),
    (
        2,
        hex!("0bacb7fa082fef30782211938bc1c5e70416ff44"),
        137_359_152,
        "359152",
    ),
    (
        3,
        hex!("66c28227d03a2d5529262ff016a1e6ef76557ece"),
        1_726_969_429,
        "969429",
    ),
    (
        4,
        hex!("a904c900a64b35909874b33e61c5938a8e15ed1c"),
        1_640_338_314,
        "338314",
    ),
    (
        5,
        hex!("a37e783d7b7233c083d4f62926c7a25f238d0316"),
        868_254_676,
        "254676",
    ),
    (
        6,
        hex!("bc9cd28561042c83f219324d3c607256c03272ae"),
        1_918_287_922,
        "287922",
    ),
    (
        7,
        hex!("a4fb960c0bc06e1eabb804e5b397cdc4b45596fa"),
        82_162_583,
        "162583",
    ),
    (
        8,
        hex!("1b3c89f65e6c9e883012052823443f048b4332db"),
        673_399_871,
        "399871",
    ),
    (
        9,
        hex!("1637409809a679dc698207310c8c7fc07290d9e5"),
        645_520_489,
        "520489",
    ),
];

fn secret() -> SecretBytes {
    SecretBytes::from_slice(SECRET)
}

#[test]
fn appendix_d_table_1_intermediate_hmac() {
    for (count, expected, _, _) in APPENDIX_D {
        let digest = raw::hmac_counter(HashAlg::Sha1, SECRET, count).unwrap();
        assert_eq!(&digest[..], &expected[..], "HMAC for count {count}");
    }
}

#[test]
fn appendix_d_table_2_dynamic_truncation() {
    for (count, digest, expected, _) in APPENDIX_D {
        assert_eq!(
            raw::dynamic_truncation(&digest).unwrap(),
            expected,
            "truncation for count {count}"
        );
        // The published hex column is the low 31 bits of the same value.
        assert_eq!(expected & 0x7FFF_FFFF, expected);
    }
}

#[test]
fn appendix_d_table_2_hotp_values() {
    for (count, _, _, expected) in APPENDIX_D {
        let code = hotp(&secret(), count, 6, HashAlg::Sha1).unwrap();
        assert_eq!(code.value(), expected, "HOTP for count {count}");
        assert_eq!(code.len(), 6);
        // Counter-based codes have no validity window.
        assert_eq!(code.window(), None);
    }
}

#[test]
fn config_generation_matches_the_free_function() {
    for (count, _, _, expected) in APPENDIX_D {
        let config = OtpConfig::hotp(secret(), count).unwrap();
        assert_eq!(config.kind(), OtpKind::Hotp);
        // HOTP takes its moving factor from the counter, so the instant passed
        // in must not matter.
        for unix_ms in [0, 1, 59_000, 1_234_567_890_000, u64::MAX] {
            assert_eq!(config.generate_at(unix_ms).unwrap().value(), expected);
            assert_eq!(config.counter_at(unix_ms).unwrap(), count);
        }
    }
}

#[test]
fn next_code_is_the_next_counter() {
    for window in APPENDIX_D.windows(2) {
        let [(count, _, _, _), (_, _, _, next_expected)] = window else {
            unreachable!("windows(2) yields pairs")
        };
        let config = OtpConfig::hotp(secret(), *count).unwrap();
        assert_eq!(config.next_code_at(0).unwrap().value(), *next_expected);
        // Peeking does not consume the counter.
        assert_eq!(config.counter(), *count);
    }
}

/// Derived, **not** published: RFC 4226 only tabulates 6 digits. These are the
/// same truncated integers reduced to other widths, which is the definition of
/// the algorithm rather than an independent vector.
#[test]
fn other_digit_counts_reduce_the_published_truncation() {
    for (count, _, truncated, _) in APPENDIX_D {
        for digits in 1..=10u8 {
            let modulus = 10u64.pow(u32::from(digits));
            let expected = format!(
                "{:0width$}",
                u64::from(truncated) % modulus,
                width = usize::from(digits)
            );
            let code = hotp(&secret(), count, digits, HashAlg::Sha1).unwrap();
            assert_eq!(code.value(), expected, "count {count}, {digits} digits");
            assert_eq!(code.len(), usize::from(digits));
        }
    }
}

#[test]
fn resynchronization_finds_the_matching_counter() {
    // A token that has drifted forward: the vault thinks counter 0, the token
    // has been pressed up to 9 times.
    let config = OtpConfig::hotp(secret(), 0).unwrap();
    for (count, _, _, code) in APPENDIX_D {
        assert_eq!(config.resync_counter(code, 9), Some(count));
    }
    // Bounded: a code beyond the window is not found.
    let tight = OtpConfig::hotp(secret(), 0).unwrap();
    assert_eq!(tight.resync_counter("520489", 8), None);
    assert_eq!(tight.resync_counter("520489", 9), Some(9));
    // A code from before the current counter is never accepted, because
    // accepting it would replay a consumed code (SPEC 4).
    let ahead = OtpConfig::hotp(secret(), 5).unwrap();
    assert_eq!(ahead.resync_counter("755224", 1000), None);
    assert_eq!(ahead.resync_counter("254676", 0), Some(5));
    // Nonsense never matches.
    for bogus in ["", "0", "755225", "7552240", "abcdef"] {
        assert_eq!(ahead.resync_counter(bogus, 1000), None);
    }
}

#[test]
fn resynchronization_is_meaningless_for_time_based_kinds() {
    let config = OtpConfig::totp(secret()).unwrap();
    assert_eq!(config.resync_counter("287082", 100), None);
}

#[test]
fn hotp_rejects_unusable_parameters() {
    assert!(hotp(&secret(), 0, 0, HashAlg::Sha1).is_err());
    assert!(hotp(&secret(), 0, 11, HashAlg::Sha1).is_err());
    assert!(hotp(&SecretBytes::new(Vec::new()), 0, 6, HashAlg::Sha1).is_err());
}
