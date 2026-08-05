// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The four non-RFC variants: Steam, mOTP, Blizzard and Yandex.
//!
//! # Which vectors here are authoritative
//!
//! None of these four variants has a specification, let alone vendor-published
//! test vectors. What this file uses instead, in descending order of strength:
//!
//! | Variant | Vectors | Strength |
//! |---|---|---|
//! | Blizzard | RFC 6238 Appendix B, SHA-1 column | **Authoritative by reduction.** A Battle.net authenticator is RFC 6238 with SHA-1, 8 digits and a 30-second step, so the RFC's own vectors *are* the Blizzard vectors. |
//! | Steam | `steamguard-cli`'s `test_generate_code` | **Published third-party.** Not from Valve, but from an independent implementation in wide use, so agreeing with it means agreeing with something real. Additionally, the HMAC and truncation halves are anchored to RFC 4226 Appendix D's published truncation column. |
//! | mOTP | Aegis Authenticator's `MOTPTest` | **Published third-party.** Also checked against an independent re-implementation of the documented formula, which pins the concatenation order. |
//! | Yandex | Aegis Authenticator's `YAOTPTest` | **Published third-party.** The only public description of this algorithm is source code; these vectors are how that source proves itself. |
//!
//! Sources:
//! * <https://github.com/dyc3/steamguard-cli> — `steamguard/src/token.rs`
//! * <https://github.com/beemdevelopment/Aegis> — `app/src/test/java/com/beemdevelopment/aegis/crypto/otp/{MOTPTest,YAOTPTest}.java`
//!
//! Vectors labelled *self-generated* below came out of this crate and prove only
//! that behaviour has not changed. They are marked as such and are never
//! presented as evidence of correctness.

use md5::{Digest as _, Md5};
use misty_otp::{HashAlg, OtpConfig, OtpKind, SecretBytes};

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

/// The RFC 4226 Appendix D secret, reused so the Steam anchor below can lean on
/// the RFC's published truncation column.
fn rfc_secret() -> SecretBytes {
    SecretBytes::from_slice(b"12345678901234567890")
}

fn base32_secret() -> SecretBytes {
    SecretBytes::from_base32("JBSWY3DPEHPK3PXP").expect("valid base32")
}

// ---------------------------------------------------------------- Steam

/// RFC 4226 Appendix D, Table 2, `(count, truncated decimal)`. Authoritative.
const RFC4226_TRUNCATIONS: [(u64, u32); 10] = [
    (0, 1_284_755_224),
    (1, 1_094_287_082),
    (2, 137_359_152),
    (3, 1_726_969_429),
    (4, 1_640_338_314),
    (5, 868_254_676),
    (6, 1_918_287_922),
    (7, 82_162_583),
    (8, 673_399_871),
    (9, 645_520_489),
];

/// Steam's rendering, written out independently of the implementation.
fn base26(mut value: u32) -> String {
    let mut out = String::new();
    for _ in 0..5 {
        out.push(char::from(STEAM_ALPHABET[(value % 26) as usize]));
        value /= 26;
    }
    out
}

#[test]
fn steam_defaults_match_the_variant() {
    let config = OtpConfig::steam(base32_secret()).unwrap();
    assert_eq!(config.kind(), OtpKind::Steam);
    assert_eq!(config.digits(), 5);
    assert_eq!(config.period(), 30);
    assert_eq!(config.algorithm(), HashAlg::Sha1);
}

/// Anchors Steam's HMAC and truncation to RFC 4226's published intermediate
/// values: only the base-26 step is unverified against a published source.
#[test]
fn steam_truncation_matches_rfc4226() {
    let config = OtpConfig::steam(rfc_secret()).unwrap();
    for (counter, truncated) in RFC4226_TRUNCATIONS {
        // A 30-second period puts time step `counter` at `counter * 30_000` ms.
        let code = config.generate_at(counter * 30_000).unwrap();
        assert_eq!(
            code.value(),
            base26(truncated),
            "steam code for RFC 4226 count {counter}"
        );
    }
}

#[test]
fn steam_codes_use_only_the_steam_alphabet() {
    let config = OtpConfig::steam(base32_secret()).unwrap();
    for step in 0..500u64 {
        let code = config.generate_at(step * 30_000 + 12_345).unwrap();
        assert_eq!(code.len(), 5);
        for ch in code.value().chars() {
            assert!(
                STEAM_ALPHABET.contains(&u8::try_from(ch).unwrap()),
                "{ch:?} is not a Steam character"
            );
        }
    }
    // No vowels, no visually ambiguous glyphs, no duplicates.
    assert_eq!(STEAM_ALPHABET.len(), 26);
    for forbidden in b"AEIOU01LSZ" {
        assert!(!STEAM_ALPHABET.contains(forbidden));
    }
}

/// Published third-party vector: `steamguard-cli`, `steamguard/src/token.rs`,
/// `test_generate_code`. The shared secret there is base64
/// `zvIayp3JPvtvX/QGHqsqKBk/44s=`, which is these 20 bytes.
#[test]
fn steam_matches_the_steamguard_cli_vector() {
    let secret = SecretBytes::from_hex("cef21aca9dc93efb6f5ff4061eab2a28193fe38b").unwrap();
    let config = OtpConfig::steam(secret).unwrap();
    assert_eq!(
        config.generate_at(1_616_374_841_000).unwrap().value(),
        "2F9J5"
    );
    // The whole window, not just the instant the other project happened to pick:
    // 1616374841 falls in the step starting at 1616374830.
    assert_eq!(
        config.generate_at(1_616_374_830_000).unwrap().value(),
        "2F9J5"
    );
    assert_eq!(
        config.generate_at(1_616_374_859_999).unwrap().value(),
        "2F9J5"
    );
    assert_ne!(
        config.generate_at(1_616_374_829_999).unwrap().value(),
        "2F9J5"
    );
    assert_ne!(
        config.generate_at(1_616_374_860_000).unwrap().value(),
        "2F9J5"
    );
}

/// Self-generated regression vectors, not authoritative.
#[test]
fn steam_frozen_vectors() {
    // secret = base32 "JBSWY3DPEHPK3PXP"
    let config = OtpConfig::steam(base32_secret()).unwrap();
    for (unix_secs, expected) in [
        (0u64, "VH8YJ"),
        (59, "2YXGV"),
        (1_111_111_109, "CWDGV"),
        (1_234_567_890, "K8G5W"),
        (2_000_000_000, "HNCVQ"),
    ] {
        assert_eq!(
            config.generate_at(unix_secs * 1_000).unwrap().value(),
            expected,
            "steam at {unix_secs}"
        );
    }

    // secret = the RFC 4226 ASCII secret, which is also covered by the
    // truncation anchor above.
    let rfc = OtpConfig::steam(rfc_secret()).unwrap();
    for (unix_secs, expected) in [
        (0u64, "GG5F5"),
        (59, "PV9M4"),
        (1_111_111_109, "PY4YB"),
        (1_234_567_890, "VHHQY"),
        (2_000_000_000, "9N776"),
    ] {
        assert_eq!(
            rfc.generate_at(unix_secs * 1_000).unwrap().value(),
            expected,
            "steam at {unix_secs}"
        );
    }
}

// ---------------------------------------------------------------- mOTP

/// The documented Mobile-OTP construction, re-implemented here so the test
/// pins the *formula* — specifically the concatenation order, which is the part
/// implementations get wrong — rather than only the output.
fn motp_reference(secret_hex: &str, pin: &str, unix_secs: u64) -> String {
    let interval = unix_secs / 10;
    let mut digest = Md5::new();
    digest.update(format!("{interval}{secret_hex}{pin}").as_bytes());
    let rendered: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    rendered[..6].to_owned()
}

#[test]
fn motp_defaults_match_the_variant() {
    let config = OtpConfig::motp(
        SecretBytes::from_hex("bfa47a0b71ac8f4d").unwrap(),
        SecretBytes::from_slice(b"9999"),
    )
    .unwrap();
    assert_eq!(config.kind(), OtpKind::Motp);
    assert_eq!(config.digits(), 6);
    assert_eq!(config.period(), 10);
}

#[test]
fn motp_matches_the_documented_formula() {
    let secret_hex = "bfa47a0b71ac8f4d";
    let pin = "9999";
    let config = OtpConfig::motp(
        SecretBytes::from_hex(secret_hex).unwrap(),
        SecretBytes::from_slice(pin.as_bytes()),
    )
    .unwrap();

    for unix_secs in [
        0u64,
        1,
        9,
        10,
        11,
        1_297_919_940,
        1_234_567_890,
        1_111_111_109,
    ] {
        let code = config.generate_at(unix_secs * 1_000).unwrap();
        assert_eq!(
            code.value(),
            motp_reference(secret_hex, pin, unix_secs),
            "motp at {unix_secs}"
        );
        assert_eq!(code.len(), 6);
        assert!(code.value().chars().all(|ch| ch.is_ascii_hexdigit()));
        assert!(code.value().chars().all(|ch| !ch.is_ascii_uppercase()));
    }
}

/// The secret is hashed as its lowercase hex *text*: mOTP predates `otpauth://`
/// and specifies a 16-hex-character init-secret.
#[test]
fn motp_hashes_the_hex_text_of_the_secret() {
    let config = OtpConfig::motp(
        SecretBytes::from_hex("bfa47a0b71ac8f4d").unwrap(),
        SecretBytes::from_slice(b"9999"),
    )
    .unwrap();
    // Same bytes written in uppercase hex must produce the same code, because
    // the implementation re-renders them itself.
    let upper = OtpConfig::motp(
        SecretBytes::from_hex("BFA47A0B71AC8F4D").unwrap(),
        SecretBytes::from_slice(b"9999"),
    )
    .unwrap();
    assert_eq!(
        config.generate_at(1_297_919_940_000).unwrap().value(),
        upper.generate_at(1_297_919_940_000).unwrap().value()
    );
}

#[test]
fn motp_periods_are_ten_seconds() {
    let config = OtpConfig::motp(
        SecretBytes::from_hex("bfa47a0b71ac8f4d").unwrap(),
        SecretBytes::from_slice(b"9999"),
    )
    .unwrap();
    let first = config.generate_at(1_297_919_940_000).unwrap();
    assert_eq!(first.valid_from_ms(), Some(1_297_919_940_000));
    assert_eq!(first.valid_until_ms(), Some(1_297_919_950_000));
    assert_eq!(
        config.generate_at(1_297_919_949_999).unwrap().value(),
        first.value()
    );
    assert_ne!(
        config.generate_at(1_297_919_950_000).unwrap().value(),
        first.value()
    );
}

#[test]
fn motp_without_a_pin_fails_at_generation_not_construction() {
    let config = OtpConfig::builder(
        OtpKind::Motp,
        SecretBytes::from_hex("bfa47a0b71ac8f4d").unwrap(),
    )
    .build()
    .expect("an importer may learn the secret before the PIN");
    assert!(config.pin().is_none());
    assert!(config.generate_at(0).is_err());
}

/// Published third-party vectors: Aegis Authenticator, `MOTPTest.java`.
/// `(unix seconds, expected code, PIN, hex secret)`.
const AEGIS_MOTP: [(u64, &str, &str, &str); 6] = [
    (165_892_298, "e7d8b6", "1234", "e3152afee62599c8"),
    (123_456_789, "4ebfb2", "1234", "e3152afee62599c8"),
    (1_659_540_020, "ced7b1", "9999", "bbb1912bb5c515be"),
    // The same 10-second step: mOTP rounds the timestamp down.
    (1_659_540_022, "ced7b1", "9999", "bbb1912bb5c515be"),
    (1_659_539_870, "1a14f8", "9999", "bbb1912bb5c515be"),
    (1_659_539_878, "1a14f8", "9999", "bbb1912bb5c515be"),
];

#[test]
fn motp_matches_the_aegis_vectors() {
    for (unix_secs, expected, pin, secret_hex) in AEGIS_MOTP {
        let config = OtpConfig::motp(
            SecretBytes::from_hex(secret_hex).unwrap(),
            SecretBytes::from_slice(pin.as_bytes()),
        )
        .unwrap();
        assert_eq!(
            config.generate_at(unix_secs * 1_000).unwrap().value(),
            expected,
            "motp at {unix_secs} with pin {pin}"
        );
    }
}

/// Self-generated regression vectors, not authoritative. Kept for the
/// `bfa47a0b71ac8f4d` secret that the historical mOTP documentation uses, for
/// which no published code could be found.
#[test]
fn motp_frozen_vectors() {
    let config = OtpConfig::motp(
        SecretBytes::from_hex("bfa47a0b71ac8f4d").unwrap(),
        SecretBytes::from_slice(b"9999"),
    )
    .unwrap();
    for (unix_secs, expected) in [
        (0u64, "3cc9ab"),
        (10, "07c469"),
        (1_297_919_940, "69f4b6"),
        (1_234_567_890, "f78c12"),
        (1_111_111_109, "a26061"),
    ] {
        assert_eq!(
            config.generate_at(unix_secs * 1_000).unwrap().value(),
            expected,
            "motp at {unix_secs}"
        );
    }
}

// ------------------------------------------------------------- Blizzard

/// RFC 6238 Appendix B, SHA-1 column. Authoritative: a Battle.net authenticator
/// is RFC 6238 with SHA-1, 8 digits and a 30-second step, so these *are* the
/// Blizzard vectors.
const RFC6238_SHA1: [(u64, &str); 6] = [
    (59, "94287082"),
    (1_111_111_109, "07081804"),
    (1_111_111_111, "14050471"),
    (1_234_567_890, "89005924"),
    (2_000_000_000, "69279037"),
    (20_000_000_000, "65353130"),
];

#[test]
fn blizzard_defaults_match_the_variant() {
    let config = OtpConfig::blizzard(base32_secret()).unwrap();
    assert_eq!(config.kind(), OtpKind::Blizzard);
    assert_eq!(config.digits(), 8);
    assert_eq!(config.period(), 30);
    assert_eq!(config.algorithm(), HashAlg::Sha1);
}

#[test]
fn blizzard_is_rfc6238_with_sha1_and_eight_digits() {
    let blizzard = OtpConfig::blizzard(rfc_secret()).unwrap();
    let totp = OtpConfig::totp_with(rfc_secret(), HashAlg::Sha1, 8, 30).unwrap();

    for (unix_secs, expected) in RFC6238_SHA1 {
        let code = blizzard.generate_at(unix_secs * 1_000).unwrap();
        assert_eq!(code.value(), expected, "blizzard at {unix_secs}");
        assert_eq!(
            code.value(),
            totp.generate_at(unix_secs * 1_000).unwrap().value()
        );
    }
}

/// Battle.net distributes 20-byte secrets as 40 hex characters. The URI carries
/// base32, so check that the two paths land on the same secret.
#[test]
fn blizzard_hex_and_base32_secrets_agree() {
    let hex = "3132333435363738393031323334353637383930";
    let from_hex = OtpConfig::blizzard(SecretBytes::from_hex(hex).unwrap()).unwrap();
    let base32 = from_hex.secret().to_base32();
    let from_base32 = OtpConfig::blizzard(SecretBytes::from_base32(&base32).unwrap()).unwrap();
    for (unix_secs, expected) in RFC6238_SHA1 {
        assert_eq!(
            from_hex.generate_at(unix_secs * 1_000).unwrap().value(),
            expected
        );
        assert_eq!(
            from_base32.generate_at(unix_secs * 1_000).unwrap().value(),
            expected
        );
    }
}

// --------------------------------------------------------------- Yandex

/// Published third-party vectors: Aegis Authenticator, `YAOTPTest.java`.
/// `(PIN, base32 secret, unix seconds, expected code)`.
///
/// The secrets are the 26-byte form Yandex prints for manual entry: 16 bytes of
/// key plus a checksum. Only the first 16 bytes take part in the computation.
const AEGIS_YANDEX: [(&str, &str, u64, &str); 5] = [
    (
        "5239",
        "6SB2IKNM6OBZPAVBVTOHDKS4FAAAAAAADFUTQMBTRY",
        1_641_559_648,
        "umozdicq",
    ),
    (
        "7586",
        "LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI",
        1_581_064_020,
        "oactmacq",
    ),
    (
        "7586",
        "LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI",
        1_581_090_810,
        "wemdwrix",
    ),
    (
        "5210481216086702",
        "JBGSAU4G7IEZG6OY4UAXX62JU4AAAAAAHTSG4HXU3M",
        1_581_091_469,
        "dfrpywob",
    ),
    (
        "5210481216086702",
        "JBGSAU4G7IEZG6OY4UAXX62JU4AAAAAAHTSG4HXU3M",
        1_581_093_059,
        "vunyprpd",
    ),
];

fn yandex(pin: &str, secret_base32: &str) -> OtpConfig {
    OtpConfig::yandex(
        SecretBytes::from_base32(secret_base32).unwrap(),
        SecretBytes::from_slice(pin.as_bytes()),
    )
    .unwrap()
}

#[test]
fn yandex_defaults_match_the_variant() {
    let config = yandex("5239", AEGIS_YANDEX[0].1);
    assert_eq!(config.kind(), OtpKind::Yandex);
    assert_eq!(config.digits(), 8);
    assert_eq!(config.period(), 30);
    assert_eq!(config.algorithm(), HashAlg::Sha256);
    assert_eq!(OtpKind::Yandex.secret_prefix_used(), Some(16));
}

#[test]
fn yandex_matches_the_aegis_vectors() {
    for (pin, secret, unix_secs, expected) in AEGIS_YANDEX {
        let config = yandex(pin, secret);
        assert_eq!(
            config.generate_at(unix_secs * 1_000).unwrap().value(),
            expected,
            "yandex at {unix_secs} with pin {pin}"
        );
    }
}

/// The construction ignores everything past the 16th byte of the secret, which
/// is how the 26-byte printed form works. Getting this wrong would produce codes
/// that look perfectly plausible and never work.
#[test]
fn yandex_uses_only_the_first_sixteen_secret_bytes() {
    for (pin, secret, unix_secs, expected) in AEGIS_YANDEX {
        let full = SecretBytes::from_base32(secret).unwrap();
        assert_eq!(full.len(), 26);
        let truncated = SecretBytes::from_slice(&full.expose_secret()[..16]);

        let from_truncated =
            OtpConfig::yandex(truncated, SecretBytes::from_slice(pin.as_bytes())).unwrap();
        assert_eq!(
            from_truncated
                .generate_at(unix_secs * 1_000)
                .unwrap()
                .value(),
            expected
        );

        // Corrupting the checksum tail must not change the code.
        let mut tampered = full.expose_secret().to_vec();
        tampered[20] ^= 0xFF;
        let from_tampered = OtpConfig::yandex(
            SecretBytes::new(tampered),
            SecretBytes::from_slice(pin.as_bytes()),
        )
        .unwrap();
        assert_eq!(
            from_tampered
                .generate_at(unix_secs * 1_000)
                .unwrap()
                .value(),
            expected
        );
    }
}

#[test]
fn yandex_codes_are_eight_lowercase_letters() {
    let config = yandex("5239", AEGIS_YANDEX[0].1);
    let mut seen_last = std::collections::HashSet::new();
    for step in 0..300u64 {
        let code = config.generate_at(step * 30_000).unwrap();
        assert_eq!(code.len(), 8);
        assert!(
            code.value().chars().all(|ch| ch.is_ascii_lowercase()),
            "{code}"
        );
        seen_last.insert(code.value().chars().next_back());
    }
    // The eight-byte truncation exists so that every position varies. A
    // 31-bit truncation would pin the trailing characters to a handful of
    // values, which is the bug this assertion is here to catch.
    assert!(
        seen_last.len() > 20,
        "only {} distinct final characters",
        seen_last.len()
    );
}

#[test]
fn yandex_without_a_pin_fails_at_generation_not_construction() {
    let config = OtpConfig::builder(
        OtpKind::Yandex,
        SecretBytes::from_base32(AEGIS_YANDEX[0].1).unwrap(),
    )
    .build()
    .unwrap();
    assert!(config.pin().is_none());
    assert!(config.generate_at(0).is_err());
}

/// The PIN is part of the key, not a wrapper around it: a different PIN is a
/// different token, not a rejected one.
#[test]
fn yandex_pin_changes_the_code() {
    let (pin, secret, unix_secs, expected) = AEGIS_YANDEX[0];
    assert_eq!(
        yandex(pin, secret)
            .generate_at(unix_secs * 1_000)
            .unwrap()
            .value(),
        expected
    );
    for wrong in ["5238", "05239", "5239 "] {
        let code = yandex(wrong, secret)
            .generate_at(unix_secs * 1_000)
            .unwrap();
        assert_ne!(code.value(), expected, "pin {wrong:?}");
        assert_eq!(code.len(), 8);
    }
    // An empty PIN is no PIN, so it fails rather than keying with nothing.
    assert!(yandex("", secret).generate_at(unix_secs * 1_000).is_err());
}
