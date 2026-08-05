// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Property tests for the invariants that must hold for *every* input, not just
//! the ones someone thought to write down.
//!
//! The headline property is SPEC 7's: `parse -> model -> serialize -> parse`
//! yields an identical model.

use proptest::prelude::*;
use proptest::sample::select;
use proptest::test_runner::TestCaseError;

use misty_otp::{
    base32, hotp, HashAlg, OtpConfig, OtpError, OtpKind, OtpUri, SecretBytes, MAX_DIGITS,
    MAX_PERIOD, MIN_DIGITS, MIN_PERIOD,
};

fn secret_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=64)
}

fn kinds() -> impl Strategy<Value = OtpKind> {
    select(OtpKind::ALL.to_vec())
}

fn algorithms() -> impl Strategy<Value = HashAlg> {
    select(vec![HashAlg::Sha1, HashAlg::Sha256, HashAlg::Sha512])
}

/// Printable ASCII plus a slice of Latin-1 and CJK, and nothing that decoding
/// would legitimately reject: no controls, no bidi overrides.
fn text() -> impl Strategy<Value = String> {
    prop::string::string_regex("[ -~\u{a1}-\u{ff}\u{4e00}-\u{4e05}]{0,24}").expect("valid regex")
}

fn pins() -> impl Strategy<Value = Option<SecretBytes>> {
    prop_oneof![
        1 => Just(None),
        3 => prop::string::string_regex("[0-9]{1,8}")
            .expect("valid regex")
            .prop_map(|pin| Some(SecretBytes::from_slice(pin.as_bytes()))),
    ]
}

prop_compose! {
    fn configs()(
        kind in kinds(),
        secret in secret_bytes(),
        algorithm in algorithms(),
        digits in MIN_DIGITS..=MAX_DIGITS,
        period in MIN_PERIOD..=MAX_PERIOD,
        counter in any::<u64>(),
        pin in pins(),
    ) -> OtpConfig {
        OtpConfig::builder(kind, SecretBytes::new(secret))
            .algorithm(algorithm)
            .digits(digits)
            .period(period)
            .counter(counter)
            .pin(pin)
            .build()
            .expect("every generated parameter is in range")
    }
}

prop_compose! {
    fn uris()(
        config in configs(),
        issuer in prop::option::of(text()),
        account in text(),
        extra in prop::collection::vec((text(), text()), 0..4),
    ) -> OtpUri {
        OtpUri::new(config, issuer, account).with_extra(extra)
    }
}

// URI-shaped strings, most of which are valid and all of which exercise the
// parser's decision points.
prop_compose! {
    fn uri_strings()(
        // Weighted toward valid inputs so most cases reach the round-trip
        // assertions rather than stopping at a rejection.
        scheme in select(vec!["otpauth", "otpauth", "otpauth", "OTPAUTH", "OtpAuth", "otpauth-migration", "totp", ""]),
        kind in select(vec![
            "totp", "totp", "hotp", "steam", "motp", "yandex", "yaotp", "blizzard", "blizzard", "TOTP",
            "Hotp", "nope", "",
        ]),
        label in prop::string::string_regex("[a-zA-Z0-9%:@. \u{e9}-]{0,20}").expect("valid regex"),
        secret in select(vec![
            "JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP", "jbswy3dp", "JBSW-Y3DP", "MZXW6===",
            "bfa47a0b71ac8f4d", "", "A", "!!", "12345678901234567890",
        ]),
        params in prop::collection::vec(
            select(vec![
                "digits=6", "digits=8", "digits=0", "digits=255", "period=30", "period=0",
                "period=3600", "counter=1", "counter=-1", "algorithm=SHA256", "algorithm=sha-512",
                "algorithm=nope", "pin=1234", "pin=GEZDGNA", "issuer=ACME", "issuer=", "image=x%3Ay", "foo=bar",
                "foo=bar", "secret=MZXW6", "", "flag",
            ]),
            0..6,
        ),
        fragment in select(vec!["", "#", "#notes"]),
    ) -> String {
        let mut uri = format!("{scheme}://{kind}/{label}?secret={secret}");
        for param in params {
            uri.push('&');
            uri.push_str(param);
        }
        uri.push_str(fragment);
        uri
    }
}

fn fail(context: &str, error: &impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(format!("{context}: {error}"))
}

proptest! {
    /// SPEC 3: `digits` is a promise about the rendered code, for every variant.
    #[test]
    fn code_length_always_equals_digits(
        config in configs(),
        unix_ms in 0u64..=4_000_000_000_000,
    ) {
        match config.generate_at(unix_ms) {
            Ok(code) => {
                prop_assert_eq!(code.len(), usize::from(config.digits()));
                prop_assert_eq!(code.value().chars().count(), usize::from(config.digits()));
            }
            Err(error) => {
                // The only legitimate failure is a variant that needs a PIN.
                prop_assert!(
                    config.kind().uses_pin() && config.pin().is_none(),
                    "unexpected failure: {}", error
                );
                prop_assert!(matches!(error, OtpError::MissingPin(_)));
            }
        }
    }

    /// SPEC 6.5: the UI must be able to draw a countdown from the code alone.
    #[test]
    fn window_invariants_hold(
        config in configs(),
        unix_ms in 0u64..=4_000_000_000_000,
    ) {
        prop_assume!(!(config.kind().uses_pin() && config.pin().is_none()));
        let code = config.generate_at(unix_ms).map_err(|e| fail("generate_at", &e))?;
        let period_ms = u64::from(config.period()) * 1_000;

        if config.kind().uses_counter() {
            prop_assert_eq!(code.window(), None);
            return Ok(());
        }

        let window = code.window().expect("time-based codes have a window");
        prop_assert!(window.remaining_ms >= 1);
        prop_assert!(window.remaining_ms <= period_ms);
        prop_assert!(window.progress >= 0.0);
        prop_assert!(window.progress < 1.0);
        prop_assert_eq!(window.valid_from_ms % period_ms, 0);
        prop_assert_eq!(window.valid_until_ms - window.valid_from_ms, period_ms);
        prop_assert!(window.valid_from_ms <= unix_ms);
        prop_assert!(unix_ms < window.valid_until_ms);
        prop_assert_eq!(window.remaining_ms, window.valid_until_ms - unix_ms);

        // The next code claims the next window, from its start.
        let next = code_or_fail(&config, window.valid_until_ms)?;
        let peeked = config.next_code_at(unix_ms).map_err(|e| fail("next_code_at", &e))?;
        prop_assert_eq!(peeked.value(), next.value());
        prop_assert_eq!(peeked.remaining_ms(), Some(period_ms));
        prop_assert_eq!(peeked.progress(), Some(0.0));
    }

    /// Codes do not change within a window, and the window is the largest span
    /// for which that is true.
    #[test]
    fn codes_are_constant_within_their_window(
        config in configs(),
        unix_ms in 0u64..=4_000_000_000_000,
        offset in 0u64..3_600_000,
    ) {
        prop_assume!(!(config.kind().uses_pin() && config.pin().is_none()));
        prop_assume!(!config.kind().uses_counter());
        let first = code_or_fail(&config, unix_ms)?;
        let window = first.window().expect("time-based");
        let inside = window.valid_from_ms + (offset % (window.valid_until_ms - window.valid_from_ms));
        let second = code_or_fail(&config, inside)?;
        prop_assert_eq!(first.value(), second.value());
        prop_assert_eq!(second.valid_from_ms(), Some(window.valid_from_ms));
    }

    #[test]
    fn base32_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..=256)) {
        let encoded = base32::encode(&bytes);
        let padded = base32::encode_padded(&bytes);

        prop_assert_eq!(base32::decode(&encoded).map_err(|e| fail("decode", &e))?, bytes.clone());
        prop_assert_eq!(base32::decode(&padded).map_err(|e| fail("decode padded", &e))?, bytes.clone());
        prop_assert_eq!(padded.len() % 8, 0);
        prop_assert!(padded.starts_with(&encoded));
        prop_assert!(encoded.chars().all(|ch| ch.is_ascii_uppercase() || ('2'..='7').contains(&ch)));

        // Case, hyphens and whitespace are noise, per SPEC 7.
        let lowered = encoded.to_ascii_lowercase();
        prop_assert_eq!(base32::decode(&lowered).map_err(|e| fail("decode lowercase", &e))?, bytes.clone());
        let grouped: String = encoded
            .as_bytes()
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("- ");
        prop_assert_eq!(base32::decode(&grouped).map_err(|e| fail("decode grouped", &e))?, bytes);
    }

    #[test]
    fn base32_decoding_never_panics(input in ".{0,300}") {
        let _ = base32::decode(&input);
    }

    #[test]
    fn hex_secrets_round_trip(bytes in secret_bytes()) {
        let secret = SecretBytes::new(bytes);
        let hex = secret.to_hex();
        prop_assert_eq!(
            SecretBytes::from_hex(&hex).map_err(|e| fail("from_hex", &e))?,
            secret.clone()
        );
        prop_assert_eq!(
            SecretBytes::from_hex(&hex.to_ascii_uppercase()).map_err(|e| fail("from_hex", &e))?,
            secret
        );
    }

    /// SPEC 7: a model survives serialization exactly — except `Blizzard`, whose
    /// deliberate normalization to `totp` is asserted rather than excused.
    #[test]
    fn uri_models_round_trip(uri in uris()) {
        let serialized = uri.to_uri();
        let parsed = OtpUri::parse(&serialized).map_err(|e| fail("parse", &e))?;

        let kind = uri.config().kind();
        if kind == kind.serializes_as() {
            prop_assert_eq!(&parsed, &uri);
        } else {
            prop_assert_eq!(kind, OtpKind::Blizzard);
            prop_assert_eq!(parsed.config().kind(), OtpKind::Totp);
            prop_assert_eq!(parsed.config().digits(), 8);
            prop_assert_eq!(parsed.config().period(), 30);
            prop_assert_eq!(parsed.config().algorithm(), HashAlg::Sha1);
            prop_assert_eq!(parsed.issuer(), uri.issuer());
            prop_assert_eq!(parsed.account(), uri.account());
            // Behaviourally identical, which is the property that matters.
            for unix_ms in [0u64, 59_000, 1_234_567_890_000] {
                let from_blizzard = uri
                    .config()
                    .generate_at(unix_ms)
                    .map_err(|e| fail("blizzard", &e))?;
                let from_totp = parsed
                    .config()
                    .generate_at(unix_ms)
                    .map_err(|e| fail("totp", &e))?;
                prop_assert_eq!(from_blizzard.value(), from_totp.value());
            }
        }
        prop_assert_eq!(&parsed, &uri.export_form());
        prop_assert_eq!(&*parsed.to_uri(), &*serialized);
        prop_assert_eq!(&*uri.export_form().to_uri(), &*serialized);
    }

    /// SPEC 7, stated the way the spec states it: for any input that parses at
    /// all, `parse -> serialize -> parse` is the identity on the model — strictly
    /// for every kind but `Blizzard`, which is documented to export as `totp` and
    /// so lands on its `export_form` instead.
    #[test]
    fn uri_parsing_round_trips_or_errors(input in uri_strings()) {
        let Ok(first) = OtpUri::parse(&input) else {
            return Ok(());
        };
        let serialized = first.to_uri();
        let second = OtpUri::parse(&serialized).map_err(|e| fail("reparse", &e))?;

        let kind = first.config().kind();
        if kind == kind.serializes_as() {
            prop_assert_eq!(&first, &second);
        } else {
            prop_assert_eq!(kind, OtpKind::Blizzard);
            prop_assert_eq!(second.config().kind(), OtpKind::Totp);
            prop_assert_eq!(
                first.config().generate_at(1_234_567_890_000).ok().map(|c| c.value().to_owned()),
                second.config().generate_at(1_234_567_890_000).ok().map(|c| c.value().to_owned())
            );
        }
        prop_assert_eq!(&second, &first.export_form());
        prop_assert_eq!(&*second.to_uri(), &*serialized);
        // A canonical URI parses without warnings.
        let (_, warnings) = OtpUri::parse_with_warnings(&serialized)
            .map_err(|e| fail("reparse with warnings", &e))?;
        prop_assert!(warnings.is_empty(), "{:?}", warnings);
    }

    #[test]
    fn uri_parsing_never_panics(input in ".{0,400}") {
        let _ = OtpUri::parse(&input);
    }

    #[test]
    fn hotp_codes_have_the_requested_length(
        secret in secret_bytes(),
        counter in any::<u64>(),
        digits in MIN_DIGITS..=MAX_DIGITS,
        algorithm in algorithms(),
    ) {
        let code = hotp(&SecretBytes::new(secret), counter, digits, algorithm)
            .map_err(|e| fail("hotp", &e))?;
        prop_assert_eq!(code.len(), usize::from(digits));
        prop_assert!(code.value().chars().all(|ch| ch.is_ascii_digit()));
        prop_assert_eq!(code.window(), None);
    }

    /// Resynchronization finds *a* counter that produces the observed code, and
    /// never one past it. It may find an earlier collision, which is inherent to
    /// a short code space rather than a bug.
    #[test]
    fn resync_finds_a_counter_that_produces_the_code(
        secret in secret_bytes(),
        start in any::<u64>(),
        offset in 0u64..=32,
        digits in MIN_DIGITS..=MAX_DIGITS,
    ) {
        let start = start.min(u64::MAX - 64);
        let secret = SecretBytes::new(secret);
        let config = OtpConfig::hotp_with(secret.clone(), HashAlg::Sha1, digits, start)
            .map_err(|e| fail("config", &e))?;
        let observed = hotp(&secret, start + offset, digits, HashAlg::Sha1)
            .map_err(|e| fail("hotp", &e))?;

        let found = config.resync_counter(observed.value(), 32);
        prop_assert!(found.is_some());
        let found = found.expect("checked");
        prop_assert!(found >= start);
        prop_assert!(found <= start + offset);
        let regenerated = hotp(&secret, found, digits, HashAlg::Sha1)
            .map_err(|e| fail("hotp", &e))?;
        prop_assert_eq!(regenerated.value(), observed.value());
    }
}

/// Generate at `unix_ms`, turning a failure into a test failure with context.
fn code_or_fail(config: &OtpConfig, unix_ms: u64) -> Result<misty_otp::Code, TestCaseError> {
    config
        .generate_at(unix_ms)
        .map_err(|error| fail("generate_at", &error))
}
