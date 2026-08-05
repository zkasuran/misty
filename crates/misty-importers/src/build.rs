// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Turning one vendor's fields into an [`OtpConfig`].
//!
//! Nine formats hand over the same seven values under different names, and the
//! rules for combining them are identical: the token type decides which
//! parameters are meaningful, the type's defaults fill in what the export left
//! out, and anything the type fixes overrides what the export claimed. Doing that
//! in one place is what keeps a Steam entry from importing as a 6-digit TOTP in
//! one importer and a 5-character Steam token in another.

use misty_otp::{HashAlg, OtpConfig, OtpKind, SecretBytes, SecretEncoding};

use crate::error::RowError;
use crate::outcome::ImportWarning;

/// The token type a vendor's string names.
///
/// Accepts the spellings that actually turn up in export files. Aegis writes
/// `yandex`, its own `otpauth://` output says `yaotp`, and 2FAS shouts `STEAM`.
#[must_use]
pub(crate) fn kind_from_str(value: &str) -> Option<OtpKind> {
    let value = value.trim();
    match value.to_ascii_lowercase().as_str() {
        "totp" | "time" | "time-based" | "otp" => Some(OtpKind::Totp),
        "hotp" | "counter" | "counter-based" => Some(OtpKind::Hotp),
        "steam" | "steamguard" | "steam-totp" => Some(OtpKind::Steam),
        "motp" | "mobile-otp" | "mobileotp" => Some(OtpKind::Motp),
        "yandex" | "yaotp" | "yandex.key" => Some(OtpKind::Yandex),
        "blizzard" | "battle.net" | "battlenet" | "bnet" => Some(OtpKind::Blizzard),
        _ => None,
    }
}

/// Decode a secret the way the token type encodes it.
///
/// mOTP secrets are hex and everything else is base32 — a distinction `misty-otp`
/// already owns, so it is read from [`OtpKind::secret_encoding`] rather than
/// restated here. A base32-looking secret in an mOTP entry is an error, not
/// something to reinterpret: the two decodings of the same string are different
/// keys, and the codes from the wrong one look perfectly plausible.
pub(crate) fn decode_secret(
    kind: OtpKind,
    raw: &str,
) -> core::result::Result<SecretBytes, RowError> {
    match kind.secret_encoding() {
        SecretEncoding::Base32 => SecretBytes::from_base32(raw),
        SecretEncoding::Hex => SecretBytes::from_hex(raw),
        SecretEncoding::Text => Ok(SecretBytes::from_slice(raw.as_bytes())),
    }
    .map_err(RowError::Otp)
}

/// One export's OTP fields, before interpretation.
#[derive(Debug, Default)]
pub(crate) struct OtpFields<'a> {
    /// The vendor's type string. `None` means the format has only one type.
    pub kind: Option<&'a str>,
    /// The type to assume when `kind` is absent.
    pub default_kind: OtpKind,
    /// The encoded secret.
    pub secret: Option<&'a str>,
    /// A secret the caller already decoded, for formats that store raw bytes.
    pub secret_bytes: Option<Vec<u8>>,
    /// The vendor's algorithm string.
    pub algorithm: Option<&'a str>,
    /// Digit count.
    pub digits: Option<u8>,
    /// Time step in seconds.
    pub period: Option<u16>,
    /// HOTP counter.
    pub counter: Option<u64>,
    /// mOTP or Yandex PIN, as literal text.
    ///
    /// Literal, not base32: the base32 PIN is an `otpauth://yaotp/` URI
    /// convention (SPEC 7), and every JSON export that carries a Yandex PIN
    /// stores the digits the user types.
    pub pin: Option<&'a str>,
}

/// Build a validated configuration, or say which field made it impossible.
///
/// Returns the warnings the caller should attach to the row: which parameters were
/// assumed because the export did not state them, and which were normalized
/// because the token type fixes them.
pub(crate) fn config(
    fields: &OtpFields<'_>,
) -> core::result::Result<(OtpConfig, Vec<ImportWarning>), RowError> {
    let mut warnings = Vec::new();

    let kind = match fields.kind {
        Some(raw) => kind_from_str(raw).ok_or(RowError::InvalidField("type"))?,
        None => fields.default_kind,
    };

    let secret = match (&fields.secret_bytes, fields.secret) {
        (Some(bytes), _) => SecretBytes::from_slice(bytes),
        (None, Some(raw)) => decode_secret(kind, raw)?,
        (None, None) => return Err(RowError::MissingField("secret")),
    };

    let mut builder = OtpConfig::builder(kind, secret);

    match fields.algorithm {
        Some(raw) => {
            let algorithm = raw.parse::<HashAlg>().map_err(|_| {
                // A hash this crate does not implement — MD5, SHA-224 — is a
                // rejection rather than a downgrade to SHA-1: codes from the
                // wrong hash are indistinguishable from a wrong secret.
                RowError::InvalidField("algorithm")
            })?;
            if kind
                .fixed_algorithm()
                .is_some_and(|fixed| fixed != algorithm)
            {
                warnings.push(ImportWarning::NormalizedParam("algorithm"));
            }
            builder = builder.algorithm(algorithm);
        }
        None => {
            if kind.fixed_algorithm().is_none() {
                warnings.push(ImportWarning::AssumedDefault("algorithm"));
            }
        }
    }

    match fields.digits {
        Some(digits) => {
            if kind.fixed_digits().is_some_and(|fixed| fixed != digits) {
                warnings.push(ImportWarning::NormalizedParam("digits"));
            }
            builder = builder.digits(digits);
        }
        None => {
            if kind.fixed_digits().is_none() {
                warnings.push(ImportWarning::AssumedDefault("digits"));
            }
        }
    }

    match fields.period {
        Some(period) => {
            if kind.fixed_period().is_some_and(|fixed| fixed != period) {
                warnings.push(ImportWarning::NormalizedParam("period"));
            }
            builder = builder.period(period);
        }
        None => {
            if kind.fixed_period().is_none() && kind.is_time_based() {
                warnings.push(ImportWarning::AssumedDefault("period"));
            }
        }
    }

    if kind.uses_counter() {
        match fields.counter {
            Some(counter) => builder = builder.counter(counter),
            // SPEC 7.2: a defaulted HOTP counter silently desynchronizes a token.
            // It cannot be refused here — plenty of exports omit a counter of zero
            // — but it must not pass unremarked.
            None => warnings.push(ImportWarning::AssumedDefault("counter")),
        }
    } else if fields.counter.is_some_and(|counter| counter != 0) {
        warnings.push(ImportWarning::NormalizedParam("counter"));
    }

    match (kind.uses_pin(), fields.pin) {
        (true, Some(pin)) => {
            builder = builder.pin(Some(SecretBytes::from_slice(pin.as_bytes())));
        }
        (true, None) => {
            // Not an error: `misty-otp` lets an importer learn a secret before the
            // user supplies the PIN, and generation is where it becomes a problem.
            warnings.push(ImportWarning::AssumedDefault("pin"));
        }
        (false, Some(_)) => warnings.push(ImportWarning::NormalizedParam("pin")),
        (false, None) => {}
    }

    let config = builder.build().map_err(RowError::Otp)?;
    Ok((config, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMMY: &str = "AAAAAAAAAAAAAAAA";

    #[test]
    fn every_spelling_vendors_use_maps_to_a_kind() {
        for (spelling, expected) in [
            ("TOTP", OtpKind::Totp),
            ("totp", OtpKind::Totp),
            ("HOTP", OtpKind::Hotp),
            ("Steam", OtpKind::Steam),
            ("motp", OtpKind::Motp),
            ("yandex", OtpKind::Yandex),
            ("yaotp", OtpKind::Yandex),
            ("battle.net", OtpKind::Blizzard),
        ] {
            assert_eq!(kind_from_str(spelling), Some(expected), "{spelling}");
        }
        assert_eq!(kind_from_str("carrier pigeon"), None);
        assert_eq!(kind_from_str(""), None);
    }

    #[test]
    fn defaults_are_reported_rather_than_silently_taken() {
        let (built, warnings) = config(&OtpFields {
            secret: Some(DUMMY),
            ..OtpFields::default()
        })
        .expect("builds");
        assert_eq!(built.kind(), OtpKind::Totp);
        assert_eq!(built.digits(), 6);
        assert_eq!(built.period(), 30);
        assert_eq!(built.algorithm(), HashAlg::Sha1);
        assert_eq!(
            warnings,
            vec![
                ImportWarning::AssumedDefault("algorithm"),
                ImportWarning::AssumedDefault("digits"),
                ImportWarning::AssumedDefault("period"),
            ]
        );
    }

    #[test]
    fn a_type_that_fixes_a_parameter_normalizes_it_with_a_warning() {
        let (built, warnings) = config(&OtpFields {
            kind: Some("steam"),
            secret: Some(DUMMY),
            digits: Some(6),
            period: Some(60),
            algorithm: Some("SHA256"),
            ..OtpFields::default()
        })
        .expect("builds");
        assert_eq!(built.digits(), 5);
        assert_eq!(built.period(), 30);
        assert_eq!(built.algorithm(), HashAlg::Sha1);
        assert!(warnings.contains(&ImportWarning::NormalizedParam("digits")));
        assert!(warnings.contains(&ImportWarning::NormalizedParam("period")));
        assert!(warnings.contains(&ImportWarning::NormalizedParam("algorithm")));
    }

    #[test]
    fn an_hotp_entry_with_no_counter_says_so() {
        let (built, warnings) = config(&OtpFields {
            kind: Some("hotp"),
            secret: Some(DUMMY),
            ..OtpFields::default()
        })
        .expect("builds");
        assert_eq!(built.counter(), 0);
        assert!(warnings.contains(&ImportWarning::AssumedDefault("counter")));
    }

    #[test]
    fn motp_secrets_are_hex_and_base32_is_not_reinterpreted() {
        let (built, _) = config(&OtpFields {
            kind: Some("motp"),
            secret: Some("bfa47a0b71ac8f4d"),
            pin: Some("1234"),
            ..OtpFields::default()
        })
        .expect("builds");
        assert_eq!(built.secret().len(), 8);
        assert_eq!(
            built.pin().map(|pin| pin.expose_secret().to_vec()),
            Some(b"1234".to_vec())
        );

        // `AAAAAAAAAAAAAAAA` is valid hex as well as valid base32, so the case that
        // proves mOTP is not reinterpreting base32 needs a secret that is only
        // base32: J, S, W, Y, K and X are outside the hex alphabet.
        assert!(matches!(
            config(&OtpFields {
                kind: Some("motp"),
                secret: Some("JBSWY3DPEHPK3PXP"),
                ..OtpFields::default()
            }),
            Err(RowError::Otp(_))
        ));
    }

    #[test]
    fn unusable_fields_name_themselves_and_never_the_value() {
        let error = config(&OtpFields {
            kind: Some("carrier pigeon"),
            secret: Some(DUMMY),
            ..OtpFields::default()
        })
        .expect_err("unknown type");
        assert_eq!(error, RowError::InvalidField("type"));

        let error = config(&OtpFields {
            secret: Some(DUMMY),
            algorithm: Some("MD5"),
            ..OtpFields::default()
        })
        .expect_err("md5 is not a supported hash");
        assert_eq!(error, RowError::InvalidField("algorithm"));

        let error = config(&OtpFields {
            secret: Some("!!!! not base32 !!!!"),
            ..OtpFields::default()
        })
        .expect_err("undecodable secret");
        assert!(!error.to_string().contains("not base32 !!!!"));

        assert_eq!(
            config(&OtpFields::default()).expect_err("no secret"),
            RowError::MissingField("secret")
        );
    }
}
