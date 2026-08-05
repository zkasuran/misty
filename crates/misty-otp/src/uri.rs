// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `otpauth://` URI parsing and serialization.
//!
//! The format has no RFC. The de facto specification is Google's Key Uri Format
//! wiki page, and real-world producers deviate from it freely, so this parser is
//! written to a simple rule: be liberal about *shape* (case, missing padding,
//! unknown parameters, an absent label) and strict about *meaning* (never guess a
//! digit count, never guess which of two `secret` parameters was meant, never
//! silently drop a parameter it did not understand).
//!
//! # Round-tripping
//!
//! `parse -> model -> to_uri -> parse` yields an identical model (SPEC 7). That
//! is a property test, not a claim: see `tests/proptests.rs`. Three details make
//! it hold:
//!
//! * A colon inside an issuer or account is written `%3A`, so the only raw colon
//!   in a label is the separator. The label is therefore split *before*
//!   percent-decoding, and an issuer containing a colon survives.
//! * Parameters a variant fixes (Steam's 5 characters, mOTP's 10-second step)
//!   are normalized on parse and omitted on write, so a second parse recomputes
//!   the same values.
//! * Unknown parameters are preserved in order rather than dropped, because a
//!   vendor extension is somebody's icon or colour and losing it on re-export is
//!   data loss.
//!
//! There is exactly one documented exception, [`OtpKind::Blizzard`]: it is
//! written as `totp`, because its algorithm is identical to 8-digit SHA-1 TOTP
//! and a private type marker would only stop other authenticators importing our
//! export. Round-tripping a Blizzard URI therefore yields a
//! [`OtpKind::Totp`] model that generates the same codes at the same instants —
//! [`OtpUri::export_form`] is that model, and equality against it holds for every
//! kind. See [`OtpKind::serializes_as`] for why that trade is the right way
//! round.
//!
//! # Serialized URIs contain the secret
//!
//! [`OtpUri::to_uri`] returns a [`Zeroizing<String>`], and [`OtpUri`]
//! deliberately implements neither `Display` nor `ToString`, so it cannot reach a
//! log line through `{}`. For an mOTP or Yandex token the URI also contains the
//! PIN: a QR code of one of these is a complete credential.

use core::fmt;

use zeroize::Zeroizing;

use crate::base32;
use crate::config::{HashAlg, OtpConfig, OtpKind, SecretEncoding};
use crate::error::{OtpError, Result, UriError};
use crate::percent;
use crate::secret::SecretBytes;

/// Longest URI [`OtpUri::parse`] will look at, in bytes.
///
/// Real provisioning URIs are 100 to 300 bytes. The cap keeps a hostile QR code
/// from turning into a large allocation before anything is validated.
pub const MAX_URI_LEN: usize = 4096;

/// Query parameters this crate understands. Anything else is preserved verbatim.
const KNOWN_PARAMS: [&str; 7] = [
    "secret",
    "issuer",
    "algorithm",
    "digits",
    "period",
    "counter",
    "pin",
];

/// Something a URI got away with, that the caller may want to show the user.
///
/// Warnings are not part of the model: they describe the *input*, and a
/// canonical URI produced by [`OtpUri::to_uri`] parses without any. Keeping them
/// out of [`OtpUri`] is what lets round-trip equality be exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriWarning {
    /// The label and the `issuer` parameter disagreed. The parameter won.
    IssuerMismatch {
        /// Issuer taken from the `Issuer:account` label.
        label: String,
        /// Issuer taken from the `issuer=` parameter, which is what was kept.
        parameter: String,
    },
    /// A parameter that is fixed or meaningless for this variant was normalized
    /// away — `digits` on a Steam token, `counter` on a TOTP token.
    IgnoredParam {
        /// The parameter name.
        name: &'static str,
    },
    /// A `#fragment` was present. Fragments carry no otpauth meaning and are
    /// dropped.
    FragmentIgnored,
}

impl fmt::Display for UriWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IssuerMismatch { label, parameter } => write!(
                f,
                "label issuer {label:?} disagrees with the issuer parameter {parameter:?}; \
                 using the parameter"
            ),
            Self::IgnoredParam { name } => {
                write!(f, "parameter {name:?} does not apply here and was ignored")
            }
            Self::FragmentIgnored => f.write_str("uri fragment ignored"),
        }
    }
}

/// A parsed `otpauth://` URI: an [`OtpConfig`] plus the naming around it.
///
/// The issuer and account live here rather than in [`OtpConfig`] because that is
/// where SPEC 3 puts them — they are `Item` fields, not OTP parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpUri {
    config: OtpConfig,
    issuer: Option<String>,
    account: String,
    extra: Vec<(String, String)>,
}

impl OtpUri {
    /// Assemble a URI model. An empty issuer is stored as `None`.
    #[must_use]
    pub fn new(config: OtpConfig, issuer: Option<String>, account: impl Into<String>) -> Self {
        Self {
            config,
            issuer: issuer.filter(|issuer| !issuer.is_empty()),
            account: account.into(),
            extra: Vec::new(),
        }
    }

    /// Attach vendor parameters, dropping any that would collide with a
    /// parameter this crate owns (which would make the result ambiguous on
    /// re-parse) or that have an empty name.
    #[must_use]
    pub fn with_extra(mut self, extra: Vec<(String, String)>) -> Self {
        self.extra = extra
            .into_iter()
            .filter(|(name, _)| !name.is_empty() && !is_known_param(name))
            .collect();
        self
    }

    /// The OTP parameters.
    #[must_use]
    pub fn config(&self) -> &OtpConfig {
        &self.config
    }

    /// The OTP parameters, mutably. Every [`OtpConfig`] setter validates, so this
    /// cannot be used to build something ungeneratable.
    pub fn config_mut(&mut self) -> &mut OtpConfig {
        &mut self.config
    }

    /// The issuer, from the `issuer` parameter or the label.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// The account name. May be empty: plenty of real QR codes have no label.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Vendor parameters, in the order they appeared.
    #[must_use]
    pub fn extra(&self) -> &[(String, String)] {
        &self.extra
    }

    /// Parse an `otpauth://` URI, discarding warnings.
    ///
    /// # Errors
    ///
    /// [`OtpError`] for anything malformed. This function never panics for any
    /// input, which is what makes it usable on a scanned QR code.
    pub fn parse(input: &str) -> Result<Self> {
        Self::parse_with_warnings(input).map(|(uri, _)| uri)
    }

    /// Parse an `otpauth://` URI, reporting what the input got away with.
    ///
    /// Warnings are advisory: the model is already normalized when they are
    /// returned. A URI produced by [`OtpUri::to_uri`] always parses with none.
    ///
    /// # Errors
    ///
    /// [`OtpError::Uri`] for a structural problem, [`OtpError::InvalidDigits`] /
    /// [`OtpError::InvalidPeriod`] for an out-of-range parameter, or
    /// [`OtpError::Base32`] / [`OtpError::InvalidHexSecret`] for an undecodable
    /// secret.
    ///
    /// # Examples
    ///
    /// ```
    /// use misty_otp::{OtpUri, UriWarning};
    ///
    /// let (uri, warnings) = OtpUri::parse_with_warnings(
    ///     "otpauth://totp/Wrong:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Right",
    /// )?;
    /// assert_eq!(uri.issuer(), Some("Right"));
    /// assert_eq!(
    ///     warnings,
    ///     vec![UriWarning::IssuerMismatch {
    ///         label: "Wrong".to_owned(),
    ///         parameter: "Right".to_owned(),
    ///     }]
    /// );
    /// # Ok::<(), misty_otp::OtpError>(())
    /// ```
    pub fn parse_with_warnings(input: &str) -> Result<(Self, Vec<UriWarning>)> {
        if input.len() > MAX_URI_LEN {
            return Err(UriError::TooLong {
                len: input.len(),
                max: MAX_URI_LEN,
            }
            .into());
        }
        let mut warnings = Vec::new();

        let rest = strip_scheme(input)?;
        let rest = match rest.split_once('#') {
            Some((head, _fragment)) => {
                warnings.push(UriWarning::FragmentIgnored);
                head
            }
            None => rest,
        };
        let (path, raw_query) = match rest.split_once('?') {
            Some(split) => split,
            None => (rest, ""),
        };
        let (authority, label) = match path.split_once('/') {
            Some(split) => split,
            None => (path, ""),
        };
        let kind = match OtpKind::from_uri_type(authority) {
            Some(kind) => kind,
            None => return Err(UriError::UnknownKind.into()),
        };

        // Split the label before percent-decoding: a colon that is part of a
        // name is still `%3A` at this point, so only the separator is a raw ':'.
        let (raw_label_issuer, raw_account) = match label.split_once(':') {
            Some((issuer, account)) => (Some(issuer), account),
            None => (None, label),
        };
        let label_issuer = match raw_label_issuer {
            Some(raw) => Some(percent::decode(raw)?).filter(|issuer| !issuer.is_empty()),
            None => None,
        };
        let account = percent::decode(raw_account)?;
        let query = Query::parse(raw_query)?;

        let secret = match &query.secret {
            Some(raw) => decode_field(kind.secret_encoding(), raw)?,
            None => return Err(UriError::MissingParam("secret").into()),
        };

        let algorithm = match &query.algorithm {
            Some(raw) => Some(raw.parse::<HashAlg>()?),
            None => None,
        };
        let digits = match &query.digits {
            Some(raw) => {
                let value = parse_u64(raw, "digits")?;
                Some(u8::try_from(value).map_err(|_| OtpError::InvalidDigits(value))?)
            }
            None => None,
        };
        let period = match &query.period {
            Some(raw) => {
                let value = parse_u64(raw, "period")?;
                Some(u16::try_from(value).map_err(|_| OtpError::InvalidPeriod(value))?)
            }
            None => None,
        };
        let counter = match &query.counter {
            Some(raw) => Some(parse_u64(raw, "counter")?),
            None => None,
        };

        // The Key Uri Format makes `counter` mandatory for HOTP, and defaulting
        // it would silently desynchronize a token.
        if kind.uses_counter() && counter.is_none() {
            return Err(UriError::MissingParam("counter").into());
        }

        // Say so whenever the variant is about to override the input.
        let overridden = [
            (
                "algorithm",
                matches!((algorithm, kind.fixed_algorithm()), (Some(a), Some(b)) if a != b),
            ),
            (
                "digits",
                matches!((digits, kind.fixed_digits()), (Some(a), Some(b)) if a != b),
            ),
            (
                "period",
                matches!((period, kind.fixed_period()), (Some(a), Some(b)) if a != b),
            ),
            ("counter", counter.is_some() && !kind.uses_counter()),
            ("pin", query.pin.is_some() && !kind.uses_pin()),
        ];
        warnings.extend(
            overridden
                .into_iter()
                .filter(|(_, ignored)| *ignored)
                .map(|(name, _)| UriWarning::IgnoredParam { name }),
        );

        let mut builder = OtpConfig::builder(kind, secret);
        if let Some(algorithm) = algorithm {
            builder = builder.algorithm(algorithm);
        }
        if let Some(digits) = digits {
            builder = builder.digits(digits);
        }
        if let Some(period) = period {
            builder = builder.period(period);
        }
        if let Some(counter) = counter {
            builder = builder.counter(counter);
        }
        if let Some(pin) = &query.pin {
            builder = builder.pin(Some(decode_pin(kind, pin)?));
        }
        let config = builder.build()?;

        let issuer = match (label_issuer, query.issuer.filter(|i| !i.is_empty())) {
            (Some(label), Some(parameter)) => {
                if label != parameter {
                    warnings.push(UriWarning::IssuerMismatch {
                        label,
                        parameter: parameter.clone(),
                    });
                }
                Some(parameter)
            }
            (Some(only), None) | (None, Some(only)) => Some(only),
            (None, None) => None,
        };

        let uri = Self {
            config,
            issuer,
            account,
            extra: query.extra,
        };

        // Percent-encoding can expand a name threefold, so an input under the
        // cap can canonicalize to something over it. Reject that here rather
        // than emit a URI this parser would refuse.
        let canonical_len = uri.to_uri().len();
        if canonical_len > MAX_URI_LEN {
            return Err(UriError::CanonicalTooLong {
                len: canonical_len,
                max: MAX_URI_LEN,
            }
            .into());
        }

        Ok((uri, warnings))
    }

    /// Serialize to a canonical `otpauth://` URI.
    ///
    /// Canonical means: lowercase scheme and type, `Issuer:account` label with
    /// every colon inside a name escaped, unpadded uppercase base32 secret (hex
    /// for mOTP), parameters in a fixed order, parameters the variant fixes
    /// omitted, and vendor parameters last in their original order.
    ///
    /// [`OtpKind::Blizzard`] is written as `totp` with `algorithm`, `digits` and
    /// `period` all stated explicitly, because its algorithm is exactly RFC 6238
    /// with SHA-1 and 8 digits and a private type marker would only stop other
    /// authenticators importing it. The URI is byte-identical to the one the
    /// equivalent [`OtpKind::Totp`] configuration produces. See
    /// [`OtpKind::serializes_as`] and [`OtpUri::export_form`].
    ///
    /// The result contains the secret, and the PIN for mOTP and Yandex. It is
    /// [`Zeroizing`] for that reason.
    #[must_use]
    pub fn to_uri(&self) -> Zeroizing<String> {
        // The kind whose *shape* is written, which is the kind itself for
        // everything except Blizzard.
        let kind = self.config.kind().serializes_as();
        let secret = encode_field(kind.secret_encoding(), self.config.secret().expose_secret());
        let account = percent::encode(&self.account);
        let issuer = self.issuer.as_deref().map(percent::encode);

        let extra_len: usize = self
            .extra
            .iter()
            .map(|(name, value)| name.len() + value.len() + 8)
            .sum();
        let capacity = 96
            + account.len()
            + issuer.as_ref().map_or(0, |issuer| issuer.len() * 2 + 12)
            + secret.len() * 3
            + extra_len;
        let mut out = Zeroizing::new(String::with_capacity(capacity));

        out.push_str("otpauth://");
        out.push_str(kind.uri_type());
        out.push('/');
        if let Some(issuer) = &issuer {
            out.push_str(issuer);
            out.push(':');
        }
        out.push_str(&account);

        out.push_str("?secret=");
        out.push_str(&secret);
        if let Some(issuer) = &issuer {
            out.push_str("&issuer=");
            out.push_str(issuer);
        }
        if kind.fixed_algorithm().is_none() {
            out.push_str("&algorithm=");
            out.push_str(self.config.algorithm().as_str());
        }
        if kind.fixed_digits().is_none() {
            out.push_str("&digits=");
            out.push_str(&self.config.digits().to_string());
        }
        if kind.fixed_period().is_none() {
            out.push_str("&period=");
            out.push_str(&self.config.period().to_string());
        }
        if kind.uses_counter() {
            out.push_str("&counter=");
            out.push_str(&self.config.counter().to_string());
        }
        if let Some(pin) = self.config.pin() {
            out.push_str("&pin=");
            out.push_str(&encode_field(kind.pin_encoding(), pin.expose_secret()));
        }
        for (name, value) in &self.extra {
            out.push('&');
            out.push_str(&percent::encode(name));
            out.push('=');
            out.push_str(&percent::encode(value));
        }

        out
    }

    /// The model this one's [`OtpUri::to_uri`] output parses back into.
    ///
    /// The identity for every kind but [`OtpKind::Blizzard`], which exports as
    /// plain 8-digit SHA-1 [`OtpKind::Totp`] so that other authenticators can
    /// import it (see [`OtpKind::serializes_as`]). The returned configuration
    /// generates the same codes at the same instants; only the label the UI shows
    /// is lost.
    ///
    /// Use it to tell a user what an export will look like on the way back in, or
    /// to state the round-trip property exactly:
    ///
    /// ```
    /// use misty_otp::{OtpKind, OtpUri};
    ///
    /// let uri = OtpUri::parse("otpauth://blizzard/Battle.net:ada?secret=JBSWY3DPEHPK3PXP")?;
    /// assert_eq!(uri.config().kind(), OtpKind::Blizzard);
    ///
    /// let exported = OtpUri::parse(&uri.to_uri())?;
    /// assert_eq!(exported.config().kind(), OtpKind::Totp);
    /// assert_eq!(exported, uri.export_form());
    /// assert_eq!(
    ///     exported.config().generate_at(1_234_567_890_000)?.value(),
    ///     uri.config().generate_at(1_234_567_890_000)?.value()
    /// );
    /// # Ok::<(), misty_otp::OtpError>(())
    /// ```
    #[must_use]
    pub fn export_form(&self) -> Self {
        let wire = self.config.kind().serializes_as();
        if wire == self.config.kind() {
            return self.clone();
        }
        Self {
            config: self.config.with_kind(wire),
            issuer: self.issuer.clone(),
            account: self.account.clone(),
            extra: self.extra.clone(),
        }
    }
}

/// Strip and validate the scheme.
fn strip_scheme(input: &str) -> Result<&str> {
    let Some((scheme, rest)) = input.split_once("://") else {
        return Err(UriError::NotOtpauth.into());
    };
    if scheme.eq_ignore_ascii_case("otpauth-migration") {
        return Err(UriError::MigrationUri.into());
    }
    if !scheme.eq_ignore_ascii_case("otpauth") {
        return Err(UriError::NotOtpauth.into());
    }
    Ok(rest)
}

/// Decode a `pin` parameter according to the variant's convention.
fn decode_pin(kind: OtpKind, value: &str) -> Result<SecretBytes> {
    decode_field(kind.pin_encoding(), value)
}

/// Decode a secret-shaped parameter. Length is checked by
/// [`OtpConfigBuilder::build`](crate::OtpConfigBuilder::build), so every entry
/// point reports the same error for the same problem.
fn decode_field(encoding: SecretEncoding, value: &str) -> Result<SecretBytes> {
    Ok(match encoding {
        SecretEncoding::Base32 => SecretBytes::new(base32::decode(value)?),
        SecretEncoding::Hex => SecretBytes::from_hex(value)?,
        SecretEncoding::Text => SecretBytes::from_slice(value.as_bytes()),
    })
}

/// Render a secret-shaped value for a URI. Zeroizing: it is the secret.
fn encode_field(encoding: SecretEncoding, bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(match encoding {
        SecretEncoding::Base32 => base32::encode(bytes),
        SecretEncoding::Hex => hex::encode(bytes),
        SecretEncoding::Text => percent::encode_bytes(bytes),
    })
}

/// Parse a decimal parameter. Rejects signs, whitespace and overflow rather than
/// clamping, because a token whose digit count was guessed is worse than one that
/// failed to import.
fn parse_u64(value: &str, name: &'static str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| OtpError::Uri(UriError::InvalidParam(name)))
}

fn is_known_param(name: &str) -> bool {
    KNOWN_PARAMS
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
}

/// The query string, decoded but not yet interpreted.
#[derive(Debug, Default)]
struct Query {
    secret: Option<Zeroizing<String>>,
    issuer: Option<String>,
    algorithm: Option<String>,
    digits: Option<String>,
    period: Option<String>,
    counter: Option<String>,
    pin: Option<Zeroizing<String>>,
    extra: Vec<(String, String)>,
}

impl Query {
    fn parse(query: &str) -> Result<Self> {
        let mut parsed = Self::default();

        for pair in query.split('&') {
            // Tolerate `&&` and a trailing `&`: harmless, and common.
            if pair.is_empty() {
                continue;
            }
            let (raw_name, raw_value) = match pair.split_once('=') {
                Some(split) => split,
                None => (pair, ""),
            };
            if raw_name.is_empty() {
                return Err(UriError::MalformedQuery.into());
            }
            let name = percent::decode(raw_name)?;
            let value = percent::decode(raw_value)?;

            // Known names match case-insensitively; unknown ones keep their case.
            match name.to_ascii_lowercase().as_str() {
                "secret" => set_once(&mut parsed.secret, "secret", Zeroizing::new(value))?,
                "issuer" => set_once(&mut parsed.issuer, "issuer", value)?,
                "algorithm" => set_once(&mut parsed.algorithm, "algorithm", value)?,
                "digits" => set_once(&mut parsed.digits, "digits", value)?,
                "period" => set_once(&mut parsed.period, "period", value)?,
                "counter" => set_once(&mut parsed.counter, "counter", value)?,
                "pin" => set_once(&mut parsed.pin, "pin", Zeroizing::new(value))?,
                _ => parsed.extra.push((name, value)),
            }
        }

        Ok(parsed)
    }
}

/// Reject a repeated parameter instead of picking one of its values.
fn set_once<T>(slot: &mut Option<T>, name: &'static str, value: T) -> Result<()> {
    if slot.is_some() {
        return Err(UriError::DuplicateParam(name).into());
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HashAlg;

    const TOTP: &str = "otpauth://totp/ACME:ada@example.com\
                        ?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30";

    fn parse(input: &str) -> OtpUri {
        OtpUri::parse(input).expect("should parse")
    }

    /// parse -> model -> serialize -> parse yields an identical model (SPEC 7).
    ///
    /// Strict equality for every kind whose URI type is its own. For
    /// [`OtpKind::Blizzard`], which exports as `totp` on purpose, the model comes
    /// back as [`OtpUri::export_form`] — asserted here too, so the exception is
    /// pinned rather than merely tolerated.
    fn assert_round_trips(input: &str) -> OtpUri {
        let first = parse(input);
        let serialized = first.to_uri();
        let second = parse(&serialized);

        let kind = first.config().kind();
        if kind == kind.serializes_as() {
            assert_eq!(first, second, "round-trip changed the model for {input:?}");
        } else {
            assert_ne!(second.config().kind(), kind);
        }
        assert_eq!(
            second,
            first.export_form(),
            "round-trip did not land on the export form for {input:?}"
        );
        assert_eq!(
            &*second.to_uri(),
            &*serialized,
            "serialization is not idempotent for {input:?}"
        );
        first
    }

    #[test]
    fn parses_the_canonical_form() {
        let uri = assert_round_trips(TOTP);
        assert_eq!(uri.issuer(), Some("ACME"));
        assert_eq!(uri.account(), "ada@example.com");
        assert_eq!(uri.config().kind(), OtpKind::Totp);
        assert_eq!(uri.config().digits(), 6);
        assert_eq!(uri.config().period(), 30);
        assert_eq!(uri.config().algorithm(), HashAlg::Sha1);
        assert_eq!(uri.config().secret().len(), 10);
        assert!(uri.extra().is_empty());
        assert_eq!(&*uri.to_uri(), TOTP);
    }

    #[test]
    fn serializes_each_kind_canonically() {
        let cases = [
            (
                "otpauth://totp/ACME:ada?secret=JBSWY3DPEHPK3PXP",
                "otpauth://totp/ACME:ada?secret=JBSWY3DPEHPK3PXP&issuer=ACME\
                 &algorithm=SHA1&digits=6&period=30",
            ),
            (
                "otpauth://hotp/ACME:ada?secret=JBSWY3DPEHPK3PXP&counter=5",
                "otpauth://hotp/ACME:ada?secret=JBSWY3DPEHPK3PXP&issuer=ACME\
                 &algorithm=SHA1&digits=6&counter=5",
            ),
            (
                "otpauth://steam/Valve:ada?secret=JBSWY3DPEHPK3PXP",
                "otpauth://steam/Valve:ada?secret=JBSWY3DPEHPK3PXP&issuer=Valve",
            ),
            (
                "otpauth://motp/Site:ada?secret=bfa47a0b71ac8f4d&pin=1234",
                "otpauth://motp/Site:ada?secret=bfa47a0b71ac8f4d&issuer=Site&pin=1234",
            ),
            (
                // Blizzard is written as plain 8-digit SHA-1 TOTP, so that every
                // other authenticator can import it.
                "otpauth://blizzard/Battle.net:ada?secret=JBSWY3DPEHPK3PXP",
                "otpauth://totp/Battle.net:ada?secret=JBSWY3DPEHPK3PXP&issuer=Battle.net\
                 &algorithm=SHA1&digits=8&period=30",
            ),
            (
                // Yandex.Key's own QR codes say `yaotp` and base32 the PIN;
                // `GEZDGNA` is base32 for "1234".
                "otpauth://yaotp/Yandex:ada?secret=JBSWY3DPEHPK3PXP&pin=GEZDGNA",
                "otpauth://yaotp/Yandex:ada?secret=JBSWY3DPEHPK3PXP&issuer=Yandex&pin=GEZDGNA",
            ),
            (
                // `yandex` is accepted as an alias and normalizes to `yaotp`.
                "otpauth://yandex/Yandex:ada?secret=JBSWY3DPEHPK3PXP&pin=GEZDGNA",
                "otpauth://yaotp/Yandex:ada?secret=JBSWY3DPEHPK3PXP&issuer=Yandex&pin=GEZDGNA",
            ),
        ];
        for (input, expected) in cases {
            let uri = assert_round_trips(input);
            assert_eq!(&*uri.to_uri(), expected);
        }
        // A Yandex PIN that is not base32 is a hard error, not a literal PIN.
        assert!(OtpUri::parse("otpauth://yaotp/ada?secret=JBSWY3DPEHPK3PXP&pin=1234").is_err());
        let yandex = parse("otpauth://yaotp/ada?secret=JBSWY3DPEHPK3PXP&pin=GEZDGNA");
        assert_eq!(
            yandex
                .config()
                .pin()
                .map(|pin| pin.expose_secret().to_vec()),
            Some(b"1234".to_vec())
        );
    }

    /// The one documented round-trip exception. Blizzard exports as plain
    /// 8-digit SHA-1 TOTP: structurally different on the way back in,
    /// behaviourally identical.
    #[test]
    fn blizzard_exports_as_interoperable_totp() {
        let blizzard = parse("otpauth://blizzard/Battle.net:ada?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(blizzard.config().kind(), OtpKind::Blizzard);

        let serialized = blizzard.to_uri();
        assert!(
            serialized.starts_with("otpauth://totp/"),
            "{}",
            &*serialized
        );
        assert!(!serialized.contains("blizzard"), "{}", &*serialized);
        // Stated explicitly, so an importer that defaults differently still
        // reads it correctly.
        assert!(serialized.contains("&digits=8"), "{}", &*serialized);
        assert!(serialized.contains("&algorithm=SHA1"), "{}", &*serialized);
        assert!(serialized.contains("&period=30"), "{}", &*serialized);

        // Byte-identical to what the equivalent TOTP configuration writes: an
        // importer cannot tell, which is the entire point.
        let equivalent = OtpUri::new(
            OtpConfig::totp_with(
                SecretBytes::from_base32("JBSWY3DPEHPK3PXP").unwrap(),
                HashAlg::Sha1,
                8,
                30,
            )
            .unwrap(),
            Some("Battle.net".to_owned()),
            "ada",
        );
        assert_eq!(&*serialized, &*equivalent.to_uri());

        // Re-parsing yields TOTP, equal to the export form, and generating the
        // same codes.
        let reparsed = parse(&serialized);
        assert_eq!(reparsed.config().kind(), OtpKind::Totp);
        assert_eq!(reparsed, blizzard.export_form());
        assert_eq!(reparsed, equivalent);
        for unix_ms in [0, 59_000, 1_234_567_890_000, 2_000_000_000_000] {
            assert_eq!(
                reparsed.config().generate_at(unix_ms).unwrap().value(),
                blizzard.config().generate_at(unix_ms).unwrap().value(),
                "codes differ at {unix_ms}"
            );
        }

        // The type is still accepted on the way in, and the preset still exists.
        assert_eq!(OtpKind::from_uri_type("blizzard"), Some(OtpKind::Blizzard));
        assert_eq!(OtpKind::from_uri_type("BLIZZARD"), Some(OtpKind::Blizzard));
        assert_eq!(OtpKind::Blizzard.display_name(), "Blizzard");
        assert_eq!(OtpKind::Blizzard.serializes_as(), OtpKind::Totp);

        // Export form is idempotent, and identity for every other kind.
        assert_eq!(blizzard.export_form().export_form(), blizzard.export_form());
        for kind in OtpKind::ALL {
            if kind != OtpKind::Blizzard {
                assert_eq!(kind.serializes_as(), kind, "{kind}");
            }
        }
        let totp = parse(TOTP);
        assert_eq!(totp.export_form(), totp);
    }

    #[test]
    fn issuer_comes_from_the_parameter_when_they_disagree() {
        let (uri, warnings) = OtpUri::parse_with_warnings(
            "otpauth://totp/Label:ada?secret=JBSWY3DPEHPK3PXP&issuer=Param",
        )
        .unwrap();
        assert_eq!(uri.issuer(), Some("Param"));
        assert_eq!(
            warnings,
            [UriWarning::IssuerMismatch {
                label: "Label".to_owned(),
                parameter: "Param".to_owned(),
            }]
        );
        // The canonical form no longer disagrees with itself.
        assert!(OtpUri::parse_with_warnings(&uri.to_uri())
            .unwrap()
            .1
            .is_empty());
    }

    #[test]
    fn issuer_from_either_place_alone() {
        let from_label = parse("otpauth://totp/OnlyLabel:ada?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(from_label.issuer(), Some("OnlyLabel"));
        let from_param = parse("otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&issuer=OnlyParam");
        assert_eq!(from_param.issuer(), Some("OnlyParam"));
        assert_eq!(from_param.account(), "ada");
        let neither = parse("otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(neither.issuer(), None);
        // An empty issuer is no issuer, in either position.
        assert_eq!(
            parse("otpauth://totp/:ada?secret=JBSWY3DPEHPK3PXP&issuer=").issuer(),
            None
        );
    }

    #[test]
    fn colons_inside_names_survive_the_round_trip() {
        // This is the case a decode-then-split parser gets wrong.
        let uri = OtpUri::new(
            OtpConfig::totp(SecretBytes::from_slice(b"12345678901234567890")).unwrap(),
            Some("Big:Corp".to_owned()),
            "a:b@example.com",
        );
        let serialized = uri.to_uri();
        assert!(
            serialized.contains("Big%3ACorp:a%3Ab@example.com"),
            "{}",
            &*serialized
        );
        let reparsed = parse(&serialized);
        assert_eq!(reparsed.issuer(), Some("Big:Corp"));
        assert_eq!(reparsed.account(), "a:b@example.com");
        assert_eq!(reparsed, uri);
    }

    #[test]
    fn labels_split_on_the_first_colon_only() {
        let uri = parse("otpauth://totp/ACME:ada:extra?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(uri.issuer(), Some("ACME"));
        assert_eq!(uri.account(), "ada:extra");
        assert_round_trips("otpauth://totp/ACME:ada:extra?secret=JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn tolerates_real_world_sloppiness() {
        for input in [
            // Lowercase scheme and type, spaces and hyphens in the secret,
            // missing padding, no label at all, stray separators.
            "OTPAUTH://TOTP/ACME:ada?SECRET=jbswy3dpehpk3pxp",
            "otpauth://totp/?secret=JBSW-Y3DP-EHPK-3PXP",
            "otpauth://totp?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&",
            "otpauth://totp/ada?&&secret=JBSWY3DPEHPK3PXP&&",
            "otpauth://totp/ACME%3Aada?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/ACME:%61da?secret=JBSWY3DPEHPK3PXP&digits=06",
        ] {
            let uri = assert_round_trips(input);
            assert_eq!(uri.config().secret().len(), 10, "for {input:?}");
        }
        // A percent-encoded colon in the label is part of the account, not a
        // separator.
        let escaped = parse("otpauth://totp/ACME%3Aada?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(escaped.issuer(), None);
        assert_eq!(escaped.account(), "ACME:ada");
    }

    #[test]
    fn unicode_names_are_legitimate() {
        let uri = assert_round_trips(
            "otpauth://totp/%E6%97%A5%E6%9C%AC:%E3%81%82?secret=JBSWY3DPEHPK3PXP",
        );
        assert_eq!(uri.issuer(), Some("日本"));
        assert_eq!(uri.account(), "あ");
    }

    #[test]
    fn vendor_parameters_are_preserved_in_order() {
        let uri = assert_round_trips(
            "otpauth://totp/ACME:ada?secret=JBSWY3DPEHPK3PXP\
             &image=https%3A%2F%2Fexample.com%2Ficon.png&color=ff0000&image=second&lock=true",
        );
        assert_eq!(
            uri.extra(),
            [
                (
                    "image".to_owned(),
                    "https://example.com/icon.png".to_owned()
                ),
                ("color".to_owned(), "ff0000".to_owned()),
                ("image".to_owned(), "second".to_owned()),
                ("lock".to_owned(), "true".to_owned()),
            ]
        );
        // Vendor parameters come last, after everything this crate owns.
        let serialized = uri.to_uri();
        let query = serialized.split_once('?').expect("has a query").1;
        assert!(
            query.starts_with(
                "secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30&image="
            ),
            "{query}"
        );
        // A vendor parameter that would collide with a known one is dropped
        // rather than silently duplicating it.
        let filtered = uri
            .clone()
            .with_extra(vec![("secret".to_owned(), "nope".to_owned())]);
        assert!(filtered.extra().is_empty());
    }

    #[test]
    fn parameters_with_no_value_survive() {
        let uri = assert_round_trips("otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&flag");
        assert_eq!(uri.extra(), [("flag".to_owned(), String::new())]);
    }

    #[test]
    fn fixed_parameters_are_normalized_with_a_warning() {
        let (uri, warnings) = OtpUri::parse_with_warnings(
            "otpauth://steam/ada?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256\
             &counter=7&pin=1234",
        )
        .unwrap();
        assert_eq!(uri.config().digits(), 5);
        assert_eq!(uri.config().period(), 30);
        assert_eq!(uri.config().algorithm(), HashAlg::Sha1);
        assert_eq!(uri.config().counter(), 0);
        assert_eq!(uri.config().pin(), None);
        assert_eq!(
            warnings,
            [
                UriWarning::IgnoredParam { name: "algorithm" },
                UriWarning::IgnoredParam { name: "digits" },
                UriWarning::IgnoredParam { name: "period" },
                UriWarning::IgnoredParam { name: "counter" },
                UriWarning::IgnoredParam { name: "pin" },
            ]
        );
        // Matching the fixed value is not worth warning about.
        let (_, quiet) =
            OtpUri::parse_with_warnings("otpauth://steam/ada?secret=JBSWY3DPEHPK3PXP&digits=5")
                .unwrap();
        assert!(quiet.is_empty());
    }

    #[test]
    fn hotp_period_is_ignored_because_it_means_nothing() {
        let (uri, warnings) = OtpUri::parse_with_warnings(
            "otpauth://hotp/ada?secret=JBSWY3DPEHPK3PXP&counter=1&period=90",
        )
        .unwrap();
        assert_eq!(uri.config().period(), 30);
        assert_eq!(warnings, [UriWarning::IgnoredParam { name: "period" }]);
        assert!(!uri.to_uri().contains("period"));
    }

    #[test]
    fn fragments_are_dropped_with_a_warning() {
        let (uri, warnings) =
            OtpUri::parse_with_warnings("otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP#notes")
                .unwrap();
        assert_eq!(warnings, [UriWarning::FragmentIgnored]);
        assert!(!uri.to_uri().contains('#'));
    }

    #[test]
    fn mutating_the_config_keeps_the_uri_valid() {
        let mut uri = parse(TOTP);
        uri.config_mut().set_digits(8).unwrap();
        uri.config_mut().set_period(60).unwrap();
        let reparsed = parse(&uri.to_uri());
        assert_eq!(reparsed.config().digits(), 8);
        assert_eq!(reparsed.config().period(), 60);
        assert_eq!(reparsed, uri);
    }

    #[test]
    fn motp_secrets_are_hex() {
        let uri = assert_round_trips("otpauth://motp/ada?secret=bfa47a0b71ac8f4d&pin=1234");
        assert_eq!(uri.config().secret().len(), 8);
        assert_eq!(&*uri.config().secret().to_hex(), "bfa47a0b71ac8f4d");
        // Base32 in a motp URI is not silently reinterpreted.
        assert!(OtpUri::parse("otpauth://motp/ada?secret=JBSWY3DPEHPK3PXP&pin=1").is_err());
        // Uppercase hex is accepted and normalized.
        let upper = parse("otpauth://motp/ada?secret=BFA47A0B71AC8F4D&pin=1234");
        assert_eq!(upper.config().secret(), uri.config().secret());
    }

    #[test]
    fn structural_rejections() {
        for (input, expected) in [
            ("", UriError::NotOtpauth),
            ("totp/ada?secret=A", UriError::NotOtpauth),
            ("https://example.com/?secret=A", UriError::NotOtpauth),
            ("otpauth:totp/ada?secret=A", UriError::NotOtpauth),
            (
                "otpauth-migration://offline?data=AAA",
                UriError::MigrationUri,
            ),
            ("otpauth://nope/ada?secret=A", UriError::UnknownKind),
            ("otpauth:///ada?secret=A", UriError::UnknownKind),
            (
                "otpauth://totp/ada?issuer=ACME",
                UriError::MissingParam("secret"),
            ),
            (
                "otpauth://hotp/ada?secret=JBSWY3DPEHPK3PXP",
                UriError::MissingParam("counter"),
            ),
            (
                "otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&secret=MZXW6",
                UriError::DuplicateParam("secret"),
            ),
            (
                "otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&issuer=A&ISSUER=B",
                UriError::DuplicateParam("issuer"),
            ),
            (
                "otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&digits=six",
                UriError::InvalidParam("digits"),
            ),
            (
                "otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
                UriError::InvalidParam("algorithm"),
            ),
            (
                "otpauth://totp/ada?=novalue&secret=JBSWY3DPEHPK3PXP",
                UriError::MalformedQuery,
            ),
        ] {
            assert_eq!(
                OtpUri::parse(input),
                Err(OtpError::Uri(expected.clone())),
                "for {input:?}"
            );
        }
    }

    #[test]
    fn over_long_input_is_rejected_before_anything_else() {
        let huge = format!(
            "otpauth://totp/{}?secret=JBSWY3DPEHPK3PXP",
            "a".repeat(MAX_URI_LEN)
        );
        assert!(matches!(
            OtpUri::parse(&huge),
            Err(OtpError::Uri(UriError::TooLong { .. }))
        ));
    }

    #[test]
    fn debug_output_holds_no_secret() {
        let uri = parse(TOTP);
        let debug = format!("{uri:?}");
        assert!(debug.contains("[redacted]"), "{debug}");
        assert!(!debug.contains("JBSWY3DPEHPK3PXP"), "{debug}");
    }
}
