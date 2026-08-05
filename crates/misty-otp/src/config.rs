// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The configuration that describes one token, and the vocabulary it is built
//! from. Mirrors SPEC 3.

use core::fmt;
use core::str::FromStr;

use crate::error::{OtpError, Result};
use crate::secret::SecretBytes;

/// Fewest digits a code may have (SPEC 3).
pub const MIN_DIGITS: u8 = 1;
/// Most digits a code may have (SPEC 3). Ten is the ceiling because RFC 4226
/// dynamic truncation yields a 31-bit value, which is at most ten decimal
/// digits.
pub const MAX_DIGITS: u8 = 10;
/// Shortest time step, in seconds (SPEC 3).
pub const MIN_PERIOD: u16 = 1;
/// Longest time step, in seconds (SPEC 3).
pub const MAX_PERIOD: u16 = 3600;
/// Longest secret accepted, in bytes.
///
/// Every real provisioning URI is 10 to 64 bytes; HMAC hashes anything longer
/// than a block down anyway. The cap exists so a hostile QR code cannot make us
/// allocate.
pub const MAX_SECRET_LEN: usize = 1024;

/// The HMAC hash under a code.
///
/// Interop only: these are the three RFC 6238 permits. Misty's own
/// cryptography does not use SHA-1 for anything (SPEC 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HashAlg {
    /// HMAC-SHA-1. The default, and what essentially every issuer uses.
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl HashAlg {
    /// The `algorithm=` spelling used in `otpauth://` URIs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// Digest length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HashAlg {
    type Err = OtpError;

    /// Case-insensitive, and tolerant of the hyphenated spellings some exporters
    /// emit (`SHA-1`).
    fn from_str(input: &str) -> Result<Self> {
        for (name, alg) in [
            ("SHA1", Self::Sha1),
            ("SHA-1", Self::Sha1),
            ("SHA256", Self::Sha256),
            ("SHA-256", Self::Sha256),
            ("SHA512", Self::Sha512),
            ("SHA-512", Self::Sha512),
        ] {
            if input.eq_ignore_ascii_case(name) {
                return Ok(alg);
            }
        }
        Err(OtpError::Uri(crate::error::UriError::InvalidParam(
            "algorithm",
        )))
    }
}

/// How a variant's secret or PIN is written in an `otpauth://` URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretEncoding {
    /// RFC 4648 base32. Every variant's secret except mOTP's, and the Yandex
    /// PIN, which Yandex's own QR codes base32-encode.
    Base32,
    /// Lowercase hex, used by mOTP because the mOTP construction hashes the
    /// secret's hex text rather than its bytes.
    Hex,
    /// Percent-encoded text, used for the mOTP PIN.
    Text,
}

/// Which one-time-password construction a token uses (SPEC 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OtpKind {
    /// RFC 6238 time-based. The default.
    #[default]
    Totp,
    /// RFC 4226 counter-based.
    Hotp,
    /// Steam Guard: TOTP with a 5-character alphabet.
    Steam,
    /// Mobile-OTP: MD5 over time, secret and PIN.
    Motp,
    /// Battle.net: TOTP fixed at SHA-1 and 8 digits.
    Blizzard,
    /// Yandex.Key: PIN-keyed HMAC-SHA-256 rendered as 8 letters.
    Yandex,
}

impl OtpKind {
    /// Every kind, in a stable order, for UI pickers and exhaustive tests.
    pub const ALL: [Self; 6] = [
        Self::Totp,
        Self::Hotp,
        Self::Steam,
        Self::Motp,
        Self::Blizzard,
        Self::Yandex,
    ];

    /// The `otpauth://<type>/` authority that names this kind.
    ///
    /// `totp` and `hotp` are from the Key Uri Format; `steam`, `motp` and
    /// `yaotp` follow Aegis, which is the closest thing to a registry these
    /// variants have. `blizzard` is Misty's own spelling — Aegis has no name for
    /// Battle.net tokens because it stores them as plain 8-digit TOTP — and it is
    /// **accepted on parse but never written**: see [`OtpKind::serializes_as`].
    #[must_use]
    pub const fn uri_type(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
            Self::Steam => "steam",
            Self::Motp => "motp",
            Self::Blizzard => "blizzard",
            Self::Yandex => "yaotp",
        }
    }

    /// The kind whose URI shape this one is written as.
    ///
    /// Identity for every kind except [`OtpKind::Blizzard`], which is written as
    /// [`OtpKind::Totp`].
    ///
    /// A type marker earns its place on the wire by carrying information a parser
    /// cannot otherwise recover. `steam`, `motp` and `yaotp` do: their algorithms
    /// genuinely differ, and no combination of `digits`, `period` and `algorithm`
    /// describes them. Battle.net's does not — it *is* RFC 6238 with SHA-1 and 8
    /// digits, which `tests/variants.rs` asserts both ways against the RFC's own
    /// vectors. So `otpauth://blizzard/` would carry nothing except the guarantee
    /// that every other authenticator fails to import our export, and a
    /// non-interoperable export string is worse than a slightly untidy enum
    /// (SPEC 8: no lock-in, in either direction).
    ///
    /// [`OtpKind::Blizzard`] therefore survives as a preset — the digit count is
    /// worth not having to remember, [`OtpKind::display_name`] still says
    /// "Blizzard", and `blizzard` still parses — but
    /// [`OtpUri::to_uri`](crate::OtpUri::to_uri) emits `totp`, with `algorithm`,
    /// `digits` and `period` all stated explicitly so an importer that defaults
    /// differently still reads it correctly. The documented consequence is that
    /// Blizzard is the one kind for which `parse -> serialize -> parse` returns a
    /// *behaviourally* identical model rather than a structurally identical one;
    /// [`OtpUri::export_form`](crate::OtpUri::export_form) is that model.
    ///
    /// Any kind mapped here must agree with its target on
    /// [`OtpKind::secret_encoding`] and [`OtpKind::pin_encoding`], or the URI it
    /// writes would not decode back to the same bytes.
    #[must_use]
    pub const fn serializes_as(self) -> Self {
        match self {
            Self::Blizzard => Self::Totp,
            other => other,
        }
    }

    /// Parse a URI authority, case-insensitively.
    ///
    /// `yandex` is accepted as an alias for `yaotp`: it is the name Aegis uses
    /// for the variant internally, so it turns up in hand-written URIs even
    /// though Yandex's own QR codes say `yaotp`. `blizzard` is accepted because
    /// Misty emitted it before, and because someone else may copy the idea.
    #[must_use]
    pub fn from_uri_type(authority: &str) -> Option<Self> {
        if authority.eq_ignore_ascii_case("yandex") {
            return Some(Self::Yandex);
        }
        Self::ALL
            .into_iter()
            .find(|kind| authority.eq_ignore_ascii_case(kind.uri_type()))
    }

    /// The name to show a human. Distinct from [`OtpKind::uri_type`], which is
    /// wire format.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Totp => "TOTP",
            Self::Hotp => "HOTP",
            Self::Steam => "Steam",
            Self::Motp => "mOTP",
            Self::Blizzard => "Blizzard",
            Self::Yandex => "Yandex",
        }
    }

    /// Digit count when the URI does not say.
    #[must_use]
    pub const fn default_digits(self) -> u8 {
        match self {
            Self::Totp | Self::Hotp | Self::Motp => 6,
            Self::Steam => 5,
            Self::Blizzard | Self::Yandex => 8,
        }
    }

    /// Time step in seconds when the URI does not say. Meaningless for
    /// [`OtpKind::Hotp`], which is counter-based; reported as the conventional
    /// 30 so the field is never garbage.
    #[must_use]
    pub const fn default_period(self) -> u16 {
        match self {
            Self::Motp => 10,
            _ => 30,
        }
    }

    /// Hash when the URI does not say.
    #[must_use]
    pub const fn default_algorithm(self) -> HashAlg {
        match self {
            Self::Yandex => HashAlg::Sha256,
            _ => HashAlg::Sha1,
        }
    }

    /// Digit count the construction fixes, if it fixes one. A URI that disagrees
    /// is normalized to this with a [`UriWarning`](crate::UriWarning).
    #[must_use]
    pub const fn fixed_digits(self) -> Option<u8> {
        match self {
            Self::Totp | Self::Hotp => None,
            other => Some(other.default_digits()),
        }
    }

    /// Time step the construction fixes, if it fixes one.
    #[must_use]
    pub const fn fixed_period(self) -> Option<u16> {
        match self {
            Self::Totp => None,
            other => Some(other.default_period()),
        }
    }

    /// Hash the construction fixes, if it fixes one. mOTP is fixed at MD5, which
    /// [`HashAlg`] deliberately cannot name; its `algorithm` is pinned to the
    /// default and ignored.
    #[must_use]
    pub const fn fixed_algorithm(self) -> Option<HashAlg> {
        match self {
            Self::Totp | Self::Hotp => None,
            other => Some(other.default_algorithm()),
        }
    }

    /// Whether the moving factor comes from the clock.
    #[must_use]
    pub const fn is_time_based(self) -> bool {
        !matches!(self, Self::Hotp)
    }

    /// Whether `counter` is meaningful.
    #[must_use]
    pub const fn uses_counter(self) -> bool {
        matches!(self, Self::Hotp)
    }

    /// Whether the construction mixes in a user PIN.
    #[must_use]
    pub const fn uses_pin(self) -> bool {
        matches!(self, Self::Motp | Self::Yandex)
    }

    /// How this kind's secret is encoded in a URI.
    #[must_use]
    pub const fn secret_encoding(self) -> SecretEncoding {
        match self {
            Self::Motp => SecretEncoding::Hex,
            _ => SecretEncoding::Base32,
        }
    }

    /// How this kind's PIN is encoded in a URI.
    ///
    /// mOTP PINs are plain text; Yandex PINs are base32, because that is what
    /// Yandex's own `otpauth://yaotp/` QR codes carry. Meaningless for kinds
    /// where [`OtpKind::uses_pin`] is false.
    #[must_use]
    pub const fn pin_encoding(self) -> SecretEncoding {
        match self {
            Self::Yandex => SecretEncoding::Base32,
            _ => SecretEncoding::Text,
        }
    }

    /// Longest prefix of the secret the construction actually uses, if it
    /// ignores the tail.
    ///
    /// Yandex is the only such variant: a Yandex secret is 16 bytes, and the
    /// 26-byte form printed for manual entry is those 16 bytes plus a checksum.
    /// The reference implementations truncate, so Misty truncates, or it would
    /// generate codes that do not work.
    #[must_use]
    pub const fn secret_prefix_used(self) -> Option<usize> {
        match self {
            Self::Yandex => Some(16),
            _ => None,
        }
    }
}

impl fmt::Display for OtpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// Everything needed to generate codes for one token (SPEC 3).
///
/// Fields are private and every mutation goes through a validating setter, so a
/// value of this type is always generatable: `digits` is in range, `period` is in
/// range, and parameters a variant fixes (Steam is always 5 characters, mOTP is
/// always a 10-second step) can never disagree with what generation will
/// actually produce. That invariant is what makes
/// `code.len() == config.digits()` unconditionally true.
///
/// Parameters that a variant fixes are normalized rather than rejected:
/// `builder(Steam, s).digits(6)` yields `digits == 5`. Out-of-*range* values are
/// still errors, so `digits(0)` fails for every kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpConfig {
    kind: OtpKind,
    secret: SecretBytes,
    algorithm: HashAlg,
    digits: u8,
    period: u16,
    counter: u64,
    pin: Option<SecretBytes>,
}

impl OtpConfig {
    /// Start building a configuration of `kind`.
    #[must_use]
    pub fn builder(kind: OtpKind, secret: SecretBytes) -> OtpConfigBuilder {
        OtpConfigBuilder::new(kind, secret)
    }

    /// RFC 6238 TOTP with the conventional defaults: SHA-1, 6 digits, 30
    /// seconds.
    ///
    /// # Errors
    ///
    /// If the secret is empty or over [`MAX_SECRET_LEN`].
    pub fn totp(secret: SecretBytes) -> Result<Self> {
        Self::builder(OtpKind::Totp, secret).build()
    }

    /// RFC 6238 TOTP with explicit parameters.
    ///
    /// # Errors
    ///
    /// If the secret is unusable, `digits` is outside
    /// [`MIN_DIGITS`]`..=`[`MAX_DIGITS`], or `period` is outside
    /// [`MIN_PERIOD`]`..=`[`MAX_PERIOD`].
    pub fn totp_with(
        secret: SecretBytes,
        algorithm: HashAlg,
        digits: u8,
        period: u16,
    ) -> Result<Self> {
        Self::builder(OtpKind::Totp, secret)
            .algorithm(algorithm)
            .digits(digits)
            .period(period)
            .build()
    }

    /// RFC 4226 HOTP starting at `counter`, SHA-1, 6 digits.
    ///
    /// # Errors
    ///
    /// If the secret is empty or over [`MAX_SECRET_LEN`].
    pub fn hotp(secret: SecretBytes, counter: u64) -> Result<Self> {
        Self::builder(OtpKind::Hotp, secret)
            .counter(counter)
            .build()
    }

    /// RFC 4226 HOTP with explicit parameters.
    ///
    /// # Errors
    ///
    /// If the secret is unusable or `digits` is out of range.
    pub fn hotp_with(
        secret: SecretBytes,
        algorithm: HashAlg,
        digits: u8,
        counter: u64,
    ) -> Result<Self> {
        Self::builder(OtpKind::Hotp, secret)
            .algorithm(algorithm)
            .digits(digits)
            .counter(counter)
            .build()
    }

    /// Steam Guard: 5 characters, 30 seconds, SHA-1.
    ///
    /// # Errors
    ///
    /// If the secret is empty or over [`MAX_SECRET_LEN`].
    pub fn steam(secret: SecretBytes) -> Result<Self> {
        Self::builder(OtpKind::Steam, secret).build()
    }

    /// Mobile-OTP: 6 hex characters, 10 seconds, MD5, PIN required.
    ///
    /// # Errors
    ///
    /// If the secret is empty or over [`MAX_SECRET_LEN`].
    pub fn motp(secret: SecretBytes, pin: SecretBytes) -> Result<Self> {
        Self::builder(OtpKind::Motp, secret).pin(Some(pin)).build()
    }

    /// Battle.net: 8 digits, 30 seconds, SHA-1.
    ///
    /// # Errors
    ///
    /// If the secret is empty or over [`MAX_SECRET_LEN`].
    pub fn blizzard(secret: SecretBytes) -> Result<Self> {
        Self::builder(OtpKind::Blizzard, secret).build()
    }

    /// Yandex.Key: 8 letters, 30 seconds, SHA-256, PIN required.
    ///
    /// # Errors
    ///
    /// If the secret is empty or over [`MAX_SECRET_LEN`].
    pub fn yandex(secret: SecretBytes, pin: SecretBytes) -> Result<Self> {
        Self::builder(OtpKind::Yandex, secret)
            .pin(Some(pin))
            .build()
    }

    /// Which construction this token uses.
    #[must_use]
    pub fn kind(&self) -> OtpKind {
        self.kind
    }

    /// The shared secret.
    #[must_use]
    pub fn secret(&self) -> &SecretBytes {
        &self.secret
    }

    /// The HMAC hash. Fixed, and unused, for mOTP.
    #[must_use]
    pub fn algorithm(&self) -> HashAlg {
        self.algorithm
    }

    /// Character count of generated codes.
    #[must_use]
    pub fn digits(&self) -> u8 {
        self.digits
    }

    /// Time step in seconds. Reported for HOTP too, where it means nothing.
    #[must_use]
    pub fn period(&self) -> u16 {
        self.period
    }

    /// HOTP counter. Always 0 for time-based kinds.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The mOTP/Yandex PIN, if one is set.
    #[must_use]
    pub fn pin(&self) -> Option<&SecretBytes> {
        self.pin.as_ref()
    }

    /// Set the digit count.
    ///
    /// Kinds with a fixed digit count keep theirs; the value is still range
    /// checked first, so `set_digits(0)` fails even for Steam.
    ///
    /// # Errors
    ///
    /// [`OtpError::InvalidDigits`] outside [`MIN_DIGITS`]`..=`[`MAX_DIGITS`].
    pub fn set_digits(&mut self, digits: u8) -> Result<()> {
        self.digits = self.kind.fixed_digits().unwrap_or(check_digits(digits)?);
        Ok(())
    }

    /// Set the time step in seconds.
    ///
    /// Kinds with a fixed step keep theirs, HOTP included; the value is still
    /// range checked first.
    ///
    /// # Errors
    ///
    /// [`OtpError::InvalidPeriod`] outside [`MIN_PERIOD`]`..=`[`MAX_PERIOD`].
    pub fn set_period(&mut self, period: u16) -> Result<()> {
        self.period = self.kind.fixed_period().unwrap_or(check_period(period)?);
        Ok(())
    }

    /// Set the HMAC hash. Kinds that fix theirs keep it.
    pub fn set_algorithm(&mut self, algorithm: HashAlg) {
        self.algorithm = self.kind.fixed_algorithm().unwrap_or(algorithm);
    }

    /// Set the HOTP counter. Ignored by time-based kinds, which keep 0.
    ///
    /// The vault merges this field with max-wins, never last-write-wins: a lower
    /// counter would replay a consumed code (SPEC 4).
    pub fn set_counter(&mut self, counter: u64) {
        if self.kind.uses_counter() {
            self.counter = counter;
        }
    }

    /// Set or clear the PIN. Ignored by kinds that do not use one. An empty PIN
    /// is stored as `None`.
    pub fn set_pin(&mut self, pin: Option<SecretBytes>) {
        self.pin = if self.kind.uses_pin() {
            pin.filter(|pin| !pin.is_empty())
        } else {
            None
        };
    }

    /// Replace the secret.
    ///
    /// The vault treats a secret as immutable and keeps both sides of a conflict
    /// (SPEC 4); this exists for import and repair flows, not for merging.
    ///
    /// # Errors
    ///
    /// If the secret is empty or over [`MAX_SECRET_LEN`].
    pub fn set_secret(&mut self, secret: SecretBytes) -> Result<()> {
        secret.check_len()?;
        self.secret = secret;
        Ok(())
    }

    /// The same parameters, re-normalized as another kind.
    ///
    /// Infallible, unlike the builder: every field is already in range, and the
    /// new kind's fixed values simply replace the old ones. Used to describe what
    /// a URI written for one kind parses back as — see
    /// [`OtpKind::serializes_as`].
    pub(crate) fn with_kind(&self, kind: OtpKind) -> Self {
        Self {
            kind,
            secret: self.secret.clone(),
            algorithm: kind.fixed_algorithm().unwrap_or(self.algorithm),
            digits: kind.fixed_digits().unwrap_or(self.digits),
            period: kind.fixed_period().unwrap_or(self.period),
            counter: if kind.uses_counter() { self.counter } else { 0 },
            pin: if kind.uses_pin() {
                self.pin.clone()
            } else {
                None
            },
        }
    }
}

/// Range check for `digits`, shared by every entry point.
fn check_digits(digits: u8) -> Result<u8> {
    if (MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        Ok(digits)
    } else {
        Err(OtpError::InvalidDigits(u64::from(digits)))
    }
}

/// Range check for `period`, shared by every entry point.
fn check_period(period: u16) -> Result<u16> {
    if (MIN_PERIOD..=MAX_PERIOD).contains(&period) {
        Ok(period)
    } else {
        Err(OtpError::InvalidPeriod(u64::from(period)))
    }
}

/// Builder for [`OtpConfig`]. Unset parameters take the kind's default; fixed
/// parameters take the kind's fixed value whatever you pass.
#[derive(Debug, Clone)]
pub struct OtpConfigBuilder {
    kind: OtpKind,
    secret: SecretBytes,
    algorithm: Option<HashAlg>,
    digits: Option<u8>,
    period: Option<u16>,
    counter: u64,
    pin: Option<SecretBytes>,
}

impl OtpConfigBuilder {
    /// A builder for `kind` over `secret`.
    #[must_use]
    pub fn new(kind: OtpKind, secret: SecretBytes) -> Self {
        Self {
            kind,
            secret,
            algorithm: None,
            digits: None,
            period: None,
            counter: 0,
            pin: None,
        }
    }

    /// Set the HMAC hash.
    #[must_use]
    pub fn algorithm(mut self, algorithm: HashAlg) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Set the digit count.
    #[must_use]
    pub fn digits(mut self, digits: u8) -> Self {
        self.digits = Some(digits);
        self
    }

    /// Set the time step in seconds.
    #[must_use]
    pub fn period(mut self, period: u16) -> Self {
        self.period = Some(period);
        self
    }

    /// Set the HOTP counter.
    #[must_use]
    pub fn counter(mut self, counter: u64) -> Self {
        self.counter = counter;
        self
    }

    /// Set the mOTP/Yandex PIN.
    #[must_use]
    pub fn pin(mut self, pin: Option<SecretBytes>) -> Self {
        self.pin = pin;
        self
    }

    /// Validate and freeze into an [`OtpConfig`].
    ///
    /// # Errors
    ///
    /// [`OtpError::EmptySecret`] or [`OtpError::SecretTooLong`] for an unusable
    /// secret, [`OtpError::InvalidDigits`] or [`OtpError::InvalidPeriod`] for an
    /// out-of-range parameter. A missing PIN is *not* an error here: importers
    /// routinely learn the secret before the user supplies the PIN. Generation
    /// is where [`OtpError::MissingPin`] surfaces.
    pub fn build(self) -> Result<OtpConfig> {
        self.secret.check_len()?;

        let digits = match self.digits {
            Some(digits) => check_digits(digits)?,
            None => self.kind.default_digits(),
        };
        let period = match self.period {
            Some(period) => check_period(period)?,
            None => self.kind.default_period(),
        };

        Ok(OtpConfig {
            kind: self.kind,
            secret: self.secret,
            algorithm: self.kind.fixed_algorithm().unwrap_or_else(|| {
                self.algorithm
                    .unwrap_or_else(|| self.kind.default_algorithm())
            }),
            digits: self.kind.fixed_digits().unwrap_or(digits),
            period: self.kind.fixed_period().unwrap_or(period),
            counter: if self.kind.uses_counter() {
                self.counter
            } else {
                0
            },
            pin: if self.kind.uses_pin() {
                self.pin.filter(|pin| !pin.is_empty())
            } else {
                None
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> SecretBytes {
        SecretBytes::from_slice(b"12345678901234567890")
    }

    #[test]
    fn defaults_match_spec() {
        let config = OtpConfig::totp(secret()).unwrap();
        assert_eq!(config.kind(), OtpKind::Totp);
        assert_eq!(config.algorithm(), HashAlg::Sha1);
        assert_eq!(config.digits(), 6);
        assert_eq!(config.period(), 30);
        assert_eq!(config.counter(), 0);
        assert_eq!(config.pin(), None);
    }

    #[test]
    fn digits_and_period_are_range_checked() {
        for digits in [0u8, 11, 255] {
            assert_eq!(
                OtpConfig::totp_with(secret(), HashAlg::Sha1, digits, 30),
                Err(OtpError::InvalidDigits(u64::from(digits)))
            );
        }
        for period in [0u16, 3601, 65535] {
            assert_eq!(
                OtpConfig::totp_with(secret(), HashAlg::Sha1, 6, period),
                Err(OtpError::InvalidPeriod(u64::from(period)))
            );
        }
        assert!(OtpConfig::totp_with(secret(), HashAlg::Sha512, 1, 1).is_ok());
        assert!(OtpConfig::totp_with(secret(), HashAlg::Sha512, 10, 3600).is_ok());
    }

    #[test]
    fn fixed_parameters_win_over_requests() {
        let steam = OtpConfig::builder(OtpKind::Steam, secret())
            .digits(6)
            .period(60)
            .algorithm(HashAlg::Sha512)
            .counter(9)
            .build()
            .unwrap();
        assert_eq!(steam.digits(), 5);
        assert_eq!(steam.period(), 30);
        assert_eq!(steam.algorithm(), HashAlg::Sha1);
        assert_eq!(steam.counter(), 0);

        let motp = OtpConfig::motp(secret(), SecretBytes::from_slice(b"1234")).unwrap();
        assert_eq!(motp.digits(), 6);
        assert_eq!(motp.period(), 10);

        // Out-of-range still fails, even where the value would be overridden.
        assert!(OtpConfig::builder(OtpKind::Steam, secret())
            .digits(0)
            .build()
            .is_err());
    }

    #[test]
    fn pins_only_stick_where_they_mean_something() {
        let pin = SecretBytes::from_slice(b"1234");
        assert!(OtpConfig::builder(OtpKind::Totp, secret())
            .pin(Some(pin.clone()))
            .build()
            .unwrap()
            .pin()
            .is_none());
        assert_eq!(
            OtpConfig::motp(secret(), pin.clone()).unwrap().pin(),
            Some(&pin)
        );
        // An empty PIN is no PIN.
        assert!(OtpConfig::builder(OtpKind::Motp, secret())
            .pin(Some(SecretBytes::new(Vec::new())))
            .build()
            .unwrap()
            .pin()
            .is_none());
    }

    #[test]
    fn setters_preserve_invariants() {
        let mut config = OtpConfig::steam(secret()).unwrap();
        config.set_digits(8).unwrap();
        config.set_period(90).unwrap();
        config.set_algorithm(HashAlg::Sha512);
        config.set_counter(12);
        assert_eq!(
            (
                config.digits(),
                config.period(),
                config.algorithm(),
                config.counter()
            ),
            (5, 30, HashAlg::Sha1, 0)
        );
        assert!(config.set_digits(0).is_err());
        assert!(config.set_period(0).is_err());

        let mut totp = OtpConfig::totp(secret()).unwrap();
        totp.set_digits(8).unwrap();
        totp.set_period(90).unwrap();
        assert_eq!((totp.digits(), totp.period()), (8, 90));
    }

    #[test]
    fn unusable_secrets_are_rejected() {
        assert_eq!(
            OtpConfig::totp(SecretBytes::new(Vec::new())),
            Err(OtpError::EmptySecret)
        );
        assert!(matches!(
            OtpConfig::totp(SecretBytes::new(vec![0; MAX_SECRET_LEN + 1])),
            Err(OtpError::SecretTooLong { .. })
        ));
        assert!(OtpConfig::totp(SecretBytes::new(vec![0; MAX_SECRET_LEN])).is_ok());
    }

    #[test]
    fn algorithm_parsing_is_forgiving_about_spelling() {
        for (input, expected) in [
            ("SHA1", HashAlg::Sha1),
            ("sha1", HashAlg::Sha1),
            ("Sha-1", HashAlg::Sha1),
            ("SHA256", HashAlg::Sha256),
            ("sha-256", HashAlg::Sha256),
            ("SHA512", HashAlg::Sha512),
        ] {
            assert_eq!(input.parse::<HashAlg>().unwrap(), expected, "{input}");
        }
        for input in ["", "SHA", "SHA-224", "MD5", "sha1 "] {
            assert!(input.parse::<HashAlg>().is_err(), "{input}");
        }
    }

    #[test]
    fn uri_types_round_trip() {
        for kind in OtpKind::ALL {
            assert_eq!(OtpKind::from_uri_type(kind.uri_type()), Some(kind));
            assert_eq!(
                OtpKind::from_uri_type(&kind.uri_type().to_ascii_uppercase()),
                Some(kind)
            );
        }
        assert_eq!(OtpKind::from_uri_type("nope"), None);
        assert_eq!(OtpKind::from_uri_type(""), None);
    }
}
