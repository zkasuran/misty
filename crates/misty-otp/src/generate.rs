// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Code generation for every supported variant.
//!
//! The moving factor is computed once, in [`window_at`], and every variant reads
//! it from there. TOTP, Steam, mOTP, Blizzard and Yandex differ only in how they
//! turn `(secret, moving factor)` into characters.

use md5::Md5;
use sha2::{Digest as _, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::code::{Code, CodeWindow};
use crate::config::{HashAlg, OtpConfig, OtpKind};
use crate::error::{OtpError, Result};
use crate::raw;
use crate::secret::SecretBytes;

/// Steam's 26-character code alphabet. Excludes vowels and the glyphs that get
/// misread aloud (`0`/`O`, `1`/`I`/`L`, `S`/`5`, `Z`/`2`).
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// Yandex.Key renders its codes as letters, not digits.
const YANDEX_ALPHABET: &[u8; 26] = b"abcdefghijklmnopqrstuvwxyz";

/// Largest forward scan [`OtpConfig::resync_counter`] will perform, whatever the
/// caller asks for. RFC 4226 section 7.4 wants a "look-ahead window" that is
/// small enough not to weaken the code space; 1000 is far past any realistic
/// number of unsynchronized presses and bounds the work a hostile caller can ask
/// for.
pub const MAX_RESYNC_WINDOW: u64 = 1000;

/// RFC 4226 HOTP.
///
/// The one-shot form: [`OtpConfig`] is the stateful one. `digits` is range
/// checked here too, so this is safe to call with numbers straight off the wire.
///
/// # Errors
///
/// [`OtpError::EmptySecret`] or [`OtpError::SecretTooLong`] for an unusable
/// secret, [`OtpError::InvalidDigits`] if `digits` is outside
/// [`MIN_DIGITS`](crate::MIN_DIGITS)`..=`[`MAX_DIGITS`](crate::MAX_DIGITS).
///
/// # Examples
///
/// ```
/// use misty_otp::{hotp, HashAlg, SecretBytes};
///
/// let secret = SecretBytes::from_slice(b"12345678901234567890");
/// assert_eq!(hotp(&secret, 0, 6, HashAlg::Sha1)?.value(), "755224");
/// assert_eq!(hotp(&secret, 9, 6, HashAlg::Sha1)?.value(), "520489");
/// # Ok::<(), misty_otp::OtpError>(())
/// ```
pub fn hotp(secret: &SecretBytes, counter: u64, digits: u8, algorithm: HashAlg) -> Result<Code> {
    secret.check_len()?;
    Ok(Code::counter_based(hotp_value(
        algorithm,
        secret.expose_secret(),
        counter,
        digits,
    )?))
}

/// The moving factor and validity window covering `unix_ms` for a `period`
/// second step.
///
/// # Errors
///
/// [`OtpError::TimeOutOfRange`] if the window's end is not representable in
/// `u64` milliseconds, which needs a timestamp within one period of the year
/// 584 million.
fn window_at(period: u16, unix_ms: u64) -> Result<(u64, CodeWindow)> {
    // `period` is 1..=3600 by construction, so this is 1_000..=3_600_000.
    let period_ms = u64::from(period) * 1_000;
    // floor(ms / (period * 1000)) == floor(floor(ms / 1000) / period), so this is
    // the RFC 6238 counter without a separate seconds step.
    let counter = unix_ms / period_ms;
    let valid_from_ms = counter * period_ms;
    let valid_until_ms = valid_from_ms
        .checked_add(period_ms)
        .ok_or(OtpError::TimeOutOfRange(unix_ms))?;
    let elapsed_ms = unix_ms - valid_from_ms;
    // Precision loss is irrelevant: this drives a progress ring, and both values
    // are well under 2^24.
    let progress = (elapsed_ms as f64 / period_ms as f64) as f32;

    Ok((
        counter,
        CodeWindow {
            valid_from_ms,
            valid_until_ms,
            remaining_ms: valid_until_ms - unix_ms,
            progress,
        },
    ))
}

/// RFC 4226: HMAC, dynamic truncation, decimal reduction.
fn hotp_value(
    algorithm: HashAlg,
    secret: &[u8],
    counter: u64,
    digits: u8,
) -> Result<Zeroizing<String>> {
    let digest = raw::hmac_counter(algorithm, secret, counter)?;
    raw::decimal_digits(raw::dynamic_truncation(&digest)?, digits)
}

/// Steam Guard: RFC 4226 truncation, then base-26 into Steam's alphabet.
///
/// No published specification exists; this matches every open implementation
/// (see `README.md`). `digits` is always 5 for this kind, but it is honoured so
/// the code length always equals the configured digit count.
fn steam_value(secret: &[u8], counter: u64, digits: u8) -> Result<Zeroizing<String>> {
    let digest = raw::hmac_counter(HashAlg::Sha1, secret, counter)?;
    let truncated = u64::from(raw::dynamic_truncation(&digest)?);
    // Steam writes the least significant base-26 digit first.
    Ok(Zeroizing::new(
        base26(truncated, digits, STEAM_ALPHABET)
            .into_iter()
            .collect(),
    ))
}

/// The low `digits` base-26 digits of `value`, least significant first.
fn base26(mut value: u64, digits: u8, alphabet: &[u8; 26]) -> Vec<char> {
    let mut out = Vec::with_capacity(usize::from(digits));
    for _ in 0..digits {
        // `% 26` keeps the index in range unconditionally.
        out.push(char::from(alphabet[(value % 26) as usize]));
        value /= 26;
    }
    out
}

/// Mobile-OTP: `md5(interval_decimal || secret_hex || pin)`, truncated to
/// `digits` lowercase hex characters.
///
/// The secret is hashed as its *hex text*, not its bytes: mOTP predates
/// `otpauth://` and specifies its secret as a 16-character hex string.
fn motp_value(
    secret: &SecretBytes,
    pin: &SecretBytes,
    interval: u64,
    digits: u8,
) -> Result<Zeroizing<String>> {
    let mut input = Zeroizing::new(Vec::with_capacity(24 + secret.len() * 2 + pin.len()));
    input.extend_from_slice(interval.to_string().as_bytes());
    input.extend_from_slice(secret.to_hex().as_bytes());
    input.extend_from_slice(pin.expose_secret());

    let digest = Zeroizing::new(Md5::digest(&*input).to_vec());
    let rendered = Zeroizing::new(hex::encode(&*digest));
    let truncated: String = rendered.chars().take(usize::from(digits)).collect();
    if truncated.len() != usize::from(digits) {
        return Err(OtpError::Internal(
            "md5 digest shorter than the digit count",
        ));
    }
    Ok(Zeroizing::new(truncated))
}

/// Yandex.Key: a PIN-keyed HMAC whose output is rendered as letters.
///
/// No specification is published. This reproduces the open-source
/// implementations (Aegis `YAOTP.java`, `KeeYaOtp`), quirks included, because a
/// code that disagrees with Yandex's server is worthless however principled it
/// is:
///
/// 1. `key = SHA-256(pin || secret)`, and **if the first byte of that digest is
///    zero it is dropped**, leaving a 31-byte key. That is not a design choice,
///    it is a sign-byte artefact of the original implementation that every
///    interoperable client has to reproduce.
/// 2. `HMAC-SHA-256(key, counter)`, counter as 8 big-endian bytes.
/// 3. RFC 4226 offset selection, but reading *eight* big-endian bytes there and
///    clearing the top bit, giving a 63-bit value. The extra width matters: a
///    31-bit value cannot fill eight base-26 digits, and the last characters
///    would barely vary.
/// 4. The low `digits` base-26 digits, **most significant first**, as `a`-`z`.
///
/// Only the first 16 bytes of the secret are used
/// ([`OtpKind::secret_prefix_used`]).
fn yandex_value(
    secret: &SecretBytes,
    pin: &SecretBytes,
    counter: u64,
    digits: u8,
) -> Result<Zeroizing<String>> {
    let exposed = secret.expose_secret();
    let used = match exposed.get(..16) {
        Some(prefix) => prefix,
        None => exposed,
    };

    // The PIN is not a second factor here, it is part of the key: the stored
    // secret alone cannot produce a code.
    let mut keyed = Zeroizing::new(Vec::with_capacity(pin.len() + used.len()));
    keyed.extend_from_slice(pin.expose_secret());
    keyed.extend_from_slice(used);
    let hashed = Zeroizing::new(Sha256::digest(&*keyed).to_vec());
    let key = match hashed.split_first() {
        Some((&0, tail)) => tail,
        _ => &hashed[..],
    };

    let digest = raw::hmac_counter(HashAlg::Sha256, key, counter)?;
    let offset = usize::from(
        digest
            .last()
            .ok_or(OtpError::Internal("empty hmac output"))?
            & 0x0F,
    );
    let selected: [u8; 8] = digest
        .get(offset..offset + 8)
        .and_then(|window| window.try_into().ok())
        .ok_or(OtpError::Internal("hmac output too short for yandex"))?;
    let truncated = u64::from_be_bytes(selected) & 0x7FFF_FFFF_FFFF_FFFF;

    let mut rendered = base26(truncated, digits, YANDEX_ALPHABET);
    rendered.reverse();
    Ok(Zeroizing::new(rendered.into_iter().collect()))
}

impl OtpConfig {
    /// The moving factor at `unix_ms`: the RFC 6238 time step, or the stored
    /// counter for HOTP.
    ///
    /// # Errors
    ///
    /// [`OtpError::TimeOutOfRange`] as [`OtpConfig::generate_at`].
    pub fn counter_at(&self, unix_ms: u64) -> Result<u64> {
        if self.kind().uses_counter() {
            Ok(self.counter())
        } else {
            Ok(window_at(self.period(), unix_ms)?.0)
        }
    }

    /// Generate the code for a specific instant.
    ///
    /// HOTP ignores `unix_ms` and uses the stored counter.
    ///
    /// # Errors
    ///
    /// [`OtpError::MissingPin`] if the variant needs a PIN and none is set,
    /// [`OtpError::TimeOutOfRange`] for a timestamp whose window end is not
    /// representable.
    pub fn generate_at(&self, unix_ms: u64) -> Result<Code> {
        if self.kind().uses_counter() {
            return Ok(Code::counter_based(self.value_at(self.counter())?));
        }
        let (counter, window) = window_at(self.period(), unix_ms)?;
        Ok(Code::time_based(self.value_at(counter)?, window))
    }

    /// Generate the code for the clock's current instant.
    ///
    /// Pass a [`SkewedClock`](crate::SkewedClock) to apply a measured server
    /// offset (SPEC 6.5).
    ///
    /// # Errors
    ///
    /// As [`OtpConfig::generate_at`].
    pub fn generate<C: Clock + ?Sized>(&self, clock: &C) -> Result<Code> {
        self.generate_at(clock.now_unix_ms())
    }

    /// Generate the code that follows the one current at `unix_ms`, for the
    /// "peek at the next code" affordance.
    ///
    /// The returned window describes the *next* window, so `remaining_ms` is a
    /// full period and `progress` is `0.0`: that is what will be true when the
    /// code becomes current. For HOTP this is the code at `counter + 1`, which
    /// does not advance the stored counter.
    ///
    /// # Errors
    ///
    /// As [`OtpConfig::generate_at`], plus [`OtpError::CounterExhausted`] if a
    /// HOTP counter is at [`u64::MAX`].
    pub fn next_code_at(&self, unix_ms: u64) -> Result<Code> {
        if self.kind().uses_counter() {
            let next = self
                .counter()
                .checked_add(1)
                .ok_or(OtpError::CounterExhausted(self.counter()))?;
            return Ok(Code::counter_based(self.value_at(next)?));
        }
        let (_, window) = window_at(self.period(), unix_ms)?;
        self.generate_at(window.valid_until_ms)
    }

    /// [`OtpConfig::next_code_at`] against a clock.
    ///
    /// # Errors
    ///
    /// As [`OtpConfig::next_code_at`].
    pub fn next_code<C: Clock + ?Sized>(&self, clock: &C) -> Result<Code> {
        self.next_code_at(clock.now_unix_ms())
    }

    /// Find the counter that produced `observed_code`, scanning forward from the
    /// stored counter (RFC 4226 section 7.4 resynchronization).
    ///
    /// Returns the *matching* counter; a caller that accepts the code should
    /// then store `matched + 1`, because that code is now spent. `window` is
    /// clamped to [`MAX_RESYNC_WINDOW`]. Always `None` for time-based kinds,
    /// which have nothing to resynchronize.
    ///
    /// Comparison is constant-time and the scan does not stop early, so timing
    /// reveals neither whether nor where a match occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// use misty_otp::{OtpConfig, SecretBytes};
    ///
    /// // The token is at counter 0; the user has pressed the button 3 times.
    /// let config = OtpConfig::hotp(SecretBytes::from_slice(b"12345678901234567890"), 0)?;
    /// assert_eq!(config.resync_counter("969429", 10), Some(3));
    /// assert_eq!(config.resync_counter("969429", 2), None);
    /// assert_eq!(config.resync_counter("000000", 10), None);
    /// # Ok::<(), misty_otp::OtpError>(())
    /// ```
    #[must_use]
    pub fn resync_counter(&self, observed_code: &str, window: u64) -> Option<u64> {
        if !self.kind().uses_counter() {
            return None;
        }
        let window = window.min(MAX_RESYNC_WINDOW);
        let mut found = Choice::from(0u8);
        let mut matched = 0u64;

        for step in 0..=window {
            let Some(counter) = self.counter().checked_add(step) else {
                break;
            };
            let Ok(candidate) = self.value_at(counter) else {
                break;
            };
            let hit = candidate.as_bytes().ct_eq(observed_code.as_bytes());
            // First match wins, without branching on which one it was.
            matched = u64::conditional_select(&matched, &counter, hit & !found);
            found |= hit;
        }

        bool::from(found).then_some(matched)
    }

    /// Render the code for an already-computed moving factor.
    fn value_at(&self, moving_factor: u64) -> Result<Zeroizing<String>> {
        let secret = self.secret();
        match self.kind() {
            OtpKind::Totp | OtpKind::Hotp | OtpKind::Blizzard => hotp_value(
                self.algorithm(),
                secret.expose_secret(),
                moving_factor,
                self.digits(),
            ),
            OtpKind::Steam => steam_value(secret.expose_secret(), moving_factor, self.digits()),
            OtpKind::Motp => motp_value(
                secret,
                self.pin().ok_or(OtpError::MissingPin(OtpKind::Motp))?,
                moving_factor,
                self.digits(),
            ),
            OtpKind::Yandex => yandex_value(
                secret,
                self.pin().ok_or(OtpError::MissingPin(OtpKind::Yandex))?,
                moving_factor,
                self.digits(),
            ),
        }
    }
}
