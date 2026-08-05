// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one type in this crate that holds key material.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::base32;
use crate::config::MAX_SECRET_LEN;
use crate::error::{OtpError, Result};

/// A shared OTP secret, or an mOTP/Yandex PIN.
///
/// Zeroized on drop. Renders as `[redacted]` through both [`fmt::Debug`] and
/// [`fmt::Display`], so it cannot reach a log line, a panic message, or an error
/// message by accident (SPEC 3, SPEC 9).
///
/// This type intentionally implements neither `Serialize` nor `Deserialize`.
/// Secrets leave the process only through the vault's encryption path, which
/// serializes the bytes explicitly; there is no derive that can accidentally
/// pull a secret into a JSON log or a debug dump.
///
/// Equality is constant-time ([`subtle::ConstantTimeEq`]); `==` on secrets is a
/// review-blocking bug per SPEC 2.1, so the `PartialEq` impl is the safe one.
/// Length is not secret and is compared first, as it must be.
///
/// # Examples
///
/// ```
/// use misty_otp::SecretBytes;
///
/// let secret = SecretBytes::from_base32("JBSWY3DPEHPK3PXP")?;
/// assert_eq!(secret.len(), 10);
/// assert_eq!(format!("{secret:?}"), "[redacted]");
/// assert_eq!(format!("{secret}"), "[redacted]");
/// # Ok::<(), misty_otp::OtpError>(())
/// ```
#[derive(Clone)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Take ownership of raw secret bytes.
    ///
    /// Infallible on purpose: this is a container, not a policy. Range checks
    /// live in [`OtpConfigBuilder::build`](crate::OtpConfigBuilder::build),
    /// which is where an empty or over-long secret actually becomes a problem.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Copy secret bytes out of a slice.
    ///
    /// Prefer [`SecretBytes::new`] where you can move the buffer instead: this
    /// leaves the caller's copy for the caller to zeroize.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// Decode a base32 secret, the encoding used by every `otpauth://` variant
    /// except mOTP.
    ///
    /// # Errors
    ///
    /// [`OtpError::Base32`] if the input is not decodable (see
    /// [`base32::decode`]), [`OtpError::EmptySecret`] if it decodes to nothing,
    /// or [`OtpError::SecretTooLong`] past [`MAX_SECRET_LEN`].
    pub fn from_base32(encoded: &str) -> Result<Self> {
        let secret = Self::new(base32::decode(encoded)?);
        secret.check_len()?;
        Ok(secret)
    }

    /// Decode a hex secret, the encoding mOTP uses.
    ///
    /// # Errors
    ///
    /// [`OtpError::InvalidHexSecret`] if the input is not an even-length run of
    /// hex digits, [`OtpError::EmptySecret`] if empty, or
    /// [`OtpError::SecretTooLong`] past [`MAX_SECRET_LEN`].
    pub fn from_hex(encoded: &str) -> Result<Self> {
        if encoded.len() > MAX_SECRET_LEN * 2 {
            return Err(OtpError::SecretTooLong {
                len: encoded.len() / 2,
                max: MAX_SECRET_LEN,
            });
        }
        let bytes = hex::decode(encoded).map_err(|_| OtpError::InvalidHexSecret)?;
        let secret = Self::new(bytes);
        secret.check_len()?;
        Ok(secret)
    }

    /// Borrow the raw bytes. Named to make review grep-able: every call site is
    /// a place where a secret is in the clear.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Canonical unpadded base32 of the secret, for export and QR generation.
    ///
    /// Returns a zeroizing string: it is the secret, in a shape that is very
    /// easy to accidentally keep.
    #[must_use]
    pub fn to_base32(&self) -> Zeroizing<String> {
        Zeroizing::new(base32::encode(self.expose_secret()))
    }

    /// Lowercase hex of the secret, for mOTP export.
    #[must_use]
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.expose_secret()))
    }

    /// Length in bytes. Not secret; sizes leak anyway (SPEC 1, A1).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Enforce the length policy shared by every entry point.
    pub(crate) fn check_len(&self) -> Result<()> {
        if self.is_empty() {
            return Err(OtpError::EmptySecret);
        }
        if self.len() > MAX_SECRET_LEN {
            return Err(OtpError::SecretTooLong {
                len: self.len(),
                max: MAX_SECRET_LEN,
            });
        }
        Ok(())
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Sound because the inner `Zeroizing` zeroizes in its own `Drop`.
impl zeroize::ZeroizeOnDrop for SecretBytes {}

impl ConstantTimeEq for SecretBytes {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SecretBytes {}

#[cfg(test)]
mod tests {
    use super::*;

    /// SPEC 3: a secret reaching a log line is a release blocker. This is the
    /// test that keeps the redaction honest.
    #[test]
    fn debug_and_display_leak_nothing() {
        let base32 = "JBSWY3DPEHPK3PXP";
        let secret = SecretBytes::from_base32(base32).unwrap();

        let debug = format!("{secret:?}");
        let display = format!("{secret}");
        let nested = format!("{:?}", Some(vec![secret.clone()]));

        for rendered in [&debug, &display, &nested] {
            assert!(rendered.contains("[redacted]"), "{rendered}");
            // No base32, in any case.
            assert!(
                !rendered.to_ascii_uppercase().contains(base32),
                "{rendered}"
            );
            // No hex.
            assert!(
                !rendered
                    .to_ascii_lowercase()
                    .contains(&*secret.to_hex().to_ascii_lowercase()),
                "{rendered}"
            );
            // No decimal byte values: `Vec<u8>`'s own Debug would print these.
            for byte in secret.expose_secret() {
                assert!(!rendered.contains(&byte.to_string()), "{rendered}");
            }
        }
        assert_eq!(debug, "[redacted]");
        assert_eq!(display, "[redacted]");
    }

    #[test]
    fn equality_is_length_and_value_sensitive() {
        let a = SecretBytes::from_slice(b"1234567890");
        let b = SecretBytes::from_slice(b"1234567890");
        let c = SecretBytes::from_slice(b"1234567891");
        let d = SecretBytes::from_slice(b"123456789");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn hex_and_base32_round_trip() {
        let secret = SecretBytes::from_slice(b"\x00\x01\xfe\xff");
        assert_eq!(&*secret.to_hex(), "0001feff");
        assert_eq!(SecretBytes::from_hex("0001feff").unwrap(), secret);
        assert_eq!(
            SecretBytes::from_base32(&secret.to_base32()).unwrap(),
            secret
        );
    }

    #[test]
    fn rejects_empty_and_over_long() {
        assert_eq!(SecretBytes::from_base32(""), Err(OtpError::EmptySecret));
        assert_eq!(SecretBytes::from_hex(""), Err(OtpError::EmptySecret));
        let long = "A".repeat(MAX_SECRET_LEN * 2 + 8);
        assert!(matches!(
            SecretBytes::from_base32(&long),
            Err(OtpError::SecretTooLong { .. })
        ));
        assert!(matches!(
            SecretBytes::from_hex(&"ab".repeat(MAX_SECRET_LEN + 1)),
            Err(OtpError::SecretTooLong { .. })
        ));
    }

    #[test]
    fn rejects_bad_hex() {
        assert_eq!(
            SecretBytes::from_hex("abc"),
            Err(OtpError::InvalidHexSecret)
        );
        assert_eq!(SecretBytes::from_hex("zz"), Err(OtpError::InvalidHexSecret));
    }
}
