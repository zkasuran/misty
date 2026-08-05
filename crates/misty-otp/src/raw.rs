// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Low-level primitives, one layer below [`OtpConfig`](crate::OtpConfig).
//!
//! These exist because the RFC 4226 test vectors publish intermediate values —
//! the raw HMAC and the truncated integer — and a test suite that only checks
//! final codes cannot tell a correct implementation from one that is wrong in
//! two cancelling ways. They are also the honest seam for an integration that
//! needs a moving factor this crate does not model.
//!
//! Everything here takes raw bytes: the caller is responsible for keeping key
//! material zeroized. Prefer [`OtpConfig`](crate::OtpConfig) for anything else.

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

use crate::config::HashAlg;
use crate::error::{OtpError, Result};

/// HMAC over an arbitrary message.
///
/// # Errors
///
/// Only [`OtpError::Internal`], and only if the HMAC construction rejects the
/// key length, which it never does: HMAC accepts keys of any length.
pub fn hmac(alg: HashAlg, key: &[u8], message: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // Same body for three concrete hashes. A generic function would need the
    // full `CoreProxy` bound salad for no benefit.
    macro_rules! mac_with {
        ($hash:ty) => {{
            let mut mac = <Hmac<$hash> as Mac>::new_from_slice(key)
                .map_err(|_| OtpError::Internal("hmac rejected the key length"))?;
            mac.update(message);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }};
    }

    Ok(match alg {
        HashAlg::Sha1 => mac_with!(sha1::Sha1),
        HashAlg::Sha256 => mac_with!(sha2::Sha256),
        HashAlg::Sha512 => mac_with!(sha2::Sha512),
    })
}

/// HMAC over a counter, the RFC 4226 message: the counter as 8 big-endian bytes.
///
/// # Errors
///
/// As [`hmac()`].
///
/// # Examples
///
/// RFC 4226 Appendix D publishes this value for counter 0:
///
/// ```
/// use misty_otp::{raw, HashAlg};
///
/// let digest = raw::hmac_counter(HashAlg::Sha1, b"12345678901234567890", 0)?;
/// let rendered: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
/// assert_eq!(rendered, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0");
/// assert_eq!(raw::dynamic_truncation(&digest)?, 1_284_755_224);
/// # Ok::<(), misty_otp::OtpError>(())
/// ```
pub fn hmac_counter(alg: HashAlg, key: &[u8], counter: u64) -> Result<Zeroizing<Vec<u8>>> {
    hmac(alg, key, &counter.to_be_bytes())
}

/// RFC 4226 section 5.3 dynamic truncation: take the low nibble of the last
/// byte as an offset, read four big-endian bytes there, and clear the high bit
/// so the result is a positive 31-bit integer regardless of the reader's
/// signedness.
///
/// # Errors
///
/// [`OtpError::Internal`] if `digest` is too short for the offset it names.
/// Unreachable for the hashes this crate supports, whose outputs are all at
/// least 20 bytes while the largest possible offset is 15.
pub fn dynamic_truncation(digest: &[u8]) -> Result<u32> {
    let last = digest
        .last()
        .ok_or(OtpError::Internal("cannot truncate an empty digest"))?;
    let offset = usize::from(last & 0x0F);
    let selected: [u8; 4] = digest
        .get(offset..offset + 4)
        .and_then(|window| window.try_into().ok())
        .ok_or(OtpError::Internal(
            "digest too short for dynamic truncation",
        ))?;
    Ok(u32::from_be_bytes(selected) & 0x7FFF_FFFF)
}

/// Reduce a truncated value to exactly `digits` decimal digits, zero-padded.
///
/// # Errors
///
/// [`OtpError::InvalidDigits`] if `digits` is out of range.
pub fn decimal_digits(value: u32, digits: u8) -> Result<Zeroizing<String>> {
    if !(crate::MIN_DIGITS..=crate::MAX_DIGITS).contains(&digits) {
        return Err(OtpError::InvalidDigits(u64::from(digits)));
    }
    let modulus = 10u64
        .checked_pow(u32::from(digits))
        .ok_or(OtpError::Internal("digit count overflowed the modulus"))?;
    let reduced = u64::from(value) % modulus;
    let width = usize::from(digits);
    Ok(Zeroizing::new(format!("{reduced:0width$}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_lengths_match_the_hash() {
        for alg in [HashAlg::Sha1, HashAlg::Sha256, HashAlg::Sha512] {
            assert_eq!(
                hmac_counter(alg, b"key", 1).unwrap().len(),
                alg.output_len()
            );
        }
    }

    #[test]
    fn empty_keys_and_messages_are_accepted() {
        assert_eq!(hmac(HashAlg::Sha1, b"", b"").unwrap().len(), 20);
    }

    #[test]
    fn truncation_rejects_short_digests() {
        // Last byte 0x0f names offset 15, needing 19 bytes.
        assert!(matches!(
            dynamic_truncation(&[0x0f; 18]),
            Err(OtpError::Internal(_))
        ));
        assert!(dynamic_truncation(&[0x0f; 19]).is_ok());
        assert!(matches!(
            dynamic_truncation(&[]),
            Err(OtpError::Internal(_))
        ));
    }

    #[test]
    fn truncation_clears_the_high_bit() {
        let digest = [0xFF; 20];
        // Offset 15, bytes ff ff ff ff, high bit cleared.
        assert_eq!(dynamic_truncation(&digest).unwrap(), 0x7FFF_FFFF);
    }

    #[test]
    fn digits_are_padded_and_range_checked() {
        assert_eq!(&*decimal_digits(7, 6).unwrap(), "000007");
        assert_eq!(&*decimal_digits(0, 1).unwrap(), "0");
        assert_eq!(&*decimal_digits(u32::MAX, 10).unwrap(), "4294967295");
        assert_eq!(&*decimal_digits(1_284_755_224, 6).unwrap(), "755224");
        for digits in [0, 11, 255] {
            assert!(decimal_digits(1, digits).is_err());
        }
    }
}
