// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 4648 base32, with exactly the lenience real-world QR payloads need.
//!
//! Decoding accepts, per SPEC 7:
//!
//! * either case (`jbswy3dp` == `JBSWY3DP`),
//! * absent `=` padding (Google Authenticator omits it),
//! * ASCII whitespace anywhere (` `, `\t`, `\n`, `\r`, vertical tab, form feed),
//! * `-` anywhere, because printed secrets are grouped with hyphens.
//!
//! It rejects everything else, including characters outside the alphabet, `=`
//! followed by more data, and character counts that cannot encode whole bytes.
//!
//! Non-zero trailing bits in the final partial group are *tolerated* and
//! discarded rather than rejected. RFC 4648 section 3.5 permits either
//! behaviour, and rejecting would break otherwise-usable secrets from sloppy
//! provisioning tools.
//!
//! Encoding always produces the canonical form: uppercase, no separators. Use
//! [`encode`] (no padding, what `otpauth://` URIs carry in practice) or
//! [`encode_padded`] (strict RFC 4648 with `=`).

use crate::error::Base32Error;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Longest base32 input [`decode`] will look at, in bytes.
///
/// 4096 characters encode 2560 bytes, far beyond any legitimate OTP secret,
/// while keeping a hostile QR code from making us allocate.
pub const MAX_INPUT_CHARS: usize = 4096;

/// Decode base32, tolerating the sloppiness documented at the module level.
///
/// An empty (or separator-only) input decodes to an empty `Vec`; rejecting a
/// zero-length *secret* is [`SecretBytes`](crate::SecretBytes)' job, since that
/// is where the meaning lives.
///
/// # Errors
///
/// [`Base32Error`] if the input is over-long, contains a character outside the
/// alphabet and tolerated separators, has padding before the end of the data,
/// or has a significant-character count of `n % 8 in {1, 3, 6}`, which no whole
/// number of bytes can produce.
///
/// # Examples
///
/// ```
/// use misty_otp::base32;
///
/// assert_eq!(base32::decode("JBSWY3DP")?, b"Hello");
/// assert_eq!(base32::decode("jbsw y3dp")?, b"Hello");
/// assert_eq!(base32::decode("JBSW-Y3DP")?, b"Hello");
/// assert_eq!(base32::decode("MZXW6===")?, b"foo");
/// assert!(base32::decode("JBSWY3D1").is_err()); // '1' is not in the alphabet
/// # Ok::<(), misty_otp::Base32Error>(())
/// ```
pub fn decode(input: &str) -> Result<Vec<u8>, Base32Error> {
    if input.len() > MAX_INPUT_CHARS {
        return Err(Base32Error::TooLong {
            len: input.len(),
            max: MAX_INPUT_CHARS,
        });
    }

    let mut out = Vec::with_capacity(input.len() / 8 * 5 + 5);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut chars: usize = 0;
    let mut padding_at: Option<usize> = None;

    for (offset, ch) in input.char_indices() {
        let value = match ch {
            'A'..='Z' => u32::from(ch) - u32::from('A'),
            'a'..='z' => u32::from(ch) - u32::from('a'),
            '2'..='7' => u32::from(ch) - u32::from('2') + 26,
            ' ' | '\t' | '\n' | '\r' | '\u{0b}' | '\u{0c}' | '-' => continue,
            '=' => {
                if padding_at.is_none() {
                    padding_at = Some(offset);
                }
                continue;
            }
            _ => return Err(Base32Error::InvalidChar { ch, offset }),
        };

        if padding_at.is_some() {
            return Err(Base32Error::PaddingInMiddle { offset });
        }

        chars += 1;
        // Mask to 12 bits: `bits` is at most 7 here, so 12 bits is all that can
        // ever be significant, and masking keeps the shift from overflowing.
        acc = ((acc << 5) | value) & 0xFFF;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }

    // 1, 3 and 6 leftover characters carry 5, 15 and 30 bits: none is a whole
    // number of bytes plus discardable padding bits.
    if matches!(chars % 8, 1 | 3 | 6) {
        return Err(Base32Error::InvalidLength { chars });
    }

    Ok(out)
}

/// Encode to canonical unpadded uppercase base32.
///
/// This is what [`OtpUri::to_uri`](crate::OtpUri::to_uri) emits: padding is
/// legal in a URI query but some scanners choke on `=`, and every otpauth
/// producer in the wild omits it.
///
/// # Examples
///
/// ```
/// use misty_otp::base32;
///
/// assert_eq!(base32::encode(b"Hello"), "JBSWY3DP");
/// assert_eq!(base32::encode(b"foo"), "MZXW6");
/// ```
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    encode_inner(bytes, false)
}

/// Encode to canonical uppercase base32 with RFC 4648 `=` padding.
///
/// # Examples
///
/// ```
/// use misty_otp::base32;
///
/// assert_eq!(base32::encode_padded(b"foo"), "MZXW6===");
/// ```
#[must_use]
pub fn encode_padded(bytes: &[u8]) -> String {
    encode_inner(bytes, true)
}

fn encode_inner(bytes: &[u8], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in bytes {
        // At most 4 bits are pending, so 12 bits is all that can be significant.
        acc = ((acc << 8) | u32::from(byte)) & 0xFFF;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(symbol(acc >> bits));
        }
    }
    if bits > 0 {
        out.push(symbol(acc << (5 - bits)));
    }
    if pad {
        while out.len() % 8 != 0 {
            out.push('=');
        }
    }
    out
}

/// Map the low 5 bits of `value` to an alphabet character. The mask makes the
/// index unconditionally in range, so this cannot panic.
fn symbol(value: u32) -> char {
    char::from(ALPHABET[(value & 0x1F) as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 section 10 test vectors.
    const RFC4648: &[(&[u8], &str, &str)] = &[
        (b"", "", ""),
        (b"f", "MY", "MY======"),
        (b"fo", "MZXQ", "MZXQ===="),
        (b"foo", "MZXW6", "MZXW6==="),
        (b"foob", "MZXW6YQ", "MZXW6YQ="),
        (b"fooba", "MZXW6YTB", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI", "MZXW6YTBOI======"),
    ];

    #[test]
    fn rfc4648_vectors() {
        for (bytes, unpadded, padded) in RFC4648 {
            assert_eq!(encode(bytes), *unpadded, "encoding {bytes:?}");
            assert_eq!(encode_padded(bytes), *padded, "padded encoding {bytes:?}");
            assert_eq!(decode(unpadded).unwrap(), *bytes, "decoding {unpadded}");
            assert_eq!(decode(padded).unwrap(), *bytes, "decoding {padded}");
        }
    }

    #[test]
    fn lenient_inputs() {
        let expected = b"Hello".to_vec();
        for input in [
            "JBSWY3DP",
            "jbswy3dp",
            "JbSwY3dP",
            "JBSW Y3DP",
            "JBSW-Y3DP",
            " JBSW\tY3\nDP\r\n",
            "J-B-S-W-Y-3-D-P",
        ] {
            assert_eq!(decode(input).unwrap(), expected, "decoding {input:?}");
        }
    }

    #[test]
    fn tolerates_non_zero_trailing_bits() {
        // "MY" is 'f' with two zero trailing bits; "MZ" sets one of them.
        assert_eq!(decode("MY").unwrap(), b"f");
        assert_eq!(decode("MZ").unwrap(), b"f");
    }

    #[test]
    fn rejects_bad_alphabet() {
        assert_eq!(
            decode("JBSWY3D1"),
            Err(Base32Error::InvalidChar { ch: '1', offset: 7 })
        );
        assert!(matches!(
            decode("JBSWY3D\u{e9}"),
            Err(Base32Error::InvalidChar { ch: 'é', .. })
        ));
        assert!(matches!(
            decode("JBSWY3D_"),
            Err(Base32Error::InvalidChar { ch: '_', .. })
        ));
    }

    #[test]
    fn rejects_impossible_lengths() {
        for input in ["A", "ABC", "ABCDEF", "MZXW6YTBOIA"] {
            assert!(
                matches!(decode(input), Err(Base32Error::InvalidLength { .. })),
                "should reject {input:?}"
            );
        }
    }

    #[test]
    fn rejects_padding_in_the_middle() {
        assert!(matches!(
            decode("MZXW6===MZXW6==="),
            Err(Base32Error::PaddingInMiddle { .. })
        ));
    }

    #[test]
    fn rejects_over_long_input() {
        let huge = "A".repeat(MAX_INPUT_CHARS + 1);
        assert!(matches!(decode(&huge), Err(Base32Error::TooLong { .. })));
    }

    #[test]
    fn empty_decodes_to_empty() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode("  --  ").unwrap(), Vec::<u8>::new());
        assert_eq!(decode("====").unwrap(), Vec::<u8>::new());
    }
}
