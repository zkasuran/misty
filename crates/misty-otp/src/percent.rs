// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Percent-encoding, strict in both directions.
//!
//! The `percent-encoding` crate decodes `%zz` to the literal text `%zz` instead
//! of failing. For a parser whose whole job is to reject hostile QR payloads
//! rather than guess at them (SPEC 7), silently passing through a malformed
//! escape is the wrong behaviour, so this module does its own decoding.

use crate::error::UriError;

/// Code points that are never legitimate in an issuer, account name, or
/// parameter value, and that exist to make text display as something other than
/// what it is: zero-width characters, bidirectional overrides and isolates, line
/// and paragraph separators, and the byte-order mark.
///
/// C0 and C1 control characters (including NUL) are rejected separately via
/// [`char::is_control`].
const SPOOFING_CHARS: &[char] = &[
    '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}', '\u{202a}',
    '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    '\u{feff}',
];

/// Decode `%XX` escapes.
///
/// Rejects a truncated or non-hex escape, bytes that are not valid UTF-8 once
/// decoded, control characters, and the display-spoofing code points listed in
/// [`SPOOFING_CHARS`]. Legitimate non-ASCII text (`日本`, `Bäckerei`) decodes
/// normally: an issuer name is not required to be ASCII.
pub(crate) fn decode(input: &str) -> Result<String, UriError> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let high = bytes.get(index + 1).copied().and_then(hex_nibble);
            let low = bytes.get(index + 2).copied().and_then(hex_nibble);
            let (Some(high), Some(low)) = (high, low) else {
                return Err(UriError::BadPercentEscape { offset: index });
            };
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }

    let text = String::from_utf8(decoded).map_err(|_| UriError::NotUtf8)?;
    if let Some(ch) = text
        .chars()
        .find(|ch| ch.is_control() || SPOOFING_CHARS.contains(ch))
    {
        return Err(UriError::ControlChar(u32::from(ch)));
    }
    Ok(text)
}

/// Percent-encode everything except the RFC 3986 unreserved set and `@`.
///
/// `@` stays literal because account names are usually email addresses and
/// `Issuer:ada@example.com` is what every other implementation writes. `:` is
/// *always* escaped, which is what makes the `issuer:account` label split
/// unambiguous: the only unescaped colon in a label this crate writes is the
/// separator it put there.
pub(crate) fn encode(value: &str) -> String {
    encode_bytes(value.as_bytes())
}

/// [`encode`] for values that are not required to be text, such as a PIN read
/// straight out of a vault.
pub(crate) fn encode_bytes(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex_upper(byte >> 4));
            out.push(hex_upper(byte & 0x0F));
        }
    }
    out
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_upper(nibble: u8) -> char {
    char::from(match nibble & 0x0F {
        digit @ 0..=9 => b'0' + digit,
        letter => b'A' + letter - 10,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_plain_and_escaped_text() {
        assert_eq!(decode("ACME%20Co").unwrap(), "ACME Co");
        assert_eq!(decode("ada%40example.com").unwrap(), "ada@example.com");
        assert_eq!(decode("a%3Ab").unwrap(), "a:b");
        assert_eq!(decode("").unwrap(), "");
        // Lowercase escapes, and a literal + is a literal + (RFC 3986, not
        // form encoding).
        assert_eq!(decode("%e6%97%a5+%f0%9f%94%91").unwrap(), "日+🔑");
    }

    #[test]
    fn rejects_malformed_escapes() {
        for input in ["%", "%2", "%zz", "%2z", "%%20", "abc%"] {
            assert!(
                matches!(decode(input), Err(UriError::BadPercentEscape { .. })),
                "should reject {input:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(decode("%ff"), Err(UriError::NotUtf8));
        assert_eq!(decode("%c3%28"), Err(UriError::NotUtf8));
        // A lone surrogate, the classic WTF-8 smuggling attempt.
        assert_eq!(decode("%ed%a0%80"), Err(UriError::NotUtf8));
    }

    #[test]
    fn rejects_control_and_spoofing_characters() {
        assert_eq!(decode("a%00b"), Err(UriError::ControlChar(0)));
        assert_eq!(decode("a\u{0}b"), Err(UriError::ControlChar(0)));
        assert_eq!(decode("a%0Ab"), Err(UriError::ControlChar(0x0A)));
        assert_eq!(decode("a%7Fb"), Err(UriError::ControlChar(0x7F)));
        assert_eq!(decode("%e2%80%ae"), Err(UriError::ControlChar(0x202E)));
        assert_eq!(decode("%ef%bb%bf"), Err(UriError::ControlChar(0xFEFF)));
    }

    #[test]
    fn encoding_round_trips() {
        for value in [
            "",
            "ACME",
            "ACME Co",
            "ada@example.com",
            "a:b",
            "a=b&c",
            "日本銀行",
            "100%",
            "?#/",
            "~-._",
        ] {
            let encoded = encode(value);
            assert_eq!(decode(&encoded).unwrap(), value, "for {value:?}");
        }
    }

    #[test]
    fn encoding_escapes_the_structural_characters() {
        assert_eq!(encode("a:b"), "a%3Ab");
        assert_eq!(encode("a=b"), "a%3Db");
        assert_eq!(encode("a&b"), "a%26b");
        assert_eq!(encode("a?b"), "a%3Fb");
        assert_eq!(encode("a#b"), "a%23b");
        assert_eq!(encode("a/b"), "a%2Fb");
        assert_eq!(encode("a%b"), "a%25b");
        assert_eq!(encode(" "), "%20");
        assert_eq!(encode("ada@example.com"), "ada@example.com");
    }
}
