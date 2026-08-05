// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Text handling shared by every importer: size and encoding checks, and the one
//! definition of which code points are allowed in a name.

use crate::context::Limits;
use crate::error::{ImportError, Result, RowError};

/// UTF-8 byte-order mark, which Windows exporters put in front of CSV and JSON.
const BOM: &str = "\u{feff}";

/// Check the size, reject an empty input, and decode as UTF-8.
///
/// A leading BOM is stripped: it is an encoding artefact, and leaving it in makes
/// the first header name of a CSV file mysteriously not match.
pub(crate) fn decode<'a>(input: &'a [u8], limits: &Limits) -> Result<&'a str> {
    if input.is_empty() {
        return Err(ImportError::Empty);
    }
    if input.len() > limits.max_input_bytes {
        return Err(ImportError::InputTooLarge {
            len: input.len(),
            max: limits.max_input_bytes,
        });
    }
    let text = core::str::from_utf8(input).map_err(|_| ImportError::NotUtf8)?;
    Ok(text.strip_prefix(BOM).unwrap_or(text))
}

/// Whether a code point must never appear in imported text.
///
/// The list is SPEC 7.2's, applied beyond the URI parser because the reasoning
/// does not stop there: an issuer with an embedded NUL or a right-to-left override
/// is a terminal- and log-injection vector wherever it came from. Ordinary
/// non-ASCII is **not** hostile — `日本銀行` is a real bank — and rejecting it
/// would be a correctness bug dressed up as hardening.
#[must_use]
pub(crate) fn is_forbidden(ch: char, allow_newlines: bool) -> bool {
    if allow_newlines && matches!(ch, '\n' | '\r' | '\t') {
        return false;
    }
    ch.is_control()
        || matches!(ch,
            // Bidirectional overrides and isolates.
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            // Zero-width and invisible formatting.
            | '\u{200b}'..='\u{200f}' | '\u{2060}'..='\u{2064}' | '\u{feff}'
        )
}

/// Validate one text field: length, then code points.
///
/// Rejects the row rather than sanitizing it, for the reason SPEC 7.2 gives about
/// the URI parser: a name that was silently rewritten is a name the user cannot
/// recognize, and guessing what they meant is worse than telling them which row
/// to fix.
pub(crate) fn check_field(
    field: &'static str,
    value: &str,
    max: usize,
    allow_newlines: bool,
) -> core::result::Result<(), RowError> {
    if value.len() > max {
        return Err(RowError::FieldTooLong {
            field,
            len: value.len(),
            max,
        });
    }
    if value.chars().any(|ch| is_forbidden(ch, allow_newlines)) {
        return Err(RowError::InvalidField(field));
    }
    Ok(())
}

/// Collapse a vendor's free-text field into something storable, or `None` if it
/// held nothing.
#[must_use]
pub(crate) fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// How much of a file every sniffer is allowed to look at.
///
/// Sniffing runs once per importer per file, so it must be bounded: fourteen
/// importers each scanning 32 MiB to answer "is this yours?" would be the slowest
/// part of an import.
pub(crate) const SNIFF_WINDOW: usize = 4096;

/// The first [`SNIFF_WINDOW`] bytes as text, lossily.
///
/// Lossy is right for a sniffer: it looks for ASCII markers, and a multi-byte
/// character cut in half at the window edge is not a reason to reject a file.
#[must_use]
pub(crate) fn sniff_text(input: &[u8]) -> String {
    let head = input.get(..SNIFF_WINDOW.min(input.len())).unwrap_or(input);
    String::from_utf8_lossy(head).into_owned()
}

/// Whether the text begins a JSON object, ignoring leading whitespace and a BOM.
#[must_use]
pub(crate) fn starts_json_object(text: &str) -> bool {
    first_meaningful(text) == Some('{')
}

/// Whether the text begins a JSON array.
#[must_use]
pub(crate) fn starts_json_array(text: &str) -> bool {
    first_meaningful(text) == Some('[')
}

fn first_meaningful(text: &str) -> Option<char> {
    text.strip_prefix(BOM)
        .unwrap_or(text)
        .chars()
        .find(|ch| !ch.is_whitespace())
}

/// Split a delimited list field, dropping empties and honouring the tag limit.
#[must_use]
pub(crate) fn split_list(value: &str, separator: char, max: usize) -> Vec<String> {
    value
        .split(separator)
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .take(max)
        .map(str::to_owned)
        .collect()
}

/// Split a label of the shape `Issuer:account`, the way `otpauth://` does.
///
/// Used by formats that store the whole label in one field — Google's protobuf
/// `name`, FreeOTP's key, andOTP's `label`. Splits on the **first** colon only,
/// and returns no issuer when there is nothing before it.
#[must_use]
pub(crate) fn split_label(label: &str) -> (Option<&str>, &str) {
    match label.split_once(':') {
        Some((issuer, account)) => {
            let issuer = issuer.trim();
            (
                Some(issuer).filter(|issuer| !issuer.is_empty()),
                account.trim(),
            )
        }
        None => (None, label.trim()),
    }
}

/// Reduce a URL to the host, for the `origins` list the extension matches
/// against. Returns `None` for anything that is not plausibly a host.
#[must_use]
pub(crate) fn origin_of(url: &str) -> Option<String> {
    let rest = url
        .split_once("://")
        .map_or(url, |(_scheme, rest)| rest)
        .trim();
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .rsplit('@')
        .next()
        .unwrap_or(rest);
    let host = host.split(':').next().unwrap_or(host);
    let ok = !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && !host
            .chars()
            .any(|ch| ch.is_whitespace() || is_forbidden(ch, false));
    ok.then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bom_is_stripped_not_rejected() {
        let limits = Limits::default();
        assert_eq!(
            decode("\u{feff}hello".as_bytes(), &limits).unwrap(),
            "hello"
        );
    }

    #[test]
    fn utf16_is_reported_as_an_encoding_problem() {
        let limits = Limits::default();
        // "ab" in UTF-16LE with a BOM: not valid UTF-8.
        let utf16 = [0xff, 0xfe, b'a', 0, b'b', 0];
        assert_eq!(decode(&utf16, &limits), Err(ImportError::NotUtf8));
    }

    #[test]
    fn empty_and_oversized_inputs_are_refused() {
        let limits = Limits {
            max_input_bytes: 4,
            ..Limits::default()
        };
        assert_eq!(decode(b"", &limits), Err(ImportError::Empty));
        assert_eq!(
            decode(b"12345", &limits),
            Err(ImportError::InputTooLarge { len: 5, max: 4 })
        );
    }

    #[test]
    fn legitimate_non_ascii_is_accepted_and_hostile_control_text_is_not() {
        assert!(check_field("issuer", "日本銀行", 64, false).is_ok());
        assert!(check_field("issuer", "Ünïcödé", 64, false).is_ok());
        assert_eq!(
            check_field("issuer", "ada\0evil", 64, false),
            Err(RowError::InvalidField("issuer"))
        );
        assert_eq!(
            check_field("issuer", "ada\u{202e}live", 64, false),
            Err(RowError::InvalidField("issuer"))
        );
        assert_eq!(
            check_field("issuer", "a\nb", 64, false),
            Err(RowError::InvalidField("issuer"))
        );
        // Notes are multi-line by nature.
        assert!(check_field("note", "line\nline\ttab", 64, true).is_ok());
        assert_eq!(
            check_field("note", "still\0no", 64, true),
            Err(RowError::InvalidField("note"))
        );
        assert!(matches!(
            check_field("issuer", "aaaa", 3, false),
            Err(RowError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn labels_split_on_the_first_colon() {
        assert_eq!(split_label("ACME:ada"), (Some("ACME"), "ada"));
        assert_eq!(split_label("ACME:ada:extra"), (Some("ACME"), "ada:extra"));
        assert_eq!(split_label("ada"), (None, "ada"));
        assert_eq!(split_label(":ada"), (None, "ada"));
        assert_eq!(split_label(" ACME : ada "), (Some("ACME"), "ada"));
    }

    #[test]
    fn origins_reduce_to_hosts() {
        assert_eq!(
            origin_of("https://GitHub.com/login?next=1"),
            Some("github.com".to_owned())
        );
        assert_eq!(
            origin_of("http://user:pw@example.co.uk:8443/x"),
            Some("example.co.uk".to_owned())
        );
        assert_eq!(origin_of("localhost"), None);
        assert_eq!(origin_of(""), None);
        assert_eq!(origin_of("not a url"), None);
    }
}
