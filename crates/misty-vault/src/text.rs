// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What counts as acceptable text in a vault field.
//!
//! # Non-ASCII is not hostile
//!
//! `日本銀行` is a real bank and `Bücherei` is a real library. SPEC §7.2 settles
//! this for the URI parser and the same rule holds here: rejecting text because
//! it is not ASCII is a correctness bug dressed up as hardening. What is rejected
//! is text engineered to render as something other than what it is:
//!
//! * **control characters** — a `\r` in an issuer name can rewrite a log line,
//!   and an embedded NUL truncates the string in any C consumer downstream;
//! * **bidirectional overrides** (`U+202A`–`U+202E`, `U+2066`–`U+2069`) — the
//!   reason `moc.elpmaxe` can be made to display as `example.com`. Threat model
//!   `A11` is phishing, and an issuer name that lies about the site it belongs to
//!   is phishing with our own UI as the delivery vehicle;
//! * **zero-width characters** (`U+200B`–`U+200F`, `U+FEFF`) — two items whose
//!   issuers differ only by an invisible character look identical, which defeats
//!   the whole of SPEC §3.1;
//! * **a soft hyphen** (`U+00AD`) — invisible until it is at a line break.
//!
//! Notes are the one exception: a note is prose the user typed for themselves, so
//! newlines and tabs are allowed there. Nothing else is — a bare carriage return
//! included, because it can rewrite a terminal line just as `\r` in an issuer
//! name can. `\r\n` in pasted text is normalised to `\n` by
//! [`Edit::note`](crate::Edit::note) before it ever reaches this module.

use crate::error::{Result, VaultError};

/// Whether `ch` may never appear in vault text, note or label.
fn is_always_forbidden(ch: char) -> bool {
    matches!(ch,
        '\u{0}'..='\u{8}'
        | '\u{b}'..='\u{1f}'
        | '\u{7f}'..='\u{9f}'
        | '\u{ad}'
        | '\u{200b}'..='\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}'
        | '\u{feff}'
    )
}

/// Checks a single-line label: an issuer, an account, a nickname, a tag, an
/// origin, a group name, an icon slug.
///
/// # Errors
///
/// [`VaultError::StringTooLong`] past `max` bytes of UTF-8, or
/// [`VaultError::DisallowedCharacter`] for the classes named in the
/// [module docs](self).
pub fn check_label(field: &'static str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        return Err(VaultError::StringTooLong {
            field,
            max,
            found: value.len(),
        });
    }
    for (index, ch) in value.chars().enumerate() {
        if is_always_forbidden(ch) || ch == '\t' || ch == '\n' || ch == '\r' {
            return Err(VaultError::DisallowedCharacter {
                field,
                code: u32::from(ch),
                index,
            });
        }
    }
    Ok(())
}

/// As [`check_label`], and additionally rejects a label that is empty or
/// whitespace only.
///
/// `issuer` and `account` use this: an item whose account name is three spaces is
/// indistinguishable from one with no account name at all, and SPEC §3.1's
/// collision rule is defined on those two fields.
///
/// # Errors
///
/// [`VaultError::EmptyField`] for blank input, plus anything [`check_label`]
/// rejects.
pub fn check_required_label(field: &'static str, value: &str, max: usize) -> Result<()> {
    check_label(field, value, max)?;
    if value.trim().is_empty() {
        return Err(VaultError::EmptyField { field });
    }
    Ok(())
}

/// Checks multi-line prose: a note. Newlines and tabs are allowed; every other
/// forbidden class is not.
///
/// # Errors
///
/// As [`check_label`], minus the newline and tab rejections.
pub fn check_prose(field: &'static str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        return Err(VaultError::StringTooLong {
            field,
            max,
            found: value.len(),
        });
    }
    for (index, ch) in value.chars().enumerate() {
        if is_always_forbidden(ch) {
            return Err(VaultError::DisallowedCharacter {
                field,
                code: u32::from(ch),
                index,
            });
        }
    }
    Ok(())
}

/// The comparison key SPEC §3.1 collision detection uses.
///
/// Trimmed and lowercased, so `"GitHub"` and `" github "` are the same issuer.
/// This is `to_lowercase`, not `to_ascii_lowercase`: an account name written
/// `ADA@EXAMPLE.COM` in Turkish locale input still has to match `ada@example.com`,
/// and non-ASCII issuers are first-class here.
#[must_use]
pub fn fold(value: &str) -> String {
    value.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_world_non_ascii_is_accepted() {
        for value in ["日本銀行", "Bücherei", "Ωμέγα", "עברית", "🔐 Prod"] {
            assert!(check_label("issuer", value, 256).is_ok(), "{value}");
        }
    }

    #[test]
    fn adversarial_text_is_rejected_by_class() {
        let cases = [
            ("nul", "ada\u{0}@example.com"),
            ("newline", "ada\n@example.com"),
            ("carriage return", "ada\r@example.com"),
            ("tab", "ada\t@example.com"),
            ("delete", "ada\u{7f}"),
            ("c1", "ada\u{85}"),
            ("soft hyphen", "exam\u{ad}ple.com"),
            ("zero width space", "exa\u{200b}mple.com"),
            ("rtl override", "\u{202e}moc.elpmaxe"),
            ("isolate", "\u{2066}spoof\u{2069}"),
            ("bom", "\u{feff}GitHub"),
        ];
        for (what, value) in cases {
            assert!(
                matches!(
                    check_label("issuer", value, 256),
                    Err(VaultError::DisallowedCharacter {
                        field: "issuer",
                        ..
                    })
                ),
                "{what} was accepted"
            );
        }
    }

    #[test]
    fn prose_allows_layout_but_not_deception() {
        assert!(check_prose("note", "line one\nline two\tindented", 64).is_ok());
        assert!(check_prose("note", "sneaky\u{202e}", 64).is_err());
        assert!(check_prose("note", "sneaky\u{0}", 64).is_err());
    }

    #[test]
    fn length_is_measured_in_bytes_not_characters() {
        // Four characters, twelve bytes: a character-count limit would let a
        // hostile field be three times the intended size.
        let value = "日本銀行";
        assert_eq!(value.len(), 12);
        assert!(matches!(
            check_label("issuer", value, 11),
            Err(VaultError::StringTooLong {
                max: 11,
                found: 12,
                ..
            })
        ));
        assert!(check_label("issuer", value, 12).is_ok());
    }

    #[test]
    fn required_labels_reject_blanks() {
        for blank in ["", " ", "\u{3000}", "  \u{a0} "] {
            assert!(
                matches!(
                    check_required_label("account", blank, 64),
                    Err(VaultError::EmptyField { field: "account" })
                ),
                "{blank:?}"
            );
        }
        assert!(check_label("nickname", "", 64).is_ok());
    }

    #[test]
    fn folding_is_case_and_whitespace_insensitive() {
        assert_eq!(fold("  GitHub "), "github");
        assert_eq!(fold("ADA@Example.COM"), "ada@example.com");
        assert_eq!(fold("ÄÖÜ"), "äöü");
    }
}
