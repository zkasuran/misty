// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The result of generating a code, including everything the UI needs to draw a
//! countdown without doing time arithmetic of its own.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// When a time-based code is valid, precomputed for the UI.
///
/// All four fields are derived from one instant and one period, so they cannot
/// disagree with each other the way independently computed UI state does.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CodeWindow {
    /// Start of the code's validity window, Unix milliseconds. Always an exact
    /// multiple of the period.
    pub valid_from_ms: u64,
    /// End of the window, Unix milliseconds, exclusive.
    pub valid_until_ms: u64,
    /// Milliseconds left at the instant the code was generated. Always in
    /// `1..=period * 1000`; never zero, because the generating instant is inside
    /// the window by construction.
    pub remaining_ms: u64,
    /// Fraction of the window already elapsed, in `0.0..1.0`. A depleting
    /// progress ring wants `1.0 - progress`.
    pub progress: f32,
}

/// A generated one-time password.
///
/// [`fmt::Debug`] redacts the value so a code cannot land in a log line by
/// accident; [`fmt::Display`] renders it, because something has to show the user
/// their code. Counter-based codes (HOTP) have no [`CodeWindow`], which is why
/// the timing accessors return [`Option`].
///
/// # Examples
///
/// ```
/// use misty_otp::{OtpConfig, SecretBytes};
///
/// let config = OtpConfig::totp(SecretBytes::from_slice(b"12345678901234567890"))?;
/// let code = config.generate_at(59_500)?;
/// assert_eq!(code.value(), "287082");
/// assert_eq!(code.valid_from_ms(), Some(30_000));
/// assert_eq!(code.valid_until_ms(), Some(60_000));
/// assert_eq!(code.remaining_ms(), Some(500));
/// assert!(format!("{code:?}").contains("[redacted]"));
/// assert_eq!(format!("{code}"), "287082");
/// # Ok::<(), misty_otp::OtpError>(())
/// ```
#[derive(Clone)]
pub struct Code {
    value: Zeroizing<String>,
    window: Option<CodeWindow>,
}

impl Code {
    /// A time-based code and its validity window.
    pub(crate) fn time_based(value: Zeroizing<String>, window: CodeWindow) -> Self {
        Self {
            value,
            window: Some(window),
        }
    }

    /// A counter-based (HOTP) code, valid until it is used.
    pub(crate) fn counter_based(value: Zeroizing<String>) -> Self {
        Self {
            value,
            window: None,
        }
    }

    /// The code as text. Always exactly `digits` characters long.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Take the code's storage, so a caller that must own it does not copy it.
    #[must_use]
    pub fn into_value(self) -> Zeroizing<String> {
        self.value
    }

    /// Character count of the code, which equals the configured `digits`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.value.chars().count()
    }

    /// Always false; a generated code is never empty. Present because clippy
    /// asks for it next to [`Code::len`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// The validity window, or `None` for counter-based codes.
    #[must_use]
    pub fn window(&self) -> Option<CodeWindow> {
        self.window
    }

    /// Start of the validity window in Unix milliseconds; `None` for HOTP.
    #[must_use]
    pub fn valid_from_ms(&self) -> Option<u64> {
        self.window.map(|w| w.valid_from_ms)
    }

    /// End of the validity window in Unix milliseconds, exclusive; `None` for
    /// HOTP.
    #[must_use]
    pub fn valid_until_ms(&self) -> Option<u64> {
        self.window.map(|w| w.valid_until_ms)
    }

    /// Milliseconds of validity left at generation time; `None` for HOTP.
    #[must_use]
    pub fn remaining_ms(&self) -> Option<u64> {
        self.window.map(|w| w.remaining_ms)
    }

    /// Fraction of the window elapsed, `0.0..1.0`; `None` for HOTP.
    #[must_use]
    pub fn progress(&self) -> Option<f32> {
        self.window.map(|w| w.progress)
    }

    /// Compare against a user-supplied code in constant time.
    ///
    /// Use this instead of `==` anywhere a code is being verified: `==` on a
    /// `str` returns early on the first differing byte (SPEC 2.1).
    #[must_use]
    pub fn ct_eq(&self, candidate: &str) -> bool {
        self.value.as_bytes().ct_eq(candidate.as_bytes()).into()
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Code")
            .field("value", &"[redacted]")
            .field("window", &self.window)
            .finish()
    }
}

impl fmt::Display for Code {
    /// Renders the code itself. This is the one intentional way a code becomes
    /// text; do not put it in a log, a window title, or a notification
    /// (SPEC 9, A9).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code() -> Code {
        Code::time_based(
            Zeroizing::new("123456".to_owned()),
            CodeWindow {
                valid_from_ms: 30_000,
                valid_until_ms: 60_000,
                remaining_ms: 500,
                progress: 0.983_333_33,
            },
        )
    }

    #[test]
    fn debug_redacts_but_display_does_not() {
        let code = code();
        let debug = format!("{code:?}");
        assert!(debug.contains("[redacted]"), "{debug}");
        assert!(!debug.contains("123456"), "{debug}");
        assert_eq!(format!("{code}"), "123456");
    }

    #[test]
    fn counter_based_codes_have_no_window() {
        let code = Code::counter_based(Zeroizing::new("755224".to_owned()));
        assert_eq!(code.window(), None);
        assert_eq!(code.valid_from_ms(), None);
        assert_eq!(code.valid_until_ms(), None);
        assert_eq!(code.remaining_ms(), None);
        assert_eq!(code.progress(), None);
        assert_eq!(code.len(), 6);
        assert!(!code.is_empty());
    }

    #[test]
    fn constant_time_comparison_matches_equality() {
        let code = code();
        assert!(code.ct_eq("123456"));
        assert!(!code.ct_eq("123457"));
        assert!(!code.ct_eq("12345"));
        assert!(!code.ct_eq(""));
    }
}
