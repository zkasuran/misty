// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-row outcomes: the reason one bad line cannot cost a user 199 good ones.
//!
//! Every importer returns one [`RowOutcome`] per row it looked at, in file order,
//! alongside the items it managed to build. A malformed row produces
//! [`RowOutcome::Failed`] and the batch continues. This is the crate's central
//! safety property and `tests/hostile_inputs.rs` is what keeps it honest.

use core::fmt;

use serde::Serialize;

use crate::error::RowError;
use crate::model::{ImportedItem, ItemPreview, SourceFormat};

/// Which row an outcome is about.
///
/// Rows are identified by position and, where the format has one, by a label the
/// user will recognize. The label is built from issuer and account only —
/// never from the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RowId {
    /// Zero-based index of the row within its container.
    pub index: usize,
    /// One-based line number, for line-oriented formats (URI lists, CSV).
    pub line: Option<usize>,
    /// `Issuer: account`, where the row got far enough to have one.
    pub label: Option<String>,
}

impl RowId {
    /// A row identified only by position.
    #[must_use]
    pub const fn at(index: usize) -> Self {
        Self {
            index,
            line: None,
            label: None,
        }
    }

    /// A row identified by position and one-based line number.
    #[must_use]
    pub const fn at_line(index: usize, line: usize) -> Self {
        Self {
            index,
            line: Some(line),
            label: None,
        }
    }

    /// Attach a human-recognizable label. Truncated so a hostile row cannot make
    /// an error message unbounded.
    #[must_use]
    pub fn labelled(mut self, issuer: Option<&str>, account: &str) -> Self {
        const MAX_LABEL: usize = 96;
        let mut label = String::new();
        if let Some(issuer) = issuer.filter(|issuer| !issuer.is_empty()) {
            label.push_str(issuer);
            if !account.is_empty() {
                label.push_str(": ");
            }
        }
        label.push_str(account);
        // Truncate on a character boundary; a label is display text, not data.
        if label.len() > MAX_LABEL {
            let cut = label
                .char_indices()
                .map(|(at, _)| at)
                .take_while(|at| *at <= MAX_LABEL)
                .last()
                .unwrap_or(0);
            label.truncate(cut);
            label.push('…');
        }
        self.label = Some(label).filter(|label| !label.is_empty());
        self
    }
}

impl fmt::Display for RowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line, &self.label) {
            (Some(line), Some(label)) => write!(f, "line {line} ({label})"),
            (Some(line), None) => write!(f, "line {line}"),
            (None, Some(label)) => write!(f, "entry {} ({label})", self.index + 1),
            (None, None) => write!(f, "entry {}", self.index + 1),
        }
    }
}

/// What happened to one row.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RowOutcome {
    /// The row became an item.
    Imported {
        /// Which row.
        row: RowId,
        /// Index of the item in [`ImportReport::items`].
        item: usize,
        /// Everything the importer had to assume, normalize, or drop.
        warnings: Vec<ImportWarning>,
    },
    /// The row was understood and deliberately not imported.
    Skipped {
        /// Which row.
        row: RowId,
        /// Why.
        reason: SkipReason,
    },
    /// The row could not be read. **The batch continued.**
    Failed {
        /// Which row.
        row: RowId,
        /// What was wrong with it. Never contains a field value.
        error: RowError,
    },
}

impl RowOutcome {
    /// Which row this outcome is about.
    #[must_use]
    pub fn row(&self) -> &RowId {
        match self {
            Self::Imported { row, .. } | Self::Skipped { row, .. } | Self::Failed { row, .. } => {
                row
            }
        }
    }

    /// Whether an item was produced.
    #[must_use]
    pub const fn is_imported(&self) -> bool {
        matches!(self, Self::Imported { .. })
    }
}

impl fmt::Display for RowOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Imported { row, warnings, .. } if warnings.is_empty() => {
                write!(f, "{row}: imported")
            }
            Self::Imported { row, warnings, .. } => {
                write!(f, "{row}: imported with {} warning(s)", warnings.len())
            }
            Self::Skipped { row, reason } => write!(f, "{row}: skipped, {reason}"),
            Self::Failed { row, error } => write!(f, "{row}: failed, {error}"),
        }
    }
}

/// Why a row was understood but not imported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[non_exhaustive]
pub enum SkipReason {
    /// The caller already has this exact `(issuer, account, secret)` triple
    /// (SPEC 3.1: identical triples are a genuine duplicate).
    #[error("already present")]
    DuplicateOfExisting,
    /// An earlier row in the same file had the same triple.
    #[error("duplicate of an earlier row in this file")]
    DuplicateInBatch,
    /// The row is a record of some other kind — a password with no TOTP field, a
    /// KeePass entry with no `otp` attribute, a Proton note. Overwhelmingly the
    /// most common outcome when importing a password manager's export, and not a
    /// failure.
    #[error("no one-time-password secret in this entry")]
    NoOtpSecret,
    /// The row names an algorithm Misty will not generate codes with. MD5 turns
    /// up in Google's protobuf enum; `misty-otp` has no MD5 TOTP because no
    /// issuer uses one.
    #[error("unsupported algorithm {0:?}")]
    UnsupportedAlgorithm(String),
    /// The row names an OTP type this crate does not implement.
    #[error("unsupported token type {0:?}")]
    UnsupportedType(String),
    /// The secret is still encrypted with a key this crate cannot derive — an
    /// Authy `encrypted_seed`, for instance.
    #[error("the secret in this entry is still encrypted")]
    EncryptedSecret,
    /// The vendor had already deleted it and the caller asked not to import
    /// trash.
    #[error("deleted in the source application")]
    Deleted,
}

/// Something an importer had to assume, normalize, or drop.
///
/// Warnings are per row and never fatal. They exist because a lossy import that
/// says what it lost is honest, and one that stays quiet is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[non_exhaustive]
pub enum ImportWarning {
    /// The export did not state this parameter, so the format's documented
    /// default was used. For `counter` this matters: a wrong HOTP counter
    /// produces codes the server rejects.
    #[error("{0:?} was not stated; the format's default was assumed")]
    AssumedDefault(&'static str),
    /// The value the export gave was out of range or meaningless for the token
    /// kind, and was replaced by the kind's fixed value.
    #[error("{0:?} did not apply to this token kind and was normalized")]
    NormalizedParam(&'static str),
    /// Data the export carried that Misty's model has nowhere to put — embedded
    /// icon images, vendor-private flags, unknown `otpauth://` parameters.
    #[error("{0:?} was dropped: Misty's model has nowhere to keep it")]
    DroppedField(&'static str),
    /// The caller already has an item with this `(issuer, account)` but a
    /// **different** secret. SPEC 3.1 says these are two real accounts: both are
    /// kept, and the UI must make the user name them apart.
    #[error("an existing entry has the same issuer and account but a different secret")]
    CollidesWithExisting,
    /// The caller already has this exact triple, and asked for duplicates to be
    /// imported anyway ([`DuplicatePolicy::Keep`](crate::DuplicatePolicy)).
    #[error("already present; imported anyway because duplicates were not being skipped")]
    DuplicateOfExisting,
    /// Only a prefix of the stored secret is used by the construction — Yandex
    /// prints 26 bytes and keys with the first 16.
    #[error("only the first {0} bytes of this secret take part in the code")]
    SecretPrefixUsed(usize),
    /// The `otpauth://` parser reported something the input got away with.
    #[error("{0}")]
    Uri(String),
    /// The row was marked deleted or archived in the source application and was
    /// imported as archived rather than dropped.
    #[error("marked deleted in the source application; imported as archived")]
    ImportedAsArchived,
}

/// One part of a multi-part export.
///
/// Google Authenticator splits a large export across several QR codes, each a
/// complete `otpauth-migration://` URI carrying its own index and the total. A user
/// who scans one of three and sees "12 accounts imported" has lost two thirds of
/// their accounts and has no way to know it, which is why this is reported rather
/// than ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BatchPart {
    /// Zero-based index of this part.
    pub index: u32,
    /// How many parts the export has in total.
    pub total: u32,
}

/// Everything one import produced.
///
/// `items` and `outcomes` are separate lists on purpose: the caller inserts
/// items, and shows outcomes. [`RowOutcome::Imported::item`] indexes into
/// `items`, so a UI can join the two without matching on content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReport {
    /// The items, in file order. **Not** `Serialize`: they hold secrets.
    pub items: Vec<ImportedItem>,
    /// One outcome per row the importer looked at, in file order.
    pub outcomes: Vec<RowOutcome>,
    /// Which importer produced this.
    pub format: SourceFormat,
    /// Which parts of a multi-part export this file contained, in file order.
    /// Empty for every format that does not split its export.
    pub batch_parts: Vec<BatchPart>,
}

impl ImportReport {
    /// How many rows became items.
    #[must_use]
    pub fn imported(&self) -> usize {
        self.items.len()
    }

    /// How many rows were deliberately skipped.
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RowOutcome::Skipped { .. }))
            .count()
    }

    /// How many rows could not be read.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RowOutcome::Failed { .. }))
            .count()
    }

    /// Whether every row was read successfully.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.failed() == 0
    }

    /// Whether a multi-part export was complete: every part from `0` to
    /// `total - 1` present exactly once. `true` for formats that do not split.
    #[must_use]
    pub fn is_complete_batch(&self) -> bool {
        batch_is_complete(&self.batch_parts)
    }

    /// The parts of a multi-part export that this file did **not** contain.
    #[must_use]
    pub fn missing_batch_parts(&self) -> Vec<u32> {
        missing_parts(&self.batch_parts)
    }

    /// Turn this into the redacted preview the UI shows, consuming the secrets.
    ///
    /// The items are dropped — and therefore zeroized — as this returns, which is
    /// what makes [`Importer::preview`](crate::Importer::preview) a dry run rather
    /// than an import whose result the caller is trusted to throw away.
    #[must_use]
    pub fn into_preview(self) -> PreviewReport {
        let previews = self
            .outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                RowOutcome::Imported { item, warnings, .. } => self.items.get(*item).map(|item| {
                    let duplicate = warnings.contains(&ImportWarning::DuplicateOfExisting);
                    item.preview(duplicate, warnings)
                }),
                _ => None,
            })
            .collect();
        PreviewReport {
            items: previews,
            outcomes: self.outcomes,
            format: self.format,
            batch_parts: self.batch_parts,
        }
    }
}

/// Whether a set of parts covers `0..total` exactly once.
fn batch_is_complete(parts: &[BatchPart]) -> bool {
    missing_parts(parts).is_empty()
}

fn missing_parts(parts: &[BatchPart]) -> Vec<u32> {
    let Some(total) = parts.iter().map(|part| part.total).max() else {
        return Vec::new();
    };
    (0..total)
        .filter(|index| !parts.iter().any(|part| part.index == *index))
        .collect()
}

/// A dry run: exactly what an import would add, with every secret left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewReport {
    /// One preview per item that would be added, in file order.
    pub items: Vec<ItemPreview>,
    /// The same per-row outcomes the real import would report.
    #[serde(skip)]
    pub outcomes: Vec<RowOutcome>,
    /// Which importer produced this.
    pub format: SourceFormat,
    /// Which parts of a multi-part export this file contained.
    pub batch_parts: Vec<BatchPart>,
}

impl PreviewReport {
    /// How many items would be added.
    #[must_use]
    pub fn would_import(&self) -> usize {
        self.items.len()
    }

    /// Whether a multi-part export was complete.
    #[must_use]
    pub fn is_complete_batch(&self) -> bool {
        batch_is_complete(&self.batch_parts)
    }

    /// The parts of a multi-part export that this file did **not** contain.
    #[must_use]
    pub fn missing_batch_parts(&self) -> Vec<u32> {
        missing_parts(&self.batch_parts)
    }

    /// How many rows would be skipped.
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RowOutcome::Skipped { .. }))
            .count()
    }

    /// How many rows could not be read.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| matches!(outcome, RowOutcome::Failed { .. }))
            .count()
    }
}
