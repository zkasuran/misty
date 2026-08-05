// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The [`Importer`] trait, format sniffing, and the registry `detect` searches.

use crate::context::ImportContext;
use crate::error::{ImportError, Result};
use crate::model::SourceFormat;
use crate::outcome::{ImportReport, PreviewReport};

/// How sure an importer is that the bytes belong to it.
///
/// Ordered, so `detect` can pick the best answer. The generic CSV and JSON
/// importers never report better than [`Confidence::Possible`], which is what
/// stops a 2FAS backup being read as anonymous JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Not this format.
    No,
    /// Could be, on the strength of shape alone.
    Possible,
    /// Has this format's distinctive fields.
    Likely,
    /// Has a magic string only this format produces.
    Certain,
}

/// One format's reader.
///
/// Implementations are stateless unit structs; [`importers`] hands out shared
/// references to them.
pub trait Importer: Sync {
    /// Which format this reads.
    fn format(&self) -> SourceFormat;

    /// Whether these bytes look like this format. Must not allocate
    /// proportionally to the input, and must not panic: it runs on every
    /// importer for every file.
    fn sniff(&self, input: &[u8]) -> Confidence;

    /// Whether this particular file is encrypted and so needs
    /// [`ImportContext::with_passphrase`].
    ///
    /// Answered from the file rather than the format, because Aegis and andOTP
    /// each have a plain and an encrypted variant of the same extension.
    fn needs_passphrase(&self, _input: &[u8]) -> bool {
        false
    }

    /// Read the file.
    ///
    /// # Errors
    ///
    /// [`ImportError`] only when the *file* is unusable. A single unusable row is
    /// not an error: it is a [`RowOutcome::Failed`](crate::RowOutcome::Failed) in
    /// the report.
    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport>;

    /// A dry run: exactly what [`Importer::import`] would add, with the secrets
    /// left out.
    ///
    /// The default implementation imports and then drops the items, which is what
    /// makes the preview *exactly* the import rather than a second code path that
    /// might disagree with it. Dropping zeroizes them.
    ///
    /// # Errors
    ///
    /// As [`Importer::import`].
    fn preview(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<PreviewReport> {
        self.import(input, ctx).map(ImportReport::into_preview)
    }
}

/// What [`detect`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detection {
    /// The format.
    pub format: SourceFormat,
    /// How sure the importer was.
    pub confidence: Confidence,
    /// Whether this file needs a passphrase.
    pub needs_passphrase: bool,
}

/// Every importer, in priority order: specific formats first, the generic
/// CSV and JSON readers last.
#[must_use]
pub fn importers() -> &'static [&'static dyn Importer] {
    crate::formats::ALL
}

/// The importer for one format.
#[must_use]
pub fn importer_for(format: SourceFormat) -> Option<&'static dyn Importer> {
    importers()
        .iter()
        .copied()
        .find(|importer| importer.format() == format)
}

/// Every importer that recognizes these bytes, best first.
#[must_use]
pub fn detect_all(input: &[u8]) -> Vec<Detection> {
    let mut found: Vec<Detection> = importers()
        .iter()
        .filter_map(|importer| {
            let confidence = importer.sniff(input);
            (confidence > Confidence::No).then(|| Detection {
                format: importer.format(),
                confidence,
                needs_passphrase: importer.needs_passphrase(input),
            })
        })
        .collect();
    // A stable sort by descending confidence keeps registry order as the tiebreak,
    // which is what makes the generic readers lose to a vendor format.
    found.sort_by_key(|found| core::cmp::Reverse(found.confidence));
    found
}

/// The importer most likely to be right about these bytes.
#[must_use]
pub fn detect(input: &[u8]) -> Option<&'static dyn Importer> {
    detect_format(input).and_then(|found| importer_for(found.format))
}

/// [`detect`], but returning what was decided rather than the reader — so a UI
/// can say "this looks like an Aegis vault, and it needs your password" before
/// asking for anything.
#[must_use]
pub fn detect_format(input: &[u8]) -> Option<Detection> {
    detect_all(input).first().copied()
}

/// Detect and import in one step.
///
/// # Errors
///
/// [`ImportError::UnrecognizedFormat`] if nothing recognized the input, otherwise
/// whatever the chosen importer reports.
pub fn import_auto(input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
    detect(input)
        .ok_or(ImportError::UnrecognizedFormat)?
        .import(input, ctx)
}

/// Detect and preview in one step.
///
/// # Errors
///
/// As [`import_auto`].
pub fn preview_auto(input: &[u8], ctx: &ImportContext<'_>) -> Result<PreviewReport> {
    detect(input)
        .ok_or(ImportError::UnrecognizedFormat)?
        .preview(input, ctx)
}
