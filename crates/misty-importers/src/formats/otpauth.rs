// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `otpauth://` URIs: one scanned QR code, or a text file of them.
//!
//! The parsing is entirely `misty-otp`'s. This module's job is the file around the
//! URIs: line splitting, comments, blank lines, and turning one bad line into one
//! failed row instead of a failed import.

use misty_otp::{OtpUri, UriWarning};

use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, Result, RowError};
use crate::importer::{Confidence, Importer};
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId};
use crate::text;

/// Reads a file of `otpauth://` URIs, one per line.
///
/// This is the format every other authenticator can also read, which is why it is
/// the one Misty exports. Blank lines and `#` comments are ignored, so a user can
/// annotate the file.
#[derive(Debug, Clone, Copy, Default)]
pub struct OtpauthImporter;

/// Turn one `otpauth://` URI into an item, with the parser's warnings translated.
///
/// Shared with the Ente Auth importer, whose plaintext export is a URI list with
/// one extra parameter.
pub(crate) fn item_from_uri(
    source: SourceFormat,
    line: &str,
) -> core::result::Result<(ImportedItem, Vec<ImportWarning>, OtpUri), RowError> {
    let (uri, uri_warnings) = OtpUri::parse_with_warnings(line)?;
    let item = ImportedItem::from_uri(source, &uri);
    let mut warnings: Vec<ImportWarning> = uri_warnings
        .iter()
        .map(|warning| match warning {
            UriWarning::IgnoredParam { name } => ImportWarning::NormalizedParam(name),
            other => ImportWarning::Uri(other.to_string()),
        })
        .collect();
    if !uri.extra().is_empty() {
        // Vendor parameters are somebody's icon or colour. `misty-otp` keeps them
        // for its own round-trip, but Misty's model has nowhere to store them, so
        // say they were dropped rather than let the user find out later.
        warnings.push(ImportWarning::DroppedField("uri parameters"));
    }
    Ok((item, warnings, uri))
}

/// Whether a line is worth trying to parse at all.
pub(crate) fn is_uri_line(line: &str) -> bool {
    !line.is_empty() && !line.starts_with('#')
}

/// Shared sniffer for the URI-list formats.
///
/// Looks at a bounded prefix: sniffing runs for every importer on every file and
/// must not walk 32 MiB. Decoding is lossy because a sniffer only needs to
/// recognize ASCII markers, and a multi-byte character straddling the window is
/// not a reason to give up on the file.
pub(crate) fn sniff_uri_list(input: &[u8], required_param: Option<&str>) -> Confidence {
    const WINDOW: usize = 4096;
    let head = input.get(..WINDOW.min(input.len())).unwrap_or(input);
    sniff_uri_text(&String::from_utf8_lossy(head), required_param)
}

fn sniff_uri_text(text: &str, required_param: Option<&str>) -> Confidence {
    let mut saw_uri = false;
    for line in text.lines().take(64) {
        let line = line.trim();
        if !is_uri_line(line) {
            continue;
        }
        if line.len() >= 12
            && line
                .get(..12)
                .is_some_and(|head| head.eq_ignore_ascii_case("otpauth-mig"))
        {
            // That is the migration importer's payload, not this one's.
            return Confidence::No;
        }
        let is_uri = line
            .get(..10)
            .is_some_and(|head| head.eq_ignore_ascii_case("otpauth://"));
        if !is_uri {
            continue;
        }
        saw_uri = true;
        match required_param {
            Some(param) => {
                if line.contains(param) {
                    return Confidence::Certain;
                }
            }
            None => return Confidence::Certain,
        }
    }
    if saw_uri {
        // A URI list without the distinctive parameter: it is somebody's list,
        // just not this format's.
        Confidence::Possible
    } else {
        Confidence::No
    }
}

impl Importer for OtpauthImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::Otpauth
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        match sniff_uri_list(input, None) {
            // Ente's export is also a URI list; both importers claim it, and this
            // one reads it correctly minus the `codeDisplay` metadata.
            Confidence::Certain => Confidence::Likely,
            other => other,
        }
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let text = text::decode(input, ctx.limits())?;
        let mut collector = Collector::new(self.format(), ctx);

        for (offset, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if !is_uri_line(line) {
                continue;
            }
            if collector.is_full() {
                return Err(ImportError::TooManyRows {
                    max: ctx.limits().max_rows,
                });
            }
            let row = RowId::at_line(collector.rows(), offset + 1);
            match item_from_uri(self.format(), line) {
                Ok((item, warnings, uri)) => {
                    let row = row.labelled(uri.issuer(), uri.account());
                    collector.accept(row, item, warnings);
                }
                Err(error) => collector.fail(row, error),
            }
        }

        let report = collector.finish();
        if report.outcomes.is_empty() {
            // Nothing that even looked like a URI: this was not our file.
            return Err(ImportError::UnrecognizedFormat);
        }
        Ok(report)
    }
}

impl OtpauthImporter {
    /// Parse exactly one URI, the shape a QR scan hands over.
    ///
    /// # Errors
    ///
    /// [`RowError`] if the URI is unusable. Unlike [`Importer::import`], this has
    /// no batch to isolate a failure from, so the failure is the return value.
    pub fn one(uri: &str) -> core::result::Result<ImportedItem, RowError> {
        item_from_uri(SourceFormat::Otpauth, uri.trim()).map(|(item, _, _)| item)
    }
}
