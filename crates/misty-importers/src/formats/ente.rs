// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ente Auth's plaintext export.
//!
//! The file is a list of `otpauth://` URIs, one per line, with one extra
//! parameter:
//!
//! ```text
//! otpauth://totp/GitHub:ada?secret=…&issuer=GitHub&algorithm=SHA1&digits=6&period=30
//!   &codeDisplay=%7B%22pinned%22%3Afalse%2C%22trashed%22%3Afalse%2C%22tags%22%3A%5B%5D%7D
//! ```
//!
//! `codeDisplay` is a percent-encoded JSON object holding what Ente shows in its
//! list: `pinned`, `trashed`, `tags`, `note`, `position`, `lastUsedAt`, `tapCount`.
//! Reading it is the difference between importing somebody's starred and deleted
//! entries as an undifferentiated pile and importing them as they were.
//!
//! A trashed entry is imported **archived**, not dropped: Ente's trash is
//! recoverable, and silently discarding a token during a migration is the one
//! mistake that cannot be undone from the destination.
//!
//! # Ente's encrypted export
//!
//! Refused, deliberately. It is a libsodium `crypto_secretstream_xchacha20poly1305`
//! payload under an Argon2id key, and the chunked stream framing — 24-byte header,
//! per-chunk 17-byte overhead, implicit nonce advance — is not something to
//! reimplement from memory against a file format this crate has never seen. Getting
//! it subtly wrong produces "wrong password" for a correct password, which is worse
//! than a clear refusal. Ente offers a plaintext export in the same menu.

use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, Result};
use crate::formats::{is_uri_line, item_from_uri, sniff_uri_list};
use crate::importer::{Confidence, Importer};
use crate::model::SourceFormat;
use crate::outcome::{ImportReport, ImportWarning, RowId};
use crate::text;

/// The parameter that distinguishes an Ente export from any other URI list.
const MARKER: &str = "codeDisplay";

/// Reads Ente Auth's plaintext `otpauth://` export.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnteAuthImporter;

impl Importer for EnteAuthImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::EnteAuth
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if text::starts_json_object(&head) && head.contains("\"encryptedData\"") {
            // An encrypted Ente export: recognized so the error can say what to do,
            // rather than falling through to "unrecognized format".
            return Confidence::Likely;
        }
        sniff_uri_list(input, Some(MARKER))
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let text = text::decode(input, ctx.limits())?;
        if text::starts_json_object(text) {
            return Err(ImportError::EncryptedNotSupported {
                format: SourceFormat::EnteAuth,
                advice: "in Ente Auth, choose Export ▸ plain text instead of encrypted",
            });
        }

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
                Ok((mut item, mut warnings, uri)) => {
                    // `item_from_uri` already reported that vendor parameters were
                    // dropped. Here they are not dropped, so that warning is
                    // replaced by what was actually read.
                    warnings.retain(|warning| {
                        *warning != ImportWarning::DroppedField("uri parameters")
                    });
                    let display = uri
                        .extra()
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(MARKER))
                        .map(|(_, value)| value.as_str());
                    apply_code_display(&mut item, &mut warnings, display, ctx);
                    let row = row.labelled(item.issuer.as_deref(), &item.account);
                    collector.accept(row, item, warnings);
                }
                Err(error) => collector.fail(row, error),
            }
        }

        let report = collector.finish();
        if report.outcomes.is_empty() {
            return Err(ImportError::UnrecognizedFormat);
        }
        Ok(report)
    }
}

/// Fold Ente's `codeDisplay` blob into the item.
///
/// A malformed blob is not a row failure: it carries presentation, and losing a
/// star is not losing an account. Anything unreadable becomes a dropped-field
/// warning.
fn apply_code_display(
    item: &mut crate::model::ImportedItem,
    warnings: &mut Vec<ImportWarning>,
    raw: Option<&str>,
    ctx: &ImportContext<'_>,
) {
    let Some(raw) = raw else { return };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        warnings.push(ImportWarning::DroppedField(MARKER));
        return;
    };
    let display = crate::json::Rec::raw(&value, SourceFormat::EnteAuth);

    item.favorite = display.bool("pinned").unwrap_or(false);
    item.tags = display.strings("tags", ctx.limits());
    item.note = text::non_empty(display.str("note"));
    // `lastUsedAt` is deliberately not imported: Ente records times in
    // microseconds in some places and milliseconds in others, and this crate has
    // no real export to confirm which this field is. A last-used time that is off
    // by a factor of a thousand sorts a list wrongly forever, and SPEC 3.1 leans on
    // that field to disambiguate same-issuer accounts. See README.md.
    if display.bool("trashed") == Some(true) {
        item.archived = true;
        warnings.push(ImportWarning::ImportedAsArchived);
    }
    if display.str("iconSrc").is_some() || display.str("iconID").is_some() {
        warnings.push(ImportWarning::DroppedField("icon"));
    }
}
