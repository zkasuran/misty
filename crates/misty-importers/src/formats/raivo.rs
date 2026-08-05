// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Raivo OTP (iOS) JSON export.
//!
//! ```json
//! [ { "issuer": "GitHub", "account": "ada@example.com", "secret": "…",
//!     "algorithm": "SHA1", "digits": "6", "kind": "TOTP", "timer": "30",
//!     "counter": "0", "pinned": "false", "iconType": "", "iconValue": "" } ]
//! ```
//!
//! Every value is a **string**, including the numbers and the booleans — Raivo
//! exports its Core Data attributes verbatim. [`crate::json`] coerces them, which is
//! why this importer is short.
//!
//! Raivo also offers a ZIP archive with a password. That is refused: it needs a ZIP
//! reader, and a ZIP reader is a large amount of new attack surface to add to a
//! crate that parses hostile files, for one vendor's convenience wrapper. Raivo's
//! plain JSON export is in the same menu.

use serde_json::Value;

use crate::build::{self, OtpFields};
use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, Result, RowError};
use crate::importer::{Confidence, Importer};
use crate::json::{self, Rec};
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId, SkipReason};
use crate::text;

/// Reads Raivo OTP's JSON export.
#[derive(Debug, Clone, Copy, Default)]
pub struct RaivoImporter;

impl Importer for RaivoImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::Raivo
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if !text::starts_json_array(&head) {
            return Confidence::No;
        }
        // `timer` and `kind` together are Raivo's spelling and nobody else's.
        if head.contains("\"timer\"") && head.contains("\"kind\"") {
            return Confidence::Certain;
        }
        if head.contains("\"iconValue\"") || head.contains("\"iconType\"") {
            return Confidence::Likely;
        }
        Confidence::No
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let doc = json::parse(input, ctx.limits())?;
        let entries = doc
            .as_array()
            .ok_or(ImportError::InvalidField("(document root)"))?;

        let mut collector = Collector::new(self.format(), ctx);
        for entry in entries {
            if collector.is_full() {
                return Err(ImportError::TooManyRows {
                    max: ctx.limits().max_rows,
                });
            }
            let row = RowId::at(collector.rows());
            match read_entry(entry) {
                Ok(Some((item, warnings))) => {
                    let row = row.labelled(item.issuer.as_deref(), &item.account);
                    collector.accept(row, item, warnings);
                }
                Ok(None) => collector.skip(
                    row,
                    SkipReason::UnsupportedType(
                        Rec::raw(entry, SourceFormat::Raivo)
                            .text("kind")
                            .unwrap_or_default(),
                    ),
                ),
                Err(error) => collector.fail(row, error),
            }
        }
        Ok(collector.finish())
    }
}

type EntryResult = core::result::Result<Option<(ImportedItem, Vec<ImportWarning>)>, RowError>;

fn read_entry(entry: &Value) -> EntryResult {
    let entry = Rec::object(entry, SourceFormat::Raivo)?;
    let kind = match entry.str("kind") {
        Some(raw) => match build::kind_from_str(raw) {
            Some(kind) => kind,
            None => return Ok(None),
        },
        None => misty_otp::OtpKind::Totp,
    };

    let (config, warnings) = build::config(&OtpFields {
        default_kind: kind,
        secret: Some(entry.require_str("secret")?),
        algorithm: entry.str("algorithm"),
        digits: entry.u8("digits")?,
        period: entry.u16("timer")?,
        counter: entry.u64("counter")?,
        pin: entry.str("pin"),
        ..OtpFields::default()
    })?;

    let mut item = ImportedItem::new(
        SourceFormat::Raivo,
        config,
        entry.str("issuer").map(str::to_owned),
        entry.str("account").unwrap_or_default().to_owned(),
    );
    item.favorite = entry.bool("pinned").unwrap_or(false);
    // `iconType` names a provider ("Raivo", "Custom"); `iconValue` is the slug.
    item.icon_hint = text::non_empty(entry.str("iconValue"));
    Ok(Some((item, warnings)))
}
