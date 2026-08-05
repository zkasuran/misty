// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Proton Pass JSON export.
//!
//! ```json
//! { "version": "1.31.6", "encrypted": false,
//!   "vaults": { "<shareId>": { "name": "Personal", "items": [
//!     { "itemId": "…", "state": 1, "createTime": 1690000000, "pinned": false,
//!       "data": { "metadata": { "name": "GitHub", "note": "" },
//!                 "content": { "itemEmail": "ada@example.com", "urls": [ … ],
//!                              "totpUri": "otpauth://totp/…" },
//!                 "extraFields": [ { "fieldName": "backup", "type": "totp",
//!                                    "data": { "totpUri": "…" } } ] } } ] } } }
//! ```
//!
//! One Proton item can hold **several** TOTP secrets: the login's own `totpUri`
//! plus any number of `totp` extra fields. Each becomes its own row, because each
//! is its own credential, and an importer that kept only the first would silently
//! drop the backup token a careful user deliberately added.
//!
//! `state` 2 means trashed. Those are imported archived rather than dropped, for the
//! reason [`crate::formats::ente`] gives.
//!
//! An `"encrypted": true` export is a PGP file whose key lives in the Proton
//! client; it is refused with a pointer at the plain JSON export.

use serde_json::Value;

use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, Result, RowError};
use crate::formats::totp_field;
use crate::importer::{Confidence, Importer};
use crate::json::{self, Rec};
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId, SkipReason};
use crate::text;

/// Proton's item state for "in the trash".
const STATE_TRASHED: u64 = 2;

/// Reads Proton Pass JSON exports.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProtonPassImporter;

impl Importer for ProtonPassImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::ProtonPass
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if !text::starts_json_object(&head) {
            return Confidence::No;
        }
        if head.contains("\"vaults\"")
            && (head.contains("\"userId\"") || head.contains("\"encrypted\""))
        {
            return Confidence::Certain;
        }
        if head.contains("\"totpUri\"") {
            return Confidence::Likely;
        }
        Confidence::No
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let doc = json::parse(input, ctx.limits())?;
        let root = Rec::object(&doc, self.format()).map_err(|_| ImportError::UnrecognizedFormat)?;

        if root.bool("encrypted") == Some(true) {
            return Err(ImportError::EncryptedNotSupported {
                format: SourceFormat::ProtonPass,
                advice: "in Proton Pass, export as JSON rather than as an encrypted file",
            });
        }

        let vaults = root
            .at("vaults")
            .and_then(|vaults| vaults.value().as_object().cloned())
            .ok_or(ImportError::MissingField("vaults"))?;

        let mut collector = Collector::new(self.format(), ctx);
        for (_share_id, vault) in &vaults {
            let vault = Rec::raw(vault, SourceFormat::ProtonPass);
            let vault_name = vault.str("name").map(str::to_owned);
            let Some(items) = vault.array("items") else {
                continue;
            };
            for item in items {
                if collector.is_full() {
                    return Err(ImportError::TooManyRows {
                        max: ctx.limits().max_rows,
                    });
                }
                read_item(item, vault_name.as_deref(), &mut collector, ctx);
            }
        }
        Ok(collector.finish())
    }
}

/// Read one Proton item, which may hold zero, one, or several TOTP secrets.
fn read_item(
    item: &Value,
    vault: Option<&str>,
    collector: &mut Collector<'_, '_>,
    ctx: &ImportContext<'_>,
) {
    let row = RowId::at(collector.rows());
    let Ok(item) = Rec::object(item, SourceFormat::ProtonPass) else {
        collector.fail(row, RowError::WrongShape(SourceFormat::ProtonPass));
        return;
    };

    let Some(data) = item.at("data") else {
        collector.skip(row, SkipReason::NoOtpSecret);
        return;
    };
    let name = data.str("metadata.name");
    let account = data
        .str("content.itemEmail")
        .or_else(|| data.str("content.itemUsername"))
        .or_else(|| data.str("content.username"));

    // The login's own TOTP field, then every `totp` extra field, each its own row.
    let mut sources: Vec<(&str, Option<&str>)> = Vec::new();
    if let Some(uri) = data.str("content.totpUri") {
        sources.push((uri, None));
    }
    if let Some(fields) = data.array("extraFields") {
        for field in fields.iter().take(ctx.limits().max_tags) {
            let field = Rec::raw(field, SourceFormat::ProtonPass);
            let is_totp = field.str("type").is_some_and(|kind| {
                kind.eq_ignore_ascii_case("totp") || kind.eq_ignore_ascii_case("timebased")
            });
            if !is_totp {
                continue;
            }
            if let Some(uri) = field.str("data.totpUri").or_else(|| field.str("totpUri")) {
                sources.push((uri, field.str("fieldName")));
            }
        }
    }

    if sources.is_empty() {
        collector.skip(row, SkipReason::NoOtpSecret);
        return;
    }

    let trashed = item
        .u64("state")
        .ok()
        .flatten()
        .is_some_and(|state| state == STATE_TRASHED);

    for (uri, label) in sources {
        if collector.is_full() {
            return;
        }
        let row = RowId::at(collector.rows());
        match totp_field(uri, name, account) {
            Ok((config, mut warnings, issuer, account)) => {
                let mut built =
                    ImportedItem::new(SourceFormat::ProtonPass, config, issuer, account);
                built.nickname = text::non_empty(label);
                built.note = text::non_empty(data.str("metadata.note"));
                built.favorite = item.bool("pinned").unwrap_or(false);
                built.groups = vault.map(str::to_owned).into_iter().collect();
                // Proton records seconds; SPEC 3 wants milliseconds.
                built.created_at = item
                    .i64("createTime")
                    .filter(|at| *at > 0)
                    .map(|at| at * 1000);
                built.origins = data
                    .array("content.urls")
                    .map(|urls| {
                        urls.iter()
                            .filter_map(Value::as_str)
                            .filter_map(text::origin_of)
                            .take(ctx.limits().max_tags)
                            .collect()
                    })
                    .unwrap_or_default();
                if trashed {
                    built.archived = true;
                    warnings.push(ImportWarning::ImportedAsArchived);
                }
                let row = row.labelled(built.issuer.as_deref(), &built.account);
                collector.accept(row, built, warnings);
            }
            Err(error) => collector.fail(row, error),
        }
    }
}
