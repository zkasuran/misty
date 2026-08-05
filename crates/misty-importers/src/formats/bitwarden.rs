// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bitwarden Authenticator, and Bitwarden's password-manager JSON export.
//!
//! ```json
//! { "encrypted": false,
//!   "folders": [ { "id": "…", "name": "Work" } ],
//!   "items": [ { "id": "…", "name": "GitHub", "type": 1, "favorite": false,
//!                "folderId": "…", "notes": null,
//!                "login": { "username": "ada@example.com",
//!                           "totp": "otpauth://totp/…",
//!                           "uris": [ { "uri": "https://github.com" } ] } } ] }
//! ```
//!
//! `login.totp` is the field that matters, and it holds one of three things: a whole
//! `otpauth://` URI, a bare base32 secret, or `steam://SECRET`. All three are
//! read. Everything else in a password-manager export — cards, notes, identities,
//! logins with no TOTP — is skipped as [`SkipReason::NoOtpSecret`], which is the
//! overwhelmingly common case and not a failure.
//!
//! An `"encrypted": true` export is refused: it is sealed with a key derived inside
//! the Bitwarden client from the account key, and Bitwarden's own UI offers an
//! unencrypted export instead.

use misty_otp::{OtpConfig, OtpKind, SecretBytes};
use serde_json::Value;

use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, Result, RowError};
use crate::formats::item_from_uri;
use crate::importer::{Confidence, Importer};
use crate::json::{self, Rec};
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId, SkipReason};
use crate::text;

/// Bitwarden's item type for a login. Cards, notes and identities cannot hold a
/// TOTP field.
const TYPE_LOGIN: u64 = 1;

/// Reads Bitwarden Authenticator and Bitwarden password-manager JSON exports.
#[derive(Debug, Clone, Copy, Default)]
pub struct BitwardenImporter;

impl Importer for BitwardenImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::Bitwarden
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if !text::starts_json_object(&head) {
            return Confidence::No;
        }
        if head.contains("\"items\"") && head.contains("\"encrypted\"") {
            return Confidence::Certain;
        }
        if head.contains("\"items\"") && head.contains("\"login\"") {
            return Confidence::Likely;
        }
        Confidence::No
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let doc = json::parse(input, ctx.limits())?;
        let root = Rec::object(&doc, self.format()).map_err(|_| ImportError::UnrecognizedFormat)?;

        if root.bool("encrypted") == Some(true) {
            return Err(ImportError::EncryptedNotSupported {
                format: SourceFormat::Bitwarden,
                advice: "export again with \"Export as\" set to .json (unencrypted)",
            });
        }

        let items = root
            .array("items")
            .ok_or(ImportError::MissingField("items"))?;
        let folders: Vec<(&str, &str)> = root
            .array("folders")
            .map(|folders| {
                folders
                    .iter()
                    .filter_map(|folder| {
                        let folder = Rec::raw(folder, SourceFormat::Bitwarden);
                        Some((folder.str("id")?, folder.str("name")?))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut collector = Collector::new(self.format(), ctx);
        for item in items {
            if collector.is_full() {
                return Err(ImportError::TooManyRows {
                    max: ctx.limits().max_rows,
                });
            }
            let row = RowId::at(collector.rows());
            match read_item(item, &folders, ctx) {
                Ok(Some((item, warnings))) => {
                    let row = row.labelled(item.issuer.as_deref(), &item.account);
                    collector.accept(row, item, warnings);
                }
                Ok(None) => collector.skip(row, SkipReason::NoOtpSecret),
                Err(error) => collector.fail(row, error),
            }
        }
        Ok(collector.finish())
    }
}

type EntryResult = core::result::Result<Option<(ImportedItem, Vec<ImportWarning>)>, RowError>;

fn read_item(item: &Value, folders: &[(&str, &str)], ctx: &ImportContext<'_>) -> EntryResult {
    let item = Rec::object(item, SourceFormat::Bitwarden)?;
    if item.u64("type")?.is_some_and(|kind| kind != TYPE_LOGIN) {
        return Ok(None);
    }
    let Some(login) = item.at("login") else {
        return Ok(None);
    };
    let Some(totp) = login.str("totp") else {
        return Ok(None);
    };

    let name = item.str("name");
    let username = login.str("username").or_else(|| login.str("email"));
    let (config, mut warnings, issuer, account) = totp_field(totp, name, username)?;

    let mut built = ImportedItem::new(SourceFormat::Bitwarden, config, issuer, account);
    built.note = text::non_empty(item.str("notes"));
    built.favorite = item.bool("favorite").unwrap_or(false);
    built.groups = item
        .str("folderId")
        .and_then(|id| {
            folders
                .iter()
                .find(|(folder_id, _)| *folder_id == id)
                .map(|(_, name)| (*name).to_owned())
        })
        .into_iter()
        .collect();
    built.origins = login
        .array("uris")
        .map(|uris| {
            uris.iter()
                .filter_map(|entry| {
                    Rec::raw(entry, SourceFormat::Bitwarden)
                        .str("uri")
                        .and_then(text::origin_of)
                })
                .take(ctx.limits().max_tags)
                .collect()
        })
        .unwrap_or_default();
    if item.str("organizationId").is_some() {
        warnings.push(ImportWarning::DroppedField("organizationId"));
    }
    Ok(Some((built, warnings)))
}

/// Read the three shapes `login.totp` comes in.
///
/// Shared with the Proton Pass and KeePassXC readers, which have the same problem:
/// one text field that is either a URI or a naked secret.
pub(crate) fn totp_field(
    raw: &str,
    name: Option<&str>,
    username: Option<&str>,
) -> core::result::Result<(OtpConfig, Vec<ImportWarning>, Option<String>, String), RowError> {
    let raw = raw.trim();

    if raw.len() >= 8
        && raw
            .get(..8)
            .is_some_and(|head| head.eq_ignore_ascii_case("otpauth:"))
    {
        let (item, warnings, _uri) = item_from_uri(SourceFormat::Bitwarden, raw)?;
        // The URI's own label wins where it has one; the item's name and username
        // are the fallback, because a password manager's TOTP field is often just
        // the secret with the naming kept outside it.
        let issuer = item
            .issuer
            .or_else(|| text::non_empty(name))
            .filter(|issuer| !issuer.is_empty());
        let account = if item.account.is_empty() {
            username.unwrap_or_default().to_owned()
        } else {
            item.account
        };
        return Ok((item.otp, warnings, issuer, account));
    }

    // `steam://SECRET` is how Bitwarden stores a Steam token.
    let (kind, secret_text) = match raw.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("steam") => (OtpKind::Steam, rest),
        Some(_) => return Err(RowError::InvalidField("totp")),
        None => (OtpKind::Totp, raw),
    };

    let secret = SecretBytes::from_base32(secret_text).map_err(RowError::Otp)?;
    let config = OtpConfig::builder(kind, secret)
        .build()
        .map_err(RowError::Otp)?;
    let warnings = if kind == OtpKind::Totp {
        // A bare secret carries no parameters at all, so every one of them is this
        // crate's default rather than the issuer's statement.
        vec![
            ImportWarning::AssumedDefault("algorithm"),
            ImportWarning::AssumedDefault("digits"),
            ImportWarning::AssumedDefault("period"),
        ]
    } else {
        Vec::new()
    };
    Ok((
        config,
        warnings,
        text::non_empty(name),
        username.unwrap_or_default().to_owned(),
    ))
}
