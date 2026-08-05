// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! LastPass Authenticator JSON export.
//!
//! ```json
//! { "version": 3, "deviceName": "Pixel", "deviceSecret": "…",
//!   "folders": [ { "id": 1, "name": "Work", "isOpened": true } ],
//!   "accounts": [ { "accountID": "…", "issuerName": "GitHub",
//!                   "originalIssuerName": "GitHub", "userName": "ada@example.com",
//!                   "originalUserName": "ada@example.com", "secret": "…",
//!                   "timeStep": 30, "digits": 6, "algorithm": "SHA1",
//!                   "creationTimestamp": 1690000000000, "isFavorite": false,
//!                   "folderData": { "folderId": 1, "position": 0 },
//!                   "pushNotification": false } ] }
//! ```
//!
//! `issuerName` and `userName` are what the user may have renamed;
//! `originalIssuerName` and `originalUserName` are what the QR code said. The
//! renamed pair is what a user recognizes in a list, so that is what is imported,
//! and the original is kept as the nickname when the two differ — SPEC 3.1 wants
//! same-issuer accounts distinguishable, and this is free distinguishing
//! information.
//!
//! `deviceSecret` is LastPass's own device seed, not an account credential. It is
//! not imported.
//!
//! LastPass Authenticator has only ever exported time-based tokens, so there is no
//! type field to read.

use serde_json::Value;

use crate::build::{self, OtpFields};
use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, Result, RowError};
use crate::importer::{Confidence, Importer};
use crate::json::{self, Rec};
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId};

use crate::text;

/// Reads LastPass Authenticator's JSON export.
#[derive(Debug, Clone, Copy, Default)]
pub struct LastPassImporter;

impl Importer for LastPassImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::LastPass
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if !text::starts_json_object(&head) {
            return Confidence::No;
        }
        if head.contains("\"accounts\"")
            && (head.contains("\"issuerName\"") || head.contains("\"deviceSecret\""))
        {
            return Confidence::Certain;
        }
        if head.contains("\"originalIssuerName\"") || head.contains("\"timeStep\"") {
            return Confidence::Likely;
        }
        Confidence::No
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let doc = json::parse(input, ctx.limits())?;
        let root = Rec::object(&doc, self.format()).map_err(|_| ImportError::UnrecognizedFormat)?;
        let accounts = root
            .array("accounts")
            .ok_or(ImportError::MissingField("accounts"))?;

        let folders: Vec<(String, &str)> = root
            .array("folders")
            .map(|folders| {
                folders
                    .iter()
                    .filter_map(|folder| {
                        let folder = Rec::raw(folder, SourceFormat::LastPass);
                        Some((folder.text("id")?, folder.str("name")?))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut collector = Collector::new(self.format(), ctx);
        for account in accounts {
            if collector.is_full() {
                return Err(ImportError::TooManyRows {
                    max: ctx.limits().max_rows,
                });
            }
            let row = RowId::at(collector.rows());
            match read_account(account, &folders) {
                Ok((item, warnings)) => {
                    let row = row.labelled(item.issuer.as_deref(), &item.account);
                    collector.accept(row, item, warnings);
                }
                Err(error) => collector.fail(row, error),
            }
        }
        Ok(collector.finish())
    }
}

fn read_account(
    account: &Value,
    folders: &[(String, &str)],
) -> core::result::Result<(ImportedItem, Vec<ImportWarning>), RowError> {
    let account = Rec::object(account, SourceFormat::LastPass)?;

    let (config, warnings) = build::config(&OtpFields {
        secret: Some(account.require_str("secret")?),
        algorithm: account.str("algorithm"),
        digits: account.u8("digits")?,
        period: account.u16("timeStep")?,
        ..OtpFields::default()
    })?;

    let issuer = account.str("issuerName");
    let original_issuer = account.str("originalIssuerName");
    let user = account.str("userName");
    let original_user = account.str("originalUserName");

    let mut item = ImportedItem::new(
        SourceFormat::LastPass,
        config,
        issuer.or(original_issuer).map(str::to_owned),
        user.or(original_user).unwrap_or_default().to_owned(),
    );
    // Keep the original naming only when the user changed it, and only when it
    // says something the imported pair does not.
    let renamed = match (original_issuer, original_user) {
        (Some(issuer), Some(user)) => Some(format!("{issuer}: {user}")),
        (Some(only), None) => Some(only.to_owned()),
        (None, Some(only)) => Some(only.to_owned()),
        (None, None) => None,
    };
    let current = match (issuer, user) {
        (Some(issuer), Some(user)) => Some(format!("{issuer}: {user}")),
        (Some(only), None) => Some(only.to_owned()),
        (None, Some(only)) => Some(only.to_owned()),
        (None, None) => None,
    };
    if renamed != current {
        item.nickname = renamed;
    }

    item.favorite = account.bool("isFavorite").unwrap_or(false);
    item.created_at = account.i64("creationTimestamp").filter(|at| *at > 0);
    item.groups = account
        .text("folderData.folderId")
        .and_then(|id| {
            folders
                .iter()
                .find(|(folder_id, _)| *folder_id == id)
                .map(|(_, name)| (*name).to_owned())
        })
        .into_iter()
        .collect();
    Ok((item, warnings))
}
