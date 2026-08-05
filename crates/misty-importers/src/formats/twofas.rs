// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! 2FAS backups.
//!
//! ```json
//! { "services": [
//!     { "name": "GitHub", "secret": "…", "updatedAt": 1690000000000,
//!       "otp": { "account": "ada@example.com", "issuer": "GitHub", "digits": 6,
//!                "period": 30, "algorithm": "SHA1", "tokenType": "TOTP",
//!                "counter": 0, "link": "otpauth://…" },
//!       "order": { "position": 0 }, "groupId": null } ],
//!   "groups": [ { "id": "…", "name": "Work" } ],
//!   "schemaVersion": 4, "appOrigin": "android" }
//! ```
//!
//! An encrypted backup replaces `services` with `servicesEncrypted`, a
//! colon-separated triple of base64: `ciphertext‖tag : salt : iv`, opened with
//! AES-256-GCM under `PBKDF2(password, salt, 10000, 32)`.
//!
//! **Unverified, and labelled as such in `README.md`.** The plaintext shape is from
//! 2FAS's published backup schema and is solid; the encrypted parameters are from
//! third-party importers and this crate has never seen a real encrypted 2FAS
//! backup. Both PBKDF2 hashes are therefore tried, for the reason
//! [`crate::formats::andotp`] gives: AES-GCM authenticates, so at most one key can
//! be right, and a user with the correct password should not be told it is wrong
//! because of a parameter nobody could check.

use serde_json::Value;
use zeroize::Zeroizing;

use crate::build::{self, OtpFields};
use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, Result, RowError};
use crate::importer::{Confidence, Importer};
use crate::interop;
use crate::json::{self, Rec};
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId, SkipReason};
use crate::text;

/// Iteration count 2FAS is reported to use.
const ITERATIONS: u64 = 10_000;

/// Reads 2FAS JSON backups, encrypted or not.
#[derive(Debug, Clone, Copy, Default)]
pub struct TwoFasImporter;

impl Importer for TwoFasImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::TwoFas
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if !text::starts_json_object(&head) {
            return Confidence::No;
        }
        if head.contains("\"schemaVersion\"")
            && (head.contains("\"services\"") || head.contains("\"servicesEncrypted\""))
        {
            return Confidence::Certain;
        }
        if head.contains("\"servicesEncrypted\"") || head.contains("\"appOrigin\"") {
            return Confidence::Likely;
        }
        Confidence::No
    }

    fn needs_passphrase(&self, input: &[u8]) -> bool {
        text::sniff_text(input).contains("\"servicesEncrypted\"")
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let doc = json::parse(input, ctx.limits())?;
        let root =
            Rec::object(&doc, SourceFormat::TwoFas).map_err(|_| ImportError::UnrecognizedFormat)?;

        let groups: Vec<(&str, &str)> = root
            .array("groups")
            .map(|groups| {
                groups
                    .iter()
                    .filter_map(|group| {
                        let group = Rec::raw(group, SourceFormat::TwoFas);
                        Some((group.str("id")?, group.str("name")?))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // The decrypted services array has to outlive the borrow of it below.
        let decrypted: Option<Value> = match root.str("servicesEncrypted") {
            Some(encrypted) => {
                let plaintext = decrypt(encrypted, ctx)?;
                Some(
                    serde_json::from_slice(&plaintext).map_err(|error| ImportError::Json {
                        line: error.line(),
                        column: error.column(),
                    })?,
                )
            }
            None => None,
        };

        let services = match &decrypted {
            Some(value) => value
                .as_array()
                .ok_or(ImportError::InvalidField("servicesEncrypted"))?,
            None => root
                .array("services")
                .ok_or(ImportError::MissingField("services"))?,
        };

        let mut collector = Collector::new(SourceFormat::TwoFas, ctx);
        for service in services {
            if collector.is_full() {
                return Err(ImportError::TooManyRows {
                    max: ctx.limits().max_rows,
                });
            }
            let row = RowId::at(collector.rows());
            match read_service(service, &groups) {
                Ok(Some((item, warnings))) => {
                    let row = row.labelled(item.issuer.as_deref(), &item.account);
                    collector.accept(row, item, warnings);
                }
                Ok(None) => collector.skip(
                    row,
                    SkipReason::UnsupportedType(
                        Rec::raw(service, SourceFormat::TwoFas)
                            .text("otp.tokenType")
                            .unwrap_or_default(),
                    ),
                ),
                Err(error) => collector.fail(row, error),
            }
        }
        Ok(collector.finish())
    }
}

/// Open `servicesEncrypted`.
fn decrypt(field: &str, ctx: &ImportContext<'_>) -> Result<Zeroizing<Vec<u8>>> {
    use base64::Engine as _;
    let passphrase = ctx
        .passphrase()
        .ok_or(ImportError::PassphraseRequired(SourceFormat::TwoFas))?;

    let mut parts = field.split(':');
    let engine = &base64::engine::general_purpose::STANDARD;
    let decode = |part: Option<&str>, name: &'static str| {
        part.map(str::trim)
            .filter(|part| !part.is_empty())
            .and_then(|part| engine.decode(part).ok())
            .ok_or(ImportError::Base64(name))
    };
    let body = decode(parts.next(), "servicesEncrypted[0]")?;
    let salt = decode(parts.next(), "servicesEncrypted[1]")?;
    let nonce = decode(parts.next(), "servicesEncrypted[2]")?;

    let sha256 = interop::pbkdf2_sha256_key(passphrase, &salt, ITERATIONS, ctx.limits())?;
    if let Ok(plaintext) = interop::aes256gcm_open(&sha256, &nonce, &body) {
        return Ok(plaintext);
    }
    let sha1 = interop::pbkdf2_sha1_key(passphrase, &salt, ITERATIONS, ctx.limits())?;
    interop::aes256gcm_open(&sha1, &nonce, &body)
}

type EntryResult = core::result::Result<Option<(ImportedItem, Vec<ImportWarning>)>, RowError>;

fn read_service(service: &Value, groups: &[(&str, &str)]) -> EntryResult {
    let service = Rec::object(service, SourceFormat::TwoFas)?;
    let otp = service.at("otp");

    let token_type = otp.as_ref().and_then(|otp| otp.str("tokenType"));
    let kind = match token_type {
        Some(raw) => match build::kind_from_str(raw) {
            Some(kind) => kind,
            None => return Ok(None),
        },
        None => misty_otp::OtpKind::Totp,
    };

    let (config, warnings) = build::config(&OtpFields {
        default_kind: kind,
        secret: Some(service.require_str("secret")?),
        algorithm: otp.as_ref().and_then(|otp| otp.str("algorithm")),
        digits: otp.as_ref().and_then(|otp| otp.u8("digits").ok()).flatten(),
        period: otp
            .as_ref()
            .and_then(|otp| otp.u16("period").ok())
            .flatten(),
        counter: otp
            .as_ref()
            .and_then(|otp| otp.u64("counter").ok())
            .flatten(),
        ..OtpFields::default()
    })?;

    // `name` is the service, `otp.issuer` the issuer the QR code carried. They are
    // usually the same; when they differ, the one the user renamed is `name`.
    let issuer = service
        .str("name")
        .or_else(|| otp.as_ref().and_then(|otp| otp.str("issuer")));
    let account = otp
        .as_ref()
        .and_then(|otp| otp.str("account").or_else(|| otp.str("label")))
        .unwrap_or_default();

    let mut item = ImportedItem::new(
        SourceFormat::TwoFas,
        config,
        issuer.map(str::to_owned),
        account.to_owned(),
    );
    item.created_at = service.i64("updatedAt").filter(|at| *at > 0);
    item.groups = service
        .str("groupId")
        .and_then(|id| {
            groups
                .iter()
                .find(|(group_id, _)| *group_id == id)
                .map(|(_, name)| (*name).to_owned())
        })
        .into_iter()
        .collect();
    Ok(Some((item, warnings)))
}
