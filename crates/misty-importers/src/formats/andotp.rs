// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! andOTP backups, plain and encrypted.
//!
//! # Plain
//!
//! A JSON array, one object per token:
//!
//! ```json
//! [ { "secret": "…", "issuer": "GitHub", "label": "ada@example.com",
//!     "digits": 6, "type": "TOTP", "algorithm": "SHA1", "thumbnail": "Default",
//!     "last_used": 0, "used_frequency": 0, "period": 30, "tags": ["work"] } ]
//! ```
//!
//! # Encrypted
//!
//! A binary file, not JSON. Two layouts have shipped:
//!
//! ```text
//! password + KDF (current)   iterations:u32 be │ salt:12 │ nonce:12 │ ciphertext‖tag
//! password only (legacy)     nonce:12 │ ciphertext‖tag
//! ```
//!
//! The key is `PBKDF2(password, salt, iterations, 32)` for the first and
//! `SHA-256(password)` for the second, and the box is AES-256-GCM either way.
//! Source: andOTP's `Utilities.java` / `EncryptionHelper.java`, and Aegis's
//! `AndOtpImporter.java`, which reads the same files.
//!
//! **Which HMAC PBKDF2 uses is not something this crate could verify against a
//! real backup**, so it tries SHA-1 (what `PBKDF2WithHmacSHA1`, the JCE name
//! available on the Android versions andOTP supported, means) and then SHA-256.
//! Trying both is safe *because* the payload is authenticated: at most one key can
//! produce a valid GCM tag, so a wrong guess fails rather than yielding plausible
//! garbage. It also means a user whose password is right is not told it is wrong,
//! which is the failure mode that matters here.

use misty_otp::OtpKind;
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

/// Bytes before the ciphertext in the current encrypted layout.
const KDF_HEADER_LEN: usize = 4 + SALT_LEN + interop::NONCE_LEN;
/// Salt length in the current encrypted layout.
const SALT_LEN: usize = 12;
/// andOTP's own minimum, and a useful sniffing bound.
const MIN_ITERATIONS: u64 = 1_000;

/// Reads andOTP JSON backups, encrypted or not.
#[derive(Debug, Clone, Copy, Default)]
pub struct AndOtpImporter;

impl Importer for AndOtpImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::AndOtp
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if text::starts_json_array(&head) {
            // andOTP is the only export that is a bare array with these names.
            let plausible = head.contains("\"secret\"")
                && (head.contains("\"label\"") || head.contains("\"issuer\""))
                && (head.contains("\"used_frequency\"")
                    || head.contains("\"thumbnail\"")
                    || head.contains("\"last_used\""));
            return if plausible {
                Confidence::Certain
            } else if head.contains("\"secret\"") {
                Confidence::Possible
            } else {
                Confidence::No
            };
        }
        if encrypted_iterations(input).is_some() {
            // A binary blob whose first four bytes are a plausible iteration
            // count. Never better than `Possible`: the legacy layout has no header
            // at all and cannot be recognized, so an encrypted andOTP backup may
            // need the format choosing by hand.
            return Confidence::Possible;
        }
        Confidence::No
    }

    fn needs_passphrase(&self, input: &[u8]) -> bool {
        !text::starts_json_array(&text::sniff_text(input))
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        if text::starts_json_array(&text::sniff_text(input)) {
            let doc = json::parse(input, ctx.limits())?;
            return read_array(&doc, ctx);
        }

        let plaintext = decrypt(input, ctx)?;
        let doc: Value = serde_json::from_slice(&plaintext).map_err(|error| ImportError::Json {
            line: error.line(),
            column: error.column(),
        })?;
        read_array(&doc, ctx)
    }
}

/// The iteration count of the current encrypted layout, if the file plausibly has
/// one.
fn encrypted_iterations(input: &[u8]) -> Option<u64> {
    if input.len() < KDF_HEADER_LEN + interop::TAG_LEN {
        return None;
    }
    let header: [u8; 4] = input.get(..4)?.try_into().ok()?;
    let iterations = u64::from(u32::from_be_bytes(header));
    (MIN_ITERATIONS..=10_000_000)
        .contains(&iterations)
        .then_some(iterations)
}

/// Try both encrypted layouts, and both PBKDF2 hashes for the current one.
fn decrypt(input: &[u8], ctx: &ImportContext<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let passphrase = ctx
        .passphrase()
        .ok_or(ImportError::PassphraseRequired(SourceFormat::AndOtp))?;

    if let Some(iterations) = encrypted_iterations(input) {
        let salt = input
            .get(4..4 + SALT_LEN)
            .ok_or(ImportError::DecryptionFailed)?;
        let nonce = input
            .get(4 + SALT_LEN..KDF_HEADER_LEN)
            .ok_or(ImportError::DecryptionFailed)?;
        let body = input
            .get(KDF_HEADER_LEN..)
            .ok_or(ImportError::DecryptionFailed)?;

        let sha1 = interop::pbkdf2_sha1_key(passphrase, salt, iterations, ctx.limits())?;
        if let Ok(plaintext) = interop::aes256gcm_open(&sha1, nonce, body) {
            return Ok(plaintext);
        }
        let sha256 = interop::pbkdf2_sha256_key(passphrase, salt, iterations, ctx.limits())?;
        if let Ok(plaintext) = interop::aes256gcm_open(&sha256, nonce, body) {
            return Ok(plaintext);
        }
    }

    // Legacy layout: no KDF, no salt, the nonce first.
    let nonce = input
        .get(..interop::NONCE_LEN)
        .ok_or(ImportError::DecryptionFailed)?;
    let body = input
        .get(interop::NONCE_LEN..)
        .ok_or(ImportError::DecryptionFailed)?;
    if body.len() < interop::TAG_LEN {
        return Err(ImportError::DecryptionFailed);
    }
    interop::aes256gcm_open(&interop::sha256_key(passphrase), nonce, body)
}

fn read_array(doc: &Value, ctx: &ImportContext<'_>) -> Result<ImportReport> {
    let entries = doc
        .as_array()
        .ok_or(ImportError::InvalidField("(document root)"))?;
    let mut collector = Collector::new(SourceFormat::AndOtp, ctx);

    for entry in entries {
        if collector.is_full() {
            return Err(ImportError::TooManyRows {
                max: ctx.limits().max_rows,
            });
        }
        let row = RowId::at(collector.rows());
        match read_entry(entry, ctx) {
            Ok(Some((item, warnings))) => {
                let row = row.labelled(item.issuer.as_deref(), &item.account);
                collector.accept(row, item, warnings);
            }
            Ok(None) => collector.skip(
                row,
                SkipReason::UnsupportedType(
                    Rec::raw(entry, SourceFormat::AndOtp)
                        .text("type")
                        .unwrap_or_default(),
                ),
            ),
            Err(error) => collector.fail(row, error),
        }
    }
    Ok(collector.finish())
}

type EntryResult = core::result::Result<Option<(ImportedItem, Vec<ImportWarning>)>, RowError>;

fn read_entry(entry: &Value, ctx: &ImportContext<'_>) -> EntryResult {
    let entry = Rec::object(entry, SourceFormat::AndOtp)?;
    let kind = match entry.str("type") {
        Some(raw) => match build::kind_from_str(raw) {
            Some(kind) => kind,
            None => return Ok(None),
        },
        None => OtpKind::Totp,
    };

    let (config, warnings) = build::config(&OtpFields {
        default_kind: kind,
        secret: Some(entry.require_str("secret")?),
        algorithm: entry.str("algorithm"),
        digits: entry.u8("digits")?,
        period: entry.u16("period")?,
        counter: entry.u64("counter")?,
        pin: entry.str("pin"),
        ..OtpFields::default()
    })?;

    // andOTP keeps the issuer separately, but plenty of its entries have an empty
    // issuer and `Issuer:account` in the label — it imported them that way from
    // somewhere else.
    let label = entry.str("label").unwrap_or_default();
    let (issuer, account) = match entry.str("issuer") {
        Some(issuer) => (Some(issuer), label),
        None => text::split_label(label),
    };

    let mut item = ImportedItem::new(
        SourceFormat::AndOtp,
        config,
        issuer.map(str::to_owned),
        account.to_owned(),
    );
    item.tags = entry.strings("tags", ctx.limits());
    // andOTP records `last_used` in unix milliseconds and 0 for "never".
    item.last_used_at = entry.i64("last_used").filter(|at| *at > 0);
    if entry.str("thumbnail").is_some_and(|icon| icon != "Default") {
        item.icon_hint = entry.str("thumbnail").map(str::to_owned);
    }
    Ok(Some((item, warnings)))
}
