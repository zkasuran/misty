// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Twilio Authy — best effort, and honest about it.
//!
//! # Authy does not export
//!
//! There is no export function in Authy, by design. Twilio's only documented
//! seed-export endpoint is a *provider-side* API gated behind a support request and
//! rate-limited to a handful of calls per user per month; nothing an account holder
//! can invoke. This importer therefore reads a file the user has to produce
//! themselves, from the Authy desktop application's own data — the widely
//! circulated developer-tools method. Twilio has since discontinued that
//! application, which means for many users **no path out exists at all**.
//!
//! That is worth stating plainly rather than papering over: the reason this crate
//! exists is that lock-in is a choice a vendor makes, and Authy made it.
//!
//! # What this reads
//!
//! Either shape, with either naming convention, because both are in circulation:
//!
//! ```json
//! { "authenticator_tokens": [
//!     { "name": "Example", "original_name": "Example: ada", "account_type": "authy",
//!       "digits": 7, "unique_id": "…", "decrypted_seed": "…",
//!       "encrypted_seed": "…", "salt": "…" } ] }
//! ```
//!
//! ```json
//! [ { "name": "Example", "originalName": "Example: ada", "digits": 7,
//!     "decryptedSecret": "…", "secretSeed": "…" } ]
//! ```
//!
//! # What it will not do
//!
//! * **It will not guess a period for a third-party token.** Authy's records carry
//!   no period field. An Authy-*native* token is given the 10-second step Authy's
//!   own exporters use — see [`AUTHY_NATIVE_PERIOD`] for the sources — and every
//!   other row takes the `otpauth://` default of 30 with
//!   [`ImportWarning::AssumedDefault`] on `period`. `README.md` says in plain words
//!   that an Authy-native token must be checked against a live code before the
//!   Authy app is deleted: a silently wrong period produces codes that look right
//!   and never work, and by then the app is gone.
//! * **It will not decrypt `encrypted_seed`.** Authy's backup-password wrapping is
//!   undocumented, and the parameters circulating for it could not be verified
//!   against a real account. An unverified decryptor reports "wrong password" for a
//!   correct password, which for a user whose only copy is in that file is worse
//!   than a clear refusal. Those rows are skipped as
//!   [`SkipReason::EncryptedSecret`].
//! * **It will not choose between two readings of one seed.** A seed is decoded as
//!   base32; only if that is impossible is it read as hex. The rule is
//!   deterministic and documented rather than clever, because the two decodings of
//!   one string are two different keys.

use misty_otp::SecretBytes;
use serde_json::Value;

use crate::build::OtpFields;
use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, Result, RowError};
use crate::importer::{Confidence, Importer};
use crate::json::{self, Rec};
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId, SkipReason};
use crate::{build, text};

/// Reads a user-extracted Authy token dump.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuthyImporter;

/// Time step of an Authy-*native* token, as opposed to a third-party token Authy
/// merely stores.
///
/// From `alexzorin/authy` `crypto.go` (`totpTimeStep = 10`) and the `period=10` its
/// exporter writes for the native `apps[]` array. Third-party tokens carry no period
/// and take the `otpauth://` default of 30.
const AUTHY_NATIVE_PERIOD: u16 = 10;

/// Whether this record is one of Authy's own tokens rather than a third-party one
/// Authy is storing.
///
/// Two discriminators, because two shapes circulate: the Android preferences file
/// puts a hex `secretSeed` on native tokens and nothing on the others, and the API
/// JSON carries `account_type`.
fn is_authy_native(token: &Rec<'_>) -> bool {
    if ["secret_seed", "secretSeed"]
        .into_iter()
        .any(|field| token.str(field).is_some())
    {
        return true;
    }
    ["account_type", "accountType"]
        .into_iter()
        .filter_map(|field| token.str(field))
        .any(|kind| kind.eq_ignore_ascii_case("authy"))
}

impl Importer for AuthyImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::Authy
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if head.contains("\"authenticator_tokens\"") {
            return Confidence::Certain;
        }
        let authy_fields = [
            "\"decryptedSecret\"",
            "\"encrypted_seed\"",
            "\"encryptedSeed\"",
            "\"secretSeed\"",
        ];
        if authy_fields.iter().any(|field| head.contains(field)) {
            return Confidence::Likely;
        }
        Confidence::No
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let doc = json::parse(input, ctx.limits())?;
        let tokens = match &doc {
            Value::Array(tokens) => tokens,
            Value::Object(_) => Rec::raw(&doc, self.format())
                .array("authenticator_tokens")
                .or_else(|| Rec::raw(&doc, self.format()).array("tokens"))
                .ok_or(ImportError::MissingField("authenticator_tokens"))?,
            _ => return Err(ImportError::UnrecognizedFormat),
        };

        let mut collector = Collector::new(self.format(), ctx);
        for token in tokens {
            if collector.is_full() {
                return Err(ImportError::TooManyRows {
                    max: ctx.limits().max_rows,
                });
            }
            let row = RowId::at(collector.rows());
            match read_token(token) {
                Ok(Some((item, warnings))) => {
                    let row = row.labelled(item.issuer.as_deref(), &item.account);
                    collector.accept(row, item, warnings);
                }
                Ok(None) => collector.skip(row, SkipReason::EncryptedSecret),
                Err(error) => collector.fail(row, error),
            }
        }
        Ok(collector.finish())
    }
}

type EntryResult = core::result::Result<Option<(ImportedItem, Vec<ImportWarning>)>, RowError>;

fn read_token(token: &Value) -> EntryResult {
    let token = Rec::object(token, SourceFormat::Authy)?;

    // Both naming conventions, in the order of decreasing confidence that the
    // value is plaintext.
    let seed = [
        "decrypted_seed",
        "decryptedSecret",
        "secret_seed",
        "secretSeed",
        "secret",
    ]
    .into_iter()
    .find_map(|field| token.str(field));

    let Some(seed) = seed else {
        // No plaintext seed. If there is a wrapped one, the row is skipped as
        // encrypted; if there is nothing at all, it is a broken record.
        let wrapped = ["encrypted_seed", "encryptedSeed"]
            .into_iter()
            .any(|field| token.str(field).is_some());
        return if wrapped {
            Ok(None)
        } else {
            Err(RowError::MissingField("decrypted_seed"))
        };
    };

    let (secret, encoding_assumed) = decode_seed(seed)?;
    let digits = token.u8("digits")?;

    // Authy's own tokens are not 30-second tokens, and this is the single most
    // consequential thing this importer has to get right: a 30-second period on a
    // 10-second token produces codes that look correct and are never accepted.
    //
    // Verified by reading the sources rather than by reputation:
    // `alexzorin/authy` `crypto.go` declares `totpTimeStep = 10` and
    // `totpDigits = 7`, and its `authy-export` sets `period=10` for the Authy-native
    // `apps[]` while setting no period at all for third-party
    // `authenticator_tokens[]`, which leaves those at the `otpauth://` default of
    // 30. Aegis's `AuthyImporter` does the same, keyed on the same discriminator.
    //
    // A period the record actually states always wins over this.
    let native = is_authy_native(&token);
    let period = match token.u16("period")? {
        Some(period) => Some(period),
        None if native => Some(AUTHY_NATIVE_PERIOD),
        None => None,
    };

    let (config, mut warnings) = build::config(&OtpFields {
        secret_bytes: Some(secret.expose_secret().to_vec()),
        digits,
        period,
        ..OtpFields::default()
    })?;
    if encoding_assumed {
        warnings.push(ImportWarning::AssumedDefault("secret encoding"));
    }
    if native && token.u16("period")?.is_none() {
        // Inferred from the account type, not read from the row. The user still has
        // to check one live code before deleting Authy — see `README.md`.
        warnings.push(ImportWarning::AssumedDefault("period"));
    }
    // `build::config` has already recorded that `digits` was assumed where the
    // record did not state it, which for Authy is the usual case and the other half
    // of what this importer has to say.

    // `name` is the service; `original_name` is what the QR code said, often
    // `Issuer: account`.
    let name = token.str("name").or_else(|| token.str("originalName"));
    let original = token
        .str("original_name")
        .or_else(|| token.str("originalName"));
    let (label_issuer, account) = text::split_label(original.unwrap_or_default());
    let issuer = token.str("issuer").or(name).or(label_issuer);

    let mut item = ImportedItem::new(
        SourceFormat::Authy,
        config,
        issuer.map(str::to_owned),
        account.to_owned(),
    );
    item.icon_hint = text::non_empty(token.str("logo"));
    Ok(Some((item, warnings)))
}

/// Decode a seed as base32, falling back to hex only when base32 is impossible.
///
/// Returns whether the fallback was taken, so the row can say so. The order is not
/// arbitrary: base32 is what every `otpauth://` URI uses, so a string that is valid
/// base32 is read as base32 even though many such strings are also valid hex.
fn decode_seed(seed: &str) -> core::result::Result<(SecretBytes, bool), RowError> {
    match SecretBytes::from_base32(seed) {
        Ok(secret) => Ok((secret, false)),
        Err(base32_error) => match SecretBytes::from_hex(seed) {
            Ok(secret) => Ok((secret, true)),
            Err(_) => Err(RowError::Otp(base32_error)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_wins_over_hex_when_both_are_possible() {
        // "abcdef23" is valid base32 (lowercase) and valid hex. Base32 wins, and
        // the row is not told an encoding was assumed.
        let (secret, assumed) = decode_seed("abcdef23").expect("decodes");
        assert!(!assumed);
        assert_eq!(secret.len(), 5);

        // "0189" cannot be base32 — 0, 1, 8 and 9 are not in the alphabet — so hex
        // is the only reading, and the row is told.
        let (secret, assumed) = decode_seed("0189").expect("decodes");
        assert!(assumed);
        assert_eq!(secret.expose_secret(), [0x01, 0x89]);

        assert!(decode_seed("!!!!").is_err());
        assert!(decode_seed("").is_err());
    }
}
