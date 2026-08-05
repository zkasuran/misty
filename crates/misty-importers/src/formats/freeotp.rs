// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! FreeOTP and FreeOTP+.
//!
//! Both store the same per-token JSON. They differ in what is around it.
//!
//! # FreeOTP
//!
//! An Android `SharedPreferences` file, `tokens.xml`, pulled off the device:
//!
//! ```xml
//! <map>
//!   <string name="tokenOrder">[&quot;GitHub:ada&quot;]</string>
//!   <string name="GitHub:ada">{&quot;algo&quot;:&quot;SHA1&quot;,&quot;digits&quot;:6,…}</string>
//! </map>
//! ```
//!
//! # FreeOTP+
//!
//! A JSON file with the same objects in an array:
//!
//! ```json
//! { "tokenOrder": ["GitHub:ada"],
//!   "tokens": [ { "algo": "SHA1", "counter": 0, "digits": 6, "issuerExt": "GitHub",
//!                 "label": "ada", "period": 30, "secret": [65, 65, …],
//!                 "type": "TOTP" } ] }
//! ```
//!
//! # The signed-byte secret
//!
//! `secret` is a JSON array of **signed** bytes, because it is a Java `byte[]`
//! serialized by Gson: `0xAA` arrives as `-86`. Reading it as unsigned would
//! silently truncate every byte above 127 to nothing usable, which is a working
//! import that generates wrong codes — the worst failure this crate can have. Both
//! readers accept a base32 string too, which FreeOTP+ writes in some versions.
//!
//! # The HOTP counter is off by one, on purpose
//!
//! FreeOTP stores the counter it last *used*; an `otpauth://` counter is the one to
//! use *next*. `Token.java` v1.5 parses `counter = uri_counter - 1` (line 120) and
//! writes `counter + 1` back out (line 273), so this importer adds one. Not doing
//! so imports a token whose first code the server has already consumed.
//!
//! Source: `freeotp/freeotp-android` `Token.java` and `helloworld1/FreeOTPPlus`
//! `BackupHelper.kt`.

use quick_xml::events::Event;
use quick_xml::XmlVersion;
use serde_json::Value;

use crate::build::{self, OtpFields};
use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, Result, RowError};
use crate::importer::{Confidence, Importer};
use crate::json::{self, Rec};
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId, SkipReason};
use crate::{formats::xml, text};

/// The `SharedPreferences` key that holds display order, not a token.
const ORDER_KEY: &str = "tokenOrder";

/// Reads FreeOTP's Android `tokens.xml`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FreeOtpImporter;

/// Reads FreeOTP+'s JSON backup.
#[derive(Debug, Clone, Copy, Default)]
pub struct FreeOtpPlusImporter;

impl Importer for FreeOtpImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::FreeOtp
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        let xml = head.trim_start().starts_with("<?xml") || head.contains("<map>");
        if !xml {
            return Confidence::No;
        }
        if head.contains(ORDER_KEY) {
            return Confidence::Certain;
        }
        if head.contains("<string name=") {
            return Confidence::Possible;
        }
        Confidence::No
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let text = text::decode(input, ctx.limits())?;
        let mut reader = quick_xml::Reader::from_str(text);
        reader.config_mut().trim_text(true);

        let mut collector = Collector::new(self.format(), ctx);
        let mut depth = 0usize;

        loop {
            match reader.read_event() {
                Ok(Event::Start(start)) => {
                    if start.name().as_ref() != b"string" {
                        depth += 1;
                        if depth > xml::MAX_DEPTH {
                            return Err(ImportError::Xml {
                                offset: reader.buffer_position(),
                            });
                        }
                        continue;
                    }
                    let key = start
                        .try_get_attribute("name")
                        .ok()
                        .flatten()
                        // XML 1.0 normalization, which is what a `SharedPreferences`
                        // file is: `XmlVersion::default()` is `Implicit1_0`, and 1.0
                        // and 1.1 differ only in end-of-line handling inside
                        // attribute values.
                        .and_then(|attr| attr.normalized_value(XmlVersion::default()).ok())
                        .map(|value| value.into_owned())
                        .unwrap_or_default();
                    // Consumes the closing tag, entities included, so the JSON
                    // inside is one string rather than one event per `&quot;`.
                    let body = xml::text_until(&mut reader, start.name())?;
                    if key == ORDER_KEY {
                        continue;
                    }
                    if collector.is_full() {
                        return Err(ImportError::TooManyRows {
                            max: ctx.limits().max_rows,
                        });
                    }
                    let row = RowId::at(collector.rows());
                    match serde_json::from_str::<Value>(body.trim()) {
                        Ok(value) => push(&value, Some(&key), self.format(), row, &mut collector),
                        // A `SharedPreferences` file holds every setting the app
                        // had, not only tokens. A value that is not JSON is a
                        // setting, not a broken token.
                        Err(_) => collector.skip(row, SkipReason::NoOtpSecret),
                    }
                }
                Ok(Event::End(_)) => depth = depth.saturating_sub(1),
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(_) => {
                    return Err(ImportError::Xml {
                        offset: reader.buffer_position(),
                    })
                }
            }
        }

        let report = collector.finish();
        if report.outcomes.is_empty() {
            return Err(ImportError::UnrecognizedFormat);
        }
        Ok(report)
    }
}

impl Importer for FreeOtpPlusImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::FreeOtpPlus
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if !text::starts_json_object(&head) {
            return Confidence::No;
        }
        if head.contains("\"tokens\"")
            && (head.contains(ORDER_KEY) || head.contains("\"issuerExt\""))
        {
            return Confidence::Certain;
        }
        if head.contains("\"issuerExt\"") {
            return Confidence::Likely;
        }
        Confidence::No
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let doc = json::parse(input, ctx.limits())?;
        let root = Rec::object(&doc, self.format()).map_err(|_| ImportError::UnrecognizedFormat)?;
        let tokens = root
            .array("tokens")
            .ok_or(ImportError::MissingField("tokens"))?;

        let mut collector = Collector::new(self.format(), ctx);
        for token in tokens {
            if collector.is_full() {
                return Err(ImportError::TooManyRows {
                    max: ctx.limits().max_rows,
                });
            }
            let row = RowId::at(collector.rows());
            push(token, None, self.format(), row, &mut collector);
        }
        Ok(collector.finish())
    }
}

/// Interpret one token object and record the outcome.
fn push(
    token: &Value,
    key: Option<&str>,
    format: SourceFormat,
    row: RowId,
    collector: &mut Collector<'_, '_>,
) {
    match read_token(token, key, format) {
        Ok(Some((item, warnings))) => {
            let row = row.labelled(item.issuer.as_deref(), &item.account);
            collector.accept(row, item, warnings);
        }
        Ok(None) => collector.skip(row, SkipReason::NoOtpSecret),
        Err(error) => collector.fail(row, error),
    }
}

type EntryResult = core::result::Result<Option<(ImportedItem, Vec<ImportWarning>)>, RowError>;

fn read_token(token: &Value, key: Option<&str>, format: SourceFormat) -> EntryResult {
    let Ok(token) = Rec::object(token, format) else {
        return Ok(None);
    };
    let secret_field = token.value().get("secret");
    if secret_field.is_none() {
        // Some other preference. Not a token, not a failure.
        return Ok(None);
    }

    let kind = match token.str("type") {
        Some(raw) => match build::kind_from_str(raw) {
            Some(kind) => kind,
            None => {
                return Err(RowError::InvalidField("type"));
            }
        },
        None => misty_otp::OtpKind::Totp,
    };

    let secret_bytes = match secret_field {
        Some(Value::Array(bytes)) => Some(signed_bytes(bytes)?),
        _ => None,
    };
    let secret_text = token.str("secret");

    // FreeOTP stores the counter it *last used*, not the one it will use next: its
    // URI parser does `counter = parse(uri_counter) - 1` and `toUri()` writes
    // `counter + 1` back (`Token.java` lines 120 and 273 in `freeotp-android`
    // v1.5, read directly). An `otpauth://` counter is the next one, so importing
    // the stored value unchanged puts the token one code behind and the first code
    // it generates is one the server has already consumed.
    //
    // Aegis's own FreeOTP importer reads the field raw and has this off by one.
    let counter = match token.u64("counter")? {
        Some(counter) if kind.uses_counter() => Some(counter.saturating_add(1)),
        other => other,
    };

    let (config, warnings) = build::config(&OtpFields {
        default_kind: kind,
        secret: secret_text,
        secret_bytes,
        algorithm: token.str("algo").or_else(|| token.str("algorithm")),
        digits: token.u8("digits")?,
        period: token.u16("period")?,
        counter,
        ..OtpFields::default()
    })?;

    // `issuerExt` is what the QR code said; `issuerInt` is what the service told
    // the app later. FreeOTP shows `issuerExt`, so that is what a user recognizes.
    let issuer = token
        .str("issuerExt")
        .or_else(|| token.str("issuerInt"))
        .or_else(|| key.and_then(|key| text::split_label(key).0));
    let account = token
        .str("label")
        .or_else(|| key.map(|key| text::split_label(key).1))
        .unwrap_or_default();

    Ok(Some((
        ImportedItem::new(
            format,
            config,
            issuer.map(str::to_owned),
            account.to_owned(),
        ),
        warnings,
    )))
}

/// Convert Gson's signed `byte[]` rendering back into bytes.
///
/// Accepts both spellings — `-86` and `170` — because FreeOTP+ has emitted each,
/// and rejects anything outside `-128..=255` rather than wrapping it, since a
/// wrapped byte is a working import with a wrong secret.
fn signed_bytes(values: &[Value]) -> core::result::Result<Vec<u8>, RowError> {
    values
        .iter()
        .map(|value| {
            let number = value.as_i64().ok_or(RowError::InvalidField("secret"))?;
            match number {
                -128..=-1 => {
                    u8::try_from(number + 256).map_err(|_| RowError::InvalidField("secret"))
                }
                0..=255 => u8::try_from(number).map_err(|_| RowError::InvalidField("secret")),
                _ => Err(RowError::InvalidField("secret")),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_and_unsigned_byte_arrays_agree() {
        let signed: Vec<Value> = [-86i64, -1, 0, 127]
            .iter()
            .map(|n| Value::from(*n))
            .collect();
        let unsigned: Vec<Value> = [170i64, 255, 0, 127]
            .iter()
            .map(|n| Value::from(*n))
            .collect();
        assert_eq!(signed_bytes(&signed).unwrap(), vec![0xaa, 0xff, 0x00, 0x7f]);
        assert_eq!(
            signed_bytes(&unsigned).unwrap(),
            vec![0xaa, 0xff, 0x00, 0x7f]
        );
    }

    #[test]
    fn a_byte_outside_the_range_is_refused_rather_than_wrapped() {
        for out_of_range in [256i64, -129, 1_000_000] {
            let values = vec![Value::from(out_of_range)];
            assert_eq!(signed_bytes(&values), Err(RowError::InvalidField("secret")));
        }
        assert_eq!(
            signed_bytes(&[Value::from("nope")]),
            Err(RowError::InvalidField("secret"))
        );
    }
}
