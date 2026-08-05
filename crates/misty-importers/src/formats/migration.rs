// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Google Authenticator's `otpauth-migration://offline?data=…` export.
//!
//! The payload is base64 in a percent-encoded query parameter, and the decoded
//! bytes are a protobuf message. The decoder is [`crate::protobuf`] — hand-rolled,
//! for the reasons that module gives.
//!
//! # The message
//!
//! ```text
//! message MigrationPayload {
//!   enum Algorithm  { UNSPECIFIED = 0; SHA1 = 1; SHA256 = 2; SHA512 = 3; MD5 = 4; }
//!   enum DigitCount { UNSPECIFIED = 0; SIX = 1; EIGHT = 2; }
//!   enum OtpType    { UNSPECIFIED = 0; HOTP = 1; TOTP = 2; }
//!
//!   message OtpParameters {
//!     bytes      secret    = 1;
//!     string     name      = 2;
//!     string     issuer    = 3;
//!     Algorithm  algorithm = 4;
//!     DigitCount digits    = 5;
//!     OtpType    type      = 6;
//!     int64      counter   = 7;
//!   }
//!
//!   repeated OtpParameters otp_parameters = 1;
//!   int32 version     = 2;
//!   int32 batch_size  = 3;
//!   int32 batch_index = 4;
//!   int32 batch_id    = 5;
//! }
//! ```
//!
//! Google publishes no `.proto` file. This schema is the one every third-party
//! importer uses — it matches `google_auth.proto` in
//! `scito/extract_otp_secrets` and Aegis's `GoogleAuthImporter` — and the field
//! numbers are confirmed by the payloads themselves. Unknown field numbers are
//! skipped, so a payload from a newer version still imports.
//!
//! # Batches
//!
//! Google splits a large export across several QR codes, each a complete
//! `otpauth-migration://` URI with its own `batch_index`. A file with one URI per
//! line therefore imports as one batch, and `batch_size`/`batch_index` are
//! surfaced only to warn when a batch is obviously incomplete.

use base64::Engine as _;
use misty_otp::{HashAlg, OtpConfig, OtpKind, SecretBytes};

use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, ProtobufError, Result, RowError};
use crate::importer::{Confidence, Importer};
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId, SkipReason};
use crate::protobuf::Reader;
use crate::text;

/// The URI scheme Google Authenticator writes into its export QR codes.
const SCHEME: &str = "otpauth-migration://";

/// Reads `otpauth-migration://offline?data=…` URIs, one per line.
#[derive(Debug, Clone, Copy, Default)]
pub struct GoogleMigrationImporter;

/// One `OtpParameters` sub-message, still uninterpreted.
#[derive(Debug, Default)]
struct Params<'a> {
    secret: Option<&'a [u8]>,
    name: Option<&'a str>,
    issuer: Option<&'a str>,
    algorithm: Option<u64>,
    digits: Option<u64>,
    kind: Option<u64>,
    counter: Option<u64>,
}

impl Importer for GoogleMigrationImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::GoogleMigration
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        const WINDOW: usize = 512;
        let head = input.get(..WINDOW.min(input.len())).unwrap_or(input);
        let text = String::from_utf8_lossy(head);
        for line in text.lines().take(8) {
            let line = line.trim();
            if line
                .get(..SCHEME.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(SCHEME))
            {
                return Confidence::Certain;
            }
        }
        Confidence::No
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let text = text::decode(input, ctx.limits())?;
        let mut collector = Collector::new(self.format(), ctx);
        let mut saw_payload = false;

        for (offset, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let payload = decode_uri(line)?;
            saw_payload = true;
            read_payload(&payload, offset + 1, &mut collector)?;
        }

        if !saw_payload {
            return Err(ImportError::UnrecognizedFormat);
        }
        Ok(collector.finish())
    }
}

/// Pull the base64 payload out of one `otpauth-migration://offline?data=…` URI.
fn decode_uri(line: &str) -> Result<Vec<u8>> {
    let rest = line
        .get(..SCHEME.len())
        .filter(|head| head.eq_ignore_ascii_case(SCHEME))
        .and_then(|_| line.get(SCHEME.len()..))
        .ok_or(ImportError::UnrecognizedFormat)?;

    let query = rest
        .split_once('?')
        .map(|(_authority, query)| query)
        .ok_or(ImportError::MissingField("data"))?;

    let raw = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| name.eq_ignore_ascii_case("data"))
        .map(|(_, value)| value)
        .ok_or(ImportError::MissingField("data"))?;

    let percent_decoded = percent_decode(raw).ok_or(ImportError::Base64("data"))?;
    decode_base64(&percent_decoded).ok_or(ImportError::Base64("data"))
}

/// Percent-decode a query value. Hand-written because the only thing behind the
/// escapes here is base64, so there is no encoding question to get wrong — and
/// because `+` means a space in a query string, while base64 uses it as a digit.
/// Google percent-encodes its `+`, so a bare `+` is treated as base64.
fn percent_decode(raw: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = char::from(bytes.next()?).to_digit(16)?;
            let low = char::from(bytes.next()?).to_digit(16)?;
            out.push(u8::try_from(high * 16 + low).ok()?);
        } else {
            out.push(byte);
        }
    }
    Some(out)
}

/// Decode base64, tolerating the URL-safe alphabet and missing padding. Real
/// exports use the standard alphabet with padding; QR readers and copy-paste
/// mangle both.
fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let trimmed: Vec<u8> = input
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(decoded) = engine.decode(&trimmed) {
            return Some(decoded);
        }
    }
    None
}

/// Walk one decoded payload, turning each `OtpParameters` into a row.
fn read_payload(payload: &[u8], line: usize, collector: &mut Collector<'_, '_>) -> Result<()> {
    let mut reader = Reader::new(payload);
    let mut batch_size: Option<u64> = None;
    let mut batch_index: Option<u64> = None;

    while let Some(field) = reader.next_field() {
        let (number, value) = field?;
        match number {
            1 => {
                if collector.is_full() {
                    return Err(ImportError::TooManyRows {
                        max: collector.ctx().limits().max_rows,
                    });
                }
                let bytes = value.bytes().ok_or(ProtobufError::WrongType { field: 1 })?;
                let row = RowId::at_line(collector.rows(), line);
                match read_params(&reader, bytes) {
                    Ok(params) => interpret(params, row, collector),
                    Err(error) => collector.fail(row, RowError::Protobuf(error)),
                }
            }
            3 => batch_size = value.varint(),
            4 => batch_index = value.varint(),
            // version, batch_id and anything a newer version adds: read and
            // ignored. Skipping unknown fields is what keeps this importer working
            // against an app that grows a field.
            _ => {}
        }
    }

    // A truncated batch is the difference between "I imported everything" and "I
    // imported the first QR code of three". Google puts both numbers in every
    // payload, so the report can say which parts are missing rather than let the
    // user discover it the next time they try to log in.
    if let (Some(total), Some(index)) = (batch_size, batch_index) {
        if let (Ok(total), Ok(index)) = (u32::try_from(total), u32::try_from(index)) {
            collector.note_batch_part(index, total);
        }
    }
    Ok(())
}

/// Read one `OtpParameters` sub-message.
fn read_params<'a>(
    parent: &Reader<'_>,
    bytes: &'a [u8],
) -> core::result::Result<Params<'a>, ProtobufError> {
    let mut reader = parent.nested(bytes)?;
    let mut params = Params::default();
    while let Some(field) = reader.next_field() {
        let (number, value) = field?;
        match number {
            1 => params.secret = value.bytes(),
            2 => params.name = Some(value.string(2)?),
            3 => params.issuer = Some(value.string(3)?),
            4 => params.algorithm = value.varint(),
            5 => params.digits = value.varint(),
            6 => params.kind = value.varint(),
            7 => params.counter = value.varint(),
            _ => {}
        }
    }
    Ok(params)
}

/// Turn one sub-message into an item, a skip, or a failed row.
fn interpret(params: Params<'_>, row: RowId, collector: &mut Collector<'_, '_>) {
    let mut warnings = Vec::new();

    let algorithm = match params.algorithm.unwrap_or(0) {
        0 => {
            warnings.push(ImportWarning::AssumedDefault("algorithm"));
            HashAlg::Sha1
        }
        1 => HashAlg::Sha1,
        2 => HashAlg::Sha256,
        3 => HashAlg::Sha512,
        // The enum has an MD5 member. `misty-otp` deliberately has no MD5 TOTP —
        // no issuer uses one — so this is a skip with a reason, not a silent
        // downgrade to SHA-1, which would produce plausible codes that never work.
        4 => {
            collector.skip(row, SkipReason::UnsupportedAlgorithm("MD5".to_owned()));
            return;
        }
        _ => {
            collector.fail(row, RowError::InvalidField("algorithm"));
            return;
        }
    };

    let digits = match params.digits.unwrap_or(0) {
        0 => {
            warnings.push(ImportWarning::AssumedDefault("digits"));
            6
        }
        1 => 6,
        2 => 8,
        _ => {
            collector.fail(row, RowError::InvalidField("digits"));
            return;
        }
    };

    // Type is the one field with no safe default: guessing between HOTP and TOTP
    // either desynchronizes a counter or produces codes from the wrong moving
    // factor. Google always sets it.
    let kind = match params.kind.unwrap_or(0) {
        1 => OtpKind::Hotp,
        2 => OtpKind::Totp,
        0 => {
            collector.fail(row, RowError::MissingField("type"));
            return;
        }
        _ => {
            collector.fail(row, RowError::InvalidField("type"));
            return;
        }
    };

    let Some(secret) = params.secret else {
        collector.fail(row, RowError::MissingField("secret"));
        return;
    };

    let counter = match (kind, params.counter) {
        (OtpKind::Hotp, None) => {
            // Absent means zero on the wire, and zero is a real counter value, so
            // this cannot be rejected — but a wrong HOTP counter produces codes
            // the server refuses, so it must be visible.
            warnings.push(ImportWarning::AssumedDefault("counter"));
            0
        }
        (_, counter) => counter.unwrap_or(0),
    };

    let config = match OtpConfig::builder(kind, SecretBytes::from_slice(secret))
        .algorithm(algorithm)
        .digits(digits)
        .counter(counter)
        .build()
    {
        Ok(config) => config,
        Err(error) => {
            collector.fail(row, RowError::Otp(error));
            return;
        }
    };

    // Google puts the account in `name` and the issuer in `issuer`, but older
    // exports put `Issuer:account` in `name` alone, and some put the issuer in
    // both. Prefer the explicit field and strip the redundant prefix.
    let (label_issuer, account) = text::split_label(params.name.unwrap_or_default());
    let issuer = params
        .issuer
        .map(str::trim)
        .filter(|issuer| !issuer.is_empty());
    let (issuer, account) = match (issuer, label_issuer) {
        (Some(explicit), Some(from_label)) if explicit == from_label => (Some(explicit), account),
        (Some(explicit), Some(_)) => {
            // The label disagreed with the field. The field wins, as it does in
            // `otpauth://` (SPEC 7), and the whole label becomes the account so
            // nothing the user could recognize is thrown away.
            (Some(explicit), params.name.unwrap_or_default().trim())
        }
        (Some(explicit), None) => (Some(explicit), account),
        (None, from_label) => (from_label, account),
    };

    let item = ImportedItem::new(
        SourceFormat::GoogleMigration,
        config,
        issuer.map(str::to_owned),
        account.to_owned(),
    );
    let row = row.labelled(issuer, account);
    collector.accept(row, item, warnings);
}
