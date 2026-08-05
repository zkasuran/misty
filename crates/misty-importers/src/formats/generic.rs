// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic CSV and JSON, driven by a [`ColumnMapping`].
//!
//! SPEC 8 asks for "generic CSV/JSON with a column-mapping UI", and this is the
//! part that makes the crate able to read the fifteenth format nobody has written a
//! module for. The caller names which column holds which field; nothing is guessed
//! unless a CSV header row makes it unambiguous, and the caller's mapping always
//! wins over inference.
//!
//! Both importers sit last in the registry and never claim better than
//! [`Confidence::Possible`], so a 2FAS backup is never read as anonymous JSON.
//!
//! A mapped `uri` column short-circuits everything else: if the file has a column
//! of `otpauth://` URIs, that is the whole record, and the remaining columns supply
//! only metadata. That is how KeePassXC's CSV export and Bitwarden's CSV export are
//! read.

use serde_json::Value;

use crate::build::{self, OtpFields};
use crate::collect::Collector;
use crate::context::ImportContext;
use crate::csv;
use crate::error::{ImportError, Result, RowError};
use crate::formats::item_from_uri;
use crate::importer::{Confidence, Importer};
use crate::json::{self as json_helper, Rec};
use crate::mapping::ColumnMapping;
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId, SkipReason};
use crate::text;

/// Reads delimited text with a caller-supplied or header-inferred mapping.
#[derive(Debug, Clone, Copy, Default)]
pub struct CsvImporter;

/// Reads JSON with a caller-supplied path mapping.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonImporter;

impl Importer for CsvImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::Csv
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        let trimmed = head.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('<') {
            return Confidence::No;
        }
        let first = head.lines().next().unwrap_or_default();
        if first.contains(',') || first.contains('\t') || first.contains(';') {
            Confidence::Possible
        } else {
            Confidence::No
        }
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let text = text::decode(input, ctx.limits())?;
        let mut mapping = ctx.mapping().cloned().unwrap_or_else(ColumnMapping::new);
        if !mapping.delimiter.is_ascii() || mapping.delimiter == 0 {
            return Err(ImportError::InvalidField("delimiter"));
        }

        let mut rows = csv::rows(text, mapping.delimiter, ctx.limits()).into_iter();
        let mut collector = Collector::new(self.format(), ctx);

        let header: Option<Vec<String>> = if mapping.has_header {
            let first = rows.next().ok_or(ImportError::Empty)?;
            let header = first.fields.map_err(|_| ImportError::RowTooLarge {
                row: first.line,
                limit: "header",
                max: ctx.limits().max_csv_columns,
            })?;
            if !mapping.infer_from_header(&header) {
                return Err(ImportError::MappingRequired);
            }
            Some(header)
        } else {
            if mapping.is_empty() {
                return Err(ImportError::MappingRequired);
            }
            None
        };

        // Resolve every named column once, so a mapping naming a column the file
        // does not have fails the file rather than every row in it.
        let columns = Columns::resolve(&mapping, header.as_deref())?;

        for row in rows {
            if collector.is_full() {
                return Err(ImportError::TooManyRows {
                    max: ctx.limits().max_rows,
                });
            }
            let id = RowId::at_line(collector.rows(), row.line);
            let fields = match row.fields {
                Ok(fields) => fields,
                Err(error) => {
                    collector.fail(id, error);
                    continue;
                }
            };
            if fields.iter().all(|field| field.trim().is_empty()) {
                continue;
            }
            let field = |name: &str| -> Option<String> {
                columns
                    .index_of(name)
                    .and_then(|at| fields.get(at))
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            };
            match read_row(field, &mapping, SourceFormat::Csv, ctx) {
                Ok(Some((item, warnings))) => {
                    let id = id.labelled(item.issuer.as_deref(), &item.account);
                    collector.accept(id, item, warnings);
                }
                Ok(None) => collector.skip(id, SkipReason::NoOtpSecret),
                Err(error) => collector.fail(id, error),
            }
        }

        let report = collector.finish();
        if report.outcomes.is_empty() {
            return Err(ImportError::UnrecognizedFormat);
        }
        Ok(report)
    }
}

impl Importer for JsonImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::Json
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if text::starts_json_object(&head) || text::starts_json_array(&head) {
            Confidence::Possible
        } else {
            Confidence::No
        }
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let doc = json_helper::parse(input, ctx.limits())?;
        let mapping = ctx.mapping().cloned().unwrap_or_else(ColumnMapping::new);
        if mapping.is_empty() {
            return Err(ImportError::MappingRequired);
        }

        let records = match &mapping.array_path {
            Some(path) => json_helper::path(&doc, path)
                .and_then(Value::as_array)
                .ok_or(ImportError::MissingField("(mapped array path)"))?,
            None => doc.as_array().ok_or(ImportError::MappingRequired)?,
        };

        let mut collector = Collector::new(self.format(), ctx);
        for record in records {
            if collector.is_full() {
                return Err(ImportError::TooManyRows {
                    max: ctx.limits().max_rows,
                });
            }
            let id = RowId::at(collector.rows());
            let rec = Rec::raw(record, SourceFormat::Json);
            let field = |name: &str| -> Option<String> {
                mapping.slot(name).and_then(|path| rec.text(path))
            };
            match read_row(field, &mapping, SourceFormat::Json, ctx) {
                Ok(Some((item, warnings))) => {
                    let id = id.labelled(item.issuer.as_deref(), &item.account);
                    collector.accept(id, item, warnings);
                }
                Ok(None) => collector.skip(id, SkipReason::NoOtpSecret),
                Err(error) => collector.fail(id, error),
            }
        }
        Ok(collector.finish())
    }
}

/// A resolved set of CSV column indices.
#[derive(Debug, Default)]
struct Columns {
    uri: Option<usize>,
    secret: Option<usize>,
    issuer: Option<usize>,
    account: Option<usize>,
    kind: Option<usize>,
    algorithm: Option<usize>,
    digits: Option<usize>,
    period: Option<usize>,
    counter: Option<usize>,
    pin: Option<usize>,
    note: Option<usize>,
    tags: Option<usize>,
    group: Option<usize>,
    url: Option<usize>,
}

impl Columns {
    fn resolve(mapping: &ColumnMapping, header: Option<&[String]>) -> Result<Self> {
        let mut columns = Self::default();
        for (field, slot) in [
            ("uri", &mut columns.uri),
            ("secret", &mut columns.secret),
            ("issuer", &mut columns.issuer),
            ("account", &mut columns.account),
            ("kind", &mut columns.kind),
            ("algorithm", &mut columns.algorithm),
            ("digits", &mut columns.digits),
            ("period", &mut columns.period),
            ("counter", &mut columns.counter),
            ("pin", &mut columns.pin),
            ("note", &mut columns.note),
            ("tags", &mut columns.tags),
            ("group", &mut columns.group),
            ("url", &mut columns.url),
        ] {
            let Some(name) = mapping.slot(field) else {
                continue;
            };
            *slot = Some(resolve_column(name, header).ok_or(match field {
                "uri" => ImportError::MappedColumnMissing("uri"),
                "secret" => ImportError::MappedColumnMissing("secret"),
                "issuer" => ImportError::MappedColumnMissing("issuer"),
                "account" => ImportError::MappedColumnMissing("account"),
                _ => ImportError::MappedColumnMissing("(mapped column)"),
            })?);
        }
        if columns.uri.is_none() && columns.secret.is_none() {
            return Err(ImportError::MappingRequired);
        }
        Ok(columns)
    }
}

/// A column named by header name, or by index when the file has no header.
fn resolve_column(name: &str, header: Option<&[String]>) -> Option<usize> {
    if let Some(header) = header {
        let wanted = name.trim().to_ascii_lowercase();
        if let Some(at) = header
            .iter()
            .position(|column| column.trim().to_ascii_lowercase() == wanted)
        {
            return Some(at);
        }
    }
    name.trim().parse::<usize>().ok()
}

/// The JSON side of the same lookup: paths, not indices.
impl Columns {
    fn index_of(&self, field: &str) -> Option<usize> {
        match field {
            "uri" => self.uri,
            "secret" => self.secret,
            "issuer" => self.issuer,
            "account" => self.account,
            "kind" => self.kind,
            "algorithm" => self.algorithm,
            "digits" => self.digits,
            "period" => self.period,
            "counter" => self.counter,
            "pin" => self.pin,
            "note" => self.note,
            "tags" => self.tags,
            "group" => self.group,
            "url" => self.url,
            _ => None,
        }
    }
}

/// Build one item from whichever backing store the caller has.
///
/// `field` is the only thing the two importers do differently: CSV resolves a name
/// to a column index, JSON resolves it to a document path. It returns owned text
/// because a JSON number has no `&str` to borrow — `6` and `"6"` must both work,
/// and vendors write both.
fn read_row<F>(
    field: F,
    mapping: &ColumnMapping,
    format: SourceFormat,
    ctx: &ImportContext<'_>,
) -> core::result::Result<Option<(ImportedItem, Vec<ImportWarning>)>, RowError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut warnings = Vec::new();

    // Materialized first so the borrows below outlive the builder.
    let uri = field("uri");
    let secret = field("secret");
    let kind = field("kind");
    let algorithm = field("algorithm");
    let pin = field("pin");
    let issuer = field("issuer");
    let account = field("account");

    let (config, issuer, account) = match &uri {
        Some(uri) => {
            let (item, uri_warnings, _) = item_from_uri(format, uri)?;
            warnings.extend(uri_warnings);
            let issuer = item.issuer.or_else(|| text::non_empty(issuer.as_deref()));
            let account = if item.account.is_empty() {
                account.unwrap_or_default()
            } else {
                item.account
            };
            (item.otp, issuer, account)
        }
        None => {
            let Some(secret) = secret.as_deref() else {
                // A row in a password-manager CSV with an empty TOTP column.
                return Ok(None);
            };
            let number = |name: &'static str| -> Option<String> { field(name) };
            let digits = match number("digits") {
                Some(value) => Some(
                    value
                        .trim()
                        .parse::<u8>()
                        .map_err(|_| RowError::InvalidField("digits"))?,
                ),
                None => None,
            };
            let period = match number("period") {
                Some(value) => Some(
                    value
                        .trim()
                        .parse::<u16>()
                        .map_err(|_| RowError::InvalidField("period"))?,
                ),
                None => None,
            };
            let counter = match number("counter") {
                Some(value) => Some(
                    value
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| RowError::InvalidField("counter"))?,
                ),
                None => None,
            };
            let (config, built) = build::config(&OtpFields {
                kind: kind.as_deref(),
                secret: Some(secret),
                algorithm: algorithm.as_deref(),
                digits,
                period,
                counter,
                pin: pin.as_deref(),
                ..OtpFields::default()
            })?;
            warnings.extend(built);
            (
                config,
                text::non_empty(issuer.as_deref()),
                account.unwrap_or_default(),
            )
        }
    };

    let mut item = ImportedItem::new(format, config, issuer, account);
    item.note = text::non_empty(field("note").as_deref());
    item.tags = field("tags")
        .map(|tags| text::split_list(&tags, mapping.list_separator, ctx.limits().max_tags))
        .unwrap_or_default();
    item.groups = text::non_empty(field("group").as_deref())
        .into_iter()
        .collect();
    item.origins = field("url")
        .as_deref()
        .and_then(text::origin_of)
        .into_iter()
        .collect();
    Ok(Some((item, warnings)))
}
