// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! KeePassXC's unencrypted XML export.
//!
//! ```xml
//! <KeePassFile>
//!   <Root>
//!     <Group>
//!       <Name>Root</Name>
//!       <Entry>
//!         <String><Key>Title</Key><Value>GitHub</Value></String>
//!         <String><Key>UserName</Key><Value>ada@example.com</Value></String>
//!         <String><Key>otp</Key><Value>otpauth://totp/GitHub:ada?secret=…</Value></String>
//!       </Entry>
//!     </Group>
//!   </Root>
//! </KeePassFile>
//! ```
//!
//! # Three ways a KeePass entry stores a TOTP, all read
//!
//! | Attributes | Shape |
//! |---|---|
//! | `otp` | a whole `otpauth://` URI — what KeePassXC writes today |
//! | `otp` | KeeOtp's query string: `key=SECRET&size=6&step=30` |
//! | `TOTP Seed` + `TOTP Settings` | the seed, and `30;6` — or `30;S` for Steam |
//!
//! `30;S` is not a typo: KeePassXC spells a Steam token that way, and reading it as
//! a digit count would produce a 6-digit code for a token Steam expects five
//! characters of.
//!
//! # `<History>` is skipped
//!
//! A KeePass entry embeds its own previous versions. Importing them would add one
//! item per historical edit, each with a superseded secret, and the user would have
//! no way to tell which is current. Everything inside `<History>` is ignored.
//!
//! # Reading a `.kdbx` file itself is not implemented
//!
//! Deliberately, and this is the crate's one substantive deviation from SPEC 8 —
//! see `README.md`. A KDBX4 reader needs Argon2id *and* AES-KDF, AES-256-CBC *and*
//! ChaCha20, an HMAC-SHA-256 block chain, an inner Salsa20/ChaCha20 stream cipher
//! for protected values, and gzip, all before the XML above is reachable. That is a
//! large amount of new cryptographic surface, in a crate whose input is hostile by
//! definition, to replace two clicks in KeePassXC's own export menu. The trade is
//! not worth it; the CSV export is also read, through
//! [`ColumnMapping::keepassxc_csv`](crate::ColumnMapping::keepassxc_csv).

use misty_otp::{OtpConfig, OtpKind, SecretBytes};
use quick_xml::events::Event;

use crate::collect::Collector;
use crate::context::ImportContext;
use crate::error::{ImportError, Result, RowError};
use crate::formats::{totp_field, xml};
use crate::importer::{Confidence, Importer};
use crate::model::{ImportedItem, SourceFormat};
use crate::outcome::{ImportReport, ImportWarning, RowId, SkipReason};
use crate::text;

/// Deepest group nesting followed. KeePass databases are shallow; anything deeper
/// is a file trying to make this reader recurse.
const MAX_GROUP_DEPTH: usize = 32;

/// Reads KeePassXC's XML export.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeePassXcImporter;

/// One entry's string attributes, in file order.
#[derive(Debug, Default)]
struct Entry {
    title: Option<String>,
    username: Option<String>,
    notes: Option<String>,
    url: Option<String>,
    otp: Option<String>,
    seed: Option<String>,
    settings: Option<String>,
}

impl Importer for KeePassXcImporter {
    fn format(&self) -> SourceFormat {
        SourceFormat::KeePassXcXml
    }

    fn sniff(&self, input: &[u8]) -> Confidence {
        let head = text::sniff_text(input);
        if head.contains("<KeePassFile") {
            return Confidence::Certain;
        }
        if head.contains("<Entry>") && head.contains("<Key>") {
            return Confidence::Likely;
        }
        Confidence::No
    }

    fn import(&self, input: &[u8], ctx: &ImportContext<'_>) -> Result<ImportReport> {
        let text = text::decode(input, ctx.limits())?;
        let mut reader = quick_xml::Reader::from_str(text);
        reader.config_mut().trim_text(true);

        let mut collector = Collector::new(self.format(), ctx);
        let mut groups: Vec<String> = Vec::new();
        let mut entry: Option<Entry> = None;
        let mut history_depth = 0usize;
        let mut depth = 0usize;
        let mut in_group = false;
        let mut pending_key: Option<String> = None;

        loop {
            match reader.read_event() {
                Ok(Event::Start(start)) => {
                    let name = start.name();
                    // The three leaf elements are read whole — `read_text`
                    // consumes their end tag — because their content is escaped and
                    // `quick-xml` would otherwise deliver it in fragments.
                    match name.as_ref() {
                        b"Name" if history_depth == 0 && in_group => {
                            let value = xml::text_until(&mut reader, name)?;
                            if let Some(last) = groups.last_mut() {
                                *last = value.trim().to_owned();
                            }
                            continue;
                        }
                        b"Key" if history_depth == 0 => {
                            pending_key =
                                Some(xml::text_until(&mut reader, name)?.trim().to_owned());
                            continue;
                        }
                        b"Value" if history_depth == 0 => {
                            let value = xml::text_until(&mut reader, name)?;
                            if let (Some(key), Some(entry)) = (&pending_key, entry.as_mut()) {
                                entry.set(key, value.trim());
                            }
                            continue;
                        }
                        _ => {}
                    }

                    depth += 1;
                    if depth > xml::MAX_DEPTH {
                        return Err(ImportError::Xml {
                            offset: reader.buffer_position(),
                        });
                    }
                    in_group = name.as_ref() == b"Group";
                    match name.as_ref() {
                        b"History" => history_depth += 1,
                        b"Group" if history_depth == 0 => {
                            if groups.len() >= MAX_GROUP_DEPTH {
                                return Err(ImportError::Xml {
                                    offset: reader.buffer_position(),
                                });
                            }
                            groups.push(String::new());
                        }
                        b"Entry" if history_depth == 0 => entry = Some(Entry::default()),
                        _ => {}
                    }
                }
                Ok(Event::End(end)) => {
                    depth = depth.saturating_sub(1);
                    in_group = false;
                    match end.name().as_ref() {
                        b"History" => history_depth = history_depth.saturating_sub(1),
                        b"Group" if history_depth == 0 => {
                            groups.pop();
                        }
                        b"Entry" if history_depth == 0 => {
                            if let Some(entry) = entry.take() {
                                if collector.is_full() {
                                    return Err(ImportError::TooManyRows {
                                        max: ctx.limits().max_rows,
                                    });
                                }
                                push_entry(&entry, &groups, &mut collector);
                            }
                        }
                        b"String" => pending_key = None,
                        _ => {}
                    }
                }
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

impl Entry {
    fn set(&mut self, key: &str, value: &str) {
        let slot = match key {
            "Title" => &mut self.title,
            "UserName" => &mut self.username,
            "Notes" => &mut self.notes,
            "URL" => &mut self.url,
            "otp" => &mut self.otp,
            "TOTP Seed" => &mut self.seed,
            "TOTP Settings" => &mut self.settings,
            _ => return,
        };
        if !value.is_empty() {
            *slot = Some(value.to_owned());
        }
    }
}

fn push_entry(entry: &Entry, groups: &[String], collector: &mut Collector<'_, '_>) {
    let row = RowId::at(collector.rows()).labelled(
        entry.title.as_deref(),
        entry.username.as_deref().unwrap_or_default(),
    );

    let built = match read_entry(entry, groups) {
        Ok(Some(built)) => built,
        // A KeePass database is mostly passwords. An entry with no TOTP attribute
        // is the normal case, not a problem.
        Ok(None) => {
            collector.skip(row, SkipReason::NoOtpSecret);
            return;
        }
        Err(error) => {
            collector.fail(row, error);
            return;
        }
    };
    let (item, warnings) = built;
    collector.accept(row, item, warnings);
}

type EntryResult = core::result::Result<Option<(ImportedItem, Vec<ImportWarning>)>, RowError>;

fn read_entry(entry: &Entry, groups: &[String]) -> EntryResult {
    let title = entry.title.as_deref();
    let username = entry.username.as_deref();

    let (config, warnings, issuer, account) = match (&entry.otp, &entry.seed) {
        (Some(otp), _) => read_otp_attribute(otp, title, username)?,
        (None, Some(seed)) => read_legacy(seed, entry.settings.as_deref(), title, username)?,
        (None, None) => return Ok(None),
    };

    let mut item = ImportedItem::new(SourceFormat::KeePassXcXml, config, issuer, account);
    item.note = entry.notes.clone();
    item.groups = groups
        .iter()
        .filter(|name| !name.is_empty() && *name != "Root")
        .cloned()
        .collect();
    item.origins = entry
        .url
        .as_deref()
        .and_then(text::origin_of)
        .into_iter()
        .collect();
    Ok(Some((item, warnings)))
}

type Parsed = (OtpConfig, Vec<ImportWarning>, Option<String>, String);

/// The `otp` attribute: an `otpauth://` URI, or KeeOtp's query string.
fn read_otp_attribute(
    value: &str,
    title: Option<&str>,
    username: Option<&str>,
) -> core::result::Result<Parsed, RowError> {
    if value.contains("key=") && !value.contains("://") {
        return read_keeotp(value, title, username);
    }
    totp_field(value, title, username)
}

/// KeeOtp1's `otp` attribute: `key=SECRET&size=6&step=30&type=totp`.
fn read_keeotp(
    value: &str,
    title: Option<&str>,
    username: Option<&str>,
) -> core::result::Result<Parsed, RowError> {
    let mut secret = None;
    let mut digits = None;
    let mut period = None;
    for (name, field) in value.split('&').filter_map(|pair| pair.split_once('=')) {
        match name.trim() {
            "key" => secret = Some(field.trim()),
            "size" => digits = field.trim().parse::<u8>().ok(),
            "step" => period = field.trim().parse::<u16>().ok(),
            _ => {}
        }
    }
    let secret = secret.ok_or(RowError::MissingField("otp.key"))?;
    let mut builder = OtpConfig::builder(
        OtpKind::Totp,
        SecretBytes::from_base32(secret).map_err(RowError::Otp)?,
    );
    let mut warnings = Vec::new();
    match digits {
        Some(digits) => builder = builder.digits(digits),
        None => warnings.push(ImportWarning::AssumedDefault("digits")),
    }
    match period {
        Some(period) => builder = builder.period(period),
        None => warnings.push(ImportWarning::AssumedDefault("period")),
    }
    Ok((
        builder.build().map_err(RowError::Otp)?,
        warnings,
        text::non_empty(title),
        username.unwrap_or_default().to_owned(),
    ))
}

/// The legacy pair: `TOTP Seed` plus `TOTP Settings`, which is `step;digits` —
/// or `step;S` for a Steam token.
fn read_legacy(
    seed: &str,
    settings: Option<&str>,
    title: Option<&str>,
    username: Option<&str>,
) -> core::result::Result<Parsed, RowError> {
    let mut warnings = Vec::new();
    let mut period = None;
    let mut digits = None;
    let mut kind = OtpKind::Totp;

    match settings {
        Some(settings) => {
            let mut parts = settings.split(';').map(str::trim);
            period = parts.next().and_then(|part| part.parse::<u16>().ok());
            match parts.next() {
                Some(part) if part.eq_ignore_ascii_case("S") => kind = OtpKind::Steam,
                Some(part) => digits = part.parse::<u8>().ok(),
                None => {}
            }
            if period.is_none() {
                return Err(RowError::InvalidField("TOTP Settings"));
            }
        }
        None => warnings.push(ImportWarning::AssumedDefault("TOTP Settings")),
    }

    let mut builder =
        OtpConfig::builder(kind, SecretBytes::from_base32(seed).map_err(RowError::Otp)?);
    if let Some(period) = period {
        builder = builder.period(period);
    }
    match digits {
        Some(digits) => builder = builder.digits(digits),
        None if kind == OtpKind::Totp => warnings.push(ImportWarning::AssumedDefault("digits")),
        None => {}
    }
    Ok((
        builder.build().map_err(RowError::Otp)?,
        warnings,
        text::non_empty(title),
        username.unwrap_or_default().to_owned(),
    ))
}
