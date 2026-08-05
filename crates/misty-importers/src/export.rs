// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Export: `otpauth://` for the QR sheet, and plaintext JSON as the escape hatch.
//!
//! # What is here, and what is deliberately not
//!
//! | SPEC 8 asks for | Where it lives |
//! |---|---|
//! | `otpauth://` QR sheet | here: [`qr_sheet`] returns the URI per item; rendering is the UI's job |
//! | plaintext JSON behind a confirmation gate | here: [`plaintext_json`] |
//! | encrypted `.mistybak` | `misty_crypto::backup` — **not** reimplemented here |
//! | SLIP-39 splitting of the Recovery Key | `misty-crypto`: it splits a key, not an item list |
//!
//! A PDF writer is not in this crate. [`qr_sheet`] returns the label and the URI
//! for each item, which is everything a renderer needs, and it keeps a font stack
//! and a PDF serializer out of a crate that has to compile to
//! `wasm32-unknown-unknown` and whose other job is parsing hostile files.
//!
//! # Everything here returns [`Zeroizing`]
//!
//! An export *is* the secrets, in the most copyable form they will ever take. The
//! strings this module returns zeroize when dropped, and none of them can reach a
//! log line through `Display` on a wrapper type, because the wrappers do not
//! implement it.

use zeroize::Zeroizing;

use crate::model::ImportedItem;

/// The phrase [`plaintext_json`] requires, verbatim.
///
/// SPEC 2.5 says a plaintext export must be behind a typed confirmation phrase. A
/// UI could enforce that and forget to; making the library refuse without it means
/// the gate cannot be skipped by accident. The fresh biometric or PIN check the same
/// section requires is the application's to make — this crate has no idea what
/// platform it is on.
pub const PLAINTEXT_EXPORT_CONFIRMATION: &str = "EXPORT MY SECRETS IN PLAIN TEXT";

/// The header written into every plaintext export, as the first field of the
/// object.
///
/// JSON has no comment syntax, so the "loud header comment" SPEC 2.5 asks for is a
/// `_WARNING` string field written first. Writing it first is why this module
/// serializes the document by hand: `serde_json`'s map is ordered by key, and a
/// warning nobody sees until they scroll is not a warning.
pub const PLAINTEXT_EXPORT_WARNING: &str = "\
    THIS FILE CONTAINS YOUR TWO-FACTOR SECRETS IN PLAIN TEXT. \
    Anyone who reads it can generate your codes forever, and no service will \
    notice. It is not protected by your device lock, your passphrase, or anything \
    else. Do not put it in cloud storage, do not email it, do not keep it in \
    Downloads. Import it where you need it and then delete it securely. \
    For a backup you can keep, use an encrypted .mistybak file instead.";

/// The `format` marker written into a plaintext export, so an importer can
/// recognize it.
pub const PLAINTEXT_EXPORT_FORMAT: &str = "misty-plaintext-export";

/// Version of the plaintext export shape.
pub const PLAINTEXT_EXPORT_VERSION: u32 = 1;

/// Why an export was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExportError {
    /// The caller did not pass [`PLAINTEXT_EXPORT_CONFIRMATION`].
    #[error("a plaintext export requires the confirmation phrase to be typed exactly")]
    ConfirmationRequired,
}

/// One item's line on a printable sheet.
///
/// `Debug` shows the label and hides the URI, because the URI is the credential.
#[derive(Clone)]
pub struct QrEntry {
    /// What to print under the code: `Issuer: account`, or whichever of the two
    /// exists.
    pub label: String,
    /// The token kind's display name, for a sheet that mixes TOTP and Steam.
    pub kind: &'static str,
    /// The `otpauth://` URI to encode. **This is the secret.**
    pub uri: Zeroizing<String>,
}

impl core::fmt::Debug for QrEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QrEntry")
            .field("label", &self.label)
            .field("kind", &self.kind)
            .field("uri", &"[redacted]")
            .finish()
    }
}

/// A printable sheet's worth of data.
#[derive(Debug, Clone, Default)]
pub struct QrSheet {
    /// One entry per item, in the order given.
    pub entries: Vec<QrEntry>,
}

impl QrSheet {
    /// How many codes the sheet holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there is nothing to print.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The data for a printable `otpauth://` QR sheet.
///
/// A [`Blizzard`](misty_otp::OtpKind::Blizzard) item is written as plain 8-digit
/// SHA-1 TOTP, which is `misty-otp`'s documented and deliberate normalization: the
/// URI is byte-identical to the equivalent TOTP one, so every other authenticator
/// can read it (SPEC 7.1).
#[must_use]
pub fn qr_sheet(items: &[ImportedItem]) -> QrSheet {
    QrSheet {
        entries: items
            .iter()
            .map(|item| QrEntry {
                label: label_for(item),
                kind: item.otp.kind().display_name(),
                uri: item.to_uri(),
            })
            .collect(),
    }
}

/// Every item as one `otpauth://` URI per line.
///
/// No header, no comments, no trailing commentary: this is the form other
/// authenticators paste into, and anything else in the file is something for one of
/// them to choke on. Misty's own reader would accept `#` comments; not every
/// reader does.
#[must_use]
pub fn uri_list(items: &[ImportedItem]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    for item in items {
        out.push_str(&item.to_uri());
        out.push('\n');
    }
    out
}

/// A plaintext JSON export, warning first.
///
/// # Errors
///
/// [`ExportError::ConfirmationRequired`] unless `confirmation` is exactly
/// [`PLAINTEXT_EXPORT_CONFIRMATION`].
///
/// # Round-tripping
///
/// Every item carries its own `otpauth://` URI in a `uri` field, so the file reads
/// back through [`ColumnMapping::misty_plaintext_json`](crate::ColumnMapping::misty_plaintext_json)
/// with no new importer. `tests/round_trip.rs` asserts that.
pub fn plaintext_json(
    items: &[ImportedItem],
    confirmation: &str,
) -> core::result::Result<Zeroizing<String>, ExportError> {
    if confirmation != PLAINTEXT_EXPORT_CONFIRMATION {
        return Err(ExportError::ConfirmationRequired);
    }

    let mut out = Zeroizing::new(String::with_capacity(512 + items.len() * 256));
    out.push_str("{\n  \"_WARNING\": ");
    out.push_str(&quote(PLAINTEXT_EXPORT_WARNING));
    out.push_str(",\n  \"format\": ");
    out.push_str(&quote(PLAINTEXT_EXPORT_FORMAT));
    out.push_str(",\n  \"version\": ");
    out.push_str(&PLAINTEXT_EXPORT_VERSION.to_string());
    out.push_str(",\n  \"item_count\": ");
    out.push_str(&items.len().to_string());
    out.push_str(",\n  \"items\": [");

    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("\n    {");
        write_item(&mut out, item);
        out.push('}');
    }

    out.push_str("\n  ]\n}\n");
    Ok(out)
}

fn write_item(out: &mut Zeroizing<String>, item: &ImportedItem) {
    let config = &item.otp;
    let kind = config.kind();

    let mut first = true;
    let mut field = |out: &mut Zeroizing<String>, name: &str, value: &str| {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str("\n      ");
        out.push_str(&quote(name));
        out.push_str(": ");
        out.push_str(value);
    };

    field(out, "issuer", &opt_quote(item.issuer.as_deref()));
    field(out, "account", &quote(&item.account));
    field(out, "nickname", &opt_quote(item.nickname.as_deref()));
    field(out, "note", &opt_quote(item.note.as_deref()));
    field(out, "kind", &quote(kind.uri_type()));
    field(out, "algorithm", &quote(config.algorithm().as_str()));
    field(out, "digits", &config.digits().to_string());
    field(out, "period", &config.period().to_string());
    field(
        out,
        "counter",
        &if kind.uses_counter() {
            config.counter().to_string()
        } else {
            "null".to_owned()
        },
    );

    // The one place in this crate that writes a secret out. `misty-otp` chooses the
    // encoding per kind — hex for mOTP, base32 for everything else — and the
    // returned strings zeroize.
    let secret = match kind.secret_encoding() {
        misty_otp::SecretEncoding::Hex => config.secret().to_hex(),
        _ => config.secret().to_base32(),
    };
    field(out, "secret", &quote(&secret));
    let pin = config
        .pin()
        .map(|pin| Zeroizing::new(String::from_utf8_lossy(pin.expose_secret()).into_owned()));
    field(out, "pin", &opt_quote(pin.as_deref().map(String::as_str)));

    field(out, "tags", &list(&item.tags));
    field(out, "groups", &list(&item.groups));
    field(out, "origins", &list(&item.origins));
    field(out, "favorite", &item.favorite.to_string());
    field(out, "archived", &item.archived.to_string());
    field(out, "icon", &opt_quote(item.icon_hint.as_deref()));
    field(
        out,
        "created_at",
        &item
            .created_at
            .map_or_else(|| "null".to_owned(), |at| at.to_string()),
    );
    field(
        out,
        "last_used_at",
        &item
            .last_used_at
            .map_or_else(|| "null".to_owned(), |at| at.to_string()),
    );
    field(out, "source", &quote(item.source.slug()));
    // Last, and the field an importer actually needs: everything above is metadata.
    field(out, "uri", &quote(&item.to_uri()));
}

/// JSON-quote a string. `serde_json` does the escaping, so the output is correct
/// for control characters, quotes and non-ASCII alike.
fn quote(value: &str) -> Zeroizing<String> {
    Zeroizing::new(serde_json::to_string(value).unwrap_or_else(|_| {
        // `to_string` on a `&str` cannot fail; this branch exists so the export
        // path has no `unwrap`.
        "\"\"".to_owned()
    }))
}

fn opt_quote(value: Option<&str>) -> Zeroizing<String> {
    match value {
        Some(value) => quote(value),
        None => Zeroizing::new("null".to_owned()),
    }
}

fn list(values: &[String]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::from("["));
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&quote(value));
    }
    out.push(']');
    out
}

/// `Issuer: account`, or whichever exists, or the token kind as a last resort.
fn label_for(item: &ImportedItem) -> String {
    match (item.issuer.as_deref(), item.account.as_str()) {
        (Some(issuer), "") => issuer.to_owned(),
        (Some(issuer), account) => format!("{issuer}: {account}"),
        (None, "") => item.otp.kind().display_name().to_owned(),
        (None, account) => account.to_owned(),
    }
}
