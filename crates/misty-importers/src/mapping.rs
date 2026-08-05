// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Column mapping for the generic CSV and JSON importers.
//!
//! SPEC 8 asks for "generic CSV/JSON with a column-mapping UI". This is the model
//! behind that UI: the caller names which column or JSON path holds which field,
//! and the importer does no guessing. When the caller names nothing, a CSV header
//! row is matched against [`ColumnMapping::CANDIDATES`] instead — inference is a
//! convenience, and an explicit mapping always wins.

/// Which column or JSON path holds which field.
///
/// Every field is optional. For CSV, a value is a header name when
/// [`ColumnMapping::has_header`] is true and a zero-based column index (written in
/// decimal) when it is false. For JSON, a value is a dot-separated path inside one
/// array element, so `info.secret` reaches `{"info": {"secret": "…"}}`.
///
/// Either [`ColumnMapping::uri`] or [`ColumnMapping::secret`] must resolve, or
/// there is nothing to import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ColumnMapping {
    /// A column holding a whole `otpauth://` URI. When it resolves, every other
    /// OTP field is taken from the URI and the rest of this mapping applies only
    /// to metadata.
    pub uri: Option<String>,
    /// The shared secret: base32, or hex for mOTP.
    pub secret: Option<String>,
    /// Issuer.
    pub issuer: Option<String>,
    /// Account name.
    pub account: Option<String>,
    /// Token type: `totp`, `hotp`, `steam`, `motp`, `yaotp`, `blizzard`.
    pub kind: Option<String>,
    /// Hash: `SHA1`, `SHA256`, `SHA512`.
    pub algorithm: Option<String>,
    /// Digit count.
    pub digits: Option<String>,
    /// Time step in seconds.
    pub period: Option<String>,
    /// HOTP counter.
    pub counter: Option<String>,
    /// mOTP or Yandex PIN.
    pub pin: Option<String>,
    /// Free-text note.
    pub note: Option<String>,
    /// Tags, split on [`ColumnMapping::list_separator`].
    pub tags: Option<String>,
    /// Group or folder name.
    pub group: Option<String>,
    /// A URL, kept as an autofill origin.
    pub url: Option<String>,
    /// Whether the first CSV row is a header. Ignored for JSON.
    pub has_header: bool,
    /// CSV field separator. Ignored for JSON.
    pub delimiter: u8,
    /// Separator for multi-value fields such as tags.
    pub list_separator: char,
    /// Dot-separated path to the array of records. JSON only; `None` means the
    /// document is itself an array.
    pub array_path: Option<String>,
}

impl ColumnMapping {
    /// Header names the CSV importer recognizes without being told, lowercased.
    ///
    /// Order matters: the first candidate present in the header row wins, so
    /// `secret` beats `key` and `issuer` beats `name`.
    pub const CANDIDATES: &'static [(&'static str, &'static [&'static str])] = &[
        (
            "uri",
            &[
                "otpauth",
                "otpauth_url",
                "otp_url",
                "uri",
                "url_otp",
                "link",
            ],
        ),
        (
            "secret",
            &[
                "secret",
                "seed",
                "secret_key",
                "totp_secret",
                "key",
                "otp_secret",
            ],
        ),
        (
            "issuer",
            &[
                "issuer",
                "service",
                "provider",
                "site",
                "organisation",
                "organization",
                "name",
                "title",
            ],
        ),
        (
            "account",
            &[
                "account",
                "username",
                "user",
                "login",
                "email",
                "account_name",
                "label",
            ],
        ),
        (
            "kind",
            &["kind", "type", "otp_type", "token_type", "tokentype"],
        ),
        ("algorithm", &["algorithm", "algo", "hash", "hmac"]),
        (
            "digits",
            &["digits", "length", "code_length", "digit_count"],
        ),
        (
            "period",
            &[
                "period",
                "timestep",
                "time_step",
                "interval",
                "timer",
                "step",
            ],
        ),
        ("counter", &["counter", "hotp_counter"]),
        ("pin", &["pin", "motp_pin"]),
        ("note", &["note", "notes", "comment", "description"]),
        ("tags", &["tags", "tag", "labels"]),
        ("group", &["group", "folder", "category", "collection"]),
        ("url", &["url", "website", "origin", "domain"]),
    ];

    /// An empty mapping: infer from the CSV header row, or fail with
    /// [`ImportError::MappingRequired`](crate::ImportError).
    #[must_use]
    pub fn new() -> Self {
        Self {
            has_header: true,
            delimiter: b',',
            list_separator: ',',
            ..Self::default()
        }
    }

    /// KeePassXC's `Database ▸ Export ▸ CSV` columns, which put the whole
    /// `otpauth://` URI in a `TOTP` column.
    #[must_use]
    pub fn keepassxc_csv() -> Self {
        Self {
            uri: Some("TOTP".to_owned()),
            issuer: Some("Title".to_owned()),
            account: Some("Username".to_owned()),
            note: Some("Notes".to_owned()),
            group: Some("Group".to_owned()),
            url: Some("URL".to_owned()),
            ..Self::new()
        }
    }

    /// Bitwarden's password-manager CSV columns.
    #[must_use]
    pub fn bitwarden_csv() -> Self {
        Self {
            uri: Some("login_totp".to_owned()),
            issuer: Some("name".to_owned()),
            account: Some("login_username".to_owned()),
            note: Some("notes".to_owned()),
            group: Some("folder".to_owned()),
            url: Some("login_uri".to_owned()),
            ..Self::new()
        }
    }

    /// The shape Misty's own plaintext JSON export writes, so the escape hatch
    /// can be walked back in.
    #[must_use]
    pub fn misty_plaintext_json() -> Self {
        Self {
            array_path: Some("items".to_owned()),
            uri: Some("uri".to_owned()),
            issuer: Some("issuer".to_owned()),
            account: Some("account".to_owned()),
            note: Some("note".to_owned()),
            ..Self::new()
        }
    }

    /// Set the column holding a whole `otpauth://` URI.
    #[must_use]
    pub fn uri(mut self, column: impl Into<String>) -> Self {
        self.uri = Some(column.into());
        self
    }

    /// Set the column holding the secret.
    #[must_use]
    pub fn secret(mut self, column: impl Into<String>) -> Self {
        self.secret = Some(column.into());
        self
    }

    /// Set the column holding the issuer.
    #[must_use]
    pub fn issuer(mut self, column: impl Into<String>) -> Self {
        self.issuer = Some(column.into());
        self
    }

    /// Set the column holding the account name.
    #[must_use]
    pub fn account(mut self, column: impl Into<String>) -> Self {
        self.account = Some(column.into());
        self
    }

    /// Set the column holding the token type.
    #[must_use]
    pub fn kind(mut self, column: impl Into<String>) -> Self {
        self.kind = Some(column.into());
        self
    }

    /// Set the column holding the hash algorithm.
    #[must_use]
    pub fn algorithm(mut self, column: impl Into<String>) -> Self {
        self.algorithm = Some(column.into());
        self
    }

    /// Set the column holding the digit count.
    #[must_use]
    pub fn digits(mut self, column: impl Into<String>) -> Self {
        self.digits = Some(column.into());
        self
    }

    /// Set the column holding the period.
    #[must_use]
    pub fn period(mut self, column: impl Into<String>) -> Self {
        self.period = Some(column.into());
        self
    }

    /// Set the column holding the HOTP counter.
    #[must_use]
    pub fn counter(mut self, column: impl Into<String>) -> Self {
        self.counter = Some(column.into());
        self
    }

    /// Set the column holding the mOTP/Yandex PIN.
    #[must_use]
    pub fn pin(mut self, column: impl Into<String>) -> Self {
        self.pin = Some(column.into());
        self
    }

    /// Set the column holding a note.
    #[must_use]
    pub fn note(mut self, column: impl Into<String>) -> Self {
        self.note = Some(column.into());
        self
    }

    /// Set the column holding tags.
    #[must_use]
    pub fn tags(mut self, column: impl Into<String>) -> Self {
        self.tags = Some(column.into());
        self
    }

    /// Set the column holding a group or folder name.
    #[must_use]
    pub fn group(mut self, column: impl Into<String>) -> Self {
        self.group = Some(column.into());
        self
    }

    /// Set the column holding a URL.
    #[must_use]
    pub fn url(mut self, column: impl Into<String>) -> Self {
        self.url = Some(column.into());
        self
    }

    /// Set the dot-separated path to the array of records (JSON only).
    #[must_use]
    pub fn array_path(mut self, path: impl Into<String>) -> Self {
        self.array_path = Some(path.into());
        self
    }

    /// Say whether the first CSV row is a header.
    #[must_use]
    pub fn with_header(mut self, has_header: bool) -> Self {
        self.has_header = has_header;
        self
    }

    /// Set the CSV field separator — `b'\t'` for TSV, `b';'` for the European
    /// spreadsheet convention.
    #[must_use]
    pub fn with_delimiter(mut self, delimiter: u8) -> Self {
        self.delimiter = delimiter;
        self
    }

    /// Set the separator used inside multi-value fields such as tags.
    #[must_use]
    pub fn with_list_separator(mut self, separator: char) -> Self {
        self.list_separator = separator;
        self
    }

    /// Whether anything at all was named.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.uri.is_none()
            && self.secret.is_none()
            && self.issuer.is_none()
            && self.account.is_none()
            && self.kind.is_none()
            && self.algorithm.is_none()
            && self.digits.is_none()
            && self.period.is_none()
            && self.counter.is_none()
            && self.pin.is_none()
            && self.note.is_none()
            && self.tags.is_none()
            && self.group.is_none()
            && self.url.is_none()
    }

    /// Fill in anything unset from a CSV header row, by matching
    /// [`ColumnMapping::CANDIDATES`] case-insensitively.
    ///
    /// Returns whether the result can import anything at all.
    pub(crate) fn infer_from_header(&mut self, header: &[String]) -> bool {
        let normalized: Vec<String> = header
            .iter()
            .map(|name| {
                name.trim()
                    .trim_start_matches('\u{feff}')
                    .to_ascii_lowercase()
                    .replace([' ', '-'], "_")
            })
            .collect();

        for (field, candidates) in Self::CANDIDATES {
            if self.slot(field).is_some() {
                continue;
            }
            let found = candidates.iter().find_map(|candidate| {
                normalized
                    .iter()
                    .position(|name| name == candidate)
                    .and_then(|at| header.get(at))
            });
            if let Some(name) = found {
                let name = name.clone();
                if let Some(slot) = self.slot_mut(field) {
                    *slot = Some(name);
                }
            }
        }

        self.uri.is_some() || self.secret.is_some()
    }

    /// Read one named slot. Kept in one place so the field list cannot drift out
    /// of step with [`ColumnMapping::CANDIDATES`].
    pub(crate) fn slot(&self, field: &str) -> Option<&String> {
        match field {
            "uri" => self.uri.as_ref(),
            "secret" => self.secret.as_ref(),
            "issuer" => self.issuer.as_ref(),
            "account" => self.account.as_ref(),
            "kind" => self.kind.as_ref(),
            "algorithm" => self.algorithm.as_ref(),
            "digits" => self.digits.as_ref(),
            "period" => self.period.as_ref(),
            "counter" => self.counter.as_ref(),
            "pin" => self.pin.as_ref(),
            "note" => self.note.as_ref(),
            "tags" => self.tags.as_ref(),
            "group" => self.group.as_ref(),
            "url" => self.url.as_ref(),
            _ => None,
        }
    }

    fn slot_mut(&mut self, field: &str) -> Option<&mut Option<String>> {
        match field {
            "uri" => Some(&mut self.uri),
            "secret" => Some(&mut self.secret),
            "issuer" => Some(&mut self.issuer),
            "account" => Some(&mut self.account),
            "kind" => Some(&mut self.kind),
            "algorithm" => Some(&mut self.algorithm),
            "digits" => Some(&mut self.digits),
            "period" => Some(&mut self.period),
            "counter" => Some(&mut self.counter),
            "pin" => Some(&mut self.pin),
            "note" => Some(&mut self.note),
            "tags" => Some(&mut self.tags),
            "group" => Some(&mut self.group),
            "url" => Some(&mut self.url),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_finds_common_spellings() {
        let mut mapping = ColumnMapping::new();
        let header: Vec<String> = ["Service", "Login", "Secret Key", "Time Step", "Notes"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        assert!(mapping.infer_from_header(&header));
        assert_eq!(mapping.issuer.as_deref(), Some("Service"));
        assert_eq!(mapping.account.as_deref(), Some("Login"));
        assert_eq!(mapping.secret.as_deref(), Some("Secret Key"));
        assert_eq!(mapping.period.as_deref(), Some("Time Step"));
        assert_eq!(mapping.note.as_deref(), Some("Notes"));
    }

    #[test]
    fn inference_never_overwrites_the_caller() {
        let mut mapping = ColumnMapping::new().secret("mine");
        let header = vec!["secret".to_owned(), "issuer".to_owned()];
        assert!(mapping.infer_from_header(&header));
        assert_eq!(mapping.secret.as_deref(), Some("mine"));
        assert_eq!(mapping.issuer.as_deref(), Some("issuer"));
    }

    #[test]
    fn a_header_with_nothing_usable_is_reported() {
        let mut mapping = ColumnMapping::new();
        let header = vec!["colour".to_owned(), "shoe size".to_owned()];
        assert!(!mapping.infer_from_header(&header));
    }

    #[test]
    fn every_candidate_field_has_a_slot() {
        // Guards against a candidate list entry whose field name is misspelled,
        // which would silently never be inferred.
        let mut mapping = ColumnMapping::new();
        for (field, _) in ColumnMapping::CANDIDATES {
            assert!(mapping.slot_mut(field).is_some(), "no slot for {field:?}");
        }
    }
}
