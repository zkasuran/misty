// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What an importer produces: items, per-row outcomes, and the redacted preview
//! the UI shows before anything is written.

use core::fmt;

use misty_otp::{OtpConfig, OtpUri};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::outcome::ImportWarning;

/// Which application's export a row came from.
///
/// One variant per [`Importer`](crate::Importer). Encrypted and plaintext
/// variants of the same vendor format share a variant: they are the same
/// application, and the importer sniffs which one it is holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[non_exhaustive]
pub enum SourceFormat {
    /// One or more `otpauth://` URIs, one per line.
    Otpauth,
    /// Google Authenticator's `otpauth-migration://offline?data=` protobuf.
    GoogleMigration,
    /// Aegis Authenticator JSON vault, plain or scrypt+AES-256-GCM encrypted.
    Aegis,
    /// 2FAS JSON backup.
    TwoFas,
    /// andOTP JSON backup, plain or PBKDF2+AES-256-GCM encrypted.
    AndOtp,
    /// FreeOTP's Android `tokens.xml` (SharedPreferences).
    FreeOtp,
    /// FreeOTP+ JSON backup.
    FreeOtpPlus,
    /// Bitwarden Authenticator (and Bitwarden password manager) JSON export.
    Bitwarden,
    /// Ente Auth plaintext export: `otpauth://` URIs with a `codeDisplay` blob.
    EnteAuth,
    /// Raivo OTP (iOS) JSON export.
    Raivo,
    /// LastPass Authenticator JSON export.
    LastPass,
    /// Proton Pass JSON export.
    ProtonPass,
    /// KeePassXC's unencrypted XML export.
    KeePassXcXml,
    /// Twilio Authy, via a user-extracted JSON dump. Best effort by construction.
    Authy,
    /// Generic CSV with a caller-supplied or header-inferred column mapping.
    Csv,
    /// Generic JSON with a caller-supplied path mapping.
    Json,
}

impl SourceFormat {
    /// Every format, in a stable order, for UI pickers and exhaustive tests.
    pub const ALL: [Self; 16] = [
        Self::Otpauth,
        Self::GoogleMigration,
        Self::Aegis,
        Self::TwoFas,
        Self::AndOtp,
        Self::FreeOtp,
        Self::FreeOtpPlus,
        Self::Bitwarden,
        Self::EnteAuth,
        Self::Raivo,
        Self::LastPass,
        Self::ProtonPass,
        Self::KeePassXcXml,
        Self::Authy,
        Self::Csv,
        Self::Json,
    ];

    /// The name to show a human.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Otpauth => "otpauth:// URI",
            Self::GoogleMigration => "Google Authenticator",
            Self::Aegis => "Aegis Authenticator",
            Self::TwoFas => "2FAS",
            Self::AndOtp => "andOTP",
            Self::FreeOtp => "FreeOTP",
            Self::FreeOtpPlus => "FreeOTP+",
            Self::Bitwarden => "Bitwarden Authenticator",
            Self::EnteAuth => "Ente Auth",
            Self::Raivo => "Raivo OTP",
            Self::LastPass => "LastPass Authenticator",
            Self::ProtonPass => "Proton Pass",
            Self::KeePassXcXml => "KeePassXC (XML export)",
            Self::Authy => "Twilio Authy",
            Self::Csv => "generic CSV",
            Self::Json => "generic JSON",
        }
    }

    /// A short stable slug, used for fixture directory names and telemetry-free
    /// UI strings.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Otpauth => "otpauth",
            Self::GoogleMigration => "google-migration",
            Self::Aegis => "aegis",
            Self::TwoFas => "2fas",
            Self::AndOtp => "andotp",
            Self::FreeOtp => "freeotp",
            Self::FreeOtpPlus => "freeotp-plus",
            Self::Bitwarden => "bitwarden",
            Self::EnteAuth => "ente",
            Self::Raivo => "raivo",
            Self::LastPass => "lastpass",
            Self::ProtonPass => "proton-pass",
            Self::KeePassXcXml => "keepassxc",
            Self::Authy => "authy",
            Self::Csv => "csv",
            Self::Json => "json",
        }
    }
}

impl fmt::Display for SourceFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// One account, read out of somebody else's export and ready for the caller to
/// insert.
///
/// This is deliberately **not** SPEC 3's `Item`: it carries no `ItemId`, no
/// `GroupId`s, no `Hlc`, and no `UsageCounter`, because minting ids and clocks is
/// the vault's job and this crate does not depend on the vault. Groups and icons
/// arrive as the vendor's own names, for the caller to resolve.
///
/// `Debug` is safe to print: the secret lives in a
/// [`SecretBytes`](misty_otp::SecretBytes), which renders `[redacted]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedItem {
    /// The OTP parameters, already validated by `misty-otp`.
    pub otp: OtpConfig,
    /// Issuer, if the export named one.
    pub issuer: Option<String>,
    /// Account name. May be empty: plenty of real exports have no label.
    pub account: String,
    /// A distinguishing label, where the source had one that is neither issuer
    /// nor account (SPEC 3.1 wants same-issuer items distinguishable).
    pub nickname: Option<String>,
    /// Free-text note.
    pub note: Option<String>,
    /// Vendor group or folder names, in file order. The caller maps these to
    /// `GroupId`s.
    pub groups: Vec<String>,
    /// Tags, in file order.
    pub tags: Vec<String>,
    /// The vendor's icon name or slug, if it had one. Never image bytes: an
    /// importer that fetched or embedded artwork would be a network dependency
    /// and a fingerprint (SPEC 0, no icon CDN).
    pub icon_hint: Option<String>,
    /// ARGB colour override the vendor recorded.
    pub color: Option<u32>,
    /// Whether the vendor had it starred.
    pub favorite: bool,
    /// Whether the vendor had it archived, hidden, or in a trash can.
    pub archived: bool,
    /// Domains for extension autofill, where the export carried URLs.
    pub origins: Vec<String>,
    /// Creation time in unix milliseconds, if the export recorded one.
    pub created_at: Option<i64>,
    /// Last-used time in unix milliseconds, if the export recorded one.
    pub last_used_at: Option<i64>,
    /// Which importer produced this item.
    pub source: SourceFormat,
}

impl ImportedItem {
    /// An item with only the fields every format has.
    #[must_use]
    pub fn new(
        source: SourceFormat,
        otp: OtpConfig,
        issuer: Option<String>,
        account: String,
    ) -> Self {
        Self {
            otp,
            issuer: issuer.filter(|issuer| !issuer.is_empty()),
            account,
            nickname: None,
            note: None,
            groups: Vec::new(),
            tags: Vec::new(),
            icon_hint: None,
            color: None,
            favorite: false,
            archived: false,
            origins: Vec::new(),
            created_at: None,
            last_used_at: None,
            source,
        }
    }

    /// Build from a parsed `otpauth://` URI.
    #[must_use]
    pub fn from_uri(source: SourceFormat, uri: &OtpUri) -> Self {
        Self::new(
            source,
            uri.config().clone(),
            uri.issuer().map(str::to_owned),
            uri.account().to_owned(),
        )
    }

    /// The canonical `otpauth://` URI for this item.
    ///
    /// Zeroizing, because it contains the secret — and the PIN, for mOTP and
    /// Yandex.
    #[must_use]
    pub fn to_uri(&self) -> Zeroizing<String> {
        self.as_otp_uri().to_uri()
    }

    /// This item as an [`OtpUri`], for callers that want the URI model rather
    /// than the string.
    #[must_use]
    pub fn as_otp_uri(&self) -> OtpUri {
        OtpUri::new(self.otp.clone(), self.issuer.clone(), self.account.clone())
    }

    /// The item that [`ImportedItem::to_uri`] round-trips back to.
    ///
    /// The identity for every kind except
    /// [`OtpKind::Blizzard`](misty_otp::OtpKind::Blizzard), which `misty-otp`
    /// writes as plain 8-digit SHA-1 TOTP so other authenticators can read it (see
    /// [`OtpKind::serializes_as`](misty_otp::OtpKind::serializes_as)). Fields no
    /// `otpauth://` URI can carry — notes, tags, groups, colours, timestamps — are
    /// dropped, because a URI cannot carry them and pretending otherwise would
    /// make the round-trip property a lie.
    #[must_use]
    pub fn export_form(&self, source: SourceFormat) -> Self {
        let wire = self.otp.kind().serializes_as();
        let otp = if wire == self.otp.kind() {
            self.otp.clone()
        } else {
            // Rebuild through the URI, which is the definition of what the
            // exported form parses back into.
            match OtpUri::parse(&self.to_uri()) {
                Ok(parsed) => parsed.config().clone(),
                Err(_) => self.otp.clone(),
            }
        };
        Self::new(source, otp, self.issuer.clone(), self.account.clone())
    }

    /// A redacted view for the preview screen.
    #[must_use]
    pub fn preview(&self, duplicate_of_existing: bool, warnings: &[ImportWarning]) -> ItemPreview {
        ItemPreview {
            source: self.source,
            issuer: self.issuer.clone(),
            account: self.account.clone(),
            nickname: self.nickname.clone(),
            kind: self.otp.kind().display_name(),
            algorithm: self.otp.algorithm().as_str(),
            digits: self.otp.digits(),
            period: self.otp.period(),
            counter: if self.otp.kind().uses_counter() {
                Some(self.otp.counter())
            } else {
                None
            },
            secret_len: self.otp.secret().len(),
            has_pin: self.otp.pin().is_some(),
            has_note: self.note.is_some(),
            groups: self.groups.clone(),
            tags: self.tags.clone(),
            favorite: self.favorite,
            archived: self.archived,
            origins: self.origins.clone(),
            duplicate_of_existing,
            warnings: warnings.to_vec(),
        }
    }
}

/// What the UI shows before anything is written: every field of an
/// [`ImportedItem`] **except** the secret and the PIN.
///
/// `Serialize` on purpose — this is the type that crosses into the UI — and it is
/// exactly the reason [`ImportedItem`] is not `Serialize`. The secret is described
/// by its length and nothing else. `tests/redaction.rs` asserts that neither the
/// serialized form nor the `Debug` form of a preview contains the secret bytes,
/// their base32, or their hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemPreview {
    /// Which importer produced it.
    pub source: SourceFormat,
    /// Issuer, if any.
    pub issuer: Option<String>,
    /// Account name.
    pub account: String,
    /// Distinguishing label, if the source had one.
    pub nickname: Option<String>,
    /// `OtpKind::display_name` — "TOTP", "Steam", "Yandex".
    pub kind: &'static str,
    /// `HashAlg::as_str` — "SHA1", "SHA256", "SHA512".
    pub algorithm: &'static str,
    /// Digit count of generated codes.
    pub digits: u8,
    /// Time step in seconds.
    pub period: u16,
    /// HOTP counter, where the kind has one.
    pub counter: Option<u64>,
    /// Length of the secret in bytes. Not the secret: a length is not a
    /// credential, and a preview that showed "16 bytes" versus "10 bytes" is how
    /// a user spots a truncated import.
    pub secret_len: usize,
    /// Whether an mOTP/Yandex PIN came along.
    pub has_pin: bool,
    /// Whether a note came along. The note itself is metadata, not secret, but
    /// notes are where people put recovery codes.
    pub has_note: bool,
    /// Vendor group names.
    pub groups: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Starred by the vendor.
    pub favorite: bool,
    /// Archived, hidden or trashed by the vendor.
    pub archived: bool,
    /// Autofill origins recovered from the export.
    pub origins: Vec<String>,
    /// Whether this collides with an entry the caller already has, on the full
    /// `(issuer, account, secret)` triple.
    pub duplicate_of_existing: bool,
    /// Everything the importer had to assume, normalize, or drop.
    pub warnings: Vec<ImportWarning>,
}
