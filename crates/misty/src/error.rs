// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The flattened error taxonomy (SPEC §11.3).
//!
//! Five source error enums collapse into one [`FacadeError`] whose stability lives in
//! a machine-readable [`ErrorCode`], never in a discriminant — because a
//! `#[non_exhaustive]` source enum has no frozen discriminant and wasm-bindgen cannot
//! carry a data-carrying enum at all. Bindings branch on [`ErrorCode::as_str`], never
//! on [`FacadeError::message`] (§11.3.2).

use core::fmt;

/// The frozen, machine-readable failure vocabulary (SPEC §11.3). Serialized across
/// the boundary by its [`as_str`](Self::as_str) `UPPER_SNAKE` name — the contract
/// bindings branch on. New codes MAY be added, so downstream matches carry a default
/// arm; hence `#[non_exhaustive]`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The call needs an unlocked vault; the handle is locked (§11.5).
    VaultLocked,
    /// The operation is absent on this build's target.
    UnsupportedOnTarget,
    /// A caught impossible state, a CSPRNG/AEAD failure, or an unmapped variant.
    Internal,
    /// No item or group with that id.
    NotFound,
    /// The id or device already exists.
    AlreadyExists,
    /// The same `(issuer, account, secret)` is already stored (§3.1).
    DuplicateAccount,
    /// The same `(issuer, account)` with a different secret; needs a nickname (§3.1).
    AmbiguousAccount,
    /// A label or field failed validation on a write.
    InvalidField,
    /// The OTP secret is empty, mis-encoded, or too long.
    OtpInvalidSecret,
    /// OTP digits/period out of range, or a required PIN is missing.
    OtpInvalidParam,
    /// An `otpauth://` URI failed to parse or is too long.
    UriMalformed,
    /// A code could not be produced (clock out of range, internal).
    OtpGenerationFailed,
    /// A monotonic ceiling was hit: HLC, epoch, or HOTP counter.
    ResourceExhausted,
    /// A merge could not settle.
    MergeFailed,
    /// An envelope, backup, recovery blob, or enrollment would not open.
    DecryptFailed,
    /// An Ed25519 signature or verifying key failed verification (tamper).
    SignatureInvalid,
    /// The writer or approver is not in the signed roster (§6.2).
    UntrustedSigner,
    /// This device is absent from the roster (revoked or never enrolled).
    DeviceRevoked,
    /// A stored or received blob will not decode.
    CorruptData,
    /// Argon2id id or parameters outside the accepted range.
    KdfRejected,
    /// A format/schema/state/export version newer than this build.
    VersionUnsupported,
    /// The epoch key does not match the envelope's epoch.
    EpochMismatch,
    /// Recovery words/compact/QR mistyped, wrong length, or bad checksum.
    RecoveryInputInvalid,
    /// The typed enrollment confirmation code is wrong.
    ConfirmationCodeMismatch,
    /// An enrollment blob's `enroll_id` does not match.
    EnrollIdMismatch,
    /// The request never reached a well-formed response.
    Network,
    /// TLS handshake failed or a certificate pin did not match (A2).
    TlsError,
    /// The server returned `5xx`.
    ServerError,
    /// A challenge/verify/refresh was refused.
    AuthFailed,
    /// The vault is full (`507`, §6.1).
    QuotaExhausted,
    /// The server broke a protocol invariant.
    ProtocolViolation,
    /// Signed `/v1/time` failed to verify, replayed, or went backwards (§6.5).
    TimeUntrusted,
    /// The server URL is not `https`/malformed, or a pin is the wrong length.
    ConfigInvalid,
    /// The SQLite or state backend reported a failure.
    StorageFailed,
    /// No importer matched, or the input is empty.
    ImportUnrecognized,
    /// The import file is broken, too large, or lacks a usable header.
    ImportMalformed,
    /// An encrypted export needs a passphrase.
    ImportPassphraseRequired,
    /// This vendor's export encryption is not supported.
    ImportEncryptedUnsupported,
    /// A plaintext export was attempted without the §2.5 confirmation gate.
    ConfirmationRequired,
}
impl ErrorCode {
    /// The frozen `UPPER_SNAKE` token bindings branch on (SPEC §11.3.1).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VaultLocked => "VAULT_LOCKED",
            Self::UnsupportedOnTarget => "UNSUPPORTED_ON_TARGET",
            Self::Internal => "INTERNAL",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::DuplicateAccount => "DUPLICATE_ACCOUNT",
            Self::AmbiguousAccount => "AMBIGUOUS_ACCOUNT",
            Self::InvalidField => "INVALID_FIELD",
            Self::OtpInvalidSecret => "OTP_INVALID_SECRET",
            Self::OtpInvalidParam => "OTP_INVALID_PARAM",
            Self::UriMalformed => "URI_MALFORMED",
            Self::OtpGenerationFailed => "OTP_GENERATION_FAILED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::MergeFailed => "MERGE_FAILED",
            Self::DecryptFailed => "DECRYPT_FAILED",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::UntrustedSigner => "UNTRUSTED_SIGNER",
            Self::DeviceRevoked => "DEVICE_REVOKED",
            Self::CorruptData => "CORRUPT_DATA",
            Self::KdfRejected => "KDF_REJECTED",
            Self::VersionUnsupported => "VERSION_UNSUPPORTED",
            Self::EpochMismatch => "EPOCH_MISMATCH",
            Self::RecoveryInputInvalid => "RECOVERY_INPUT_INVALID",
            Self::ConfirmationCodeMismatch => "CONFIRMATION_CODE_MISMATCH",
            Self::EnrollIdMismatch => "ENROLL_ID_MISMATCH",
            Self::Network => "NETWORK",
            Self::TlsError => "TLS_ERROR",
            Self::ServerError => "SERVER_ERROR",
            Self::AuthFailed => "AUTH_FAILED",
            Self::QuotaExhausted => "QUOTA_EXHAUSTED",
            Self::ProtocolViolation => "PROTOCOL_VIOLATION",
            Self::TimeUntrusted => "TIME_UNTRUSTED",
            Self::ConfigInvalid => "CONFIG_INVALID",
            Self::StorageFailed => "STORAGE_FAILED",
            Self::ImportUnrecognized => "IMPORT_UNRECOGNIZED",
            Self::ImportMalformed => "IMPORT_MALFORMED",
            Self::ImportPassphraseRequired => "IMPORT_PASSPHRASE_REQUIRED",
            Self::ImportEncryptedUnsupported => "IMPORT_ENCRYPTED_UNSUPPORTED",
            Self::ConfirmationRequired => "CONFIRMATION_REQUIRED",
        }
    }
    /// Whether a bare retry of the identical call MAY succeed — transient conditions
    /// only (SPEC §11.3.3). A pure function of the code: exactly `NETWORK` and
    /// `SERVER_ERROR` are retryable.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Network | Self::ServerError)
    }
}

/// The one error that crosses the boundary (SPEC §11.3.1). `code` is the stable
/// contract; `message` is English, redacted (§11.3.4), and MUST NOT be parsed.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FacadeError {
    /// The stable, machine-readable code.
    pub code: ErrorCode,
    /// A human, redacted, non-normative message. Never parsed or matched.
    pub message: String,
}

impl FacadeError {
    /// Build an error from a code and a redacted message.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The locked-vault error (SPEC §11.5).
    #[must_use]
    pub fn locked() -> Self {
        Self::new(ErrorCode::VaultLocked, "the vault is locked")
    }

    /// An internal-invariant error, surfaced instead of a panic (SPEC §10 rule 8).
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    /// See [`ErrorCode::retryable`].
    #[must_use]
    pub fn retryable(&self) -> bool {
        self.code.retryable()
    }
}
impl fmt::Display for FacadeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for FacadeError {}

/// A facade result: `Ok(T)` or the one flat [`FacadeError`].
pub type Result<T> = core::result::Result<T, FacadeError>;
use misty_otp::OtpError;

/// The `misty_otp::OtpError` mapping (SPEC §11.3.6).
pub(crate) fn code_for_otp(err: &OtpError) -> ErrorCode {
    match err {
        OtpError::InvalidDigits(_) | OtpError::InvalidPeriod(_) | OtpError::MissingPin(_) => {
            ErrorCode::OtpInvalidParam
        }
        OtpError::EmptySecret | OtpError::InvalidHexSecret | OtpError::SecretTooLong { .. } => {
            ErrorCode::OtpInvalidSecret
        }
        OtpError::Base32(_) => ErrorCode::OtpInvalidSecret,
        OtpError::Uri(_) => ErrorCode::UriMalformed,
        OtpError::TimeOutOfRange(_) | OtpError::Internal(_) => ErrorCode::OtpGenerationFailed,
        OtpError::CounterExhausted(_) => ErrorCode::ResourceExhausted,
    }
}

impl From<OtpError> for FacadeError {
    fn from(err: OtpError) -> Self {
        Self::new(code_for_otp(&err), err.to_string())
    }
}
use misty_crypto::Error as CryptoError;

/// The `misty_crypto::Error` mapping (SPEC §11.3.6).
pub(crate) fn code_for_crypto(err: &CryptoError) -> ErrorCode {
    match err {
        CryptoError::Random { .. } | CryptoError::AeadEncrypt => ErrorCode::Internal,
        CryptoError::Truncated { .. }
        | CryptoError::BadEnvelopeMagic
        | CryptoError::BadBackupMagic
        | CryptoError::UnknownEnvelopeKind { .. }
        | CryptoError::ReservedNotZero { .. }
        | CryptoError::MalformedBody { .. }
        | CryptoError::BadPaddingLength { .. }
        | CryptoError::BadPadding { .. }
        | CryptoError::PayloadTooLarge { .. }
        | CryptoError::Cbor { .. }
        | CryptoError::Inflate { .. }
        | CryptoError::InflateLimit { .. }
        | CryptoError::RecoveryBlobMalformed => ErrorCode::CorruptData,
        CryptoError::UnsupportedFormatVersion { .. } => ErrorCode::VersionUnsupported,
        CryptoError::EpochMismatch { .. } => ErrorCode::EpochMismatch,
        CryptoError::UnknownSigner { .. }
        | CryptoError::RosterUnsigned
        | CryptoError::RosterSignerNotInRoster { .. }
        | CryptoError::EnrollmentApproverUnknown => ErrorCode::UntrustedSigner,
        CryptoError::SignatureInvalid
        | CryptoError::RosterSignatureInvalid
        | CryptoError::EnrollmentSignatureInvalid
        | CryptoError::BadVerifyingKey
        | CryptoError::NonContributoryKeyExchange => ErrorCode::SignatureInvalid,
        CryptoError::ItemKeyUnwrapFailed
        | CryptoError::PayloadDecryptFailed
        | CryptoError::BackupDecryptFailed
        | CryptoError::RecoveryUnwrapFailed
        | CryptoError::EnrollmentUnsealFailed => ErrorCode::DecryptFailed,
        CryptoError::UnknownKdfId { .. }
        | CryptoError::KdfParamsRejected { .. }
        | CryptoError::Kdf { .. } => ErrorCode::KdfRejected,
        CryptoError::WrongWordCount { .. }
        | CryptoError::UnknownWord { .. }
        | CryptoError::WordChecksumMismatch
        | CryptoError::BadCompactLength { .. }
        | CryptoError::BadCompactChar { .. }
        | CryptoError::BadCompactPadding
        | CryptoError::Crc32Mismatch
        | CryptoError::BadQrPrefix => ErrorCode::RecoveryInputInvalid,
        CryptoError::DuplicateDevice { .. } => ErrorCode::AlreadyExists,
        CryptoError::DeviceNotInRoster { .. } => ErrorCode::DeviceRevoked,
        CryptoError::ConfirmationCodeMismatch => ErrorCode::ConfirmationCodeMismatch,
        CryptoError::EnrollIdMismatch => ErrorCode::EnrollIdMismatch,
        CryptoError::StringTooLong { .. } => ErrorCode::CorruptData,
        _ => ErrorCode::Internal,
    }
}

impl From<CryptoError> for FacadeError {
    fn from(err: CryptoError) -> Self {
        Self::new(code_for_crypto(&err), err.to_string())
    }
}
use misty_vault::VaultError;

/// Which path a `VaultError` arose on, for the §11.3.6 context rule.
#[derive(Clone, Copy)]
pub(crate) enum Ctx {
    /// A user write (add/update/import intake): ambiguous variants are validation.
    Write,
    /// A decode/merge/open path: ambiguous variants are tamper or damage.
    Decode,
}

/// The `misty_vault::VaultError` mapping (SPEC §11.3.6).
pub(crate) fn code_for_vault(err: &VaultError, ctx: Ctx) -> ErrorCode {
    match err {
        VaultError::Crypto(e) => code_for_crypto(e),
        VaultError::Otp(e) => code_for_otp(e),
        VaultError::NoSuchItem { .. } | VaultError::NoSuchGroup { .. } => ErrorCode::NotFound,
        VaultError::ItemExists { .. } => ErrorCode::AlreadyExists,
        VaultError::DuplicateAccount { .. } => ErrorCode::DuplicateAccount,
        VaultError::AmbiguousAccount { .. } => ErrorCode::AmbiguousAccount,
        VaultError::EmptyField { .. } => ErrorCode::InvalidField,
        VaultError::DisallowedCharacter { .. }
        | VaultError::StringTooLong { .. }
        | VaultError::TooManyElements { .. } => match ctx {
            Ctx::Write => ErrorCode::InvalidField,
            Ctx::Decode => ErrorCode::CorruptData,
        },
        VaultError::Cbor { .. }
        | VaultError::PayloadTooLarge { .. }
        | VaultError::UnknownEnumValue { .. }
        | VaultError::HlcOutOfRange { .. }
        | VaultError::DuplicateKey { .. }
        | VaultError::CorruptRecord { .. } => ErrorCode::CorruptData,
        VaultError::UnsupportedFormatVersion { .. } | VaultError::SchemaTooNew { .. } => {
            ErrorCode::VersionUnsupported
        }
        VaultError::IdMismatch { .. }
        | VaultError::KindMismatch { .. }
        | VaultError::SecretIsImmutable { .. }
        | VaultError::MergeDidNotSettle { .. }
        | VaultError::ClockCollision { .. } => ErrorCode::MergeFailed,
        VaultError::ClockExhausted | VaultError::EpochExhausted => ErrorCode::ResourceExhausted,
        VaultError::DeviceNotInRoster { .. } => ErrorCode::DeviceRevoked,
        VaultError::Storage { .. } => ErrorCode::StorageFailed,
        VaultError::NoTransaction => ErrorCode::Internal,
        _ => ErrorCode::Internal,
    }
}

impl From<VaultError> for FacadeError {
    fn from(err: VaultError) -> Self {
        // A direct facade call is the user write/read path; the sync decode path maps
        // through `code_for_vault(.., Ctx::Decode)` explicitly (SPEC §11.3.6).
        Self::new(code_for_vault(&err, Ctx::Write), err.to_string())
    }
}
use misty_sync::{RosterRejection, SyncError, TransportKind};

/// The `misty_sync::SyncError` mapping (SPEC §11.3.6).
pub(crate) fn code_for_sync(err: &SyncError) -> ErrorCode {
    match err {
        SyncError::Crypto(e) => code_for_crypto(e),
        SyncError::Vault { source, .. } => code_for_vault(source.get(), Ctx::Decode),
        SyncError::Transport { kind, .. } => match kind {
            TransportKind::Tls | TransportKind::PinMismatch => ErrorCode::TlsError,
            _ => ErrorCode::Network,
        },
        SyncError::Server { status, .. } => {
            if (500..=599).contains(status) {
                ErrorCode::ServerError
            } else {
                // 4xx and any other well-formed-but-unexpected status (SPEC §11.3.6).
                ErrorCode::ProtocolViolation
            }
        }
        SyncError::AuthRefused { .. } => ErrorCode::AuthFailed,
        SyncError::Malformed { .. }
        | SyncError::ResponseTooLarge { .. }
        | SyncError::EnvelopeTooLarge { .. }
        | SyncError::SeqRollback { .. }
        | SyncError::FeedOutOfOrder { .. }
        | SyncError::SeqOutOfRange { .. }
        | SyncError::FeedTooLong { .. }
        | SyncError::ConflictWithoutEnvelope
        | SyncError::UnusableVersionToken => ErrorCode::ProtocolViolation,
        SyncError::UnknownSigner { .. } => ErrorCode::UntrustedSigner,
        SyncError::RosterRejected { reason } => match reason {
            RosterRejection::Unsigned | RosterRejection::SignerNotTrusted => {
                ErrorCode::UntrustedSigner
            }
            RosterRejection::SignatureInvalid => ErrorCode::SignatureInvalid,
            _ => ErrorCode::CorruptData,
        },
        SyncError::Revoked { .. } => ErrorCode::DeviceRevoked,
        SyncError::TimeSignatureInvalid
        | SyncError::TimeNonceMismatch
        | SyncError::TimeWentBackwards { .. } => ErrorCode::TimeUntrusted,
        SyncError::ConflictLoop { .. } => ErrorCode::MergeFailed,
        SyncError::QuotaExhausted { .. } => ErrorCode::QuotaExhausted,
        SyncError::StateStore { .. } => ErrorCode::StorageFailed,
        SyncError::StateTooNew { .. } => ErrorCode::VersionUnsupported,
        SyncError::BadServerUrl | SyncError::BadPin { .. } => ErrorCode::ConfigInvalid,
        _ => ErrorCode::Internal,
    }
}

impl From<SyncError> for FacadeError {
    fn from(err: SyncError) -> Self {
        Self::new(code_for_sync(&err), err.to_string())
    }
}
