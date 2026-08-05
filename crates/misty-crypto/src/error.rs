// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed errors.
//!
//! Two rules hold for every variant:
//!
//! 1. **No secret material.** Not a key byte, not a recovery word, not a
//!    passphrase. Errors are logged; secrets are not. A recovery-word error
//!    carries the *index* of the bad word, never the word.
//! 2. **Distinguishable failures.** Callers (and the negative test suite)
//!    must be able to tell "not a Misty file" from "wrong passphrase" from
//!    "unknown signer" without string matching.

use crate::types::DeviceId;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong in `misty-crypto`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The OS CSPRNG failed. Misty never falls back to a userspace PRNG for
    /// key material, so this is fatal to the operation.
    ///
    /// The raw `getrandom` code is carried rather than the error type itself,
    /// to keep a dependency out of this crate's public API.
    #[error("the operating system CSPRNG failed (getrandom code {code})")]
    Random {
        /// `getrandom`'s error code, or 0 if it reported none.
        code: u32,
    },

    /// A buffer was too short for the structure being parsed.
    #[error("{context}: input is {got} bytes, need at least {needed}")]
    Truncated {
        /// What was being parsed.
        context: &'static str,
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        got: usize,
    },

    /// The first four bytes are not `MSTY`.
    #[error("not a Misty envelope: bad magic")]
    BadEnvelopeMagic,

    /// The first eight bytes are not `MISTYBAK`.
    #[error("not a Misty backup: bad magic")]
    BadBackupMagic,

    /// A `format_version` this build does not implement. Forward compatibility
    /// is deliberately *not* attempted: a newer writer may have changed the
    /// meaning of the bytes that follow.
    #[error("{context}: unsupported format_version {found}, this build implements {supported}")]
    UnsupportedFormatVersion {
        /// What was being parsed.
        context: &'static str,
        /// The version found in the header.
        found: u8,
        /// The version this build implements.
        supported: u8,
    },
    /// The `kind` byte is not one of the five defined envelope kinds.
    #[error("unknown envelope kind {found}")]
    UnknownEnvelopeKind {
        /// The byte found at offset 5.
        found: u8,
    },

    /// Reserved header bytes were not zero. A non-zero reserved field means
    /// either corruption or a newer format smuggling data past us.
    #[error("{context}: reserved bytes are not zero")]
    ReservedNotZero {
        /// What was being parsed.
        context: &'static str,
    },

    /// The body length is not consistent with the format.
    #[error("malformed envelope body: {detail}")]
    MalformedBody {
        /// Which invariant failed.
        detail: &'static str,
    },

    /// The envelope belongs to a different epoch than the supplied epoch key.
    #[error("envelope is from epoch {found} but the supplied epoch key is for epoch {expected}")]
    EpochMismatch {
        /// Epoch of the supplied [`EpochKey`](crate::keys::EpochKey).
        expected: u32,
        /// Epoch named in the envelope header.
        found: u32,
    },

    /// The signing device is not in the roster. This is the `A6` mitigation:
    /// it fires *before* any decryption is attempted.
    #[error("envelope is signed by device {signer}, which is not in the roster")]
    UnknownSigner {
        /// The unrecognised signer.
        signer: DeviceId,
    },

    /// The Ed25519 signature over the envelope did not verify.
    #[error("envelope signature is invalid")]
    SignatureInvalid,

    /// The wrapped item key did not authenticate: wrong epoch key, wrong
    /// `item_id` (an envelope relocated to another id), or tampering.
    #[error("wrapped item key did not authenticate")]
    ItemKeyUnwrapFailed,

    /// The payload did not authenticate under the unwrapped item key.
    #[error("envelope payload did not authenticate")]
    PayloadDecryptFailed,
    /// The padding length prefix does not agree with the buffer it prefixes.
    #[error("bad padding: declared payload length {declared} does not fit in {available} bytes")]
    BadPaddingLength {
        /// The `LE32` length prefix, as read.
        declared: u32,
        /// Bytes actually available after the prefix.
        available: usize,
    },

    /// The padded buffer violates another padding invariant (size not a
    /// multiple of the block, non-minimal padding, or non-zero filler).
    #[error("bad padding: {detail}")]
    BadPadding {
        /// Which invariant failed.
        detail: &'static str,
    },

    /// A payload exceeded the crate's hard size limit.
    #[error("payload of {len} bytes exceeds the {max} byte limit")]
    PayloadTooLarge {
        /// Length offered.
        len: usize,
        /// Hard limit.
        max: usize,
    },

    /// A backup header named a KDF this build does not implement.
    #[error("unknown kdf_id {found}")]
    UnknownKdfId {
        /// The byte found at offset 9.
        found: u8,
    },

    /// Argon2 parameters outside the range this build will run. A header
    /// claiming 64 GiB of memory is a denial-of-service vector, not a
    /// configuration.
    #[error("rejected Argon2id parameters (m={memory_kib} KiB, t={iterations}, p={parallelism}): {detail}")]
    KdfParamsRejected {
        /// Memory cost, in KiB, as claimed by the header.
        memory_kib: u32,
        /// Iteration (time) cost as claimed by the header.
        iterations: u32,
        /// Parallelism (lanes) as claimed by the header.
        parallelism: u32,
        /// Which bound was violated.
        detail: &'static str,
    },

    /// Key derivation itself failed.
    #[error("key derivation failed: {detail}")]
    Kdf {
        /// Underlying reason, rendered by the KDF implementation.
        detail: String,
    },
    /// AEAD encryption failed. Unreachable for the sizes this crate uses; kept
    /// so the encrypt path has no `unwrap`.
    #[error("AEAD encryption failed")]
    AeadEncrypt,

    /// CBOR serialisation or deserialisation failed.
    #[error("CBOR {operation} failed: {detail}")]
    Cbor {
        /// `"encode"` or `"decode"`.
        operation: &'static str,
        /// Underlying reason.
        detail: String,
    },

    /// DEFLATE decompression failed.
    #[error("DEFLATE decompression failed: {detail}")]
    Inflate {
        /// Underlying reason.
        detail: &'static str,
    },

    /// Decompression would exceed the crate's limit — a compression bomb.
    #[error("decompressed payload exceeds the {max} byte limit")]
    InflateLimit {
        /// Hard limit.
        max: usize,
    },

    /// The backup did not authenticate: wrong passphrase, or tampering.
    /// Indistinguishable by design.
    #[error("backup did not authenticate (wrong passphrase or tampered file)")]
    BackupDecryptFailed,

    /// A recovery kit did not have exactly 24 words.
    #[error("recovery kit must be {expected} words, got {found}")]
    WrongWordCount {
        /// Words required.
        expected: usize,
        /// Words supplied.
        found: usize,
    },

    /// A word is not in the BIP-39 English wordlist. Carries the position
    /// only — never the word, which is secret material.
    #[error("word {index} is not in the BIP-39 English wordlist")]
    UnknownWord {
        /// Zero-based position of the offending word.
        index: usize,
    },

    /// All 24 words are real words but the 8-bit checksum does not match, so
    /// at least one is transcribed wrongly.
    #[error("recovery words failed the checksum")]
    WordChecksumMismatch,
    /// The compact (Crockford Base32) code has the wrong length.
    #[error("compact recovery code must be {expected} characters, got {found}")]
    BadCompactLength {
        /// Characters required, ignoring grouping separators.
        expected: usize,
        /// Characters supplied.
        found: usize,
    },

    /// The compact code contains a character outside the Crockford alphabet.
    #[error("compact recovery code has an invalid character at position {index}")]
    BadCompactChar {
        /// Zero-based position, counted after separators are stripped.
        index: usize,
    },

    /// The final Base32 character carries non-zero bits beyond the 288 that
    /// encode the key, so the string was not produced by this encoder.
    #[error("compact recovery code has non-zero trailing bits")]
    BadCompactPadding,

    /// The CRC32 trailer of a compact code does not match the key bytes.
    #[error("compact recovery code failed its CRC32 check")]
    Crc32Mismatch,

    /// A QR payload did not start with `misty-recovery:v1:`.
    #[error("not a Misty recovery QR payload")]
    BadQrPrefix,

    /// The stored `recovery_blob` is not the expected length.
    #[error("recovery blob is malformed")]
    RecoveryBlobMalformed,

    /// The `recovery_blob` did not authenticate under the supplied recovery
    /// key: wrong kit, or a tampered blob.
    #[error("recovery blob did not authenticate")]
    RecoveryUnwrapFailed,

    /// The roster carries no signature, so it cannot be trusted at all.
    #[error("roster is not signed")]
    RosterUnsigned,

    /// The roster is signed by a device that is not itself in the roster. A
    /// roster must be self-contained: the signer has to be a member.
    #[error("roster is signed by device {signer}, which is not itself in the roster")]
    RosterSignerNotInRoster {
        /// The claimed signer.
        signer: DeviceId,
    },

    /// The roster signature did not verify.
    #[error("roster signature is invalid")]
    RosterSignatureInvalid,
    /// Two records in one roster claim the same `device_id`.
    #[error("device {device} is already in the roster")]
    DuplicateDevice {
        /// The duplicated id.
        device: DeviceId,
    },

    /// A device that had to be in a roster was not.
    #[error("device {device} is not in the roster")]
    DeviceNotInRoster {
        /// The missing id.
        device: DeviceId,
    },

    /// A 32-byte value is not a valid Ed25519 public key.
    #[error("malformed Ed25519 public key")]
    BadVerifyingKey,

    /// An X25519 agreement produced the all-zero shared secret, which means the
    /// peer offered a small-order public key.
    #[error("X25519 key agreement was non-contributory")]
    NonContributoryKeyExchange,

    /// The sealed enrollment payload did not authenticate under the
    /// X25519-derived key.
    #[error("enrollment payload did not authenticate")]
    EnrollmentUnsealFailed,

    /// The 6-digit confirmation code the user compared out of band does not
    /// match the request being approved.
    #[error("enrollment confirmation code does not match")]
    ConfirmationCodeMismatch,

    /// The sealed response is for a different enrollment than the request.
    #[error("enroll_id in the sealed response does not match the request")]
    EnrollIdMismatch,

    /// The sealed enrollment names an approver that is absent from the roster
    /// it delivers, so the grant cannot be chained to a trusted device.
    #[error("enrollment approver is not in the delivered roster")]
    EnrollmentApproverUnknown,

    /// The approver's signature over the sealed enrollment did not verify.
    #[error("enrollment signature is invalid")]
    EnrollmentSignatureInvalid,

    /// Bounds exist so a hostile roster or enrollment blob cannot force
    /// unbounded allocation.
    #[error("field {field} is longer than {max} bytes")]
    StringTooLong {
        /// Which field.
        field: &'static str,
        /// Hard limit, in bytes of UTF-8.
        max: usize,
    },
}

impl From<getrandom::Error> for Error {
    fn from(error: getrandom::Error) -> Self {
        Self::Random {
            code: error.code().get(),
        }
    }
}
