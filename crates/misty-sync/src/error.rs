// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed errors.
//!
//! Four rules hold for every variant, and there is a test for each:
//!
//! 1. **An error names the operation and the failure, never the value.** No
//!    secret byte, no envelope byte, no `item_id`, no server-supplied text. A
//!    sync error is logged; a vault's contents are not (SPEC §9).
//! 2. **Nothing a server sent is echoed back.** A status code and a length are
//!    facts about the exchange; a response body is attacker-controlled text, and
//!    interpolating it into a message hands the attacker the log file.
//! 3. **Distinguishable failures.** "the server is offline" and "the server
//!    lied" need different UI, so they are different variants rather than one
//!    variant with different strings.
//! 4. **No panics on this path.** Everything reachable from a response returns
//!    one of these.
//!
//! A [`DeviceId`] *is* allowed in a message. It appears in cleartext in every
//! envelope header (SPEC §2.4), so the server already has it, and "which device
//! signed this" is the single most useful thing to know when a roster check
//! fails.

use core::fmt;

use misty_crypto::DeviceId;
use misty_vault::VaultError;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, SyncError>;

/// Why a transport could not complete a request.
///
/// A classification rather than the underlying error's text: an `io::Error` from
/// a TLS stack can contain a hostname, a path, or a chunk of a peer's response,
/// and none of that belongs in a log line this crate produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportKind {
    /// The name did not resolve, or the connection was refused or reset.
    Connect,
    /// The TLS handshake failed for a reason other than the pin.
    Tls,
    /// The server's certificate did not match any configured pin
    /// (SPEC §1, `A2`).
    PinMismatch,
    /// The request or response did not complete in time.
    Timeout,
    /// The response was not valid HTTP, or the body ended early.
    Protocol,
    /// The host environment refused the request: no `fetch` available, a
    /// browser CORS or mixed-content refusal, a runtime shutting down.
    Environment,
}

/// Why a fetched roster was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RosterRejection {
    /// The roster carried no signature.
    Unsigned,
    /// The signature did not verify, or the signer is not in the roster it
    /// signed.
    SignatureInvalid,
    /// The signer is not a device the roster we already trust vouches for, so
    /// this roster does not chain to anything (SPEC §6.2, threat model `A6`).
    SignerNotTrusted,
    /// The roster arrived under an `item_id` that is not the roster's address.
    WrongAddress,
    /// The envelope did not declare `kind = DeviceRoster`.
    WrongKind,
}

/// Everything that can go wrong in `misty-sync`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// A cryptographic check failed: a bad signature, an unknown signer, a
    /// tampered envelope, a wrong epoch key. No variant of
    /// [`misty_crypto::Error`] carries an `item_id` or a secret, so this one is
    /// transparent.
    #[error(transparent)]
    Crypto(#[from] misty_crypto::Error),

    /// The vault refused a change. The underlying [`VaultError`] is reachable
    /// through [`VaultFailure::get`] for a caller that wants it, and is
    /// deliberately absent from this error's `Display` and `Debug`, because
    /// `misty-vault`'s own messages name item ids.
    #[error("{operation}: the vault rejected it")]
    Vault {
        /// Which operation was under way.
        operation: &'static str,
        /// The vault's own error, not rendered.
        #[source]
        source: VaultFailure,
    },

    /// The transport could not complete the request.
    #[error("{operation}: transport failed ({kind:?})")]
    Transport {
        /// Which operation was under way.
        operation: &'static str,
        /// What kind of failure it was.
        kind: TransportKind,
    },

    /// The server answered with a status this client does not accept. The body
    /// is deliberately not read: a status code is a fact, a body is a payload.
    #[error("{operation}: the server answered HTTP {status}")]
    Server {
        /// Which operation was under way.
        operation: &'static str,
        /// The HTTP status.
        status: u16,
    },

    /// The server's own credentials were rejected, or it rejected ours and a
    /// fresh challenge did not help.
    #[error("{operation}: authentication was refused")]
    AuthRefused {
        /// Which operation was under way.
        operation: &'static str,
    },

    /// A response was not the shape the protocol requires.
    #[error("{operation}: field {field} is missing or malformed")]
    Malformed {
        /// Which operation was under way.
        operation: &'static str,
        /// Which field, by name. Never its value.
        field: &'static str,
    },

    /// A response was longer than this client will read.
    #[error("{operation}: response exceeds the {max} byte limit")]
    ResponseTooLarge {
        /// Which operation was under way.
        operation: &'static str,
        /// The cap, from [`crate::limits`].
        max: usize,
    },

    /// An envelope offered by the server was longer than this client will read.
    #[error("an envelope of {len} bytes exceeds the {max} byte limit")]
    EnvelopeTooLarge {
        /// Length offered.
        len: usize,
        /// The cap, from [`crate::limits`].
        max: usize,
    },

    /// The change feed offered a `seq` at or below where the client already is.
    ///
    /// A monotonic `seq` is the only ordering guarantee SPEC §6.1 gives, and a
    /// server that walks it backwards is trying to make the client re-apply an
    /// old state or skip a new one.
    #[error("the change feed went backwards: offered seq {offered} at cursor {cursor}")]
    SeqRollback {
        /// What the server offered.
        offered: i64,
        /// Where the client already was.
        cursor: i64,
    },

    /// Changes within one page were not in ascending `seq` order.
    #[error("the change feed is out of order: seq {offered} follows {previous}")]
    FeedOutOfOrder {
        /// The offending entry.
        offered: i64,
        /// The entry before it.
        previous: i64,
    },

    /// A `seq` was negative or implausibly large.
    #[error("seq {offered} is outside the plausible range 0..{max}")]
    SeqOutOfRange {
        /// What the server offered.
        offered: i64,
        /// The exclusive bound, [`crate::limits::MAX_SEQ`].
        max: i64,
    },

    /// The server claimed more pages than this client will walk.
    #[error("the change feed did not end within {max} pages")]
    FeedTooLong {
        /// The bound, [`crate::limits::MAX_PAGES_PER_SYNC`].
        max: usize,
    },

    /// An envelope was signed by a device the roster does not list, so it was
    /// refused before any decryption was attempted (SPEC §6.2, `A6`).
    #[error("an envelope is signed by device {signer}, which is not in the roster")]
    UnknownSigner {
        /// The signer named in the envelope header.
        signer: DeviceId,
    },

    /// A roster fetched from the server was refused.
    #[error("the fetched roster was refused: {reason:?}")]
    RosterRejected {
        /// Why.
        reason: RosterRejection,
    },

    /// A signed roster no longer lists this device. This is what a legitimate
    /// revocation looks like from the revoked device's side (SPEC §6.4), and it
    /// is honoured because it is *signed* — a server cannot forge one.
    #[error("device {device} has been revoked by a signed roster")]
    Revoked {
        /// This device.
        device: DeviceId,
    },

    /// A `/v1/time` response did not verify against the pinned server key
    /// (SPEC §6.5).
    #[error("the signed time response did not verify")]
    TimeSignatureInvalid,

    /// A `/v1/time` response did not echo the nonce this client sent, so it is
    /// a replay of an earlier exchange rather than an answer to this one.
    #[error("the signed time response answers a different request")]
    TimeNonceMismatch,

    /// A `/v1/time` response moved server time backwards past the tolerance.
    ///
    /// Defence in depth behind [`SyncError::TimeNonceMismatch`]: even a server
    /// that cooperates with the nonce protocol must not be able to walk a
    /// client's effective clock backwards into a window where consumed codes
    /// validate again.
    #[error("server time went backwards: {offered} follows {previous}")]
    TimeWentBackwards {
        /// The new reading.
        offered: i64,
        /// The reading before it.
        previous: i64,
    },

    /// A `409` loop did not converge within [`crate::limits::MAX_CONFLICT_RETRIES`].
    #[error("a conflicting write did not settle within {max} attempts")]
    ConflictLoop {
        /// The bound.
        max: usize,
    },

    /// A `409` carried no current envelope, so there is nothing to merge with.
    /// SPEC §6.1 requires one.
    #[error("the server reported a conflict without the current envelope")]
    ConflictWithoutEnvelope,

    /// A server-supplied `version` token could not be used as an HTTP header
    /// value.
    ///
    /// A token containing CR, LF or a NUL would be header injection on the next
    /// request, so it is rejected where it arrives rather than where it is used.
    #[error("the server's version token is not a usable header value")]
    UnusableVersionToken,

    /// The vault is full: SPEC §6.1's `507`, not `413`.
    ///
    /// Distinct from a retriable failure on purpose. `413` tells a client to retry
    /// with a smaller request, which is the wrong advice when the request was the
    /// right size and the vault has no room; and backing off in a loop would never
    /// tell the user the one thing they can act on.
    #[error("{operation}: the vault is full")]
    QuotaExhausted {
        /// Which operation was under way.
        operation: &'static str,
    },

    /// The durable sync state could not be read or written.
    #[error("{operation}: the sync state store failed")]
    StateStore {
        /// `"load"` or `"save"`.
        operation: &'static str,
    },

    /// A stored sync state came from a newer build.
    #[error("sync state format {found} is newer than the {supported} this build implements")]
    StateTooNew {
        /// Version found.
        found: u8,
        /// Version implemented.
        supported: u8,
    },

    /// A `misty-sync` operation was given a server URL it cannot use.
    #[error("the server URL is not a usable https origin")]
    BadServerUrl,

    /// A certificate pin was configured that this build cannot represent.
    #[error("a certificate pin must be {expected} bytes of SHA-256, got {found}")]
    BadPin {
        /// Required length.
        expected: usize,
        /// Length supplied.
        found: usize,
    },
}

impl SyncError {
    /// Wraps a [`VaultError`] without letting its message escape.
    pub(crate) fn vault(operation: &'static str, source: VaultError) -> Self {
        Self::Vault {
            operation,
            source: VaultFailure(Box::new(source)),
        }
    }
}

/// A `misty-vault` failure, held so `Error::source` can chain without this
/// crate's `Debug` or `Display` reproducing what it says.
///
/// `misty-vault`'s errors name item ids — reasonably, since an id is cleartext
/// on the wire — but this crate promises that nothing *it* formats does. The
/// wrapper is how both hold at once: [`get`](Self::get) is an explicit,
/// grep-able opt-in.
pub struct VaultFailure(Box<VaultError>);

impl VaultFailure {
    /// The underlying error. Formatting it may name an `item_id`.
    #[must_use]
    pub fn get(&self) -> &VaultError {
        &self.0
    }

    /// Takes the underlying error.
    #[must_use]
    pub fn into_inner(self) -> VaultError {
        *self.0
    }
}

impl fmt::Debug for VaultFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultFailure([redacted])")
    }
}

impl fmt::Display for VaultFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the vault rejected it")
    }
}

impl core::error::Error for VaultFailure {}
