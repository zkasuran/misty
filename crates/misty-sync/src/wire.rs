// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The JSON wire format for SPEC §6.1, and the strict decoders for it.
//!
//! SPEC §6.1.1 is normative for the encoding and this module implements it, with
//! the four documented exceptions in [`crate::encoding`] where the server in this
//! tree emits something else and interoperation would otherwise be impossible.
//!
//! | Kind of value | Encoding |
//! |---|---|
//! | `vault_id`, `device_id`, `item_id`, `enroll_id` | lowercase hex |
//! | nonces, signatures, public keys | lowercase hex per §6.1.1; see [`crate::encoding`] |
//! | envelope, sealed blob | standard base64 with padding |
//! | `seq`, `unix_ms`, `expires_at` | JSON number, integer-valued |
//! | `version` | an opaque token, never parsed |
//!
//! # Unknown fields are ignored, and that is §6.1.1's rule rather than this
//! crate's preference
//!
//! §6.1.1: "A client MUST **ignore unknown response fields** so the server can add
//! one without a flag day. This is the opposite of the at-rest rule … and the
//! asymmetry is deliberate: at rest, an unexpected field means corruption or
//! attack, while on the wire it means a newer peer."
//!
//! What *is* strict: every field this client acts on is bounded before it is
//! decoded, every id is exactly its width, and every `seq` is range-checked. The
//! decoders here are the hostile-input boundary for the whole crate
//! (`fuzz/fuzz_targets/change_feed.rs` is pointed at [`decode_change_feed`]).

use misty_crypto::{DeviceId, EnrollId, ItemId, SignatureBytes, VaultId};
use serde::{Deserialize, Serialize};

use crate::encoding;
use crate::error::{Result, SyncError};
use crate::limits;

/// The server's opaque optimistic-concurrency token (SPEC §6.1's `version`).
///
/// Opaque means opaque: this client never parses it, compares it for ordering, or
/// assumes it is a number — even though the server in this tree happens to emit
/// one. It does check that it can be used as an HTTP header value, because a token
/// containing CR or LF would be request smuggling on the next `If-Match`, and
/// §6.1.1 requires rejecting CR, LF and a quote.
///
/// # It arrives as a JSON string *or* a JSON number
///
/// §6.1.1 calls `version` "an opaque printable-ASCII token"; `misty-server` emits
/// a JSON number (`routes/items.rs:55`). Both are accepted, a number by taking its
/// decimal digits verbatim, which keeps "never parse it" true in the only sense
/// that matters: nothing here treats it as ordered, incrementable, or comparable to
/// any other version.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ServerVersion(String);

impl ServerVersion {
    /// Validates and wraps a token.
    ///
    /// A single pair of surrounding double quotes is stripped, because that is how
    /// an `ETag` arrives and it is the framing rather than the token.
    ///
    /// # Errors
    ///
    /// [`SyncError::UnusableVersionToken`] if it is empty, longer than
    /// [`MAX_VERSION_LEN`](crate::limits::MAX_VERSION_LEN), or contains anything
    /// outside printable ASCII except `"`.
    pub fn parse(token: &str) -> Result<Self> {
        let token = token
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or(token);
        let usable = !token.is_empty()
            && token.len() <= limits::MAX_VERSION_LEN
            && token
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'"');
        if !usable {
            return Err(SyncError::UnusableVersionToken);
        }
        Ok(Self(token.to_owned()))
    }

    /// The token as it arrived.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The token as a strong `If-Match` value: quoted, as SPEC §6.1 writes it and
    /// as an `ETag` requires.
    #[must_use]
    pub fn to_if_match(&self) -> String {
        format!("\"{}\"", self.0)
    }

    /// Whether the server means "there is no such row" by this token.
    ///
    /// `misty-server` answers a `409` on an absent row with `version: 0`
    /// (`store/mod.rs:120`). A client that retried with `If-Match: "0"` would be
    /// told the same thing forever; the right move is to retry as a create.
    #[must_use]
    pub fn means_absent(&self) -> bool {
        self.0 == "0"
    }

    /// The token as the bytes `misty-vault` stores in its `version` column.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone().into_bytes()
    }

    /// Reads a token back out of `misty-vault`'s `version` column.
    ///
    /// # Errors
    ///
    /// As [`parse`](Self::parse), plus [`SyncError::UnusableVersionToken`] if the
    /// stored bytes are not UTF-8.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let text = core::str::from_utf8(bytes).map_err(|_| SyncError::UnusableVersionToken)?;
        Self::parse(text)
    }
}

/// One entry of SPEC §6.1's change feed, decoded and bounded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedChange {
    /// Storage key.
    pub item_id: ItemId,
    /// The server's sequence number for this change.
    pub seq: i64,
    /// The server's concurrency token, if it sent one.
    pub version: Option<ServerVersion>,
    /// The sealed envelope, exactly as it came off the wire, or `None` if the
    /// server has reclaimed the bytes.
    ///
    /// SPEC §6.1's feed does not mention that a row can outlive its envelope, but
    /// it has to: `version` must stay monotonic after a `DELETE` or a stale
    /// `If-Match` would win, so `misty-server` keeps the row and drops the bytes
    /// (`routes/items.rs:56`). A client that required an envelope here would
    /// refuse the whole page over a row it had itself asked to be deleted.
    pub envelope: Option<Vec<u8>>,
    /// SPEC §6.1's `deleted` flag.
    ///
    /// **Advisory only, and never acted on.** It is decoded so this type is
    /// honest about what the wire carries and so a test can set it and prove
    /// nothing happens. Real deletion is a signed tombstone inside the
    /// encrypted payload (SPEC §4); honouring a bare transport flag would hand a
    /// server that holds the database but no keys the one destructive power the
    /// design exists to deny it.
    pub deleted: bool,
}

/// A whole decoded change-feed page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeFeed {
    /// The changes, in ascending `seq`.
    pub changes: Vec<FeedChange>,
    /// Where the next request should resume.
    pub next_seq: i64,
    /// Whether the server claims more pages follow.
    pub has_more: bool,
}

/// What a `PUT` produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PutOutcome {
    /// `200`: the write landed.
    Applied {
        /// The sequence number the server assigned.
        seq: i64,
        /// The new concurrency token.
        version: ServerVersion,
    },
    /// `409`: the precondition did not hold, and here is what the server has.
    Conflict {
        /// The token to use on the retry, or `None` if the server signalled that
        /// there is no such row (see [`ServerVersion::means_absent`]).
        version: Option<ServerVersion>,
        /// The envelope the server currently holds, or `None` if the row is
        /// absent or its bytes have been reclaimed. There is nothing to merge in
        /// that case — only a version to retry with.
        envelope: Option<Vec<u8>>,
    },
}

/// A verified `/v1/time` reading (SPEC §6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedTime {
    /// The server's Unix milliseconds.
    pub unix_ms: i64,
}

/// What `GET /v1/quota` reports.
///
/// The limit field names are `misty-server`'s (`routes/meta.rs:79`). SPEC §6.1
/// writes `limits` without naming its contents, so those names are the only ones
/// specified anywhere and this follows them rather than inventing a second set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Quota {
    /// Stored envelope bytes.
    pub bytes_used: u64,
    /// Rows that still hold an envelope.
    pub item_count: u64,
    /// All rows, reclaimed ones included. This is what `max_items_per_vault`
    /// counts, and it is what a client should compare against.
    pub row_count: u64,
    /// Largest single envelope the server will accept.
    pub max_envelope_bytes: Option<u64>,
    /// Most rows one vault may hold.
    pub max_items_per_vault: Option<u64>,
    /// Most envelope bytes one vault may hold.
    pub max_vault_bytes: Option<u64>,
    /// Largest `limit` the change feed will honour.
    pub max_changes_limit: Option<u32>,
}

/// An authentication challenge (SPEC §6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The server's nonce, decoded. This is what gets signed.
    pub nonce: Vec<u8>,
    /// The nonce exactly as the server encoded it.
    ///
    /// Echoed back verbatim in the verify body rather than re-encoded, so that the
    /// server's own decoder reproduces the same bytes whatever alphabet it chose.
    /// A re-encode would be a second place for the two sides to disagree.
    pub encoded_nonce: String,
    /// When the server says it stops accepting the answer, in Unix ms.
    pub expires_at: i64,
}

/// A session, as `POST /v1/auth/verify` or `POST /v1/auth/refresh` returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tokens {
    /// The bearer token for subsequent requests.
    pub access_token: String,
    /// Single-use token for `POST /v1/auth/refresh`. Rotating: SPEC §6.1 says
    /// reuse revokes the family, so a client keeps exactly the newest one.
    pub refresh_token: Option<String>,
    /// Lifetime in seconds, if the server states one.
    pub expires_in: Option<u64>,
}

/// What `GET /v1/enroll/poll/{id}?want=…` returns (SPEC §6.1, §6.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnrollmentPoll {
    /// Whether the blob the caller asked for is present.
    pub ready: bool,
    /// The new device's ephemeral X25519 public key. Only for `?want=request`.
    pub x25519_pub: Option<[u8; 32]>,
    /// The new device's public enrollment request, CBOR. Only for
    /// `?want=request`.
    pub enroll_request: Option<Vec<u8>>,
    /// The approver's sealed grant, CBOR. Only for `?want=response`.
    pub sealed_response: Option<Vec<u8>>,
}

/// Which blob a poll is asking for (SPEC §6.1, `?want=`).
///
/// Retrieval is single-use per blob, so a caller that asked for the wrong one
/// consumes something it cannot use. Naming the role is what makes "delivered
/// once" unambiguous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    /// The approving device collecting what the new device published.
    Request,
    /// The new device waiting for the grant.
    Response,
}

impl Want {
    /// The query-string value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

// --- raw serde shapes -------------------------------------------------------
//
// Separated from the validated types above so that "what JSON says" and "what
// this client will act on" are two different types and the conversion between
// them is the only path. A field is `Option` here whenever the server may omit
// it; whether omission is acceptable is decided in the validating step, not by
// serde.

/// A `version` as it may arrive: §6.1.1's opaque token, or the JSON number
/// `misty-server` emits.
///
/// A dedicated type rather than `serde_json::Value` so the two accepted shapes are
/// named in one place and everything else in this module holds a
/// [`ServerVersion`].
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawVersion {
    Token(String),
    Number(i64),
}

impl RawVersion {
    fn into_token(self) -> Result<ServerVersion> {
        match self {
            Self::Token(text) => ServerVersion::parse(&text),
            Self::Number(value) => ServerVersion::parse(&value.to_string()),
        }
    }
}

#[derive(Deserialize)]
struct RawChangeFeed {
    changes: Option<Vec<RawChange>>,
    next_seq: Option<i64>,
    has_more: Option<bool>,
}

#[derive(Deserialize)]
struct RawChange {
    item_id: Option<String>,
    seq: Option<i64>,
    version: Option<RawVersion>,
    envelope: Option<String>,
    deleted: Option<bool>,
}

#[derive(Deserialize)]
struct RawPutApplied {
    seq: Option<i64>,
    version: Option<RawVersion>,
}

#[derive(Deserialize)]
struct RawConflict {
    version: Option<RawVersion>,
    envelope: Option<String>,
}

#[derive(Deserialize)]
struct RawChallenge {
    nonce: Option<String>,
    expires_at: Option<i64>,
}

#[derive(Deserialize)]
struct RawTokens {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct RawTime {
    unix_ms: Option<i64>,
    nonce: Option<String>,
    sig: Option<String>,
}

#[derive(Deserialize)]
struct RawQuota {
    bytes_used: Option<u64>,
    item_count: Option<u64>,
    row_count: Option<u64>,
    limits: Option<RawQuotaLimits>,
}

#[derive(Deserialize)]
struct RawQuotaLimits {
    max_envelope_bytes: Option<u64>,
    max_items_per_vault: Option<u64>,
    max_vault_bytes: Option<u64>,
    max_changes_limit: Option<u32>,
}

#[derive(Deserialize)]
struct RawEnrollmentPoll {
    ready: Option<bool>,
    x25519_pub: Option<String>,
    /// §6.1's name for the public request blob.
    enroll_request: Option<String>,
    /// `misty-server`'s name for the same blob (`routes/enroll.rs:59`). Accepted so
    /// one client works against a server on either side of the rename.
    sealed_request: Option<String>,
    sealed_response: Option<String>,
}

// --- request bodies ---------------------------------------------------------

#[derive(Serialize)]
struct ChallengeRequestBody<'a> {
    vault_id: &'a str,
    device_id: &'a str,
}

#[derive(Serialize)]
struct VerifyRequestBody<'a> {
    vault_id: &'a str,
    device_id: &'a str,
    /// The nonce being answered, echoed exactly as the server encoded it.
    ///
    /// Not in SPEC §6.1's body list; §6.1's own note explains why it has to be:
    /// "`verify` carries the `nonce` it is answering, so the server does not have
    /// to guess which outstanding challenge a signature belongs to."
    nonce: &'a str,
    sig: &'a str,
    /// The device's own public key.
    ///
    /// Required only when bootstrapping a vault's first device — for a device the
    /// server already knows, the stored key is used and a mismatching one is
    /// refused — but always sent, because a client cannot tell which case it is in
    /// and sending it never overwrites anything.
    ed25519_pub: &'a str,
}

#[derive(Serialize)]
struct RefreshRequestBody<'a> {
    refresh_token: &'a str,
}

#[derive(Serialize)]
struct AddDeviceBody<'a> {
    device_id: &'a str,
    ed25519_pub: &'a str,
}

#[derive(Serialize)]
struct EnvelopeBody<'a> {
    envelope: &'a str,
}

/// `POST /v1/enroll/begin`, with the field named as SPEC §6.1 names it.
#[derive(Serialize)]
struct EnrollBeginBody<'a> {
    enroll_id: &'a str,
    x25519_pub: &'a str,
    enroll_request: &'a str,
}

/// The same body under `misty-server`'s current field name
/// (`routes/enroll.rs:59`), which it enforces with `deny_unknown_fields`.
///
/// Sent only as a fallback after the canonical name has been refused, so a client
/// is correct per §6.1 first and compatible second. The fallback disappears when
/// the server adopts the spec's name.
#[derive(Serialize)]
struct LegacyEnrollBeginBody<'a> {
    enroll_id: &'a str,
    x25519_pub: &'a str,
    sealed_request: &'a str,
}

#[derive(Serialize)]
struct EnrollCompleteBody<'a> {
    enroll_id: &'a str,
    sealed_response: &'a str,
}

// --- decoding ---------------------------------------------------------------

/// Parses a JSON body, bounding its length first.
fn json<T: serde::de::DeserializeOwned>(operation: &'static str, body: &[u8]) -> Result<T> {
    if body.len() > limits::MAX_RESPONSE_BODY_LEN {
        return Err(SyncError::ResponseTooLarge {
            operation,
            max: limits::MAX_RESPONSE_BODY_LEN,
        });
    }
    // `from_slice` rather than `from_str`: a body is bytes, and a non-UTF-8 body
    // has to be a parse failure rather than a decoding decision taken earlier.
    serde_json::from_slice(body).map_err(|_| SyncError::Malformed {
        operation,
        field: "body",
    })
}

/// Unwraps a field the protocol requires.
fn required<T>(operation: &'static str, field: &'static str, value: Option<T>) -> Result<T> {
    value.ok_or(SyncError::Malformed { operation, field })
}

/// Decodes a fixed-width id field. Lowercase hex per SPEC §6.1.1, on which both
/// sides already agree.
fn hex_array<const N: usize>(
    operation: &'static str,
    field: &'static str,
    value: Option<String>,
) -> Result<[u8; N]> {
    let text = required(operation, field, value)?;
    let mut out = [0u8; N];
    // `hex::decode_to_slice` refuses any length but exactly `2 * N`, which is
    // the check we want: a 30-character "item id" is not a truncated id, it is a
    // different value.
    hex::decode_to_slice(text.as_bytes(), &mut out)
        .map_err(|_| SyncError::Malformed { operation, field })?;
    Ok(out)
}

/// Decodes a fixed-width nonce, signature or public key.
///
/// SPEC §6.1.1 puts these in hex and `misty-server` emits base64; both are
/// accepted, unambiguously, because the width is fixed. See [`crate::encoding`].
fn fixed_field<const N: usize>(
    operation: &'static str,
    field: &'static str,
    value: Option<String>,
) -> Result<[u8; N]> {
    let text = required(operation, field, value)?;
    encoding::fixed_from_wire::<N>(&text).ok_or(SyncError::Malformed { operation, field })
}

/// Decodes a base64 blob field, bounding the decoded length.
fn base64_field(
    operation: &'static str,
    field: &'static str,
    value: Option<String>,
    max: usize,
) -> Result<Vec<u8>> {
    let text = required(operation, field, value)?;
    // Reject on the encoded length before decoding: base64 expands by 4/3, so
    // this bounds the allocation without performing it.
    if text.len() / 4 * 3 > max {
        return Err(SyncError::ResponseTooLarge { operation, max });
    }
    let bytes = encoding::blob_from_wire(&text).ok_or(SyncError::Malformed { operation, field })?;
    if bytes.len() > max {
        return Err(SyncError::ResponseTooLarge { operation, max });
    }
    Ok(bytes)
}

/// Bounds a `seq` to the plausible range.
fn checked_seq(offered: i64) -> Result<i64> {
    if !(0..limits::MAX_SEQ).contains(&offered) {
        return Err(SyncError::SeqOutOfRange {
            offered,
            max: limits::MAX_SEQ,
        });
    }
    Ok(offered)
}

/// Decodes and validates one change-feed page.
///
/// This is the crate's widest hostile-input surface and the target of
/// `fuzz/fuzz_targets/change_feed.rs`. It enforces, in this order: the body
/// length cap, JSON well-formedness, the page's entry count, then per entry the
/// id length, the `seq` range, the `version` token shape and the envelope
/// length, and finally that `seq` ascends strictly within the page and that
/// `next_seq` is not below the last change it delivered.
///
/// It deliberately does **not** compare anything against the client's stored
/// cursor: that comparison needs the cursor, and belongs to the engine that
/// holds it.
///
/// # Errors
///
/// [`SyncError::Malformed`], [`SyncError::ResponseTooLarge`],
/// [`SyncError::SeqOutOfRange`], [`SyncError::FeedOutOfOrder`],
/// [`SyncError::EnvelopeTooLarge`] or [`SyncError::UnusableVersionToken`].
pub fn decode_change_feed(body: &[u8]) -> Result<ChangeFeed> {
    const OP: &str = "changes";
    let raw: RawChangeFeed = json(OP, body)?;
    let entries = raw.changes.unwrap_or_default();
    if entries.len() > limits::MAX_CHANGES_PER_PAGE {
        return Err(SyncError::ResponseTooLarge {
            operation: OP,
            max: limits::MAX_CHANGES_PER_PAGE,
        });
    }

    let mut changes = Vec::with_capacity(entries.len());
    let mut previous: Option<i64> = None;
    for entry in entries {
        let seq = checked_seq(required(OP, "seq", entry.seq)?)?;
        if let Some(previous) = previous {
            // Strictly ascending. Equal sequence numbers would make "resume
            // after seq n" ambiguous, and descending ones are a reordering
            // attempt.
            if seq <= previous {
                return Err(SyncError::FeedOutOfOrder {
                    offered: seq,
                    previous,
                });
            }
        }
        previous = Some(seq);

        // Absent rather than required: a row whose bytes the server has reclaimed
        // still appears in the feed so that `version` stays monotonic.
        let envelope = match entry.envelope {
            None => None,
            Some(text) => {
                let bytes = base64_field(OP, "envelope", Some(text), limits::MAX_ENVELOPE_LEN)
                    .map_err(|error| match error {
                        SyncError::ResponseTooLarge { max, .. } => SyncError::EnvelopeTooLarge {
                            len: max.saturating_add(1),
                            max,
                        },
                        other => other,
                    })?;
                Some(bytes)
            }
        };

        changes.push(FeedChange {
            item_id: ItemId::from_bytes(hex_array::<16>(OP, "item_id", entry.item_id)?),
            seq,
            version: entry.version.map(RawVersion::into_token).transpose()?,
            envelope,
            deleted: entry.deleted.unwrap_or(false),
        });
    }

    let next_seq = checked_seq(required(OP, "next_seq", raw.next_seq)?)?;
    if let Some(last) = previous {
        if next_seq < last {
            return Err(SyncError::FeedOutOfOrder {
                offered: next_seq,
                previous: last,
            });
        }
    }
    Ok(ChangeFeed {
        changes,
        next_seq,
        has_more: raw.has_more.unwrap_or(false),
    })
}

/// Decodes the `200` answer to a `PUT`.
///
/// # Errors
///
/// [`SyncError::Malformed`], [`SyncError::SeqOutOfRange`] or
/// [`SyncError::UnusableVersionToken`].
pub fn decode_put_applied(body: &[u8]) -> Result<PutOutcome> {
    const OP: &str = "put item";
    let raw: RawPutApplied = json(OP, body)?;
    Ok(PutOutcome::Applied {
        seq: checked_seq(required(OP, "seq", raw.seq)?)?,
        version: required(OP, "version", raw.version)?.into_token()?,
    })
}

/// Decodes the `409` answer to a `PUT`.
///
/// SPEC §6.1 requires the current envelope to come back "so the client can merge
/// locally and retry", and a `409` that carries neither an envelope nor a usable
/// version is refused rather than turned into a blind overwrite.
///
/// Two `409`s carry no envelope legitimately, and both are handled rather than
/// refused: a row whose bytes the server reclaimed after a `DELETE` (there is a
/// version to retry with and nothing to merge), and a row that does not exist at
/// all, which `misty-server` signals as `version: 0` (`store/mod.rs:120`) and which
/// means "retry as a create".
///
/// # Errors
///
/// [`SyncError::ConflictWithoutEnvelope`] if neither an envelope nor a version
/// arrived, [`SyncError::Malformed`], [`SyncError::EnvelopeTooLarge`] or
/// [`SyncError::UnusableVersionToken`].
pub fn decode_conflict(body: &[u8]) -> Result<PutOutcome> {
    const OP: &str = "resolve conflict";
    let raw: RawConflict = json(OP, body)?;
    let envelope = match raw.envelope {
        None => None,
        Some(text) => Some(base64_field(
            OP,
            "envelope",
            Some(text),
            limits::MAX_ENVELOPE_LEN,
        )?),
    };
    let version = raw
        .version
        .map(RawVersion::into_token)
        .transpose()?
        .filter(|version| !version.means_absent());
    if envelope.is_none() && version.is_none() {
        return Err(SyncError::ConflictWithoutEnvelope);
    }
    Ok(PutOutcome::Conflict { version, envelope })
}

/// Decodes `POST /v1/auth/challenge`.
///
/// # Errors
///
/// [`SyncError::Malformed`].
pub fn decode_challenge(body: &[u8]) -> Result<Challenge> {
    const OP: &str = "auth challenge";
    let raw: RawChallenge = json(OP, body)?;
    let encoded_nonce = required(OP, "nonce", raw.nonce)?;
    if encoded_nonce.len() > limits::MAX_CHALLENGE_NONCE_LEN * 2 {
        return Err(SyncError::ResponseTooLarge {
            operation: OP,
            max: limits::MAX_CHALLENGE_NONCE_LEN,
        });
    }
    let nonce = encoding::challenge_nonce_from_wire(&encoded_nonce)
        .filter(|bytes| bytes.len() <= limits::MAX_CHALLENGE_NONCE_LEN)
        .ok_or(SyncError::Malformed {
            operation: OP,
            field: "nonce",
        })?;
    if nonce.len() < limits::MIN_CHALLENGE_NONCE_LEN {
        return Err(SyncError::Malformed {
            operation: OP,
            field: "nonce",
        });
    }
    Ok(Challenge {
        nonce,
        encoded_nonce,
        expires_at: raw.expires_at.unwrap_or(0),
    })
}

/// Decodes `POST /v1/auth/verify` or `POST /v1/auth/refresh`.
///
/// # Errors
///
/// [`SyncError::Malformed`].
pub fn decode_tokens(body: &[u8]) -> Result<Tokens> {
    const OP: &str = "auth verify";
    let raw: RawTokens = json(OP, body)?;
    let access_token = required(OP, "access_token", raw.access_token)?;
    if access_token.is_empty() || access_token.len() > limits::MAX_TOKEN_LEN {
        return Err(SyncError::Malformed {
            operation: OP,
            field: "access_token",
        });
    }
    // A bearer token becomes an `Authorization` header value; the same
    // header-injection check the version token gets applies here.
    if !access_token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(SyncError::Malformed {
            operation: OP,
            field: "access_token",
        });
    }
    Ok(Tokens {
        access_token,
        refresh_token: raw
            .refresh_token
            .filter(|token| !token.is_empty() && token.len() <= limits::MAX_TOKEN_LEN),
        expires_in: raw.expires_in,
    })
}

/// Decodes `GET /v1/time` into its three parts, verifying nothing.
///
/// Verification is [`crate::time`]'s job, because it needs the pinned key and
/// the nonce this client sent.
///
/// # Errors
///
/// [`SyncError::Malformed`].
pub fn decode_time(body: &[u8]) -> Result<(i64, Vec<u8>, SignatureBytes)> {
    const OP: &str = "time";
    let raw: RawTime = json(OP, body)?;
    let unix_ms = required(OP, "unix_ms", raw.unix_ms)?;
    let nonce = fixed_field::<{ limits::TIME_NONCE_LEN }>(OP, "nonce", raw.nonce)?;
    let sig = fixed_field::<64>(OP, "sig", raw.sig)?;
    Ok((unix_ms, nonce.to_vec(), SignatureBytes::from_bytes(sig)))
}

/// Decodes `GET /v1/quota`.
///
/// # Errors
///
/// [`SyncError::Malformed`].
pub fn decode_quota(body: &[u8]) -> Result<Quota> {
    const OP: &str = "quota";
    let raw: RawQuota = json(OP, body)?;
    let limits = raw.limits.unwrap_or(RawQuotaLimits {
        max_envelope_bytes: None,
        max_items_per_vault: None,
        max_vault_bytes: None,
        max_changes_limit: None,
    });
    let item_count = raw.item_count.unwrap_or(0);
    Ok(Quota {
        bytes_used: raw.bytes_used.unwrap_or(0),
        item_count,
        // A server that does not report reclaimed rows separately is reporting
        // that every row still holds an envelope.
        row_count: raw.row_count.unwrap_or(item_count),
        max_envelope_bytes: limits.max_envelope_bytes,
        max_items_per_vault: limits.max_items_per_vault,
        max_vault_bytes: limits.max_vault_bytes,
        max_changes_limit: limits.max_changes_limit,
    })
}

/// Decodes `GET /v1/enroll/poll/{enroll_id}?want=…`.
///
/// # Errors
///
/// [`SyncError::Malformed`] or [`SyncError::ResponseTooLarge`].
pub fn decode_enrollment_poll(body: &[u8]) -> Result<EnrollmentPoll> {
    const OP: &str = "enroll poll";
    let raw: RawEnrollmentPoll = json(OP, body)?;
    let max = limits::MAX_ENROLLMENT_PAYLOAD_LEN;
    // §6.1's name first, then the server's current one. Whichever arrives, the
    // bytes are the same public CBOR request.
    let enroll_request = raw.enroll_request.or(raw.sealed_request);
    let ready_implied = enroll_request.is_some() || raw.sealed_response.is_some();
    Ok(EnrollmentPoll {
        ready: raw.ready.unwrap_or(ready_implied),
        x25519_pub: raw
            .x25519_pub
            .map(|text| fixed_field::<32>(OP, "x25519_pub", Some(text)))
            .transpose()?,
        enroll_request: enroll_request
            .map(|text| base64_field(OP, "enroll_request", Some(text), max))
            .transpose()?,
        sealed_response: raw
            .sealed_response
            .map(|text| base64_field(OP, "sealed_response", Some(text), max))
            .transpose()?,
    })
}

// --- encoding ---------------------------------------------------------------

/// Encodes a blob field: standard base64 with padding, per SPEC §6.1.1.
#[must_use]
pub fn to_base64(bytes: &[u8]) -> String {
    encoding::to_standard(bytes)
}

/// Encodes an id, nonce, signature, or public key: lowercase hex, per SPEC §6.1.1.
///
/// This replaced a base64url encoder. Base64url existed only because standard
/// base64's `+` arrives as a space in a query string, so `/v1/time`'s nonce needed a
/// query-safe alphabet — which left the protocol carrying three alphabets. Hex is safe
/// in a body and in a query string, so the third one is gone.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    encoding::to_hex(bytes)
}

/// Serialises a body, or panics-free-fails into a `Malformed` error.
fn encode<T: Serialize>(operation: &'static str, value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| SyncError::Malformed {
        operation,
        field: "body",
    })
}

/// `POST /v1/auth/challenge` body.
///
/// # Errors
///
/// [`SyncError::Malformed`] if serialisation fails, which it cannot for these
/// field types; the error exists so no `unwrap` does.
pub fn challenge_body(vault: &VaultId, device: &DeviceId) -> Result<Vec<u8>> {
    encode(
        "auth challenge",
        &ChallengeRequestBody {
            vault_id: &vault.to_hex(),
            device_id: &device.to_hex(),
        },
    )
}

/// `POST /v1/auth/verify` body.
///
/// `encoded_nonce` is echoed exactly as the server sent it. `sig` and
/// `ed25519_pub` go out as standard base64, which is what `misty-server` parses
/// (`routes/auth.rs:185,211`); SPEC §6.1.1 asks for hex and [`crate::encoding`]
/// records the disagreement.
///
/// # Errors
///
/// As [`challenge_body`].
pub fn verify_body(
    vault: &VaultId,
    device: &DeviceId,
    encoded_nonce: &str,
    signature: &SignatureBytes,
    ed25519_pub: &[u8; 32],
) -> Result<Vec<u8>> {
    encode(
        "auth verify",
        &VerifyRequestBody {
            vault_id: &vault.to_hex(),
            device_id: &device.to_hex(),
            nonce: encoded_nonce,
            sig: &encoding::to_hex(signature.as_bytes()),
            ed25519_pub: &encoding::to_hex(ed25519_pub),
        },
    )
}

/// `POST /v1/auth/refresh` body.
///
/// # Errors
///
/// As [`challenge_body`].
pub fn refresh_body(refresh_token: &str) -> Result<Vec<u8>> {
    encode("auth refresh", &RefreshRequestBody { refresh_token })
}

/// `POST /v1/vaults/{vid}/devices` body.
///
/// # Errors
///
/// As [`challenge_body`].
pub fn add_device_body(device: &DeviceId, ed25519_pub: &[u8; 32]) -> Result<Vec<u8>> {
    encode(
        "admit device",
        &AddDeviceBody {
            device_id: &device.to_hex(),
            ed25519_pub: &encoding::to_hex(ed25519_pub),
        },
    )
}

/// `PUT /v1/vaults/{vid}/items/{item_id}` body.
///
/// # Errors
///
/// As [`challenge_body`].
pub fn envelope_body(envelope: &[u8]) -> Result<Vec<u8>> {
    encode(
        "put item",
        &EnvelopeBody {
            envelope: &to_base64(envelope),
        },
    )
}

/// `POST /v1/enroll/begin` body, with the field named as SPEC §6.1 names it.
///
/// # Errors
///
/// As [`challenge_body`].
pub fn enroll_begin_body(
    enroll_id: &EnrollId,
    x25519_pub: &[u8; 32],
    enroll_request: &[u8],
) -> Result<Vec<u8>> {
    encode(
        "enroll begin",
        &EnrollBeginBody {
            enroll_id: &enroll_id.to_hex(),
            x25519_pub: &encoding::to_hex(x25519_pub),
            enroll_request: &to_base64(enroll_request),
        },
    )
}

/// The same body under `misty-server`'s current field name, for the one-shot
/// fallback described on [`enroll_begin_body`] and in
/// [`SyncClient::enroll_begin`](crate::SyncClient::enroll_begin).
///
/// # Errors
///
/// As [`challenge_body`].
pub fn legacy_enroll_begin_body(
    enroll_id: &EnrollId,
    x25519_pub: &[u8; 32],
    enroll_request: &[u8],
) -> Result<Vec<u8>> {
    encode(
        "enroll begin",
        &LegacyEnrollBeginBody {
            enroll_id: &enroll_id.to_hex(),
            x25519_pub: &encoding::to_hex(x25519_pub),
            sealed_request: &to_base64(enroll_request),
        },
    )
}

/// `POST /v1/enroll/complete` body.
///
/// # Errors
///
/// As [`challenge_body`].
pub fn enroll_complete_body(enroll_id: &EnrollId, sealed: &[u8]) -> Result<Vec<u8>> {
    encode(
        "enroll complete",
        &EnrollCompleteBody {
            enroll_id: &enroll_id.to_hex(),
            sealed_response: &to_base64(sealed),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_token_round_trips_through_the_vault_column() {
        let version = ServerVersion::parse("W/abc-123").expect("version");
        let bytes = version.to_bytes();
        assert_eq!(ServerVersion::from_bytes(&bytes).expect("back"), version);
        // The vault stores opaque bytes; non-UTF-8 there is a corrupt column.
        assert!(ServerVersion::from_bytes(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn an_honest_change_feed_decodes() {
        let body = format!(
            "{{\"changes\":[{{\"item_id\":\"{}\",\"seq\":3,\"version\":\"v7\",\"envelope\":\"{}\",\"deleted\":true}}],\"next_seq\":3,\"has_more\":false}}",
            "ab".repeat(16),
            to_base64(b"not really an envelope"),
        );
        let feed = decode_change_feed(body.as_bytes()).expect("decode");
        assert_eq!(feed.next_seq, 3);
        assert!(!feed.has_more);
        let change = feed.changes.first().expect("one change");
        assert_eq!(change.seq, 3);
        assert_eq!(change.item_id, ItemId::from_bytes([0xab; 16]));
        assert_eq!(
            change.envelope.as_deref(),
            Some(b"not really an envelope".as_slice())
        );
        assert_eq!(
            change.version.as_ref().map(ServerVersion::as_str),
            Some("v7")
        );
        // Decoded, and used by nothing. SPEC §6.1 makes it advisory.
        assert!(change.deleted);
    }

    #[test]
    fn an_absent_changes_array_is_an_empty_page_rather_than_an_error() {
        // A server with nothing to say may omit the array. `next_seq` may not be
        // omitted: without it the client would not know where to resume.
        let feed = decode_change_feed(b"{\"next_seq\":0}").expect("decode");
        assert!(feed.changes.is_empty());
        assert!(decode_change_feed(b"{\"changes\":[]}").is_err());
    }

    #[test]
    fn unknown_response_fields_are_ignored() {
        // Deliberately unlike `misty-vault`'s CBOR decoder: a transport framing that
        // grows a field has not changed the meaning of anything read here.
        let feed = decode_change_feed(
            b"{\"changes\":[],\"next_seq\":1,\"retry_after\":30,\"note\":\"hello\"}",
        )
        .expect("decode");
        assert_eq!(feed.next_seq, 1);
    }

    #[test]
    fn a_conflict_carrying_neither_an_envelope_nor_a_version_is_refused() {
        // Nothing to merge and nothing to retry with is not a conflict, it is a
        // server that has given the client no way forward. `version: 0` is
        // `misty-server`'s way of saying "there is no such row", so it counts as
        // absent rather than as a token.
        for body in [
            b"{}".as_slice(),
            b"{\"version\":0}".as_slice(),
            b"{\"version\":\"0\"}".as_slice(),
        ] {
            let error = decode_conflict(body).expect_err("nothing to act on");
            assert!(
                matches!(error, SyncError::ConflictWithoutEnvelope),
                "{error:?}"
            );
        }
    }

    #[test]
    fn a_conflict_with_a_version_and_no_envelope_is_a_retry_not_a_refusal() {
        // SPEC §6.1 keeps a row after a `DELETE` so `version` stays monotonic, so
        // this is what a conflict against a reclaimed row looks like. There is
        // nothing to merge; there is something to retry with.
        let outcome = decode_conflict(b"{\"version\":7,\"envelope\":null}").expect("decode");
        let PutOutcome::Conflict { version, envelope } = outcome else {
            panic!("expected a conflict");
        };
        assert_eq!(version.as_ref().map(ServerVersion::as_str), Some("7"));
        assert_eq!(envelope, None);
    }

    #[test]
    fn a_version_arrives_as_a_string_or_a_number() {
        // §6.1.1 makes this an opaque printable-ASCII token and `misty-server` now
        // emits a string. A JSON number is still accepted, and that tolerance is
        // deliberately unlike the encoding tolerance removed from `encoding.rs`: a
        // number has exactly one string rendering, so accepting it cannot yield the
        // wrong bytes. The hazard there was two alphabets producing two different
        // readings of one string; there is no analogue here.
        let from_number = decode_put_applied(b"{\"seq\":1,\"version\":42}").expect("number");
        let from_string = decode_put_applied(b"{\"seq\":1,\"version\":\"42\"}").expect("string");
        assert_eq!(from_number, from_string);
        let PutOutcome::Applied { version, .. } = from_number else {
            panic!("expected an applied write");
        };
        assert_eq!(version.as_str(), "42");
        assert_eq!(version.to_if_match(), "\"42\"");
    }

    #[test]
    fn a_challenge_nonce_has_a_floor_and_a_ceiling() {
        let body = |nonce: &[u8]| format!("{{\"nonce\":\"{}\",\"expires_at\":1}}", to_hex(nonce));
        assert!(decode_challenge(body(&[0u8; 16]).as_bytes()).is_ok());
        assert!(decode_challenge(body(&[0u8; 15]).as_bytes()).is_err());
        assert!(decode_challenge(body(&[0u8; 129]).as_bytes()).is_err());
        // The nonce is echoed verbatim, never re-encoded: the server's own decoder
        // has to reproduce the same bytes, and a round trip through this client's
        // choice of alphabet would be a second place for the two to disagree.
        let encoded = to_hex(&[7u8; 32]);
        let challenge = decode_challenge(body(&[7u8; 32]).as_bytes()).expect("decode");
        assert_eq!(challenge.encoded_nonce, encoded);
        assert_eq!(challenge.nonce, vec![7u8; 32]);
    }

    #[test]
    fn a_bearer_token_that_is_not_a_header_value_is_refused() {
        let body = |token: &str| {
            serde_json::to_vec(&serde_json::json!({ "access_token": token })).unwrap_or_default()
        };
        assert!(decode_tokens(&body("abc.def")).is_ok());
        for bad in ["", "with space", "with\nlf", "with\rcr"] {
            assert!(decode_tokens(&body(bad)).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_quota_without_limits_reads_as_no_limits() {
        let quota = decode_quota(b"{\"bytes_used\":10,\"item_count\":2}").expect("decode");
        assert_eq!(quota.bytes_used, 10);
        assert_eq!(quota.item_count, 2);
        assert_eq!(quota.max_vault_bytes, None);
        assert_eq!(
            quota.row_count, 2,
            "no reclaimed rows reported means none exist"
        );
    }

    #[test]
    fn a_time_response_needs_all_three_fields_at_their_exact_lengths() {
        let nonce = "11".repeat(limits::TIME_NONCE_LEN);
        let sig = "22".repeat(64);
        let ok = format!("{{\"unix_ms\":7,\"nonce\":\"{nonce}\",\"sig\":\"{sig}\"}}");
        let (unix_ms, echoed, signature) = decode_time(ok.as_bytes()).expect("decode");
        assert_eq!(unix_ms, 7);
        assert_eq!(echoed.len(), limits::TIME_NONCE_LEN);
        assert_eq!(signature.as_bytes().len(), 64);
        for bad in [
            format!("{{\"nonce\":\"{nonce}\",\"sig\":\"{sig}\"}}"),
            format!("{{\"unix_ms\":7,\"sig\":\"{sig}\"}}"),
            format!("{{\"unix_ms\":7,\"nonce\":\"{nonce}\"}}"),
            format!("{{\"unix_ms\":7,\"nonce\":\"11\",\"sig\":\"{sig}\"}}"),
            format!("{{\"unix_ms\":7,\"nonce\":\"{nonce}\",\"sig\":\"22\"}}"),
        ] {
            assert!(decode_time(bad.as_bytes()).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn request_bodies_are_the_documented_shape() {
        let vault = VaultId::from_bytes([1; 16]);
        let device = DeviceId::from_bytes([2; 16]);
        let body = challenge_body(&vault, &device).expect("body");
        let text = String::from_utf8(body).expect("utf8");
        assert!(
            text.contains(&format!("\"vault_id\":\"{}\"", vault.to_hex())),
            "{text}"
        );
        assert!(
            text.contains(&format!("\"device_id\":\"{}\"", device.to_hex())),
            "{text}"
        );

        let body = envelope_body(b"bytes").expect("body");
        let text = String::from_utf8(body).expect("utf8");
        assert_eq!(
            text,
            format!("{{\"envelope\":\"{}\"}}", to_base64(b"bytes"))
        );
    }
}
