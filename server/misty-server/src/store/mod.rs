// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The storage trait, its row types, and the rule that defines this server.
//!
//! # The rule
//!
//! **Nothing derived from envelope contents is ever stored.** Not a hash, not a
//! length beyond the blob's own (which the client has already bucketed to 256
//! bytes, SPEC §2.4), not a timestamp read from inside a payload, not a field
//! name, not a count of anything internal. `tests/schema_zero_knowledge.rs`
//! asserts the column list against a hard-coded allowlist so that adding a
//! column is a deliberate act with a test to update, rather than a Tuesday.
//!
//! The envelope is `Vec<u8>` from the moment it is decoded from base64 until it
//! is handed back. No code path in this crate inspects a byte of it, and the
//! crate does not depend on `misty-crypto` outside dev-dependencies, so it could
//! not interpret one if it tried.
//!
//! # Why a trait
//!
//! SQLite is the right default — one binary, one file, no daemon to operate —
//! but a large instance will want Postgres. Everything above this module speaks
//! [`Store`], so that is an additive change rather than a rewrite. The trait is
//! deliberately **synchronous**: `rusqlite` is blocking, and pretending
//! otherwise with an `async` façade would hide the blocking call rather than move
//! it off the runtime. Handlers push these calls onto
//! [`tokio::task::spawn_blocking`] instead ([`crate::routes::blocking`]).

pub mod sqlite;

use crate::ids::{DeviceId, EnrollId, ItemId, VaultId};

/// Anything that went wrong below the HTTP layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database rejected or failed an operation.
    #[error("database error: {0}")]
    Database(String),
    /// A stored value had a shape the schema should have made impossible.
    #[error("corrupt row: {0}")]
    Corrupt(&'static str),
    /// The OS CSPRNG failed while minting an identifier.
    #[error("the operating system CSPRNG failed")]
    Entropy,
}

impl From<StoreError> for crate::error::ApiError {
    fn from(error: StoreError) -> Self {
        // The caller learns nothing but "internal error"; the operator gets the
        // detail in a log line with no vault or item identifier attached.
        Self::Internal(error.to_string())
    }
}

/// A `Store` result.
pub type Result<T> = core::result::Result<T, StoreError>;

/// One entry of the changes feed (SPEC §6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// Which item.
    pub item_id: ItemId,
    /// Server-assigned per-vault sequence number.
    pub seq: u64,
    /// Per-item version, monotonic and never reset.
    pub version: u64,
    /// The opaque envelope, or `None` for a row whose bytes were reclaimed.
    pub envelope: Option<Vec<u8>>,
    /// Advisory only. SPEC §6.1: a client that acted on this would let a hostile
    /// server erase a vault it cannot read.
    pub deleted: bool,
}

/// The precondition on a write.
///
/// A single `u64` covers both HTTP forms because version numbering starts at 1:
///
/// * `If-Match: "7"` → `Precondition(7)` — the row must exist at version 7.
/// * `If-None-Match: *` → `Precondition(0)` — no row may exist.
/// * `If-Match: "0"` → `Precondition(0)`, the same thing, accepted because a
///   client that tracks "version I last saw, or 0 for never" needs no special
///   case for creation.
///
/// Collapsing the two into one integer is what makes the conflict response
/// uniform: version `0` in a `409` means "there is no such item", which a client
/// can act on without a second code path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Precondition(pub u64);

impl Precondition {
    /// Whether this precondition demands the row be absent.
    #[must_use]
    pub const fn expects_absent(self) -> bool {
        self.0 == 0
    }
}

/// What a successful write produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    /// The newly allocated per-vault sequence number.
    pub seq: u64,
    /// The item's new version.
    pub version: u64,
}

/// The outcome of a `PUT` or `DELETE`.
///
/// An enum rather than `Result<_, ApiError>` because a conflict and a quota
/// refusal are ordinary answers, not failures — the storage layer decides them,
/// and the HTTP layer only chooses a status code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Stored.
    Ok(Written),
    /// The precondition did not hold. Carries the current state so the client
    /// can merge locally and retry. The server never merges (SPEC §6.1).
    Conflict {
        /// Current version, or `0` if there is no such item.
        version: u64,
        /// Current envelope, or `None` if absent or reclaimed.
        envelope: Option<Vec<u8>>,
    },
    /// The vault holds as many rows as it may.
    ItemLimit,
    /// The vault holds as many envelope bytes as it may.
    ByteLimit,
    /// `DELETE` for an item that was never stored.
    Missing,
}

/// Per-vault usage, for `GET /v1/quota`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Total bytes of stored envelopes. Each is already padded to a 256-byte
    /// bucket by the client, so this is a bucket count times 256 plus framing.
    pub bytes_used: u64,
    /// Rows that still hold an envelope.
    pub item_count: u64,
    /// All rows, including reclaimed ones. This is what the item limit counts,
    /// because a row is what keeps `version` monotonic.
    pub row_count: u64,
}

/// The server's access-control record for one device.
///
/// Emphatically **not** a source of trust. SPEC §6.2: clients trust the
/// client-signed roster and nothing else, so a row here buys an attacker the
/// ability to write bytes that every client rejects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Device {
    /// Which device.
    pub device_id: DeviceId,
    /// Its Ed25519 public key, as first presented.
    pub ed25519_pub: [u8; 32],
}

/// What happened when a device asked to be admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The vault did not exist; it was created and this is its first device.
    Bootstrapped,
    /// Added to an existing vault by an already-admitted device.
    Admitted,
    /// Already present with this exact key. Idempotent.
    AlreadyPresent,
    /// Present with a *different* key. Refused: otherwise anyone who learned a
    /// `vault_id` could take over a device slot by re-presenting it.
    KeyMismatch,
    /// The instance is at `MISTY_MAX_VAULTS`.
    VaultLimit,
    /// The vault exists and this device is not in it, so admission requires an
    /// already-admitted device to vouch (`POST /v1/vaults/{vid}/devices`).
    NeedsSponsor,
}

/// A challenge, as stored between `challenge` and `verify`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// Which vault the challenge was issued for.
    pub vault_id: VaultId,
    /// Which device the challenge was issued for. A challenge is redeemable
    /// **only** by this device; see `tests/hostile_server.rs`.
    pub device_id: DeviceId,
}

/// A session token's binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    /// Which vault.
    pub vault_id: VaultId,
    /// Which device.
    pub device_id: DeviceId,
    /// The rotation chain this token belongs to.
    pub family: [u8; 16],
}

/// The outcome of presenting a refresh token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// Valid and unused. Now consumed; mint a successor in `family`.
    Rotated(Session),
    /// No such token, or it has expired, or its family was revoked.
    Rejected,
    /// **A consumed token was presented again.** Either the client replayed or
    /// someone stole it, and the server cannot tell which — so the whole family
    /// is revoked and both parties have to re-authenticate with the device key.
    ReuseDetected(Session),
}

/// The outcome of `POST /v1/enroll/begin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollBegin {
    /// Stored.
    Created,
    /// An enrollment with this id already exists. Refused rather than
    /// overwritten: `enroll_id` travels in a QR code, and whoever can read the
    /// QR must not be able to swap the request underneath it.
    Exists,
}

/// The outcome of retrieving the enrollment request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollRequest {
    /// Here it is, once.
    Ready {
        /// The new device's ephemeral X25519 public key, as posted.
        x25519_pub: [u8; 32],
        /// The opaque enrollment request. Authenticated by the 6-digit
        /// confirmation code, not encrypted — SPEC §6.3 explains why it cannot be.
        enroll_request: Vec<u8>,
    },
    /// No such enrollment, it expired, or the request was already collected.
    Gone,
}

/// The outcome of polling for the sealed response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollResponse {
    /// The approving device has not answered yet.
    Pending,
    /// Here it is, once. The record is destroyed by this call.
    Ready(Vec<u8>),
    /// No such enrollment, or it expired, or the response was already collected.
    Gone,
}

/// The outcome of `POST /v1/enroll/complete`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollComplete {
    /// Stored.
    Stored,
    /// No such enrollment, or it expired.
    Missing,
    /// A response is already recorded. Refused, so a race cannot replace a
    /// legitimate answer with an attacker's.
    AlreadyAnswered,
}

/// Rows removed by one sweep. Logged; useful for nothing else.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Expired challenges.
    pub challenges: u64,
    /// Expired access and refresh tokens, and stale revocation records.
    pub tokens: u64,
    /// Expired enrollment records.
    pub enrollments: u64,
    /// Reclaimed rows past the tombstone horizon (SPEC §4: purge after 90 days).
    pub tombstones: u64,
}

/// Ceilings applied to a single write. Passed in rather than read from a
/// configuration global so the storage layer stays testable in isolation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most rows one vault may hold.
    pub max_rows: u64,
    /// Most envelope bytes one vault may hold.
    pub max_bytes: u64,
}

/// Everything the HTTP layer needs from storage.
///
/// Implementations must be safe to share across threads and must serialise
/// writes: SPEC §6.1's `seq` is only useful as a change cursor if a reader can
/// never observe `seq = n` committed while `seq = n - 1` is still in flight. A
/// gap-free feed is the whole contract, and it is the implementation's job.
pub trait Store: Send + Sync + 'static {
    /// Applies any outstanding forward-only migrations.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn migrate(&self) -> Result<()>;

    /// Records a challenge bound to `(vault_id, device_id)`.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn put_challenge(
        &self,
        nonce_hash: [u8; 32],
        vault_id: VaultId,
        device_id: DeviceId,
        expires_at_ms: i64,
    ) -> Result<()>;

    /// Consumes a challenge by nonce, whatever the outcome of verification.
    ///
    /// Single-use is enforced here, not at the call site: a challenge that
    /// survived a failed verification would be an online guessing oracle.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn take_challenge(&self, nonce_hash: [u8; 32], now_ms: i64) -> Result<Option<Challenge>>;

    /// Looks up a device's public key.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn device(&self, vault_id: VaultId, device_id: DeviceId) -> Result<Option<Device>>;

    /// Admits a device, creating the vault if it does not exist.
    ///
    /// `sponsor` is `None` for a bootstrap (first device of a new vault) and
    /// `Some(device)` when an already-admitted device vouches for a new one.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn admit_device(
        &self,
        vault_id: VaultId,
        device_id: DeviceId,
        ed25519_pub: [u8; 32],
        sponsor: Option<DeviceId>,
        now_ms: i64,
        max_vaults: Option<u64>,
    ) -> Result<Admission>;

    /// Stores an access token hash.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn put_access_token(
        &self,
        token_hash: [u8; 32],
        session: Session,
        expires_at_ms: i64,
    ) -> Result<()>;

    /// Resolves an access token hash to its session, if live.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn access_token(&self, token_hash: [u8; 32], now_ms: i64) -> Result<Option<Session>>;

    /// Stores a refresh token hash.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn put_refresh_token(
        &self,
        token_hash: [u8; 32],
        session: Session,
        expires_at_ms: i64,
    ) -> Result<()>;

    /// Consumes a refresh token, detecting reuse of an already-consumed one.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn consume_refresh_token(&self, token_hash: [u8; 32], now_ms: i64) -> Result<RefreshOutcome>;

    /// Revokes an entire rotation chain: every access token in it, and every
    /// refresh token in it, past and future.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn revoke_family(&self, family: [u8; 16], now_ms: i64) -> Result<()>;

    /// Reads the changes feed. Returns at most `limit` entries in `seq` order,
    /// plus whether more exist.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn changes(&self, vault_id: VaultId, since: u64, limit: u32) -> Result<(Vec<Change>, bool)>;

    /// Stores an envelope under a precondition.
    ///
    /// The `envelope` argument is opaque. This method does not read it, measure
    /// anything but its length, or record anything about it beyond the bytes
    /// themselves.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn put_item(
        &self,
        vault_id: VaultId,
        item_id: ItemId,
        precondition: Precondition,
        envelope: Vec<u8>,
        limits: Limits,
        now_ms: i64,
    ) -> Result<WriteOutcome>;

    /// Reclaims an item's bytes under a precondition.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn delete_item(
        &self,
        vault_id: VaultId,
        item_id: ItemId,
        precondition: Precondition,
        now_ms: i64,
    ) -> Result<WriteOutcome>;

    /// Reads per-vault usage.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn usage(&self, vault_id: VaultId) -> Result<Usage>;

    /// Stores an enrollment request, refusing to overwrite.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn enroll_begin(
        &self,
        enroll_id: EnrollId,
        x25519_pub: [u8; 32],
        enroll_request: Vec<u8>,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<EnrollBegin>;

    /// Collects the enrollment request, once.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn enroll_take_request(&self, enroll_id: EnrollId, now_ms: i64) -> Result<EnrollRequest>;

    /// Records the sealed response, refusing to overwrite.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn enroll_complete(
        &self,
        enroll_id: EnrollId,
        sealed_response: Vec<u8>,
        now_ms: i64,
    ) -> Result<EnrollComplete>;

    /// Collects the sealed response, once, destroying the record.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn enroll_take_response(&self, enroll_id: EnrollId, now_ms: i64) -> Result<EnrollResponse>;

    /// Deletes everything that has expired.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn sweep(&self, now_ms: i64, tombstone_horizon_ms: i64) -> Result<Swept>;

    /// Column names per table, for `tests/schema_zero_knowledge.rs`.
    ///
    /// Part of the trait rather than the SQLite type because the
    /// zero-knowledge property is a claim about *any* backend, and a Postgres
    /// implementation must be held to the same allowlist.
    ///
    /// # Errors
    ///
    /// [`StoreError`].
    fn schema_columns(&self) -> Result<Vec<(String, String)>>;
}
