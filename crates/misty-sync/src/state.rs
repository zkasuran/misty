// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The durable sync state, and the store it lives in.
//!
//! # The outbound queue is derived, not remembered
//!
//! The obvious way to build an offline-first queue is a list of "writes I still
//! owe the server", appended to on every local edit. It has a failure mode that
//! is silent and permanent: if the process dies between the vault's commit and
//! the queue's append, that write is never sent, and nothing afterwards notices.
//! The app also has to remember to enqueue, on every path, forever.
//!
//! So the queue here is *derived* on demand by comparing two durable facts:
//!
//! * the envelope `misty-vault` currently stores for an item — the truth about
//!   what this device holds, committed in the vault's own transaction;
//! * the [`Fingerprint`] of the envelope the **server** last confirmed for that
//!   item, recorded here.
//!
//! An item is pending exactly when those disagree. A crash cannot lose a write,
//! because the vault's commit *is* the enqueue; a crash cannot duplicate one,
//! because a re-sent write carries the same `If-Match` and the server's answer —
//! `200` or `409` — settles it either way. And the app cannot forget to enqueue,
//! because there is nothing to call.
//!
//! What this state must therefore survive a restart is small: a change-feed
//! cursor, one fingerprint and one `version` token per item, the last verified
//! time sample, and whether an epoch rotation is in progress.
//!
//! # Save the whole thing, or none of it
//!
//! [`StateStore`] has one write method and it takes the entire state. That is
//! deliberate: every transition this crate makes is a single durable step, so
//! there is no half-saved state to reason about, and a backend only has to get
//! one atomic write right rather than a transaction protocol. A vault is capped
//! well under 10 000 items (SPEC §5), so the state is a few hundred kilobytes.

use std::collections::BTreeMap;

use misty_crypto::envelope::EnvelopeKind;
use misty_crypto::{derive, ItemId};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SyncError};
use crate::wire::ServerVersion;

/// Bumped whenever the persisted shape changes. A state file from a newer build
/// is refused rather than guessed at.
pub const STATE_FORMAT_VERSION: u8 = 1;

/// Domain separator for [`Fingerprint::of`].
///
/// Local-only: this value never reaches the wire, never derives a key, and never
/// enters a signature, so unlike the constants in SPEC §6.6 it is not part of
/// the frozen format. Changing it costs one redundant push per item.
pub const FINGERPRINT_SALT: &[u8] = b"misty/sync/fingerprint/v1";

/// A 32-byte fingerprint of an envelope.
///
/// HKDF-SHA-512 under [`FINGERPRINT_SALT`], because `misty-crypto` is the only
/// place cryptography happens in Misty (SPEC §0) and it exposes HKDF but no bare
/// hash. A fingerprint needs collision resistance and domain separation, and
/// HMAC-SHA-512 under a fixed salt gives both. It fingerprints *ciphertext* the
/// server already holds, so it is not secret.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Fingerprints an envelope.
    ///
    /// # Errors
    ///
    /// [`SyncError::Crypto`] if the HKDF call fails, which it cannot for a
    /// 32-byte output.
    pub fn of(envelope: &[u8]) -> Result<Self> {
        let mut out = [0u8; 32];
        derive::hkdf_sha512(envelope, FINGERPRINT_SALT, &[], &mut out)?;
        Ok(Self(out))
    }
}

impl core::fmt::Debug for Fingerprint {
    /// Short and unambiguous. A full fingerprint in a log line would let anyone
    /// holding the database confirm which envelope a device had, so only the
    /// first four bytes are shown.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let head = self.0.first_chunk::<4>().copied().unwrap_or_default();
        write!(f, "Fingerprint({}…)", hex::encode(head))
    }
}

/// What the server last confirmed about one item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownRow {
    /// The envelope kind, as its wire byte. Stored so a purge can tell an item
    /// or group — which this device owns and may delete server-side — from a
    /// roster or settings blob, which it must not.
    pub kind: u8,
    /// Fingerprint of the envelope the server holds, or `None` when the server has
    /// a row whose bytes this device has not seen.
    ///
    /// `None` arises two ways, and both must leave the item **pending** so this
    /// device offers its own copy: a row whose envelope the server reclaimed after a
    /// `DELETE` (SPEC §6.1 keeps the row so `version` stays monotonic), and a `409`
    /// that carried a version but no bytes. Recording the version without a
    /// fingerprint is what makes the next `If-Match` correct while still saying "we
    /// do not have what they have".
    pub fingerprint: Option<Fingerprint>,
    /// The `If-Match` token for the next write to this item.
    ///
    /// This is the authoritative copy. `misty-vault`'s `version` column is not:
    /// when a merge produces a value neither side had, the vault carries the
    /// *pre-merge* token over to the new row, which is the token the server no
    /// longer has. See `README.md`.
    pub version: Option<ServerVersion>,
    /// The `seq` the server assigned, for diagnostics.
    pub seq: Option<i64>,
}

impl KnownRow {
    /// Whether this row names an object this device may delete server-side.
    #[must_use]
    pub fn is_deletable(&self) -> bool {
        matches!(
            EnvelopeKind::from_u8(self.kind),
            Ok(EnvelopeKind::Item | EnvelopeKind::Group)
        )
    }
}

/// One verified `/v1/time` measurement (SPEC §6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeSample {
    /// The local clock when the measurement was taken, in Unix ms.
    pub measured_at_ms: i64,
    /// What the server said, in Unix ms.
    pub server_ms: i64,
    /// `server_ms - measured_at_ms`, the correction to apply. Positive means
    /// this device is running slow.
    pub offset_ms: i64,
}

/// A rotation in progress (SPEC §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationState {
    /// The epoch every object is being re-sealed under.
    pub target_epoch: u32,
}

/// Everything the sync engine must remember across a restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// The persisted shape's version.
    pub format_version: u8,
    /// Where the change feed was last read to. `None` means "from the start".
    pub cursor: Option<i64>,
    /// What the server last confirmed, per item.
    pub known: BTreeMap<ItemId, KnownRow>,
    /// The last verified time measurement.
    pub time: Option<TimeSample>,
    /// An epoch rotation in progress.
    pub rotation: Option<RotationState>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            format_version: STATE_FORMAT_VERSION,
            cursor: None,
            known: BTreeMap::new(),
            time: None,
            rotation: None,
        }
    }
}

impl SyncState {
    /// A fresh state for a vault that has never synced.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rejects a state written by a newer build.
    ///
    /// # Errors
    ///
    /// [`SyncError::StateTooNew`].
    pub fn check_version(&self) -> Result<()> {
        if self.format_version > STATE_FORMAT_VERSION {
            return Err(SyncError::StateTooNew {
                found: self.format_version,
                supported: STATE_FORMAT_VERSION,
            });
        }
        Ok(())
    }

    /// The `If-Match` token for an item, if the server has confirmed one.
    #[must_use]
    pub fn version_of(&self, item: &ItemId) -> Option<&ServerVersion> {
        self.known.get(item).and_then(|row| row.version.as_ref())
    }

    /// Encodes to CBOR, for a store that persists bytes.
    ///
    /// CBOR rather than JSON because [`ItemId`] serialises as a byte string and
    /// CBOR admits byte strings as map keys, so the natural `BTreeMap<ItemId, _>`
    /// needs no hex-string detour.
    ///
    /// # Errors
    ///
    /// [`SyncError::StateStore`] if encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|_| SyncError::StateStore {
            operation: "encode",
        })?;
        Ok(out)
    }

    /// Decodes from CBOR and checks the format version.
    ///
    /// # Errors
    ///
    /// [`SyncError::StateStore`] if the bytes are not this shape, or
    /// [`SyncError::StateTooNew`].
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        let state: Self = ciborium::from_reader(bytes).map_err(|_| SyncError::StateStore {
            operation: "decode",
        })?;
        state.check_version()?;
        Ok(state)
    }
}

/// Where the durable sync state lives.
///
/// One load, one whole-state save. Apps supply their own: SQLite beside the
/// vault natively, IndexedDB in a browser. [`MemoryStateStore`] exists on every
/// target for tests, and [`FileStateStore`] natively for a CLI.
pub trait StateStore {
    /// Reads the state, or [`SyncState::new`] if none has been written.
    ///
    /// # Errors
    ///
    /// [`SyncError::StateStore`] if the backend fails, or
    /// [`SyncError::StateTooNew`] for a state from a newer build.
    fn load(&self) -> Result<SyncState>;

    /// Replaces the state. MUST be atomic: a torn write is indistinguishable
    /// from a state that never existed, and would resend every item.
    ///
    /// # Errors
    ///
    /// [`SyncError::StateStore`] if the backend fails.
    fn save(&mut self, state: &SyncState) -> Result<()>;
}

impl<S: StateStore + ?Sized> StateStore for &mut S {
    fn load(&self) -> Result<SyncState> {
        (**self).load()
    }

    fn save(&mut self, state: &SyncState) -> Result<()> {
        (**self).save(state)
    }
}

/// An in-memory state store, on every target.
///
/// Counts its saves, which is what the interruption tests assert against, and
/// keeps the bytes rather than the struct so that "survives a restart" is tested
/// through a real encode/decode rather than a clone.
#[derive(Debug, Default)]
pub struct MemoryStateStore {
    bytes: Option<Vec<u8>>,
    saves: usize,
}

impl MemoryStateStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store already holding `state`.
    ///
    /// # Errors
    ///
    /// As [`SyncState::to_cbor`].
    pub fn with_state(state: &SyncState) -> Result<Self> {
        Ok(Self {
            bytes: Some(state.to_cbor()?),
            saves: 0,
        })
    }

    /// How many times [`StateStore::save`] has returned `Ok`.
    #[must_use]
    pub const fn saves(&self) -> usize {
        self.saves
    }

    /// The persisted bytes, for a test that wants to simulate a restart by
    /// building a second store from them.
    #[must_use]
    pub fn persisted(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }
}

impl StateStore for MemoryStateStore {
    fn load(&self) -> Result<SyncState> {
        match &self.bytes {
            None => Ok(SyncState::new()),
            Some(bytes) => SyncState::from_cbor(bytes),
        }
    }

    fn save(&mut self, state: &SyncState) -> Result<()> {
        self.bytes = Some(state.to_cbor()?);
        self.saves = self.saves.saturating_add(1);
        Ok(())
    }
}

/// A file-backed state store.
///
/// Writes to a sibling temporary file, `fsync`s it, renames it over the target
/// and `fsync`s the directory. That sequence is what makes
/// [`StateStore::save`]'s atomicity requirement true on a POSIX filesystem: a
/// crash at any point leaves either the previous state or the new one, never a
/// blend of the two.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub struct FileStateStore {
    path: std::path::PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
impl FileStateStore {
    /// A store at `path`. The file need not exist yet.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn temp_path(&self) -> std::path::PathBuf {
        let mut path = self.path.clone();
        // A fixed suffix rather than a random one: there is one writer by
        // construction (the engine owns the store by value), so a second
        // temporary file would only be a second thing to leak.
        path.as_mut_os_string().push(".tmp");
        path
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl StateStore for FileStateStore {
    fn load(&self) -> Result<SyncState> {
        match std::fs::read(&self.path) {
            Ok(bytes) => SyncState::from_cbor(&bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(SyncState::new()),
            Err(_) => Err(SyncError::StateStore { operation: "load" }),
        }
    }

    fn save(&mut self, state: &SyncState) -> Result<()> {
        use std::io::Write as _;

        let bytes = state.to_cbor()?;
        let temp = self.temp_path();
        let fail = || SyncError::StateStore { operation: "save" };
        let mut file = std::fs::File::create(&temp).map_err(|_| fail())?;
        file.write_all(&bytes).map_err(|_| fail())?;
        file.sync_all().map_err(|_| fail())?;
        drop(file);
        std::fs::rename(&temp, &self.path).map_err(|_| fail())?;
        if let Some(parent) = self.path.parent() {
            // Renames are only durable once the directory entry is. Best effort:
            // a filesystem that cannot open a directory as a file still gets the
            // rename's own ordering guarantees.
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> SyncState {
        let mut state = SyncState::new();
        state.cursor = Some(42);
        state.known.insert(
            ItemId::from_bytes([7; 16]),
            KnownRow {
                kind: EnvelopeKind::Item.as_u8(),
                fingerprint: Some(Fingerprint::of(b"an envelope").expect("hash")),
                version: Some(ServerVersion::parse("v9").expect("version")),
                seq: Some(42),
            },
        );
        state.time = Some(TimeSample {
            measured_at_ms: 1,
            server_ms: 2,
            offset_ms: 1,
        });
        state.rotation = Some(RotationState { target_epoch: 3 });
        state
    }

    #[test]
    fn a_state_survives_a_round_trip_through_cbor() {
        let state = sample_state();
        let bytes = state.to_cbor().expect("encode");
        assert_eq!(SyncState::from_cbor(&bytes).expect("decode"), state);
    }

    #[test]
    fn a_state_from_a_newer_build_is_refused() {
        let mut state = SyncState::new();
        state.format_version = STATE_FORMAT_VERSION + 1;
        let bytes = state.to_cbor().expect("encode");
        assert!(matches!(
            SyncState::from_cbor(&bytes),
            Err(SyncError::StateTooNew { .. })
        ));
    }

    #[test]
    fn a_fingerprint_is_stable_and_separates_inputs() {
        let one = Fingerprint::of(b"envelope one").expect("hash");
        assert_eq!(one, Fingerprint::of(b"envelope one").expect("hash"));
        assert_ne!(one, Fingerprint::of(b"envelope two").expect("hash"));
        assert_ne!(one, Fingerprint::of(b"").expect("hash"));
    }

    #[test]
    fn only_items_and_groups_are_deletable_server_side() {
        for (kind, deletable) in [
            (EnvelopeKind::Item, true),
            (EnvelopeKind::Group, true),
            (EnvelopeKind::DeviceRoster, false),
            (EnvelopeKind::Settings, false),
            (EnvelopeKind::CustomIcon, false),
        ] {
            let row = KnownRow {
                kind: kind.as_u8(),
                fingerprint: Some(Fingerprint::of(b"x").expect("hash")),
                version: None,
                seq: None,
            };
            assert_eq!(row.is_deletable(), deletable, "{kind:?}");
        }
        // An unknown wire byte is not deletable either: refusing to act is the
        // right answer for an object this build does not understand.
        let row = KnownRow {
            kind: 200,
            fingerprint: Some(Fingerprint::of(b"x").expect("hash")),
            version: None,
            seq: None,
        };
        assert!(!row.is_deletable());
    }

    #[test]
    fn a_memory_store_starts_empty_and_counts_its_saves() {
        let mut store = MemoryStateStore::new();
        assert_eq!(store.load().expect("load"), SyncState::new());
        assert_eq!(store.saves(), 0);
        store.save(&sample_state()).expect("save");
        assert_eq!(store.saves(), 1);
        assert_eq!(store.load().expect("load"), sample_state());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn a_file_store_round_trips_and_leaves_no_temporary_behind() {
        let dir = std::env::temp_dir().join(format!("misty-sync-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("sync.state");
        let mut store = FileStateStore::new(&path);

        // Nothing written yet is not an error: it is a vault that has never synced.
        assert_eq!(store.load().expect("load"), SyncState::new());
        store.save(&sample_state()).expect("save");
        assert_eq!(store.load().expect("load"), sample_state());
        assert!(!path.with_extension("state.tmp").exists());

        // A second save replaces rather than appends.
        let mut second = sample_state();
        second.cursor = Some(99);
        store.save(&second).expect("save");
        assert_eq!(store.load().expect("load").cursor, Some(99));
        std::fs::remove_dir_all(&dir).ok();
    }
}
