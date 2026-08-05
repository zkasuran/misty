// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared harness for the integration tests.
//!
//! Deterministic throughout: fixed device keys, a fixed vault key, a fixed clock.
//! A convergence or interruption failure has to be reproducible from the seed
//! alone; a test that draws real entropy is one that fails once a month for
//! reasons nobody can reconstruct. The two exceptions are the mock server's
//! `/v1/time` signing keys, which it generates itself and the test pins from it,
//! and envelope nonces, which `misty-crypto` always draws freshly.

#![allow(dead_code, reason = "each test binary uses a different part of this")]

use misty_crypto::identity::{DeviceIdentity, DeviceRecord, Roster};
use misty_crypto::keys::VaultKey;
use misty_crypto::{DeviceId, ItemId, VaultId};
use misty_otp::{FixedClock, OtpConfig, SecretBytes};
use misty_sync::runtime::block_on;
use misty_sync::state::MemoryStateStore;
use misty_sync::transport::MockTransport;
use misty_sync::{duplicate_identity, MockServer, SyncConfig, SyncEngine, SyncReport};
use misty_vault::{Edit, MemoryStore, NewItem, Vault};

/// Somewhere in 2027, comfortably inside the `Hlc` window.
pub const NOW: u64 = 1_800_000_000_000;

/// The vault every test syncs.
pub fn vault_id() -> VaultId {
    VaultId::from_bytes([0x11; 16])
}

/// The vault key every device in a test shares.
pub fn vault_key() -> VaultKey {
    VaultKey::from_bytes([0x5a; 32])
}

/// A second handle onto the same key material.
pub fn clone_vault_key(key: &VaultKey) -> VaultKey {
    VaultKey::from_bytes(*key.expose_secret())
}

/// A device whose keys are a function of `seed`, so a failing case is replayable.
pub fn device(seed: u8) -> DeviceIdentity {
    DeviceIdentity::from_secret_bytes(
        DeviceId::from_bytes([seed; 16]),
        &[seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
    )
}

/// A roster record for `identity`.
pub fn record(identity: &DeviceIdentity, name: &str) -> DeviceRecord {
    identity.record(name, "linux", 1, None).expect("record")
}

/// A roster holding `devices`, signed by the first of them.
pub fn roster(devices: &[&DeviceIdentity]) -> Roster {
    let records = devices
        .iter()
        .enumerate()
        .map(|(index, device)| record(device, &format!("device {index}")))
        .collect();
    let mut roster = Roster::new(records);
    roster
        .sign(devices.first().expect("at least one device"))
        .expect("sign");
    roster
}

/// A TOTP config over `secret`.
pub fn totp(secret: &[u8]) -> OtpConfig {
    OtpConfig::totp(SecretBytes::from_slice(secret)).expect("totp")
}

/// The concrete vault every test uses.
pub type TestVault = Vault<MemoryStore, FixedClock>;

/// The concrete engine every test uses.
pub type TestEngine = SyncEngine<MockTransport, MemoryStateStore>;

/// One simulated device: a vault, an engine, and the roster it trusts.
///
/// Generic over the state store so the interruption suite can substitute one that
/// fails on demand; every other test uses the default.
pub struct Peer<S: misty_sync::StateStore = MemoryStateStore> {
    pub vault: TestVault,
    pub engine: SyncEngine<MockTransport, S>,
    pub roster: Roster,
}

impl<S: misty_sync::StateStore> Peer<S> {
    /// One pull-then-push round.
    pub fn sync(&mut self) -> misty_sync::Result<SyncReport> {
        block_on(self.engine.sync_once(&mut self.vault, &self.roster))
    }

    /// Sync, asserting success.
    pub fn sync_ok(&mut self) -> SyncReport {
        self.sync().expect("sync")
    }

    /// Adds an item and returns its id.
    pub fn add(&mut self, issuer: &str, account: &str, secret: &[u8]) -> ItemId {
        self.vault
            .add(NewItem::new(totp(secret), issuer, account))
            .expect("add")
    }

    /// Edits an item's nickname.
    pub fn rename(&mut self, id: &ItemId, nickname: &str) {
        self.vault
            .update(id, Edit::new().nickname(Some(nickname.to_owned())))
            .expect("update");
    }

    /// The decrypted model, as a comparable summary.
    ///
    /// Byte-identical state is the property SPEC §4 states, and the envelope bytes
    /// cannot be compared directly: every re-seal draws fresh nonces, so two
    /// devices holding the *same* item hold different ciphertext. What must match
    /// is the model, and the CBOR the vault would write for it is that model's
    /// canonical form — `encode_item` is deterministic and
    /// `tests/wire_format.rs` in `misty-vault` pins it.
    pub fn digest(&self) -> Vec<(ItemId, Vec<u8>)> {
        let mut out: Vec<(ItemId, Vec<u8>)> = self
            .vault
            .item_set()
            .iter()
            .map(|item| {
                (
                    item.id(),
                    misty_vault::encode_item(item).expect("encode").to_vec(),
                )
            })
            .collect();
        out.sort_by_key(|(id, _)| *id);
        out
    }
}

/// Seals an envelope the way a device would, for tests that need the server to
/// hold something no honest client of *this* vault would have written.
pub fn seal(
    kind: misty_crypto::envelope::EnvelopeKind,
    item_id: &ItemId,
    payload: &[u8],
    signer: &DeviceIdentity,
) -> Vec<u8> {
    let key = vault_key();
    let epoch_key = misty_crypto::derive::epoch_key(&key, 0).expect("epoch key");
    misty_crypto::envelope::seal(kind, 0, item_id, payload, &epoch_key, signer).expect("seal")
}

/// A mock server plus however many devices a test needs, all sharing one vault
/// key and one roster.
pub struct Fixture {
    pub server: MockServer,
    pub roster: Roster,
    identities: Vec<DeviceIdentity>,
}

impl Fixture {
    /// `count` devices, all in one roster signed by the first, all registered with
    /// a fresh server.
    pub fn new(count: usize) -> Self {
        let identities: Vec<DeviceIdentity> = (0..count)
            .map(|index| device(u8::try_from(index).expect("few devices") + 1))
            .collect();
        let borrowed: Vec<&DeviceIdentity> = identities.iter().collect();
        let roster = roster(&borrowed);
        let server = MockServer::new(vault_id()).expect("mock server");
        for identity in &identities {
            server.register(identity);
        }
        Self {
            server,
            roster,
            identities,
        }
    }

    /// One device's identity.
    pub fn identity(&self, index: usize) -> &DeviceIdentity {
        self.identities.get(index).expect("device index")
    }

    /// The config a peer uses: this vault, and the server's real time key pinned.
    pub fn config(&self) -> SyncConfig {
        SyncConfig::new(vault_id(), self.server.time_public_key())
    }

    /// Builds a peer for device `index`, with a fresh state store.
    pub fn peer(&self, index: usize) -> Peer {
        self.peer_with_store(index, MemoryStateStore::new())
    }

    /// Builds a peer for device `index` over any state store.
    pub fn peer_with_store<S: misty_sync::StateStore>(&self, index: usize, store: S) -> Peer<S> {
        self.peer_with(index, store, self.roster.clone())
    }

    /// Builds a peer that trusts `roster` rather than the fixture's original — how
    /// a device that has adopted a successor roster is simulated.
    pub fn peer_with_roster(&self, index: usize, roster: Roster) -> Peer {
        self.peer_with(index, MemoryStateStore::new(), roster)
    }

    fn peer_with<S: misty_sync::StateStore>(
        &self,
        index: usize,
        store: S,
        roster: Roster,
    ) -> Peer<S> {
        let identity = self.identity(index);
        let vault = Vault::open(
            MemoryStore::new(),
            FixedClock::new(NOW),
            vault_key(),
            duplicate_identity(identity),
            roster.clone(),
        )
        .expect("open vault");
        let engine = SyncEngine::new(
            self.server.transport(),
            self.config(),
            duplicate_identity(identity),
            store,
        )
        .expect("engine");
        Peer {
            vault,
            engine,
            roster,
        }
    }

    /// Rebuilds an engine for `index` from the bytes a store had persisted,
    /// keeping the vault it already had. This is what "the process restarted"
    /// means: the vault's rows and this crate's state both survive, and nothing
    /// in memory does.
    pub fn restart<S: misty_sync::StateStore>(&self, peer: Peer<S>, index: usize) -> Peer {
        let persisted = peer
            .engine
            .state()
            .to_cbor()
            .expect("encode persisted state");
        self.resume(peer, index, Some(&persisted))
    }

    /// Rebuilds an engine over exactly `bytes` — what a store actually wrote to
    /// disk — keeping the vault the peer already had.
    ///
    /// This is the honest version of a restart for a store whose last save failed:
    /// the engine's in-memory state is *ahead* of the bytes in that case, and
    /// resuming from memory would test a process that did not die.
    pub fn resume<S: misty_sync::StateStore>(
        &self,
        peer: Peer<S>,
        index: usize,
        bytes: Option<&[u8]>,
    ) -> Peer {
        let store = match bytes {
            None => MemoryStateStore::new(),
            Some(bytes) => MemoryStateStore::with_state(
                &misty_sync::SyncState::from_cbor(bytes).expect("decode persisted state"),
            )
            .expect("store"),
        };
        let engine = SyncEngine::new(
            self.server.transport(),
            self.config(),
            duplicate_identity(self.identity(index)),
            store,
        )
        .expect("engine");
        Peer {
            vault: peer.vault,
            engine,
            roster: peer.roster,
        }
    }
}

/// Syncs both peers until neither has anything left to do.
///
/// Two rounds each, alternating, is enough for every case in this suite: a write
/// lands on the server in the first round and is pulled in the other peer's next
/// one. The loop runs to a fixed point anyway, so a case needing more does not
/// silently pass on a stale assertion.
pub fn converge<A: misty_sync::StateStore, B: misty_sync::StateStore>(
    left: &mut Peer<A>,
    right: &mut Peer<B>,
) {
    for _ in 0..6 {
        let a = left.sync_ok();
        let b = right.sync_ok();
        if a.is_quiet() && b.is_quiet() && a.pending_after == 0 && b.pending_after == 0 {
            return;
        }
    }
    let a = left.sync_ok();
    let b = right.sync_ok();
    assert!(
        a.is_quiet() && b.is_quiet(),
        "did not reach a fixed point: {a:?} / {b:?}"
    );
}
