// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared harness for the integration tests.
//!
//! Everything here is deterministic: fixed device keys, a fixed vault key, a fixed
//! clock. A convergence failure or a crash-injection failure has to be
//! reproducible from the seed alone, and a test that draws real entropy is a test
//! that fails once a month for reasons nobody can reconstruct.

#![allow(dead_code, reason = "each test binary uses a different part of this")]

use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::keys::VaultKey;
use misty_crypto::{DeviceId, ItemId};
use misty_otp::{FixedClock, OtpConfig, OtpKind, SecretBytes};
use misty_vault::{MemoryStore, NewItem, RemoteChange, Vault, VaultStore};

/// Somewhere in 2027, comfortably inside the `Hlc` window.
pub const NOW: u64 = 1_800_000_000_000;

/// A device whose keys are a function of `seed`, so a failing case is replayable.
pub fn device(seed: u8) -> DeviceIdentity {
    DeviceIdentity::from_secret_bytes(
        DeviceId::from_bytes([seed; 16]),
        &[seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
    )
}

/// A roster holding `devices`, signed by the first of them.
pub fn roster(devices: &[&DeviceIdentity]) -> Roster {
    let records = devices
        .iter()
        .enumerate()
        .map(|(index, device)| {
            device
                .record(&format!("device {index}"), "linux", 1, None)
                .expect("record")
        })
        .collect();
    let mut roster = Roster::new(records);
    roster
        .sign(devices.first().expect("at least one device"))
        .expect("sign");
    roster
}

/// The vault key every test uses. Fixed so forked item ids are reproducible.
pub fn vault_key() -> VaultKey {
    VaultKey::from_bytes([0x5a; 32])
}

/// A TOTP config over `secret`.
pub fn totp(secret: &[u8]) -> OtpConfig {
    OtpConfig::totp(SecretBytes::from_slice(secret)).expect("totp")
}

/// A HOTP config over `secret`, starting at `counter`.
pub fn hotp(secret: &[u8], counter: u64) -> OtpConfig {
    OtpConfig::builder(OtpKind::Hotp, SecretBytes::from_slice(secret))
        .counter(counter)
        .build()
        .expect("hotp")
}

/// A minimal `NewItem`.
pub fn new_item(issuer: &str, account: &str, secret: &[u8]) -> NewItem {
    NewItem::new(totp(secret), issuer, account)
}

/// A vault on a memory store, at a clock frozen at [`NOW`].
pub fn vault(device_seed: u8) -> Vault<MemoryStore, FixedClock> {
    let identity = device(device_seed);
    let roster = roster(&[&identity]);
    Vault::open(
        MemoryStore::new(),
        FixedClock::new(NOW),
        vault_key(),
        identity,
        roster,
    )
    .expect("open")
}

/// A vault whose roster holds `seeds`, opened as the first of them.
pub fn vault_for(
    seeds: &[u8],
    store: MemoryStore,
    clock: FixedClock,
) -> Vault<MemoryStore, FixedClock> {
    let identities: Vec<DeviceIdentity> = seeds.iter().copied().map(device).collect();
    let refs: Vec<&DeviceIdentity> = identities.iter().collect();
    let roster = roster(&refs);
    let first = identities.into_iter().next().expect("a device");
    Vault::open(store, clock, vault_key(), first, roster).expect("open")
}

/// A vault for device `as_seed`, on a roster holding every seed in `seeds`.
///
/// This is what makes a multi-device test work: every device has to be in one
/// roster or the envelopes one writes will not verify on another (SPEC §6.2).
pub fn peer(as_seed: u8, seeds: &[u8], clock_ms: u64) -> Vault<MemoryStore, FixedClock> {
    let identities: Vec<DeviceIdentity> = seeds.iter().copied().map(device).collect();
    let refs: Vec<&DeviceIdentity> = identities.iter().collect();
    let roster = roster(&refs);
    Vault::open(
        MemoryStore::new(),
        FixedClock::new(clock_ms),
        vault_key(),
        device(as_seed),
        roster,
    )
    .expect("open")
}

/// Every stored row of `from`, as a change feed a peer can merge.
///
/// This is the whole sync protocol as far as this crate is concerned: SPEC §6.1's
/// feed is `{item_id, seq, version, envelope}` and nothing else, and in particular
/// no `deleted` flag — a delete travels as a signed tombstone inside the payload.
pub fn changes(from: &Vault<MemoryStore, FixedClock>) -> Vec<RemoteChange> {
    from.store()
        .load_all()
        .expect("load_all")
        .into_iter()
        .map(|row| RemoteChange {
            item_id: row.item_id,
            seq: row.seq,
            version: row.version,
            envelope: row.envelope,
        })
        .collect()
}

/// One row of `from`, as a change.
pub fn change_for(from: &Vault<MemoryStore, FixedClock>, id: &ItemId) -> RemoteChange {
    let row = from.stored(id).expect("stored").expect("a row for that id");
    RemoteChange {
        item_id: row.item_id,
        seq: row.seq,
        version: row.version,
        envelope: row.envelope,
    }
}

/// Merges everything `from` holds into `into`.
pub fn sync(
    from: &Vault<MemoryStore, FixedClock>,
    into: &mut Vault<MemoryStore, FixedClock>,
) -> misty_vault::MergeReport {
    into.merge_remote(&changes(from)).expect("merge_remote")
}

/// The fingerprint SPEC §4's "byte-identical state" is measured on.
pub fn fingerprint(vault: &Vault<MemoryStore, FixedClock>) -> Vec<u8> {
    vault
        .item_set()
        .fingerprint()
        .expect("fingerprint")
        .to_vec()
}
