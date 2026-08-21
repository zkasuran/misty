// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The native slice of the SPEC §11.8 conformance flow, driven through the real
//! facade compiled with `MemoryStore` + `MockTransport` (§11.8.1) — a build
//! configuration, not a hand-written mock.
//!
//! This covers add → generate → sync (two devices converging through one
//! `MockServer`) → lock → unlock, plus the auto-lock deadline and a lifecycle event.
//! The live enrollment and revocation protocol steps are the next increment; here the
//! two devices are placed in a pre-signed roster, as the sync crate's own harness does.

use std::future::Future;

use misty::dto::{HashAlg, NewItemInput, OtpKind, SortKey};
use misty::{ErrorCode, Facade, LifecycleEvent, ManualClock};

use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::{DeviceId, VaultId};
use misty_otp::FixedClock;
use misty_sync::{duplicate_identity, MemoryStateStore, MockServer, SyncConfig, SyncEngine};
use misty_vault::MemoryStore;

use futures::executor::LocalPool;
use futures::task::LocalSpawnExt;

/// A fixed wall-clock reading inside the §4.1 HLC window, so both devices generate
/// the same code deterministically.
const NOW: u64 = 1_700_000_000_000;
/// The auto-lock timeout the facade is configured with.
const TIMEOUT_MS: i64 = 60_000;
/// The shared vault key both devices unlock with (obvious dummy, per §8 fixtures).
const VAULT_KEY: [u8; 32] = [0x2b; 32];

fn device(seed: u8) -> DeviceIdentity {
    DeviceIdentity::from_secret_bytes(
        DeviceId::from_bytes([seed; 16]),
        &[seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
    )
}

fn vault_id() -> VaultId {
    VaultId::from_bytes([0x11; 16])
}

fn roster(devices: &[&DeviceIdentity]) -> Roster {
    let records = devices
        .iter()
        .enumerate()
        .map(|(i, d)| {
            d.record(&format!("device {i}"), "linux", 1, None)
                .expect("record")
        })
        .collect();
    let mut roster = Roster::new(records);
    roster.sign(devices[0]).expect("sign roster");
    roster
}

fn new_totp() -> NewItemInput {
    NewItemInput {
        kind: OtpKind::Totp,
        algorithm: HashAlg::Sha1,
        digits: 6,
        period: 30,
        hotp_counter: 0,
        secret: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        pin: None,
        issuer: "GitHub".to_string(),
        account: "ada@example.com".to_string(),
        nickname: None,
        note: None,
        groups: Vec::new(),
        tags: Vec::new(),
        origins: Vec::new(),
        icon: None,
        color: None,
        favorite: false,
    }
}

fn peer(
    seed: u8,
    roster: &Roster,
    server: &MockServer,
    host: ManualClock,
) -> (Facade, impl Future<Output = ()>) {
    let identity = device(seed);
    let config = SyncConfig::new(vault_id(), server.time_public_key());
    let engine = SyncEngine::new(
        server.transport(),
        config,
        duplicate_identity(&identity),
        MemoryStateStore::new(),
    )
    .expect("engine");
    misty::spawn(
        MemoryStore::new(),
        FixedClock::new(NOW),
        identity,
        roster.clone(),
        engine,
        host,
        TIMEOUT_MS,
    )
}

#[test]
fn conformance_flow() {
    let dev_a = device(1);
    let dev_b = device(2);
    let roster = roster(&[&dev_a, &dev_b]);
    let server = MockServer::new(vault_id()).expect("server");
    server.register(&dev_a);
    server.register(&dev_b);

    let host_a = ManualClock::new(0);
    let (facade_a, task_a) = peer(1, &roster, &server, host_a.clone());
    let (facade_b, task_b) = peer(2, &roster, &server, ManualClock::new(0));

    let mut pool = LocalPool::new();
    pool.spawner().spawn_local(task_a).expect("spawn a");
    pool.spawner().spawn_local(task_b).expect("spawn b");

    pool.run_until(async move {
        facade_a.unlock(VAULT_KEY.to_vec()).await.unwrap();
        facade_b.unlock(VAULT_KEY.to_vec()).await.unwrap();

        let id = facade_a.add(new_totp()).await.unwrap();
        let code_a = facade_a.generate_code(id.clone()).await.unwrap();
        assert_eq!(code_a.code.len(), 6);

        // A pushes, B pulls: the two converge through one server.
        facade_a.sync_once().await.unwrap();
        facade_b.sync_once().await.unwrap();

        let items_b = facade_b.list().await.unwrap();
        assert_eq!(items_b.len(), 1);
        assert_eq!(items_b[0].issuer, "GitHub");
        let code_b = facade_b.generate_code(items_b[0].id.clone()).await.unwrap();
        assert_eq!(code_a.code, code_b.code, "both devices agree on the code");

        // The broadened read + item/group-lifecycle surface, on A.
        assert_eq!(
            facade_a.search("GitHub".to_string()).await.unwrap().len(),
            1
        );
        assert_eq!(facade_a.sorted(SortKey::Issuer).await.unwrap().len(), 1);
        let gid = facade_a.add_group("Work".to_string()).await.unwrap();
        assert_eq!(facade_a.groups().await.unwrap().len(), 1);
        assert_eq!(facade_a.group(gid.clone()).await.unwrap().name, "Work");

        // update(): set a nickname, replace the tag set, and put the item in the group.
        let edit = misty::dto::EditInput {
            nickname: Some("work github".to_string()),
            tags: Some(vec!["work".to_string()]),
            groups: Some(vec![gid.clone()]),
            ..Default::default()
        };
        facade_a.update(id.clone(), edit).await.unwrap();
        let v = facade_a.item(id.clone()).await.unwrap();
        assert_eq!(v.nickname.as_deref(), Some("work github"));
        assert_eq!(v.tags, vec!["work".to_string()]);
        assert_eq!(v.groups, vec![gid.clone()]);

        facade_a.record_use(id.clone()).await.unwrap();
        assert_eq!(facade_a.item(id.clone()).await.unwrap().use_count, 1);
        facade_a.trash_item(id.clone()).await.unwrap();
        assert_eq!(facade_a.trash().await.unwrap().len(), 1);
        assert!(facade_a.list().await.unwrap().is_empty());
        facade_a.restore_item(id.clone()).await.unwrap();
        assert_eq!(facade_a.list().await.unwrap().len(), 1);
        facade_a.delete_group(gid).await.unwrap();
        assert!(facade_a
            .groups()
            .await
            .unwrap()
            .iter()
            .all(|g| g.is_deleted));

        // Explicit lock on B; reads and sync then fail with the stable VAULT_LOCKED code.
        facade_b.lock().await.unwrap();
        assert!(facade_b.lock_state().await.unwrap().locked);
        assert_eq!(
            facade_b.list().await.unwrap_err().code,
            ErrorCode::VaultLocked
        );
        assert_eq!(
            facade_b.sync_once().await.unwrap_err().code,
            ErrorCode::VaultLocked
        );

        // Auto-lock on A: advancing the host clock past the deadline locks on the next wake.
        assert!(!facade_a.lock_state().await.unwrap().locked);
        host_a.advance(TIMEOUT_MS + 1);
        assert!(facade_a.poll().await.unwrap().locked, "A auto-locks");

        // Unlock again, revoke B (§6.4), then a lifecycle event relocks immediately.
        facade_a.unlock(VAULT_KEY.to_vec()).await.unwrap();
        assert!(!facade_a.lock_state().await.unwrap().locked);

        // Revoke device B: the epoch rotates, the vault is re-sealed and re-opened
        // under a successor roster, and A keeps working — the code survives.
        facade_a
            .revoke_device(dev_b.device_id().to_hex())
            .await
            .unwrap();
        let code_after = facade_a.generate_code(id.clone()).await.unwrap();
        assert_eq!(code_after.code, code_a.code, "code survives epoch rotation");
        facade_a.sync_once().await.unwrap();

        assert!(
            facade_a
                .report_lifecycle(LifecycleEvent::Backgrounded)
                .await
                .unwrap()
                .locked,
            "backgrounding locks immediately"
        );

        facade_a.shutdown().await.unwrap();
        facade_b.shutdown().await.unwrap();
    });
}
