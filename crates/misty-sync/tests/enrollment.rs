// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device-to-device enrollment end to end (SPEC §6.3), both sides, over the
//! transport.
//!
//! The cryptography is `misty-crypto`'s and is tested there. What is asserted here
//! is the *protocol*: that the QR payload survives a round trip, that the
//! camera-less path can read the request off the server, that the confirmation code
//! is what stops a substituted request, that the roster reaches the server before
//! the grant does, and that a device which joins this way can immediately decrypt
//! and sync the vault it was invited into.

mod support;

use misty_crypto::identity::Roster;
use misty_otp::FixedClock;
use misty_sync::runtime::block_on;
use misty_sync::state::MemoryStateStore;
use misty_sync::{
    duplicate_identity, enroll, Approval, Enrollment, PendingApproval, SyncConfig, SyncEngine,
    ENROLL_QR_PREFIX,
};
use misty_vault::{MemoryStore, Vault};
use support::{device, vault_key, Fixture, NOW};

/// What every approval in this file grants: the shared vault key, an origin, and a
/// fixed enrolment timestamp.
fn grant_details() -> misty_sync::GrantDetails<'static> {
    // Leaked on purpose: a `'static` borrow of a key is exactly what a test wants
    // and exactly what production code should not have.
    misty_sync::GrantDetails {
        vault_key: Box::leak(Box::new(vault_key())),
        server_url: "https://sync.example",
        enrolled_at: NOW as i64,
    }
}

/// The new device's keys. Not in any roster yet, which is the whole point.
fn newcomer() -> misty_crypto::identity::DeviceIdentity {
    device(42)
}

#[test]
fn the_qr_payload_round_trips_and_carries_the_confirmation_code() {
    let joiner = newcomer();
    let enrollment = Enrollment::begin(&joiner, "Ada's Pixel", "android").expect("begin");
    let payload = enrollment.qr_payload().expect("qr");
    assert!(payload.starts_with(ENROLL_QR_PREFIX));

    let scanned = PendingApproval::from_qr(&payload).expect("scan");
    assert_eq!(scanned.device_name(), "Ada's Pixel");
    assert_eq!(scanned.platform(), "android");
    assert_eq!(scanned.device_id(), joiner.device_id());
    assert_eq!(
        scanned.confirmation_code(),
        enrollment.confirmation_code(),
        "the code the user compares is a function of the payload"
    );
    assert_eq!(scanned.confirmation_code().len(), 6);
    assert!(scanned.confirmation_code().chars().all(char::is_numeric));

    // Anything that is not this scheme is refused rather than guessed at.
    for text in [
        "",
        "misty-recovery:v1:AAAA",
        "misty-enroll:v2:AAAA",
        "nonsense",
    ] {
        assert!(PendingApproval::from_qr(text).is_err(), "accepted {text:?}");
    }
}

#[test]
fn a_new_device_joins_and_syncs_the_vault_it_was_invited_into() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    let secret = b"aaaaaaaaaaaaaaaa";
    let id = alice.add("GitHub", "ada@example.com", secret);
    alice.sync_ok();

    // --- new device -------------------------------------------------------
    let joiner = newcomer();
    let enrollment = Enrollment::begin(&joiner, "Ada's Pixel", "android").expect("begin");
    let mut joiner_client = misty_sync::SyncClient::new(
        fixture.server.transport(),
        fixture.config(),
        duplicate_identity(&joiner),
    );
    block_on(enrollment.publish(&mut joiner_client)).expect("publish");

    // --- existing device --------------------------------------------------
    // The camera-less path: the user reads six digits off the new device and the
    // approver fetches the request behind them.
    let approval = block_on(PendingApproval::fetch(
        alice.engine.client_mut(),
        &enrollment.enroll_id(),
    ))
    .expect("poll")
    .expect("the request is published");
    assert_eq!(approval.confirmation_code(), enrollment.confirmation_code());

    // A wrong code refuses to seal anything at all.
    let wrong = block_on(alice.engine.approve_enrollment(
        &alice.vault,
        &alice.roster,
        &approval,
        "000000",
        &grant_details(),
    ));
    assert!(
        matches!(
            wrong,
            Err(misty_sync::SyncError::Crypto(
                misty_crypto::Error::ConfirmationCodeMismatch
            ))
        ),
        "{wrong:?}"
    );

    let outcome = block_on(alice.engine.approve_enrollment(
        &alice.vault,
        &alice.roster,
        &approval,
        &approval.confirmation_code(),
        &grant_details(),
    ))
    .expect("approve");
    let Approval::Approved { roster, record } = outcome else {
        panic!("expected an approval, got {outcome:?}");
    };
    assert_eq!(record.device_id, joiner.device_id());
    assert_eq!(roster.devices.len(), 2);

    // The roster is on the server *before* the grant, so no device can hold the
    // vault key while every peer rejects its writes.
    let address = misty_sync::roster::roster_item_id(&vault_key()).expect("address");
    assert!(fixture.server.envelope_of(&address).is_some());

    // --- new device, again ------------------------------------------------
    let grant = block_on(enrollment.poll(&mut joiner_client))
        .expect("poll")
        .expect("the grant is waiting");
    assert_eq!(grant.vault_id, fixture.config().vault_id);
    assert_eq!(grant.server_url, "https://sync.example");
    assert_eq!(grant.roster.devices.len(), 2);
    assert!(grant.vault_key.constant_time_eq(&vault_key()));

    // It opens a vault with what it was granted and syncs. Nothing else was needed:
    // the roster in the grant is the trust anchor, and it chains to alice.
    let mut newborn = Vault::open(
        MemoryStore::new(),
        FixedClock::new(NOW),
        misty_crypto::keys::VaultKey::from_bytes(*grant.vault_key.expose_secret()),
        duplicate_identity(&joiner),
        grant.roster.clone(),
    )
    .expect("open the granted vault");
    let mut engine = SyncEngine::new(
        fixture.server.transport(),
        SyncConfig::new(grant.vault_id, fixture.server.time_public_key()),
        duplicate_identity(&joiner),
        MemoryStateStore::new(),
    )
    .expect("engine");
    fixture.server.register(&joiner);

    let report = block_on(engine.sync_once(&mut newborn, &grant.roster)).expect("sync");
    assert!(report.applied >= 1, "{report:?}");
    let item = newborn.item(&id).expect("the item arrived");
    assert_eq!(item.issuer(), "GitHub");
    assert_eq!(item.account(), "ada@example.com");
    assert_eq!(
        item.otp().expect("otp").secret().expose_secret(),
        secret,
        "and it decrypts: the grant really did carry the vault key"
    );
}

#[test]
fn a_substituted_request_cannot_be_approved_by_a_user_who_compared_the_code() {
    // The `A6` attack in its active form: the server replaces the published request
    // with one naming its own keys, hoping the approver seals a grant to it. Two
    // things stop it, and this test exercises both: `POST /v1/enroll/begin` is
    // create-only, so an id that has been published cannot be overwritten; and if
    // the impostor gets there *first*, the confirmation code — which covers
    // `x25519_pub`, `ed25519_pub` and `device_id` — no longer matches the six digits
    // the user is reading off the real device.
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);

    let honest = Enrollment::begin(&newcomer(), "Ada's Pixel", "android").expect("begin");
    let mut client = misty_sync::SyncClient::new(
        fixture.server.transport(),
        fixture.config(),
        duplicate_identity(&newcomer()),
    );
    block_on(honest.publish(&mut client)).expect("publish");

    // The impostor reuses the enroll_id — the only field the approver looks up by —
    // and substitutes everything else.
    let impostor_keys = device(43);
    let mut impostor = Enrollment::begin(&impostor_keys, "Ada's Pixel", "android")
        .expect("begin")
        .request()
        .clone();
    impostor.enroll_id = honest.enroll_id();
    let mut impostor_client = misty_sync::SyncClient::new(
        fixture.server.transport(),
        fixture.config(),
        duplicate_identity(&impostor_keys),
    );
    let refused = block_on(impostor_client.enroll_begin(
        &impostor.enroll_id,
        &impostor.x25519_pub,
        &enroll::encode_request(&impostor).expect("encode"),
    ));
    assert!(
        matches!(
            refused,
            Err(misty_sync::SyncError::Server { status: 409, .. })
        ),
        "an id that is already published cannot be overwritten: {refused:?}"
    );

    // Now the harder case: the impostor publishes first, under an id it chose, so
    // there is nothing to overwrite. The approver fetches what the server has, and
    // the code it would display is not the one on the real device's screen.
    let fixture = Fixture::new(1);
    let mut alice2 = fixture.peer(0);
    let mut impostor_client = misty_sync::SyncClient::new(
        fixture.server.transport(),
        fixture.config(),
        duplicate_identity(&impostor_keys),
    );
    block_on(impostor_client.enroll_begin(
        &impostor.enroll_id,
        &impostor.x25519_pub,
        &enroll::encode_request(&impostor).expect("encode"),
    ))
    .expect("the impostor got there first");

    let fetched = block_on(PendingApproval::fetch(
        alice2.engine.client_mut(),
        &honest.enroll_id(),
    ))
    .expect("poll")
    .expect("something is published");
    assert_ne!(
        fetched.confirmation_code(),
        honest.confirmation_code(),
        "the code the approver would display is not the one the user is reading"
    );

    // The user types what the *real* new device showed, and the approval fails.
    let refused = block_on(alice2.engine.approve_enrollment(
        &alice2.vault,
        &alice2.roster,
        &fetched,
        &honest.confirmation_code(),
        &grant_details(),
    ));
    assert!(
        matches!(
            refused,
            Err(misty_sync::SyncError::Crypto(
                misty_crypto::Error::ConfirmationCodeMismatch
            ))
        ),
        "{refused:?}"
    );
    // Nothing was sealed, and the roster was not published either.
    let address = misty_sync::roster::roster_item_id(&vault_key()).expect("address");
    assert!(fixture.server.envelope_of(&address).is_none());
    let _ = &mut alice;
}

#[test]
fn a_grant_from_another_enrollment_does_not_open() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    let joiner = newcomer();

    let first = Enrollment::begin(&joiner, "Pixel", "android").expect("begin");
    let second = Enrollment::begin(&joiner, "Pixel", "android").expect("begin");
    let mut client = misty_sync::SyncClient::new(
        fixture.server.transport(),
        fixture.config(),
        duplicate_identity(&joiner),
    );
    block_on(first.publish(&mut client)).expect("publish");

    let approval = block_on(PendingApproval::fetch(
        alice.engine.client_mut(),
        &first.enroll_id(),
    ))
    .expect("poll")
    .expect("published");
    block_on(alice.engine.approve_enrollment(
        &alice.vault,
        &alice.roster,
        &approval,
        &approval.confirmation_code(),
        &grant_details(),
    ))
    .expect("approve");

    // The second enrollment polls its own id and finds nothing; if it could be
    // pointed at the first one's grant, the ephemeral key would not match.
    assert!(block_on(second.poll(&mut client)).expect("poll").is_none());
    assert!(block_on(first.poll(&mut client)).expect("poll").is_some());
}

#[test]
fn an_unsigned_roster_is_never_pushed() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    let unsigned = Roster::new(alice.roster.devices.clone());
    let error = block_on(
        alice
            .engine
            .push_roster(&alice.vault, &unsigned, &vault_key()),
    )
    .expect_err("an unsigned roster is not a roster");
    assert!(
        matches!(
            error,
            misty_sync::SyncError::Crypto(misty_crypto::Error::RosterUnsigned)
        ),
        "{error:?}"
    );
}
