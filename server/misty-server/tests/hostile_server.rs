// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile-server tests: what an attacker who *is* the server can and cannot do.
//!
//! Every test here gives the attacker the operator's full powers — the database,
//! the signing key, the ability to write any row — and then checks that the client
//! is unharmed. These are the tests that make the zero-knowledge claim in
//! `README.md` a fact rather than a promise, and they are the exit gate for
//! ROADMAP P4.
//!
//! The client side is the real `misty-crypto`, not a stub. When a test says "the
//! client rejects this", it means `misty_crypto::envelope::open` rejects it.

mod common;

use common::{b64_decode, b64_encode, bootstrap, Harness, Vault};
use misty_crypto::enrollment::{GrantContents, NewDeviceEnrollment, SealedEnrollment};
use misty_crypto::envelope::{self, EnvelopeKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::{derive, ItemId as CryptoItemId};
use misty_server::store::{Limits, Precondition, Store, WriteOutcome};
use misty_server::time_key::{now_unix_ms, verify_time};
use misty_server::{DeviceId, ItemId, VaultId};

const LIMITS: Limits = Limits {
    max_rows: 10_000,
    max_bytes: 64 * 1024 * 1024,
};

/// Reads one item's current envelope and version straight from the feed.
async fn current(harness: &Harness, bearer: &str, vault: VaultId) -> (u64, Vec<u8>) {
    let reply = harness
        .send(
            "GET",
            &format!("/v1/vaults/{}/changes?since=0", vault.to_hex()),
            &[("Authorization", bearer)],
            None,
        )
        .await;
    reply.expect_status(200);
    let entry = reply.value()["changes"][0].clone();
    // §6.1.1 makes `version` an opaque token, so a test that needs the internal
    // counter has to parse the token the way nothing else is allowed to.
    (
        entry["version"].as_str().unwrap().parse().unwrap(),
        b64_decode(entry["envelope"].as_str().unwrap()),
    )
}

#[tokio::test]
async fn an_injected_device_cannot_produce_a_write_any_client_accepts() {
    let harness = Harness::start().await;
    let owner = bootstrap(&harness).await;
    let vault = Vault::new(&owner.identity);

    // The operator injects a device into its own access-control table, vouched
    // for by a device it can read out of the database. This is the strongest form
    // of the attack: the row is indistinguishable from a legitimate one.
    let attacker = DeviceIdentity::generate().unwrap();
    let attacker_id = DeviceId::from_bytes(*attacker.device_id().as_bytes());
    let admission = harness
        .store
        .admit_device(
            owner.vault,
            attacker_id,
            attacker.ed25519_public(),
            Some(owner.device),
            now_unix_ms(),
            None,
        )
        .unwrap();
    assert_eq!(
        admission,
        misty_server::store::Admission::Admitted,
        "the operator can always write its own tables; that is the premise"
    );

    // And it authenticates, because the server believes its own table.
    let injected = common::join(&harness, owner.vault, attacker, &[]).await;

    // Now hand the attacker the *vault key as well* — far beyond the threat
    // model, and it still gains nothing, because trust lives in the
    // client-signed roster and the attacker is not in it (SPEC §6.2).
    let item = ItemId::from_bytes(common::random16());
    let forged = vault.seal(&item, b"an item the user never created", &injected.identity);
    harness
        .json(
            "PUT",
            &format!(
                "/v1/vaults/{}/items/{}",
                owner.vault.to_hex(),
                item.to_hex()
            ),
            &[
                ("Authorization", &injected.bearer()),
                ("If-None-Match", "*"),
            ],
            &serde_json::json!({ "envelope": b64_encode(&forged) }),
        )
        .await
        .expect_status(200);

    // The owner reads it back and refuses it. Note *which* error: the signer is
    // unknown, so no decryption was even attempted (SPEC §2.4's mandatory order).
    let (_, stored) = current(&harness, &owner.bearer(), owner.vault).await;
    assert_eq!(stored, forged, "the server did store the bytes");
    let error = vault
        .open(&item, &stored)
        .expect_err("a client must reject a write from a device absent from the roster");
    assert!(
        format!("{error:?}").contains("Unknown") || format!("{error:?}").contains("Roster"),
        "expected an unknown-signer rejection, got {error:?}"
    );

    // The same bytes, signed by a device that *is* in the roster, open fine — so
    // the rejection is about roster membership and nothing else.
    let honest = vault.seal(&item, b"an item the user really created", &owner.identity);
    assert_eq!(
        vault.open(&item, &honest).unwrap(),
        b"an item the user really created"
    );
}

#[tokio::test]
async fn a_server_forged_roster_does_not_chain_to_a_trusted_device() {
    let owner = DeviceIdentity::generate().unwrap();
    let vault = Vault::new(&owner);

    // The operator builds a roster naming only itself and signs it correctly.
    let attacker = DeviceIdentity::generate().unwrap();
    let mut forged = Roster::new(vec![attacker
        .record("operator", "linux", now_unix_ms(), None)
        .unwrap()]);
    forged.sign(&attacker).unwrap();

    // It is internally valid — and worthless, because the only question a client
    // asks is whether the signer is a device it already trusts.
    assert!(forged.verify().is_ok(), "self-consistent, as expected");
    let signer = forged.signed_by.unwrap();
    assert!(
        vault.roster.contains(&signer).is_none(),
        "the forged signer must not be in the client's roster"
    );
    assert!(
        forged.contains(&owner.device_id()).is_none(),
        "and the forged roster has quietly dropped the real device"
    );
}

#[tokio::test]
async fn a_single_tampered_envelope_byte_is_detected_by_the_client() {
    let harness = Harness::start().await;
    let owner = bootstrap(&harness).await;
    let vault = Vault::new(&owner.identity);
    let item = ItemId::from_bytes(common::random16());

    let sealed = vault.seal(&item, b"the real payload", &owner.identity);
    harness
        .json(
            "PUT",
            &format!(
                "/v1/vaults/{}/items/{}",
                owner.vault.to_hex(),
                item.to_hex()
            ),
            &[("Authorization", &owner.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&sealed) }),
        )
        .await
        .expect_status(200);

    // Flip one byte in every region of the envelope: header, wrapped item key,
    // ciphertext, signature. Each must be caught.
    let offsets = [4usize, 6, 10, 30, 80, 130, sealed.len() - 1];
    for offset in offsets {
        let (version, stored) = current(&harness, &owner.bearer(), owner.vault).await;
        let mut tampered = stored.clone();
        tampered[offset] ^= 0x01;

        let outcome = harness
            .store
            .put_item(
                owner.vault,
                item,
                Precondition(version),
                tampered.clone(),
                LIMITS,
                now_unix_ms(),
            )
            .unwrap();
        assert!(
            matches!(outcome, WriteOutcome::Ok(_)),
            "the operator can write"
        );

        let (_, served) = current(&harness, &owner.bearer(), owner.vault).await;
        assert_eq!(served, tampered);
        assert!(
            vault.open(&item, &served).is_err(),
            "a flipped byte at offset {offset} went undetected"
        );

        // Put the honest bytes back for the next round.
        let (version, _) = current(&harness, &owner.bearer(), owner.vault).await;
        harness
            .store
            .put_item(
                owner.vault,
                item,
                Precondition(version),
                sealed.clone(),
                LIMITS,
                now_unix_ms(),
            )
            .unwrap();
    }
}

#[tokio::test]
async fn an_envelope_cannot_be_relocated_to_another_item_id() {
    let harness = Harness::start().await;
    let owner = bootstrap(&harness).await;
    let vault = Vault::new(&owner.identity);

    let original = ItemId::from_bytes(common::random16());
    let elsewhere = ItemId::from_bytes(common::random16());
    let sealed = vault.seal(&original, b"payload", &owner.identity);

    // The operator copies the row under a different item id — a plausible way to
    // make one item look like another without touching a byte of ciphertext.
    harness
        .store
        .put_item(
            owner.vault,
            elsewhere,
            Precondition(0),
            sealed.clone(),
            LIMITS,
            now_unix_ms(),
        )
        .unwrap();

    assert!(
        vault.open(&elsewhere, &sealed).is_err(),
        "item_id is bound by the AAD (SPEC §2.4), so a relocated envelope must fail"
    );
    assert!(vault.open(&original, &sealed).is_ok());
}

#[tokio::test]
async fn a_stale_if_match_and_a_replayed_write_are_both_refused() {
    let harness = Harness::start().await;
    let owner = bootstrap(&harness).await;
    let vault = Vault::new(&owner.identity);
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        owner.vault.to_hex(),
        item.to_hex()
    );

    let first = vault.seal(&item, b"one", &owner.identity);
    harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &owner.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&first) }),
        )
        .await
        .expect_status(200);

    let second = vault.seal(&item, b"two", &owner.identity);
    harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &owner.bearer()), ("If-Match", "\"1\"")],
            &serde_json::json!({ "envelope": b64_encode(&second) }),
        )
        .await
        .expect_status(200);

    // Replaying the *identical* request — same precondition, same bytes — is
    // refused, and the refusal carries what the client needs to merge.
    let replayed = harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &owner.bearer()), ("If-Match", "\"1\"")],
            &serde_json::json!({ "envelope": b64_encode(&second) }),
        )
        .await;
    replayed.expect_status(409);
    assert_eq!(replayed.error_code(), "conflict");
    assert_eq!(replayed.value()["version"], "2");
    assert_eq!(
        b64_decode(replayed.value()["envelope"].as_str().unwrap()),
        second,
        "the 409 must carry the current envelope (SPEC §6.1)"
    );

    // A creation attempt on an existing item is the same conflict, so a client
    // that lost its cursor cannot silently clobber.
    let recreate = harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &owner.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&first) }),
        )
        .await;
    recreate.expect_status(409);
    assert_eq!(recreate.value()["version"], "2");

    // An If-Match for an item that does not exist reports version 0 — "absent" —
    // rather than pretending to be a version mismatch.
    let ghost = ItemId::from_bytes(common::random16());
    let missing = harness
        .json(
            "PUT",
            &format!(
                "/v1/vaults/{}/items/{}",
                owner.vault.to_hex(),
                ghost.to_hex()
            ),
            &[("Authorization", &owner.bearer()), ("If-Match", "\"9\"")],
            &serde_json::json!({ "envelope": b64_encode(&first) }),
        )
        .await;
    missing.expect_status(409);
    assert_eq!(missing.value()["version"], "0", "0 means absent");
    // Present *and* null, not omitted: SPEC §6.1 makes the difference
    // load-bearing, because a reclaimed or absent row still carries a version the
    // client must record.
    let body = missing.value();
    let object = body.as_object().unwrap();
    assert!(object.contains_key("envelope"));
    assert!(object["envelope"].is_null());

    // A stale DELETE is refused too.
    harness
        .send(
            "DELETE",
            &path,
            &[
                ("Authorization", owner.bearer().as_str()),
                ("If-Match", "\"1\""),
            ],
            None,
        )
        .await
        .expect_status(409);
}

#[tokio::test]
async fn a_challenge_cannot_be_redeemed_by_a_different_device_or_vault() {
    let harness = Harness::start().await;
    let owner = bootstrap(&harness).await;
    let intruder = DeviceIdentity::generate().unwrap();
    let intruder_id = DeviceId::from_bytes(*intruder.device_id().as_bytes());
    common::admit(&harness, &owner, &intruder)
        .await
        .expect_status(201);

    // A challenge issued for the owner, signed and submitted by the intruder as
    // itself. Both devices are legitimately admitted, so this isolates the
    // binding: the nonce belongs to the owner, and nothing else.
    let nonce = common::challenge(&harness, owner.vault, owner.device).await;
    let stolen = common::verify(
        &harness,
        owner.vault,
        intruder_id,
        &intruder,
        &nonce,
        true,
        &[],
    )
    .await;
    stolen.expect_status(401);
    assert_eq!(stolen.error_code(), "unauthorized");

    // And the nonce is now spent, so the owner cannot use it either: a challenge
    // is consumed by the first attempt, successful or not.
    let owner_retry = common::verify(
        &harness,
        owner.vault,
        owner.device,
        &owner.identity,
        &nonce,
        false,
        &[],
    )
    .await;
    owner_retry.expect_status(401);

    // A challenge for one vault is not redeemable against another.
    let other = bootstrap(&harness).await;
    let nonce = common::challenge(&harness, owner.vault, owner.device).await;
    let cross_vault = common::verify(
        &harness,
        other.vault,
        owner.device,
        &owner.identity,
        &nonce,
        false,
        &[],
    )
    .await;
    cross_vault.expect_status(401);

    // A signature over a *different* nonce than the one presented fails, which is
    // what the length-prefixed, domain-separated payload buys.
    let real = common::challenge(&harness, owner.vault, owner.device).await;
    let signature = owner
        .identity
        .sign(&misty_server::routes::auth::auth_payload(
            owner.vault,
            owner.device,
            b"a nonce the server never issued",
        ));
    let mismatched = harness
        .json(
            "POST",
            "/v1/auth/verify",
            &[],
            &serde_json::json!({
                "vault_id": owner.vault.to_hex(),
                "device_id": owner.device.to_hex(),
                "nonce": hex::encode(&real),
                "sig": hex::encode(signature.as_bytes()),
            }),
        )
        .await;
    mismatched.expect_status(401);
}

#[tokio::test]
async fn a_device_cannot_be_taken_over_by_re_presenting_it_with_a_new_key() {
    let harness = Harness::start().await;
    let owner = bootstrap(&harness).await;

    // Same device_id, different key. The server holds the first key and must not
    // let it be replaced — otherwise anyone who learned a vault_id and a
    // device_id could become that device.
    let impostor = DeviceIdentity::from_secret_bytes(
        misty_crypto::DeviceId::from_bytes(*owner.device.as_bytes()),
        &common::random32(),
        common::random32(),
    );
    let reply =
        common::authenticate(&harness, owner.vault, owner.device, &impostor, true, &[]).await;
    reply.expect_status(401);

    // And admission refuses the swap with a conflict rather than overwriting.
    let sponsored = harness
        .json(
            "POST",
            &format!("/v1/vaults/{}/devices", owner.vault.to_hex()),
            &[("Authorization", &owner.bearer())],
            &serde_json::json!({
                "device_id": owner.device.to_hex(),
                "ed25519_pub": hex::encode(impostor.ed25519_public()),
            }),
        )
        .await;
    sponsored.expect_status(409);

    // The original key still works.
    let again = common::authenticate(
        &harness,
        owner.vault,
        owner.device,
        &owner.identity,
        false,
        &[],
    )
    .await;
    again.expect_status(200);
}

#[tokio::test]
async fn reusing_a_consumed_refresh_token_revokes_the_whole_chain() {
    let harness = Harness::start().await;
    let owner = bootstrap(&harness).await;

    let rotated = harness
        .json(
            "POST",
            "/v1/auth/refresh",
            &[],
            &serde_json::json!({ "refresh_token": owner.refresh }),
        )
        .await;
    rotated.expect_status(200);
    let fresh_refresh = rotated.value()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let fresh_access = rotated.value()["access_token"].as_str().unwrap().to_owned();

    // The stolen copy is presented. The server cannot tell the thief from the
    // client, so it revokes the family rather than guessing.
    let replayed = harness
        .json(
            "POST",
            "/v1/auth/refresh",
            &[],
            &serde_json::json!({ "refresh_token": owner.refresh }),
        )
        .await;
    replayed.expect_status(401);
    assert_eq!(replayed.error_code(), "unauthorized");

    // The legitimate successor is dead too — that is the point of revoking the
    // family, and it is why the honest client is forced back to its device key.
    harness
        .json(
            "POST",
            "/v1/auth/refresh",
            &[],
            &serde_json::json!({ "refresh_token": fresh_refresh }),
        )
        .await
        .expect_status(401);

    // Every access token in the family is gone immediately, not at the next sweep.
    for token in [owner.access.as_str(), fresh_access.as_str()] {
        harness
            .send(
                "GET",
                "/v1/quota",
                &[("Authorization", &format!("Bearer {token}"))],
                None,
            )
            .await
            .expect_status(401);
    }

    // The device recovers with the one credential an attacker does not have.
    let recovered = common::authenticate(
        &harness,
        owner.vault,
        owner.device,
        &owner.identity,
        false,
        &[],
    )
    .await;
    recovered.expect_status(200);
}

#[tokio::test]
async fn a_time_response_cannot_be_replayed_against_a_different_nonce() {
    let harness = Harness::start().await;
    let first_nonce = common::random32();
    let captured = harness
        .send(
            "GET",
            &format!("/v1/time?nonce={}", hex::encode(first_nonce)),
            &[],
            None,
        )
        .await;
    captured.expect_status(200);
    let unix_ms = captured.value()["unix_ms"].as_i64().unwrap();
    let signature = common::hex_decode(captured.value()["sig"].as_str().unwrap());
    assert!(verify_time(
        &harness.time_public_key,
        &first_nonce,
        unix_ms,
        &signature
    ));

    // A MITM replays the captured response to a client whose nonce is different.
    let second_nonce = common::random32();
    assert_ne!(first_nonce, second_nonce);
    assert!(
        !verify_time(&harness.time_public_key, &second_nonce, unix_ms, &signature),
        "a captured /v1/time response must not verify for another nonce"
    );

    // Nor can the timestamp be moved: the signature covers it.
    assert!(!verify_time(
        &harness.time_public_key,
        &first_nonce,
        unix_ms - 3_600_000,
        &signature
    ));

    // A fresh request for the same nonce is a different signature only if the
    // clock moved; what matters is that the *nonce* binding holds both ways.
    let fresh = harness
        .send(
            "GET",
            &format!("/v1/time?nonce={}", hex::encode(second_nonce)),
            &[],
            None,
        )
        .await;
    fresh.expect_status(200);
    assert!(!verify_time(
        &harness.time_public_key,
        &first_nonce,
        fresh.value()["unix_ms"].as_i64().unwrap(),
        &common::hex_decode(fresh.value()["sig"].as_str().unwrap()),
    ));
}

#[tokio::test]
async fn server_side_deletion_is_the_only_destructive_power_and_it_is_recoverable() {
    let harness = Harness::start().await;
    let owner = bootstrap(&harness).await;
    let vault = Vault::new(&owner.identity);
    let item = ItemId::from_bytes(common::random16());
    let sealed = vault.seal(&item, b"the user's data", &owner.identity);
    let path = format!(
        "/v1/vaults/{}/items/{}",
        owner.vault.to_hex(),
        item.to_hex()
    );

    harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &owner.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&sealed) }),
        )
        .await
        .expect_status(200);

    // The operator throws the bytes away.
    let outcome = harness
        .store
        .delete_item(owner.vault, item, Precondition(1), now_unix_ms())
        .unwrap();
    let version = match outcome {
        WriteOutcome::Ok(written) => written.version,
        other => panic!("unexpected {other:?}"),
    };

    // The feed reports it, and SPEC §6.1 forbids a client from acting on that
    // report — which is exactly why this is survivable.
    let reply = harness
        .send(
            "GET",
            &format!("/v1/vaults/{}/changes?since=0", owner.vault.to_hex()),
            &[("Authorization", owner.bearer().as_str())],
            None,
        )
        .await;
    assert_eq!(reply.value()["changes"][0]["deleted"], true);
    assert!(reply.value()["changes"][0]["envelope"].is_null());

    // The client still holds the plaintext, and `version` never went backwards,
    // so it re-uploads and the vault is whole again.
    let restored = harness
        .json(
            "PUT",
            &path,
            &[
                ("Authorization", &owner.bearer()),
                ("If-Match", &format!("\"{version}\"")),
            ],
            &serde_json::json!({ "envelope": b64_encode(&sealed) }),
        )
        .await;
    restored.expect_status(200);
    assert_eq!(restored.value()["version"], (version + 1).to_string());
    let (_, served) = current(&harness, &owner.bearer(), owner.vault).await;
    assert_eq!(vault.open(&item, &served).unwrap(), b"the user's data");
}

#[tokio::test]
async fn two_devices_converge_through_the_real_server() {
    let harness = Harness::start().await;
    let first = bootstrap(&harness).await;

    // The second device is enrolled the way SPEC §6.3 says: an existing device
    // vouches for it, and the roster it will trust is signed by that device.
    let second_identity = DeviceIdentity::generate().unwrap();
    let mut vault = Vault::new(&first.identity);
    vault
        .roster
        .add(
            second_identity
                .record(
                    "second device",
                    "android",
                    now_unix_ms(),
                    Some(first.identity.device_id()),
                )
                .unwrap(),
        )
        .unwrap();
    vault.roster.sign(&first.identity).unwrap();
    let second = common::join_admitted(&harness, &first, second_identity).await;

    // Each device writes an item the other has never seen.
    let mut expected = Vec::new();
    for (client, payload) in [
        (&first, &b"written by the first device"[..]),
        (&second, &b"written by the second device"[..]),
    ] {
        let item = ItemId::from_bytes(common::random16());
        let sealed = vault.seal(&item, payload, &client.identity);
        harness
            .json(
                "PUT",
                &format!(
                    "/v1/vaults/{}/items/{}",
                    client.vault.to_hex(),
                    item.to_hex()
                ),
                &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
                &serde_json::json!({ "envelope": b64_encode(&sealed) }),
            )
            .await
            .expect_status(200);
        expected.push((item, payload.to_vec()));
    }

    // Both devices walk the feed and end up with byte-identical plaintext.
    for client in [&first, &second] {
        let reply = harness
            .send(
                "GET",
                &format!("/v1/vaults/{}/changes?since=0", client.vault.to_hex()),
                &[("Authorization", client.bearer().as_str())],
                None,
            )
            .await;
        reply.expect_status(200);
        let entries = reply.value()["changes"].as_array().unwrap().clone();
        assert_eq!(entries.len(), 2);
        for (item, payload) in &expected {
            let entry = entries
                .iter()
                .find(|e| e["item_id"] == item.to_hex())
                .expect("item in feed");
            let bytes = b64_decode(entry["envelope"].as_str().unwrap());
            assert_eq!(&vault.open(item, &bytes).unwrap(), payload);
        }
    }
}

#[tokio::test]
async fn the_server_relays_the_vault_key_and_cannot_see_it() {
    let harness = Harness::start().await;

    // A full SPEC §6.3 enrollment, with the real key schedule. The server holds
    // neither X25519 private half at any point.
    let approver_identity = DeviceIdentity::generate().unwrap();
    let mut vault = Vault::new(&approver_identity);
    let new_identity = DeviceIdentity::generate().unwrap();
    let enrollment = NewDeviceEnrollment::begin(&new_identity, "Ada's Pixel", "android").unwrap();
    let confirmation_code = enrollment.confirmation_code();
    let request = enrollment.request().clone();
    let enroll_hex = hex::encode(request.enroll_id.as_bytes());

    // Step 1: the new device posts its request. Note that this blob is *not*
    // encrypted and cannot be: §6.3 derives the sealing key from the approver's
    // ephemeral key, which does not exist until step 3. See README.
    harness
        .json(
            "POST",
            "/v1/enroll/begin",
            &[],
            &serde_json::json!({
                "enroll_id": enroll_hex,
                "x25519_pub": hex::encode(request.x25519_pub),
                "enroll_request": b64_encode(&serde_json::to_vec(&request).unwrap()),
            }),
        )
        .await
        .expect_status(201);

    // Step 2/3: the approver collects it, compares the code out of band, adds the
    // device to the roster, re-signs, and seals the grant.
    let collected = harness
        .send(
            "GET",
            &format!("/v1/enroll/poll/{enroll_hex}?want=request"),
            &[],
            None,
        )
        .await;
    collected.expect_status(200);
    let relayed_request: misty_crypto::enrollment::EnrollmentRequest = serde_json::from_slice(
        &b64_decode(collected.value()["enroll_request"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(relayed_request, request);

    vault
        .roster
        .add(
            new_identity
                .record(
                    &relayed_request.name,
                    &relayed_request.platform,
                    now_unix_ms(),
                    Some(approver_identity.device_id()),
                )
                .unwrap(),
        )
        .unwrap();
    vault.roster.sign(&approver_identity).unwrap();

    let sealed = misty_crypto::enrollment::approve(
        &relayed_request,
        &confirmation_code,
        &GrantContents {
            vault_id: misty_crypto::VaultId::from_bytes(common::random16()),
            vault_key: &vault.key,
            epoch: vault.epoch,
            server_url: "https://misty.test",
            roster: &vault.roster,
        },
        &approver_identity,
    )
    .unwrap();
    let wire = serde_json::to_vec(&sealed).unwrap();

    harness
        .json(
            "POST",
            "/v1/enroll/complete",
            &[],
            &serde_json::json!({
                "enroll_id": enroll_hex,
                "sealed_response": b64_encode(&wire),
            }),
        )
        .await
        .expect_status(200);

    // Step 4: the new device collects and unseals it.
    let answer = harness
        .send("GET", &format!("/v1/enroll/poll/{enroll_hex}"), &[], None)
        .await;
    answer.expect_status(200);
    let relayed = b64_decode(answer.value()["sealed_response"].as_str().unwrap());
    assert_eq!(relayed, wire);

    // The relayed bytes do not contain the vault key. This is the whole claim:
    // the server carried the key across and never held it.
    let secret = vault.key.expose_secret();
    assert!(
        !relayed.windows(secret.len()).any(|w| w == secret),
        "the vault key must not appear in what the server stored"
    );

    let delivered: SealedEnrollment = serde_json::from_slice(&relayed).unwrap();
    let grant = enrollment
        .open(&delivered)
        .expect("the new device unseals it");
    assert!(grant.vault_key.constant_time_eq(&vault.key));
    assert!(grant.roster.contains(&new_identity.device_id()).is_some());
    assert_eq!(grant.server_url, "https://misty.test");

    // A third party holding the same blob — including the operator, who holds
    // every byte of it — gets nothing.
    let bystander = DeviceIdentity::generate().unwrap();
    let bystander_enrollment = NewDeviceEnrollment::begin(&bystander, "attacker", "linux").unwrap();
    assert!(
        bystander_enrollment.open(&delivered).is_err(),
        "only the device that started the enrollment can open the answer"
    );
}

#[tokio::test]
async fn an_epoch_change_invalidates_an_old_envelope_so_a_revoked_device_is_locked_out() {
    // SPEC §6.4: rotation re-seals, because `epoch` is in the payload AAD.
    // Asserted here because the server stores envelopes across a rotation and
    // must not be able to help a stale one survive.
    let owner = DeviceIdentity::generate().unwrap();
    let mut vault = Vault::new(&owner);
    let item = ItemId::from_bytes(common::random16());
    let sealed = vault.seal(&item, b"pre-rotation", &owner);

    vault.epoch = 1;
    assert!(
        vault.open(&item, &sealed).is_err(),
        "an envelope from epoch 0 must not open under epoch 1"
    );

    let resealed = vault.seal(&item, b"post-rotation", &owner);
    assert_eq!(vault.open(&item, &resealed).unwrap(), b"post-rotation");

    // And the raw bytes really did change, so a server that kept the old row
    // cannot pass it off as rotated.
    let epoch_key = derive::epoch_key(&vault.key, 0).unwrap();
    let crypto_item = CryptoItemId::from_bytes(*item.as_bytes());
    assert!(envelope::open(
        &envelope::seal(
            EnvelopeKind::Item,
            0,
            &crypto_item,
            b"pre-rotation",
            &epoch_key,
            &owner,
        )
        .unwrap(),
        &crypto_item,
        &derive::epoch_key(&vault.key, 1).unwrap(),
        &vault.roster,
    )
    .is_err());
}
