// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Abuse limits and housekeeping (SPEC §6.1's rate limits, plus the ceilings the
//! task list calls for).
//!
//! An open zero-knowledge blob store is, without these, a free disk. Each limit
//! is asserted through the HTTP surface rather than against the store, because the
//! status code and the `Retry-After` header are the parts a client has to act on.

mod common;

use common::{b64_encode, bootstrap, Harness, Vault};
use misty_crypto::identity::DeviceIdentity;
use misty_server::store::Store;
use misty_server::time_key::now_unix_ms;
use misty_server::{DeviceId, ItemId, VaultId};

#[tokio::test]
async fn an_ip_over_its_rate_is_told_when_to_come_back() {
    let harness = Harness::start_with(|config| {
        config.rate_limit_ip_per_minute = 1;
        config.rate_limit_burst = 1;
    })
    .await;

    harness
        .send("GET", "/healthz", &[], None)
        .await
        .expect_status(200);
    let reply = harness.send("GET", "/healthz", &[], None).await;
    reply.expect_status(429);
    assert_eq!(reply.error_code(), "rate_limited");
    let retry: u64 = reply
        .header("retry-after")
        .expect("Retry-After is required on a 429")
        .parse()
        .expect("a number of seconds");
    assert!(
        (1..=3600).contains(&retry),
        "implausible Retry-After: {retry}"
    );
}

#[tokio::test]
async fn a_vault_over_its_rate_is_limited_even_from_a_fresh_connection() {
    // The IP bucket is left wide open so this isolates the per-vault limit. The
    // bootstrap itself spends two tokens: one on `challenge`, one on `verify`.
    let harness = Harness::start_with(|config| {
        config.rate_limit_vault_per_minute = 1;
        config.rate_limit_burst = 3;
    })
    .await;
    let client = bootstrap(&harness).await;

    harness
        .send(
            "GET",
            "/v1/quota",
            &[("Authorization", client.bearer().as_str())],
            None,
        )
        .await
        .expect_status(200);
    let reply = harness
        .send(
            "GET",
            "/v1/quota",
            &[("Authorization", client.bearer().as_str())],
            None,
        )
        .await;
    reply.expect_status(429);
    assert!(reply.header("retry-after").is_some());
}

#[tokio::test]
async fn a_vault_at_its_item_limit_is_told_the_vault_is_full_not_the_request_too_big() {
    let harness = Harness::start_with(|config| config.max_items_per_vault = 2).await;
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);

    for round in 0..3 {
        let item = ItemId::from_bytes(common::random16());
        let envelope = vault.seal(&item, format!("item {round}").as_bytes(), &client.identity);
        let reply = harness
            .json(
                "PUT",
                &format!(
                    "/v1/vaults/{}/items/{}",
                    client.vault.to_hex(),
                    item.to_hex()
                ),
                &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
                &serde_json::json!({ "envelope": b64_encode(&envelope) }),
            )
            .await;
        if round < 2 {
            reply.expect_status(200);
        } else {
            // 507, not 413: the request is a perfectly good size, the vault is
            // full. Telling a client to shrink its item would send it down the
            // wrong path.
            reply.expect_status(507);
            assert_eq!(reply.error_code(), "quota_exceeded");
            assert!(reply.value()["message"]
                .as_str()
                .unwrap()
                .contains("item count"));
            assert_eq!(reply.header("retry-after"), Some("0"));
        }
    }
}

#[tokio::test]
async fn a_vault_at_its_byte_limit_refuses_the_write_that_would_cross_it() {
    let harness = Harness::start_with(|config| {
        config.max_envelope_bytes = 512;
        config.max_vault_bytes = 1000;
    })
    .await;
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);

    // One real envelope is 458 bytes (SPEC §2.4's 256-byte bucketing), so two fit
    // and the third does not.
    let mut accepted = 0;
    for round in 0..3 {
        let item = ItemId::from_bytes(common::random16());
        let envelope = vault.seal(&item, format!("item {round}").as_bytes(), &client.identity);
        assert!(envelope.len() < 512);
        let reply = harness
            .json(
                "PUT",
                &format!(
                    "/v1/vaults/{}/items/{}",
                    client.vault.to_hex(),
                    item.to_hex()
                ),
                &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
                &serde_json::json!({ "envelope": b64_encode(&envelope) }),
            )
            .await;
        if reply.status == 200 {
            accepted += 1;
        } else {
            reply.expect_status(507);
            assert!(reply.value()["message"]
                .as_str()
                .unwrap()
                .contains("total bytes"));
        }
    }
    assert_eq!(accepted, 2, "two 458-byte envelopes fit in 1000 bytes");

    let quota = harness
        .send(
            "GET",
            "/v1/quota",
            &[("Authorization", client.bearer().as_str())],
            None,
        )
        .await;
    assert!(quota.value()["bytes_used"].as_u64().unwrap() <= 1000);
}

#[tokio::test]
async fn a_registration_token_closes_an_instance_to_new_vaults() {
    let harness =
        Harness::start_with(|config| config.registration_token = Some("an invite secret".into()))
            .await;
    let identity = DeviceIdentity::generate().unwrap();
    let vault = VaultId::from_bytes(common::random16());
    let device = DeviceId::from_bytes(*identity.device_id().as_bytes());

    let refused = common::authenticate(&harness, vault, device, &identity, true, &[]).await;
    refused.expect_status(403);

    let wrong = common::authenticate(
        &harness,
        vault,
        device,
        &identity,
        true,
        &[("X-Misty-Registration", "not the secret")],
    )
    .await;
    wrong.expect_status(403);

    let allowed = common::authenticate(
        &harness,
        vault,
        device,
        &identity,
        true,
        &[("X-Misty-Registration", "an invite secret")],
    )
    .await;
    allowed.expect_status(200);

    // An existing device never presents the invite secret again.
    let returning = common::authenticate(&harness, vault, device, &identity, false, &[]).await;
    returning.expect_status(200);
}

#[tokio::test]
async fn an_instance_at_its_vault_limit_stops_creating_vaults() {
    let harness = Harness::start_with(|config| config.max_vaults = Some(1)).await;
    let first = bootstrap(&harness).await;

    let identity = DeviceIdentity::generate().unwrap();
    let reply = common::authenticate(
        &harness,
        VaultId::from_bytes(common::random16()),
        DeviceId::from_bytes(*identity.device_id().as_bytes()),
        &identity,
        true,
        &[],
    )
    .await;
    reply.expect_status(507);
    assert_eq!(reply.error_code(), "quota_exceeded");

    // The existing vault is unaffected.
    harness
        .send(
            "GET",
            "/v1/quota",
            &[("Authorization", first.bearer().as_str())],
            None,
        )
        .await
        .expect_status(200);
}

#[tokio::test]
async fn an_oversized_sealed_enrollment_blob_is_refused() {
    let harness = Harness::start_with(|config| config.max_sealed_bytes = 64).await;
    let enroll = hex::encode(common::random16());

    let reply = harness
        .json(
            "POST",
            "/v1/enroll/begin",
            &[],
            &serde_json::json!({
                "enroll_id": enroll,
                "x25519_pub": hex::encode([0u8; 32]),
                "enroll_request": b64_encode(&vec![9u8; 256]),
            }),
        )
        .await;
    reply.expect_status(413);
    assert_eq!(reply.error_code(), "payload_too_large");
}

#[tokio::test]
async fn the_sweeper_reclaims_challenges_tokens_enrollments_and_tombstones() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );

    // An outstanding challenge, an enrollment, and a deleted item.
    let nonce = common::challenge(&harness, client.vault, client.device).await;
    let enroll = hex::encode(common::random16());
    harness
        .json(
            "POST",
            "/v1/enroll/begin",
            &[],
            &serde_json::json!({
                "enroll_id": enroll,
                "x25519_pub": hex::encode([1u8; 32]),
                "enroll_request": b64_encode(b"opaque"),
            }),
        )
        .await
        .expect_status(201);
    harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&vault.seal(&item, b"x", &client.identity)) }),
        )
        .await
        .expect_status(200);
    harness
        .send(
            "DELETE",
            &path,
            &[
                ("Authorization", client.bearer().as_str()),
                ("If-Match", "\"1\""),
            ],
            None,
        )
        .await
        .expect_status(200);

    // Sweep as if a long time had passed.
    let future = now_unix_ms() + 400 * 24 * 3_600_000;
    let swept = harness.store.sweep(future, future).unwrap();
    assert!(swept.challenges >= 1, "the challenge should be gone");
    assert!(
        swept.tokens >= 2,
        "the access and refresh tokens should be gone"
    );
    assert_eq!(swept.enrollments, 1);
    assert_eq!(swept.tombstones, 1, "the tombstone row releases its slot");

    // The swept challenge cannot be redeemed.
    common::verify(
        &harness,
        client.vault,
        client.device,
        &client.identity,
        &nonce,
        false,
        &[],
    )
    .await
    .expect_status(401);

    // The swept token no longer authenticates.
    harness
        .send(
            "GET",
            "/v1/quota",
            &[("Authorization", client.bearer().as_str())],
            None,
        )
        .await
        .expect_status(401);

    // The swept enrollment is gone.
    harness
        .send("GET", &format!("/v1/enroll/poll/{enroll}"), &[], None)
        .await
        .expect_status(404);

    // And the reclaimed row means the item id is creatable again from scratch.
    let fresh = common::authenticate(
        &harness,
        client.vault,
        client.device,
        &client.identity,
        false,
        &[],
    )
    .await;
    fresh.expect_status(200);
    let bearer = format!("Bearer {}", fresh.value()["access_token"].as_str().unwrap());
    let recreated = harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &bearer), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&vault.seal(&item, b"y", &client.identity)) }),
        )
        .await;
    recreated.expect_status(200);
    assert_eq!(recreated.value()["version"], "1");
}
