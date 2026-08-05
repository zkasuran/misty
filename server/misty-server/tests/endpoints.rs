// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every endpoint in SPEC §6.1, end to end over a listening socket and a real
//! SQLite file.

mod common;

use common::{b64_decode, b64_encode, bootstrap, hex_decode, Harness, Vault};
use misty_crypto::identity::DeviceIdentity;
use misty_server::time_key::verify_time;
use misty_server::{ItemId, VaultId};

#[tokio::test]
async fn healthz_reports_ok_and_nothing_else() {
    let harness = Harness::start().await;
    let reply = harness.send("GET", "/healthz", &[], None).await;
    reply.expect_status(200);
    // Exactly one field: a health endpoint is reachable by anyone who can reach
    // the socket, so it must not double as a version banner.
    assert_eq!(reply.value(), serde_json::json!({ "status": "ok" }));
}

#[tokio::test]
async fn an_unmatched_path_is_a_typed_json_404() {
    let harness = Harness::start().await;
    let reply = harness.send("GET", "/v1/nope", &[], None).await;
    reply.expect_status(404);
    assert_eq!(reply.error_code(), "not_found");
}

#[tokio::test]
async fn a_challenge_is_issued_for_a_vault_that_does_not_exist() {
    let harness = Harness::start().await;
    // No existence oracle: an unknown vault gets the same answer as a known one.
    let unknown = VaultId::from_bytes([0xaa; 16]);
    let reply = harness
        .json(
            "POST",
            "/v1/auth/challenge",
            &[],
            &serde_json::json!({
                "vault_id": unknown.to_hex(),
                "device_id": "00112233445566778899aabbccddeeff",
            }),
        )
        .await;
    reply.expect_status(200);
    // SPEC §6.1.1: 32 bytes as 64 lowercase hex characters.
    let nonce = reply.value()["nonce"].as_str().unwrap().to_owned();
    assert_eq!(nonce.len(), 64, "hex, not the 44 characters of base64");
    assert_eq!(hex_decode(&nonce).len(), 32);
    assert!(reply.value()["expires_at"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn verify_bootstraps_a_vault_and_issues_a_short_lived_token() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    assert_eq!(client.access.len(), 43);
    assert_eq!(client.refresh.len(), 43);

    let quota = harness
        .send(
            "GET",
            "/v1/quota",
            &[("Authorization", &client.bearer())],
            None,
        )
        .await;
    quota.expect_status(200);
    let value = quota.value();
    assert_eq!(value["bytes_used"], 0);
    assert_eq!(value["item_count"], 0);
    assert_eq!(value["limits"]["max_items_per_vault"], 10_000);
}

#[tokio::test]
async fn an_item_is_created_updated_read_back_and_deleted() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );
    let bearer = client.bearer();
    let auth = [("Authorization", bearer.as_str())];

    // Create needs `If-None-Match: *`; SPEC §6.1 defines no precondition for a
    // new item, and a write with none at all is refused.
    let first = vault.seal(&item, b"one", &client.identity);
    let created = harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&first) }),
        )
        .await;
    created.expect_status(200);
    assert_eq!(created.value()["version"], "1", "§6.1.1: an opaque token");
    assert!(created.value()["version"].is_string());
    assert_eq!(created.value()["seq"], 1);
    assert_eq!(created.header("etag"), Some("\"1\""));

    // Update with the version just returned.
    let second = vault.seal(&item, b"two", &client.identity);
    let updated = harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &client.bearer()), ("If-Match", "\"1\"")],
            &serde_json::json!({ "envelope": b64_encode(&second) }),
        )
        .await;
    updated.expect_status(200);
    assert_eq!(updated.value()["version"], "2");
    assert_eq!(updated.value()["seq"], 2);

    // The feed hands back the exact bytes, and they still open.
    let feed = harness
        .send(
            "GET",
            &format!("/v1/vaults/{}/changes?since=0", client.vault.to_hex()),
            &auth,
            None,
        )
        .await;
    feed.expect_status(200);
    let value = feed.value();
    assert_eq!(value["changes"].as_array().unwrap().len(), 1);
    assert_eq!(value["next_seq"], 2);
    assert_eq!(value["has_more"], false);
    let entry = &value["changes"][0];
    assert_eq!(entry["item_id"], item.to_hex());
    assert_eq!(entry["deleted"], false);
    let returned = b64_decode(entry["envelope"].as_str().unwrap());
    assert_eq!(returned, second);
    assert_eq!(vault.open(&item, &returned).unwrap(), b"two");

    // Delete reclaims the bytes; the row and its monotonic version survive.
    let deleted = harness
        .send(
            "DELETE",
            &path,
            &[
                ("Authorization", client.bearer().as_str()),
                ("If-Match", "\"2\""),
            ],
            None,
        )
        .await;
    deleted.expect_status(200);
    assert_eq!(deleted.value()["version"], "3");

    let feed = harness
        .send(
            "GET",
            &format!("/v1/vaults/{}/changes?since=0", client.vault.to_hex()),
            &auth,
            None,
        )
        .await;
    let entry = &feed.value()["changes"][0];
    assert_eq!(entry["deleted"], true);
    assert!(entry["envelope"].is_null(), "the bytes must be gone");

    let quota = harness.send("GET", "/v1/quota", &auth, None).await;
    assert_eq!(quota.value()["bytes_used"], 0);
    assert_eq!(quota.value()["item_count"], 0);
    assert_eq!(
        quota.value()["row_count"],
        1,
        "the row keeps version monotonic"
    );
}

#[tokio::test]
async fn a_reclaimed_row_reports_envelope_as_an_explicit_null_everywhere() {
    // SPEC §6.1: `envelope` is nullable in the feed *and* in a `409`, because a
    // `DELETE` keeps the row so `version` stays monotonic. The difference between
    // `null` and an absent key is load-bearing: a client must record the version
    // from such a row or its next `If-Match` is wrong, so it has to be able to tell
    // "no bytes" from "this server did not answer".
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );
    let bearer = client.bearer();

    let sealed = vault.seal(&item, b"data the client still holds", &client.identity);
    harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &bearer), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&sealed) }),
        )
        .await
        .expect_status(200);
    harness
        .send(
            "DELETE",
            &path,
            &[("Authorization", bearer.as_str()), ("If-Match", "\"1\"")],
            None,
        )
        .await
        .expect_status(200);

    // In the feed.
    let feed = harness
        .send(
            "GET",
            &format!("/v1/vaults/{}/changes?since=0", client.vault.to_hex()),
            &[("Authorization", bearer.as_str())],
            None,
        )
        .await;
    feed.expect_status(200);
    let body = feed.value();
    let entry = body["changes"][0].as_object().expect("an entry");
    assert!(entry.contains_key("envelope"), "the key must be present");
    assert!(entry["envelope"].is_null(), "and null, not an empty string");
    assert_eq!(entry["version"], "2");
    assert_eq!(entry["deleted"], true);

    // And in a `409`, where the client learns the version to retry with.
    let stale = harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &bearer), ("If-Match", "\"1\"")],
            &serde_json::json!({ "envelope": b64_encode(&sealed) }),
        )
        .await;
    stale.expect_status(409);
    let body = stale.value();
    let object = body.as_object().expect("an object");
    assert!(object.contains_key("envelope"));
    assert!(object["envelope"].is_null());
    assert_eq!(object["version"], "2");
    assert!(object["version"].is_string());

    // The version it just learned is the one that works.
    harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &bearer), ("If-Match", "\"2\"")],
            &serde_json::json!({ "envelope": b64_encode(&sealed) }),
        )
        .await
        .expect_status(200);
}

#[tokio::test]
async fn the_feed_paginates_without_losing_or_repeating_a_row() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);
    let mut items = Vec::new();
    for _ in 0..5 {
        let item = ItemId::from_bytes(common::random16());
        let sealed = vault.seal(&item, b"payload", &client.identity);
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
        items.push(item.to_hex());
    }

    let mut seen = Vec::new();
    let mut cursor = 0u64;
    loop {
        let reply = harness
            .send(
                "GET",
                &format!(
                    "/v1/vaults/{}/changes?since={cursor}&limit=2",
                    client.vault.to_hex()
                ),
                &[("Authorization", client.bearer().as_str())],
                None,
            )
            .await;
        reply.expect_status(200);
        let value = reply.value();
        for entry in value["changes"].as_array().unwrap() {
            let seq = entry["seq"].as_u64().unwrap();
            assert!(seq > cursor, "the feed must never rewind");
            seen.push(entry["item_id"].as_str().unwrap().to_owned());
        }
        cursor = value["next_seq"].as_u64().unwrap();
        if !value["has_more"].as_bool().unwrap() {
            break;
        }
    }
    assert_eq!(seen, items, "every row exactly once, in seq order");
}

#[tokio::test]
async fn signed_time_verifies_against_the_pinned_key() {
    let harness = Harness::start().await;
    let nonce = common::random32();
    let reply = harness
        .send(
            "GET",
            &format!("/v1/time?nonce={}", hex::encode(nonce)),
            &[],
            None,
        )
        .await;
    reply.expect_status(200);
    let value = reply.value();
    let unix_ms = value["unix_ms"].as_i64().unwrap();
    let echoed = hex_decode(value["nonce"].as_str().unwrap());
    assert_eq!(echoed, nonce, "the response must be bound to our nonce");
    assert!(verify_time(
        &harness.time_public_key,
        &nonce,
        unix_ms,
        &hex_decode(value["sig"].as_str().unwrap()),
    ));
    assert!(unix_ms > 1_577_836_800_000);
}

#[tokio::test]
async fn time_without_a_nonce_is_refused_because_it_would_be_replayable() {
    let harness = Harness::start().await;
    let reply = harness.send("GET", "/v1/time", &[], None).await;
    reply.expect_status(400);
    assert_eq!(reply.error_code(), "bad_request");
    assert!(reply.value()["message"]
        .as_str()
        .unwrap()
        .contains("replayable"));
}

#[tokio::test]
async fn the_enrollment_relay_hands_each_blob_out_once() {
    let harness = Harness::start().await;
    let enroll_id = hex::encode(common::random16());
    let x25519_pub = common::random32();
    let enroll_request = b"the new device's request, opaque to the server".to_vec();
    let sealed_response = b"sealed by the approving device".to_vec();

    let begun = harness
        .json(
            "POST",
            "/v1/enroll/begin",
            &[],
            &serde_json::json!({
                "enroll_id": enroll_id,
                "x25519_pub": hex::encode(x25519_pub),
                "enroll_request": b64_encode(&enroll_request),
            }),
        )
        .await;
    begun.expect_status(201);
    assert!(begun.value()["expires_at"].as_i64().unwrap() > 0);

    // A second `begin` on the same id is refused, not silently overwritten: the
    // id travels in a QR code.
    harness
        .json(
            "POST",
            "/v1/enroll/begin",
            &[],
            &serde_json::json!({
                "enroll_id": enroll_id,
                "x25519_pub": hex::encode(x25519_pub),
                "enroll_request": b64_encode(b"substituted"),
            }),
        )
        .await
        .expect_status(409);

    // The new device polls; nothing yet.
    let pending = harness
        .send("GET", &format!("/v1/enroll/poll/{enroll_id}"), &[], None)
        .await;
    pending.expect_status(200);
    assert_eq!(pending.value()["ready"], false);

    // The approving device collects the request — once.
    let collected = harness
        .send(
            "GET",
            &format!("/v1/enroll/poll/{enroll_id}?want=request"),
            &[],
            None,
        )
        .await;
    collected.expect_status(200);
    assert_eq!(
        b64_decode(collected.value()["enroll_request"].as_str().unwrap()),
        enroll_request
    );
    assert_eq!(
        hex_decode(collected.value()["x25519_pub"].as_str().unwrap()),
        x25519_pub
    );
    harness
        .send(
            "GET",
            &format!("/v1/enroll/poll/{enroll_id}?want=request"),
            &[],
            None,
        )
        .await
        .expect_status(404);

    // It answers.
    harness
        .json(
            "POST",
            "/v1/enroll/complete",
            &[],
            &serde_json::json!({
                "enroll_id": enroll_id,
                "sealed_response": b64_encode(&sealed_response),
            }),
        )
        .await
        .expect_status(200);

    // A racing second answer cannot displace the first.
    harness
        .json(
            "POST",
            "/v1/enroll/complete",
            &[],
            &serde_json::json!({
                "enroll_id": enroll_id,
                "sealed_response": b64_encode(b"attacker's answer"),
            }),
        )
        .await
        .expect_status(409);

    // The new device collects it — once. The record is then gone, so neither a
    // second reader nor the operator can find it later.
    let answer = harness
        .send("GET", &format!("/v1/enroll/poll/{enroll_id}"), &[], None)
        .await;
    answer.expect_status(200);
    assert_eq!(answer.value()["ready"], true);
    assert_eq!(
        b64_decode(answer.value()["sealed_response"].as_str().unwrap()),
        sealed_response
    );
    harness
        .send("GET", &format!("/v1/enroll/poll/{enroll_id}"), &[], None)
        .await
        .expect_status(404);
}

#[tokio::test]
async fn a_refresh_token_rotates_and_the_old_access_token_still_works_until_it_expires() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;

    let rotated = harness
        .json(
            "POST",
            "/v1/auth/refresh",
            &[],
            &serde_json::json!({ "refresh_token": client.refresh }),
        )
        .await;
    rotated.expect_status(200);
    let value = rotated.value();
    let new_access = value["access_token"].as_str().unwrap();
    let new_refresh = value["refresh_token"].as_str().unwrap();
    assert_ne!(new_refresh, client.refresh, "a refresh token is single-use");
    assert_ne!(new_access, client.access);
    assert_eq!(value["vault_id"], client.vault.to_hex());

    // Both access tokens are live: rotation issues a new one, it does not revoke
    // the previous one mid-request.
    for token in [client.access.as_str(), new_access] {
        harness
            .send(
                "GET",
                "/v1/quota",
                &[("Authorization", &format!("Bearer {token}"))],
                None,
            )
            .await
            .expect_status(200);
    }
}

#[tokio::test]
async fn a_second_device_needs_an_existing_device_to_vouch_for_it() {
    let harness = Harness::start().await;
    let first = bootstrap(&harness).await;
    let newcomer = DeviceIdentity::generate().unwrap();

    // Straight to verify: the vault exists, the device is unknown, and the
    // server refuses to admit it on its own authority.
    let refused = common::authenticate(
        &harness,
        first.vault,
        misty_server::DeviceId::from_bytes(*newcomer.device_id().as_bytes()),
        &newcomer,
        true,
        &[],
    )
    .await;
    refused.expect_status(403);
    assert_eq!(refused.error_code(), "forbidden");

    // With a sponsor it works, and a repeat is idempotent rather than an error.
    common::admit(&harness, &first, &newcomer)
        .await
        .expect_status(201);
    let again = common::admit(&harness, &first, &newcomer).await;
    again.expect_status(200);
    assert_eq!(again.value()["result"], "already_present");

    let second = common::join(&harness, first.vault, newcomer, &[]).await;
    assert_ne!(second.access, first.access);
}

#[tokio::test]
async fn a_token_for_one_vault_cannot_touch_another() {
    let harness = Harness::start().await;
    let a = bootstrap(&harness).await;
    let b = bootstrap(&harness).await;
    assert_ne!(a.vault.to_hex(), b.vault.to_hex());

    let reply = harness
        .send(
            "GET",
            &format!("/v1/vaults/{}/changes", b.vault.to_hex()),
            &[("Authorization", a.bearer().as_str())],
            None,
        )
        .await;
    reply.expect_status(403);
    assert_eq!(reply.error_code(), "forbidden");

    let vault = Vault::new(&a.identity);
    let item = ItemId::from_bytes(common::random16());
    let write = harness
        .json(
            "PUT",
            &format!("/v1/vaults/{}/items/{}", b.vault.to_hex(), item.to_hex()),
            &[("Authorization", &a.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&vault.seal(&item, b"x", &a.identity)) }),
        )
        .await;
    write.expect_status(403);
}

#[tokio::test]
async fn every_authenticated_endpoint_refuses_a_missing_or_bogus_token() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let item = ItemId::from_bytes(common::random16());
    let vault = client.vault.to_hex();

    let cases: Vec<(&str, String, Option<Vec<u8>>)> = vec![
        ("GET", "/v1/quota".to_owned(), None),
        ("GET", format!("/v1/vaults/{vault}/changes"), None),
        (
            "PUT",
            format!("/v1/vaults/{vault}/items/{}", item.to_hex()),
            Some(br#"{"envelope":"AAAA"}"#.to_vec()),
        ),
        (
            "DELETE",
            format!("/v1/vaults/{vault}/items/{}", item.to_hex()),
            None,
        ),
        (
            "POST",
            format!("/v1/vaults/{vault}/devices"),
            Some(
                br#"{"device_id":"00000000000000000000000000000000","ed25519_pub":"AAAA"}"#
                    .to_vec(),
            ),
        ),
    ];

    for (method, path, body) in cases {
        for authorization in [None, Some("Bearer nope"), Some("Basic abc"), Some("")] {
            let mut headers = vec![("Content-Type", "application/json"), ("If-Match", "\"1\"")];
            if let Some(value) = authorization {
                headers.push(("Authorization", value));
            }
            let reply = harness.send(method, &path, &headers, body.as_deref()).await;
            assert_eq!(
                reply.status, 401,
                "{method} {path} with {authorization:?} should be 401"
            );
        }
    }
}
