// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile input on every endpoint.
//!
//! Each case asserts three things: a specific status, a body that parses as our
//! JSON error shape, and — by the suite finishing — that the process neither
//! panicked nor allocated its way out of memory. Every test ends with a `/healthz`
//! call, so a request that killed a worker would be caught rather than
//! swallowed.
//!
//! A handful of cases are rejected by hyper before any Misty code runs (an
//! invalid request target, for instance). Those are called out where they occur
//! and asserted on status alone, because the body is not ours to shape.

mod common;

use common::{b64_encode, bootstrap, Harness, Vault};
use misty_server::ItemId;

/// Every endpoint, as `(method, path, body)` — enough to aim a hostile request at.
fn surface(vault: &str, item: &str) -> Vec<(&'static str, String, Option<Vec<u8>>)> {
    vec![
        ("GET", "/healthz".to_owned(), None),
        ("GET", "/v1/time?nonce=AAAAAAAAAAAAAAAAAAAAAA".to_owned(), None),
        ("GET", "/v1/quota".to_owned(), None),
        (
            "POST",
            "/v1/auth/challenge".to_owned(),
            Some(br#"{"vault_id":"00000000000000000000000000000000","device_id":"00000000000000000000000000000000"}"#.to_vec()),
        ),
        ("POST", "/v1/auth/refresh".to_owned(), Some(br#"{"refresh_token":"x"}"#.to_vec())),
        ("GET", format!("/v1/vaults/{vault}/changes"), None),
        (
            "PUT",
            format!("/v1/vaults/{vault}/items/{item}"),
            Some(br#"{"envelope":"AAAA"}"#.to_vec()),
        ),
        ("DELETE", format!("/v1/vaults/{vault}/items/{item}"), None),
        ("GET", format!("/v1/enroll/poll/{item}"), None),
    ]
}

#[tokio::test]
async fn a_declared_four_gigabyte_body_is_refused_from_the_header() {
    let harness = Harness::start().await;
    let raw = b"POST /v1/auth/challenge HTTP/1.1\r\n\
                Host: misty.test\r\n\
                Connection: close\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 4294967296\r\n\r\n";
    let reply = harness.send_raw(raw).await;
    reply.expect_status(413);
    assert_eq!(reply.error_code(), "payload_too_large");

    // Not a byte of that body was ever read, so the server is untouched.
    harness
        .send("GET", "/healthz", &[], None)
        .await
        .expect_status(200);
}

#[tokio::test]
async fn a_chunked_body_over_the_limit_is_refused_while_it_streams() {
    let harness = Harness::start_with(|config| config.max_body_bytes = 4096).await;
    let payload = "A".repeat(16 * 1024);
    let mut raw = Vec::new();
    raw.extend_from_slice(
        b"POST /v1/auth/challenge HTTP/1.1\r\n\
          Host: misty.test\r\n\
          Connection: close\r\n\
          Content-Type: application/json\r\n\
          Transfer-Encoding: chunked\r\n\r\n",
    );
    // No Content-Length to pre-check, so this exercises `DefaultBodyLimit`, the
    // backstop.
    raw.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
    raw.extend_from_slice(payload.as_bytes());
    raw.extend_from_slice(b"\r\n0\r\n\r\n");

    let reply = harness.send_raw(&raw).await;
    reply.expect_status(413);
    assert_eq!(reply.error_code(), "payload_too_large");
    harness
        .send("GET", "/healthz", &[], None)
        .await
        .expect_status(200);
}

#[tokio::test]
async fn an_envelope_over_the_cap_is_refused_with_the_cap_named() {
    let harness = Harness::start_with(|config| config.max_envelope_bytes = 1024).await;
    let client = bootstrap(&harness).await;
    let item = ItemId::from_bytes(common::random16());

    let reply = harness
        .json(
            "PUT",
            &format!(
                "/v1/vaults/{}/items/{}",
                client.vault.to_hex(),
                item.to_hex()
            ),
            &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&vec![7u8; 4096]) }),
        )
        .await;
    reply.expect_status(413);
    assert_eq!(reply.error_code(), "payload_too_large");
    assert!(reply.value()["message"].as_str().unwrap().contains("1024"));
}

#[tokio::test]
async fn malformed_base64_and_json_are_typed_four_hundreds() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );
    let bearer = client.bearer();
    let headers = [
        ("Authorization", bearer.as_str()),
        ("If-None-Match", "*"),
        ("Content-Type", "application/json"),
    ];

    let bodies: Vec<Vec<u8>> = vec![
        br#"{"envelope":"!!!!"}"#.to_vec(),
        br#"{"envelope":"AQI"}"#.to_vec(), // non-canonical padding
        br#"{"envelope":""}"#.to_vec(),    // empty
        br#"{"envelope":"AAAA","extra":1}"#.to_vec(), // unknown field
        br#"{"envelope":42}"#.to_vec(),    // wrong type
        br#"{}"#.to_vec(),                 // missing field
        br#"[]"#.to_vec(),                 // not an object
        br#""a string""#.to_vec(),
        b"null".to_vec(),
        b"".to_vec(),
        b"{".to_vec(),
        vec![0xff, 0xfe, 0xfd], // not UTF-8
        format!(r#"{{"envelope":{}}}"#, "[".repeat(2000)).into_bytes(), // deeply nested
    ];

    for body in bodies {
        let reply = harness.send("PUT", &path, &headers, Some(&body)).await;
        assert_eq!(
            reply.status,
            400,
            "body {:?} should be a 400",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(reply.error_code(), "bad_request");
    }
    harness
        .send("GET", "/healthz", &[], None)
        .await
        .expect_status(200);
}

#[tokio::test]
async fn the_pre_spec_base64_forms_are_refused_on_every_hex_field() {
    // A regression guard for SPEC §6.1.1. This server shipped standard base64 for
    // nonces, signatures and public keys, and `misty-sync` shipped hex; the two
    // did not interoperate and nothing caught it until an interop test existed.
    // Accepting both would have "fixed" it and been unsound — a hex string is also
    // well-formed base64 — so the old forms must stay refused, loudly.
    let harness = Harness::start().await;
    let identity = misty_crypto::identity::DeviceIdentity::generate().unwrap();
    let vault = misty_server::VaultId::from_bytes(common::random16());
    let device = misty_server::DeviceId::from_bytes(*identity.device_id().as_bytes());
    let nonce = common::challenge(&harness, vault, device).await;
    let signature = identity.sign(&misty_server::routes::auth::auth_payload(
        vault, device, &nonce,
    ));

    // Each field, one at a time, in the retired encoding.
    let hex_body = serde_json::json!({
        "vault_id": vault.to_hex(),
        "device_id": device.to_hex(),
        "nonce": hex::encode(&nonce),
        "sig": hex::encode(signature.as_bytes()),
        "ed25519_pub": hex::encode(identity.ed25519_public()),
    });
    for field in ["nonce", "sig", "ed25519_pub"] {
        let mut body = hex_body.clone();
        let raw = match field {
            "nonce" => nonce.clone(),
            "sig" => signature.as_bytes().to_vec(),
            _ => identity.ed25519_public().to_vec(),
        };
        body[field] = serde_json::Value::String(b64_encode(&raw));
        let reply = harness.json("POST", "/v1/auth/verify", &[], &body).await;
        assert_eq!(reply.status, 400, "base64 {field} should be refused");
        assert_eq!(reply.error_code(), "bad_request");
    }

    // Uppercase hex is not a second spelling either.
    let mut body = hex_body.clone();
    body["sig"] = serde_json::Value::String(hex::encode(signature.as_bytes()).to_uppercase());
    harness
        .json("POST", "/v1/auth/verify", &[], &body)
        .await
        .expect_status(400);

    // `/v1/time` no longer takes base64url, which was this server's own form.
    for wrong in [common::b64_encode(&[0x5au8; 32]), {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5au8; 32])
    }] {
        let reply = harness
            .send("GET", &format!("/v1/time?nonce={wrong}"), &[], None)
            .await;
        assert_eq!(reply.status, 400, "nonce {wrong} should be refused");
    }

    // And `/v1/enroll/begin`'s retired field name is gone, not aliased.
    let reply = harness
        .json(
            "POST",
            "/v1/enroll/begin",
            &[],
            &serde_json::json!({
                "enroll_id": hex::encode(common::random16()),
                "x25519_pub": hex::encode([2u8; 32]),
                "sealed_request": b64_encode(b"opaque"),
            }),
        )
        .await;
    reply.expect_status(400);
}

#[tokio::test]
async fn a_rejection_message_that_quotes_multi_byte_input_does_not_panic() {
    // The rejection text for an unknown field quotes the field name, and that
    // text is clipped before it is returned. Clipping a `String` at a fixed byte
    // offset panics if the offset lands inside a multi-byte character — and with
    // the workspace's `panic = "abort"` release profile, a panic in a handler is a
    // process-level denial of service rather than a `500`. Hence a field name made
    // entirely of 3-byte characters, long enough to cross the clip point.
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );

    for filler in ["日", "é", "🔐", "\u{0301}"] {
        let field = filler.repeat(300);
        let body = format!(r#"{{"envelope":"AAAA","{field}":1}}"#);
        let reply = harness
            .send(
                "PUT",
                &path,
                &[
                    ("Authorization", client.bearer().as_str()),
                    ("If-None-Match", "*"),
                    ("Content-Type", "application/json"),
                ],
                Some(body.as_bytes()),
            )
            .await;
        assert_eq!(reply.status, 400, "filler {filler:?}");
        assert_eq!(reply.error_code(), "bad_request");
    }

    // Still alive, which is the actual assertion.
    harness
        .send("GET", "/healthz", &[], None)
        .await
        .expect_status(200);
}

#[tokio::test]
async fn a_body_that_is_not_json_is_an_unsupported_media_type() {
    let harness = Harness::start().await;
    for content_type in ["text/plain", "application/octet-stream", "application/xml"] {
        let reply = harness
            .send(
                "POST",
                "/v1/auth/challenge",
                &[("Content-Type", content_type)],
                Some(b"{}"),
            )
            .await;
        reply.expect_status(415);
        assert_eq!(reply.error_code(), "unsupported_media_type");
    }
    // No Content-Type at all is the same answer.
    let reply = harness
        .send("POST", "/v1/auth/challenge", &[], Some(b"{}"))
        .await;
    reply.expect_status(415);
}

#[tokio::test]
async fn identifiers_have_exactly_one_spelling() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let good = client.vault.to_hex();

    let hostile_ids = [
        "ABABABABABABABABABABABABABABABAB", // uppercase is rejected, not folded
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "0123456789abcdef",                   // too short
        "0123456789abcdef0123456789abcdef00", // too long
        "0123456789abcde%200123456789abcde",  // a percent-encoded space
        "................................",
        "%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00",
    ];
    for id in hostile_ids {
        let reply = harness
            .send(
                "GET",
                &format!("/v1/vaults/{id}/changes"),
                &[("Authorization", client.bearer().as_str())],
                None,
            )
            .await;
        assert_eq!(reply.status, 400, "vault id {id:?} should be a 400");
        assert_eq!(reply.error_code(), "bad_request");

        let reply = harness
            .send(
                "DELETE",
                &format!("/v1/vaults/{good}/items/{id}"),
                &[
                    ("Authorization", client.bearer().as_str()),
                    ("If-Match", "\"1\""),
                ],
                None,
            )
            .await;
        assert_eq!(reply.status, 400, "item id {id:?} should be a 400");
    }
}

#[tokio::test]
async fn path_traversal_never_reaches_a_route_or_a_file() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault = client.vault.to_hex();

    let attempts = [
        format!("/v1/vaults/{vault}/items/../../../../../../etc/passwd"),
        format!("/v1/vaults/{vault}/items/..%2f..%2f..%2fetc%2fpasswd"),
        format!("/v1/vaults/{vault}/items/%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        format!("/v1/vaults/{vault}/items/.."),
        format!("/v1/vaults/{vault}/items/"),
        format!("/v1/vaults/../../{vault}/items/x"),
        "/../../etc/passwd".to_owned(),
        "/healthz/../v1/quota".to_owned(),
    ];
    for path in attempts {
        let reply = harness
            .send(
                "DELETE",
                &path,
                &[
                    ("Authorization", client.bearer().as_str()),
                    ("If-Match", "\"1\""),
                ],
                None,
            )
            .await;
        assert!(
            matches!(reply.status, 400 | 401 | 404 | 405),
            "{path} produced {}",
            reply.status
        );
        // Whatever the answer, it is our JSON and it mentions no filesystem.
        let text = String::from_utf8_lossy(&reply.body);
        assert!(!text.contains("root:"), "{path} leaked a file: {text}");
        assert!(reply.value()["error"].is_string(), "{path} was not typed");
    }
}

#[tokio::test]
async fn absurd_query_values_are_refused_rather_than_clamped() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault = client.vault.to_hex();
    let bearer = client.bearer();

    let queries = [
        "since=-1",
        "since=1e9",
        "since=99999999999999999999999999999999",
        "since=9223372036854775808",
        "since=0x10",
        "since=%00",
        "limit=0",
        "limit=100000",
        "limit=-5",
        "limit=abc",
        &format!("since={}", "9".repeat(4000)),
    ];
    for query in queries {
        let reply = harness
            .send(
                "GET",
                &format!("/v1/vaults/{vault}/changes?{query}"),
                &[("Authorization", bearer.as_str())],
                None,
            )
            .await;
        assert_eq!(reply.status, 400, "{query} should be a 400");
        assert_eq!(reply.error_code(), "bad_request");
    }

    // The largest sequence number the server can ever assign is accepted, and
    // simply returns nothing.
    let reply = harness
        .send(
            "GET",
            &format!("/v1/vaults/{vault}/changes?since=9223372036854775807"),
            &[("Authorization", bearer.as_str())],
            None,
        )
        .await;
    reply.expect_status(200);
    assert_eq!(reply.value()["changes"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn a_write_needs_a_precondition_and_only_a_sane_one() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault_state = Vault::new(&client.identity);
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );
    let body = serde_json::json!({
        "envelope": b64_encode(&vault_state.seal(&item, b"x", &client.identity))
    });

    // None at all.
    let bearer = client.bearer();
    let reply = harness
        .json("PUT", &path, &[("Authorization", bearer.as_str())], &body)
        .await;
    reply.expect_status(428);
    assert_eq!(reply.error_code(), "precondition_required");

    for headers in [
        vec![("If-Match", "*")],
        vec![("If-Match", "W/\"1\"")],
        vec![("If-Match", "\"\"")],
        vec![("If-Match", "one")],
        vec![("If-Match", "1.5")],
        vec![("If-Match", "18446744073709551616")],
        vec![("If-None-Match", "\"1\"")],
        vec![("If-None-Match", "**")],
        vec![("If-Match", "1"), ("If-None-Match", "*")],
    ] {
        let mut all = vec![("Authorization", bearer.as_str())];
        for (name, value) in &headers {
            all.push((name, value));
        }
        let reply = harness.json("PUT", &path, &all, &body).await;
        assert_eq!(reply.status, 400, "{headers:?} should be a 400");
    }

    // DELETE cannot create, so `If-None-Match: *` is meaningless there.
    let reply = harness
        .send(
            "DELETE",
            &path,
            &[("Authorization", bearer.as_str()), ("If-None-Match", "*")],
            None,
        )
        .await;
    reply.expect_status(400);
}

#[tokio::test]
async fn the_wrong_method_on_a_real_path_is_a_typed_405() {
    let harness = Harness::start().await;
    for (method, path) in [
        ("POST", "/v1/quota"),
        ("DELETE", "/healthz"),
        ("PUT", "/v1/auth/challenge"),
        ("GET", "/v1/enroll/begin"),
    ] {
        let reply = harness.send(method, path, &[], None).await;
        reply.expect_status(405);
        assert_eq!(reply.error_code(), "method_not_allowed");
    }
}

#[tokio::test]
async fn hostile_authorization_headers_are_unauthorized_not_five_hundred() {
    let harness = Harness::start().await;
    for value in [
        "Bearer",
        "Bearer ",
        "Bearer !!!!",
        "Bearer AAAA",
        &format!("Bearer {}", "A".repeat(4000)),
        "bearer x",
        "Basic dXNlcjpwYXNz",
        "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let reply = harness
            .send("GET", "/v1/quota", &[("Authorization", value)], None)
            .await;
        assert_eq!(reply.status, 401, "{value:?} should be a 401");
        assert_eq!(reply.error_code(), "unauthorized");
    }
}

#[tokio::test]
async fn hostile_time_nonces_and_enrollment_fields_are_refused() {
    let harness = Harness::start().await;

    for query in [
        "",
        "?nonce=",
        "?nonce=AAAA",
        "?nonce=!!!!!!!!!!!!!!!!!!!!!!",
        // Over the server's own cap, well inside hyper's URI limit, so this is
        // our rejection rather than the framework's.
        &format!("?nonce={}", "A".repeat(200)),
        "?nonce=%00%00%00%00",
        "?other=1",
    ] {
        let reply = harness
            .send("GET", &format!("/v1/time{query}"), &[], None)
            .await;
        assert_eq!(reply.status, 400, "nonce {query:?} should be a 400");
        assert_eq!(reply.error_code(), "bad_request");
    }

    // A megabyte of query string is refused by hyper as a too-long request
    // target before Misty sees it. Asserted on status alone: the body is not ours.
    let enormous = harness
        .send(
            "GET",
            &format!("/v1/time?nonce={}", "A".repeat(100_000)),
            &[],
            None,
        )
        .await;
    assert!(
        matches!(enormous.status, 400 | 414 | 431),
        "an enormous URI produced {}",
        enormous.status
    );

    let enroll = hex::encode(common::random16());
    for body in [
        serde_json::json!({"enroll_id": "nope", "x25519_pub": b64_encode(&[0u8; 32]), "sealed_request": "AAAA"}),
        serde_json::json!({"enroll_id": enroll, "x25519_pub": "AAAA", "sealed_request": "AAAA"}),
        serde_json::json!({"enroll_id": enroll, "x25519_pub": b64_encode(&[0u8; 32]), "sealed_request": "!!!"}),
        serde_json::json!({"enroll_id": enroll, "x25519_pub": b64_encode(&[0u8; 33]), "sealed_request": "AAAA"}),
        serde_json::json!({"enroll_id": enroll, "sealed_request": "AAAA"}),
    ] {
        let reply = harness.json("POST", "/v1/enroll/begin", &[], &body).await;
        assert_eq!(reply.status, 400, "{body} should be a 400");
    }

    // An unrecognised `want` names what it expected.
    let reply = harness
        .send(
            "GET",
            &format!("/v1/enroll/poll/{enroll}?want=everything"),
            &[],
            None,
        )
        .await;
    reply.expect_status(400);
    assert!(reply.value()["message"].as_str().unwrap().contains("want"));

    harness
        .send("GET", "/healthz", &[], None)
        .await
        .expect_status(200);
}

#[tokio::test]
async fn a_hostile_request_target_is_rejected_before_any_misty_code_runs() {
    let harness = Harness::start().await;
    // Invalid request targets: hyper answers these itself, so only the status is
    // ours to assert. The point is that the connection is refused cleanly and the
    // server survives.
    for raw in [
        &b"GET /\xff\xfe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"[..],
        &b"GET /v1/quota\x00 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"[..],
        &b"GET  HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"[..],
    ] {
        let reply = harness.send_raw(raw).await;
        assert!(
            reply.status >= 400,
            "hostile target produced {}",
            reply.status
        );
    }
    harness
        .send("GET", "/healthz", &[], None)
        .await
        .expect_status(200);
}

#[tokio::test]
async fn every_endpoint_survives_a_body_it_did_not_ask_for() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let item = ItemId::from_bytes(common::random16());

    for (method, path, _) in surface(&client.vault.to_hex(), &item.to_hex()) {
        for body in [
            &br#"{"envelope":null}"#[..],
            &b"\x00\x01\x02"[..],
            &br#"{"vault_id":"../../etc","device_id":" "}"#[..],
        ] {
            let reply = harness
                .send(
                    method,
                    &path,
                    &[
                        ("Content-Type", "application/json"),
                        ("Authorization", client.bearer().as_str()),
                        ("If-Match", "\"1\""),
                    ],
                    Some(body),
                )
                .await;
            assert!(
                reply.status < 500,
                "{method} {path} produced {} for {:?}",
                reply.status,
                String::from_utf8_lossy(body)
            );
            assert!(
                reply.value()["error"].is_string() || reply.status < 400,
                "{method} {path} was not a typed error"
            );
        }
    }
    harness
        .send("GET", "/healthz", &[], None)
        .await
        .expect_status(200);
}
