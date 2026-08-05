// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Logging that cannot leak.
//!
//! SPEC §6.1 forbids writing IPs to a durable log, and the zero-knowledge claim
//! forbids writing anything about an envelope. This test installs a capturing
//! subscriber, drives a full request cycle against a live server, and then greps
//! the captured bytes for everything that must not be there.
//!
//! One test function, one file: `tracing`'s default subscriber is process-global,
//! so a second test in this binary would race for it. The single function is why
//! the flow below is long — it has to cover every path that logs.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{b64_encode, bootstrap, Harness, Vault};
use misty_server::ItemId;

/// A `MakeWriter` that appends every log line to a shared buffer.
#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut sink) = self.0.lock() {
            sink.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_log_line_contains_an_envelope_an_item_id_or_an_address() {
    let sink = Arc::new(Mutex::new(Vec::new()));
    tracing_subscriber::fmt()
        .json()
        .with_target(true)
        // Everything, including the levels a production instance would filter
        // out: a leak at `debug` is still a leak once someone raises the level.
        .with_max_level(tracing::Level::TRACE)
        .with_writer(Capture(Arc::clone(&sink)))
        .init();

    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );
    let envelope = vault.seal(
        &item,
        b"a secret the operator must not see",
        &client.identity,
    );
    let encoded = b64_encode(&envelope);

    // Write, read, conflict, delete, and 404 — every handler that logs.
    harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": encoded }),
        )
        .await
        .expect_status(200);
    harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": encoded }),
        )
        .await
        .expect_status(409);
    harness
        .send(
            "GET",
            &format!("/v1/vaults/{}/changes?since=0", client.vault.to_hex()),
            &[("Authorization", client.bearer().as_str())],
            None,
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
    harness
        .send("GET", &path, &[], None)
        .await
        .expect_status(405);
    harness
        .send("GET", "/v1/nope", &[], None)
        .await
        .expect_status(404);

    // The refresh-reuse path, which logs a warning naming the vault.
    harness
        .json(
            "POST",
            "/v1/auth/refresh",
            &[],
            &serde_json::json!({ "refresh_token": client.refresh }),
        )
        .await
        .expect_status(200);
    harness
        .json(
            "POST",
            "/v1/auth/refresh",
            &[],
            &serde_json::json!({ "refresh_token": client.refresh }),
        )
        .await
        .expect_status(401);

    // The rate-limit path, on a second server tuned to trip immediately.
    let tight = Harness::start_with(|config| {
        config.rate_limit_ip_per_minute = 1;
        config.rate_limit_burst = 1;
    })
    .await;
    tight
        .send("GET", "/healthz", &[], None)
        .await
        .expect_status(200);
    tight
        .send("GET", "/healthz", &[], None)
        .await
        .expect_status(429);

    let captured = sink.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&captured).into_owned();
    assert!(!text.is_empty(), "the subscriber captured nothing");
    assert!(
        text.contains("\"message\":\"request\""),
        "no access log at all"
    );
    assert!(
        text.contains("rate limited"),
        "the rate-limit path did not log"
    );

    // --- what must never appear -------------------------------------------
    let item_hex = item.to_hex();
    assert!(
        !text.contains(&item_hex),
        "an item id reached a log line: {item_hex}"
    );
    assert!(!text.contains(&item_hex.to_ascii_uppercase()));
    assert!(
        !text.contains(&client.vault.to_hex()),
        "a full vault id reached a log line"
    );
    assert!(
        text.contains(&client.vault.log_prefix()),
        "the 4-byte vault prefix is deliberately present, for correlation"
    );
    assert!(!text.contains(&encoded), "an envelope reached a log line");
    assert!(
        !text.contains(&client.access),
        "an access token reached a log line"
    );
    assert!(
        !text.contains(&client.refresh),
        "a refresh token reached a log line"
    );
    let offenders: Vec<&str> = text.lines().filter(|l| l.contains("127.0.0.1")).collect();
    assert!(
        offenders.is_empty(),
        "a client address reached a log line: {offenders:?}"
    );
    assert!(
        !text.contains(&harness.addr.port().to_string()),
        "a socket detail reached a log line"
    );

    // No window of the raw envelope survives either, which catches a leak that
    // re-encoded the bytes rather than copying the base64 verbatim.
    for window in envelope.windows(16) {
        assert!(
            !captured.windows(16).any(|w| w == window),
            "raw envelope bytes reached a log line"
        );
    }

    // The route template is what replaced the path, so an operator still gets a
    // useful log.
    assert!(
        text.contains("/v1/vaults/{id}/items/{id}"),
        "the sanitised route is missing, so the access log is useless"
    );
}
