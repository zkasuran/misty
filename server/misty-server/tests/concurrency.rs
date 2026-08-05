// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Concurrency: exactly one writer wins, and `seq` survives the interleaving.
//!
//! SPEC §6.1 promises clients a gap-free ordered change feed. That promise is
//! only worth something under concurrent writes, so these tests fire real
//! simultaneous requests at a real socket and then walk the feed to check that no
//! row was skipped, duplicated, or handed a `seq` twice.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use common::{b64_decode, b64_encode, bootstrap, Harness, Vault};
use misty_server::ItemId;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_simultaneous_writes_to_one_item_produce_one_winner_and_one_conflict() {
    let harness = Arc::new(Harness::start().await);
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );

    // Establish version 1 so both racers can send the same `If-Match`.
    let base = vault.seal(&item, b"base", &client.identity);
    harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&base) }),
        )
        .await
        .expect_status(200);

    let left = vault.seal(&item, b"left wrote this", &client.identity);
    let right = vault.seal(&item, b"right wrote this", &client.identity);

    let mut tasks = Vec::new();
    for envelope in [left.clone(), right.clone()] {
        let harness = Arc::clone(&harness);
        let path = path.clone();
        let bearer = client.bearer();
        tasks.push(tokio::spawn(async move {
            harness
                .json(
                    "PUT",
                    &path,
                    &[("Authorization", &bearer), ("If-Match", "\"1\"")],
                    &serde_json::json!({ "envelope": b64_encode(&envelope) }),
                )
                .await
        }));
    }
    let mut replies = Vec::new();
    for task in tasks {
        replies.push(task.await.expect("join"));
    }

    let winners: Vec<_> = replies.iter().filter(|r| r.status == 200).collect();
    let losers: Vec<_> = replies.iter().filter(|r| r.status == 409).collect();
    assert_eq!(winners.len(), 1, "exactly one write may win");
    assert_eq!(losers.len(), 1, "and the other must be told to merge");
    assert_eq!(winners[0].value()["version"], "2");

    // The loser is handed the winner's envelope, which is what makes a
    // client-side merge possible without a second round trip.
    let loser = &losers[0];
    assert_eq!(loser.value()["version"], "2");
    let returned = b64_decode(loser.value()["envelope"].as_str().unwrap());
    assert!(
        returned == left || returned == right,
        "the 409 must carry whichever envelope actually won"
    );
    assert!(
        vault.open(&item, &returned).is_ok(),
        "and it must be intact"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_simultaneous_creates_of_one_item_produce_one_winner() {
    let harness = Arc::new(Harness::start().await);
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );

    let mut tasks = Vec::new();
    for label in [&b"first"[..], &b"second"[..], &b"third"[..]] {
        let envelope = vault.seal(&item, label, &client.identity);
        let harness = Arc::clone(&harness);
        let path = path.clone();
        let bearer = client.bearer();
        tasks.push(tokio::spawn(async move {
            harness
                .json(
                    "PUT",
                    &path,
                    &[("Authorization", &bearer), ("If-None-Match", "*")],
                    &serde_json::json!({ "envelope": b64_encode(&envelope) }),
                )
                .await
        }));
    }
    let mut statuses = Vec::new();
    for task in tasks {
        statuses.push(task.await.expect("join").status);
    }
    statuses.sort_unstable();
    assert_eq!(statuses, vec![200, 409, 409]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_simultaneous_put_and_delete_cannot_both_win() {
    let harness = Arc::new(Harness::start().await);
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );

    let base = vault.seal(&item, b"base", &client.identity);
    harness
        .json(
            "PUT",
            &path,
            &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
            &serde_json::json!({ "envelope": b64_encode(&base) }),
        )
        .await
        .expect_status(200);

    let writer = {
        let harness = Arc::clone(&harness);
        let path = path.clone();
        let bearer = client.bearer();
        let envelope = vault.seal(&item, b"updated", &client.identity);
        tokio::spawn(async move {
            harness
                .json(
                    "PUT",
                    &path,
                    &[("Authorization", &bearer), ("If-Match", "\"1\"")],
                    &serde_json::json!({ "envelope": b64_encode(&envelope) }),
                )
                .await
                .status
        })
    };
    let deleter = {
        let harness = Arc::clone(&harness);
        let path = path.clone();
        let bearer = client.bearer();
        tokio::spawn(async move {
            harness
                .send(
                    "DELETE",
                    &path,
                    &[("Authorization", &bearer), ("If-Match", "\"1\"")],
                    None,
                )
                .await
                .status
        })
    };

    let mut statuses = vec![writer.await.expect("join"), deleter.await.expect("join")];
    statuses.sort_unstable();
    assert_eq!(statuses, vec![200, 409]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_writes_leave_the_feed_gap_free_and_seq_unique() {
    const WRITERS: usize = 24;

    let harness = Arc::new(Harness::start().await);
    let client = bootstrap(&harness).await;
    let vault = Arc::new(Vault::new(&client.identity));

    let mut tasks = Vec::new();
    for index in 0..WRITERS {
        let item = ItemId::from_bytes(common::random16());
        let envelope = vault.seal(&item, format!("item {index}").as_bytes(), &client.identity);
        let harness = Arc::clone(&harness);
        let bearer = client.bearer();
        let vault_hex = client.vault.to_hex();
        tasks.push(tokio::spawn(async move {
            let reply = harness
                .json(
                    "PUT",
                    &format!("/v1/vaults/{vault_hex}/items/{}", item.to_hex()),
                    &[("Authorization", &bearer), ("If-None-Match", "*")],
                    &serde_json::json!({ "envelope": b64_encode(&envelope) }),
                )
                .await;
            reply.expect_status(200);
            (item.to_hex(), reply.value()["seq"].as_u64().unwrap())
        }));
    }

    let mut assigned = BTreeSet::new();
    let mut items = BTreeSet::new();
    for task in tasks {
        let (item, seq) = task.await.expect("join");
        assert!(assigned.insert(seq), "seq {seq} was handed out twice");
        items.insert(item);
    }
    // Allocation happens inside the same transaction as the row write, so the
    // numbers are not merely unique — they are 1..=N with no holes.
    assert_eq!(
        assigned.iter().copied().collect::<Vec<_>>(),
        (1..=WRITERS as u64).collect::<Vec<_>>()
    );

    // Walk the feed one row at a time. Every item appears exactly once, and the
    // cursor never rewinds — the property a client depends on.
    let mut seen = Vec::new();
    let mut cursor = 0u64;
    loop {
        let reply = harness
            .send(
                "GET",
                &format!(
                    "/v1/vaults/{}/changes?since={cursor}&limit=1",
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
            assert!(seq > cursor);
            seen.push(entry["item_id"].as_str().unwrap().to_owned());
        }
        let next = value["next_seq"].as_u64().unwrap();
        if !value["has_more"].as_bool().unwrap() {
            break;
        }
        assert!(
            next > cursor,
            "next_seq must advance or the walk cannot end"
        );
        cursor = next;
    }
    assert_eq!(seen.len(), WRITERS, "no row may be skipped or repeated");
    assert_eq!(seen.iter().cloned().collect::<BTreeSet<_>>(), items);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_updates_to_one_item_keep_version_and_seq_moving_forward() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);
    let item = ItemId::from_bytes(common::random16());
    let path = format!(
        "/v1/vaults/{}/items/{}",
        client.vault.to_hex(),
        item.to_hex()
    );

    let mut version = 0u64;
    let mut last_seq = 0u64;
    for round in 0..10 {
        let envelope = vault.seal(&item, format!("round {round}").as_bytes(), &client.identity);
        let precondition = if version == 0 {
            ("If-None-Match", "*".to_owned())
        } else {
            ("If-Match", format!("\"{version}\""))
        };
        let reply = harness
            .json(
                "PUT",
                &path,
                &[
                    ("Authorization", &client.bearer()),
                    (precondition.0, &precondition.1),
                ],
                &serde_json::json!({ "envelope": b64_encode(&envelope) }),
            )
            .await;
        reply.expect_status(200);
        let next_version: u64 = reply.value()["version"]
            .as_str()
            .expect("§6.1.1: a token, not a number")
            .parse()
            .expect("this server's tokens happen to be decimal");
        let next_seq = reply.value()["seq"].as_u64().unwrap();
        assert_eq!(next_version, version + 1);
        assert!(next_seq > last_seq);
        version = next_version;
        last_seq = next_seq;
    }

    // One item, ten writes: one row, version 10, and the feed reports it once.
    let reply = harness
        .send(
            "GET",
            &format!("/v1/vaults/{}/changes?since=0", client.vault.to_hex()),
            &[("Authorization", client.bearer().as_str())],
            None,
        )
        .await;
    let value = reply.value();
    assert_eq!(value["changes"].as_array().unwrap().len(), 1);
    assert_eq!(value["changes"][0]["version"], "10");
    assert_eq!(value["changes"][0]["seq"], 10);
}
