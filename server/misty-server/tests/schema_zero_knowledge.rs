// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The zero-knowledge property as an executable check.
//!
//! The claim in `README.md` is that an attacker holding a full database dump and
//! the signing key learns envelope sizes (already bucketed to 256 bytes by the
//! client), item counts, and write timing — and nothing else. That claim is only
//! as good as the schema, so the schema is asserted here against a hard-coded
//! allowlist. Adding a column is then a deliberate act with a failing test
//! attached, rather than something that happens on a Tuesday and is noticed in an
//! audit two years later.

mod common;

use common::{b64_encode, bootstrap, Harness, Vault};
use misty_server::store::Store;
use misty_server::ItemId;

/// Every column the schema is allowed to have, with why it is harmless.
///
/// Each entry is an identifier the *server* assigned, an identifier the client
/// chose at random, a server-clock timestamp, or the opaque blob itself. Nothing
/// is derived from the contents of an envelope.
const ALLOWED: &[(&str, &str)] = &[
    // Vault registry. `next_seq` is the change cursor; `created_at` is the
    // server's own clock.
    ("vaults", "vault_id"),
    ("vaults", "next_seq"),
    ("vaults", "created_at"),
    // Access-control cache, never a source of trust (SPEC §6.2).
    ("devices", "vault_id"),
    ("devices", "device_id"),
    ("devices", "ed25519_pub"),
    ("devices", "admitted_at"),
    ("devices", "admitted_by"),
    // The blob store. `envelope` is opaque; `deleted` is advisory; `updated_at`
    // is the server's clock at write time, which is the write-timing leak the
    // threat model already accepts.
    ("items", "vault_id"),
    ("items", "item_id"),
    ("items", "seq"),
    ("items", "version"),
    ("items", "envelope"),
    ("items", "deleted"),
    ("items", "updated_at"),
    // Auth. Every `*_hash` here is a hash of a value the server generated
    // itself, never of anything a client sent.
    ("challenges", "nonce_hash"),
    ("challenges", "vault_id"),
    ("challenges", "device_id"),
    ("challenges", "expires_at"),
    ("access_tokens", "token_hash"),
    ("access_tokens", "vault_id"),
    ("access_tokens", "device_id"),
    ("access_tokens", "family"),
    ("access_tokens", "expires_at"),
    ("refresh_tokens", "token_hash"),
    ("refresh_tokens", "vault_id"),
    ("refresh_tokens", "device_id"),
    ("refresh_tokens", "family"),
    ("refresh_tokens", "expires_at"),
    ("refresh_tokens", "consumed_at"),
    ("revoked_families", "family"),
    ("revoked_families", "revoked_at"),
    // The enrollment dead drop. Both blobs are opaque.
    ("enrollments", "enroll_id"),
    ("enrollments", "x25519_pub"),
    ("enrollments", "enroll_request"),
    ("enrollments", "request_taken"),
    ("enrollments", "sealed_response"),
    ("enrollments", "expires_at"),
];

#[tokio::test]
async fn the_schema_is_exactly_the_allowlist() {
    let harness = Harness::start().await;
    let actual = harness.store.schema_columns().unwrap();

    for (table, column) in &actual {
        assert!(
            ALLOWED.contains(&(table.as_str(), column.as_str())),
            "{table}.{column} is not on the zero-knowledge allowlist. \
             If it is genuinely harmless, add it to ALLOWED with a comment saying why; \
             if it is derived from envelope contents, it must not exist."
        );
    }
    for (table, column) in ALLOWED {
        assert!(
            actual.iter().any(|(t, c)| t == table && c == column),
            "{table}.{column} is on the allowlist but missing from the schema"
        );
    }
    assert_eq!(actual.len(), ALLOWED.len());
}

#[tokio::test]
async fn no_column_is_named_after_a_property_of_an_envelope() {
    let harness = Harness::start().await;
    // The forbidden vocabulary. A column called `envelope_len`, `payload_hash`,
    // `item_count`, or `content_sha256` would each be a way of recording
    // something about a payload the server is not allowed to know.
    let forbidden = [
        "len",
        "length",
        "size",
        "bytes",
        "digest",
        "sha",
        "blake",
        "crc",
        "checksum",
        "count",
        "plaintext",
        "payload",
        "content",
        "kind",
        "issuer",
        "account",
        "epoch",
        "signer",
    ];
    for (table, column) in harness.store.schema_columns().unwrap() {
        let lowered = column.to_ascii_lowercase();
        for word in forbidden {
            assert!(
                !lowered.contains(word),
                "{table}.{column} contains {word:?}, which suggests a value derived from an \
                 envelope's contents"
            );
        }
    }
}

#[tokio::test]
async fn there_is_no_user_table_to_enumerate() {
    let harness = Harness::start().await;
    let identity = [
        "email",
        "mail",
        "phone",
        "msisdn",
        "username",
        "user_name",
        "login",
        "password",
        "passwd",
        "pwhash",
        "password_hash",
        "name",
        "display_name",
        "handle",
        "address",
    ];
    for (table, column) in harness.store.schema_columns().unwrap() {
        let lowered = column.to_ascii_lowercase();
        for word in identity {
            assert!(
                !lowered.contains(word),
                "{table}.{column} contains {word:?}: the server has no user table, \
                 so there is nothing to enumerate and nothing to phish"
            );
        }
        assert_ne!(table.to_ascii_lowercase(), "users");
        assert_ne!(table.to_ascii_lowercase(), "accounts");
    }
}

#[tokio::test]
async fn stored_size_is_bucketed_so_it_does_not_identify_an_item() {
    let harness = Harness::start().await;
    let client = bootstrap(&harness).await;
    let vault = Vault::new(&client.identity);

    // Two payloads of very different lengths inside the same 256-byte bucket
    // (SPEC §2.4's `pad`). The server stores identical lengths, so the one size
    // it can see says nothing about which issuer an item belongs to.
    let short = ItemId::from_bytes(common::random16());
    let long = ItemId::from_bytes(common::random16());
    let short_envelope = vault.seal(&short, b"ab", &client.identity);
    let long_envelope = vault.seal(&long, &[b'x'; 200], &client.identity);
    assert_eq!(
        short_envelope.len(),
        long_envelope.len(),
        "the client's padding is what makes this true; the server relies on it"
    );

    for (item, envelope) in [(short, &short_envelope), (long, &long_envelope)] {
        harness
            .json(
                "PUT",
                &format!(
                    "/v1/vaults/{}/items/{}",
                    client.vault.to_hex(),
                    item.to_hex()
                ),
                &[("Authorization", &client.bearer()), ("If-None-Match", "*")],
                &serde_json::json!({ "envelope": b64_encode(envelope) }),
            )
            .await
            .expect_status(200);
    }

    let usage = harness.store.usage(client.vault).unwrap();
    assert_eq!(usage.item_count, 2);
    assert_eq!(usage.bytes_used, (short_envelope.len() * 2) as u64);

    // And a payload in the *next* bucket is visibly larger — the accepted
    // residual leak, at 256-byte granularity and no finer.
    let bigger = ItemId::from_bytes(common::random16());
    let bigger_envelope = vault.seal(&bigger, &[b'x'; 400], &client.identity);
    assert_eq!(bigger_envelope.len(), short_envelope.len() + 256);
}

#[tokio::test]
async fn the_database_is_one_ordinary_file() {
    // The self-hosting claim: one binary, one file. Asserted so a future change
    // to a directory-based backend does not slip past the README.
    let harness = Harness::start().await;
    bootstrap(&harness).await;
    let metadata = std::fs::metadata(&harness.database).expect("database file");
    assert!(metadata.is_file());
    assert!(metadata.len() > 0);
}
