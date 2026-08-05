// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Misty sync server — a versioned blob store that knows nothing.
//!
//! This crate implements [`docs/SPEC.md`] §6. It is the one Misty component a
//! third party is expected to run, so the design question it answers over and
//! over is:
//!
//! > What does an attacker with a full database dump **and** the server signing
//! > key learn?
//!
//! The answer must stay: envelope sizes (already bucketed to 256 bytes by the
//! client, SPEC §2.4), item counts, and write timing. Nothing else.
//!
//! # What is deliberately absent
//!
//! * **No user table.** A vault is addressed by a random 16-byte `vault_id`.
//!   There is no email, phone, username, or password hash anywhere in the
//!   schema — nothing to enumerate and nothing to phish.
//! * **No password grant.** Authentication is Ed25519 challenge-response over
//!   the device key ([`routes::auth`]).
//! * **No envelope parsing.** The server never looks inside an envelope, never
//!   hashes one, never records a length other than the blob's own, and never
//!   merges. Refusing to understand the payload is the security property; see
//!   [`store`].
//! * **No `misty-crypto` dependency** outside dev-dependencies, so the server
//!   cannot construct or open an envelope even by mistake.
//!
//! # Threat model hooks
//!
//! `A1` (hostile operator) is answered by the two points above plus
//! client-signed envelopes. `A2` (network attacker) is answered by signed,
//! nonce-bound `/v1/time` responses ([`routes::meta`]). `A6` (attacker with the
//! database who tries to enroll a device) is answered by the device table being
//! *only* an access-control cache: trust lives in the client-signed roster
//! (SPEC §6.2), so a server-injected device produces writes every client
//! rejects. `tests/hostile_server.rs` proves each of these against the real
//! HTTP surface.
//!
//! # Shape
//!
//! * [`config`] — every knob, read from the environment.
//! * [`store`] — the storage trait, its row types, and the SQLite backend.
//! * [`routes`] — one module per group of SPEC §6.1 endpoints.
//! * [`rate_limit`] — per-`vault_id` and per-IP token buckets. IPs live here
//!   and nowhere durable.
//! * [`token`] — opaque bearer tokens, stored only as BLAKE2b-256 hashes.
//! * [`time_key`] — the server's Ed25519 signing key for `/v1/time`.
//!
//! [`docs/SPEC.md`]: https://github.com/zkasuran/misty/blob/main/docs/SPEC.md
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    warn(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::indexing_slicing
    )
)]

pub mod config;
pub mod error;
pub mod ids;
pub mod rate_limit;
pub mod routes;
pub mod store;
pub mod time_key;
pub mod token;

pub use config::Config;
pub use error::{ApiError, ErrorCode};
pub use ids::{DeviceId, EnrollId, ItemId, VaultId};
pub use routes::{router, serve, AppState};
pub use store::{sqlite::SqliteStore, Store};
pub use time_key::TimeKey;
