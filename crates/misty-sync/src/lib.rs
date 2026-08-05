// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Misty's sync client: the offline-first half of [`docs/SPEC.md`] §6.
//!
//! The server is a versioned blob store that knows nothing (SPEC §6). This crate
//! is the half that knows everything and trusts none of it: it verifies every
//! envelope against the client-signed device roster before anything is decrypted,
//! refuses a change feed that goes backwards, ignores the server's `deleted` flag
//! outright, checks the signature on `/v1/time` against a pinned key, and pins the
//! TLS certificate where the platform lets it.
//!
//! * [`transport`] — HTTP behind a trait: `hyper` + `rustls` natively, `fetch` in a
//!   browser, an in-process [`MockServer`] everywhere. All protocol logic sits
//!   above it.
//! * [`client`] — SPEC §6.1's endpoints, one method each.
//! * [`engine`] — the state machine: pull, verify, merge, push, resolve, repeat.
//! * [`state`] — what survives a restart, and why the outbound queue is *derived*
//!   from the vault rather than remembered.
//! * [`roster`] — SPEC §6.2's device roster on the wire, and what it takes to
//!   replace one.
//! * [`enroll`] — SPEC §6.3, both sides.
//! * [`time`] — SPEC §6.5's drift, and why the signed `/v1/time` needs a nonce.
//! * [`backoff`] — the retry schedule, as a pure function.
//! * [`wire`] — the JSON encoding and the strict decoders that are this crate's
//!   hostile-input boundary.
//!
//! # Threat-model obligations
//!
//! | ID | What this crate is responsible for |
//! |---|---|
//! | `A1` | A hostile server cannot get an unverified envelope merged, cannot delete an item, cannot reorder or rewind the feed, and cannot make a client overwrite a write it could not attribute. |
//! | `A2` | TLS with certificate pinning on native builds ([`PinSet`]). In a browser the platform owns TLS and pinning is impossible; payloads are end-to-end encrypted independently of TLS, which is why that gap is survivable. See `README.md`. |
//! | `A6` | Every envelope's signer is looked up in the client-signed roster before decryption, and a roster is adopted only when it is signed by a device the current roster already vouches for. |
//!
//! # Rules that hold everywhere in this crate
//!
//! * No `unsafe`. Natively that is enforced for the whole dependency tree by
//!   `cargo deny`'s ban on `native-tls`, `openssl` and `libsodium-sys`; here it is
//!   `#![forbid(unsafe_code)]`.
//! * **This crate emits no log records at all.** There is no `tracing`
//!   dependency and no `log` call. What happened comes back as a
//!   [`SyncReport`]; what went wrong comes back as a [`SyncError`], and no variant
//!   of it names a secret, an envelope byte or an `item_id`. That is a stronger
//!   guarantee than a careful logging convention, and `tests/redaction.rs` asserts
//!   it over every variant.
//! * Merge is `misty-vault`'s and cryptography is `misty-crypto`'s. The one
//!   exception is documented, and regretted, in `src/signature.rs`.
//! * No `unwrap`/`expect`/`panic!`/slice indexing outside tests, enforced by the
//!   clippy lints below rather than by convention.
//!
//! [`docs/SPEC.md`]: https://github.com/zkasuran/misty/blob/main/docs/SPEC.md
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
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

mod signature;

pub mod encoding;

pub mod backoff;
pub mod client;
pub mod engine;
pub mod enroll;
pub mod error;
pub mod limits;
pub mod roster;
pub mod runtime;
pub mod state;
pub mod time;
pub mod transport;
pub mod wire;

pub use backoff::{Backoff, Jitter, MockSleeper, Sleeper};
pub use client::{auth_signing_bytes, SyncClient, SyncConfig, AUTH_SIGNING_CONTEXT};
pub use engine::{
    Approval, GrantDetails, PendingAction, PendingWrite, Rejection, Revocation, RosterPush,
    SyncEngine, SyncReport,
};
pub use enroll::{Enrollment, PendingApproval, ENROLL_QR_PREFIX};
pub use error::{Result, RosterRejection, SyncError, TransportKind, VaultFailure};
pub use state::{
    Fingerprint, KnownRow, MemoryStateStore, RotationState, StateStore, SyncState, TimeSample,
    STATE_FORMAT_VERSION,
};
pub use time::{Drift, DriftTracker, TIME_SIGNING_CONTEXT};
pub use transport::{
    Faults, Method, MockServer, MockTransport, SyncRequest, SyncResponse, Transport,
};
pub use wire::{ChangeFeed, FeedChange, PutOutcome, Quota, ServerVersion, Want};

#[cfg(not(target_arch = "wasm32"))]
pub use backoff::TokioSleeper;
#[cfg(not(target_arch = "wasm32"))]
pub use state::FileStateStore;
#[cfg(target_arch = "wasm32")]
pub use transport::{BrowserSleeper, FetchTransport};
#[cfg(not(target_arch = "wasm32"))]
pub use transport::{CertificatePin, NativeTransport, PinSet, PIN_LEN};

use misty_crypto::identity::DeviceIdentity;

/// Rebuilds a second handle onto one device's keys.
///
/// [`Vault::open`](misty_vault::Vault::open) takes a [`DeviceIdentity`] by value
/// and [`SyncEngine::new`] needs one too — the vault signs envelopes with it and
/// the engine signs challenges and rosters with it. Both are the same device, so
/// something has to duplicate the handle, and doing it here means one place to
/// look rather than an `export_*` pair copied into every caller.
///
/// The exported secrets are held in `zeroize::Zeroizing` for the duration and
/// wiped when this returns.
#[must_use]
pub fn duplicate_identity(identity: &DeviceIdentity) -> DeviceIdentity {
    let ed25519 = identity.export_ed25519_secret();
    let x25519 = identity.export_x25519_secret();
    DeviceIdentity::from_secret_bytes(identity.device_id(), &ed25519, *x25519)
}
