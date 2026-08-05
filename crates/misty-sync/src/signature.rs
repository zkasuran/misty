// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one place this crate touches a cryptographic primitive, and why it has to.
//!
//! Everything else here is a consumer of `misty-crypto`: envelopes are verified
//! with [`misty_crypto::envelope`], rosters with
//! [`misty_crypto::identity::Roster::verify`], grants with
//! [`misty_crypto::enrollment`], keys with [`misty_crypto::derive`]. But SPEC §6.5
//! requires the client to check an Ed25519 signature over a **server-chosen
//! message** — the `/v1/time` reading — against a **pinned public key**, and
//! `misty-crypto` exposes no detached-signature verification at all. Its two
//! verifying entry points,
//! [`Envelope::verify_with_signer`](misty_crypto::envelope::Envelope::verify_with_signer)
//! and `Roster::verify`, each verify a signature over bytes *they* construct, and
//! neither can be pointed at an arbitrary message.
//!
//! So this module exists, and it should not. The right fix is a
//! `misty_crypto::identity::verify_detached(public_key, message, signature)`,
//! after which this file is deleted and `ed25519-dalek` leaves this crate's
//! manifest. That is written up as a finding in `README.md`; it is a missing API
//! in the crypto core, not a disagreement with the spec.
//!
//! Until then: one function, `verify_strict` only, no signing, and no
//! `ed25519_dalek` type in this crate's public API.

use crate::error::{Result, SyncError};

/// Verifies a detached Ed25519 signature over `message`.
///
/// `verify_strict` rather than `verify`: it rejects small-order and mixed-order
/// public keys, so a signature is bound to exactly one key. A malleable
/// verification here would let an attacker who learned a *related* key produce
/// an accepted `/v1/time` response.
///
/// # Errors
///
/// `on_failure` if the key is malformed or the signature does not verify. The
/// caller supplies the error so that a bad time signature and a bad enrollment
/// signature are distinguishable without this function knowing about either.
pub(crate) fn verify_detached(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
    on_failure: SyncError,
) -> Result<()> {
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
        return Err(on_failure);
    };
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|_| on_failure)
}
