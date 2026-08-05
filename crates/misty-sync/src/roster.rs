// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The device roster on the wire (SPEC §6.2).
//!
//! The roster is what a client trusts. Not the server's device table, not the
//! `deleted` flag, not anything else the transport says: **a device that is not
//! signed into the roster by an already-trusted device is rejected by every
//! client, whatever the server says** (threat model `A6`). Every envelope this
//! crate accepts has had its signer looked up in a roster before anything was
//! decrypted, and this module is where a *new* roster is admitted.
//!
//! # SPEC §6.2 does not say where the roster lives, and it has to
//!
//! §6.2 says the roster is "an encrypted vault item (`kind = 2`)". An item is
//! addressed by a 16-byte `item_id`, and every device has to look it up at the
//! same address or they are not reading the same roster. §6.2 supplies no
//! address, and it cannot be random: a device joining from an enrollment grant
//! has no way to learn a random id, and `GET .../changes` would hand it back
//! among a hundred others with no way to know which is the roster until it has
//! decrypted them all.
//!
//! So the address is derived from the vault key:
//!
//! ```text
//! roster_item_id = HKDF-SHA512(ikm = VK, salt = "misty/roster-id/v1", info = "")[0..16]
//! ```
//!
//! Keyed on `VK` rather than being a fixed constant. The gain is small and real:
//! a constant would make one id identify "the roster" across every vault the
//! server holds, and while the server can already read `kind` out of the
//! authenticated-but-cleartext envelope header, there is no reason to hand it a
//! second, cheaper way to do the same thing. [`ROSTER_ID_SALT`] is wire-visible —
//! it decides an id the server stores — so by SPEC §6.6's own rule it belongs in
//! that table.

use misty_crypto::envelope::{self, Envelope, EnvelopeKind};
use misty_crypto::identity::{DeviceIdentity, Roster};
use misty_crypto::keys::VaultKey;
use misty_crypto::{derive, ItemId};

use crate::error::{Result, RosterRejection, SyncError};
use crate::limits;

/// Domain separator for the roster's storage address. Wire-visible; see the
/// module docs.
pub const ROSTER_ID_SALT: &[u8] = b"misty/roster-id/v1";

/// The address the roster lives at, for this vault.
///
/// # Errors
///
/// [`SyncError::Crypto`] if the HKDF call fails.
pub fn roster_item_id(vault_key: &VaultKey) -> Result<ItemId> {
    let mut out = [0u8; ItemId::LEN];
    derive::hkdf_sha512(vault_key.expose_secret(), ROSTER_ID_SALT, &[], &mut out)?;
    Ok(ItemId::from_bytes(out))
}

/// Encodes a roster the way an envelope payload carries it.
///
/// CBOR, matching [`misty_crypto::enrollment`]'s sealed grant, so a roster has
/// one encoding in Misty rather than two.
///
/// # Errors
///
/// [`SyncError::Malformed`] if encoding fails, or
/// [`SyncError::EnvelopeTooLarge`] if the result is past
/// [`MAX_ROSTER_PAYLOAD_LEN`](crate::limits::MAX_ROSTER_PAYLOAD_LEN).
pub fn encode_roster(roster: &Roster) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    ciborium::into_writer(roster, &mut payload).map_err(|_| SyncError::Malformed {
        operation: "encode roster",
        field: "roster",
    })?;
    if payload.len() > limits::MAX_ROSTER_PAYLOAD_LEN {
        return Err(SyncError::EnvelopeTooLarge {
            len: payload.len(),
            max: limits::MAX_ROSTER_PAYLOAD_LEN,
        });
    }
    Ok(payload)
}

/// Seals a roster into the envelope that carries it to the server.
///
/// The roster must already be signed by `identity`; a roster this device signed
/// but did not sign *as itself* is one no other client can chain to.
///
/// # Errors
///
/// [`SyncError::Crypto`] if the roster does not verify or sealing fails, or
/// anything [`encode_roster`] rejects.
pub fn seal_roster(
    roster: &Roster,
    vault_key: &VaultKey,
    epoch: u32,
    identity: &DeviceIdentity,
) -> Result<(ItemId, Vec<u8>)> {
    let signer = roster.verify()?;
    if signer.device_id != identity.device_id() {
        return Err(SyncError::RosterRejected {
            reason: RosterRejection::SignerNotTrusted,
        });
    }
    let item_id = roster_item_id(vault_key)?;
    let payload = encode_roster(roster)?;
    let epoch_key = derive::epoch_key(vault_key, epoch)?;
    let sealed = envelope::seal(
        EnvelopeKind::DeviceRoster,
        epoch,
        &item_id,
        &payload,
        &epoch_key,
        identity,
    )?;
    Ok((item_id, sealed))
}

/// Opens a roster envelope fetched from the server and decides whether to adopt
/// it.
///
/// Order, and every step is load-bearing:
///
/// 1. the envelope must be addressed to this vault's roster id — a roster served
///    under another item's id is a relocation attempt, and the AAD binds the id
///    so it would not decrypt anyway;
/// 2. the envelope must declare `kind = DeviceRoster`, which is authenticated;
/// 3. the envelope's *signer* must be in the roster we already trust — this is
///    where a server-injected device is refused, before any decryption
///    (`A6`);
/// 4. only then is the payload decrypted, which also proves it was written by
///    someone holding `VK`;
/// 5. the decoded roster's own signature must verify, by one of its own members;
/// 6. and that member must also be in the roster we already trust, so the new
///    roster *chains* rather than merely being internally consistent. Without
///    step 6 a server could replay a roster from a different vault that happened
///    to be internally valid.
///
/// # Errors
///
/// [`SyncError::RosterRejected`] for a roster that does not chain,
/// [`SyncError::Crypto`] for one that does not verify or decrypt, or
/// [`SyncError::Malformed`] for one that does not decode.
pub fn open_roster(
    envelope_bytes: &[u8],
    item_id: &ItemId,
    vault_key: &VaultKey,
    trusted: &Roster,
) -> Result<Roster> {
    if *item_id != roster_item_id(vault_key)? {
        return Err(SyncError::RosterRejected {
            reason: RosterRejection::WrongAddress,
        });
    }
    let parsed = Envelope::parse(envelope_bytes)?;
    let header = *parsed.header();
    if header.kind != EnvelopeKind::DeviceRoster {
        return Err(SyncError::RosterRejected {
            reason: RosterRejection::WrongKind,
        });
    }
    // Roster membership, then signature, then — and only then — decryption.
    let verified = parsed.verify(item_id, trusted)?;
    let epoch_key = derive::epoch_key(vault_key, header.epoch)?;
    let payload = verified.open(&epoch_key)?;
    if payload.len() > limits::MAX_ROSTER_PAYLOAD_LEN {
        return Err(SyncError::EnvelopeTooLarge {
            len: payload.len(),
            max: limits::MAX_ROSTER_PAYLOAD_LEN,
        });
    }
    let next: Roster =
        ciborium::from_reader(payload.as_slice()).map_err(|_| SyncError::Malformed {
            operation: "open roster",
            field: "roster",
        })?;
    check_successor(trusted, &next)?;
    Ok(next)
}

/// Whether `next` may replace `current`.
///
/// # Errors
///
/// [`SyncError::RosterRejected`] with the reason.
pub fn check_successor(current: &Roster, next: &Roster) -> Result<()> {
    let signer = next.verify().map_err(|error| match error {
        misty_crypto::Error::RosterUnsigned => SyncError::RosterRejected {
            reason: RosterRejection::Unsigned,
        },
        _ => SyncError::RosterRejected {
            reason: RosterRejection::SignatureInvalid,
        },
    })?;
    let Some(known) = current.contains(&signer.device_id) else {
        return Err(SyncError::RosterRejected {
            reason: RosterRejection::SignerNotTrusted,
        });
    };
    // A device whose key changed is a different device wearing the same id.
    if known.ed25519_pub != signer.ed25519_pub {
        return Err(SyncError::RosterRejected {
            reason: RosterRejection::SignerNotTrusted,
        });
    }
    Ok(())
}
