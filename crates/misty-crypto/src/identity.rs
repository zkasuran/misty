// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device identity and the signed device roster (SPEC §2.2, §6.2).
//!
//! A device is an Ed25519 keypair (it signs envelopes and server challenges)
//! plus an X25519 keypair (it agrees a key during enrollment) plus 16 random
//! bytes of `device_id`. There is no email, phone, username or password
//! anywhere in this crate: nothing to phish, SIM-swap, or enumerate.
//!
//! The [`Roster`] is what clients trust — never the server's device table. A
//! server that injects a device produces writes that every client rejects,
//! because the roster is signed by a device that was already trusted and
//! [`crate::envelope::open`] checks roster membership *before* decrypting
//! anything (threat model `A6`).

use core::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{random, DeviceId, Error, Result, SignatureBytes};

/// Domain separator for roster signatures.
pub const ROSTER_SIGNING_CONTEXT: &[u8] = b"misty/roster/v1";

/// Longest device name accepted, in bytes of UTF-8.
pub const MAX_NAME_LEN: usize = 64;

/// Longest platform string accepted, in bytes of UTF-8.
pub const MAX_PLATFORM_LEN: usize = 32;

/// A device's own keys: Ed25519 for signing, X25519 for agreement.
///
/// `Debug` renders `[redacted]`; the private halves are zeroized on drop by
/// `ed25519-dalek` and `x25519-dalek` respectively. On platforms with a
/// keystore the private key material should be held there and only mirrored
/// into this type for the duration of an operation (SPEC §2.2, §9).
pub struct DeviceIdentity {
    device_id: DeviceId,
    signing: SigningKey,
    agreement: StaticSecret,
}

impl DeviceIdentity {
    /// Generates a new identity: a fresh `device_id` and both keypairs.
    ///
    /// # Errors
    ///
    /// As [`random::fill`].
    pub fn generate() -> Result<Self> {
        Ok(Self {
            device_id: DeviceId::generate()?,
            signing: SigningKey::from_bytes(&random::array::<32>()?),
            agreement: StaticSecret::from(random::array::<32>()?),
        })
    }

    /// Rebuilds an identity from key material held elsewhere, typically an OS
    /// keystore.
    #[must_use]
    pub fn from_secret_bytes(
        device_id: DeviceId,
        ed25519_secret: &[u8; 32],
        x25519_secret: [u8; 32],
    ) -> Self {
        Self {
            device_id,
            signing: SigningKey::from_bytes(ed25519_secret),
            agreement: StaticSecret::from(x25519_secret),
        }
    }

    /// This device's id.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The Ed25519 public key, as it appears in a [`DeviceRecord`].
    #[must_use]
    pub fn ed25519_public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The X25519 public key, published in an enrollment QR.
    #[must_use]
    pub fn x25519_public(&self) -> [u8; 32] {
        PublicKey::from(&self.agreement).to_bytes()
    }

    /// Signs `message` with the device's Ed25519 key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        SignatureBytes::from_bytes(self.signing.sign(message).to_bytes())
    }

    /// X25519 agreement against `their_public`.
    ///
    /// # Errors
    ///
    /// [`Error::NonContributoryKeyExchange`] if the peer's key is of small
    /// order, which would fix the shared secret to zero.
    pub fn diffie_hellman(&self, their_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let shared = self
            .agreement
            .diffie_hellman(&PublicKey::from(*their_public));
        if !shared.was_contributory() {
            return Err(Error::NonContributoryKeyExchange);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }

    /// Exports the Ed25519 private key for storage in an OS keystore.
    ///
    /// An audit point: the return value is zeroized on drop, and must not be
    /// copied anywhere that is not.
    #[must_use]
    pub fn export_ed25519_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Exports the X25519 private key for storage in an OS keystore.
    #[must_use]
    pub fn export_x25519_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.agreement.to_bytes())
    }

    /// Builds this device's roster record.
    ///
    /// # Errors
    ///
    /// [`Error::StringTooLong`] if `name` or `platform` exceeds its bound.
    pub fn record(
        &self,
        name: &str,
        platform: &str,
        enrolled_at: i64,
        enrolled_by: Option<DeviceId>,
    ) -> Result<DeviceRecord> {
        let record = DeviceRecord {
            device_id: self.device_id,
            ed25519_pub: self.ed25519_public(),
            name: name.to_owned(),
            platform: platform.to_owned(),
            enrolled_at,
            enrolled_by,
        };
        record.validate()?;
        Ok(record)
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeviceIdentity {{ device_id: {}, keys: [redacted] }}",
            self.device_id
        )
    }
}
/// One entry in the device roster (SPEC §6.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// The device's 16 random bytes of identity.
    pub device_id: DeviceId,
    /// The device's Ed25519 public key. Envelope signatures verify against
    /// this and nothing else.
    pub ed25519_pub: [u8; 32],
    /// User-facing name, for example `"Ada's Pixel"`.
    pub name: String,
    /// Platform string, for example `"android"`.
    pub platform: String,
    /// Unix milliseconds when this device was added.
    pub enrolled_at: i64,
    /// Which device approved it. `None` for the first device in a vault.
    pub enrolled_by: Option<DeviceId>,
}

impl DeviceRecord {
    /// Checks the string bounds and that the public key is a valid Ed25519
    /// point.
    ///
    /// # Errors
    ///
    /// [`Error::StringTooLong`] or [`Error::BadVerifyingKey`].
    pub fn validate(&self) -> Result<()> {
        if self.name.len() > MAX_NAME_LEN {
            return Err(Error::StringTooLong {
                field: "device name",
                max: MAX_NAME_LEN,
            });
        }
        if self.platform.len() > MAX_PLATFORM_LEN {
            return Err(Error::StringTooLong {
                field: "device platform",
                max: MAX_PLATFORM_LEN,
            });
        }
        self.verifying_key().map(|_| ())
    }

    /// The record's Ed25519 public key, parsed.
    ///
    /// Crate-internal so `ed25519_dalek` types stay out of the public API;
    /// [`validate`](Self::validate) is the public way to ask whether the stored
    /// bytes are a valid key.
    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.ed25519_pub).map_err(|_| Error::BadVerifyingKey)
    }

    fn append_signing_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.device_id.as_bytes());
        out.extend_from_slice(&self.ed25519_pub);
        append_str(out, &self.name);
        append_str(out, &self.platform);
        out.extend_from_slice(&self.enrolled_at.to_le_bytes());
        match &self.enrolled_by {
            None => out.push(0),
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id.as_bytes());
            }
        }
    }
}

fn append_str(out: &mut Vec<u8>, value: &str) {
    // Length-prefixed so no concatenation of fields is ambiguous: without the
    // prefix, ("ab", "c") and ("a", "bc") would sign identically.
    let bytes = value.as_bytes();
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(bytes);
}
/// The device roster: the list of devices a vault trusts, signed by one of
/// them.
///
/// Stored as an ordinary encrypted vault item with `kind = DeviceRoster`. The
/// signature is over [`signing_bytes`](Self::signing_bytes), a canonical
/// encoding defined in this module rather than over the CBOR of the item, so
/// re-serialising the roster with a different CBOR writer cannot invalidate it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    /// Trusted devices, in insertion order.
    pub devices: Vec<DeviceRecord>,
    /// Which device signed this revision. Must itself be in `devices`.
    pub signed_by: Option<DeviceId>,
    /// The signature over [`signing_bytes`](Self::signing_bytes).
    pub signature: Option<SignatureBytes>,
}

impl Roster {
    /// A roster holding `devices`, not yet signed.
    #[must_use]
    pub const fn new(devices: Vec<DeviceRecord>) -> Self {
        Self {
            devices,
            signed_by: None,
            signature: None,
        }
    }

    /// Looks up a device. This is the check [`crate::envelope::open`] performs
    /// before it will decrypt anything.
    #[must_use]
    pub fn contains(&self, device_id: &DeviceId) -> Option<&DeviceRecord> {
        self.devices
            .iter()
            .find(|record| record.device_id == *device_id)
    }

    /// Adds a device, invalidating any existing signature.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateDevice`] if the id is already present, or whatever
    /// [`DeviceRecord::validate`] rejects.
    pub fn add(&mut self, record: DeviceRecord) -> Result<()> {
        record.validate()?;
        if self.contains(&record.device_id).is_some() {
            return Err(Error::DuplicateDevice {
                device: record.device_id,
            });
        }
        self.devices.push(record);
        self.signed_by = None;
        self.signature = None;
        Ok(())
    }

    /// Removes a device — the first half of a revocation. The caller then
    /// re-signs, bumps the epoch, and re-wraps item keys (SPEC §6.4).
    ///
    /// Returns whether anything was removed. Any existing signature is
    /// invalidated either way.
    pub fn remove(&mut self, device_id: &DeviceId) -> bool {
        let before = self.devices.len();
        self.devices.retain(|record| record.device_id != *device_id);
        self.signed_by = None;
        self.signature = None;
        before != self.devices.len()
    }

    /// The exact bytes a roster signature covers:
    ///
    /// ```text
    /// "misty/roster/v1"
    /// LE32(device_count)
    /// signer_device_id[16]
    /// per device, in order:
    ///   device_id[16]
    ///   ed25519_pub[32]
    ///   LE32(name_len)     || name (UTF-8)
    ///   LE32(platform_len) || platform (UTF-8)
    ///   LE64(enrolled_at)
    ///   0x00, or 0x01 || enrolled_by[16]
    /// ```
    #[must_use]
    pub fn signing_bytes(&self, signer: &DeviceId) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(ROSTER_SIGNING_CONTEXT.len() + 20 + self.devices.len() * 80);
        out.extend_from_slice(ROSTER_SIGNING_CONTEXT);
        out.extend_from_slice(
            &u32::try_from(self.devices.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        out.extend_from_slice(signer.as_bytes());
        for record in &self.devices {
            record.append_signing_bytes(&mut out);
        }
        out
    }
    /// Signs the roster with `identity`, which must itself be a member.
    ///
    /// # Errors
    ///
    /// [`Error::RosterSignerNotInRoster`] if the signer is not a member, or
    /// whatever [`validate`](Self::validate) rejects.
    pub fn sign(&mut self, identity: &DeviceIdentity) -> Result<()> {
        self.validate()?;
        let signer = identity.device_id();
        let Some(record) = self.contains(&signer) else {
            return Err(Error::RosterSignerNotInRoster { signer });
        };
        // A device signing with a key that does not match its own record would
        // produce a roster that no other client can verify.
        if record.ed25519_pub != identity.ed25519_public() {
            return Err(Error::RosterSignatureInvalid);
        }
        let signature = identity.sign(&self.signing_bytes(&signer));
        self.signed_by = Some(signer);
        self.signature = Some(signature);
        Ok(())
    }

    /// Verifies the roster's own signature.
    ///
    /// Returns the signing device's record on success. This does **not** decide
    /// whether that device is one *you* trust — for a device joining a vault,
    /// that is [`crate::enrollment`]'s job.
    ///
    /// # Errors
    ///
    /// [`Error::RosterUnsigned`], [`Error::RosterSignerNotInRoster`],
    /// [`Error::RosterSignatureInvalid`], or whatever
    /// [`validate`](Self::validate) rejects.
    pub fn verify(&self) -> Result<&DeviceRecord> {
        self.validate()?;
        let (Some(signer), Some(signature)) = (self.signed_by, self.signature) else {
            return Err(Error::RosterUnsigned);
        };
        let Some(record) = self.contains(&signer) else {
            return Err(Error::RosterSignerNotInRoster { signer });
        };
        record
            .verifying_key()?
            .verify_strict(
                &self.signing_bytes(&signer),
                &ed25519_dalek::Signature::from_bytes(signature.as_bytes()),
            )
            .map_err(|_| Error::RosterSignatureInvalid)?;
        Ok(record)
    }

    /// Checks every record and that no `device_id` repeats.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateDevice`], or whatever [`DeviceRecord::validate`]
    /// rejects.
    pub fn validate(&self) -> Result<()> {
        for (index, record) in self.devices.iter().enumerate() {
            record.validate()?;
            if self
                .devices
                .iter()
                .skip(index + 1)
                .any(|other| other.device_id == record.device_id)
            {
                return Err(Error::DuplicateDevice {
                    device: record.device_id,
                });
            }
        }
        Ok(())
    }
}
