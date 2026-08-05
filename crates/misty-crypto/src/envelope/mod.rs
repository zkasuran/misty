// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The envelope format (SPEC §2.4). `ENVELOPE_FORMAT_VERSION = 1`.
//!
//! Every encrypted object in Misty — vault item, device roster, settings blob,
//! group, custom icon — is one of these. All integers are little-endian.
//!
//! ```text
//! Header (74 bytes, authenticated but not encrypted)
//!   off  len  field
//!     0    4  magic = b"MSTY"
//!     4    1  format_version = 1
//!     5    1  kind: 1=Item 2=DeviceRoster 3=Settings 4=Group 5=CustomIcon
//!     6    4  epoch: u32
//!    10   16  signer_device_id
//!    26   24  wik_nonce
//!    50   24  payload_nonce
//!
//! Body
//!    74   48  wrapped_item_key
//!              = XChaCha20Poly1305(key=EK_epoch, nonce=wik_nonce,
//!                                  pt=IK[32], aad=Header || item_id[16])
//!   122   ..  ciphertext
//!              = XChaCha20Poly1305(key=IK, nonce=payload_nonce,
//!                                  pt=pad(payload), aad=Header || item_id[16])
//!    ..   64  signature
//!              = Ed25519(signer_priv,
//!                        Header || item_id || wrapped_item_key || ciphertext)
//! ```
//!
//! # `item_id` is not in the envelope
//!
//! It is the storage key, so storing it would be redundant — but it is bound
//! into both AEAD contexts and into the signature, which means an envelope
//! cannot be relocated to another item id. A server that swaps two items'
//! bytes produces two envelopes that fail to open.
//!
//! # Order of operations is not negotiable
//!
//! [`open`] does exactly this, in this order:
//!
//! 1. parse the header and check the body's shape;
//! 2. look the signer up in the roster — unknown signer, stop;
//! 3. verify the Ed25519 signature — bad signature, stop;
//! 4. only now unwrap the item key, and only then decrypt the payload.
//!
//! The order is enforced by the type system, not by comment: decryption lives
//! on [`Verified`], and the only way to obtain a `Verified` is
//! [`Envelope::verify`] or [`Envelope::verify_with_signer`], because it holds a
//! private field of a private type. `parse().open()` does not compile.
//!
//! # Padding
//!
//! `pad(x) = LE32(x.len()) || x || 0x00 * k` where `k` is the least value
//! making the total a multiple of 256. Sizes still leak in 256-byte buckets —
//! that is the accepted residual risk in threat model `A1` — but the exact
//! length of an issuer name does not.

use ed25519_dalek::VerifyingKey;
use zeroize::{Zeroize, Zeroizing};

use crate::identity::{DeviceIdentity, Roster};
use crate::keys::{EpochKey, ItemKey, KEY_LEN};
use crate::{aead, random, DeviceId, Error, ItemId, Result};

mod pad;
#[cfg(test)]
mod tests;

pub use pad::{pad, unpad, MAX_PAYLOAD_LEN, PAD_BLOCK};

/// `magic`, offset 0.
pub const ENVELOPE_MAGIC: [u8; 4] = *b"MSTY";

/// `format_version`, offset 4. Bump this on any layout change.
pub const ENVELOPE_FORMAT_VERSION: u8 = 1;

/// Length of the authenticated header.
pub const HEADER_LEN: usize = 74;

/// Length of the wrapped item key: 32 bytes of key plus a 16-byte tag.
pub const WRAPPED_ITEM_KEY_LEN: usize = KEY_LEN + aead::TAG_LEN;

/// Length of the trailing Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Smallest possible envelope: header, wrapped key, one 256-byte padding block
/// with its tag, signature.
pub const MIN_ENVELOPE_LEN: usize =
    HEADER_LEN + WRAPPED_ITEM_KEY_LEN + PAD_BLOCK + aead::TAG_LEN + SIGNATURE_LEN;

/// What an envelope holds, `kind` at offset 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EnvelopeKind {
    /// A vault item.
    Item = 1,
    /// The device roster (SPEC §6.2).
    DeviceRoster = 2,
    /// The settings blob.
    Settings = 3,
    /// A group definition.
    Group = 4,
    /// A user-supplied icon.
    CustomIcon = 5,
}

impl EnvelopeKind {
    /// The wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses the wire byte.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownEnvelopeKind`] for anything outside `1..=5`. Unknown
    /// kinds are rejected rather than ignored: a client that stored an object
    /// whose meaning it does not know would resign or overwrite it wrongly.
    pub const fn from_u8(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Item),
            2 => Ok(Self::DeviceRoster),
            3 => Ok(Self::Settings),
            4 => Ok(Self::Group),
            5 => Ok(Self::CustomIcon),
            found => Err(Error::UnknownEnvelopeKind { found }),
        }
    }
}
/// The parsed 74-byte header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// What the envelope holds.
    pub kind: EnvelopeKind,
    /// Which epoch key wraps the item key.
    pub epoch: u32,
    /// Which device signed this envelope. Cleartext, and the only metadata a
    /// hostile server learns beyond sizes and `seq`.
    pub signer: DeviceId,
    /// Nonce for the wrapped item key.
    pub wik_nonce: [u8; aead::NONCE_LEN],
    /// Nonce for the payload.
    pub payload_nonce: [u8; aead::NONCE_LEN],
}

impl Header {
    /// Serialises to the exact 74 wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let mut cursor = Cursor::new(&mut out);
        cursor.put(&ENVELOPE_MAGIC);
        cursor.put(&[ENVELOPE_FORMAT_VERSION]);
        cursor.put(&[self.kind.as_u8()]);
        cursor.put(&self.epoch.to_le_bytes());
        cursor.put(self.signer.as_bytes());
        cursor.put(&self.wik_nonce);
        cursor.put(&self.payload_nonce);
        out
    }

    /// Parses the first 74 bytes of `bytes`.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`], [`Error::BadEnvelopeMagic`],
    /// [`Error::UnsupportedFormatVersion`], [`Error::UnknownEnvelopeKind`].
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = take(bytes, 0, HEADER_LEN, "envelope header")?;
        if take(header, 0, 4, "envelope magic")? != ENVELOPE_MAGIC {
            return Err(Error::BadEnvelopeMagic);
        }
        let format_version = byte_at(header, 4)?;
        if format_version != ENVELOPE_FORMAT_VERSION {
            return Err(Error::UnsupportedFormatVersion {
                context: "envelope",
                found: format_version,
                supported: ENVELOPE_FORMAT_VERSION,
            });
        }
        Ok(Self {
            kind: EnvelopeKind::from_u8(byte_at(header, 5)?)?,
            epoch: u32::from_le_bytes(array_at::<4>(header, 6)?),
            signer: DeviceId::from_bytes(array_at::<16>(header, 10)?),
            wik_nonce: array_at::<24>(header, 26)?,
            payload_nonce: array_at::<24>(header, 50)?,
        })
    }
}

/// A write cursor over a fixed-size buffer, so header serialisation contains no
/// hand-written offsets to get wrong and no slice indexing that could panic.
struct Cursor<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    fn put(&mut self, bytes: &[u8]) {
        let end = self.offset.saturating_add(bytes.len());
        if let Some(slot) = self.buffer.get_mut(self.offset..end) {
            slot.copy_from_slice(bytes);
            self.offset = end;
        }
    }
}

fn take<'a>(bytes: &'a [u8], offset: usize, len: usize, context: &'static str) -> Result<&'a [u8]> {
    let end = offset.saturating_add(len);
    bytes.get(offset..end).ok_or(Error::Truncated {
        context,
        needed: end,
        got: bytes.len(),
    })
}

fn byte_at(bytes: &[u8], offset: usize) -> Result<u8> {
    bytes.get(offset).copied().ok_or(Error::Truncated {
        context: "envelope header",
        needed: offset + 1,
        got: bytes.len(),
    })
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let slice = take(bytes, offset, N, "envelope header")?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}
/// The two nonces an envelope needs.
///
/// Crate-private, and there is no public API that accepts explicit nonces: the
/// only nonce source reachable from outside is [`Nonces::random`], via
/// [`seal`]. Golden-byte tests inject fixed nonces through [`seal_with`], which
/// is why they are unit tests inside this module rather than integration tests.
#[derive(Clone, Copy)]
pub(crate) struct Nonces {
    pub(crate) wik: [u8; aead::NONCE_LEN],
    pub(crate) payload: [u8; aead::NONCE_LEN],
}

impl Nonces {
    pub(crate) fn random() -> Result<Self> {
        Ok(Self {
            wik: random::array::<{ aead::NONCE_LEN }>()?,
            payload: random::array::<{ aead::NONCE_LEN }>()?,
        })
    }
}

/// Everything [`seal_with`] needs besides the padded payload.
pub(crate) struct SealInputs<'a> {
    pub(crate) kind: EnvelopeKind,
    pub(crate) item_id: &'a ItemId,
    pub(crate) epoch_key: &'a EpochKey,
    pub(crate) item_key: &'a ItemKey,
    pub(crate) identity: &'a DeviceIdentity,
    pub(crate) nonces: Nonces,
}

/// Seals an already-padded payload with explicit keys and nonces.
pub(crate) fn seal_with(inputs: &SealInputs<'_>, padded_payload: &[u8]) -> Result<Vec<u8>> {
    let header = Header {
        kind: inputs.kind,
        epoch: inputs.epoch_key.epoch(),
        signer: inputs.identity.device_id(),
        wik_nonce: inputs.nonces.wik,
        payload_nonce: inputs.nonces.payload,
    };
    let header_bytes = header.to_bytes();

    // AAD is exactly `Header || item_id`, for both AEADs. The signed message is
    // that same prefix followed by the two ciphertexts, so `aad` is reused
    // below rather than rebuilt.
    let mut aad = Vec::with_capacity(HEADER_LEN + ItemId::LEN);
    aad.extend_from_slice(&header_bytes);
    aad.extend_from_slice(inputs.item_id.as_bytes());

    let wrapped_item_key = aead::encrypt(
        inputs.epoch_key.expose_secret(),
        &inputs.nonces.wik,
        &aad,
        inputs.item_key.expose_secret(),
    )?;
    let ciphertext = aead::encrypt(
        inputs.item_key.expose_secret(),
        &inputs.nonces.payload,
        &aad,
        padded_payload,
    )?;

    let mut message = aad;
    message.extend_from_slice(&wrapped_item_key);
    message.extend_from_slice(&ciphertext);
    let signature = inputs.identity.sign(&message);

    let mut out =
        Vec::with_capacity(HEADER_LEN + wrapped_item_key.len() + ciphertext.len() + SIGNATURE_LEN);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&wrapped_item_key);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(signature.as_bytes());
    Ok(out)
}

/// Seals `payload` into an envelope.
///
/// `payload` is the caller's already-serialised bytes — CBOR, at the vault
/// layer. This crate pads and encrypts; it deliberately knows nothing about the
/// item model.
///
/// # Errors
///
/// [`Error::EpochMismatch`] if `epoch` disagrees with `epoch_key`'s own epoch,
/// [`Error::PayloadTooLarge`] past [`MAX_PAYLOAD_LEN`], or
/// [`Error::Random`] if the CSPRNG fails.
pub fn seal(
    kind: EnvelopeKind,
    epoch: u32,
    item_id: &ItemId,
    payload: &[u8],
    epoch_key: &EpochKey,
    identity: &DeviceIdentity,
) -> Result<Vec<u8>> {
    if epoch != epoch_key.epoch() {
        return Err(Error::EpochMismatch {
            expected: epoch_key.epoch(),
            found: epoch,
        });
    }
    let item_key = ItemKey::generate()?;
    let padded = pad(payload)?;
    seal_with(
        &SealInputs {
            kind,
            item_id,
            epoch_key,
            item_key: &item_key,
            identity,
            nonces: Nonces::random()?,
        },
        &padded,
    )
}
/// A parsed, **unverified** envelope. Borrows the buffer it was parsed from.
///
/// Nothing on this type can decrypt. Call [`verify`](Self::verify) to get a
/// [`Verified`], which can.
#[derive(Clone, Copy, Debug)]
pub struct Envelope<'a> {
    header: Header,
    header_bytes: &'a [u8],
    wrapped_item_key: &'a [u8],
    ciphertext: &'a [u8],
    signature: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// Parses the header and checks the body's shape. Verifies nothing.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if the buffer cannot hold a minimal envelope,
    /// [`Error::MalformedBody`] if the ciphertext length is not
    /// `256n + 16`, plus anything [`Header::parse`] rejects.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < MIN_ENVELOPE_LEN {
            return Err(Error::Truncated {
                context: "envelope",
                needed: MIN_ENVELOPE_LEN,
                got: bytes.len(),
            });
        }
        let header = Header::parse(bytes)?;
        let ciphertext_len = bytes
            .len()
            .saturating_sub(HEADER_LEN + WRAPPED_ITEM_KEY_LEN + SIGNATURE_LEN);
        // The payload is padded to a multiple of 256 before encryption, so the
        // ciphertext is always 256n + 16. Rejecting anything else here means
        // the AEAD is never handed a length the format cannot have produced.
        if ciphertext_len.saturating_sub(aead::TAG_LEN) % PAD_BLOCK != 0 {
            return Err(Error::MalformedBody {
                detail: "ciphertext length is not a multiple of 256 plus a 16-byte tag",
            });
        }
        Ok(Self {
            header,
            header_bytes: take(bytes, 0, HEADER_LEN, "envelope header")?,
            wrapped_item_key: take(bytes, HEADER_LEN, WRAPPED_ITEM_KEY_LEN, "wrapped item key")?,
            ciphertext: take(
                bytes,
                HEADER_LEN + WRAPPED_ITEM_KEY_LEN,
                ciphertext_len,
                "ciphertext",
            )?,
            signature: take(
                bytes,
                HEADER_LEN + WRAPPED_ITEM_KEY_LEN + ciphertext_len,
                SIGNATURE_LEN,
                "signature",
            )?,
        })
    }

    /// The parsed header. Cleartext, and unauthenticated until
    /// [`verify`](Self::verify) succeeds.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Checks roster membership, then the signature.
    ///
    /// This is step 2 and 3 of [`open`], and the only door to decryption.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSigner`] if the header names a device absent from the
    /// roster, [`Error::BadVerifyingKey`] if that device's stored key is
    /// malformed, or [`Error::SignatureInvalid`].
    pub fn verify(self, item_id: &ItemId, roster: &Roster) -> Result<Verified<'a>> {
        let Some(record) = roster.contains(&self.header.signer) else {
            return Err(Error::UnknownSigner {
                signer: self.header.signer,
            });
        };
        self.verify_with_signer(item_id, &record.ed25519_pub)
    }

    /// Checks the signature against a specific public key.
    ///
    /// For the bootstrap case only: opening the roster envelope itself, whose
    /// signer's key came from an enrollment grant rather than from a roster that
    /// has not been read yet. Everything else MUST use
    /// [`verify`](Self::verify).
    ///
    /// # Errors
    ///
    /// [`Error::BadVerifyingKey`] if `signer_public_key` is not a valid Ed25519
    /// point, or [`Error::SignatureInvalid`].
    pub fn verify_with_signer(
        self,
        item_id: &ItemId,
        signer_public_key: &[u8; 32],
    ) -> Result<Verified<'a>> {
        let signature =
            ed25519_dalek::Signature::from_bytes(&array_at::<SIGNATURE_LEN>(self.signature, 0)?);
        VerifyingKey::from_bytes(signer_public_key)
            .map_err(|_| Error::BadVerifyingKey)?
            // `verify_strict` rejects small-order and mixed-order keys, so a
            // signature is bound to exactly one public key.
            .verify_strict(&self.signed_message(item_id), &signature)
            .map_err(|_| Error::SignatureInvalid)?;
        Ok(Verified {
            envelope: self,
            item_id: *item_id,
            proof: SignatureProof(()),
        })
    }

    /// `Header || item_id`, the AAD for both AEAD layers.
    fn aad(&self, item_id: &ItemId) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_LEN + ItemId::LEN);
        aad.extend_from_slice(self.header_bytes);
        aad.extend_from_slice(item_id.as_bytes());
        aad
    }

    /// `Header || item_id || wrapped_item_key || ciphertext`.
    fn signed_message(&self, item_id: &ItemId) -> Vec<u8> {
        let mut message = self.aad(item_id);
        message.extend_from_slice(self.wrapped_item_key);
        message.extend_from_slice(self.ciphertext);
        message
    }
}
/// Witness that a signature and roster check passed.
///
/// Private field of a private type: no code outside this module can build one,
/// so no code outside this module can reach [`Verified::open`] without having
/// gone through verification first. This is SPEC §2.4's mandatory decryption
/// order, expressed as a type rather than as a comment.
#[derive(Debug)]
struct SignatureProof(());

/// An envelope whose signer is known and whose signature verified.
#[derive(Debug)]
pub struct Verified<'a> {
    envelope: Envelope<'a>,
    item_id: ItemId,
    #[allow(dead_code, reason = "the witness is the point; it is never read")]
    proof: SignatureProof,
}

impl Verified<'_> {
    /// The verified header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        self.envelope.header()
    }

    /// Unwraps the item key and decrypts the payload.
    ///
    /// The return value is the caller's plaintext, zeroized on drop.
    ///
    /// # Errors
    ///
    /// [`Error::EpochMismatch`] if `epoch_key` is for another epoch,
    /// [`Error::ItemKeyUnwrapFailed`], [`Error::PayloadDecryptFailed`], or a
    /// padding error from [`unpad`].
    pub fn open(&self, epoch_key: &EpochKey) -> Result<Zeroizing<Vec<u8>>> {
        let header = self.envelope.header;
        if header.epoch != epoch_key.epoch() {
            return Err(Error::EpochMismatch {
                expected: epoch_key.epoch(),
                found: header.epoch,
            });
        }
        let aad = self.envelope.aad(&self.item_id);

        // Tests count AEAD attempts to prove nothing decrypts before the
        // signature and roster checks pass. See `tests::decrypt_attempts`.
        #[cfg(test)]
        tests::note_decrypt_attempt();

        let unwrapped = aead::decrypt(
            epoch_key.expose_secret(),
            &header.wik_nonce,
            &aad,
            self.envelope.wrapped_item_key,
            Error::ItemKeyUnwrapFailed,
        )?;
        let mut item_key_bytes = [0u8; KEY_LEN];
        if unwrapped.len() != KEY_LEN {
            return Err(Error::ItemKeyUnwrapFailed);
        }
        item_key_bytes.copy_from_slice(&unwrapped);
        let item_key = ItemKey::from_bytes(item_key_bytes);
        item_key_bytes.zeroize();

        let padded = aead::decrypt(
            item_key.expose_secret(),
            &header.payload_nonce,
            &aad,
            self.envelope.ciphertext,
            Error::PayloadDecryptFailed,
        )?;
        Ok(Zeroizing::new(unpad(&padded)?.to_vec()))
    }
}

/// Opens an envelope: parse, roster check, signature check, unwrap, decrypt —
/// in that order.
///
/// `roster` must already have been verified with [`Roster::verify`]; this
/// function checks membership, not the roster's own signature.
///
/// # Errors
///
/// Anything [`Envelope::parse`], [`Envelope::verify`] or [`Verified::open`]
/// returns.
pub fn open(
    bytes: &[u8],
    item_id: &ItemId,
    epoch_key: &EpochKey,
    roster: &Roster,
) -> Result<Zeroizing<Vec<u8>>> {
    Envelope::parse(bytes)?
        .verify(item_id, roster)?
        .open(epoch_key)
}

/// Opens an envelope whose signer's key is known directly.
///
/// The bootstrap path, for the roster envelope itself. See
/// [`Envelope::verify_with_signer`].
///
/// # Errors
///
/// As [`open`], minus [`Error::UnknownSigner`].
pub fn open_with_signer(
    bytes: &[u8],
    item_id: &ItemId,
    epoch_key: &EpochKey,
    signer_public_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    Envelope::parse(bytes)?
        .verify_with_signer(item_id, signer_public_key)?
        .open(epoch_key)
}
