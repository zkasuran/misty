// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Misty cryptographic core.
//!
//! This crate is the only place in Misty where cryptography happens. It
//! implements [`docs/SPEC.md`] §2 byte for byte:
//!
//! * [`keys`] — the key hierarchy (§2.2). Every secret type is
//!   [`Zeroize`](zeroize::Zeroize) + [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop),
//!   renders as `[redacted]`, and is deliberately **not** `Serialize`.
//! * [`kdf`] — Argon2id tiers (§2.3), stored in cleartext headers so a
//!   low-memory device can open what a desktop wrote.
//! * [`mod@derive`] — HKDF-SHA-512 epoch keys and the enrollment key schedule.
//! * [`envelope`] — the 74-byte-header envelope format (§2.4).
//! * [`backup`] — the `.mistybak` file format (§2.5).
//! * [`recovery`] — the Recovery Kit: 24 words, Crockford Base32, QR (§2.6).
//! * [`identity`] — device identity and the signed device roster (§6.2).
//! * [`enrollment`] — device-to-device enrollment sealing (§6.3).
//! * [`random`] — the single choke point for entropy.
//!
//! # Threat model hooks
//!
//! The mitigations this crate is responsible for are `A1` (a hostile sync
//! server sees only signed, padded, opaque envelopes), `A6` (a device absent
//! from the client-signed roster is rejected before any decryption) and `A8`
//! (backups are sealed under a separate Argon2id-derived passphrase key).
//!
//! # Rules that hold everywhere in this crate
//!
//! * No `unsafe`, no C dependencies: the crate builds for
//!   `wasm32-unknown-unknown`.
//! * Secrets are compared with [`subtle::ConstantTimeEq`]. `==` on a key does
//!   not compile, because no key type implements `PartialEq`.
//! * No `unwrap`/`expect`/`panic!` outside tests — enforced by clippy lints at
//!   the top of this file. Every parser returns a typed [`Error`].
//! * No error, `Debug`, or `Display` string ever contains secret material.
//!
//! # Sealing and opening an item
//!
//! ```
//! use misty_crypto::derive;
//! use misty_crypto::envelope::{self, EnvelopeKind};
//! use misty_crypto::identity::{DeviceIdentity, Roster};
//! use misty_crypto::keys::VaultKey;
//! use misty_crypto::ItemId;
//!
//! # fn main() -> Result<(), misty_crypto::Error> {
//! // One device, and a roster it has signed. Clients trust the roster, never
//! // the server's idea of which devices exist.
//! let device = DeviceIdentity::generate()?;
//! let mut roster = Roster::new(vec![device.record("My Laptop", "linux", 0, None)?]);
//! roster.sign(&device)?;
//!
//! let vault_key = VaultKey::generate()?;
//! let epoch_key = derive::epoch_key(&vault_key, 0)?;
//! let item_id = ItemId::generate()?;
//!
//! let sealed = envelope::seal(
//!     EnvelopeKind::Item,
//!     0,
//!     &item_id,
//!     b"a serialised vault item",
//!     &epoch_key,
//!     &device,
//! )?;
//!
//! // Padded to a 256-byte bucket, so the size does not identify the item.
//! assert_eq!(sealed.len(), 458);
//!
//! let opened = envelope::open(&sealed, &item_id, &epoch_key, &roster)?;
//! assert_eq!(opened.as_slice(), b"a serialised vault item");
//! # Ok(())
//! # }
//! ```
//!
//! # Issuing a Recovery Kit
//!
//! ```
//! use misty_crypto::keys::{RecoveryKey, VaultKey};
//! use misty_crypto::recovery;
//!
//! # fn main() -> Result<(), misty_crypto::Error> {
//! let vault_key = VaultKey::generate()?;
//! let recovery_key = RecoveryKey::generate()?;
//!
//! // Show this to the user exactly once.
//! let kit = recovery::kit(&recovery_key);
//! assert_eq!(kit.words().len(), 24);
//! assert!(kit.qr().starts_with("misty-recovery:v1:"));
//!
//! // Store this next to the vault; it is inert without the kit.
//! let blob = recovery::wrap_vault_key(&recovery_key, &vault_key)?;
//!
//! // Later, from the words the user wrote down:
//! let from_paper = recovery::from_words(kit.words())?;
//! let recovered = recovery::unwrap_vault_key(&from_paper, &blob)?;
//! assert!(recovered.constant_time_eq(&vault_key));
//! # Ok(())
//! # }
//! ```
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

mod aead;
mod error;
mod types;

pub mod backup;
pub mod derive;
pub mod enrollment;
pub mod envelope;
pub mod identity;
pub mod kdf;
pub mod keys;
pub mod random;
pub mod recovery;

pub use error::{Error, Result};
pub use types::{DeviceId, EnrollId, ItemId, SignatureBytes, VaultId};
