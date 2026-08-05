// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Misty's vault: the item model, the per-item CRDT merge engine, and encrypted
//! storage.
//!
//! This crate implements [`docs/SPEC.md`] §3 (data model), §3.1 (multiple
//! accounts on one site), §4 (CRDT and merge rules) and §5 (storage). It is a
//! *consumer* of [`misty_crypto`] and [`misty_otp`]: no cryptography and no
//! one-time-password arithmetic happens here.
//!
//! * [`model`] — SPEC §3's fields, each wrapped in the replicated type that
//!   implements its merge rule.
//! * [`crdt`] — those types: [`Lww`](crdt::Lww), [`OrSet`](crdt::OrSet),
//!   [`UsageCounter`](crdt::UsageCounter), [`MaxWins`](crdt::MaxWins),
//!   [`MinWins`](crdt::MinWins).
//! * [`hlc`] — the hybrid logical clock, which does not regress when the wall
//!   clock does.
//! * [`merge`] — [`ItemSet`], and the immutable-secret rule that keeps both
//!   credentials rather than guessing between them.
//! * [`codec`] — the frozen CBOR wire format.
//! * [`store`] — the [`VaultStore`] trait, an in-memory backend for every target,
//!   and SQLite as a target-conditional dependency so a wasm build never compiles
//!   C.
//! * [`vault`] — the handle: open, read, write, merge, rotate.
//!
//! # Opening a vault and adding an item
//!
//! ```
//! use misty_crypto::identity::{DeviceIdentity, Roster};
//! use misty_crypto::keys::VaultKey;
//! use misty_otp::{FixedClock, OtpConfig, SecretBytes};
//! use misty_vault::{Edit, MemoryStore, NewItem, Vault};
//!
//! # fn main() -> Result<(), misty_vault::VaultError> {
//! // Clients trust the roster, never the server's idea of which devices exist
//! // (SPEC §6.2), so a vault refuses to open for a device that is not in one.
//! let device = DeviceIdentity::generate()?;
//! let mut roster = Roster::new(vec![device.record("Laptop", "linux", 0, None)?]);
//! roster.sign(&device)?;
//!
//! // The clock is injected: `wasm32-unknown-unknown` has no `SystemTime`, and a
//! // vault that read a global clock could not be tested for a 30-day trash sweep.
//! let now = 1_800_000_000_000;
//! let mut vault = Vault::open(
//!     MemoryStore::new(),
//!     FixedClock::new(now),
//!     VaultKey::generate()?,
//!     device,
//!     roster,
//! )?;
//!
//! let secret = SecretBytes::from_base32("JBSWY3DPEHPK3PXP")?;
//! let id = vault.add(NewItem::new(
//!     OtpConfig::totp(secret)?,
//!     "GitHub",
//!     "ada@example.com",
//! ))?;
//!
//! // Codes come from `misty-otp`; the vault stores the configuration and
//! // reassembles it on demand.
//! let code = vault.item(&id)?.otp()?.generate_at(now)?;
//! assert_eq!(code.value().len(), 6);
//!
//! // SPEC §3.1: a second account at the same issuer is refused until it has a
//! // nickname that tells the two apart. Both are then kept.
//! let second = NewItem::new(
//!     OtpConfig::totp(SecretBytes::from_base32("KZ2W4Y3PNZ2W4Y3P")?)?,
//!     "GitHub",
//!     "ada@example.com",
//! );
//! assert!(vault.add(second.clone()).is_err());
//! vault.add(second.nickname("work"))?;
//!
//! vault.update(&id, Edit::new().favorite(true))?;
//! assert_eq!(vault.list().count(), 2);
//! assert_eq!(vault.same_site_cluster("github", "ADA@example.com").len(), 2);
//! # Ok(())
//! # }
//! ```
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

pub mod codec;
pub mod conflict;
pub mod crdt;
pub mod edit;
pub mod error;
pub mod hlc;
pub mod ids;
pub mod limits;
pub mod merge;
pub mod model;
pub mod store;
pub mod text;
pub mod vault;

pub use codec::{decode_group, decode_item, encode_group, encode_item, ITEM_FORMAT_VERSION};
pub use conflict::Conflict;
pub use edit::{Edit, NewItem};
pub use error::{Result, VaultError};
pub use hlc::{Hlc, HlcClock, HLC_LEN, MAX_WALL_MS, MIN_WALL_MS};
pub use ids::{BlobId, GroupId};
pub use merge::{ForkIds, ItemSet, VaultForkIds, FORK_ID_SALT};
pub use model::{Group, IconRef, Item, Tombstone, TombstoneReason};
pub use store::{MemoryStore, StoredEnvelope, VaultStore};
#[cfg(not(target_arch = "wasm32"))]
pub use store::{SqliteStore, SCHEMA_VERSION};
pub use vault::{MergeReport, RemoteChange, RewrapProgress, SortKey, Vault};
