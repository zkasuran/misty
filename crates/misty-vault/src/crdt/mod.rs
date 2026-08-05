// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The four conflict-free replicated types SPEC §4 needs, and nothing else.
//!
//! | Type | Merge | Used for |
//! |---|---|---|
//! | [`Lww`] | greater [`Hlc`](crate::Hlc) wins | plain user-edited fields |
//! | [`OrSet`] | per-element add/remove clocks, add wins on tie | `groups`, `tags`, `origins` |
//! | [`UsageCounter`] | per-device maximum, read as the sum | `usage` |
//! | [`MaxWins`] | greater value wins | `otp.counter`, `last_used_at` |
//! | [`MinWins`] | lesser value wins | `created_at` |
//!
//! Every one of them is a join over a lattice, which is what makes merge
//! commutative, associative and idempotent — the three laws SPEC §4 makes the
//! gate on this crate. [`Merge`] states the contract in one place so the property
//! tests can assert it generically instead of once per field.
//!
//! # Why nothing here ever discards a tombstone
//!
//! [`OrSet`] keeps an entry for an element that has been removed, and the item
//! model keeps a [`Tombstone`](crate::Tombstone) for an item that has been
//! deleted. Dropping either would break convergence rather than save space: a
//! peer that still holds the add would re-introduce the element on the next sync,
//! forever. Removal is expressed as a *later clock*, never as an absence.
//! Reclaiming the space is a separate, time-driven purge (SPEC §4: 90 days).

mod lww;
mod orset;
mod scalar;
mod usage;

pub use lww::Lww;
pub use orset::{OrSet, OrSetEntry};
pub use scalar::{MaxWins, MinWins};
pub use usage::UsageCounter;

use crate::error::Result;

/// The merge contract every replicated type in this crate satisfies.
///
/// For all `a`, `b`, `c` of one type, writing `⊕` for `merge`:
///
/// * **commutative** — `a ⊕ b == b ⊕ a`
/// * **associative** — `(a ⊕ b) ⊕ c == a ⊕ (b ⊕ c)`
/// * **idempotent** — `a ⊕ a == a`, and `(a ⊕ b) ⊕ b == a ⊕ b`
///
/// Asserted separately for each law, over each type, in
/// `tests/convergence.rs`: a failure that says only "these two states differ"
/// does not say which law broke, and the three break for different reasons.
///
/// `field` names the field being merged. It is used only to make an error
/// legible; no implementation branches on it.
pub trait Merge {
    /// Joins `other` into `self`.
    ///
    /// # Errors
    ///
    /// Only [`VaultError::ClockCollision`](crate::VaultError::ClockCollision),
    /// and only from [`Lww`]. See that type's documentation for why an
    /// impossible case is reported rather than resolved.
    fn merge(&mut self, other: &Self, field: &'static str) -> Result<()>;
}
