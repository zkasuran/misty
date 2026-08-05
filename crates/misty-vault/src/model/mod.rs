// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SPEC §3's data model, with SPEC §4's merge rules attached to each field.
//!
//! * [`Item`] — one credential and everything the app knows about it.
//! * [`Group`] — a user-defined grouping, its own encrypted object.
//! * [`IconRef`] — how an item is drawn, with no network fetch anywhere.
//! * [`Tombstone`] — a delete, as a value with a clock rather than an absence.
//!
//! `UsageCounter` lives in [`crate::crdt`] with the other replicated types, since
//! it is one.

mod group;
mod icon;
mod item;
mod tombstone;

pub use group::Group;
pub use icon::IconRef;
pub use item::Item;
pub use tombstone::{Tombstone, TombstoneReason};
