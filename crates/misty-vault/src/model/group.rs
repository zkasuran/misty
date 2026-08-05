// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A user-defined grouping of items.

use crate::crdt::{Lww, Merge, MinWins};
use crate::error::{Result, VaultError};
use crate::hlc::Hlc;
use crate::ids::GroupId;
use crate::limits;
use crate::model::tombstone::{self, Tombstone};
use crate::text;

/// A group, stored as its own encrypted object (`kind = 4` in SPEC §2.4).
///
/// SPEC §3 gives items a `groups: Vec<GroupId>` and does not spell out what a
/// group *is*. It has to be its own object rather than a string on each item: a
/// rename would otherwise have to rewrite every member, which is a multi-item
/// write with no transaction across devices, and two devices renaming
/// concurrently would split the group in two.
///
/// Membership lives on the item side, in an [`OrSet`](crate::crdt::OrSet), so
/// adding an item to a group is one item write and needs no lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub(crate) id: GroupId,
    pub(crate) name: Lww<String>,
    pub(crate) color: Lww<Option<u32>>,
    pub(crate) manual_order: Lww<Option<i64>>,
    pub(crate) created_at: MinWins<i64>,
    pub(crate) deleted: Option<Tombstone>,
}

impl Group {
    /// A group whose every field was written at `hlc`.
    pub(crate) fn create(id: GroupId, name: String, hlc: Hlc, created_at_ms: i64) -> Self {
        Self {
            id,
            name: Lww::new(name, hlc),
            color: Lww::new(None, hlc),
            manual_order: Lww::new(None, hlc),
            created_at: MinWins::new(created_at_ms),
            deleted: None,
        }
    }

    /// The storage key.
    #[must_use]
    pub const fn id(&self) -> GroupId {
        self.id
    }

    /// The display name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.get()
    }

    /// The ARGB colour, if set.
    #[must_use]
    pub const fn color(&self) -> Option<u32> {
        *self.color.get()
    }

    /// The manual sort position, if set.
    #[must_use]
    pub const fn manual_order(&self) -> Option<i64> {
        *self.manual_order.get()
    }

    /// When the group was created, in Unix milliseconds.
    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at.get()
    }

    /// The tombstone, if one was ever written.
    #[must_use]
    pub fn tombstone(&self) -> Option<&Tombstone> {
        self.deleted.as_ref()
    }

    /// The greatest clock across the group's field edits, tombstone excluded.
    #[must_use]
    pub fn max_field_hlc(&self) -> Hlc {
        self.name
            .hlc()
            .max(self.color.hlc())
            .max(self.manual_order.hlc())
    }

    /// The greatest clock anywhere in the group, stored as `hlc_max` (SPEC §5).
    #[must_use]
    pub fn max_hlc(&self) -> Hlc {
        match self.deleted {
            Some(stone) => self.max_field_hlc().max(stone.hlc),
            None => self.max_field_hlc(),
        }
    }

    /// Whether the group is deleted: a tombstone exists and nothing was edited
    /// after it. The same rule as an item (SPEC §4).
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        tombstone::tombstone_wins(self.deleted.as_ref(), self.max_field_hlc())
    }

    /// Every clock in the group, for validation and clock catch-up.
    pub(crate) fn every_hlc(&self) -> Vec<Hlc> {
        let mut out = vec![self.name.hlc(), self.color.hlc(), self.manual_order.hlc()];
        if let Some(stone) = self.deleted {
            out.push(stone.hlc);
        }
        out
    }

    /// Checks every invariant a decoded group must satisfy.
    ///
    /// # Errors
    ///
    /// [`VaultError::StringTooLong`], [`VaultError::DisallowedCharacter`],
    /// [`VaultError::EmptyField`] or [`VaultError::HlcOutOfRange`].
    pub fn validate(&self) -> Result<()> {
        text::check_required_label("group.name", self.name(), limits::MAX_GROUP_NAME_LEN)?;
        for hlc in self.every_hlc() {
            Hlc::new(hlc.wall_ms, hlc.counter, hlc.device_id)?;
        }
        Ok(())
    }

    /// Joins another version of this same group into `self`.
    ///
    /// # Errors
    ///
    /// [`VaultError::IdMismatch`] if the two ids differ, or
    /// [`VaultError::ClockCollision`] if one field carries identical clocks and
    /// different values.
    pub fn merge(&mut self, remote: &Self) -> Result<()> {
        if self.id != remote.id {
            return Err(VaultError::IdMismatch {
                expected: self.id.as_item_id(),
                found: remote.id.as_item_id(),
            });
        }
        self.name.merge(&remote.name, "group.name")?;
        self.color.merge(&remote.color, "group.color")?;
        self.manual_order
            .merge(&remote.manual_order, "group.manual_order")?;
        self.created_at
            .merge(&remote.created_at, "group.created_at")?;
        tombstone::merge_tombstone(&mut self.deleted, &remote.deleted);
        Ok(())
    }
}
