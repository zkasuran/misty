// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Observed-remove set, the merge rule for `groups`, `tags` and `origins`.

use core::fmt;
use std::collections::btree_map::{BTreeMap, Entry};

use serde::{Deserialize, Serialize};

use crate::crdt::Merge;
use crate::error::Result;
use crate::hlc::Hlc;

/// The two clocks one element carries.
///
/// `removed` is `None` for an element that has never been removed. An element
/// whose `removed` clock is present but not greater than `added` is present
/// again: that is SPEC §4's "add wins on tie", and it is what makes a
/// re-add after a concurrent remove behave the way a user expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrSetEntry {
    /// Clock of the most recent add.
    pub added: Hlc,
    /// Clock of the most recent remove, if any.
    pub removed: Option<Hlc>,
}

impl OrSetEntry {
    /// Whether the element is currently a member.
    #[must_use]
    pub fn is_present(&self) -> bool {
        match self.removed {
            None => true,
            Some(removed) => self.added >= removed,
        }
    }

    /// The greater of the two clocks, for the item-level "was there an edit
    /// after this delete?" comparison.
    #[must_use]
    pub fn max_hlc(&self) -> Hlc {
        match self.removed {
            Some(removed) if removed > self.added => removed,
            _ => self.added,
        }
    }
}

/// A set whose membership merges without a coordinator.
///
/// SPEC §4 gives this rule to `groups`, `tags` and `origins`, because
/// last-writer-wins over the whole vector loses concurrent additions: two devices
/// each adding one tag offline would keep only one of them.
///
/// Entries for removed elements are retained on purpose — see the
/// [module docs](crate::crdt) — and iteration is over a [`BTreeMap`], so the
/// encoding of a merged set does not depend on the order the merges happened in.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OrSet<T: Ord> {
    entries: BTreeMap<T, OrSetEntry>,
}

impl<T: Ord> OrSet<T> {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Every element ever added, member or not, in sort order.
    pub fn entries(&self) -> impl Iterator<Item = (&T, &OrSetEntry)> {
        self.entries.iter()
    }

    /// Current members, in sort order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.is_present())
            .map(|(element, _)| element)
    }

    /// Number of current members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Whether the set has no current members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// Number of retained entries, members and removed elements together. This
    /// is the count the storage limits apply to.
    #[must_use]
    pub fn stored_len(&self) -> usize {
        self.entries.len()
    }

    /// Whether `element` is a current member.
    pub fn contains(&self, element: &T) -> bool {
        self.entries
            .get(element)
            .is_some_and(OrSetEntry::is_present)
    }

    /// The greatest clock in the set, or `None` if it is untouched.
    #[must_use]
    pub fn max_hlc(&self) -> Option<Hlc> {
        self.entries.values().map(OrSetEntry::max_hlc).max()
    }

    /// Adds `element` at `hlc`. Returns whether anything changed.
    pub fn add(&mut self, element: T, hlc: Hlc) -> bool {
        match self.entries.entry(element) {
            Entry::Vacant(slot) => {
                slot.insert(OrSetEntry {
                    added: hlc,
                    removed: None,
                });
                true
            }
            Entry::Occupied(mut slot) => {
                let entry = slot.get_mut();
                if hlc > entry.added {
                    entry.added = hlc;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Removes `element` at `hlc`. Returns whether anything changed.
    ///
    /// An element that was never added is not recorded: there is nothing to
    /// observe, and inventing an entry would let a remove travel ahead of the add
    /// it is meant to cancel.
    pub fn remove(&mut self, element: &T, hlc: Hlc) -> bool {
        let Some(entry) = self.entries.get_mut(element) else {
            return false;
        };
        if entry.removed.is_some_and(|removed| removed >= hlc) {
            return false;
        }
        entry.removed = Some(hlc);
        true
    }

    /// Builds a set from raw entries, for the decoder.
    pub(crate) fn from_entries(entries: BTreeMap<T, OrSetEntry>) -> Self {
        Self { entries }
    }
}

impl<T: Ord + Clone> Merge for OrSet<T> {
    /// Per element: the later add and the later remove both survive.
    ///
    /// Taking the maximum of each clock independently is what makes this a join:
    /// there is no branch on which side is "newer", so the result cannot depend
    /// on the order or the grouping of the merges.
    fn merge(&mut self, other: &Self, _field: &'static str) -> Result<()> {
        for (element, incoming) in &other.entries {
            match self.entries.get_mut(element) {
                Some(entry) => {
                    if incoming.added > entry.added {
                        entry.added = incoming.added;
                    }
                    if let Some(removed) = incoming.removed {
                        if entry.removed.is_none_or(|current| removed > current) {
                            entry.removed = Some(removed);
                        }
                    }
                }
                None => {
                    self.entries.insert(element.clone(), *incoming);
                }
            }
        }
        Ok(())
    }
}

impl<T: Ord + fmt::Debug> fmt::Debug for OrSet<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}
