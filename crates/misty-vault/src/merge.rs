// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Merging a *set* of items, which is where the immutable-secret rule lives.
//!
//! [`Item::merge`] handles one item against another version of itself. It refuses
//! two different secrets, because resolving that needs somewhere to put the loser
//! — and SPEC §4 is emphatic that there must be a loser only in the sense of a
//! different row, never a discarded credential:
//!
//! > `otp.secret` — **immutable.** If two devices hold different secrets for one
//! > `item_id`, keep BOTH as separate items and raise a user-visible conflict.
//! > Silently picking one can destroy the only working token. Never guess with a
//! > credential.
//!
//! # The forked id has to be derived, not drawn
//!
//! A fresh random id would break convergence: two devices performing the same
//! split would invent different ids for the same credential and never agree, and
//! re-running the same merge would fork again, so the merge would not be
//! idempotent either.
//!
//! So the id is a pseudorandom function of the original id and the credential:
//!
//! ```text
//! forked_id = HKDF-SHA512(ikm = VK,
//!                         salt = "misty/vault/fork-id/v1",
//!                         info = original_item_id || secret)[0..16]
//! ```
//!
//! Keying it on the **vault key** rather than on the secret alone is deliberate.
//! An item id is stored in the clear — it is the storage key, and a hostile server
//! sees it (threat model `A1`). `H(secret)` truncated to 16 bytes would hand that
//! server an oracle: guess a secret, compute the id, and a match confirms the
//! guess. Under `VK` the id is a PRF output the server cannot compute at all,
//! while every device that holds `VK` derives the same value.
//!
//! Which credential keeps the original id is decided by comparing the two secrets
//! bytewise: the smaller secret keeps it. Arbitrary, but total and agreed on by
//! every device, which is all convergence requires.
//!
//! # `SPEC.md` addition
//!
//! `misty/vault/fork-id/v1` is a new domain-separation constant. SPEC §6.6 lists
//! every wire-visible constant and does not have it, because SPEC §4 does not say
//! how the second item gets an id. It should be added there.

use std::collections::{BTreeMap, VecDeque};

use misty_crypto::keys::VaultKey;
use misty_crypto::{derive, ItemId};
use misty_otp::SecretBytes;
use zeroize::Zeroizing;

use crate::codec;
use crate::conflict::{self, Conflict};
use crate::error::{Result, VaultError};
use crate::limits;
use crate::model::Item;

/// Domain separation for the forked-item id derivation. Wire-visible: it decides
/// an id that a server stores.
pub const FORK_ID_SALT: &[u8] = b"misty/vault/fork-id/v1";

/// Where a forked item's id comes from.
///
/// A trait so the property tests can pin the derivation without a vault key, and
/// so the derivation has exactly one production implementation
/// ([`VaultForkIds`]) rather than being inlined into the merge loop.
pub trait ForkIds {
    /// The id the credential `secret` moves to when it loses `original`.
    ///
    /// MUST be deterministic: the same inputs on two devices MUST give the same
    /// id, or merge does not converge.
    ///
    /// # Errors
    ///
    /// Whatever the derivation reports; [`VaultForkIds`] can only fail if HKDF
    /// does.
    fn fork_id(&self, original: &ItemId, secret: &SecretBytes) -> Result<ItemId>;
}

/// The production derivation: HKDF-SHA-512 under the vault key.
///
/// Borrows the key rather than holding one, because [`VaultKey`] is deliberately
/// not `Clone` (SPEC §2.2: a cloned key is a second copy to zeroize).
pub struct VaultForkIds<'a> {
    vault_key: &'a VaultKey,
}

impl<'a> VaultForkIds<'a> {
    /// Derives forked ids under `vault_key`.
    #[must_use]
    pub const fn new(vault_key: &'a VaultKey) -> Self {
        Self { vault_key }
    }
}

impl ForkIds for VaultForkIds<'_> {
    fn fork_id(&self, original: &ItemId, secret: &SecretBytes) -> Result<ItemId> {
        // Zeroizing: `info` holds the secret in the clear.
        let mut info = Zeroizing::new(Vec::with_capacity(ItemId::LEN + secret.len()));
        info.extend_from_slice(original.as_bytes());
        info.extend_from_slice(secret.expose_secret());
        let mut okm = [0u8; ItemId::LEN];
        derive::hkdf_sha512(
            self.vault_key.expose_secret(),
            FORK_ID_SALT,
            &info,
            &mut okm,
        )?;
        Ok(ItemId::from_bytes(okm))
    }
}

impl core::fmt::Debug for VaultForkIds<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VaultForkIds { vault_key: [redacted] }")
    }
}

/// A vault's items, keyed by id, with the merge that keeps both credentials.
///
/// This is the whole replicated state as far as SPEC §4's convergence property is
/// concerned, and it is deliberately separable from [`Vault`](crate::Vault): the
/// property tests exercise it directly, with no storage, no envelopes and no
/// clock, so a convergence failure cannot be blamed on any of those.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ItemSet {
    items: BTreeMap<ItemId, Item>,
}

impl ItemSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many items, deleted ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the set holds nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// One item.
    #[must_use]
    pub fn get(&self, id: &ItemId) -> Option<&Item> {
        self.items.get(id)
    }

    /// Every item, in id order. Includes deleted and trashed items; callers that
    /// want a listing filter on [`Item::is_live`].
    pub fn iter(&self) -> impl Iterator<Item = &Item> {
        self.items.values()
    }

    /// Adds an item whose id must be new.
    ///
    /// # Errors
    ///
    /// [`VaultError::ItemExists`] if the id is taken. Use [`ItemSet::absorb`] to
    /// merge instead.
    pub fn insert(&mut self, item: Item) -> Result<()> {
        if self.items.contains_key(&item.id()) {
            return Err(VaultError::ItemExists { id: item.id() });
        }
        self.items.insert(item.id(), item);
        Ok(())
    }

    /// Removes an item outright. Used by the tombstone purge, and by nothing
    /// else: a delete is a [`Tombstone`](crate::Tombstone), not a removal.
    pub fn purge(&mut self, id: &ItemId) -> Option<Item> {
        self.items.remove(id)
    }

    /// Overwrites the entry for `item.id()`, or adds it. The persistence path uses
    /// this after a write has already been committed to storage.
    pub(crate) fn replace(&mut self, item: Item) {
        self.items.insert(item.id(), item);
    }

    /// Merges one incoming item in, forking on a divergent secret.
    ///
    /// Returns every id whose stored value changed, so a caller can persist
    /// exactly those. Ids may repeat; the list is deduplicated before returning.
    ///
    /// # Errors
    ///
    /// [`VaultError::MergeDidNotSettle`] if forking does not terminate within
    /// [`MAX_MERGE_STEPS`](crate::limits::MAX_MERGE_STEPS) — which needs a
    /// 128-bit id collision — plus anything [`Item::merge`] or
    /// [`ForkIds::fork_id`] reports.
    pub fn absorb(
        &mut self,
        incoming: Item,
        fork: &impl ForkIds,
        conflicts: &mut Vec<Conflict>,
    ) -> Result<Vec<ItemId>> {
        let mut touched = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(incoming);

        for step in 0..=limits::MAX_MERGE_STEPS {
            let Some(candidate) = queue.pop_front() else {
                touched.sort_unstable();
                touched.dedup();
                return Ok(touched);
            };
            if step == limits::MAX_MERGE_STEPS {
                return Err(VaultError::MergeDidNotSettle {
                    max: limits::MAX_MERGE_STEPS,
                });
            }

            // Taken out and put back so the two sides can be moved around
            // without fighting the borrow checker over one map.
            let Some(local) = self.items.remove(&candidate.id()) else {
                touched.push(candidate.id());
                self.items.insert(candidate.id(), candidate);
                continue;
            };

            if local.secret() == candidate.secret() {
                let mut merged = local;
                merged.merge(&candidate, conflicts)?;
                touched.push(merged.id());
                self.items.insert(merged.id(), merged);
                continue;
            }

            // Two real credentials under one id. Both are kept; which one keeps
            // the id is decided by the secrets, so both devices agree.
            let (keeper, mut mover) =
                if conflict::local_keeps_id(local.secret(), candidate.secret()) {
                    (local, candidate)
                } else {
                    (candidate, local)
                };
            let forked = fork.fork_id(&keeper.id(), mover.secret())?;
            conflicts.push(Conflict::DivergentSecret {
                kept: keeper.id(),
                forked,
            });
            mover.rebind(forked);
            touched.push(keeper.id());
            self.items.insert(keeper.id(), keeper);
            // The forked id may itself be occupied — by the same credential from
            // an earlier merge, which is the idempotent case, or (needing a
            // 128-bit collision) by something else. Either way it goes back
            // through the same path.
            queue.push_back(mover);
        }
        Err(VaultError::MergeDidNotSettle {
            max: limits::MAX_MERGE_STEPS,
        })
    }

    /// Merges every item of `other` into `self`.
    ///
    /// # Errors
    ///
    /// As [`ItemSet::absorb`].
    pub fn merge(
        &mut self,
        other: &Self,
        fork: &impl ForkIds,
        conflicts: &mut Vec<Conflict>,
    ) -> Result<Vec<ItemId>> {
        let mut touched = Vec::new();
        for item in other.iter() {
            touched.extend(self.absorb(item.clone(), fork, conflicts)?);
        }
        touched.sort_unstable();
        touched.dedup();
        Ok(touched)
    }

    /// A byte string that is equal for two sets exactly when the sets are equal.
    ///
    /// This is what "byte-identical state" means in SPEC §4's convergence
    /// requirement, and it is deliberately the *stored* encoding rather than a
    /// structural comparison: two sets that compare equal in Rust but encode
    /// differently would still diverge on disk and over the wire.
    ///
    /// Holds every secret in the clear, hence
    /// [`Zeroizing`].
    ///
    /// # Errors
    ///
    /// As [`encode_item`](crate::codec::encode_item).
    pub fn fingerprint(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::new());
        for item in self.items.values() {
            let payload = codec::encode_item(item)?;
            // Length-prefixed, so no concatenation of two items can be confused
            // with a different pair.
            let length = u64::try_from(payload.len()).unwrap_or(u64::MAX);
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(&payload);
        }
        Ok(out)
    }
}

impl FromIterator<(ItemId, Item)> for ItemSet {
    fn from_iter<I: IntoIterator<Item = (ItemId, Item)>>(iter: I) -> Self {
        Self {
            items: iter.into_iter().collect(),
        }
    }
}
