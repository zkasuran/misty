// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a merge could not decide on its own, and had to hand back to the user.
//!
//! A conflict is a *report*, not state. It takes no part in the byte-identical
//! convergence property SPEC §4 makes the gate on this crate: two devices that
//! reach the same item state may well have produced their conflict lists in a
//! different order, or one of them may have merged in an order that produced no
//! report at all. What must agree is the vault; what the user is shown about how
//! it got there is a local matter.
//!
//! There are exactly two, and they exist for the same reason: a credential that
//! silently disappears is the worst failure this crate can have.

use misty_crypto::ItemId;
use misty_otp::SecretBytes;

/// Something a merge kept both sides of.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Conflict {
    /// Two devices held **different secrets** under one `item_id`, so both were
    /// kept as separate items (SPEC §4).
    ///
    /// Never resolved automatically. A secret is issued by the service and cannot
    /// be read back out of it, so a wrong guess destroys the only working token
    /// for that account — and the two secrets may both be correct, for two
    /// different accounts that collided on an id. The item that keeps `kept` is
    /// chosen by comparing the two secrets bytewise, which is arbitrary but
    /// *deterministic*: every device picks the same one without exchanging
    /// anything.
    DivergentSecret {
        /// The item that kept the original id.
        kept: ItemId,
        /// The item the other credential was moved to. Its id is derived from the
        /// original id and the credential, so every device derives the same one.
        forked: ItemId,
    },

    /// Two devices held different mOTP/Yandex **PINs** for one item.
    ///
    /// Unlike a secret this *is* resolved, last-writer-wins, because a PIN is
    /// chosen and remembered by the user rather than issued by the service: the
    /// losing value can be typed again, and forking the item on every PIN
    /// correction would produce a phantom duplicate every time somebody fixed a
    /// typo. The user is still told, because until they check, the surviving PIN
    /// may be the wrong one and the item will generate codes that do not work.
    DivergentPin {
        /// The item whose PIN was overwritten.
        item: ItemId,
    },
}

impl Conflict {
    /// The item the user should be shown first.
    #[must_use]
    pub const fn item(&self) -> ItemId {
        match self {
            Self::DivergentSecret { kept, .. } => *kept,
            Self::DivergentPin { item } => *item,
        }
    }
}

/// Which of two divergent credentials keeps the original `item_id`.
///
/// Bytewise on the secret: arbitrary, total, and computable by every device from
/// data every device has. Returns `true` if `local` keeps the id.
///
/// The comparison is deliberately **not** constant-time.
/// [`SecretBytes`]'s own `PartialEq` is, and is used for the "do these differ at
/// all" test; but once they are known to differ, an ordering is needed, and it is
/// derived from two secrets the caller already holds in plaintext. There is no
/// remote party whose timing this could inform.
#[must_use]
pub(crate) fn local_keeps_id(local: &SecretBytes, remote: &SecretBytes) -> bool {
    local.expose_secret() <= remote.expose_secret()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keeper_is_the_same_whichever_side_asks() {
        let a = SecretBytes::from_slice(b"aaaa");
        let b = SecretBytes::from_slice(b"bbbb");
        assert!(local_keeps_id(&a, &b));
        assert!(!local_keeps_id(&b, &a));
        // Shorter is smaller when it is a prefix, which is all that is needed:
        // the rule only has to be total and agreed on.
        assert!(local_keeps_id(&SecretBytes::from_slice(b"aa"), &a));
    }

    #[test]
    fn a_conflict_names_the_item_to_show_first() {
        let kept = ItemId::from_bytes([1; 16]);
        let forked = ItemId::from_bytes([2; 16]);
        assert_eq!(Conflict::DivergentSecret { kept, forked }.item(), kept);
        assert_eq!(Conflict::DivergentPin { item: forked }.item(), forked);
    }
}
