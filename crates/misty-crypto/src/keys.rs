// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The key hierarchy (SPEC §2.2).
//!
//! ```text
//! Recovery Key (RK)   32B random, shown once, wraps VK, never stored unwrapped
//! Vault Key (VK)      32B random, root of all item encryption
//! Epoch Key (EK_n)    HKDF-SHA512(ikm=VK, salt="misty/epoch/v1", info=LE32(n))
//! Item Key (IK)       32B random per item, wrapped by EK_current
//! KDF Key             Argon2id(passphrase) or an HKDF output used as a KEK
//! ```
//!
//! Every type in this module:
//!
//! * is [`Zeroize`] and [`ZeroizeOnDrop`];
//! * renders as `[redacted]` in both `Debug` and `Display`;
//! * does **not** implement `Serialize`, `Deserialize`, `Clone`, `PartialEq`,
//!   or `Eq`.
//!
//! The missing `PartialEq` is deliberate: `==` on secret material is a
//! review-blocking bug (SPEC §2.1), so it does not compile. Use
//! [`ConstantTimeEq`] or the inherent `constant_time_eq` method.
//!
//! The missing `Clone` is also deliberate. A cloned key is a second copy to
//! zeroize and a second chance to leak one; pass references instead. Where a
//! copy is genuinely required, `expose_secret` makes it explicit and grep-able.
//!
//! Keys leave the process only through an explicit sealing API:
//! [`crate::envelope`], [`crate::backup`], [`crate::recovery::wrap_vault_key`]
//! or [`crate::enrollment`].

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{random, Result};

/// Length of every symmetric key in the hierarchy, in bytes.
pub const KEY_LEN: usize = 32;

macro_rules! secret_key {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        ///
        /// Zeroized on drop; `Debug` and `Display` render `[redacted]`; not
        /// `Serialize`, not `Clone`, not `PartialEq`. See the [module
        /// docs](self).
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; KEY_LEN]);

        impl $name {
            /// Draws a fresh key from the OS CSPRNG.
            ///
            /// # Errors
            ///
            /// As [`random::fill`].
            pub fn generate() -> Result<Self> {
                Ok(Self(random::array::<KEY_LEN>()?))
            }

            /// Adopts existing key bytes, for example after unwrapping.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            /// Borrows the raw key bytes.
            ///
            /// Every call site is an audit point: the bytes must not be copied
            /// into anything that is not itself zeroized.
            #[must_use]
            pub const fn expose_secret(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            /// Constant-time equality.
            #[must_use]
            pub fn constant_time_eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("[redacted]")
            }
        }
    };
}

secret_key!(
    /// Root of all item encryption. Wrapped at rest by an OS-keystore key and,
    /// for recovery, by the [`RecoveryKey`].
    VaultKey
);

secret_key!(
    /// Per-item key. Random per item, wrapped by the current [`EpochKey`], and
    /// the only key that ever touches an item payload.
    ItemKey
);

secret_key!(
    /// Shown to the user exactly once, as the Recovery Kit. Wraps the
    /// [`VaultKey`] into `recovery_blob`.
    RecoveryKey
);

secret_key!(
    /// A key derived from a passphrase by Argon2id, or from a shared secret by
    /// HKDF. Used as a key-encryption key, never on an item payload directly.
    KdfKey
);
/// An epoch key, `EK_n`, together with the epoch number `n` it was derived
/// for.
///
/// Carrying `n` inside the key is not in SPEC §2.2, which describes only the
/// bytes. It is here because [`crate::envelope::open`] can then reject an
/// envelope from the wrong epoch with a typed error instead of an opaque AEAD
/// failure, and because it makes "decrypt this with the key for its own epoch"
/// the only easy thing to write.
///
/// Zeroized on drop; `Debug` shows the epoch (not secret) and `[redacted]` for
/// the key material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EpochKey {
    epoch: u32,
    key: [u8; KEY_LEN],
}

impl EpochKey {
    /// Adopts derived key bytes for `epoch`.
    ///
    /// Prefer [`crate::derive::epoch_key`], which derives them from the vault
    /// key as the spec requires.
    #[must_use]
    pub const fn from_bytes(epoch: u32, key: [u8; KEY_LEN]) -> Self {
        Self { epoch, key }
    }

    /// The epoch this key belongs to.
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Borrows the raw key bytes. An audit point; see [`VaultKey::expose_secret`].
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    /// Constant-time equality of both the epoch and the key material.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for EpochKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key) & self.epoch.ct_eq(&other.epoch)
    }
}

impl fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EpochKey {{ epoch: {}, key: [redacted] }}", self.epoch)
    }
}

impl fmt::Display for EpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_are_redacted() {
        let vk = VaultKey::from_bytes([0xab; 32]);
        assert_eq!(format!("{vk:?}"), "VaultKey([redacted])");
        assert_eq!(format!("{vk}"), "[redacted]");
        let ek = EpochKey::from_bytes(9, [0xcd; 32]);
        assert_eq!(format!("{ek:?}"), "EpochKey { epoch: 9, key: [redacted] }");
    }

    #[test]
    fn constant_time_eq_agrees_with_the_bytes() {
        let a = ItemKey::from_bytes([1; 32]);
        let b = ItemKey::from_bytes([1; 32]);
        let c = ItemKey::from_bytes([2; 32]);
        assert!(a.constant_time_eq(&b));
        assert!(!a.constant_time_eq(&c));
    }

    #[test]
    fn epoch_is_part_of_epoch_key_equality() {
        let a = EpochKey::from_bytes(1, [1; 32]);
        let b = EpochKey::from_bytes(2, [1; 32]);
        assert!(!a.constant_time_eq(&b));
    }
}
