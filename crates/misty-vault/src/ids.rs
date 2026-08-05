// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identifiers that are not [`ItemId`] but are stored like one.
//!
//! A group and a custom icon are each their own encrypted object with its own
//! envelope (`kind = 4` and `kind = 5` in SPEC §2.4), so each is addressed by a
//! 16-byte storage key exactly like an item. They are newtypes over [`ItemId`]
//! rather than aliases for it: a `GroupId` in `Item::groups` and the `ItemId` of
//! the item holding that list are different things, and mixing them up would be
//! a silent bug that no test would notice.
//!
//! Like every id in Misty these are 16 CSPRNG bytes, **not** UUIDv7: a timestamp
//! prefix would leak creation order to the server (SPEC §3).

use core::fmt;

use misty_crypto::ItemId;
use serde::{Deserialize, Serialize};

use crate::error::Result;

macro_rules! item_id_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(ItemId);

        impl $name {
            /// Draws a fresh id from the OS CSPRNG.
            ///
            /// # Errors
            ///
            /// [`VaultError::Crypto`](crate::VaultError::Crypto) if the OS
            /// entropy source is unavailable. Misty never falls back to a
            /// userspace PRNG.
            pub fn generate() -> Result<Self> {
                Ok(Self(ItemId::generate()?))
            }

            /// Wraps raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(ItemId::from_bytes(bytes))
            }

            /// Wraps a storage key.
            #[must_use]
            pub const fn from_item_id(id: ItemId) -> Self {
                Self(id)
            }

            /// The storage key this id addresses.
            #[must_use]
            pub const fn as_item_id(&self) -> ItemId {
                self.0
            }

            /// Borrows the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            /// Lowercase hex rendering. Not secret.
            #[must_use]
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0.to_hex())
            }
        }
    };
}

item_id_newtype!(
    /// Storage key of a [`Group`](crate::Group), and the element type of
    /// [`Item::groups`](crate::Item::groups).
    GroupId
);

item_id_newtype!(
    /// Storage key of a user-supplied icon blob, referenced by
    /// [`IconRef::Custom`](crate::IconRef::Custom).
    BlobId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_through_cbor_as_byte_strings() {
        let id = GroupId::from_bytes([0x2b; 16]);
        let mut buf = Vec::new();
        ciborium::into_writer(&id, &mut buf).unwrap();
        // 0x50 = CBOR major type 2, length 16. A transparent newtype must not
        // add a wrapper: an extra array header per group reference would grow
        // every item payload.
        assert_eq!(buf.first(), Some(&0x50));
        assert_eq!(buf.len(), 17);
        let back: GroupId = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn debug_names_the_type_and_display_does_not() {
        let id = BlobId::from_bytes([0x01; 16]);
        assert_eq!(format!("{id}"), "01".repeat(16));
        assert_eq!(format!("{id:?}"), format!("BlobId({})", "01".repeat(16)));
    }

    #[test]
    fn distinct_id_types_do_not_interconvert_silently() {
        let group = GroupId::from_bytes([7; 16]);
        // The only route across is through the storage key, which is grep-able.
        let blob = BlobId::from_item_id(group.as_item_id());
        assert_eq!(blob.as_bytes(), group.as_bytes());
    }
}
