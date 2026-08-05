// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Non-secret fixed-width byte arrays: identifiers and signatures.
//!
//! These are newtypes rather than bare `[u8; 16]` because Misty has four
//! different 16-byte identifiers and mixing them up (sealing an envelope with
//! a `device_id` in place of an `item_id`, say) would be a silent, undetectable
//! bug. The compiler catches it instead.
//!
//! Identifiers are 16 CSPRNG bytes, **not** UUIDv7: a timestamp prefix would
//! leak item creation order to the server (SPEC §3).

use core::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{random, Result};

/// Lowercase hex, for `Debug`/`Display` of non-secret byte arrays.
pub(crate) fn hex_string(bytes: &[u8]) -> String {
    fn nibble(value: u8) -> char {
        // No indexing: this must not be able to panic, and it is on the
        // `Display` path of types that appear in error messages.
        char::from(if value < 10 {
            b'0' + value
        } else {
            b'a' + value - 10
        })
    }
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble(byte >> 4));
        out.push(nibble(byte & 0x0f));
    }
    out
}

macro_rules! byte_array_type {
    ($(#[$doc:meta])* $name:ident, $len:expr, $what:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $len;

            /// Wraps raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrows the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Reads from a slice.
            ///
            /// # Errors
            ///
            /// [`Error::Truncated`](crate::Error::Truncated) if the slice is
            /// not exactly `LEN` bytes.
            pub fn from_slice(bytes: &[u8]) -> Result<Self> {
                let array: [u8; $len] = bytes.try_into().map_err(|_| crate::Error::Truncated {
                    context: $what,
                    needed: $len,
                    got: bytes.len(),
                })?;
                Ok(Self(array))
            }

            /// Lowercase hex rendering. Not secret.
            #[must_use]
            pub fn to_hex(&self) -> String {
                hex_string(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex_string(&self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex_string(&self.0))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
                s.serialize_bytes(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
                struct V;
                impl<'de> Visitor<'de> for V {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "a {}-byte {}", $len, $what)
                    }

                    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> core::result::Result<$name, E> {
                        let array: [u8; $len] = v
                            .try_into()
                            .map_err(|_| E::invalid_length(v.len(), &self))?;
                        Ok($name(array))
                    }

                    fn visit_seq<A: de::SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> core::result::Result<$name, A::Error> {
                        let mut out = [0u8; $len];
                        for (i, slot) in out.iter_mut().enumerate() {
                            *slot = seq
                                .next_element()?
                                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                        }
                        Ok($name(out))
                    }
                }
                d.deserialize_bytes(V)
            }
        }
    };
}

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident, $what:literal) => {
        byte_array_type!($(#[$doc])* $name, 16, $what);

        impl $name {
            /// Draws a fresh identifier from the OS CSPRNG.
            ///
            /// # Errors
            ///
            /// As [`random::fill`].
            pub fn generate() -> Result<Self> {
                Ok(Self(random::array::<16>()?))
            }
        }
    };
}
id_type!(
    /// Storage key of a vault item. Bound into every envelope by the AAD but
    /// never stored inside one (SPEC §2.4).
    ItemId,
    "item id"
);

id_type!(
    /// Identifies one device in the roster. Appears in cleartext in every
    /// envelope header as `signer_device_id`.
    DeviceId,
    "device id"
);

id_type!(
    /// Addresses a vault on the server. The server has no other user handle:
    /// no email, no phone, no username (SPEC §6).
    VaultId,
    "vault id"
);

id_type!(
    /// One device-to-device enrollment attempt (SPEC §6.3).
    EnrollId,
    "enroll id"
);

byte_array_type!(
    /// A detached Ed25519 signature.
    ///
    /// A newtype because `serde` has no derive support for `[u8; 64]`, and
    /// because a bare 64-byte array in a struct field says nothing about what
    /// it is.
    SignatureBytes,
    64,
    "Ed25519 signature"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex_string(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn ids_round_trip_through_cbor_as_byte_strings() {
        let id = ItemId::from_bytes([0xab; 16]);
        let mut buf = Vec::new();
        ciborium::into_writer(&id, &mut buf).unwrap();
        // 0x50 = major type 2 (byte string), length 16. If this ever becomes
        // an array of integers the on-disk size of every roster doubles.
        assert_eq!(buf.first(), Some(&0x50));
        assert_eq!(buf.len(), 17);
        let back: ItemId = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn distinct_id_types_do_not_interconvert() {
        // Compile-time property, asserted here as documentation: the only way
        // across is through raw bytes, which is grep-able.
        let device = DeviceId::from_bytes([1; 16]);
        let item = ItemId::from_bytes(*device.as_bytes());
        assert_eq!(item.as_bytes(), device.as_bytes());
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert!(matches!(
            DeviceId::from_slice(&[0u8; 15]),
            Err(crate::Error::Truncated {
                needed: 16,
                got: 15,
                ..
            })
        ));
    }

    #[test]
    fn signature_bytes_round_trip_through_cbor() {
        let sig = SignatureBytes::from_bytes([7; 64]);
        let mut buf = Vec::new();
        ciborium::into_writer(&sig, &mut buf).unwrap();
        let back: SignatureBytes = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, sig);
    }
}
