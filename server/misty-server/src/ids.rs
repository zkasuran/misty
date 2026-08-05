// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The four 16-byte identifiers the server handles, and their canonical
//! encodings.
//!
//! These are newtypes rather than `[u8; 16]` for the same reason `misty-crypto`
//! makes them newtypes: Misty has four different 16-byte ids and swapping two of
//! them would be a silent bug. The server deliberately does **not** depend on
//! `misty-crypto`, so the types are redefined here rather than imported; the
//! wire encodings match.
//!
//! # Canonical encodings
//!
//! * In a URL path: exactly 32 **lowercase** hex characters. Uppercase is
//!   rejected rather than folded, so one item has exactly one path. Two spellings
//!   of the same id would mean two cache keys, two rate-limit buckets, and two
//!   plausible readings of a log line.
//! * In JSON: the same lowercase hex string, so a request body and a path agree.
//!
//! Path traversal is impossible by construction: `..`, `%2e%2e`, and `/` all
//! fail the hex check.

use core::fmt;

use serde::de::{Deserialize, Deserializer, Error as _};
use serde::{Serialize, Serializer};

/// Why an id string was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// Not 32 characters long.
    #[error("expected 32 hex characters for a {what}, got {got}")]
    Length {
        /// Which identifier was being parsed.
        what: &'static str,
        /// The length actually supplied.
        got: usize,
    },
    /// Contained something other than `0-9a-f`.
    #[error("{what} must be lowercase hex; uppercase and non-hex are rejected, not folded")]
    NotLowercaseHex {
        /// Which identifier was being parsed.
        what: &'static str,
    },
}

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident, $what:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// What this id is called in error messages.
            pub const WHAT: &'static str = $what;

            /// Wraps raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Borrows the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Lowercase hex, the canonical wire form.
            #[must_use]
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parses the canonical wire form.
            ///
            /// # Errors
            ///
            /// [`IdError`] if the input is not exactly 32 lowercase hex
            /// characters.
            pub fn parse(text: &str) -> Result<Self, IdError> {
                if text.len() != 32 {
                    return Err(IdError::Length { what: $what, got: text.len() });
                }
                if !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                    return Err(IdError::NotLowercaseHex { what: $what });
                }
                let mut out = [0u8; 16];
                hex::decode_to_slice(text, &mut out)
                    .map_err(|_| IdError::NotLowercaseHex { what: $what })?;
                Ok(Self(out))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = <&str as Deserialize>::deserialize(d)?;
                Self::parse(text).map_err(D::Error::custom)
            }
        }
    };
}

id_type!(
    /// Addresses a vault. The server's only handle on a user, by design
    /// (SPEC §6).
    VaultId,
    "vault id"
);

id_type!(
    /// Identifies one device within a vault. The server's device table keyed by
    /// this is an access-control cache, never a source of trust (SPEC §6.2).
    DeviceId,
    "device id"
);

id_type!(
    /// Storage key of one item. Never appears in a durable log.
    ItemId,
    "item id"
);

id_type!(
    /// One device-to-device enrollment attempt (SPEC §6.3). Functions as a
    /// bearer capability: whoever scanned the QR knows it.
    EnrollId,
    "enroll id"
);

impl VaultId {
    /// An 8-character prefix, for logs.
    ///
    /// A full `vault_id` in a durable log would be a stable per-user
    /// identifier. A 4-byte prefix is enough to correlate the lines of one
    /// request while leaving 2^96 vaults sharing it.
    #[must_use]
    pub fn log_prefix(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_hex() {
        let id = VaultId::from_bytes([0xab; 16]);
        assert_eq!(id.to_hex(), "abababababababababababababababab");
        assert_eq!(VaultId::parse(&id.to_hex()), Ok(id));
    }

    #[test]
    fn rejects_uppercase_rather_than_folding() {
        assert_eq!(
            ItemId::parse("ABABABABABABABABABABABABABABABAB"),
            Err(IdError::NotLowercaseHex { what: "item id" })
        );
    }

    #[test]
    fn rejects_path_traversal_shapes() {
        for hostile in [
            "../../../../../../../../etc/passwd",
            "..",
            "%2e%2e%2f",
            "0000000000000000000000000000000/",
            "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        ] {
            assert!(ItemId::parse(hostile).is_err(), "accepted {hostile:?}");
        }
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(matches!(
            VaultId::parse("abab"),
            Err(IdError::Length { got: 4, .. })
        ));
        assert!(matches!(
            VaultId::parse(""),
            Err(IdError::Length { got: 0, .. })
        ));
    }

    #[test]
    fn json_uses_the_same_spelling_as_a_path() {
        let id = DeviceId::from_bytes([1; 16]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"01010101010101010101010101010101\"");
        let back: DeviceId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn json_rejects_a_bad_id_instead_of_defaulting() {
        assert!(serde_json::from_str::<DeviceId>("\"nope\"").is_err());
        assert!(serde_json::from_str::<DeviceId>("42").is_err());
    }

    #[test]
    fn log_prefix_is_short() {
        let id = VaultId::from_bytes([0xde, 0xad, 0xbe, 0xef, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]);
        assert_eq!(id.log_prefix(), "deadbeef");
    }
}
