// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How an item is drawn.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::ids::BlobId;
use crate::limits::MAX_ICON_SLUG_LEN;
use crate::text;

/// Which icon an item uses (SPEC §3).
///
/// There is deliberately no "fetch it from the issuer's website" variant. SPEC §0
/// lists a network fetch of issuer icons as a v1 non-goal, and the reason is that
/// asking a CDN for `github.png` tells that CDN which services the user has
/// accounts with — the same metadata threat model `A1` spends the whole envelope
/// format protecting. A bundled slug ships in the app; a custom icon is an
/// encrypted vault object like any other.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IconRef {
    /// One of the icons shipped with the app, named by slug.
    Bundled(String),
    /// A user-supplied image, stored as its own encrypted object
    /// (`kind = 5` in SPEC §2.4).
    Custom(BlobId),
    /// The issuer's initials on a coloured tile. ARGB.
    Initials {
        /// Tile colour, ARGB.
        color: u32,
    },
}

impl IconRef {
    /// Checks a slug against [`MAX_ICON_SLUG_LEN`] and the text rules.
    ///
    /// # Errors
    ///
    /// [`VaultError::StringTooLong`](crate::VaultError::StringTooLong),
    /// [`VaultError::DisallowedCharacter`](crate::VaultError::DisallowedCharacter)
    /// or [`VaultError::EmptyField`](crate::VaultError::EmptyField).
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Bundled(slug) => text::check_required_label("icon.slug", slug, MAX_ICON_SLUG_LEN),
            Self::Custom(_) | Self::Initials { .. } => Ok(()),
        }
    }
}

impl Default for IconRef {
    /// Initials on a transparent tile: the only variant that needs neither a
    /// shipped asset nor a stored blob, so it is the one an importer can always
    /// produce.
    fn default() -> Self {
        Self::Initials { color: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VaultError;

    #[test]
    fn slugs_are_validated_like_any_other_label() {
        assert!(IconRef::Bundled("github".into()).validate().is_ok());
        assert!(matches!(
            IconRef::Bundled(String::new()).validate(),
            Err(VaultError::EmptyField { field: "icon.slug" })
        ));
        assert!(matches!(
            IconRef::Bundled("a".repeat(MAX_ICON_SLUG_LEN + 1)).validate(),
            Err(VaultError::StringTooLong { .. })
        ));
        assert!(matches!(
            IconRef::Bundled("git\u{202e}hub".into()).validate(),
            Err(VaultError::DisallowedCharacter { .. })
        ));
    }

    #[test]
    fn the_other_variants_need_no_validation() {
        assert!(IconRef::Custom(BlobId::from_bytes([1; 16]))
            .validate()
            .is_ok());
        assert!(IconRef::default().validate().is_ok());
        assert_eq!(IconRef::default(), IconRef::Initials { color: 0 });
    }

    #[test]
    fn variants_round_trip_through_cbor() {
        for icon in [
            IconRef::Bundled("github".into()),
            IconRef::Custom(BlobId::from_bytes([9; 16])),
            IconRef::Initials { color: 0xFF00_8080 },
        ] {
            let mut buf = Vec::new();
            ciborium::into_writer(&icon, &mut buf).unwrap();
            let back: IconRef = ciborium::from_reader(buf.as_slice()).unwrap();
            assert_eq!(back, icon);
        }
    }
}
