// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opaque bearer tokens, and the rule that the database never holds one.
//!
//! Access and refresh tokens are 32 CSPRNG bytes rendered as unpadded
//! base64url. They carry no structure — no vault id, no expiry, no signature —
//! because a self-contained token would have to be either encrypted (another key
//! to manage) or readable (another metadata leak). A random handle plus a row is
//! simpler and revocable.
//!
//! **Only the BLAKE2b-256 hash of a token is stored.** A database dump therefore
//! yields no usable credential, which matters because the whole premise of this
//! server is that the dump is worthless. This is the one place the server hashes
//! anything, and the input is a value the server itself generated — never
//! anything derived from an envelope.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::ApiError;

/// Length of a token in raw bytes, before encoding.
pub const TOKEN_BYTES: usize = 32;

/// Length of a challenge nonce in raw bytes.
pub const NONCE_BYTES: usize = 32;

/// The OS CSPRNG failed. Fatal for the operation that asked; never retried in a
/// loop, because a failing entropy source does not fix itself under pressure.
#[derive(Debug, thiserror::Error)]
#[error("the operating system CSPRNG failed")]
pub struct EntropyError;

impl From<EntropyError> for ApiError {
    fn from(_: EntropyError) -> Self {
        Self::Internal("CSPRNG failure".into())
    }
}

/// Fills an array from the OS CSPRNG.
///
/// # Errors
///
/// [`EntropyError`] if `getrandom` fails.
pub fn random_array<const N: usize>() -> Result<[u8; N], EntropyError> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|_| EntropyError)?;
    Ok(out)
}

/// A freshly minted secret, on its way to the client exactly once.
///
/// Zeroized on drop. The server keeps [`Secret::hash`] and forgets the rest.
pub struct Secret(Zeroizing<[u8; TOKEN_BYTES]>);

impl Secret {
    /// Draws a new secret.
    ///
    /// # Errors
    ///
    /// [`EntropyError`].
    pub fn generate() -> Result<Self, EntropyError> {
        Ok(Self(Zeroizing::new(random_array::<TOKEN_BYTES>()?)))
    }

    /// The form handed to the client: unpadded base64url, 43 characters.
    #[must_use]
    pub fn to_wire(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0.as_slice())
    }

    /// The form stored in the database.
    #[must_use]
    pub fn hash(&self) -> TokenHash {
        TokenHash::of(self.0.as_slice())
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// BLAKE2b-256 of a token. The only token representation that touches disk.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// Hashes raw token bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(b"misty/server/token/v1");
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    /// Hashes a token as presented by a client.
    ///
    /// # Errors
    ///
    /// [`ApiError::Unauthorized`] if the text is not a well-formed token. A
    /// malformed token is an authentication failure, not a `400`: telling a
    /// caller *why* its credential was rejected is free information.
    pub fn parse_presented(text: &str) -> Result<Self, ApiError> {
        use base64::Engine as _;
        let mut raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text.as_bytes())
            .map_err(|_| ApiError::Unauthorized)?;
        if raw.len() != TOKEN_BYTES {
            raw.zeroize();
            return Err(ApiError::Unauthorized);
        }
        let hash = Self::of(&raw);
        raw.zeroize();
        Ok(hash)
    }

    /// The 32 stored bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Rebuilds from stored bytes.
    ///
    /// # Errors
    ///
    /// [`ApiError::Internal`] if the stored value is not 32 bytes, which would
    /// mean the schema has been tampered with.
    pub fn from_stored(bytes: &[u8]) -> Result<Self, ApiError> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ApiError::Internal("token hash column is not 32 bytes".into()))?;
        Ok(Self(array))
    }
}

impl core::fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Not a secret — it is a hash of one — but printing it would let a log
        // reader correlate sessions, so it is redacted anyway.
        f.write_str("TokenHash([redacted])")
    }
}

/// Compares two strings without an early exit.
///
/// Used for the registration token, which is a shared secret short enough that a
/// timing side channel would be usable.
#[must_use]
pub fn secret_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_round_trips_from_wire_to_hash() {
        let secret = Secret::generate().unwrap();
        let wire = secret.to_wire();
        assert_eq!(wire.len(), 43, "43 chars of unpadded base64url");
        assert_eq!(TokenHash::parse_presented(&wire).unwrap(), secret.hash());
    }

    #[test]
    fn two_tokens_differ() {
        let a = Secret::generate().unwrap();
        let b = Secret::generate().unwrap();
        assert_ne!(a.to_wire(), b.to_wire());
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn a_malformed_token_is_unauthorized_not_bad_request() {
        for hostile in [
            "",
            "!!!!",
            "AAAA",
            "a".repeat(4096).as_str(),
            "====",
            "AA==",
        ] {
            let error = TokenHash::parse_presented(hostile).expect_err("should reject");
            assert!(matches!(error, ApiError::Unauthorized), "for {hostile:?}");
        }
    }

    #[test]
    fn padded_base64_is_rejected_so_one_token_has_one_spelling() {
        use base64::Engine as _;
        let raw = [7u8; TOKEN_BYTES];
        let padded = base64::engine::general_purpose::URL_SAFE.encode(raw);
        assert!(padded.ends_with('='));
        assert!(TokenHash::parse_presented(&padded).is_err());
    }

    #[test]
    fn debug_never_shows_material() {
        let secret = Secret::generate().unwrap();
        assert_eq!(format!("{secret:?}"), "Secret([redacted])");
        assert_eq!(format!("{:?}", secret.hash()), "TokenHash([redacted])");
    }

    #[test]
    fn hash_is_domain_separated_and_stable() {
        // Domain separation means this hash cannot collide with any other
        // BLAKE2b use in Misty. Value recorded so an accidental change to the
        // prefix breaks a test rather than silently invalidating every session.
        let hash = TokenHash::of(&[0u8; 32]);
        assert_eq!(
            hex::encode(hash.as_bytes()),
            "5b9111780543d1871cb8de589f6e088273cbbfcd0ef3d8b45b4771bd5d44081c"
        );
    }

    #[test]
    fn stored_bytes_round_trip() {
        let hash = TokenHash::of(b"x");
        assert_eq!(TokenHash::from_stored(hash.as_bytes()).unwrap(), hash);
        assert!(TokenHash::from_stored(&[0u8; 31]).is_err());
    }

    #[test]
    fn secret_str_eq_matches_ordinary_equality() {
        assert!(secret_str_eq("hunter2", "hunter2"));
        assert!(!secret_str_eq("hunter2", "hunter3"));
        assert!(!secret_str_eq("hunter2", "hunter22"));
        assert!(secret_str_eq("", ""));
    }
}
