// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! XChaCha20-Poly1305, wrapped so every call site looks the same.
//!
//! `wrap(outer, inner, ctx) = XChaCha20Poly1305(key=outer, nonce=random24,
//! pt=inner, aad=ctx)` from SPEC §2.2 is spelled out here once. 24-byte nonces
//! mean fresh random nonces are safe for the lifetime of a vault; nothing in
//! this crate ever derives a nonce from a counter.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// XChaCha20-Poly1305 nonce length.
pub(crate) const NONCE_LEN: usize = 24;

/// Poly1305 tag length.
pub(crate) const TAG_LEN: usize = 16;

/// Encrypts `plaintext`, returning `ciphertext || tag`.
pub(crate) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::AeadEncrypt)
}

/// Decrypts `ciphertext || tag`.
///
/// `on_failure` is the typed error to report, so each caller can say which
/// layer failed to authenticate without leaking anything else.
pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    on_failure: Error,
) -> Result<Zeroizing<Vec<u8>>> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| on_failure)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Authoritative: draft-irtf-cfrg-xchacha-03 §A.3.1.
    #[test]
    fn xchacha20poly1305_draft_vector() {
        let key: [u8; 32] =
            hex_literal::hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 24] = hex_literal::hex!("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = hex_literal::hex!("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = hex_literal::hex!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
            "21f9664c97637da9768812f615c68b13b52e"
            "c0875924c1c7987947deafd8780acf49"
        );

        let sealed = encrypt(&key, &nonce, &aad, plaintext).unwrap();
        assert_eq!(sealed, expected, "ciphertext || tag");

        let opened = decrypt(&key, &nonce, &aad, &sealed, Error::AeadEncrypt).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let sealed = encrypt(&key, &nonce, b"context-a", b"secret").unwrap();
        assert!(matches!(
            decrypt(
                &key,
                &nonce,
                b"context-b",
                &sealed,
                Error::PayloadDecryptFailed
            ),
            Err(Error::PayloadDecryptFailed)
        ));
    }

    #[test]
    fn tag_length_is_sixteen() {
        let sealed = encrypt(&[0u8; 32], &[0u8; 24], b"", b"").unwrap();
        assert_eq!(sealed.len(), TAG_LEN);
    }
}
