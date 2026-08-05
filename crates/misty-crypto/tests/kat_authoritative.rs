// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Known-answer tests against authoritative, published vectors.
//!
//! Everything in this file comes from a specification or a reference
//! implementation, not from this crate. Vectors that had to be generated here
//! are labelled as such where they live:
//!
//! | Primitive | Source | Where |
//! |---|---|---|
//! | Argon2id | RFC 9106 §5.3 | `src/kdf.rs` |
//! | XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha-03 §A.3.1 | `src/aead.rs` |
//! | HKDF-SHA-256 | RFC 5869 §A.1–A.3 | `src/derive.rs` |
//! | CRC-32 | CRC catalogue check value | `src/recovery/crc32.rs` |
//! | Ed25519 | RFC 8032 §7.1 | here |
//! | BIP-39 English | reference `vectors.json` | here |
//! | HKDF-SHA-512 epoch keys | self-generated, cross-checked | `src/derive.rs` |
//! | Envelope bytes | self-generated, cross-checked | `src/envelope/tests.rs` |
//! | Backup bytes | self-generated, cross-checked | `src/backup/tests.rs` |
//! | Compact / QR encodings | self-generated, cross-checked | `src/recovery/tests.rs` |

use hex_literal::hex;
use misty_crypto::identity::DeviceIdentity;
use misty_crypto::keys::RecoveryKey;
use misty_crypto::recovery;
use misty_crypto::DeviceId;

/// RFC 8032 §7.1, TEST 1, 2 and 3.
///
/// Run through [`DeviceIdentity::sign`], so this pins Misty's use of Ed25519 —
/// pure Ed25519 with SHA-512, no context, no prehash — and not merely the
/// dependency.
#[test]
fn ed25519_rfc8032_vectors() {
    struct Vector {
        secret: [u8; 32],
        public: [u8; 32],
        message: &'static [u8],
        signature: [u8; 64],
    }

    let vectors = [
        Vector {
            secret: hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
            public: hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            message: &[],
            signature: hex!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
        },
        Vector {
            secret: hex!("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
            public: hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            message: &hex!("72"),
            signature: hex!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
        },
        Vector {
            secret: hex!("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
            public: hex!("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
            message: &hex!("af82"),
            signature: hex!(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            ),
        },
    ];

    for (index, vector) in vectors.iter().enumerate() {
        let identity = DeviceIdentity::from_secret_bytes(
            DeviceId::from_bytes([0u8; 16]),
            &vector.secret,
            [0x11; 32],
        );
        assert_eq!(
            identity.ed25519_public(),
            vector.public,
            "RFC 8032 test {index}: public key"
        );
        assert_eq!(
            identity.sign(vector.message).as_bytes(),
            &vector.signature,
            "RFC 8032 test {index}: signature"
        );
    }
}

/// BIP-39 English reference vectors, the eight 256-bit entropies from
/// `vectors.json` in the reference implementation.
///
/// Misty's 24-word encoding *is* the BIP-39 construction for 256-bit entropy —
/// same wordlist, same 8-bit SHA-256 checksum — so these are authoritative for
/// [`recovery::to_words`] and [`recovery::from_words`], in both directions.
///
/// A Misty kit is not a wallet seed; the encoding is shared, nothing else is.
#[test]
fn bip39_english_reference_vectors() {
    let vectors: [(&str, [u8; 32]); 8] = [
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon art",
            [0x00; 32],
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank year \
             wave sausage worth useful legal winner thank year wave sausage worth title",
            [0x7f; 32],
        ),
        (
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage \
             absurd amount doctor acoustic avoid letter advice cage absurd amount doctor \
             acoustic bless",
            [0x80; 32],
        ),
        (
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
             zoo zoo zoo zoo vote",
            [0xff; 32],
        ),
        (
            "hamster diagram private dutch cause delay private meat slide toddler razor \
             book happy fancy gospel tennis maple dilemma loan word shrug inflict delay \
             length",
            hex!("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c"),
        ),
        (
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft \
             ostrich alcohol speed nation flash devote level hobby quick inner drive ghost \
             inside",
            hex!("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863"),
        ),
        (
            "all hour make first leader extend hole alien behind guard gospel lava path \
             output census museum junior mass reopen famous sing advance salt reform",
            hex!("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad"),
        ),
        (
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush \
             open amazing screen patrol group space point ten exist slush involve unfold",
            hex!("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f"),
        ),
    ];

    for (mnemonic, entropy) in vectors {
        let key = RecoveryKey::from_bytes(entropy);
        let words = recovery::to_words(&key);
        assert_eq!(words.len(), 24);
        assert_eq!(words.join(" "), mnemonic, "encoding {entropy:02x?}");

        let parsed: Vec<&str> = mnemonic.split_whitespace().collect();
        let decoded = recovery::from_words(&parsed).expect("decoding");
        assert!(
            decoded.constant_time_eq(&key),
            "decoding {entropy:02x?} did not round trip"
        );
    }
}
