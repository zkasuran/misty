// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backup unit tests, including the frozen golden-byte vectors.
//!
//! In-module for the same reasons as the envelope's: they need the
//! explicit-salt-and-nonce seam, and they must run on every `cargo test`.

use hex_literal::hex;
use serde::{Deserialize, Serialize};

use super::*;

const SALT: [u8; 16] = hex!("5a5b5c5d5e5f60616263646566676869");
const NONCE: [u8; 24] = hex!("606162636465666768696a6b6c6d6e6f7071727374757677");
const PASSPHRASE: &[u8] = b"correct horse battery staple";

/// Deliberately weak costs, used only where the test is about the *format*.
///
/// 32 KiB / 1 / 1 keeps the debug-build suite fast. The production default is
/// [`DEFAULT_TIER`] (1 GiB, 4, 4) and is never weakened — see
/// `interactive_tier_round_trip` for a test that runs a real tier.
const FAST: KdfParams = KdfParams::new(32, 1, 1);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Export {
    items: Vec<String>,
    epoch: u32,
}

fn export() -> Export {
    Export {
        items: vec!["github".to_owned(), "aws".to_owned()],
        epoch: 3,
    }
}

/// FROZEN GOLDEN VECTOR — the 70-byte header, byte for byte.
///
/// Independent of the KDF and the compressor, so this vector holds across any
/// dependency bump.
#[test]
fn golden_backup_header_bytes() {
    let header = BackupHeader::new(KdfTier::Interactive.params(), SALT, NONCE);
    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), BACKUP_HEADER_LEN);
    assert_eq!(
        bytes,
        hex!(
            "4d4953545942414b" // magic "MISTYBAK"
            "01" // format_version
            "01" // kdf_id = Argon2id
            "00000100" // argon2_memory_kib = 65536, little-endian
            "03000000" // argon2_iterations = 3
            "04000000" // argon2_parallelism = 4
            "5a5b5c5d5e5f60616263646566676869" // salt
            "606162636465666768696a6b6c6d6e6f7071727374757677" // nonce
            "0000000000000000" // reserved
        )
    );
    assert_eq!(BackupHeader::parse(&bytes).unwrap(), header);
}

/// FROZEN GOLDEN VECTOR — a whole file, byte for byte.
///
/// Weak-but-explicit costs (32 KiB, 1, 1) so the suite stays fast; the costs are
/// in the header, so this exercises exactly the same code path a `Sensitive`
/// file does.
///
/// This vector pins one thing the others do not: `miniz_oxide`'s exact DEFLATE
/// output. A `miniz_oxide` bump that changes its encoder will break this test
/// and `frozen_deflate_output` together, which is the signal to re-freeze both
/// — old files still open, because inflating does not care how they were
/// deflated.
///
/// Cross-checked against an independent implementation: Argon2id via
/// `argon2-cffi` (the reference C implementation) and XChaCha20-Poly1305 via
/// libsodium, over the frozen DEFLATE bytes below. Every byte matched.
#[test]
fn golden_backup_file_bytes() {
    let file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"misty golden backup").unwrap();
    assert_eq!(
        file,
        hex!(
            "4d4953545942414b" // magic
            "01" // format_version
            "01" // kdf_id
            "20000000" // memory = 32 KiB
            "01000000" // iterations = 1
            "01000000" // parallelism = 1
            "5a5b5c5d5e5f60616263646566676869" // salt
            "606162636465666768696a6b6c6d6e6f7071727374757677" // nonce
            "0000000000000000" // reserved
            // XChaCha20Poly1305(Argon2id(passphrase, salt, 32/1/1),
            //                   nonce, deflate(payload), aad = header)
            "0eb967ef540f494e7ca9ddc2a3189149df1de16de673d7962516443766d356e3"
            "4c23b4e949"
        )
    );
    let opened = open_bytes(PASSPHRASE, &file).unwrap();
    assert_eq!(opened.as_slice(), b"misty golden backup");
}

/// FROZEN GOLDEN VECTOR — `miniz_oxide`'s DEFLATE output at level 6.
///
/// Broken out so that if a `miniz_oxide` bump changes the encoder, the failure
/// says "the compressor changed" rather than "the whole file format changed".
#[test]
fn frozen_deflate_output() {
    let compressed = miniz_oxide::deflate::compress_to_vec(b"misty golden backup", DEFLATE_LEVEL);
    assert_eq!(
        compressed,
        hex!("cbcd2c2ea95448cfcf4949cd53484a4cce2e2d0000")
    );
    assert_eq!(
        inflate(&compressed).unwrap().as_slice(),
        b"misty golden backup"
    );
}
#[test]
fn cbor_round_trip_at_the_interactive_tier() {
    // One test that runs a real tier end to end. `Interactive` (64 MiB) rather
    // than the `Sensitive` production default only so the debug-build suite
    // stays usable; the tier travels in the header either way.
    let file = seal(PASSPHRASE, KdfTier::Interactive, &export()).unwrap();
    let header = BackupHeader::parse(&file).unwrap();
    assert_eq!(header.params, KdfTier::Interactive.params());
    assert_eq!(header.params.tier(), Some(KdfTier::Interactive));
    let decoded: Export = open(PASSPHRASE, &file).unwrap();
    assert_eq!(decoded, export());
}

#[test]
fn the_production_default_is_the_sensitive_tier() {
    // Guards against someone "speeding up the tests" by weakening the default.
    assert_eq!(DEFAULT_TIER, KdfTier::Sensitive);
    assert_eq!(DEFAULT_TIER.params(), KdfParams::new(1_048_576, 4, 4));
}

#[test]
fn two_seals_of_the_same_payload_differ() {
    let a = seal_bytes(PASSPHRASE, KdfTier::Interactive, b"x").unwrap();
    let b = seal_bytes(PASSPHRASE, KdfTier::Interactive, b"x").unwrap();
    assert_ne!(a, b, "fresh salt and nonce per file");
    assert_ne!(
        BackupHeader::parse(&a).unwrap().salt,
        BackupHeader::parse(&b).unwrap().salt
    );
}

#[test]
fn a_wrong_passphrase_is_rejected() {
    let file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
    assert!(matches!(
        open_bytes(b"wrong passphrase", &file),
        Err(Error::BackupDecryptFailed)
    ));
}

#[test]
fn a_tampered_ciphertext_is_rejected() {
    let mut file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
    let last = file.len() - 1;
    file[last] ^= 0x01;
    assert!(matches!(
        open_bytes(PASSPHRASE, &file),
        Err(Error::BackupDecryptFailed)
    ));
}

#[test]
fn a_tampered_header_is_rejected_by_the_aad() {
    // Swap the salt for another valid-looking one: the header parses, the KDF
    // runs, and the AAD check fails.
    let mut file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
    file[22] ^= 0xff;
    assert!(matches!(
        open_bytes(PASSPHRASE, &file),
        Err(Error::BackupDecryptFailed)
    ));
}

#[test]
fn wrong_magic_is_rejected() {
    let mut file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
    file[0] = b'X';
    assert!(matches!(
        BackupHeader::parse(&file),
        Err(Error::BadBackupMagic)
    ));
    assert!(matches!(
        open_bytes(PASSPHRASE, &file),
        Err(Error::BadBackupMagic)
    ));
}

#[test]
fn a_future_format_version_is_rejected() {
    let mut file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
    file[8] = 2;
    assert!(matches!(
        BackupHeader::parse(&file),
        Err(Error::UnsupportedFormatVersion {
            context: "backup",
            found: 2,
            supported: 1
        })
    ));
}

#[test]
fn an_unknown_kdf_id_is_rejected() {
    let mut file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
    file[9] = 9;
    assert!(matches!(
        BackupHeader::parse(&file),
        Err(Error::UnknownKdfId { found: 9 })
    ));
}

#[test]
fn non_zero_reserved_bytes_are_rejected() {
    for offset in 62..70 {
        let mut file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
        file[offset] = 1;
        assert!(
            matches!(
                BackupHeader::parse(&file),
                Err(Error::ReservedNotZero {
                    context: "backup header"
                })
            ),
            "offset {offset}"
        );
    }
}
#[test]
fn absurd_kdf_parameters_are_rejected_before_any_allocation() {
    // The denial-of-service case: a header claiming 64 GiB of Argon2 memory.
    // This must be refused by the parser, not passed to `argon2`.
    let mut file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
    file[10..14].copy_from_slice(&(64u32 * 1024 * 1024).to_le_bytes());
    let error = BackupHeader::parse(&file).unwrap_err();
    assert!(
        matches!(
            error,
            Error::KdfParamsRejected {
                memory_kib: 67_108_864,
                ..
            }
        ),
        "got {error:?}"
    );
    assert!(matches!(
        open_bytes(PASSPHRASE, &file),
        Err(Error::KdfParamsRejected { .. })
    ));

    // ...and the same for the other two costs.
    let mut file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
    file[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        BackupHeader::parse(&file),
        Err(Error::KdfParamsRejected { .. })
    ));
    let mut file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
    file[18..22].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        BackupHeader::parse(&file),
        Err(Error::KdfParamsRejected { .. })
    ));
}

#[test]
fn truncated_files_are_rejected() {
    let file = seal_bytes_with(PASSPHRASE, FAST, SALT, NONCE, b"payload").unwrap();
    for len in [0, 1, 8, 69] {
        assert!(
            matches!(
                BackupHeader::parse(&file[..len]),
                Err(Error::Truncated {
                    context: "backup header",
                    needed: 70,
                    ..
                })
            ),
            "len {len}"
        );
    }
    // Header present, body too short to hold a tag.
    for len in [70, 71, 85] {
        assert!(
            matches!(
                open_bytes(PASSPHRASE, &file[..len]),
                Err(Error::Truncated {
                    context: "backup body",
                    ..
                })
            ),
            "len {len}"
        );
    }
}

#[test]
fn a_body_that_is_not_deflate_is_rejected() {
    // Authentic, decryptable, and not a DEFLATE stream: what a corrupted
    // compressor or a future format would produce.
    let header = BackupHeader::new(FAST, SALT, NONCE).to_bytes();
    let key = FAST.derive_key(PASSPHRASE, &SALT).unwrap();
    let body =
        crate::aead::encrypt(key.expose_secret(), &NONCE, &header, b"\xff\xff\xff\xff").unwrap();
    let mut file = header.to_vec();
    file.extend_from_slice(&body);
    assert!(matches!(
        open_bytes(PASSPHRASE, &file),
        Err(Error::Inflate { .. })
    ));
}

#[test]
fn a_compression_bomb_is_rejected() {
    // 1 KiB of zeros deflates to a handful of bytes and inflates back to 1 KiB;
    // with a 64-byte limit that is a bomb. The real limit is
    // `MAX_DECOMPRESSED_LEN`; testing it at 64 MiB would cost seconds for no
    // extra coverage.
    let compressed = miniz_oxide::deflate::compress_to_vec(&[0u8; 1024], DEFLATE_LEVEL);
    assert!(compressed.len() < 64);
    assert!(matches!(
        inflate_with_limit(&compressed, 64),
        Err(Error::InflateLimit { max: 64 })
    ));
    assert_eq!(MAX_DECOMPRESSED_LEN, 64 * 1024 * 1024);
    assert_eq!(inflate(&compressed).unwrap().len(), 1024);
}

#[test]
fn the_extension_matches_the_spec() {
    assert_eq!(BACKUP_EXTENSION, "mistybak");
}
