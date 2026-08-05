// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CRC-32 (IEEE 802.3, the `zlib`/`gzip` polynomial), for the compact recovery
//! encoding.
//!
//! Hand-written, table-free, 20 lines, no dependency. A crate would be more
//! code to audit than the algorithm, and the `crc32fast` implementations reach
//! for SIMD via `unsafe`, which this crate forbids. 36 bytes at 8 iterations
//! per byte is 288 shifts; the cost is irrelevant next to Argon2id.
//!
//! This is an integrity check against transcription errors, not a MAC. The
//! authenticity of a recovery key comes from the AEAD in
//! [`unwrap_vault_key`](super::unwrap_vault_key), which will not open the blob
//! for the wrong key however good its CRC.

/// Reflected form of the IEEE CRC-32 polynomial `0x04C1_1DB7`.
const POLYNOMIAL: u32 = 0xEDB8_8320;

/// CRC-32 of `data`, `init = 0xFFFFFFFF`, reflected, final XOR `0xFFFFFFFF`.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = if crc & 1 == 0 { 0 } else { POLYNOMIAL };
            crc = (crc >> 1) ^ mask;
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Authoritative: the CRC-32 "check" value from the CRC catalogue — the
    /// checksum of the ASCII string `"123456789"` is `0xCBF43926` for
    /// `CRC-32/ISO-HDLC`, which is what `zlib`, `gzip` and PNG use.
    #[test]
    fn catalogue_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn known_small_inputs() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(&[0u8; 32]), 0x190A_55AD);
    }

    #[test]
    fn a_single_flipped_bit_changes_the_checksum() {
        let mut data = [0x5au8; 36];
        let before = crc32(&data);
        data[17] ^= 0x01;
        assert_ne!(crc32(&data), before);
    }
}
