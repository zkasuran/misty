// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The compact encoding: Crockford Base32 of `RK || CRC32(RK)`, grouped in 8s
//! (SPEC §2.6).
//!
//! Crockford's alphabet omits `I`, `L`, `O` and `U`: the first three because
//! they are confusable with `1` and `0` when read off paper, the last so the
//! encoding cannot spell unfortunate words. Decoding accepts either case and
//! folds `I`/`L` to `1` and `O` to `0`, because that is precisely the mistake a
//! human transcriber makes.
//!
//! Hand-written rather than taken from `data-encoding` because the folding rules
//! and the trailing-bit check are the interesting part, and because a decoder
//! that silently accepts a malformed string is worse than no decoder.
//!
//! ```text
//! 32 bytes RK || 4 bytes CRC32(RK), big-endian   = 288 bits
//! 288 bits / 5                                   = 58 characters (290 bits)
//! the last character's low 2 bits are padding and MUST be zero
//! 58 characters in groups of 8                   = 7 groups of 8 plus 2
//! ```

use zeroize::Zeroizing;

use super::crc32::crc32;
use crate::keys::{RecoveryKey, KEY_LEN};
use crate::{Error, Result};

/// Crockford Base32 symbols, in value order.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters per group in the printed form.
pub const COMPACT_GROUP_LEN: usize = 8;

/// Significant characters in a compact code, before grouping.
pub const COMPACT_CHAR_COUNT: usize = 58;

/// Bytes encoded: the key plus its CRC32.
const PAYLOAD_LEN: usize = KEY_LEN + 4;

fn symbol(value: u8) -> char {
    ALPHABET
        .get(usize::from(value))
        .map_or('0', |byte| char::from(*byte))
}

/// Value of a Crockford character, applying the human-confusion foldings.
fn value_of(character: char) -> Option<u8> {
    let upper = character.to_ascii_uppercase();
    match upper {
        'O' => Some(0),
        'I' | 'L' => Some(1),
        _ => ALPHABET
            .iter()
            .position(|symbol| *symbol == u8::try_from(upper).unwrap_or(0xff))
            .and_then(|index| u8::try_from(index).ok()),
    }
}

/// `RK || CRC32(RK)`, the bytes the compact code encodes.
fn payload(key: &RecoveryKey) -> Zeroizing<[u8; PAYLOAD_LEN]> {
    let mut out = Zeroizing::new([0u8; PAYLOAD_LEN]);
    let checksum = crc32(key.expose_secret()).to_be_bytes();
    if let Some(slot) = out.get_mut(..KEY_LEN) {
        slot.copy_from_slice(key.expose_secret());
    }
    if let Some(slot) = out.get_mut(KEY_LEN..) {
        slot.copy_from_slice(&checksum);
    }
    out
}

/// Encodes a recovery key, grouped in 8s with `-` separators.
#[must_use]
pub fn to_compact(key: &RecoveryKey) -> String {
    let bytes = payload(key);
    let bit = |position: usize| -> u8 {
        bytes
            .get(position / 8)
            .map_or(0, |byte| (byte >> (7 - position % 8)) & 1)
    };

    let mut out =
        String::with_capacity(COMPACT_CHAR_COUNT + COMPACT_CHAR_COUNT / COMPACT_GROUP_LEN);
    for index in 0..COMPACT_CHAR_COUNT {
        if index > 0 && index % COMPACT_GROUP_LEN == 0 {
            out.push('-');
        }
        let mut value = 0u8;
        for offset in 0..5 {
            let position = index * 5 + offset;
            let next = if position < PAYLOAD_LEN * 8 {
                bit(position)
            } else {
                0
            };
            value = (value << 1) | next;
        }
        out.push(symbol(value));
    }
    out
}

/// Decodes a compact code, tolerating separators, whitespace and case.
///
/// # Errors
///
/// [`Error::BadCompactLength`], [`Error::BadCompactChar`],
/// [`Error::BadCompactPadding`], [`Error::Crc32Mismatch`].
pub fn from_compact(text: &str) -> Result<RecoveryKey> {
    let significant: Vec<char> = text
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '-' && *character != '_')
        .collect();
    if significant.len() != COMPACT_CHAR_COUNT {
        return Err(Error::BadCompactLength {
            expected: COMPACT_CHAR_COUNT,
            found: significant.len(),
        });
    }

    let mut buffer = 0u64;
    let mut pending_bits = 0u32;
    let mut bytes = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    for (index, character) in significant.iter().enumerate() {
        let value = value_of(*character).ok_or(Error::BadCompactChar { index })?;
        buffer = (buffer << 5) | u64::from(value);
        pending_bits += 5;
        while pending_bits >= 8 {
            pending_bits -= 8;
            let byte = u8::try_from((buffer >> pending_bits) & 0xff).unwrap_or(0);
            bytes.push(byte);
        }
    }
    // 58 * 5 = 290 bits for 288 bits of payload: the last two bits are padding
    // and must be zero, or the string did not come from `to_compact`.
    if buffer & ((1u64 << pending_bits) - 1) != 0 {
        return Err(Error::BadCompactPadding);
    }
    if bytes.len() != PAYLOAD_LEN {
        return Err(Error::BadCompactLength {
            expected: COMPACT_CHAR_COUNT,
            found: significant.len(),
        });
    }

    let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
    let mut checksum = [0u8; 4];
    if let Some(slice) = bytes.get(..KEY_LEN) {
        key_bytes.copy_from_slice(slice);
    }
    if let Some(slice) = bytes.get(KEY_LEN..) {
        checksum.copy_from_slice(slice);
    }
    if crc32(&*key_bytes).to_be_bytes() != checksum {
        return Err(Error::Crc32Mismatch);
    }
    Ok(RecoveryKey::from_bytes(*key_bytes))
}
