// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The 24-word encoding, on the BIP-39 English wordlist (SPEC §2.6).
//!
//! 256 bits of key plus an 8-bit SHA-256 checksum make 264 bits, which is
//! exactly 24 × 11-bit wordlist indices — the standard BIP-39 construction. It
//! is reused here purely because it is *proven transcribable by hand*: short
//! words, unique in their first four letters, no homophones.
//!
//! A Misty kit is **not** a wallet seed. It will not restore anything in a
//! cryptocurrency wallet, and a wallet seed will not restore a Misty vault. The
//! UI is required to say so (SPEC §2.6).
//!
//! # The wordlist
//!
//! `english.txt` is the canonical BIP-39 English wordlist, shipped verbatim.
//! Its SHA-256 is
//! `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`, which
//! `wordlist_is_the_canonical_bip39_list` asserts at test time — a substituted
//! wordlist would silently produce kits that decode to the wrong key.

use std::collections::HashMap;
use std::sync::LazyLock;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keys::{RecoveryKey, KEY_LEN};
use crate::{Error, Result};

/// The BIP-39 English wordlist, one word per line.
const WORDLIST: &str = include_str!("english.txt");

/// The list as a slice, built once. `wordlist()` is the public view.
static WORDS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| WORDLIST.lines().filter(|line| !line.is_empty()).collect());

/// Reverse lookup, built once: word to index. Without it, validating one kit
/// would be 24 linear scans of 2048 entries, and the repair search below would
/// be tens of thousands.
static INDEX: LazyLock<HashMap<&'static str, usize>> = LazyLock::new(|| {
    WORDS
        .iter()
        .enumerate()
        .map(|(index, word)| (*word, index))
        .collect()
});

/// Words in the list.
pub const WORDLIST_LEN: usize = 2048;

/// Words in a recovery kit.
pub const RECOVERY_WORD_COUNT: usize = 24;

/// Bits per word: `2048 = 2^11`.
const BITS_PER_WORD: usize = 11;

/// Iterates the wordlist in index order. Useful for UI autocompletion.
pub fn wordlist() -> impl Iterator<Item = &'static str> {
    WORDS.iter().copied()
}

fn word_at(index: usize) -> Option<&'static str> {
    WORDS.get(index).copied()
}

fn index_of(word: &str) -> Option<usize> {
    INDEX
        .get(word.trim().to_ascii_lowercase().as_str())
        .copied()
}

/// `RK || SHA-256(RK)[0]`: 33 bytes, 264 bits.
fn checksummed(key: &RecoveryKey) -> Zeroizing<[u8; KEY_LEN + 1]> {
    let mut out = Zeroizing::new([0u8; KEY_LEN + 1]);
    if let Some(slot) = out.get_mut(..KEY_LEN) {
        slot.copy_from_slice(key.expose_secret());
    }
    let digest = Sha256::digest(key.expose_secret());
    if let Some(slot) = out.get_mut(KEY_LEN) {
        *slot = digest.first().copied().unwrap_or(0);
    }
    out
}

/// Renders a recovery key as 24 words.
///
/// The words themselves are `&'static str` into the embedded wordlist, so no
/// secret bytes are copied onto the heap; the *order* is the secret, and the
/// caller is responsible for clearing whatever it renders them into.
#[must_use]
pub fn to_words(key: &RecoveryKey) -> Vec<&'static str> {
    let bytes = checksummed(key);
    let bit = |position: usize| -> u16 {
        bytes
            .get(position / 8)
            .map_or(0, |byte| u16::from((byte >> (7 - position % 8)) & 1))
    };
    (0..RECOVERY_WORD_COUNT)
        .map(|word_index| {
            let mut value = 0u16;
            for offset in 0..BITS_PER_WORD {
                value = (value << 1) | bit(word_index * BITS_PER_WORD + offset);
            }
            word_at(usize::from(value)).unwrap_or("abandon")
        })
        .collect()
}

/// Parses 24 words back into a recovery key.
///
/// Words may be in any case and may carry surrounding whitespace.
///
/// # Errors
///
/// [`Error::WrongWordCount`], [`Error::UnknownWord`] (carrying the position,
/// never the word), or [`Error::WordChecksumMismatch`].
pub fn from_words<S: AsRef<str>>(words: &[S]) -> Result<RecoveryKey> {
    if words.len() != RECOVERY_WORD_COUNT {
        return Err(Error::WrongWordCount {
            expected: RECOVERY_WORD_COUNT,
            found: words.len(),
        });
    }
    let mut indices = [0u16; RECOVERY_WORD_COUNT];
    for (position, word) in words.iter().enumerate() {
        let index = index_of(word.as_ref()).ok_or(Error::UnknownWord { index: position })?;
        if let Some(slot) = indices.get_mut(position) {
            *slot = u16::try_from(index).unwrap_or(0);
        }
    }
    from_indices(&indices)
}

fn from_indices(indices: &[u16; RECOVERY_WORD_COUNT]) -> Result<RecoveryKey> {
    let mut bytes = Zeroizing::new([0u8; KEY_LEN + 1]);
    for (word_index, value) in indices.iter().enumerate() {
        for offset in 0..BITS_PER_WORD {
            if (value >> (BITS_PER_WORD - 1 - offset)) & 1 == 1 {
                let position = word_index * BITS_PER_WORD + offset;
                if let Some(byte) = bytes.get_mut(position / 8) {
                    *byte |= 1 << (7 - position % 8);
                }
            }
        }
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    if let Some(slice) = bytes.get(..KEY_LEN) {
        key.copy_from_slice(slice);
    }
    let expected = Sha256::digest(*key).first().copied().unwrap_or(0);
    if bytes.get(KEY_LEN).copied() != Some(expected) {
        return Err(Error::WordChecksumMismatch);
    }
    Ok(RecoveryKey::from_bytes(*key))
}
/// One way to make a failing kit validate again: put `candidate` at `index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordRepair {
    /// Zero-based position of the word to replace.
    pub index: usize,
    /// The word to put there.
    pub candidate: &'static str,
}

/// Words within `max_distance` edits of `word`, nearest first.
///
/// Exposed for "did you mean" hints while the user is still typing.
#[must_use]
pub fn nearest_words(word: &str, max_distance: usize) -> Vec<&'static str> {
    let normalised = word.trim().to_ascii_lowercase();
    let mut scored: Vec<(usize, &'static str)> = wordlist()
        .filter_map(|candidate| {
            let distance = edit_distance(&normalised, candidate);
            (distance <= max_distance).then_some((distance, candidate))
        })
        .collect();
    scored.sort_unstable();
    scored.into_iter().map(|(_, word)| word).collect()
}

/// Suggests single-word corrections for a kit that does not validate.
///
/// Users transcribe these by hand, so "one word is wrong" is the overwhelmingly
/// common failure. For each position this tries every wordlist entry within one
/// edit of what was typed (two, if what was typed is not a word at all) and
/// returns those substitutions whose checksum validates.
///
/// The checksum is only 8 bits, so a brute force over all 24 × 2048
/// substitutions would return ~192 spurious "fixes". Restricting candidates to
/// near neighbours is what makes the answer useful: a typo is almost always one
/// edit away, and the expected number of false positives falls to well under
/// one.
///
/// Returns an empty vector if the kit is not 24 words, if it already validates,
/// or if no single substitution works — the user must then re-read the kit.
///
/// The suggestions are secret material: they are candidate parts of the
/// recovery key. Show them to the user, do not log them.
#[must_use]
pub fn suggest_word_repairs<S: AsRef<str>>(words: &[S]) -> Vec<WordRepair> {
    if words.len() != RECOVERY_WORD_COUNT {
        return Vec::new();
    }
    let typed: Vec<String> = words
        .iter()
        .map(|word| word.as_ref().trim().to_ascii_lowercase())
        .collect();
    let resolved: Vec<Option<usize>> = typed.iter().map(|word| index_of(word)).collect();

    let unknown: Vec<usize> = resolved
        .iter()
        .enumerate()
        .filter_map(|(position, index)| index.is_none().then_some(position))
        .collect();
    // Two or more words that are not words at all is not a typo; the user has
    // to re-read the kit rather than be offered 2048² guesses.
    if unknown.len() > 1 {
        return Vec::new();
    }

    let mut base = [0u16; RECOVERY_WORD_COUNT];
    for (slot, index) in base.iter_mut().zip(resolved.iter()) {
        *slot = u16::try_from(index.unwrap_or(0)).unwrap_or(0);
    }
    if unknown.is_empty() && from_indices(&base).is_ok() {
        return Vec::new();
    }

    let candidates_positions: Vec<usize> = if unknown.is_empty() {
        (0..RECOVERY_WORD_COUNT).collect()
    } else {
        unknown
    };

    let mut repairs = Vec::new();
    for position in candidates_positions {
        let Some(original) = typed.get(position) else {
            continue;
        };
        let known = resolved.get(position).copied().flatten().is_some();
        let max_distance = if known { 1 } else { 2 };
        for candidate in nearest_words(original, max_distance) {
            if candidate == original.as_str() {
                continue;
            }
            let Some(candidate_index) = index_of(candidate) else {
                continue;
            };
            let mut attempt = base;
            if let Some(slot) = attempt.get_mut(position) {
                *slot = u16::try_from(candidate_index).unwrap_or(0);
            }
            if from_indices(&attempt).is_ok() {
                repairs.push(WordRepair {
                    index: position,
                    candidate,
                });
            }
        }
    }
    repairs
}

/// Levenshtein distance, two-row dynamic programming.
///
/// Wordlist entries are 3..=8 ASCII characters, so this is a few dozen
/// operations per comparison.
fn edit_distance(left: &str, right: &str) -> usize {
    let right_len = right.chars().count();
    let mut previous: Vec<usize> = (0..=right_len).collect();
    let mut current = vec![0usize; right_len + 1];

    for (row, left_char) in left.chars().enumerate() {
        if let Some(slot) = current.first_mut() {
            *slot = row + 1;
        }
        for (column, right_char) in right.chars().enumerate() {
            let deletion = previous.get(column + 1).copied().unwrap_or(usize::MAX);
            let insertion = current.get(column).copied().unwrap_or(usize::MAX);
            let substitution = previous.get(column).copied().unwrap_or(usize::MAX);
            let cost = usize::from(left_char != right_char);
            let best = deletion
                .saturating_add(1)
                .min(insertion.saturating_add(1))
                .min(substitution.saturating_add(cost));
            if let Some(slot) = current.get_mut(column + 1) {
                *slot = best;
            }
        }
        core::mem::swap(&mut previous, &mut current);
    }
    previous.last().copied().unwrap_or(usize::MAX)
}
