// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `pad` / `unpad` (SPEC §2.4).
//!
//! ```text
//! pad(x) = LE32(x.len()) || x || 0x00 * k
//! ```
//!
//! where `k` is the least value making the total a multiple of
//! [`PAD_BLOCK`]. An empty payload occupies one full block; 252 bytes still fit
//! in one; 253 needs two.
//!
//! This blunts size-based fingerprinting: a hostile server sees the bucket, not
//! the length, so it cannot tell a `"GitHub"` item from a
//! `"login.corp.example.com"` one by size alone (threat model `A1`).

use zeroize::Zeroizing;

use crate::{Error, Result};

/// Payloads are padded up to a multiple of this many bytes.
pub const PAD_BLOCK: usize = 256;

/// Longest payload this crate will pad or return.
///
/// The length prefix is 32 bits, so the format allows far more; the limit is
/// here so a hostile length prefix cannot ask for a huge allocation, and so a
/// single item cannot be used to exhaust a client's memory. 16 MiB is far above
/// any real item — the largest object Misty stores in an envelope is a custom
/// icon.
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

const PREFIX_LEN: usize = 4;

/// Length of `pad(payload)` for a payload of `len` bytes.
fn padded_len(len: usize) -> usize {
    let total = len.saturating_add(PREFIX_LEN);
    // Round up to the next multiple of PAD_BLOCK.
    total
        .saturating_add(PAD_BLOCK - 1)
        .saturating_div(PAD_BLOCK)
        .saturating_mul(PAD_BLOCK)
}

/// Pads `payload`.
///
/// The result is zeroized on drop: it is the plaintext.
///
/// # Errors
///
/// [`Error::PayloadTooLarge`] above [`MAX_PAYLOAD_LEN`].
pub fn pad(payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(Error::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_LEN,
        });
    }
    let total = padded_len(payload.len());
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    // `payload.len()` fits in u32 because MAX_PAYLOAD_LEN does.
    let declared = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&declared.to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(total, 0);
    Ok(out)
}

/// Recovers the payload from a padded buffer.
///
/// Validates, rather than trusts, the length prefix. Every rejection below is
/// reachable from a decrypted-but-hostile buffer — an attacker who holds the
/// item key of one item, for instance — so none of them may panic.
///
/// # Errors
///
/// * [`Error::BadPadding`] if the buffer is not a positive multiple of
///   [`PAD_BLOCK`], if the padding is not the *minimal* amount for the declared
///   length, or if any padding byte is non-zero.
/// * [`Error::BadPaddingLength`] if the declared length does not fit in the
///   buffer.
/// * [`Error::PayloadTooLarge`] above [`MAX_PAYLOAD_LEN`].
pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    if padded.is_empty() || padded.len() % PAD_BLOCK != 0 {
        return Err(Error::BadPadding {
            detail: "padded length is not a positive multiple of 256",
        });
    }
    let prefix = padded.get(..PREFIX_LEN).ok_or(Error::BadPadding {
        detail: "padded buffer is shorter than its length prefix",
    })?;
    let mut length_bytes = [0u8; PREFIX_LEN];
    length_bytes.copy_from_slice(prefix);
    let declared = u32::from_le_bytes(length_bytes);

    let available = padded.len() - PREFIX_LEN;
    let declared_usize = usize::try_from(declared).unwrap_or(usize::MAX);
    if declared_usize > available {
        return Err(Error::BadPaddingLength {
            declared,
            available,
        });
    }
    if declared_usize > MAX_PAYLOAD_LEN {
        return Err(Error::PayloadTooLarge {
            len: declared_usize,
            max: MAX_PAYLOAD_LEN,
        });
    }
    // Reject non-minimal padding. The writer is required to use the least `k`,
    // so a larger buffer than necessary means the bytes did not come from this
    // format and their meaning is not defined.
    if padded_len(declared_usize) != padded.len() {
        return Err(Error::BadPadding {
            detail: "padding is not the minimal amount for the declared length",
        });
    }
    let (payload, filler) = padded
        .get(PREFIX_LEN..)
        .and_then(|rest| rest.split_at_checked(declared_usize))
        .ok_or(Error::BadPadding {
            detail: "declared length does not fit the buffer",
        })?;
    if filler.iter().any(|byte| *byte != 0) {
        return Err(Error::BadPadding {
            detail: "padding bytes are not zero",
        });
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries() {
        // 4-byte prefix, so 252 bytes exactly fill one block.
        assert_eq!(pad(&[]).unwrap().len(), 256);
        assert_eq!(pad(&[7u8; 251]).unwrap().len(), 256);
        assert_eq!(pad(&[7u8; 252]).unwrap().len(), 256);
        assert_eq!(pad(&[7u8; 253]).unwrap().len(), 512);
        assert_eq!(pad(&[7u8; 256]).unwrap().len(), 512);
        assert_eq!(pad(&[7u8; 508]).unwrap().len(), 512);
        assert_eq!(pad(&[7u8; 509]).unwrap().len(), 768);
    }

    #[test]
    fn round_trip_at_boundaries() {
        for len in [0, 1, 251, 252, 253, 255, 256, 507, 508, 509, 1024, 8192] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let padded = pad(&payload).unwrap();
            assert_eq!(unpad(&padded).unwrap(), payload.as_slice(), "len {len}");
        }
    }

    #[test]
    fn layout_is_le32_prefix_then_payload_then_zeros() {
        let padded = pad(b"hi").unwrap();
        assert_eq!(&padded[..4], &[0x02, 0x00, 0x00, 0x00]);
        assert_eq!(&padded[4..6], b"hi");
        assert!(padded[6..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rejects_bad_length_prefix() {
        let mut padded = pad(b"hi").unwrap().to_vec();
        padded[0] = 0xff;
        padded[1] = 0xff;
        assert!(matches!(
            unpad(&padded),
            Err(Error::BadPaddingLength {
                declared: 0xffff,
                available: 252
            })
        ));
    }

    #[test]
    fn rejects_non_minimal_padding() {
        let mut padded = pad(b"hi").unwrap().to_vec();
        padded.resize(512, 0);
        assert!(matches!(unpad(&padded), Err(Error::BadPadding { .. })));
    }

    #[test]
    fn rejects_non_zero_filler() {
        let mut padded = pad(b"hi").unwrap().to_vec();
        padded[200] = 1;
        assert!(matches!(unpad(&padded), Err(Error::BadPadding { .. })));
    }

    #[test]
    fn rejects_wrong_size_buffers() {
        assert!(matches!(unpad(&[]), Err(Error::BadPadding { .. })));
        assert!(matches!(unpad(&[0u8; 255]), Err(Error::BadPadding { .. })));
        assert!(matches!(unpad(&[0u8; 257]), Err(Error::BadPadding { .. })));
    }

    #[test]
    fn rejects_absurd_declared_length_that_would_still_be_in_range() {
        // Declared length inside the buffer but claiming the whole block.
        let mut padded = vec![0u8; 256];
        padded[..4].copy_from_slice(&252u32.to_le_bytes());
        assert!(unpad(&padded).is_ok());
        padded[..4].copy_from_slice(&253u32.to_le_bytes());
        assert!(matches!(
            unpad(&padded),
            Err(Error::BadPaddingLength {
                declared: 253,
                available: 252
            })
        ));
    }
}
