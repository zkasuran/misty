// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire encoding for SPEC §6.1.1, and the one decision worth reading before you
//! change anything here.
//!
//! §6.1.1 is normative: ids, nonces, signatures and public keys travel as **lowercase
//! hex**; envelopes and sealed blobs as **standard base64 with padding**. This module
//! emits and accepts exactly that, in one alphabet per field, with **no fallbacks**.
//!
//! # Why there are no fallbacks
//!
//! An earlier version of this module was liberal on decode — hex or either base64
//! alphabet — while `misty-server` emitted base64 for four fields. Both sides passed
//! their own suites. Neither interoperated, and the tolerance is what hid it.
//!
//! Worse, tolerance here does not degrade into a loud failure. Every hex character is
//! also a base64 character, so the server's 64-character hex nonce is *also* well-formed
//! base64 of 48 bytes. A base64-first decoder does not error on it — it returns 48 bytes
//! where the answer is 32, the client signs bytes the server never issued, and the
//! symptom is a `401` that reads like a signature bug. Going the other way is no better:
//! standard base64 of 129 zero bytes is 172 `A` characters, which is valid hex for 86
//! bytes. `a_lenient_nonce_decoder_would_not_error_it_would_be_wrong` pins both.
//!
//! Fixed-width fields would have survived a fallback, because at 16, 32 and 64 bytes
//! hex, padded base64 and unpadded base64url are three different string lengths. As
//! §6.1.1 puts it, that is a reason the mistake was survivable, not a reason to make it.
//! `the_widths_this_protocol_uses_never_collide` keeps that fact on record so nobody
//! proposes reintroducing a fallback "just for the fixed widths".
//!
//! So: if an interop failure ever points at this module, the fix is to correct the
//! encoding on one side, never to add a second accepted alphabet. The tests here refuse
//! the retired forms specifically so that shortcut fails loudly.
//!
//! Uppercase hex is refused as well, matching the server. §6.1.1 says lowercase, and
//! folding case would give every field two spellings for no benefit.
//!
//! Base64url is gone entirely. It existed only because standard base64's `+` arrives as
//! a space under query-string decoding, so `/v1/time?nonce=` needed a query-safe
//! alphabet — which left the protocol carrying three. Hex is safe in a body and in a
//! query string, so there are now two: hex for short fields, standard base64 for blobs.

use base64::Engine as _;

/// RFC 4648 standard alphabet, padded. §6.1.1's encoding for blobs.
pub const STANDARD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Decodes a fixed-width field from lowercase hex, per SPEC §6.1.1.
///
/// Hex only. No base64 fallback, deliberately: a decoder that accepts a second
/// alphabet is how a peer's encoding drift turns into silently wrong bytes instead of
/// a loud error. The length check happens first, so a hostile 4 MB "signature" is
/// rejected by a comparison rather than by a decode.
///
/// Uppercase hex is rejected too. §6.1.1 says lowercase, and folding case here would
/// reintroduce two spellings of the same field for no benefit.
#[must_use]
pub fn fixed_from_wire<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(text.as_bytes(), &mut out).ok()?;
    Some(out)
}

/// Decodes a variable-width blob: standard base64 with padding, per §6.1.1.
///
/// Standard only. Blobs are envelopes and sealed payloads, which travel in JSON
/// bodies and never in a query string, so there is no reason to accept a second
/// alphabet and every reason not to.
#[must_use]
pub fn blob_from_wire(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text.as_bytes()).ok()
}

/// Decodes the `/v1/auth/challenge` nonce: lowercase hex, variable width.
///
/// This function used to accept base64 and it is worth recording why it does not any
/// more, because the failure mode was invisible rather than loud.
///
/// A variable-width binary field cannot be encoding-agnostic. Every hex character is
/// also a base64 character, so hex of `N` bytes — `2N` characters, a multiple of four
/// for every even `N`, including the 32 both sides use — is *also* well-formed base64
/// of `3N/2` bytes. Trying hex first fails the other way: standard base64 of 129 zero
/// bytes is 172 `A` characters, and `A` is a hex digit, so it reads as 86 bytes. No
/// ordering gets both right.
///
/// Concretely, with the server now emitting §6.1.1's hex, a base64-first decoder does
/// not error on a 64-character hex nonce — it returns 48 bytes where the correct answer
/// is 32. The client would then sign bytes the server never issued while echoing the
/// right string back, and the failure would arrive as a `401` that looks like a
/// signature bug. An honest `400` from a strict decoder is worth a great deal more than
/// tolerance here.
#[must_use]
pub fn challenge_nonce_from_wire(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 {
        return None;
    }
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(text).ok()
}

/// Encodes a blob field: standard base64 with padding, per §6.1.1.
#[must_use]
pub fn to_standard(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Encodes for a field §6.1.1 puts in lowercase hex: ids, nonces, signatures, and
/// public keys.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_widths_this_protocol_uses_never_collide() {
        // For N in {16, 32, 64} the hex length and both base64 lengths are three
        // different numbers. This is why the pre-ruling tolerance was survivable for
        // fixed-width fields — and, as §6.1.1 puts it, a reason the mistake was
        // survivable rather than a reason to make it. Kept as a regression guard in
        // case anyone proposes reintroducing a fallback "just for fixed widths".
        for n in [16usize, 32, 64] {
            let bytes = vec![0xab; n];
            let hex_len = to_hex(&bytes).len();
            let standard_len = to_standard(&bytes).len();
            let url_len = n.div_ceil(3) * 4 - (3 - n % 3) % 3; // base64url, unpadded
            assert_eq!(hex_len, n * 2);
            assert_ne!(hex_len, standard_len, "n = {n}");
            assert_ne!(hex_len, url_len, "n = {n}");
        }
    }

    #[test]
    fn a_fixed_field_accepts_hex_and_only_hex() {
        let bytes = [0x9au8; 32];
        assert_eq!(fixed_from_wire::<32>(&to_hex(&bytes)), Some(bytes));
        // The retired forms are now refused rather than tolerated. If an interop
        // failure ever tempts someone to add a fallback here, this fails.
        assert_eq!(fixed_from_wire::<32>(&to_standard(&bytes)), None);
        assert_eq!(
            fixed_from_wire::<32>(&STANDARD.encode(bytes).replace('+', "-").replace('/', "_")),
            None
        );
    }

    #[test]
    fn a_fixed_field_refuses_the_wrong_width() {
        let bytes = [1u8; 32];
        assert_eq!(fixed_from_wire::<64>(&to_hex(&bytes)), None);
        assert_eq!(fixed_from_wire::<16>(&to_hex(&bytes)), None);
        assert_eq!(fixed_from_wire::<32>(""), None);
        assert_eq!(fixed_from_wire::<32>("!!!!"), None);
        // Bounded before decoding: a huge field costs a comparison.
        assert_eq!(fixed_from_wire::<32>(&"a".repeat(4 * 1024 * 1024)), None);
    }

    #[test]
    fn the_challenge_nonce_is_hex_and_base64_is_refused() {
        assert_eq!(
            challenge_nonce_from_wire(&to_hex(&[0xabu8; 32])),
            Some(vec![0xab; 32])
        );
        assert_eq!(challenge_nonce_from_wire(""), None);
        assert_eq!(challenge_nonce_from_wire("!!!"), None);
        assert_eq!(challenge_nonce_from_wire("abc"), None); // odd length
    }

    #[test]
    fn a_lenient_nonce_decoder_would_not_error_it_would_be_wrong() {
        // This is the whole reason this function is strict, demonstrated rather than
        // argued. Both readings of each string are well formed, so a decoder that
        // tries two alphabets does not fail on the wrong one — it succeeds, with the
        // wrong bytes, and the damage surfaces later as a signature that does not
        // verify.
        let hex_nonce = to_hex(&[0xabu8; 32]);
        assert_eq!(hex_nonce.len(), 64);
        assert_eq!(hex::decode(&hex_nonce).map(|bytes| bytes.len()), Ok(32));
        assert_eq!(
            STANDARD
                .decode(hex_nonce.as_bytes())
                .map(|bytes| bytes.len()),
            Ok(48),
            "a base64-first decoder reads the server's hex nonce as 48 bytes"
        );

        let base64_nonce = to_standard(&[0u8; 129]);
        assert!(base64_nonce.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(hex::decode(&base64_nonce).map(|bytes| bytes.len()), Ok(86));
    }

    #[test]
    fn uppercase_hex_is_refused_on_every_field() {
        // §6.1.1 says lowercase, and `misty-server` refuses uppercase too. Folding
        // case would reintroduce two spellings of the same field for no benefit.
        let bytes = [0xabu8; 32];
        assert_eq!(fixed_from_wire::<32>(&to_hex(&bytes).to_uppercase()), None);
        assert_eq!(
            challenge_nonce_from_wire(&to_hex(&bytes).to_uppercase()),
            None
        );
    }

    #[test]
    fn a_blob_is_standard_base64_only() {
        let bytes = vec![0x5au8; 300];
        assert_eq!(blob_from_wire(&to_standard(&bytes)), Some(bytes.clone()));
        // base64url of 300 bytes differs from standard wherever a `+` or `/` occurs.
        let url = STANDARD
            .encode(&bytes)
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_owned();
        if url != to_standard(&bytes) {
            assert_eq!(blob_from_wire(&url), None);
        }
    }
}
