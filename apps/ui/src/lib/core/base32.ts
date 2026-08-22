// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * RFC 4648 base32 decoding, for turning what a user types into the raw bytes the facade
 * wants.
 *
 * ## Why this exists here, and why that is uncomfortable
 *
 * `NewItemInput.secret` is `Vec<u8>` — raw bytes. Issuers hand out base32, and a user pastes
 * base32, so something has to decode it. The facade exposes no decoder and no
 * `addFromUri`, even though `misty-otp` contains both a strict base32 implementation and an
 * `otpauth://` parser, quarantined behind the facade like everything else (SPEC §11.7).
 *
 * So this is duplicated logic, which is exactly what §11.8.1 warns about — and the warning
 * applies with less force here than it looks, for a specific reason worth stating rather
 * than assuming: base32 is a **fixed encoding**, not a policy. RFC 4648's alphabet has not
 * changed since 2006 and will not. What this deliberately does *not* do is decide anything:
 * it does not check the secret's length, its entropy, or its suitability, because those are
 * §7 policy and belong to the core. Decode here, validate there — the core still rejects a
 * bad secret with `OTP_INVALID_SECRET`, and this function's only job is to stop being an
 * obstacle to that.
 *
 * The right shape is still a facade call that takes the user's string, or an `otpauth://`
 * URI, so the core owns parsing end to end. That is a facade decision, not one to make from
 * inside a UI, and it is recorded in this app's README as the gap it is.
 */

/** The RFC 4648 base32 alphabet, without padding. */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Why a string was not usable base32. */
export type Base32Failure =
	| { kind: 'empty' }
	| { kind: 'bad-character'; character: string }
	| { kind: 'bad-length' };

export type Base32Result =
	| { ok: true; bytes: Uint8Array }
	| { ok: false; failure: Base32Failure };

/** Human wording for a decode failure. */
export function describeBase32Failure(failure: Base32Failure): string {
	switch (failure.kind) {
		case 'empty':
			return 'Enter the secret key from your provider.';
		case 'bad-character':
			return `“${failure.character}” is not a base32 character. Secrets use A–Z and 2–7.`;
		case 'bad-length':
			return 'That secret is the wrong length — it looks like some characters are missing.';
	}
}

/**
 * Decode base32 into bytes.
 *
 * Tolerant of the things people actually paste and nothing more: lower case, the spaces
 * issuers insert every four characters, and trailing `=` padding. Anything else is an error
 * rather than a silent skip, because quietly dropping a character produces a different key
 * and then a wrong code — a failure that surfaces as "the app is broken", days later, with no
 * way to trace it back.
 */
export function decodeBase32(input: string): Base32Result {
	const cleaned = input.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
	if (cleaned.length === 0) return { ok: false, failure: { kind: 'empty' } };

	let accumulator = 0;
	let bits = 0;
	const bytes: number[] = [];

	for (const character of cleaned) {
		const value = ALPHABET.indexOf(character);
		if (value === -1) return { ok: false, failure: { kind: 'bad-character', character } };
		accumulator = (accumulator << 5) | value;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			bytes.push((accumulator >> bits) & 0xff);
		}
	}

	// Left-over bits must be zero padding. Anything else means the string was truncated
	// mid-character, which would otherwise decode to a plausible-looking wrong key.
	if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) {
		return { ok: false, failure: { kind: 'bad-length' } };
	}
	if (bytes.length === 0) return { ok: false, failure: { kind: 'bad-length' } };

	return { ok: true, bytes: new Uint8Array(bytes) };
}
