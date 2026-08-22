// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The one error that crosses the boundary (SPEC §11.3.1).
 *
 * The core rejects with a plain object `{ code, message, retryable }` — not an `Error`, so
 * a bare `catch` gives you something with no stack and no `instanceof`. {@link MistyError}
 * wraps it once, at the client edge, so the rest of the app only ever handles a real Error.
 */

/**
 * The frozen failure vocabulary, mirroring `ErrorCode::as_str` in
 * `crates/misty/src/error.rs`. `UPPER_SNAKE`, and the only thing that is stable — never
 * the message, which is English, redacted, and explicitly allowed to change (§11.3.2).
 */
export const ERROR_CODES = [
	// lifecycle / internal
	'VAULT_LOCKED',
	'UNSUPPORTED_ON_TARGET',
	'INTERNAL',
	// vault lookup / conflict
	'NOT_FOUND',
	'ALREADY_EXISTS',
	'DUPLICATE_ACCOUNT',
	'AMBIGUOUS_ACCOUNT',
	// input validation
	'INVALID_FIELD',
	'OTP_INVALID_SECRET',
	'OTP_INVALID_PARAM',
	'URI_MALFORMED',
	// otp runtime / ceilings
	'OTP_GENERATION_FAILED',
	'RESOURCE_EXHAUSTED',
	// merge / clock
	'MERGE_FAILED',
	// crypto and integrity
	'DECRYPT_FAILED',
	'SIGNATURE_INVALID',
	'UNTRUSTED_SIGNER',
	'DEVICE_REVOKED',
	'CORRUPT_DATA',
	'KDF_REJECTED',
	'VERSION_UNSUPPORTED',
	'EPOCH_MISMATCH',
	// recovery / enrollment input
	'RECOVERY_INPUT_INVALID',
	'CONFIRMATION_CODE_MISMATCH',
	'ENROLL_ID_MISMATCH',
	// sync / network / server
	'NETWORK',
	'TLS_ERROR',
	'SERVER_ERROR',
	'AUTH_FAILED',
	'QUOTA_EXHAUSTED',
	'PROTOCOL_VIOLATION',
	'TIME_UNTRUSTED',
	'CONFIG_INVALID',
	'STORAGE_FAILED',
	// import / export
	'IMPORT_UNRECOGNIZED',
	'IMPORT_MALFORMED',
	'IMPORT_PASSPHRASE_REQUIRED',
	'IMPORT_ENCRYPTED_UNSUPPORTED',
	'CONFIRMATION_REQUIRED'
] as const;

/** A code this build knows about. */
export type KnownErrorCode = (typeof ERROR_CODES)[number];

/**
 * A code from the core, which may be one this build has never heard of.
 *
 * `ErrorCode` is `#[non_exhaustive]` and new codes may be added without a format-version
 * bump, so §11.3.2 requires every consumer to carry a default arm that treats an unknown
 * code as a non-retryable failure. Typing this as a plain widened string is what makes
 * TypeScript refuse to let a `switch` pretend the list is closed: a newer core is a newer
 * peer, not corruption.
 */
export type ErrorCode = KnownErrorCode | (string & {});

const KNOWN = new Set<string>(ERROR_CODES);

/** Whether `code` is one this build recognises. */
export function isKnownErrorCode(code: string): code is KnownErrorCode {
	return KNOWN.has(code);
}

/** The shape the core rejects with. */
interface RawFacadeError {
	code: string;
	message: string;
	retryable: boolean;
}

function isRawFacadeError(value: unknown): value is RawFacadeError {
	if (typeof value !== 'object' || value === null) return false;
	const candidate = value as Record<string, unknown>;
	return (
		typeof candidate.code === 'string' &&
		typeof candidate.message === 'string' &&
		typeof candidate.retryable === 'boolean'
	);
}

/** A failure from the core, as a real `Error`. */
export class MistyError extends Error {
	/** The stable, machine-readable code. Branch on this and nothing else (§11.3.2). */
	readonly code: ErrorCode;
	/**
	 * Whether a bare retry of the identical call may succeed. A frozen function of the
	 * code (§11.3.3) — exactly `NETWORK` and `SERVER_ERROR` — so it is taken from the core
	 * rather than recomputed here.
	 */
	readonly retryable: boolean;

	constructor(code: ErrorCode, message: string, retryable: boolean) {
		// The message goes in `Error.message` for a stack trace and a console, but nothing
		// may parse it. The code is the contract.
		super(`${code}: ${message}`);
		this.name = 'MistyError';
		this.code = code;
		this.retryable = retryable;
	}

	/** True when the vault is locked, which is a state rather than a fault. */
	get isLocked(): boolean {
		return this.code === 'VAULT_LOCKED';
	}

	/**
	 * Normalise whatever a rejected core call threw.
	 *
	 * Anything that is not the documented triple is a bug in the binding or a genuine JS
	 * exception, and is surfaced as `INTERNAL` rather than being reshaped into a plausible
	 * domain error — a wrong code is worse than an honest unknown, because the UI would
	 * branch on it.
	 */
	static from(thrown: unknown): MistyError {
		if (thrown instanceof MistyError) return thrown;
		if (isRawFacadeError(thrown)) {
			return new MistyError(thrown.code, thrown.message, thrown.retryable);
		}
		if (thrown instanceof Error) {
			return new MistyError('INTERNAL', thrown.message, false);
		}
		return new MistyError('INTERNAL', String(thrown), false);
	}
}

/**
 * Human wording for a code, for the one place a user sees a failure.
 *
 * This lives in the UI, not in the core, because §11.3.4 makes the core's `message`
 * non-normative and forbids parsing it — which means the UI cannot rely on it and must own
 * its own copy. Anything not listed falls back to the code itself: unhelpful, but honest,
 * and it makes a missing entry visible instead of silently generic.
 */
const WORDING: Partial<Record<KnownErrorCode, string>> = {
	VAULT_LOCKED: 'The vault is locked.',
	NOT_FOUND: 'That item no longer exists.',
	DUPLICATE_ACCOUNT: 'That account is already stored with the same secret.',
	AMBIGUOUS_ACCOUNT: 'That issuer and account already exist with a different secret. Add a nickname to tell them apart.',
	INVALID_FIELD: 'One of those fields is not valid.',
	OTP_INVALID_SECRET: 'That secret is empty or not valid base32.',
	OTP_INVALID_PARAM: 'The digits or period are out of range.',
	URI_MALFORMED: 'That otpauth link could not be read.',
	NETWORK: 'Could not reach the sync server.',
	SERVER_ERROR: 'The sync server had a problem.',
	TLS_ERROR: 'The connection was refused because the server certificate did not match.',
	QUOTA_EXHAUSTED: 'The vault is full. Delete some items to make room.',
	DEVICE_REVOKED: 'This device is no longer in the vault roster.',
	DECRYPT_FAILED: 'That could not be decrypted.',
	RESOURCE_EXHAUSTED: 'A counter reached its limit.',
	INTERNAL: 'Something went wrong inside the vault.'
};

/** A sentence for the user, plus whether offering a Retry makes sense. */
export function describe(error: MistyError): { text: string; canRetry: boolean } {
	const known = isKnownErrorCode(error.code) ? WORDING[error.code] : undefined;
	return {
		text: known ?? `Unexpected failure (${error.code}).`,
		canRetry: error.retryable
	};
}
