// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The DTO layer (SPEC §11.2), as TypeScript.
 *
 * A hand-written mirror of `crates/misty/src/dto.rs`. `wasm-bindgen` types every method as
 * `Promise<any>` because the DTOs cross as serde-lowered plain objects rather than as
 * generated handle classes (§11.7.2), so the types have to be declared somewhere; here is
 * the one place, and {@link ./client.ts} is the only thing allowed to assert them.
 *
 * Field names are `snake_case` because serde is not configured to rename them, and the
 * values are byte-identical to what UniFFI hands Kotlin and Swift — only the naming
 * convention differs, which is each toolchain's idiom rather than a difference in the data.
 *
 * Two things to be careful about, both verified against the core by
 * `crates/misty-ffi/tests/web.rs` rather than assumed:
 *
 *  - Enum variants cross as their Rust names verbatim (`"Totp"`, `"Sha1"`), except where
 *    `dto.rs` carries a `serde(rename_all = …)`. The two that do are noted below.
 *  - Absent optionals cross as `null`, not `undefined` (see `to_js` in
 *    `crates/misty-ffi/src/web.rs` for why), so these are `T | null` and not `T?`.
 */

/** Mirrors `dto::OtpKind`. The *true* kind the user chose, never the `Blizzard`→`Totp` wire alias. */
export type OtpKind = 'Totp' | 'Hotp' | 'Steam' | 'Motp' | 'Blizzard' | 'Yandex';

/** Mirrors `dto::HashAlg`. */
export type HashAlg = 'Sha1' | 'Sha256' | 'Sha512';

/**
 * Mirrors `dto::TombstoneReason`, which carries `serde(rename_all = "lowercase")`.
 *
 * Note `"trashexpired"` and not `"trash_expired"`: serde's `lowercase` lowercases the whole
 * identifier without inserting a separator. Exactly the kind of detail that is invisible
 * until a comparison silently never matches.
 */
export type TombstoneReason = 'user' | 'trashexpired';

/** Mirrors `dto::SortKey`. */
export type SortKey = 'Manual' | 'Issuer' | 'LastUsed' | 'MostUsed' | 'Created';

/** Mirrors `dto::ClearableField` — the nullable fields an edit may reset to absent. */
export type ClearableField = 'Nickname' | 'Note' | 'Color' | 'ManualOrder' | 'Pin';

/** Mirrors `facade::LifecycleEvent` (SPEC §11.5.5). The shell reports; the facade decides. */
export type LifecycleEvent = 'Backgrounded' | 'ScreenLocked' | 'WillSleep' | 'UserActivity';

/**
 * Mirrors `dto::IconRef`, which carries `serde(rename_all = "snake_case")` on the variants
 * and is externally tagged — so a bundled icon arrives as `{ bundled: { slug } }`.
 */
export type IconRef =
	| { bundled: { slug: string } }
	| { custom: { blob_id: string } }
	| { initials: { color: number } };

/**
 * Mirrors `dto::Conflict`. Externally tagged with no rename, so the keys are the Rust
 * variant names.
 *
 * A conflict is **not** an error: it rides inside an owned DTO and is never thrown
 * (§11.3.1). `Unknown` exists because the core's `Conflict` is `#[non_exhaustive]` — a
 * future variant surfaces as `Unknown` with the item id rather than vanishing.
 */
export type Conflict =
	| { DivergentSecret: { kept: string; forked: string } }
	| { DivergentPin: { item: string } }
	| { Unknown: { item: string } };

/** Mirrors `dto::HlcView` — a hybrid logical clock reading (SPEC §4). Read-only. */
export interface HlcView {
	wall_ms: number;
	counter: number;
	device_id: string;
}

/** Mirrors `dto::TombstoneView`. */
export interface TombstoneView {
	hlc: HlcView;
	reason: TombstoneReason;
}

/**
 * Mirrors `dto::ItemView`. Carries **no** secret: the only trace of a PIN is `has_pin`, and
 * the secret has no field at all (§11.2).
 */
export interface ItemView {
	id: string;
	kind: OtpKind;
	algorithm: HashAlg;
	digits: number;
	period: number;
	hotp_counter: number;
	has_pin: boolean;
	issuer: string;
	account: string;
	nickname: string | null;
	note: string | null;
	groups: string[];
	tags: string[];
	origins: string[];
	icon: IconRef;
	color: number | null;
	favorite: boolean;
	manual_order: number | null;
	archived: boolean;
	hidden: boolean;
	requires_reveal_auth: boolean;
	use_count: number;
	last_used_at: number | null;
	created_at: number;
	trashed_at: number | null;
	is_live: boolean;
	is_trashed: boolean;
	is_deleted: boolean;
	deleted: TombstoneView | null;
}

/** Mirrors `dto::GroupView`. */
export interface GroupView {
	id: string;
	name: string;
	color: number | null;
	manual_order: number | null;
	created_at: number;
	is_deleted: boolean;
	deleted: TombstoneView | null;
}

/**
 * Mirrors `dto::CodeView` — the accepted secret-egress exception (§11.6 rule 4).
 *
 * Produced on demand and never cached. §11.6 states plainly that a code handed to a
 * managed runtime becomes an unzeroizable platform string; the mitigation is that it is
 * short-lived and regenerated, which is why `valid_until_ms` is part of the contract rather
 * than something the UI guesses.
 */
export interface CodeView {
	code: string;
	valid_until_ms: number;
	period_ms: number;
}

/** Mirrors `dto::RosterUpdateView`. The envelope is opaque ciphertext, not a secret. */
export interface RosterUpdateView {
	item_id: string;
	envelope: number[];
}

/** Mirrors `dto::SyncReportView` — the owned outcome of one sync. */
export interface SyncReportView {
	conflicts: Conflict[];
	roster_update: RosterUpdateView | null;
	pulled: number;
	pushed: number;
	applied: number;
}

/** Mirrors `facade::LockState` (SPEC §11.5). */
export interface LockState {
	locked: boolean;
}

/**
 * Mirrors `dto::NewItemInput`.
 *
 * Every field is required, deliberately. serde would accept defaults for the collections,
 * but creating a credential is an explicit act and a silently defaulted `digits` or
 * `algorithm` would be a wrong code rather than a validation error. {@link newTotpInput}
 * supplies the conventional values in one visible place instead.
 *
 * `secret` and `pin` are byte arrays, not strings: §9 says no secret in a `String`, and a
 * JS string cannot be overwritten. The client zeroes the caller's buffer after the call.
 */
export interface NewItemInput {
	kind: OtpKind;
	algorithm: HashAlg;
	digits: number;
	period: number;
	hotp_counter: number;
	secret: Uint8Array;
	pin: Uint8Array | null;
	issuer: string;
	account: string;
	nickname: string | null;
	note: string | null;
	groups: string[];
	tags: string[];
	origins: string[];
	icon: IconRef | null;
	color: number | null;
	favorite: boolean;
}

/**
 * Mirrors `dto::EditInput`. A sparse edit: an omitted field is left unchanged, and naming a
 * field in `clear` resets it to absent.
 *
 * Optional here rather than `| null`, because for this type "absent" and "set to null" mean
 * different things — that is what `clear` is for. Sending `nickname: null` would be a
 * request to set the nickname to null, which is not expressible; `clear: ['Nickname']` is.
 */
export interface EditInput {
	issuer?: string;
	account?: string;
	nickname?: string;
	note?: string;
	groups?: string[];
	tags?: string[];
	origins?: string[];
	icon?: IconRef;
	color?: number;
	manual_order?: number;
	favorite?: boolean;
	archived?: boolean;
	hidden?: boolean;
	requires_reveal_auth?: boolean;
	pin?: Uint8Array;
	clear?: ClearableField[];
}

/** The §11.8.2 mock fixtures, as `mockFixtures()` hands them over. */
export interface MockFixtures {
	vault_key: number[];
	totp_secret: number[];
	peer_device_id: string;
	now_ms: number;
	auto_lock_timeout_ms: number;
}

/**
 * A `NewItemInput` with the conventional TOTP defaults filled in.
 *
 * RFC 6238's defaults are six digits over a thirty-second period with SHA-1, and almost
 * every issuer uses them. Anything a caller does not name gets those; anything security
 * relevant — the secret, the labels — has to be passed.
 */
export function newTotpInput(
	fields: Pick<NewItemInput, 'issuer' | 'account' | 'secret'> & Partial<NewItemInput>
): NewItemInput {
	return {
		kind: 'Totp',
		algorithm: 'Sha1',
		digits: 6,
		period: 30,
		hotp_counter: 0,
		pin: null,
		nickname: null,
		note: null,
		groups: [],
		tags: [],
		origins: [],
		icon: null,
		color: null,
		favorite: false,
		...fields
	};
}

/** The display name for an item: its nickname if it has one, else the account (§3.1). */
export function itemLabel(item: ItemView): string {
	return item.nickname ?? item.account;
}

/** The item id a conflict refers to, whichever variant it is. */
export function conflictItemId(conflict: Conflict): string {
	if ('DivergentSecret' in conflict) return conflict.DivergentSecret.kept;
	if ('DivergentPin' in conflict) return conflict.DivergentPin.item;
	return conflict.Unknown.item;
}
