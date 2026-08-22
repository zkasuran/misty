// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The typed edge between the app and the core.
 *
 * `wasm-bindgen` types every method as `Promise<any>`, because the DTOs cross as
 * serde-lowered plain objects rather than generated handle classes (SPEC §11.7.2). This is
 * the **only** module allowed to assert what those objects are; everything above it works
 * with the types in {@link ./types.ts} and never touches the raw facade. That keeps the
 * unchecked cast in one reviewable place instead of scattered through components.
 *
 * It also does exactly two things beyond marshalling, and no more (§11.4.6 keeps logic out
 * of the binding, and the same discipline is worth keeping here):
 *
 *  - normalises every rejection into a {@link MistyError};
 *  - zeroes the caller's secret buffers once the core has copied them.
 *
 * No caching, no retry, no state. The vault is the single source of truth and it lives in
 * the actor behind this handle; a cache here would be a second copy of vault state that can
 * disagree with it.
 */

import { MistyError } from './errors';
import type {
	CodeView,
	Conflict,
	EditInput,
	GroupView,
	ItemView,
	LifecycleEvent,
	LockState,
	MockFixtures,
	NewItemInput,
	SortKey,
	SyncReportView
} from './types';

/**
 * The generated class, as much of it as we use.
 *
 * Declared rather than imported as a type because the generated `.d.ts` says
 * `Promise<any>` everywhere, so importing it would buy nothing and hide which methods this
 * app actually depends on. `ci/check-binding-parity.py` guarantees the Rust side has them.
 */
interface RawFacade {
	free(): void;
	unlock(key: Uint8Array): Promise<unknown>;
	lock(): Promise<unknown>;
	lockState(): Promise<unknown>;
	poll(): Promise<unknown>;
	reportLifecycle(event: unknown): Promise<unknown>;
	shutdown(): Promise<unknown>;
	list(): Promise<unknown>;
	get(id: string): Promise<unknown>;
	item(id: string): Promise<unknown>;
	search(query: string): Promise<unknown>;
	sorted(key: unknown): Promise<unknown>;
	trash(): Promise<unknown>;
	groups(): Promise<unknown>;
	group(id: string): Promise<unknown>;
	conflicts(): Promise<unknown>;
	generateCode(id: string): Promise<unknown>;
	syncOnce(): Promise<unknown>;
	add(input: unknown): Promise<unknown>;
	update(id: string, edit: unknown): Promise<unknown>;
	trashItem(id: string): Promise<unknown>;
	restoreItem(id: string): Promise<unknown>;
	deleteItem(id: string): Promise<unknown>;
	recordUse(id: string): Promise<unknown>;
	addGroup(name: string): Promise<unknown>;
	deleteGroup(id: string): Promise<unknown>;
	advanceHotpCounter(id: string): Promise<unknown>;
	revokeDevice(deviceId: string): Promise<unknown>;
}

/** Overwrite a secret buffer in place. */
function zero(buffer: Uint8Array | null | undefined): void {
	if (buffer) buffer.fill(0);
}

/**
 * Await a core call and normalise its failure.
 *
 * Every method goes through here so there is no path on which a raw rejection object
 * escapes into component code, where it would arrive as a stackless plain object that fails
 * `instanceof Error`.
 */
async function call<T>(promise: Promise<unknown>): Promise<T> {
	try {
		return (await promise) as T;
	} catch (thrown) {
		throw MistyError.from(thrown);
	}
}

/** The core, typed. */
export class MistyCore {
	#facade: RawFacade;

	constructor(facade: RawFacade) {
		this.#facade = facade;
	}

	// --- lifecycle (SPEC §11.5) ---

	/**
	 * Unlock with raw key material.
	 *
	 * The buffer is zeroed once the core has copied it. §11.6 is explicit that this is a
	 * mitigation and not a guarantee: the bytes may already have been copied by the engine
	 * before we get here. What it does prevent is the key sitting in a live JS object for
	 * the rest of the session.
	 */
	async unlock(key: Uint8Array): Promise<void> {
		try {
			await call<void>(this.#facade.unlock(key));
		} finally {
			zero(key);
		}
	}

	lock(): Promise<void> {
		return call<void>(this.#facade.lock());
	}

	lockState(): Promise<LockState> {
		return call<LockState>(this.#facade.lockState());
	}

	/** Re-run the auto-lock deadline check (§11.5.4). Cheap; safe to call on every wake. */
	poll(): Promise<LockState> {
		return call<LockState>(this.#facade.poll());
	}

	/** Report a shell lifecycle event and get the resulting lock state (§11.5.5). */
	reportLifecycle(event: LifecycleEvent): Promise<LockState> {
		return call<LockState>(this.#facade.reportLifecycle(event));
	}

	/** Stop the owning task. Explicit, never a dropped promise. */
	shutdown(): Promise<void> {
		return call<void>(this.#facade.shutdown());
	}

	// --- readers ---

	list(): Promise<ItemView[]> {
		return call<ItemView[]>(this.#facade.list());
	}

	/** One item, or `null` if it is gone. Does not reject for a missing id. */
	get(id: string): Promise<ItemView | null> {
		return call<ItemView | null>(this.#facade.get(id));
	}

	/** One item, rejecting with `NOT_FOUND` if it is gone. */
	item(id: string): Promise<ItemView> {
		return call<ItemView>(this.#facade.item(id));
	}

	search(query: string): Promise<ItemView[]> {
		return call<ItemView[]>(this.#facade.search(query));
	}

	sorted(key: SortKey): Promise<ItemView[]> {
		return call<ItemView[]>(this.#facade.sorted(key));
	}

	trash(): Promise<ItemView[]> {
		return call<ItemView[]>(this.#facade.trash());
	}

	/** Every group, tombstones included — filter on `is_deleted` for the live ones. */
	groups(): Promise<GroupView[]> {
		return call<GroupView[]>(this.#facade.groups());
	}

	group(id: string): Promise<GroupView> {
		return call<GroupView>(this.#facade.group(id));
	}

	/** Unresolved merge conflicts. Not errors (§11.3.1). */
	conflicts(): Promise<Conflict[]> {
		return call<Conflict[]>(this.#facade.conflicts());
	}

	// --- codes and sync ---

	/**
	 * Generate the current code (§11.6 rule 4).
	 *
	 * Never cache the result. It is valid until `valid_until_ms` and the core is the only
	 * thing that knows the clock; holding a stale code is how a UI shows six digits that no
	 * longer work.
	 */
	generateCode(id: string): Promise<CodeView> {
		return call<CodeView>(this.#facade.generateCode(id));
	}

	syncOnce(): Promise<SyncReportView> {
		return call<SyncReportView>(this.#facade.syncOnce());
	}

	// --- mutators ---

	/** Add an item; resolves with its new hex id. Zeroes `secret` and `pin` afterwards. */
	async add(input: NewItemInput): Promise<string> {
		try {
			return await call<string>(this.#facade.add(input));
		} finally {
			zero(input.secret);
			zero(input.pin);
		}
	}

	async update(id: string, edit: EditInput): Promise<void> {
		try {
			await call<void>(this.#facade.update(id, edit));
		} finally {
			zero(edit.pin);
		}
	}

	trashItem(id: string): Promise<void> {
		return call<void>(this.#facade.trashItem(id));
	}

	restoreItem(id: string): Promise<void> {
		return call<void>(this.#facade.restoreItem(id));
	}

	deleteItem(id: string): Promise<void> {
		return call<void>(this.#facade.deleteItem(id));
	}

	recordUse(id: string): Promise<void> {
		return call<void>(this.#facade.recordUse(id));
	}

	addGroup(name: string): Promise<string> {
		return call<string>(this.#facade.addGroup(name));
	}

	deleteGroup(id: string): Promise<void> {
		return call<void>(this.#facade.deleteGroup(id));
	}

	/** Advance a HOTP counter by one; resolves with the new value. */
	advanceHotpCounter(id: string): Promise<number> {
		return call<number>(this.#facade.advanceHotpCounter(id));
	}

	revokeDevice(deviceId: string): Promise<void> {
		return call<void>(this.#facade.revokeDevice(deviceId));
	}
}

/** What the core module exports, as much of it as we use. */
interface CoreModule {
	default: (options?: unknown) => Promise<unknown>;
	MistyFacade: new () => RawFacade;
	mockFixtures: () => MockFixtures;
}

let loaded: CoreModule | undefined;

/**
 * Load and initialise the WebAssembly core, once per document.
 *
 * The import is dynamic so the module is fetched when the app decides, not as a side effect
 * of loading a route — which matters because the core is the largest asset here and nothing
 * before the unlock screen needs it.
 */
async function loadModule(): Promise<CoreModule> {
	if (loaded) return loaded;
	const module = (await import('$lib/core/pkg/misty_ffi.js')) as unknown as CoreModule;
	await module.default();
	loaded = module;
	return module;
}

/**
 * Start a core instance.
 *
 * This is the §11.8.1 mock configuration: the real facade over `MemoryStore` +
 * `MockTransport` with a fixed clock. Swapping in a real store and transport is a change in
 * `crates/misty-ffi`, and nothing in this app moves — the generics are erased at the facade
 * (§11.1), which is the whole reason the UI can be developed against this without building
 * a mock that could drift.
 */
export async function openCore(): Promise<MistyCore> {
	const module = await loadModule();
	return new MistyCore(new module.MistyFacade());
}

/**
 * The shared conformance fixtures (§11.8.2).
 *
 * The UI needs the vault key because the mock core has no key-derivation step: a real build
 * turns a passphrase into key material with Argon2id per §2.3, and that belongs to the shell
 * (P7 onward), not to this page. See {@link ../vault/session.svelte.ts} for where that seam
 * sits and what it deliberately does not pretend to do.
 */
export async function coreFixtures(): Promise<MockFixtures> {
	const module = await loadModule();
	return module.mockFixtures();
}
