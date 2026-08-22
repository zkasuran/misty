// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The app's view of the vault.
 *
 * This is a *projection*, not a copy. The vault lives in the actor behind {@link MistyCore}
 * and is the only source of truth (SPEC §11.4.4); what is held here is the result of the
 * last read, kept so components can render without each one issuing its own query. Every
 * mutation goes to the core and is followed by a re-read rather than being applied
 * optimistically to these arrays — an optimistic update is a second, divergent copy of vault
 * state, and CRDT merge means the core's answer can legitimately differ from what the
 * caller asked for (§4).
 *
 * Lock state is never inferred here either. It arrives from the core, via
 * {@link installShell} or as the reply to a command, because §11.5 puts the deadline inside
 * the actor and a UI that guessed would eventually show an unlocked vault that is not.
 */

import { openCore, coreFixtures, type MistyCore } from '$lib/core/client';
import { MistyError } from '$lib/core/errors';
import { installShell } from '$lib/core/lifecycle';
import type {
	Conflict,
	EditInput,
	GroupView,
	ItemView,
	NewItemInput,
	SortKey,
	SyncReportView
} from '$lib/core/types';

/** What the app is doing, as far as the user is concerned. */
export type Phase = 'starting' | 'locked' | 'unlocked' | 'failed';

class Session {
	/** The core handle, once the module has loaded. */
	#core: MistyCore | null = null;
	#teardown: (() => void) | null = null;

	phase = $state<Phase>('starting');
	/** Why we are in `failed`, or the last error worth showing. */
	error = $state<MistyError | null>(null);
	/** True while a command is in flight, for busy states and to disable double-submits. */
	busy = $state(false);
	/** Set when the view must be obscured (SPEC §9: blurred on background). */
	obscured = $state(false);

	items = $state<ItemView[]>([]);
	groups = $state<GroupView[]>([]);
	trashed = $state<ItemView[]>([]);
	conflicts = $state<Conflict[]>([]);
	sort = $state<SortKey>('Issuer');
	query = $state('');

	/** The last sync outcome, so the UI can say what happened rather than just "done". */
	lastSync = $state<SyncReportView | null>(null);

	/** Live groups only; the core returns tombstones too and filtering is the caller's job. */
	get liveGroups(): GroupView[] {
		return this.groups.filter((group) => !group.is_deleted);
	}

	/** The core, or a throw. Every action funnels through this so `#core` is never asserted. */
	#need(): MistyCore {
		if (!this.#core) throw new MistyError('INTERNAL', 'the core is not running', false);
		return this.#core;
	}

	/**
	 * Load the core and wire the shell. Idempotent; safe to call from `onMount`.
	 */
	async start(): Promise<void> {
		if (this.#core) return;
		try {
			const core = await openCore();
			this.#core = core;
			this.#teardown = installShell(core, {
				onLockState: (state) => {
					const wasUnlocked = this.phase === 'unlocked';
					this.phase = state.locked ? 'locked' : 'unlocked';
					// Locking is the one transition that must drop the projection. Leaving
					// decrypted labels on screen after the key is gone would contradict the
					// point of locking.
					if (state.locked && wasUnlocked) this.#forget();
				},
				onObscured: (obscured) => {
					this.obscured = obscured;
				},
				onError: (thrown) => {
					this.error = MistyError.from(thrown);
				}
			});
		} catch (thrown) {
			this.phase = 'failed';
			this.error = MistyError.from(thrown);
		}
	}

	/** Release the shell listeners and stop the core's task. */
	async stop(): Promise<void> {
		this.#teardown?.();
		this.#teardown = null;
		const core = this.#core;
		this.#core = null;
		this.#forget();
		if (core) await core.shutdown().catch(() => undefined);
	}

	/** Drop everything derived from the vault key. */
	#forget(): void {
		this.items = [];
		this.groups = [];
		this.trashed = [];
		this.conflicts = [];
		this.lastSync = null;
		this.query = '';
	}

	/**
	 * Run a command, tracking busy state and turning a failure into `error`.
	 *
	 * `VAULT_LOCKED` is handled here rather than at each call site: it is not really a
	 * failure, it is the answer to "may I", and the correct response is always the same —
	 * move to the locked phase and drop the projection.
	 */
	async #run<T>(work: (core: MistyCore) => Promise<T>): Promise<T | undefined> {
		this.busy = true;
		try {
			const result = await work(this.#need());
			this.error = null;
			return result;
		} catch (thrown) {
			const error = MistyError.from(thrown);
			if (error.isLocked) {
				this.phase = 'locked';
				this.#forget();
			}
			this.error = error;
			return undefined;
		} finally {
			this.busy = false;
		}
	}

	/** Clear a displayed error, e.g. when the user dismisses it. */
	dismissError(): void {
		this.error = null;
	}

	// --- lifecycle ---

	/**
	 * Unlock with the mock core's fixture key.
	 *
	 * There is deliberately no passphrase here, and that is a statement about what is and is
	 * not built rather than a shortcut. §2.3 fixes key derivation at Argon2id with specific
	 * parameters; the facade exposes no `deriveKey`, so this app has no way to turn a
	 * passphrase into the vault key. A passphrase box that accepted anything — or that
	 * quietly used PBKDF2 because WebCrypto has it — would look like the real unlock flow
	 * while proving nothing and misrepresenting the cryptography.
	 *
	 * What is missing is one facade method. Until it exists, this build unlocks with the
	 * §11.8.2 fixture key and says so on screen.
	 */
	async unlock(): Promise<void> {
		await this.#run(async (core) => {
			const fixtures = await coreFixtures();
			// A fresh copy: `unlock` zeroes the buffer it is given, and the fixtures are
			// re-read from the core each time rather than cached in a live JS object.
			await core.unlock(new Uint8Array(fixtures.vault_key));
			this.phase = 'unlocked';
			await this.refresh();
		});
	}

	async lock(): Promise<void> {
		await this.#run(async (core) => {
			await core.lock();
			this.phase = 'locked';
			this.#forget();
		});
	}

	// --- reads ---

	/** Re-read everything the UI shows. Called after any mutation. */
	async refresh(): Promise<void> {
		await this.#run(async (core) => {
			const [items, groups, trashed, conflicts] = await Promise.all([
				this.query.trim() ? core.search(this.query.trim()) : core.sorted(this.sort),
				core.groups(),
				core.trash(),
				core.conflicts()
			]);
			this.items = items;
			this.groups = groups;
			this.trashed = trashed;
			this.conflicts = conflicts;
		});
	}

	async setSort(key: SortKey): Promise<void> {
		this.sort = key;
		await this.refresh();
	}

	async setQuery(query: string): Promise<void> {
		this.query = query;
		await this.refresh();
	}

	// --- mutations. Each one re-reads rather than patching the projection. ---

	async add(input: NewItemInput): Promise<string | undefined> {
		const id = await this.#run((core) => core.add(input));
		if (id) await this.refresh();
		return id;
	}

	async update(id: string, edit: EditInput): Promise<void> {
		await this.#run((core) => core.update(id, edit));
		await this.refresh();
	}

	async trashItem(id: string): Promise<void> {
		await this.#run((core) => core.trashItem(id));
		await this.refresh();
	}

	async restoreItem(id: string): Promise<void> {
		await this.#run((core) => core.restoreItem(id));
		await this.refresh();
	}

	async deleteItem(id: string): Promise<void> {
		await this.#run((core) => core.deleteItem(id));
		await this.refresh();
	}

	async addGroup(name: string): Promise<string | undefined> {
		const id = await this.#run((core) => core.addGroup(name));
		if (id) await this.refresh();
		return id;
	}

	async deleteGroup(id: string): Promise<void> {
		await this.#run((core) => core.deleteGroup(id));
		await this.refresh();
	}

	async recordUse(id: string): Promise<void> {
		await this.#run((core) => core.recordUse(id));
		// This *does* refresh, and an earlier version of it did not — on the reasoning that a
		// use count is invisible so re-reading would be churn. That was wrong twice: the count
		// is shown on the item page, and `LastUsed`/`MostUsed` are sort orders, so recording a
		// use changes both a displayed value and the order of the list. Skipping the re-read
		// left the projection stale and the item page reporting "0 times" immediately after a
		// copy. Correctness first; if the re-read ever costs enough to notice, the fix is a
		// narrower read rather than a stale projection.
		await this.refresh();
	}

	async advanceHotpCounter(id: string): Promise<number | undefined> {
		const counter = await this.#run((core) => core.advanceHotpCounter(id));
		if (counter !== undefined) await this.refresh();
		return counter;
	}

	async sync(): Promise<void> {
		const report = await this.#run((core) => core.syncOnce());
		if (report) {
			this.lastSync = report;
			await this.refresh();
		}
	}

	/** Generate a code. Deliberately not cached — see {@link MistyCore.generateCode}. */
	async generateCode(id: string) {
		return this.#run((core) => core.generateCode(id));
	}

	async revokeDevice(deviceId: string): Promise<void> {
		await this.#run((core) => core.revokeDevice(deviceId));
		await this.refresh();
	}
}

/**
 * One session per document.
 *
 * A module-level instance rather than a context, because there is exactly one vault per tab
 * and threading a context through every component would suggest otherwise.
 */
export const session = new Session();
