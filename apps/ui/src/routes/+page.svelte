<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later

	The vault: the unlock gate, then the codes.
-->
<script lang="ts">
	import CodeTile from '$lib/ui/CodeTile.svelte';
	import type { SortKey } from '$lib/core/types';
	import { session } from '$lib/vault/session.svelte';

	const sorts: { value: SortKey; label: string }[] = [
		{ value: 'Issuer', label: 'Issuer' },
		{ value: 'LastUsed', label: 'Recently used' },
		{ value: 'MostUsed', label: 'Most used' },
		{ value: 'Created', label: 'Newest' },
		{ value: 'Manual', label: 'Manual order' }
	];

	let query = $state('');
	let searchTimer: number | undefined;

	/**
	 * Debounced search. Each keystroke would otherwise be a command to the actor and a full
	 * re-read; 200ms is below the threshold where typing feels laggy and well above the
	 * inter-keystroke interval.
	 */
	function onQueryInput(event: Event): void {
		query = (event.currentTarget as HTMLInputElement).value;
		window.clearTimeout(searchTimer);
		searchTimer = window.setTimeout(() => void session.setQuery(query), 200);
	}

	/** One clean string, so the live region announces no incidental whitespace. */
	let countText = $derived.by(() => {
		const total = session.items.length;
		const noun = total === 1 ? 'code' : 'codes';
		const trimmed = query.trim();
		return trimmed ? `${total} ${noun} matching “${trimmed}”` : `${total} ${noun}`;
	});
</script>

{#if session.phase === 'starting'}
	<p data-testid="starting" role="status" aria-live="polite">Starting the vault core…</p>
{:else if session.phase === 'failed'}
	<h1>The vault core did not start</h1>
	<p>
		The WebAssembly core could not be loaded, so there is nothing this page can do. The error
		above has the details.
	</p>
{:else if session.phase === 'locked'}
	<div class="gate">
		<h1>Vault locked</h1>
		<!--
			Honest about what this build is. There is no passphrase field because §2.3 fixes key
			derivation at Argon2id and the facade exposes no derivation call — a box that
			accepted anything would look like the real unlock flow while proving nothing.
		-->
		<p>
			This build runs the in-memory mock core and unlocks with the shared conformance
			fixture key. Passphrase and biometric unlock need a key-derivation call across the
			facade, which does not exist yet.
		</p>
		<button
			type="button"
			class="primary"
			onclick={() => session.unlock()}
			disabled={session.busy}
			data-testid="unlock"
		>
			{session.busy ? 'Unlocking…' : 'Unlock vault'}
		</button>
	</div>
{:else}
	<h1>Codes</h1>

	<div class="controls">
		<div class="field">
			<label for="search">Search</label>
			<input
				id="search"
				type="search"
				value={query}
				oninput={onQueryInput}
				placeholder="Issuer, account, or tag"
				autocomplete="off"
				data-testid="search"
			/>
		</div>

		<div class="field">
			<label for="sort">Sort by</label>
			<select
				id="sort"
				value={session.sort}
				onchange={(event) => session.setSort(event.currentTarget.value as SortKey)}
				disabled={query.trim().length > 0}
				data-testid="sort"
			>
				{#each sorts as option (option.value)}
					<option value={option.value}>{option.label}</option>
				{/each}
			</select>
			{#if query.trim().length > 0}
				<p class="hint">Search results are ranked by relevance.</p>
			{/if}
		</div>
	</div>

	<!--
		The result count is announced. A search that silently returns nothing is one of the most
		common screen-reader failures, and `role="status"` reports it without stealing focus.

		Built as a single expression rather than interpolations across several lines: the latter
		puts the source's newlines and indentation into the text node, so the announced string
		is "1⏎⇥⇥code matching …". Most tooling normalises that away and screen readers cope, but
		it is still incidental whitespace inside a live region, and it is the sort of thing that
		makes an assertion mysteriously not match.
	-->
	<p class="count" role="status" aria-live="polite" data-testid="count">{countText}</p>

	{#if session.items.length === 0}
		<p class="empty">
			{#if query.trim()}
				Nothing matches that search.
			{:else}
				No codes yet. <a href="/add">Add one</a>.
			{/if}
		</p>
	{:else}
		<!--
			A list, so a screen reader announces "list, 3 items" and offers list navigation. A
			pile of divs gives none of that.
		-->
		<ul class="items">
			{#each session.items as item (item.id)}
				<li>
					<CodeTile {item} />
					<a class="details" href={`/items/${item.id}`}>
						Details<span class="sr-only"> for {item.issuer} {item.nickname ?? item.account}</span>
					</a>
				</li>
			{/each}
		</ul>
	{/if}
{/if}

<style>
	.gate {
		max-width: 34rem;
	}

	.primary {
		padding: var(--space-3) var(--space-5);
		background: var(--accent);
		color: var(--accent-text);
		border: 1px solid transparent;
		border-radius: var(--radius);
		font-weight: 600;
		cursor: pointer;
	}

	.primary:hover:not(:disabled) {
		filter: brightness(1.08);
	}

	.primary:disabled {
		opacity: 0.7;
		cursor: default;
	}

	.controls {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-4);
		margin-bottom: var(--space-4);
	}

	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.field label {
		font-size: var(--step--1);
		font-weight: 600;
	}

	input,
	select {
		padding: var(--space-2) var(--space-3);
		background: var(--surface);
		border: 1px solid var(--border-strong);
		border-radius: var(--radius-sm);
		min-width: 14rem;
	}

	select:disabled {
		opacity: 0.6;
	}

	.hint,
	.count,
	.empty {
		color: var(--text-muted);
		font-size: var(--step--1);
	}

	.hint {
		margin: 0;
	}

	.items {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.items li {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.details {
		align-self: flex-start;
		font-size: var(--step--1);
		color: var(--accent);
	}
</style>
