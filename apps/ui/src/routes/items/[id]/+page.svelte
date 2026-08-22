<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import type { EditInput, ItemView } from '$lib/core/types';
	import { session } from '$lib/vault/session.svelte';

	let id = $derived(page.params.id ?? '');

	/**
	 * Read from the projection rather than issuing another query: the list has just been
	 * loaded, and a second read would be a different snapshot of a converging vault.
	 * `trashed` is searched too so a trashed item's page still resolves.
	 */
	let item = $derived<ItemView | undefined>(
		session.items.find((candidate) => candidate.id === id) ??
			session.trashed.find((candidate) => candidate.id === id)
	);

	let nickname = $state('');
	let note = $state('');
	let favorite = $state(false);
	let groupIds = $state<string[]>([]);
	let saved = $state(false);
	let hydratedFor = $state('');

	// Seed the form once per item, not on every render, or typing would be overwritten by
	// each re-read the session performs.
	$effect(() => {
		if (!item || hydratedFor === item.id) return;
		hydratedFor = item.id;
		nickname = item.nickname ?? '';
		note = item.note ?? '';
		favorite = item.favorite;
		groupIds = [...item.groups];
	});

	async function save(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		if (!item) return;

		// A sparse edit: send only what changed, and use `clear` for a field being emptied.
		// Sending `nickname: ''` would store an empty string, which is a different thing from
		// having no nickname (§11.2).
		const edit: EditInput = {};
		const clear: NonNullable<EditInput['clear']> = [];

		const trimmedNickname = nickname.trim();
		if (trimmedNickname) edit.nickname = trimmedNickname;
		else if (item.nickname !== null) clear.push('Nickname');

		const trimmedNote = note.trim();
		if (trimmedNote) edit.note = trimmedNote;
		else if (item.note !== null) clear.push('Note');

		if (favorite !== item.favorite) edit.favorite = favorite;

		const sameGroups =
			groupIds.length === item.groups.length && groupIds.every((g) => item.groups.includes(g));
		if (!sameGroups) edit.groups = groupIds;

		if (clear.length > 0) edit.clear = clear;

		await session.update(item.id, edit);
		saved = session.error === null;
	}

	async function trash(): Promise<void> {
		if (!item) return;
		await session.trashItem(item.id);
		if (session.error === null) await goto('/');
	}

	function toggleGroup(groupId: string, checked: boolean): void {
		groupIds = checked ? [...groupIds, groupId] : groupIds.filter((g) => g !== groupId);
	}
</script>

{#if session.phase !== 'unlocked'}
	<p>The vault is locked. <a href="/">Unlock it</a> to see this item.</p>
{:else if !item}
	<h1>Item not found</h1>
	<p>It may have been deleted on another device. <a href="/">Back to codes</a>.</p>
{:else}
	<h1>{item.issuer}</h1>
	<p class="account">{item.account}</p>

	<!-- Facts the core owns and the UI must not recompute. -->
	<dl class="facts">
		<dt>Type</dt>
		<dd>{item.kind} · {item.algorithm} · {item.digits} digits</dd>
		{#if item.kind === 'Totp'}
			<dt>Period</dt>
			<dd>{item.period} seconds</dd>
		{:else if item.kind === 'Hotp'}
			<dt>Counter</dt>
			<dd>{item.hotp_counter}</dd>
		{/if}
		<dt>Used</dt>
		<dd>{item.use_count} {item.use_count === 1 ? 'time' : 'times'}</dd>
		<dt>PIN</dt>
		<dd>{item.has_pin ? 'Set' : 'Not set'}</dd>
		{#if item.is_trashed}
			<dt>Status</dt>
			<dd>In the trash</dd>
		{/if}
	</dl>

	{#if item.is_trashed}
		<div class="actions">
			<button type="button" onclick={() => session.restoreItem(item.id)} disabled={session.busy}>
				Restore
			</button>
		</div>
	{:else}
		<form onsubmit={save}>
			<div class="field">
				<label for="nickname">Nickname</label>
				<input id="nickname" bind:value={nickname} autocomplete="off" data-testid="nickname" />
				<p class="hint">Leave empty to remove it.</p>
			</div>

			<div class="field">
				<label for="note">Note</label>
				<textarea id="note" bind:value={note} rows="3" data-testid="note"></textarea>
			</div>

			<div class="field checkbox">
				<input id="favorite" type="checkbox" bind:checked={favorite} data-testid="favorite" />
				<label for="favorite">Favourite</label>
			</div>

			{#if session.liveGroups.length > 0}
				<fieldset class="field">
					<legend>Groups</legend>
					{#each session.liveGroups as group (group.id)}
						<div class="checkbox">
							<input
								id={`group-${group.id}`}
								type="checkbox"
								checked={groupIds.includes(group.id)}
								onchange={(event) => toggleGroup(group.id, event.currentTarget.checked)}
							/>
							<label for={`group-${group.id}`}>{group.name}</label>
						</div>
					{/each}
				</fieldset>
			{/if}

			<div class="actions">
				<button type="submit" class="primary" disabled={session.busy} data-testid="save">
					Save changes
				</button>
				<button type="button" class="danger" onclick={trash} disabled={session.busy} data-testid="trash">
					Move to trash
				</button>
				<a href="/">Back</a>
			</div>

			<!-- Confirmation is announced, not just shown. -->
			<p class="saved" role="status" aria-live="polite" data-testid="saved">
				{saved ? 'Changes saved.' : ''}
			</p>
		</form>
	{/if}
{/if}

<style>
	.account {
		margin-top: calc(var(--space-2) * -1);
		color: var(--text-muted);
	}

	.facts {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: var(--space-2) var(--space-4);
		margin: var(--space-4) 0;
		padding: var(--space-4);
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
	}

	.facts dt {
		font-weight: 600;
		font-size: var(--step--1);
		color: var(--text-muted);
	}

	.facts dd {
		margin: 0;
	}

	form {
		max-width: 32rem;
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}

	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	fieldset.field {
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: var(--space-3);
	}

	legend,
	label {
		font-weight: 600;
		font-size: var(--step--1);
	}

	.checkbox {
		flex-direction: row;
		align-items: center;
		gap: var(--space-2);
		display: flex;
	}

	.checkbox label {
		font-weight: 400;
	}

	input:not([type='checkbox']),
	textarea {
		padding: var(--space-2) var(--space-3);
		background: var(--surface);
		border: 1px solid var(--border-strong);
		border-radius: var(--radius-sm);
		font-family: inherit;
	}

	.hint {
		margin: 0;
		font-size: var(--step--1);
		color: var(--text-muted);
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-3);
	}

	button {
		padding: var(--space-2) var(--space-4);
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-strong);
		background: var(--surface);
		cursor: pointer;
		font-weight: 600;
	}

	.primary {
		background: var(--accent);
		color: var(--accent-text);
		border-color: transparent;
	}

	.danger {
		color: var(--danger);
		border-color: var(--danger);
	}

	button:disabled {
		opacity: 0.7;
		cursor: default;
	}

	.saved {
		margin: 0;
		min-height: 1.5rem;
		color: var(--success);
		font-weight: 600;
	}
</style>
