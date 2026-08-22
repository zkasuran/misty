<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { session } from '$lib/vault/session.svelte';

	let name = $state('');

	async function create(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		if (!name.trim()) return;
		const id = await session.addGroup(name.trim());
		if (id) name = '';
	}
</script>

<h1>Groups</h1>

<form onsubmit={create}>
	<div class="field">
		<label for="name">New group</label>
		<div class="row">
			<input id="name" bind:value={name} autocomplete="off" data-testid="group-name" />
			<button type="submit" class="primary" disabled={session.busy || !name.trim()} data-testid="add-group">
				Create
			</button>
		</div>
	</div>
</form>

<p class="count" role="status" aria-live="polite" data-testid="group-count">
	{session.liveGroups.length} {session.liveGroups.length === 1 ? 'group' : 'groups'}
</p>

{#if session.liveGroups.length === 0}
	<p class="empty">No groups yet.</p>
{:else}
	<ul>
		{#each session.liveGroups as group (group.id)}
			<li>
				<span class="name">{group.name}</span>
				<!--
					The accessible name says which group, so a screen reader user hearing a list
					of "Delete" buttons can tell them apart.
				-->
				<button
					type="button"
					class="danger"
					onclick={() => session.deleteGroup(group.id)}
					disabled={session.busy}
					aria-label={`Delete group ${group.name}`}
				>
					Delete
				</button>
			</li>
		{/each}
	</ul>
{/if}

<p class="note">
	Deleting a group leaves a tombstone so the deletion converges on your other devices; the
	codes inside it are not deleted.
</p>

<style>
	form {
		max-width: 28rem;
		margin-bottom: var(--space-4);
	}

	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	label {
		font-weight: 600;
		font-size: var(--step--1);
	}

	.row {
		display: flex;
		gap: var(--space-2);
	}

	input {
		flex: 1 1 auto;
		padding: var(--space-2) var(--space-3);
		background: var(--surface);
		border: 1px solid var(--border-strong);
		border-radius: var(--radius-sm);
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
		opacity: 0.6;
		cursor: default;
	}

	ul {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		max-width: 32rem;
	}

	li {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-3);
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
	}

	.name {
		font-weight: 600;
	}

	.count,
	.empty,
	.note {
		color: var(--text-muted);
		font-size: var(--step--1);
	}

	.note {
		margin-top: var(--space-5);
		max-width: 40rem;
	}
</style>
