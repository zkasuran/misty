<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { itemLabel } from '$lib/core/types';
	import { session } from '$lib/vault/session.svelte';

	/**
	 * Deleting is irreversible and unconfirmed clicks are how people lose credentials, so it
	 * takes two steps. Held per item id rather than as a single flag, so arming one row cannot
	 * arm another.
	 */
	let confirming = $state<string | null>(null);

	async function remove(id: string): Promise<void> {
		await session.deleteItem(id);
		confirming = null;
	}
</script>

<h1>Trash</h1>

<p class="count" role="status" aria-live="polite" data-testid="trash-count">
	{session.trashed.length} {session.trashed.length === 1 ? 'item' : 'items'}
</p>

{#if session.trashed.length === 0}
	<p class="empty">The trash is empty.</p>
{:else}
	<ul>
		{#each session.trashed as item (item.id)}
			<li>
				<div class="identity">
					<span class="issuer">{item.issuer}</span>
					<span class="account">{itemLabel(item)}</span>
				</div>

				<div class="actions">
					<button
						type="button"
						onclick={() => session.restoreItem(item.id)}
						disabled={session.busy}
						aria-label={`Restore ${item.issuer} ${itemLabel(item)}`}
						data-testid="restore"
					>
						Restore
					</button>

					{#if confirming === item.id}
						<button
							type="button"
							class="danger"
							onclick={() => remove(item.id)}
							disabled={session.busy}
							aria-label={`Confirm permanent deletion of ${item.issuer} ${itemLabel(item)}`}
							data-testid="confirm-delete"
						>
							Delete permanently
						</button>
						<button type="button" onclick={() => (confirming = null)}>Cancel</button>
					{:else}
						<button
							type="button"
							class="danger"
							onclick={() => (confirming = item.id)}
							disabled={session.busy}
							aria-label={`Delete ${item.issuer} ${itemLabel(item)} permanently`}
							data-testid="delete"
						>
							Delete
						</button>
					{/if}
				</div>
			</li>
		{/each}
	</ul>
{/if}

<p class="note">
	A deleted code leaves a tombstone, so the deletion reaches your other devices instead of the
	code reappearing the next time they sync. The secret itself is gone.
</p>

<style>
	ul {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		max-width: 44rem;
	}

	li {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-3);
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
	}

	.identity {
		display: flex;
		flex-direction: column;
	}

	.issuer {
		font-weight: 600;
	}

	.account {
		color: var(--text-muted);
		font-size: var(--step--1);
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}

	button {
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-strong);
		background: var(--surface);
		cursor: pointer;
		font-weight: 600;
	}

	.danger {
		color: var(--danger);
		border-color: var(--danger);
	}

	button:disabled {
		opacity: 0.6;
		cursor: default;
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
