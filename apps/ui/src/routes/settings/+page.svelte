<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { coreFixtures } from '$lib/core/client';
	import { conflictItemId } from '$lib/core/types';
	import ThemeToggle from '$lib/ui/ThemeToggle.svelte';
	import { session } from '$lib/vault/session.svelte';

	let peerDeviceId = $state('');
	let revoked = $state(false);

	$effect(() => {
		void coreFixtures().then((fixtures) => {
			peerDeviceId = fixtures.peer_device_id;
		});
	});

	async function revoke(): Promise<void> {
		await session.revokeDevice(peerDeviceId);
		revoked = session.error === null;
	}
</script>

<h1>Settings</h1>

<section aria-labelledby="appearance">
	<h2 id="appearance">Appearance</h2>
	<ThemeToggle />
</section>

<section aria-labelledby="sync">
	<h2 id="sync">Sync</h2>
	<p class="muted">
		This build talks to an in-process mock server, so syncing exercises the real protocol
		without reaching the network.
	</p>
	<button type="button" class="primary" onclick={() => session.sync()} disabled={session.busy} data-testid="sync">
		{session.busy ? 'Syncing…' : 'Sync now'}
	</button>

	<!-- The outcome is announced, since the button gives no other feedback. -->
	<div role="status" aria-live="polite" data-testid="sync-report">
		{#if session.lastSync}
			<dl class="report">
				<dt>Pushed</dt>
				<dd>{session.lastSync.pushed}</dd>
				<dt>Pulled</dt>
				<dd>{session.lastSync.pulled}</dd>
				<dt>Applied</dt>
				<dd>{session.lastSync.applied}</dd>
			</dl>
		{/if}
	</div>
</section>

<section aria-labelledby="conflicts">
	<h2 id="conflicts">Conflicts</h2>
	{#if session.conflicts.length === 0}
		<p class="muted">Nothing to resolve.</p>
	{:else}
		<!--
			A conflict is not an error: the merge already settled and kept both sides (§4.2,
			§11.3.1). The wording says what happened rather than asking the user to fix a fault.
		-->
		<ul>
			{#each session.conflicts as conflict (conflictItemId(conflict))}
				<li>
					{#if 'DivergentSecret' in conflict}
						Two devices disagreed on a secret. Both were kept —
						<a href={`/items/${conflict.DivergentSecret.kept}`}>the original</a>
						and <a href={`/items/${conflict.DivergentSecret.forked}`}>a copy</a>. Check which one
						still works and delete the other.
					{:else if 'DivergentPin' in conflict}
						A PIN diverged on <a href={`/items/${conflict.DivergentPin.item}`}>this code</a>.
					{:else}
						<a href={`/items/${conflict.Unknown.item}`}>This code</a> has a conflict this version
						does not recognise. Updating may explain it.
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
</section>

<section aria-labelledby="devices">
	<h2 id="devices">Devices</h2>
	<p class="muted">
		The mock vault has one other device enrolled. Revoking it rotates the vault epoch and
		re-seals everything under a successor roster, which is the §6.4 flow — your codes survive
		it.
	</p>
	<p class="mono">{peerDeviceId || 'loading…'}</p>
	<button
		type="button"
		class="danger"
		onclick={revoke}
		disabled={session.busy || !peerDeviceId}
		data-testid="revoke"
	>
		Revoke this device
	</button>
	<p role="status" aria-live="polite" data-testid="revoked">
		{revoked ? 'Device revoked and the vault re-sealed under a new epoch.' : ''}
	</p>
</section>

<section aria-labelledby="about">
	<h2 id="about">About this build</h2>
	<ul class="about">
		<li>The vault is the real Rust core compiled to WebAssembly, running in this tab.</li>
		<li>Storage is in memory: everything is gone when you close the page.</li>
		<li>The clock is pinned, so a code does not change between refreshes.</li>
		<li>Auto-locks after 60 seconds idle, on backgrounding, and on screen lock.</li>
	</ul>
</section>

<style>
	section {
		max-width: 40rem;
		margin-bottom: var(--space-6);
	}

	h2 {
		font-size: var(--step-2);
		margin-bottom: var(--space-2);
	}

	.muted {
		color: var(--text-muted);
		font-size: var(--step--1);
	}

	.mono {
		font-family: var(--font-mono);
		font-size: var(--step--1);
		overflow-wrap: anywhere;
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

	.report {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: var(--space-1) var(--space-4);
		margin-top: var(--space-3);
		font-size: var(--step--1);
	}

	.report dt {
		font-weight: 600;
		color: var(--text-muted);
	}

	.report dd {
		margin: 0;
	}

	ul {
		padding-left: var(--space-5);
	}

	.about {
		color: var(--text-muted);
		font-size: var(--step--1);
	}

	li {
		margin-bottom: var(--space-1);
	}
</style>
