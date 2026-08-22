<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import ErrorBanner from '$lib/ui/ErrorBanner.svelte';
	import { theme } from '$lib/ui/theme.svelte';
	import { session } from '$lib/vault/session.svelte';
	import '../app.css';

	let { children } = $props();

	onMount(() => {
		theme.load();
		void session.start();
		// The core's task outlives a component, so shutdown is explicit — UniFFI and
		// wasm-bindgen both lack future-drop cancellation, and §11.7.1 makes teardown a
		// command rather than a dropped promise.
		return () => void session.stop();
	});

	const nav = [
		{ href: '/', label: 'Codes' },
		{ href: '/add', label: 'Add' },
		{ href: '/groups', label: 'Groups' },
		{ href: '/trash', label: 'Trash' },
		{ href: '/settings', label: 'Settings' }
	];

	let unlocked = $derived(session.phase === 'unlocked');
</script>

<svelte:head>
	<title>Misty</title>
</svelte:head>

<!--
	`data-obscured` drives the blur in app.css (SPEC §9: "blurred on background everywhere").
	It is set synchronously by the shell listeners, ahead of the core's lock reply, because a
	screenshot can be taken in that window.
-->
<div class="shell" data-obscured={session.obscured}>
	<!-- The first focusable element on the page, so a keyboard user can bypass the nav. -->
	<a class="skip-link" href="#main">Skip to main content</a>

	<header class="header">
		<div class="brand">
			<img src="{'/favicon.svg'}" alt="" width="24" height="24" />
			<span class="name">Misty</span>
			<!--
				Permanent, not dismissible. This build is wired to the in-memory mock core and
				a user must never mistake it for a vault that persists anything.
			-->
			<span class="badge" data-testid="mock-badge">mock core</span>
		</div>

		{#if unlocked}
			<nav aria-label="Sections">
				<ul>
					{#each nav as entry (entry.href)}
						<li>
							<!--
								`aria-current="page"` is the accessible way to mark the active
								link; the underline is the visual one, so the state is not
								carried by colour alone.
							-->
							<a
								href={entry.href}
								aria-current={page.url.pathname === entry.href ? 'page' : undefined}
							>
								{entry.label}
							</a>
						</li>
					{/each}
				</ul>
			</nav>

			<button
				type="button"
				class="lock"
				onclick={() => session.lock()}
				disabled={session.busy}
				data-testid="lock"
			>
				Lock now
			</button>
		{/if}
	</header>

	<main id="main" tabindex="-1">
		<ErrorBanner
			error={session.error}
			onDismiss={() => session.dismissError()}
			onRetry={session.error?.retryable ? () => session.refresh() : undefined}
		/>
		{@render children()}
	</main>
</div>

<style>
	.shell {
		min-height: 100vh;
		display: flex;
		flex-direction: column;
	}

	.header {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-4);
		padding: var(--space-3) var(--space-5);
		background: var(--surface);
		border-bottom: 1px solid var(--border);
	}

	.brand {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-weight: 700;
		font-size: var(--step-1);
	}

	.badge {
		padding: 0.1rem var(--space-2);
		border: 1px solid var(--warning);
		background: var(--warning-quiet);
		color: var(--warning);
		border-radius: var(--radius-sm);
		font-size: var(--step--1);
		font-weight: 600;
		letter-spacing: 0.02em;
	}

	nav {
		flex: 1 1 auto;
	}

	nav ul {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-1);
		list-style: none;
		margin: 0;
		padding: 0;
	}

	nav a {
		display: block;
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		color: var(--text);
		text-decoration: none;
	}

	nav a:hover {
		background: var(--surface-2);
		text-decoration: underline;
	}

	nav a[aria-current='page'] {
		background: var(--accent-quiet);
		font-weight: 600;
		/* Not colour alone: the current page is also underlined. */
		text-decoration: underline;
		text-decoration-thickness: 2px;
	}

	.lock {
		padding: var(--space-2) var(--space-4);
		background: var(--surface);
		border: 1px solid var(--border-strong);
		border-radius: var(--radius-sm);
		cursor: pointer;
		font-weight: 600;
	}

	.lock:hover:not(:disabled) {
		background: var(--surface-2);
	}

	.lock:disabled {
		opacity: 0.6;
		cursor: default;
	}

	main {
		flex: 1 1 auto;
		width: 100%;
		max-width: 60rem;
		margin: 0 auto;
		padding: var(--space-5);
	}

	/* `main` is focused programmatically by the skip link, so it must not show a ring when
	   focused that way — but `:focus-visible` in app.css already handles that distinction. */
	main:focus {
		outline: none;
	}
</style>
