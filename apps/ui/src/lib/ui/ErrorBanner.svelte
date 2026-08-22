<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { describe, type MistyError } from '$lib/core/errors';

	interface Props {
		error: MistyError | null;
		onDismiss: () => void;
		onRetry?: (() => void) | undefined;
	}

	let { error, onDismiss, onRetry }: Props = $props();

	// `describe` maps the stable code to wording this app owns. §11.3.2 forbids parsing the
	// core's `message`, so the UI cannot reuse it and must keep its own copy.
	let described = $derived(error ? describe(error) : null);
</script>

<!--
	`role="alert"` is an assertive live region, so a failure is announced as soon as it
	appears without the user having to go looking for it. The wrapper is always in the DOM
	and only its contents change; a live region that is added to the page at the same moment
	as its text is unreliable across screen readers.
-->
<div class="slot" role="alert" aria-live="assertive">
	{#if error && described}
		<div class="banner" data-testid="error-banner">
			<p class="text">{described.text}</p>
			<!--
				The code is shown deliberately. It is the stable, documented identifier
				(§11.3.1), so it is the thing worth putting in a bug report — unlike the
				wording, which is ours and may change.
			-->
			<p class="code">
				<span class="sr-only">Error code</span>
				<code>{error.code}</code>
			</p>
			<div class="actions">
				{#if described.canRetry && onRetry}
					<button type="button" onclick={onRetry}>Try again</button>
				{/if}
				<button type="button" onclick={onDismiss}>Dismiss</button>
			</div>
		</div>
	{/if}
</div>

<style>
	.banner {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-3) var(--space-4);
		margin-bottom: var(--space-4);
		background: var(--danger-quiet);
		/* A 4px start border rather than colour alone: WCAG 1.4.1 — colour must not be the
		   only thing carrying meaning, and a red tint is invisible to a lot of people. */
		border: 1px solid var(--danger);
		border-inline-start: 4px solid var(--danger);
		border-radius: var(--radius);
		color: var(--text);
	}

	.text {
		flex: 1 1 16rem;
		margin: 0;
	}

	.code {
		margin: 0;
		font-family: var(--font-mono);
		font-size: var(--step--1);
		color: var(--text-muted);
	}

	.actions {
		display: flex;
		gap: var(--space-2);
	}

	button {
		padding: var(--space-2) var(--space-3);
		background: var(--surface);
		border: 1px solid var(--border-strong);
		border-radius: var(--radius-sm);
		cursor: pointer;
	}

	button:hover {
		background: var(--surface-2);
	}
</style>
