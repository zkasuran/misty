<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { copyEphemeral, CLIPBOARD_CLEAR_MS } from '$lib/core/lifecycle';
	import type { CodeView, ItemView } from '$lib/core/types';
	import { session } from '$lib/vault/session.svelte';

	interface Props {
		item: ItemView;
	}

	let { item }: Props = $props();

	let code = $state<CodeView | null>(null);
	/** `performance.now()` when the current code arrived, for the local countdown. */
	let receivedAt = $state(0);
	let remainingMs = $state(0);
	let copyState = $state<'idle' | 'copied' | 'cleared' | 'failed'>('idle');

	/**
	 * How long this code has left, in milliseconds.
	 *
	 * The core owns validity and reports it as an absolute `valid_until_ms`. That is the value
	 * to trust — *when* the core's clock and the browser's are the same clock. Under the
	 * §11.8.1 mock core it is pinned to a fixed reading, so comparing it to `Date.now()` gives
	 * a number tens of thousands of seconds in the past and the countdown would render
	 * permanently expired.
	 *
	 * So: use `valid_until_ms` when it lands inside a plausible window, and otherwise fall
	 * back to measuring locally from the moment the code arrived. The fallback is monotonic
	 * (`performance.now()`), so it also survives the wall clock being adjusted underneath us —
	 * which is worth having regardless of the mock.
	 */
	function computeRemaining(view: CodeView, since: number): number {
		const byAbsolute = view.valid_until_ms - Date.now();
		if (byAbsolute > 0 && byAbsolute <= view.period_ms) return byAbsolute;
		const elapsed = performance.now() - since;
		return Math.max(0, view.period_ms - elapsed);
	}

	async function refreshCode(): Promise<void> {
		const view = await session.generateCode(item.id);
		if (!view) return;
		code = view;
		receivedAt = performance.now();
		remainingMs = computeRemaining(view, receivedAt);
	}

	$effect(() => {
		// Re-generate whenever the item id changes, then tick.
		void item.id;
		void refreshCode();
	});

	$effect(() => {
		const handle = window.setInterval(() => {
			const view = code;
			if (!view) return;
			remainingMs = computeRemaining(view, receivedAt);
			// The window closed: ask the core for the next one rather than extrapolating.
			// Only the core knows the counter and the clock.
			if (remainingMs <= 0) void refreshCode();
		}, 250);
		return () => window.clearInterval(handle);
	});

	let seconds = $derived(code ? Math.ceil(remainingMs / 1000) : 0);
	/** 1 at the start of the window, 0 at the end. Drives the ring. */
	let fraction = $derived(code && code.period_ms > 0 ? remainingMs / code.period_ms : 0);
	/** Under five seconds is the "about to change" state. */
	let expiring = $derived(code !== null && remainingMs <= 5_000);

	/** `746722` → `746 722`, which is markedly easier to transcribe. */
	let grouped = $derived.by(() => {
		if (!code) return '';
		const digits = code.code;
		if (digits.length !== 6 && digits.length !== 8) return digits;
		const half = digits.length / 2;
		return `${digits.slice(0, half)} ${digits.slice(half)}`;
	});

	/**
	 * Digits separated for a screen reader, so `746722` is read as digits rather than as
	 * "seven hundred forty-six thousand seven hundred twenty-two".
	 */
	let spoken = $derived(code ? code.code.split('').join(' ') : '');

	let label = $derived(item.nickname ?? item.account);

	async function copy(): Promise<void> {
		if (!code) return;
		const result = await copyEphemeral(code.code, () => {
			copyState = 'cleared';
		});
		copyState = result === 'copied' ? 'copied' : 'failed';
		if (result === 'copied') {
			// A copy is a use. The core owns the counter and the last-used time (§4).
			await session.recordUse(item.id);
		}
	}
</script>

<div class="tile" data-testid="code-tile" data-item-id={item.id}>
	<div class="identity">
		<h3 class="issuer">{item.issuer}</h3>
		<p class="account">{label}</p>
		{#if item.kind !== 'Totp'}
			<p class="kind">{item.kind}</p>
		{/if}
	</div>

	{#if code}
		<div class="readout">
			<!--
				The visible text is grouped for transcription; the accessible name spells the
				digits out. `aria-live` is deliberately absent: the code changes every thirty
				seconds and announcing it each time would make the page unusable with a screen
				reader. The user asks for it by focusing the copy button.
			-->
			<p class="code" data-testid="code" aria-hidden="true">{grouped}</p>
			<p class="sr-only" data-testid="code-plain">{code.code}</p>

			<div class="timer">
				<!--
					The ring is decorative; the seconds are given as text beside it. `style:`
					rather than a `style` attribute because `style-src 'self'` blocks inline
					style attributes (SPEC §9) — this compiles to a CSSOM write, which CSP
					does not police.
				-->
				<svg class="ring" viewBox="0 0 32 32" aria-hidden="true" focusable="false">
					<circle class="ring-track" cx="16" cy="16" r="14" />
					<circle
						class="ring-progress"
						class:expiring
						cx="16"
						cy="16"
						r="14"
						style:stroke-dashoffset={88 - 88 * fraction}
					/>
				</svg>
				<!--
					Not a live region. The text updates every second, and announcing that would
					be relentless; it is here so the information is available to anyone who
					looks, including via a virtual cursor.
				-->
				<p class="seconds" data-testid="seconds">
					{seconds}s
					<span class="sr-only">until this code changes</span>
				</p>
			</div>
		</div>

		<div class="actions">
			<button
				type="button"
				class="copy"
				onclick={copy}
				aria-label={`Copy code for ${item.issuer} ${label}: ${spoken}`}
				data-testid="copy"
			>
				Copy
			</button>
			<!--
				The copy outcome *is* announced: it is a discrete action with a result the user
				asked for, and the automatic clearing is a behaviour they should be told about
				rather than discover.
			-->
			<p class="copy-state" role="status" aria-live="polite">
				{#if copyState === 'copied'}
					Copied. Clears in {CLIPBOARD_CLEAR_MS / 1000} seconds.
				{:else if copyState === 'cleared'}
					Clipboard cleared.
				{:else if copyState === 'failed'}
					Could not copy to the clipboard.
				{/if}
			</p>
		</div>
	{:else}
		<p class="readout pending">Generating…</p>
	{/if}
</div>

<style>
	.tile {
		display: grid;
		grid-template-columns: 1fr auto auto;
		align-items: center;
		gap: var(--space-4);
		padding: var(--space-4);
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		box-shadow: var(--shadow);
	}

	@media (width < 40rem) {
		.tile {
			grid-template-columns: 1fr;
			gap: var(--space-3);
		}
	}

	.identity {
		min-width: 0;
	}

	.issuer {
		margin: 0;
		font-size: var(--step-1);
		/* Long issuer names truncate rather than reflowing the tile; the full value stays in
		   the DOM for a screen reader and for find-in-page. */
		overflow-wrap: anywhere;
	}

	.account,
	.kind {
		margin: 0;
		color: var(--text-muted);
		font-size: var(--step--1);
		overflow-wrap: anywhere;
	}

	.readout {
		display: flex;
		align-items: center;
		gap: var(--space-4);
	}

	.code {
		margin: 0;
		font-family: var(--font-mono);
		font-size: var(--code-size);
		/* Tabular figures stop the code jittering as digits change width. */
		font-variant-numeric: tabular-nums;
		letter-spacing: 0.05em;
	}

	.pending {
		color: var(--text-muted);
	}

	.timer {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}

	.ring {
		width: 2rem;
		height: 2rem;
		transform: rotate(-90deg);
	}

	.ring-track,
	.ring-progress {
		fill: none;
		stroke-width: 3;
	}

	.ring-track {
		stroke: var(--surface-2);
	}

	.ring-progress {
		stroke: var(--accent);
		/* 2πr for r=14, so a full offset empties the ring. */
		stroke-dasharray: 88;
		transition: stroke-dashoffset var(--motion-fast) linear;
	}

	.ring-progress.expiring {
		stroke: var(--warning);
	}

	.seconds {
		margin: 0;
		font-variant-numeric: tabular-nums;
		color: var(--text-muted);
		font-size: var(--step--1);
		/* Fixed width so the layout does not shift between "9s" and "30s". */
		min-width: 2.5rem;
	}

	.actions {
		display: flex;
		flex-direction: column;
		align-items: flex-end;
		gap: var(--space-1);
	}

	.copy {
		padding: var(--space-2) var(--space-4);
		background: var(--accent);
		color: var(--accent-text);
		border: 1px solid transparent;
		border-radius: var(--radius-sm);
		cursor: pointer;
		font-weight: 600;
	}

	.copy:hover {
		filter: brightness(1.08);
	}

	.copy-state {
		margin: 0;
		font-size: var(--step--1);
		color: var(--text-muted);
		text-align: end;
		max-width: 14rem;
	}
</style>
