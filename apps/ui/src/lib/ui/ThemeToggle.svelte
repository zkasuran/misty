<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { theme, type Theme } from './theme.svelte';

	const options: { value: Theme; label: string }[] = [
		{ value: 'light', label: 'Light' },
		{ value: 'dark', label: 'Dark' },
		{ value: 'system', label: 'System' }
	];
</script>

<!--
	A radio group, not a two-state toggle, because "follow the system" is a real third choice
	and a toggle cannot express it.

	`fieldset`/`legend` gives the group an accessible name without inventing ARIA: native
	grouping semantics are better supported than `role="radiogroup"`, and arrow-key
	navigation between radios comes free.
-->
<fieldset class="group">
	<legend class="sr-only">Colour theme</legend>
	{#each options as option (option.value)}
		<label class="option">
			<input
				type="radio"
				name="theme"
				value={option.value}
				checked={theme.current === option.value}
				onchange={() => theme.set(option.value)}
			/>
			<span>{option.label}</span>
		</label>
	{/each}
</fieldset>

<style>
	.group {
		display: flex;
		gap: var(--space-1);
		margin: 0;
		padding: var(--space-1);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		background: var(--surface);
	}

	.option {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-3);
		border-radius: var(--radius-sm);
		cursor: pointer;
		font-size: var(--step--1);
	}

	/* The checked state is carried by the native radio *and* by the background, so it is not
	   conveyed by colour alone. */
	.option:has(input:checked) {
		background: var(--accent-quiet);
		font-weight: 600;
	}

	.option:hover {
		background: var(--surface-2);
	}
</style>
