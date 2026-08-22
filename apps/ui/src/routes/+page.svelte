<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later

	Placeholder: replaced once the core client lands. Present only so the scaffold builds
	and the wasm loading path can be verified before any UI is written against it.
-->
<script lang="ts">
	import { onMount } from 'svelte';

	let status = $state('loading the core…');

	onMount(async () => {
		// Report the failure into the page. An unhandled rejection here leaves the status
		// stuck on "loading" and tells you nothing, which cost a debugging round already.
		try {
			const core = await import('$lib/core/pkg/misty_ffi.js');
			await core.default();
			const facade = new core.MistyFacade();
			const state = await facade.lockState();
			status = `core loaded; locked=${state.locked}`;
			await facade.shutdown();
		} catch (error) {
			status = `core failed: ${error instanceof Error ? error.message : String(error)}`;
		}
	});
</script>

<main>
	<h1>Misty</h1>
	<p data-testid="probe">{status}</p>
</main>
