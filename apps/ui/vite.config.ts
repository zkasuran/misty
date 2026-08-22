// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// `sveltekit` lives in `@sveltejs/kit/vite`, not in `@sveltejs/vite-plugin-svelte` — the
// plugin package exports the bare Svelte integration, and the Kit one wraps it with
// routing, the CSP handling in svelte.config.js, and the adapter.
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],

	build: {
		// The generated `misty_ffi_bg.wasm` is fetched by the glue at runtime, so it must
		// stay a real file rather than being inlined as a base64 data URL. Vite inlines
		// assets under 4 kB by default; the module is far larger than that, but saying so
		// explicitly means a future smaller build cannot silently change the loading
		// strategy — and an inlined module would need a CSP that allows `data:` in
		// `script-src`, which SPEC §9 does not.
		assetsInlineLimit: 0
	},

	server: {
		// No proxy, no CDN, no external origin: SPEC §9 forbids a third-party endpoint,
		// and the mock core talks to nothing.
		fs: { strict: true }
	}
});
