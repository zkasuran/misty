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
	},

	preview: {
		// Bind an explicit IPv4 address rather than letting it default to `localhost`.
		//
		// `localhost` resolves to both `::1` and `127.0.0.1`, and which one a listener ends up
		// on depends on the host's resolver order. On a machine with no IPv6 that is always
		// `127.0.0.1`; on a GitHub runner it can be `::1`, and then a test harness polling
		// `http://127.0.0.1:4173` waits forever and reports only "timed out waiting for the web
		// server" with no hint as to why. Naming the address makes local and CI identical.
		host: '127.0.0.1',
		port: 4173,
		// Fail loudly if the port is taken instead of quietly serving on another one, which
		// produces the same unexplained timeout.
		strictPort: true
	}
});
