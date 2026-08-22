// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	kit: {
		// A static SPA. There is no server: the vault is a WebAssembly module in the tab,
		// so there is nothing for a backend to do and nothing it could be trusted with.
		// `fallback` makes every route resolve to the same shell, which is what lets the
		// app work from a file host and, in P9, from a service worker offline.
		adapter: adapter({ fallback: 'index.html', strict: true }),

		// SPEC §9: "CSP with no `unsafe-inline` on web and extension". `mode: 'hash'` makes
		// SvelteKit hash the small bootstrap script it injects instead of asking for
		// `unsafe-inline`, so the policy below has no escape hatch in it.
		csp: {
			mode: 'hash',
			directives: {
				// Deny by default and name every exception, so a directive nobody thought
				// about fails closed.
				'default-src': ['none'],
				// `wasm-unsafe-eval` is what lets the core load at all. It permits
				// compiling a WebAssembly module and nothing else — it is not
				// `unsafe-eval`, and it does not allow evaluating JavaScript from a
				// string.
				'script-src': ['self', 'wasm-unsafe-eval'],
				'style-src': ['self'],
				// `data:` for the rendered fallback icons. §9 forbids an icon CDN, so
				// every icon is either bundled or drawn locally; nothing is fetched.
				'img-src': ['self', 'data:'],
				'font-src': ['self'],
				// `self` only. §9: no third-party endpoint, no analytics. The mock
				// transport talks to nothing at all; a real build talks to one pinned
				// sync server, which is a shell concern rather than a page one.
				'connect-src': ['self'],
				'manifest-src': ['self'],
				'base-uri': ['none'],
				'form-action': ['none'],
				'frame-ancestors': ['none'],
				'object-src': ['none']
			}
		}
	}
};

export default config;
