// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The vault lives in WebAssembly in the tab, so every route is client-only.
 *
 * `ssr = false` is not a performance choice. Rendering on a server would mean a server
 * that holds vault state, and there is deliberately no such thing: the sync server is a
 * zero-knowledge blob store that cannot open an envelope (SPEC §6). Prerendering the
 * shell is still worth it — it is the same static HTML for every route, which is what
 * `adapter-static`'s fallback needs.
 */
export const ssr = false;
export const prerender = true;

/** Preload on hover; there is no network round trip to save, only parse time. */
export const trailingSlash = 'never';
