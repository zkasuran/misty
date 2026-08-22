// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * This route cannot be prerendered, and that is not a limitation to work around.
 *
 * Item ids are derived from vault contents. Prerendering would mean enumerating them at build
 * time, which would require a build machine to open a vault — the exact thing this
 * architecture exists to make impossible. The layout's `prerender = true` covers the static
 * routes; this one is served by `adapter-static`'s fallback and rendered in the tab from the
 * vault already in memory.
 */
export const prerender = false;
