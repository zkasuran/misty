// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { expect, test } from '@playwright/test';

/**
 * The load-bearing question for the whole app: does the real Rust core start in a browser,
 * under the SPEC §9 CSP, from the production build?
 *
 * Everything else in this suite assumes it. Keeping it as its own spec means a failure here
 * is unambiguous — the core did not load — rather than showing up as forty confusing flow
 * failures.
 */
test('the real core loads in the browser under the production CSP', async ({ page }) => {
	const failures: string[] = [];
	page.on('pageerror', (error) => failures.push(String(error)));

	await page.goto('/');

	await expect(page.getByTestId('probe')).toHaveText(/core loaded; locked=true/, {
		timeout: 30_000
	});

	expect(failures, 'no uncaught errors while starting the core').toEqual([]);
});

test('the production build ships a CSP with no unsafe-inline', async ({ page }) => {
	await page.goto('/');
	const policy = await page
		.locator('meta[http-equiv="content-security-policy"]')
		.getAttribute('content');

	expect(policy, 'the built shell carries a CSP').toBeTruthy();
	expect(policy).toContain("default-src 'none'");
	// `wasm-unsafe-eval` is required to compile the core and is permitted. `unsafe-inline`,
	// a bare `unsafe-eval`, and `unsafe-hashes` are not (SPEC §9).
	expect(policy).not.toContain("'unsafe-inline'");
	expect(policy).not.toContain("'unsafe-hashes'");
	expect(policy?.replace(/'wasm-unsafe-eval'/g, '')).not.toContain('unsafe-eval');
});

/**
 * Nothing this app renders may carry an inline `style` attribute, because `style-src 'self'`
 * blocks it and the declaration is silently dropped — a styling bug that appears only under
 * the production CSP and not in dev.
 *
 * There is exactly one exception, and it is not ours: SvelteKit's route announcer positions
 * itself that way. Its inline style *is* blocked; `app.css` hides the element from the
 * stylesheet instead, which is why this test also checks it is not visible. Pinning the
 * element list means our own code growing a `style="…"` fails here instead of shipping.
 *
 * Where a value genuinely has to be dynamic, Svelte's `style:` directive writes through the
 * CSSOM, which CSP does not police, so this rule costs nothing.
 */
test('no element carries an inline style attribute except the framework announcer', async ({
	page
}) => {
	await page.goto('/');
	await expect(page.getByTestId('probe')).toHaveText(/core loaded/, { timeout: 30_000 });

	const styled = await page.evaluate(() =>
		Array.from(document.querySelectorAll('[style]')).map((element) => ({
			tag: element.tagName.toLowerCase(),
			id: element.id
		}))
	);

	expect(styled).toEqual([{ tag: 'div', id: 'svelte-announcer' }]);

	// Blocked inline style or not, the announcer must not be visible to a sighted user.
	const announcer = page.locator('#svelte-announcer');
	const box = await announcer.boundingBox();
	expect(box, 'the announcer is in the DOM').not.toBeNull();
	expect(box!.width, 'the announcer is visually hidden by the stylesheet').toBeLessThanOrEqual(2);
	expect(box!.height).toBeLessThanOrEqual(2);
	// It must still be a live region, or the navigation announcement is lost.
	await expect(announcer).toHaveAttribute('aria-live', /assertive|polite/);
});
