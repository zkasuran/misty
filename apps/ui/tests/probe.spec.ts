// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The load-bearing question for the whole app: does the real Rust core start in a browser,
 * under the SPEC §9 CSP, from the production build?
 *
 * Every other spec assumes it. Keeping it separate means a failure here is unambiguous — the
 * core did not start — rather than surfacing as twenty confusing flow failures.
 *
 * The signal that it started is the locked gate. `session.phase` begins at `starting` and only
 * becomes `locked` once the WebAssembly module has loaded, the facade has been constructed, and
 * it has answered a `lockState` call. So "Vault locked" being on screen means the whole chain
 * worked — and that it says *locked* rather than unlocked is itself §11.5 being honoured, since
 * the facade decides that and not the page.
 */

import { expect, test } from '@playwright/test';

test('the real core starts in the browser under the production CSP', async ({ page }) => {
	const failures: string[] = [];
	page.on('pageerror', (error) => failures.push(String(error)));

	await page.goto('/');

	// Not `starting`, and not a crash: the core answered.
	await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible({
		timeout: 30_000
	});
	await expect(page.getByTestId('starting')).toHaveCount(0);
	await expect(page.getByTestId('unlock')).toBeEnabled();

	expect(failures, 'no uncaught errors while starting the core').toEqual([]);
});

test('the production build ships a CSP with no unsafe-inline', async ({ page }) => {
	await page.goto('/');
	const policy = await page
		.locator('meta[http-equiv="content-security-policy"]')
		.getAttribute('content');

	expect(policy, 'the built shell carries a CSP').toBeTruthy();
	expect(policy).toContain("default-src 'none'");
	// `wasm-unsafe-eval` is required to compile the core and is permitted. `unsafe-inline`, a
	// bare `unsafe-eval`, and `unsafe-hashes` are not (SPEC §9).
	expect(policy).not.toContain("'unsafe-inline'");
	expect(policy).not.toContain("'unsafe-hashes'");
	expect(policy?.replace(/'wasm-unsafe-eval'/g, '')).not.toContain('unsafe-eval');
});

/**
 * `style-src 'self'` blocks inline style *attributes*, and a blocked declaration is dropped
 * silently — a styling bug that appears only in the production build and never in dev. This
 * pins the two things that follow from that.
 *
 * **What is allowed.** A CSP `style-src` policy governs styles the parser reads from markup and
 * writes made through `setAttribute('style', …)`. It does **not** police the CSSOM, so
 * `element.style.setProperty(…)` is fine — which is what Svelte's `style:` directive compiles
 * to, and what the countdown ring in `CodeTile.svelte` relies on. Note that such a write still
 * *reflects* into a `style` attribute in the DOM, so counting elements with `[style]` proves
 * nothing either way; the meaningful question is whether the browser refused anything.
 *
 * **What is not.** Exactly one violation is expected, and it is not ours: SvelteKit's route
 * announcer positions itself with an authored inline style. That one is genuinely blocked, which
 * is why `app.css` hides the element from the stylesheet instead — and why this test also checks
 * it is invisible. Anything beyond that single `style-src-attr` report means our own markup grew
 * a `style="…"`, or something worse tripped a different directive.
 */
test('the page does not trip its own CSP, beyond the framework announcer', async ({ page }) => {
	await page.addInitScript(() => {
		(window as Window & { __violations?: string[] }).__violations = [];
		document.addEventListener('securitypolicyviolation', (event) => {
			(window as Window & { __violations?: string[] }).__violations?.push(
				event.violatedDirective
			);
		});
	});

	await page.goto('/');
	await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible({
		timeout: 30_000
	});

	// Reach the screens that actually write styles at runtime, not just the gate.
	await page.getByTestId('unlock').click();
	const nav = page.getByRole('navigation', { name: 'Sections' });
	await nav.getByRole('link', { name: 'Add', exact: true }).click();
	await page.getByTestId('issuer').fill('GitHub');
	await page.getByTestId('account').fill('ada@example.com');
	await page.getByTestId('secret').fill('AEBAGBAFAYDQQCIK');
	await page.getByTestId('save').click();
	await expect(page.getByTestId('code-tile')).toBeVisible();

	const violations = await page.evaluate(
		() => (window as Window & { __violations?: string[] }).__violations ?? []
	);

	// Only the announcer's, and only ever that directive.
	expect(violations.filter((directive) => directive !== 'style-src-attr')).toEqual([]);
	expect(
		violations.length,
		'one blocked inline style attribute is expected: SvelteKit\'s route announcer'
	).toBeLessThanOrEqual(1);

	// The countdown ring proves a CSSOM write is *not* blocked: if it were, the computed value
	// would stay at the stylesheet default and the ring would never move.
	const dashoffset = await page
		.locator('.ring-progress')
		.evaluate((element) => getComputedStyle(element).strokeDashoffset);
	expect(dashoffset, 'the ring is being driven through the CSSOM').not.toBe('none');
	expect(parseFloat(dashoffset)).toBeGreaterThanOrEqual(0);

	// Blocked inline style or not, the announcer must not be visible to a sighted user.
	const announcer = page.locator('#svelte-announcer');
	const box = await announcer.boundingBox();
	expect(box, 'the announcer is in the DOM').not.toBeNull();
	expect(box!.width, 'the announcer is visually hidden by the stylesheet').toBeLessThanOrEqual(2);
	expect(box!.height).toBeLessThanOrEqual(2);
	// It must still be a live region, or the navigation announcement is lost.
	await expect(announcer).toHaveAttribute('aria-live', /assertive|polite/);
});

/**
 * The built markup itself must contain no authored `style` attribute.
 *
 * Separate from the runtime check because they catch different mistakes: this one catches a
 * `style="…"` written into a template, which would be blocked and silently dropped, and it does
 * so by reading the shipped HTML rather than by inspecting a live DOM where CSSOM reflections
 * are indistinguishable from authored attributes.
 */
test('the built shell contains no authored style attribute', async ({ request }) => {
	const response = await request.get('/');
	const html = await response.text();
	// Strip comments first: this repo's templates explain the rule in prose, and the words
	// `style="…"` appear there legitimately.
	const withoutComments = html.replace(/<!--[\s\S]*?-->/g, '');
	expect(withoutComments).not.toMatch(/<[^>]+\sstyle=/i);
});
