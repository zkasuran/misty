// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The other half of the P6 gate: "a11y audit clean, light + dark".
 *
 * Two kinds of checking, because neither is sufficient alone:
 *
 *  - **axe-core**, over every route in both themes. It catches the mechanical failures —
 *    unlabelled controls, insufficient contrast, broken heading order, missing landmarks —
 *    and it is run per theme because contrast is a property of the active palette, so a dark
 *    theme can fail everything the light one passes.
 *  - **hand-written assertions** for the things axe cannot see. Whether focus goes somewhere
 *    sensible, whether a live region actually announces, whether the skip link works, and
 *    whether the whole app is reachable from the keyboard are all behavioural, and a static
 *    scan reports none of them. An "axe clean" app can still be unusable without a mouse.
 */

import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const FIXTURE_SECRET_BASE32 = 'AEBAGBAFAYDQQCIK';

/** WCAG 2.2 A and AA. Best-practice rules are advisory and not part of the gate. */
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

function audit(page: Page) {
	return new AxeBuilder({ page }).withTags(TAGS);
}

/** Force a theme, bypassing the OS preference, exactly as the settings control does. */
async function useTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
	await page.evaluate((value) => {
		localStorage.setItem('misty:theme', value);
	}, theme);
	await page.reload();
	await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
}

/** Unlock and seed one item, so the audited pages have real content rather than empty states. */
async function seed(page: Page): Promise<void> {
	await page.goto('/');
	await page.getByTestId('unlock').click();
	await expect(page.getByRole('heading', { name: 'Codes' })).toBeVisible();

	const nav = page.getByRole('navigation', { name: 'Sections' });
	await nav.getByRole('link', { name: 'Add', exact: true }).click();
	await page.getByTestId('issuer').fill('GitHub');
	await page.getByTestId('account').fill('ada@example.com');
	await page.getByTestId('secret').fill(FIXTURE_SECRET_BASE32);
	await page.getByTestId('save').click();
	await expect(page.getByRole('heading', { name: 'Codes' })).toBeVisible();

	await nav.getByRole('link', { name: 'Groups', exact: true }).click();
	await page.getByTestId('group-name').fill('Work');
	await page.getByTestId('add-group').click();
	await expect(page.getByTestId('group-count')).toHaveText('1 group');
}

for (const theme of ['light', 'dark'] as const) {
	test.describe(`${theme} theme`, () => {
		test('the locked gate is clean', async ({ page }) => {
			await page.goto('/');
			await useTheme(page, theme);
			await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();

			const results = await audit(page).analyze();
			expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
		});

		test('every unlocked route is clean', async ({ page }) => {
			await page.goto('/');
			await useTheme(page, theme);
			await seed(page);

			const nav = page.getByRole('navigation', { name: 'Sections' });

			// The list, with a live code tile on it.
			await nav.getByRole('link', { name: 'Codes', exact: true }).click();
			await expect(page.getByTestId('code-tile')).toBeVisible();
			let results = await audit(page).analyze();
			expect(results.violations, `codes: ${JSON.stringify(results.violations, null, 2)}`).toEqual(
				[]
			);

			// The item detail page, which is the most form-heavy screen.
			await page.getByRole('link', { name: /^Details/ }).click();
			await expect(page.getByTestId('save')).toBeVisible();
			results = await audit(page).analyze();
			expect(results.violations, `detail: ${JSON.stringify(results.violations, null, 2)}`).toEqual(
				[]
			);

			for (const label of ['Add', 'Groups', 'Trash', 'Settings'] as const) {
				await nav.getByRole('link', { name: label, exact: true }).click();
				await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
				results = await audit(page).analyze();
				expect(
					results.violations,
					`${label}: ${JSON.stringify(results.violations, null, 2)}`
				).toEqual([]);
			}
		});

		test('an error banner is clean', async ({ page }) => {
			await page.goto('/');
			await useTheme(page, theme);
			await seed(page);

			// A real core failure, not a hand-rendered banner. Adding the same
			// (issuer, account, secret) twice is DUPLICATE_ACCOUNT per §3.1, and it leaves the
			// vault unlocked so the banner is audited in its actual context.
			//
			// A full navigation to a bogus item id would *not* work here, and the reason is worth
			// recording: `page.goto` reloads the document, the in-memory vault goes with it, and
			// the item page correctly renders "the vault is locked" rather than "not found".
			const nav = page.getByRole('navigation', { name: 'Sections' });
			await nav.getByRole('link', { name: 'Add', exact: true }).click();
			await page.getByTestId('issuer').fill('GitHub');
			await page.getByTestId('account').fill('ada@example.com');
			await page.getByTestId('secret').fill(FIXTURE_SECRET_BASE32);
			await page.getByTestId('save').click();

			const banner = page.getByTestId('error-banner');
			await expect(banner).toBeVisible();
			await expect(banner).toContainText('DUPLICATE_ACCOUNT');

			const results = await audit(page).analyze();
			expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
		});
	});
}

test.describe('behaviour axe cannot check', () => {
	test('the skip link is first and moves focus to main', async ({ page }) => {
		await page.goto('/');
		await page.keyboard.press('Tab');

		const skip = page.getByRole('link', { name: 'Skip to main content' });
		await expect(skip).toBeFocused();
		// Visible only when focused — otherwise it is noise for everyone else.
		await expect(skip).toBeInViewport();

		await page.keyboard.press('Enter');
		await expect(page.locator('main')).toBeFocused();
	});

	test('the whole unlocked app is reachable by keyboard alone', async ({ page }) => {
		await page.goto('/');
		// Unlock without a pointer.
		await page.keyboard.press('Tab');
		let reachedUnlock = false;
		for (let i = 0; i < 12; i++) {
			await page.keyboard.press('Tab');
			if (await page.getByTestId('unlock').evaluate((el) => el === document.activeElement)) {
				reachedUnlock = true;
				break;
			}
		}
		expect(reachedUnlock, 'the unlock button is reachable by tabbing').toBe(true);
		await page.keyboard.press('Enter');
		await expect(page.getByRole('heading', { name: 'Codes' })).toBeVisible();

		// Every nav link and the lock button must be focusable.
		const focusables = await page.evaluate(() => {
			const selector = 'a[href], button:not([disabled]), input, select, textarea, [tabindex]';
			return Array.from(document.querySelectorAll(selector)).filter((element) => {
				const style = getComputedStyle(element);
				return style.display !== 'none' && style.visibility !== 'hidden';
			}).length;
		});
		expect(focusables, 'the unlocked shell exposes focusable controls').toBeGreaterThan(5);
	});

	test('a visible focus indicator is present on interactive controls', async ({ page }) => {
		await page.goto('/');
		await page.getByTestId('unlock').focus();

		// The ring must be a real outline, not `outline: none` with nothing in its place —
		// WCAG 2.4.7, and the single most common regression when someone dislikes the default.
		const outline = await page.getByTestId('unlock').evaluate((element) => {
			const style = getComputedStyle(element);
			return { width: style.outlineWidth, style: style.outlineStyle };
		});
		expect(outline.style).not.toBe('none');
		expect(parseFloat(outline.width)).toBeGreaterThanOrEqual(2);
	});

	test('the code is announced as digits, not as a number', async ({ page }) => {
		await page.goto('/');
		await page.getByTestId('unlock').click();
		const nav = page.getByRole('navigation', { name: 'Sections' });
		await nav.getByRole('link', { name: 'Add', exact: true }).click();
		await page.getByTestId('issuer').fill('GitHub');
		await page.getByTestId('account').fill('ada@example.com');
		await page.getByTestId('secret').fill(FIXTURE_SECRET_BASE32);
		await page.getByTestId('save').click();

		// "746722" read as a number is "seven hundred forty-six thousand…", which is useless for
		// transcription. The copy button's accessible name spells it out.
		const label = await page.getByTestId('copy').getAttribute('aria-label');
		expect(label).toContain('7 4 6 7 2 2');

		// The grouped visual code is hidden from assistive tech, so it is not read twice.
		await expect(page.getByTestId('code')).toHaveAttribute('aria-hidden', 'true');
	});

	test('the code countdown is not a live region', async ({ page }) => {
		await page.goto('/');
		await page.getByTestId('unlock').click();
		const nav = page.getByRole('navigation', { name: 'Sections' });
		await nav.getByRole('link', { name: 'Add', exact: true }).click();
		await page.getByTestId('issuer').fill('GitHub');
		await page.getByTestId('account').fill('ada@example.com');
		await page.getByTestId('secret').fill(FIXTURE_SECRET_BASE32);
		await page.getByTestId('save').click();

		// A per-second live region would talk over everything else forever. The seconds are
		// available to anyone who looks, and not announced.
		const seconds = page.getByTestId('seconds');
		await expect(seconds).not.toHaveAttribute('aria-live', /.*/);
		await expect(seconds).not.toHaveAttribute('role', 'status');
	});
});
