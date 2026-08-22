// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The P6 exit gate: full flows against the mock core.
 *
 * "Against the mock core" is the load-bearing phrase. There is no stubbed API and no
 * intercepted network here — every assertion below is the real Rust vault answering, compiled
 * to WebAssembly and running in the page, with `MemoryStore` and `MockTransport` in place of
 * the disk and the network (SPEC §11.8.1). When a test says an item was trashed and restored,
 * the real CRDT tombstone was written and cleared.
 *
 * The vault is in memory and scoped to a page load, so each test starts from an empty vault
 * with no cleanup needed. That is also why the flows are written as a few long tests rather
 * than many short ones: `lock` after `unlock` is the property being checked, not an accident
 * of ordering, and splitting them would mean re-establishing state through the UI repeatedly.
 */

import { expect, test, type Page } from '@playwright/test';

/**
 * Base32 of the shared §11.8.2 fixture secret (bytes 01..0a).
 *
 * Using the conformance fixture rather than an arbitrary secret means the code this UI
 * displays is the *same literal* the other four bindings assert — so if the browser ever
 * disagreed with Swift, Kotlin, or the native facade, this test would catch it too.
 */
const FIXTURE_SECRET_BASE32 = 'AEBAGBAFAYDQQCIK';

/** The code that secret yields under the pinned clock. Same value as every conformance leg. */
const EXPECTED_CODE = '746722';

const ISSUER = 'GitHub';
const ACCOUNT = 'ada@example.com';

/**
 * A link in the section navigation.
 *
 * Scoped to the `navigation` landmark rather than the whole page, because "Add" also appears
 * as "Add one" in the empty state and an unscoped role query matches both. Scoping is the
 * better fix than `exact: true`: it asserts the landmark exists and is named, which is the
 * a11y property the layout is supposed to provide, and it keeps the test insensitive to
 * wording changes elsewhere on the page.
 */
function navLink(page: Page, name: string) {
	return page.getByRole('navigation', { name: 'Sections' }).getByRole('link', { name, exact: true });
}

/** Unlock the vault and wait for the code list. */
async function unlock(page: Page): Promise<void> {
	await page.goto('/');
	await page.getByTestId('unlock').click();
	await expect(page.getByRole('heading', { name: 'Codes' })).toBeVisible();
}

/** Add the fixture code through the real form. */
async function addFixtureCode(page: Page, overrides?: { nickname?: string }): Promise<void> {
	await navLink(page, 'Add').click();
	await expect(page.getByRole('heading', { name: 'Add a code' })).toBeVisible();
	await page.getByTestId('issuer').fill(ISSUER);
	await page.getByTestId('account').fill(ACCOUNT);
	await page.getByTestId('secret').fill(FIXTURE_SECRET_BASE32);
	if (overrides?.nickname) await page.getByTestId('nickname').fill(overrides.nickname);
	await page.getByTestId('save').click();
	// Saving navigates back to the list only on success.
	await expect(page.getByRole('heading', { name: 'Codes' })).toBeVisible();
}

test('unlock, add, generate, and the code matches every other binding', async ({ page }) => {
	await page.goto('/');

	// The vault starts locked. §11.5: the facade decides this, not the shell.
	await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
	// The mock badge is permanent, so nobody mistakes this for a persistent vault.
	await expect(page.getByTestId('mock-badge')).toBeVisible();

	await page.getByTestId('unlock').click();
	await expect(page.getByTestId('count')).toHaveText('0 codes');

	await addFixtureCode(page);

	await expect(page.getByTestId('count')).toHaveText('1 code');
	const tile = page.getByTestId('code-tile');
	await expect(tile.getByRole('heading', { name: ISSUER })).toBeVisible();
	// The exact code, not merely six digits: the clock is pinned, so a binding that lowered
	// the secret or the algorithm wrongly would still produce six of something.
	await expect(page.getByTestId('code-plain')).toHaveText(EXPECTED_CODE);
	// And the grouped presentation a user actually reads.
	await expect(page.getByTestId('code')).toHaveText('746 722');
	// The countdown is running rather than stuck.
	// The element deliberately carries a visually-hidden suffix for screen readers, so this
	// matches the visible prefix rather than the whole accessible text.
	await expect(page.getByTestId('seconds')).toHaveText(/^\d+s\b/);
});

test('a bad secret is rejected with the message beside the field', async ({ page }) => {
	await unlock(page);
	await navLink(page, 'Add').click();

	await page.getByTestId('issuer').fill(ISSUER);
	await page.getByTestId('account').fill(ACCOUNT);
	// `1` and `8` are not in the RFC 4648 alphabet.
	await page.getByTestId('secret').fill('AEBAGBAF18');
	await page.getByTestId('save').click();

	// Still on the form, with the field marked invalid and described by the error.
	await expect(page.getByRole('heading', { name: 'Add a code' })).toBeVisible();
	const secret = page.getByTestId('secret');
	await expect(secret).toHaveAttribute('aria-invalid', 'true');
	const describedBy = await secret.getAttribute('aria-describedby');
	expect(describedBy).toContain('secret-error');
	await expect(page.locator('#secret-error')).toContainText('not a base32 character');
	// Focus moved to the offending field, so a keyboard user is not left guessing.
	await expect(secret).toBeFocused();
});

test('search and sort narrow the list', async ({ page }) => {
	await unlock(page);
	await addFixtureCode(page);

	// A second item so filtering is observable.
	await navLink(page, 'Add').click();
	await page.getByTestId('issuer').fill('Fastmail');
	await page.getByTestId('account').fill('ada@fastmail.com');
	await page.getByTestId('secret').fill(FIXTURE_SECRET_BASE32);
	await page.getByTestId('nickname').fill('mail');
	await page.getByTestId('save').click();
	await expect(page.getByTestId('count')).toHaveText('2 codes');

	await page.getByTestId('search').fill('Fastmail');
	await expect(page.getByTestId('count')).toHaveText(/1 code matching/);
	await expect(page.getByTestId('code-tile')).toHaveCount(1);

	// Sort is disabled while searching, because results are relevance-ranked.
	await expect(page.getByTestId('sort')).toBeDisabled();

	await page.getByTestId('search').fill('');
	await expect(page.getByTestId('count')).toHaveText('2 codes');
	await expect(page.getByTestId('sort')).toBeEnabled();

	await page.getByTestId('sort').selectOption('Created');
	await expect(page.getByTestId('code-tile')).toHaveCount(2);
});

test('editing an item is a sparse update, and clearing a field is not the same as blanking it', async ({
	page
}) => {
	await unlock(page);
	await addFixtureCode(page, { nickname: 'work' });

	await page.getByRole('link', { name: /^Details/ }).click();
	await expect(page.getByRole('heading', { name: ISSUER })).toBeVisible();

	// Change the nickname.
	await page.getByTestId('nickname').fill('work github');
	await page.getByTestId('save').click();
	await expect(page.getByTestId('saved')).toHaveText('Changes saved.');

	// The list reflects it — the projection was re-read from the core, not patched locally.
	await navLink(page, 'Codes').click();
	await expect(page.getByTestId('code-tile')).toContainText('work github');

	// Emptying the field clears it rather than storing an empty string.
	await page.getByRole('link', { name: /^Details/ }).click();
	await page.getByTestId('nickname').fill('');
	await page.getByTestId('save').click();
	await expect(page.getByTestId('saved')).toHaveText('Changes saved.');
	await navLink(page, 'Codes').click();
	// Falls back to the account, which is what "no nickname" renders as.
	await expect(page.getByTestId('code-tile')).toContainText(ACCOUNT);
});

test('groups can be created and assigned', async ({ page }) => {
	await unlock(page);
	await addFixtureCode(page);

	await navLink(page, 'Groups').click();
	await expect(page.getByTestId('group-count')).toHaveText('0 groups');
	await page.getByTestId('group-name').fill('Work');
	await page.getByTestId('add-group').click();
	await expect(page.getByTestId('group-count')).toHaveText('1 group');

	// Assign it from the item page.
	await navLink(page, 'Codes').click();
	await page.getByRole('link', { name: /^Details/ }).click();
	await page.getByRole('checkbox', { name: 'Work' }).check();
	await page.getByTestId('save').click();
	await expect(page.getByTestId('saved')).toHaveText('Changes saved.');
	await expect(page.getByRole('checkbox', { name: 'Work' })).toBeChecked();
});

test('trash, restore, then delete permanently', async ({ page }) => {
	await unlock(page);
	await addFixtureCode(page);

	await page.getByRole('link', { name: /^Details/ }).click();
	await page.getByTestId('trash').click();
	await expect(page.getByTestId('count')).toHaveText('0 codes');

	await navLink(page, 'Trash').click();
	await expect(page.getByTestId('trash-count')).toHaveText('1 item');

	await page.getByTestId('restore').click();
	await expect(page.getByTestId('trash-count')).toHaveText('0 items');
	await navLink(page, 'Codes').click();
	await expect(page.getByTestId('count')).toHaveText('1 code');

	// Back to the trash and delete for good. Deletion takes two clicks on purpose.
	await page.getByRole('link', { name: /^Details/ }).click();
	await page.getByTestId('trash').click();
	await navLink(page, 'Trash').click();
	await page.getByTestId('delete').click();
	await page.getByTestId('confirm-delete').click();
	await expect(page.getByTestId('trash-count')).toHaveText('0 items');
});

test('sync reports what it did, and revoking a device keeps the codes working', async ({
	page
}) => {
	await unlock(page);
	await addFixtureCode(page);

	await navLink(page, 'Settings').click();
	await page.getByTestId('sync').click();
	// One item pushed to the in-process mock server.
	await expect(page.getByTestId('sync-report')).toContainText('Pushed');
	await expect(page.getByTestId('sync-report')).toContainText('1');

	// Revocation rotates the epoch and re-seals the vault under a successor roster (§6.4).
	await page.getByTestId('revoke').click();
	await expect(page.getByTestId('revoked')).toContainText('re-sealed');

	// The code survives the rotation — the same literal as before.
	await navLink(page, 'Codes').click();
	await expect(page.getByTestId('code-plain')).toHaveText(EXPECTED_CODE);
});

test('locking clears the projection and the codes are gone from the DOM', async ({ page }) => {
	await unlock(page);
	await addFixtureCode(page);
	await expect(page.getByTestId('code-plain')).toHaveText(EXPECTED_CODE);

	await page.getByTestId('lock').click();

	await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
	// Not merely hidden: the decrypted labels and the code must not still be in the document
	// after the key is gone.
	await expect(page.getByTestId('code-tile')).toHaveCount(0);
	expect(await page.content()).not.toContain(EXPECTED_CODE);
	expect(await page.content()).not.toContain(ACCOUNT);
});

test('backgrounding the tab locks the vault and obscures the view', async ({ page }) => {
	await unlock(page);
	await addFixtureCode(page);

	// Drive the real event the shell listens for, rather than calling into the app.
	await page.evaluate(() => {
		Object.defineProperty(document, 'visibilityState', {
			configurable: true,
			get: () => 'hidden'
		});
		document.dispatchEvent(new Event('visibilitychange'));
	});

	// §9: blurred on background, and §11.5.5: the facade locks on the reported event.
	await expect(page.locator('.shell')).toHaveAttribute('data-obscured', 'true');
	await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
});

test('copying a code puts it on the clipboard and counts as a use', async ({ page, context }) => {
	await context.grantPermissions(['clipboard-read', 'clipboard-write']);
	await unlock(page);
	await addFixtureCode(page);

	await page.getByTestId('copy').click();
	await expect(page.getByTestId('code-tile')).toContainText('Copied.');

	const clipboard = await page.evaluate(() => navigator.clipboard.readText());
	expect(clipboard).toBe(EXPECTED_CODE);

	// The use count lives in the vault, so the item page is the proof it was recorded.
	await page.getByRole('link', { name: /^Details/ }).click();
	await expect(page.getByRole('definition').filter({ hasText: 'time' })).toContainText('1 time');
});
