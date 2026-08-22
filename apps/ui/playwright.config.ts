// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineConfig, devices } from '@playwright/test';

/**
 * The tests run against the **production build**, served by `vite preview`, not against
 * the dev server.
 *
 * That is the artifact worth auditing. The dev server injects styles inline and relaxes
 * things a bundler tightens; the P6 gate is about the app a user would actually load, and
 * the SPEC §9 CSP only exists in the built output. Testing `dev` would pass while shipping
 * something different.
 */
export default defineConfig({
	testDir: 'tests',
	// The flows share one vault, so each spec file is ordered internally but files run in
	// parallel. Serial within a file is a property of the flows themselves: `lock` after
	// `unlock` is the point, not an accident of scheduling.
	fullyParallel: false,
	workers: 1,
	forbidOnly: !!process.env.CI,
	retries: 0,
	reporter: process.env.CI ? [['github'], ['list']] : [['list']],

	use: {
		baseURL: 'http://127.0.0.1:4173',
		trace: 'retain-on-failure',
		screenshot: 'only-on-failure',
		// The code countdown is real time. A generous action timeout keeps a slow CI box
		// from failing on a repaint rather than on a bug.
		actionTimeout: 15_000
	},

	projects: [
		{
			name: 'chromium',
			use: { ...devices['Desktop Chrome'] }
		}
	],

	webServer: {
		// `preview` serves `build/`, which `npm run build` produced from the release core.
		command: 'npm run preview -- --port 4173 --strictPort',
		url: 'http://127.0.0.1:4173',
		reuseExistingServer: !process.env.CI,
		timeout: 120_000
	}
});
