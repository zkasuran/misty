// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Theme selection: light, dark, or follow the system.
 *
 * The choice is written to `<html data-theme>`, which is what `app.css` keys its token
 * blocks off. `system` is a real third state rather than "whatever we last computed" — a user
 * who has not chosen should track their OS switching to dark at sunset, and collapsing that
 * into a stored `light` at first paint is a common bug.
 *
 * The preference is the only thing this app persists, and it is deliberately not a secret:
 * `localStorage` is readable by anything with access to the browser profile, which is why
 * SPEC §9.1 keeps every key out of it. A theme name is not vault data.
 */

export type Theme = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'misty:theme';

function isTheme(value: unknown): value is Theme {
	return value === 'light' || value === 'dark' || value === 'system';
}

class ThemeState {
	current = $state<Theme>('system');

	/**
	 * Adopt the stored preference. Called once from the layout.
	 *
	 * `app.html` ships `data-theme="system"`, so the pre-JS render is already correct for
	 * anyone who has not chosen — there is no flash of the wrong theme to work around.
	 */
	load(): void {
		let stored: string | null = null;
		try {
			stored = localStorage.getItem(STORAGE_KEY);
		} catch {
			// Storage can throw outright when cookies are blocked or the profile is in a
			// restricted mode. A theme is not worth failing a page load over.
		}
		if (isTheme(stored)) this.current = stored;
		this.#apply();
	}

	set(theme: Theme): void {
		this.current = theme;
		try {
			localStorage.setItem(STORAGE_KEY, theme);
		} catch {
			// As above: the choice still applies for this session.
		}
		this.#apply();
	}

	#apply(): void {
		document.documentElement.dataset.theme = this.current;
	}
}

export const theme = new ThemeState();
