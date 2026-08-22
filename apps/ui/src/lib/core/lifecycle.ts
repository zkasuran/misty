// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The shell's minimal responsibility (SPEC §11.5.5), and the §9 hardening that goes with it.
 *
 * The division of labour is deliberate and worth stating, because getting it backwards is
 * how auto-lock quietly stops working: **the shell reports, the facade decides.** Nothing
 * here holds a timer that locks the vault, computes a deadline, or decides that enough time
 * has passed. It observes browser events, tells the core what happened, and renders whatever
 * lock state comes back.
 *
 * §11.5 makes auto-lock a stored absolute deadline that the actor evaluates on every command
 * and on every wake, rather than a timer — precisely so that a suspended tab, a slept
 * laptop, and a reaped service worker are all the same event. A timer in this file would
 * reintroduce the thing that design avoids: it would not fire while the tab was frozen, and
 * the vault would come back unlocked after an hour asleep.
 *
 * What the shell owes the core, from §9's table:
 *
 *  - **Auto-lock on background, screen lock, and device sleep.** Reported as lifecycle
 *    events; the core locks immediately on each.
 *  - **Auto-lock on timeout.** Not reported at all — the core owns the deadline. The shell's
 *    job is only to give it opportunities to notice, which is what {@link poll} is for.
 *  - **Blurred on background everywhere.** A presentation concern, applied immediately on
 *    the same events, because the lock is asynchronous and a frame can be captured in
 *    between.
 */

import type { MistyCore } from './client';
import type { LockState } from './types';

/**
 * How often to give the core a chance to notice its own deadline while the tab is visible
 * and idle.
 *
 * §11.5.4 pairs the wake-checked deadline with "a facade-owned wake-only poll, so a live but
 * idle process still zeroizes its key". A tab that is open and untouched never wakes, so
 * without this the 60-second timeout would not fire until the next user action — which is
 * the one moment it does not matter. Five seconds bounds the overshoot at a twelfth of the
 * timeout while costing one channel round trip.
 */
const IDLE_POLL_MS = 5_000;

/**
 * How long to coalesce user activity before telling the core about it.
 *
 * Every keystroke and pointer move is activity; forwarding each one would be thousands of
 * channel messages a minute to move a deadline that only matters at second granularity.
 */
const ACTIVITY_THROTTLE_MS = 1_000;

export interface ShellCallbacks {
	/** Called whenever the core reports a lock state, so the app can re-render. */
	onLockState: (state: LockState) => void;
	/**
	 * Called when the view should be obscured or revealed (§9: "blurred on background
	 * everywhere"). Separate from the lock state because it must happen *now*, without
	 * waiting for a round trip to the core.
	 */
	onObscured: (obscured: boolean) => void;
	/** Called when talking to the core fails. Lock state is too important to swallow. */
	onError?: (error: unknown) => void;
}

/**
 * Wire the document's lifecycle to the core. Returns a teardown function.
 *
 * Safe to call only in the browser; there is no server-side rendering in this app
 * (`+layout.ts` sets `ssr = false`), so `document` is always present.
 */
export function installShell(core: MistyCore, callbacks: ShellCallbacks): () => void {
	const { onLockState, onObscured, onError } = callbacks;
	let disposed = false;
	let lastActivity = 0;

	const report = (error: unknown) => {
		if (!disposed) onError?.(error);
	};

	/** Push a lock state to the app unless we have already been torn down. */
	const publish = (state: LockState) => {
		if (!disposed) onLockState(state);
	};

	const poll = () => {
		core.poll().then(publish).catch(report);
	};

	const hidden = () => {
		// Obscure first and synchronously. The core's lock is a round trip away, and a
		// screenshot or an app-switcher thumbnail can be taken in that window — which is
		// exactly what §9's "blurred on background" is for.
		onObscured(true);
		core.reportLifecycle('Backgrounded').then(publish).catch(report);
	};

	const shown = () => {
		onObscured(false);
		// Do not assume the vault survived. The deadline may have passed while hidden, and
		// the authoritative answer comes from the core.
		poll();
	};

	const onVisibilityChange = () => {
		if (document.visibilityState === 'hidden') hidden();
		else shown();
	};

	/**
	 * Losing window focus is not the same as being hidden — another window may be covering
	 * this one, or a screen share may be running — so it obscures the view without being
	 * treated as backgrounding.
	 */
	const onBlur = () => onObscured(true);
	const onFocus = () => {
		onObscured(false);
		poll();
	};

	const onActivity = () => {
		const now = Date.now();
		if (now - lastActivity < ACTIVITY_THROTTLE_MS) return;
		lastActivity = now;
		core.reportLifecycle('UserActivity').then(publish).catch(report);
	};

	/**
	 * `freeze` and `resume` are the Page Lifecycle API's version of the same story, and they
	 * fire where `visibilitychange` does not: a tab discarded on a memory-constrained device.
	 * `WillSleep` is the closest report — §11.5.5's point is that the shell says what
	 * happened and lets the facade choose, so a frozen tab and a sleeping laptop reporting
	 * the same thing is correct rather than lossy.
	 */
	const onFreeze = () => {
		onObscured(true);
		core.reportLifecycle('WillSleep').then(publish).catch(report);
	};

	document.addEventListener('visibilitychange', onVisibilityChange);
	window.addEventListener('blur', onBlur);
	window.addEventListener('focus', onFocus);
	window.addEventListener('freeze', onFreeze);
	window.addEventListener('resume', shown);
	// `pagehide` covers a navigation away and, on iOS, the cases where `visibilitychange`
	// historically did not fire.
	window.addEventListener('pagehide', hidden);

	for (const event of ['pointerdown', 'keydown', 'wheel'] as const) {
		// Passive: none of these are cancelled, and saying so keeps scrolling smooth.
		window.addEventListener(event, onActivity, { passive: true });
	}

	const interval = window.setInterval(() => {
		// Only while visible. A hidden tab has already been locked by the `Backgrounded`
		// report, and browsers throttle timers there anyway — relying on this to lock a
		// backgrounded tab is exactly the mistake §11.5 is written to prevent.
		if (document.visibilityState === 'visible') poll();
	}, IDLE_POLL_MS);

	// Establish the current state rather than assuming unlocked.
	core.lockState().then(publish).catch(report);

	return () => {
		disposed = true;
		window.clearInterval(interval);
		document.removeEventListener('visibilitychange', onVisibilityChange);
		window.removeEventListener('blur', onBlur);
		window.removeEventListener('focus', onFocus);
		window.removeEventListener('freeze', onFreeze);
		window.removeEventListener('resume', shown);
		window.removeEventListener('pagehide', hidden);
		for (const event of ['pointerdown', 'keydown', 'wheel'] as const) {
			window.removeEventListener(event, onActivity);
		}
	};
}

/**
 * Copy text to the clipboard and clear it again after a delay.
 *
 * §9: "Clipboard — auto-clear after 20s, marked sensitive/no-history on Android and
 * Windows." The marking is a platform capability the web does not have, and saying so is
 * better than implying otherwise: on the web this is a timed overwrite and nothing more. A
 * clipboard manager that keeps history will still have the code, and §9.1's residual-risk
 * discipline says to state that rather than bury it.
 *
 * The overwrite is conditional: if the user has copied something else in the meantime,
 * clearing would destroy their data rather than ours. There is no way to read the clipboard
 * without a permission prompt, so the check is "did we succeed in writing, and has nothing
 * else been copied through us since".
 */
export const CLIPBOARD_CLEAR_MS = 20_000;

let clipboardToken = 0;

export async function copyEphemeral(
	text: string,
	afterClear?: () => void
): Promise<'copied' | 'unsupported' | 'denied'> {
	if (!navigator.clipboard?.writeText) return 'unsupported';
	const token = ++clipboardToken;
	try {
		await navigator.clipboard.writeText(text);
	} catch {
		// Denied, or the document was not focused. Either way the code is not on the
		// clipboard, so there is nothing to schedule.
		return 'denied';
	}

	window.setTimeout(() => {
		// Someone else copied through us since; leave their content alone.
		if (token !== clipboardToken) return;
		navigator.clipboard.writeText('').catch(() => {
			// Clearing can fail if the document lost focus. Nothing useful to do, and
			// nothing worth telling the user — the code has expired by now regardless.
		});
		afterClear?.();
	}, CLIPBOARD_CLEAR_MS);

	return 'copied';
}
