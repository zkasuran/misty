<!--
	SPDX-FileCopyrightText: 2026 The Misty Authors
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { decodeBase32, describeBase32Failure } from '$lib/core/base32';
	import { newTotpInput, type HashAlg, type OtpKind } from '$lib/core/types';
	import { session } from '$lib/vault/session.svelte';

	let issuer = $state('');
	let account = $state('');
	let secret = $state('');
	let nickname = $state('');
	let group = $state('');
	let kind = $state<OtpKind>('Totp');
	let algorithm = $state<HashAlg>('Sha1');
	let digits = $state(6);
	let period = $state(30);
	let showAdvanced = $state(false);

	/** Client-side field errors, keyed by input id so each can be shown beside its field. */
	let fieldErrors = $state<Record<string, string>>({});

	async function submit(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		const errors: Record<string, string> = {};

		// Only the checks the core cannot make for us, plus decoding. Everything else — secret
		// length, digit range, duplicate detection — is the core's to reject (§7, §3.1), and
		// duplicating those rules here is how two validators drift apart.
		if (!issuer.trim()) errors.issuer = 'Enter the service this code is for.';
		if (!account.trim()) errors.account = 'Enter the account name.';

		const decoded = decodeBase32(secret);
		if (!decoded.ok) errors.secret = describeBase32Failure(decoded.failure);

		fieldErrors = errors;
		if (Object.keys(errors).length > 0) {
			// Move focus to the first field with a problem. Without this a keyboard or screen
			// reader user submits, hears nothing, and has no idea where to look.
			document.getElementById(Object.keys(errors)[0]!)?.focus();
			return;
		}
		if (!decoded.ok) return;

		const id = await session.add(
			newTotpInput({
				issuer: issuer.trim(),
				account: account.trim(),
				secret: decoded.bytes,
				nickname: nickname.trim() || null,
				groups: group ? [group] : [],
				kind,
				algorithm,
				digits,
				period
			})
		);

		// `add` reports failure through `session.error`, which the layout announces. Only
		// navigate on success.
		if (id) await goto('/');
	}
</script>

<h1>Add a code</h1>

<form onsubmit={submit} novalidate>
	<!--
		`novalidate` turns off the browser's own bubbles and hands validation to the code above.
		Native messages cannot be styled, are not announced consistently, and vanish on scroll;
		an error rendered beside the field and wired with `aria-describedby` is read reliably.
	-->
	<div class="field">
		<label for="issuer">Service <span class="req" aria-hidden="true">*</span></label>
		<input
			id="issuer"
			bind:value={issuer}
			required
			aria-required="true"
			aria-invalid={fieldErrors.issuer ? 'true' : undefined}
			aria-describedby={fieldErrors.issuer ? 'issuer-error' : undefined}
			autocomplete="off"
			data-testid="issuer"
		/>
		{#if fieldErrors.issuer}
			<p class="error" id="issuer-error">{fieldErrors.issuer}</p>
		{/if}
	</div>

	<div class="field">
		<label for="account">Account <span class="req" aria-hidden="true">*</span></label>
		<input
			id="account"
			bind:value={account}
			required
			aria-required="true"
			aria-invalid={fieldErrors.account ? 'true' : undefined}
			aria-describedby={fieldErrors.account ? 'account-error' : undefined}
			autocomplete="off"
			data-testid="account"
		/>
		{#if fieldErrors.account}
			<p class="error" id="account-error">{fieldErrors.account}</p>
		{/if}
	</div>

	<div class="field">
		<label for="secret">Secret key <span class="req" aria-hidden="true">*</span></label>
		<!--
			`type="text"`, not `password`. The user is transcribing this from another screen and
			needs to check it; masking it causes typos in the one field where a typo produces a
			silently wrong code. It is also never persisted here — the bytes go straight to the
			core and the buffer is zeroed (§11.6).
		-->
		<input
			id="secret"
			bind:value={secret}
			required
			aria-required="true"
			spellcheck="false"
			autocapitalize="off"
			autocomplete="off"
			aria-invalid={fieldErrors.secret ? 'true' : undefined}
			aria-describedby={fieldErrors.secret ? 'secret-error secret-hint' : 'secret-hint'}
			data-testid="secret"
		/>
		<p class="hint" id="secret-hint">
			The base32 key from your provider. Spaces and lower case are fine.
		</p>
		{#if fieldErrors.secret}
			<p class="error" id="secret-error">{fieldErrors.secret}</p>
		{/if}
	</div>

	<div class="field">
		<label for="nickname">Nickname</label>
		<input id="nickname" bind:value={nickname} autocomplete="off" data-testid="nickname" />
		<p class="hint">
			Optional. Use it to tell two accounts on the same service apart — the vault needs one
			when the issuer and account already match another entry.
		</p>
	</div>

	{#if session.liveGroups.length > 0}
		<div class="field">
			<label for="group">Group</label>
			<select id="group" bind:value={group} data-testid="group">
				<option value="">None</option>
				{#each session.liveGroups as candidate (candidate.id)}
					<option value={candidate.id}>{candidate.name}</option>
				{/each}
			</select>
		</div>
	{/if}

	<!--
		Native disclosure. `details`/`summary` is keyboard operable and announced as an expandable
		group without a line of ARIA or a click handler.
	-->
	<details bind:open={showAdvanced}>
		<summary>Advanced</summary>
		<div class="advanced">
			<div class="field">
				<label for="kind">Type</label>
				<select id="kind" bind:value={kind} data-testid="kind">
					<option value="Totp">Time-based (TOTP)</option>
					<option value="Hotp">Counter-based (HOTP)</option>
					<option value="Steam">Steam</option>
					<option value="Motp">Mobile-OTP</option>
					<option value="Blizzard">Blizzard</option>
					<option value="Yandex">Yandex</option>
				</select>
			</div>

			<div class="field">
				<label for="algorithm">Algorithm</label>
				<select id="algorithm" bind:value={algorithm}>
					<option value="Sha1">SHA-1</option>
					<option value="Sha256">SHA-256</option>
					<option value="Sha512">SHA-512</option>
				</select>
			</div>

			<div class="field">
				<label for="digits">Digits</label>
				<input id="digits" type="number" min="4" max="10" bind:value={digits} />
			</div>

			<div class="field">
				<label for="period">Period (seconds)</label>
				<input id="period" type="number" min="1" max="300" bind:value={period} />
			</div>
		</div>
	</details>

	<div class="actions">
		<button type="submit" class="primary" disabled={session.busy} data-testid="save">
			{session.busy ? 'Saving…' : 'Save code'}
		</button>
		<a href="/">Cancel</a>
	</div>
</form>

<style>
	form {
		max-width: 32rem;
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}

	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	label {
		font-weight: 600;
		font-size: var(--step--1);
	}

	.req {
		color: var(--danger);
	}

	input,
	select {
		padding: var(--space-2) var(--space-3);
		background: var(--surface);
		border: 1px solid var(--border-strong);
		border-radius: var(--radius-sm);
	}

	input[aria-invalid='true'] {
		/* Two signals, not one: a thicker red border *and* the message below (WCAG 1.4.1). */
		border-color: var(--danger);
		border-width: 2px;
	}

	.hint {
		margin: 0;
		font-size: var(--step--1);
		color: var(--text-muted);
	}

	.error {
		margin: 0;
		font-size: var(--step--1);
		color: var(--danger);
		font-weight: 600;
	}

	details {
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: var(--space-3);
		background: var(--surface);
	}

	summary {
		cursor: pointer;
		font-weight: 600;
	}

	.advanced {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
		gap: var(--space-3);
		margin-top: var(--space-3);
	}

	.actions {
		display: flex;
		align-items: center;
		gap: var(--space-4);
	}

	.primary {
		padding: var(--space-3) var(--space-5);
		background: var(--accent);
		color: var(--accent-text);
		border: 1px solid transparent;
		border-radius: var(--radius);
		font-weight: 600;
		cursor: pointer;
	}

	.primary:disabled {
		opacity: 0.7;
		cursor: default;
	}
</style>
