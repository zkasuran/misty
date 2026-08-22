<!--
SPDX-FileCopyrightText: 2026 The Misty Authors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# apps/ui

The Misty interface: SvelteKit, one surface shared by the web app, the browser extension, and
the Tauri desktop and mobile shells (SPEC §0, §11.7.2).

## The core it runs against is not a mock

`scripts/build-core.sh` compiles [`crates/misty-ffi`](../../crates/misty-ffi) to
`wasm32-unknown-unknown` and runs `wasm-bindgen` over it. What loads in the tab is the real
vault, the real CRDT merge, the real envelope layer, and the real sync state machine, with
`MemoryStore` and `MockTransport` in place of the disk and the network (§11.8.1).

That distinction is the point, not a detail. §11.8.1 forbids a hand-written TypeScript mock
because a separate mock can drift from the core while both sides stay green — which is
exactly the P4 interop failure (§6.1.1) one layer up. This cannot drift, because it *is* the
core. Swapping in a real store and transport is a change in `crates/misty-ffi`; nothing in
this app moves, because the generics are erased at the facade (§11.1).

A visible consequence, and a reassuring one: the code this UI displays for the shared
conformance secret is `746722` — the same literal the native facade, the UniFFI object, the
generated Swift, and the generated Kotlin all assert (§11.8.2). If the browser ever disagreed
with Swift, `tests/flows.spec.ts` would fail too.

## Running it

```sh
npm install
npm run dev        # builds the core, then vite dev
npm run check      # svelte-check over types and templates
npm test           # release build, then the full flow and a11y suites
```

`npm run dev` and `npm test` both rebuild the core first, so a facade change is picked up
without a separate step.

## What the tests prove

| Spec | What it covers |
|---|---|
| `tests/probe.spec.ts` | The core starts in a browser under the production CSP, and nothing carries an inline style |
| `tests/flows.spec.ts` | Unlock → add → generate → copy → search/sort → edit → groups → trash/restore/delete → sync → revoke → lock |
| `tests/a11y.spec.ts` | axe-core (WCAG 2.2 AA) over every route in **both** themes, plus the behaviour axe cannot see |

Everything runs against the production build via `vite preview`, never the dev server. The
§9 CSP only exists in built output and dev injects styles inline, so testing dev would pass
while shipping something else.

The a11y suite deliberately does two things. axe catches the mechanical failures — unlabelled
controls, contrast, heading order, landmarks — and is run per theme because contrast is a
property of the active palette, so dark can fail everything light passes. The hand-written
half covers what a static scan cannot: whether focus lands somewhere sensible, whether the
skip link works, whether the app is usable without a mouse, and whether the code is announced
as digits rather than as "seven hundred forty-six thousand".

## SPEC §9 hardening, and what is honestly not done

Implemented here:

- **Auto-lock** on backgrounding, screen lock, and sleep — reported to the core as lifecycle
  events. The shell reports; the facade decides (§11.5.5). Nothing in this app holds a timer
  that locks the vault, because a timer does not fire in a frozen tab and the vault would come
  back unlocked after an hour asleep. §11.5's absolute deadline is checked inside the actor;
  `lifecycle.ts` only gives it opportunities to notice.
- **Blur on background**, applied synchronously ahead of the core's lock reply, because a
  screenshot can be taken in that window.
- **Clipboard auto-clear** after 20 seconds, and only if nothing else was copied through us
  since.
- **No secret in a string**: secrets cross as `Uint8Array` and the buffer is zeroed once the
  core has copied it (§11.6).
- **CSP with no `unsafe-inline`**: `default-src 'none'`, every exception named, and
  `script-src` limited to `self`, a hash for SvelteKit's bootstrap, and `wasm-unsafe-eval` —
  which permits compiling a WebAssembly module and nothing else.
- **No third-party endpoint**: no CDN, no web font, no analytics. The favicon is bundled.

Not done, and stated rather than implied away:

- **`frame-ancestors` is absent from the policy.** Browsers ignore it in a `<meta>` CSP; it
  needs a real response header, which is a host concern. A policy that looks complete and is
  not is worse than an obviously partial one.
- **Screen-capture blocking** is `FLAG_SECURE` on Android and its iOS equivalent (§9). The web
  has no such control. Blur on background is the whole mitigation here.
- **Clipboard "sensitive / no history"** marking is a platform capability the web does not
  expose. A clipboard manager with history will still hold the code.
- **Failed-attempt backoff and wipe-after-N** are unlock-path concerns and there is no unlock
  path to protect yet — see below.

## Two gaps that need a facade decision, not a UI workaround

Both are places where the honest thing was to stop rather than to build something that looks
finished.

**There is no passphrase or biometric unlock.** §2.3 fixes key derivation at Argon2id with
specific parameters, and the facade exposes no derivation call, so this app cannot turn a
passphrase into a vault key. It unlocks with the §11.8.2 fixture key and says so on screen. A
passphrase box that accepted anything — or that quietly used PBKDF2 because WebCrypto has it —
would look like the real unlock flow while proving nothing and misrepresenting the
cryptography. What is missing is one facade method.

**`otpauth://` import is absent, and base32 decoding is duplicated here.**
`NewItemInput.secret` is raw bytes; users paste base32 or scan a URI. `misty-otp` contains a
strict base32 implementation and a URI parser, both quarantined behind the facade (§11.7), so
`lib/core/base32.ts` re-implements the encoding. That is duplicated logic and the discomfort is
recorded in the file: base32 is a *fixed encoding* rather than a policy, and the decoder
deliberately validates nothing — length, entropy and suitability stay the core's to reject with
`OTP_INVALID_SECRET`. The right shape is still a facade call that takes the user's string, or a
URI, so the core owns parsing end to end.

## Why plain CSS rather than a utility framework

Three reasons that outweigh convenience here. The a11y gate is about specific colour pairs, so
owning the palette means they can be chosen to pass rather than audited afterwards and patched.
§9 forbids third-party endpoints and asks for a CSP with no `unsafe-inline`, and every
dependency that injects styles at runtime is something to argue with about that. And this is a
security product that publishes an SBOM — fewer build-time dependencies is less to audit.

One constraint falls out of the CSP and is worth knowing before editing a component: **no
`style="…"` attributes anywhere.** `style-src 'self'` blocks inline style attributes, and the
declaration is silently dropped, so the bug appears only in the production build. Where a value
must be dynamic, use Svelte's `style:` directive — it compiles to a CSSOM write, which CSP does
not police. `tests/probe.spec.ts` enforces this by pinning the set of elements allowed to carry
an inline style to exactly one: SvelteKit's own route announcer, whose blocked styling is
compensated in `app.css`.

## Layout

```
src/lib/core/     the boundary: types.ts mirrors dto.rs, client.ts is the only place
                  allowed to assert those types, errors.ts owns the flat error,
                  lifecycle.ts owns the shell's §9/§11.5.5 obligations
src/lib/vault/    session.svelte.ts — a projection of the vault, never a second copy
src/lib/ui/       presentation: theme, error banner, code tile
src/routes/       codes, add, item detail, groups, trash, settings
```

`session.svelte.ts` re-reads from the core after every mutation rather than patching its arrays
optimistically. An optimistic update would be a second, divergent copy of vault state, and CRDT
merge means the core's answer can legitimately differ from what was asked for (§4).
