# Licensing

Totem is deliberately not licensed uniformly. GitHub only displays one license per
repository, so this file is the authoritative map.

| Path | License | Why |
|---|---|---|
| `crates/totem-otp/**` | `MIT OR Apache-2.0` | A correct, exhaustively vectored RFC 4226/6238 implementation is worth more to the ecosystem shared than hoarded. Permissive terms let other authenticators adopt it outright, including proprietary ones. |
| `CODE_OF_CONDUCT.md` | `CC-BY-4.0` | Contributor Covenant 2.1, kept verbatim under its own terms. |
| everything else | `AGPL-3.0-or-later` | Anyone may run, audit, fork, and self-host. Anyone offering Totem as a service must publish their changes. |

Machine-readable declarations live in [`REUSE.toml`](../REUSE.toml), following
[REUSE 3.3](https://reuse.software/spec-3.3/). License texts are in
[`LICENSES/`](../LICENSES), named by SPDX identifier. The root `LICENSE` file is a
copy of the AGPL text so GitHub's license detection works; REUSE ignores it.

## Why AGPL for the apps, not just the server

AGPL's network clause is usually described as server-only, which makes it look like
overkill for a desktop app. It is not overkill here: Totem ships a **web app**, and
a web app is conveyed over a network. Someone forking Totem into a hosted
authenticator triggers §13 and owes their users the source. That is the outcome we
want, and it is the reason the client is AGPL rather than GPL.

## Why the OTP engine is permissive instead

`totem-otp` has no product logic in it. It is arithmetic defined by two RFCs, plus
the vendor variants, plus the sloppy-input tolerance that real QR codes demand. The
valuable part is the test suite, not the cleverness. Every authenticator needs this
code correct, and every authenticator writing it again from scratch is a worse
outcome for users than one implementation with the RFC vectors actually wired up.

Nothing about that is a competitive moat, so locking it behind copyleft costs the
ecosystem and gains Totem nothing.

## Compatibility, and the direction it runs

Apache-2.0 is one-way compatible with (A)GPLv3: Apache-2.0 code may be included in
an (A)GPLv3 work, but not the reverse. Both the
[Apache Software Foundation](https://www.apache.org/licenses/GPL-compatibility) and
the FSF agree on this. MIT is compatible with essentially everything.

So the arrow points inward and only inward:

```
totem-otp  (MIT OR Apache-2.0)
    │  may be consumed by
    ▼
totem-crypto, totem-vault, totem-sync, apps, server  (AGPL-3.0-or-later)
```

`totem-otp` must therefore never depend on a copyleft crate — including any other
`totem-*` crate. That is not a style preference: a permissive crate with a copyleft
dependency cannot be distributed under its stated terms, and the breakage is silent.
[`ci/check-otp-permissive.py`](../ci/check-otp-permissive.py) walks its dependency
closure on every CI run and fails the build if this is ever violated.

## Why `totem-crypto` is not also permissive

The obvious next question. The answer is that `totem-crypto` is not a generic
crypto library — it encodes Totem's envelope format, its key hierarchy, and the
threat model those exist to satisfy. It is product design expressed as bytes. Anyone
wanting the primitives should use RustCrypto directly, which is what this crate does.

If a genuinely reusable piece separates out later — a KDF-tier helper, say — it can
move to its own permissive crate. That is a better outcome than pre-emptively
relicensing a crate that mostly encodes decisions specific to this product.

## Rules when adding files

- A new file inherits its license from `REUSE.toml` by path. No action needed.
- A new file under `crates/totem-otp/` is `MIT OR Apache-2.0`. Do not add a
  dependency there without checking its license.
- A new crate outside `crates/totem-otp/` sets `license.workspace = true`.
  `crates/totem-otp/Cargo.toml` must set `license = "MIT OR Apache-2.0"` explicitly
  and must **not** inherit from the workspace.
- Third-party text kept verbatim needs its own `[[annotations]]` entry with
  `precedence = "override"`, its real copyright holder, and its license text added to
  `LICENSES/`. Do not relabel someone else's work as ours.
- SPDX headers in source files are encouraged and win over `REUSE.toml`, because they
  survive a file being copied out of the repo:

  ```rust
  // SPDX-FileCopyrightText: 2026 The Totem Authors
  //
  // SPDX-License-Identifier: MIT OR Apache-2.0
  ```

## Contributions

Contributions are accepted under the license already governing the path you are
editing, certified by a [DCO](https://developercertificate.org/) sign-off
(`git commit -s`). There is no CLA and no copyright assignment — nobody signs away
their rights to make this project relicensable later, which is deliberate.

## Verifying

```bash
pipx run reuse lint            # every file has copyright and license info
python3 ci/check-otp-permissive.py   # totem-otp's closure stays permissive
cargo deny check licenses      # no dependency outside the allowed set
```

## Not legal advice

This file records the reasoning behind the project's choices. It is not a legal
opinion, and if you are making a commercial decision that turns on any of it, ask a
lawyer rather than a repository.

