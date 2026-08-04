# Security Policy

Misty stores long-lived shared secrets. A vulnerability here can cost a user every
account they protect with it — permanently, until they re-enroll at each service by
hand. Reports are treated accordingly.

## Current status: pre-alpha, unaudited

Misty has had no external audit and no stable release. **Do not put a real TOTP
secret in it yet.** No version is supported for production use. When that changes
it will be stated plainly here rather than quietly implied.

| Version | Support |
|---|---|
| `main` | development only, no support commitment |
| tagged releases | none yet |

## Reporting a vulnerability

Open a private report:
**https://github.com/zkasuran/misty/security/advisories/new**

Please do not open a public issue for anything that could expose user secrets.

Useful things to include, in rough order of value:

- the version, commit, and platform
- a minimal reproduction, or the specific code path if you found it by reading
- what an attacker gains, and what access they need first
- for crypto findings: which property of [`docs/SPEC.md`](docs/SPEC.md) §2 breaks

## What to expect

| | Target |
|---|---|
| Acknowledgement | 48 hours |
| Initial assessment | 7 days |
| Fix or documented mitigation for critical findings | 30 days |
| Public advisory | after a fix ships, or 90 days, whichever is first |

These are targets from a small maintainer team, not a contractual SLA. If a
deadline slips you will be told why rather than left waiting.

There is no bug bounty. Saying so up front is more useful than implying one exists.
Credit in the advisory and the release notes is offered unless you decline.

## Scope

The full threat model is [`docs/SPEC.md`](docs/SPEC.md) §1. In scope, non-exhaustively:

- any path that writes a secret, key, or vault field to disk, a log, a crash
  report, a notification, a window title, or the clipboard in plaintext
- any way to decrypt an envelope without the vault key, or to make a client
  decrypt an envelope whose signer is not in the device roster
- any way for the server, or someone holding its database, to learn a plaintext
  field, forge a write a client accepts, or add a device the user never approved
- confusion of the AAD binding — moving an envelope to a different `item_id`,
  epoch, or vault and having it accepted
- CRDT merge bugs that lose an item, resurrect a deleted one, or move a HOTP
  counter backwards
- a parser that panics, hangs, or over-allocates on hostile input: `otpauth://`
  URIs, QR payloads, backup headers, any importer format
- KDF parameters that can be downgraded by an attacker-supplied header
- bypassing the lock screen, the per-item reveal gate, or auto-lock
- an extension autofill that fires on an origin the item does not list
- timing or size side channels that reveal which item or issuer is in use
- supply-chain issues: a dependency we should not be shipping, a build that is not
  reproducible, a release artifact that does not match its source

### Known limitations, not vulnerabilities

These are documented consequences of the threat model. Reports about them are
welcome as design discussion, but they will not be treated as vulnerabilities:

- malware running as root, or a compromised kernel, can read a decrypted vault
- an attacker with an already-unlocked device can read the vault
- a user who types a code into a phishing site has given the code away; origin
  warnings reduce this, they cannot eliminate it
- the server learns envelope sizes (bucketed to 256 bytes), item counts, and
  write timing. This is stated in the threat model, not hidden
- losing the Recovery Kit with no enrolled device means permanent loss. That is
  the deliberate cost of having no escrow to compel or breach
- a weak user passphrase weakens a backup file; Argon2id raises the cost, it does
  not fix a four-character passphrase

## Changes to cryptography

A change to any construction in `docs/SPEC.md` §2 requires the spec change and the
code change in the same pull request, plus updated frozen golden-byte vectors and a
migration path for existing vaults. "It still passes the tests" is not sufficient
review for a format change.

