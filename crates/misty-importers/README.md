<!--
SPDX-FileCopyrightText: 2026 The Misty Authors

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# misty-importers

Read every other authenticator's export, and write one that every other
authenticator can read.

Lock-in is the loudest complaint users have about the app most of them are
leaving, and refusing to build it is a decision Misty has already made
(SPEC 8). This crate is that decision in code.

`#![forbid(unsafe_code)]`. No network code anywhere, no `unwrap` on any path
reachable from parsed input, and no dependency that carries C — the browser
extension imports files too, so `wasm32-unknown-unknown` is a hard gate.

## What it promises

* **Per-row failure isolation.** One malformed row is one
  `RowOutcome::Failed`; the batch continues. A user importing 200 accounts does
  not lose 199 of them to one bad line. This is the crate's central safety
  property and `tests/hostile_inputs.rs` is what keeps it honest.
* **Preview before write.** `Importer::preview` returns exactly what
  `Importer::import` would add, with every secret left out, so the UI can show it
  before anything is committed. It is the same code path: preview imports and then
  drops the items, which is why the two cannot disagree.
* **No secret in any error, ever.** Errors name the row and the problem, never the
  value. `tests/redaction.rs` asserts that over every importer, every fixture and
  every hostile input, in base32, hex and raw-decimal renderings.
* **Duplicate detection** against a caller-supplied set of
  `(issuer, account, secret)` triples, held as domain-separated SHA-256 digests so
  this crate never compares two secrets with `==` (SPEC 2.1).
* **Nothing panics.** Five fuzz targets, and a hostile-input suite that feeds every
  input to all sixteen importers because `detect` runs them all anyway.

## Format status

| Format | Status | Notes |
|---|---|---|
| `otpauth://` URIs (single, or one per line) | **complete** | Parsing is `misty-otp`'s. Blank lines and `#` comments are ignored |
| `otpauth-migration://` (Google Authenticator) | **complete** | Hand-rolled protobuf reader; reports which QR code of a multi-part export is missing |
| Aegis Authenticator, plain JSON | **complete** | `totp`, `hotp`, `steam`, `motp`, `yandex`; groups, notes, favourites |
| Aegis Authenticator, encrypted JSON | **complete, self-verified** | scrypt + AES-256-GCM. Never checked against a vault a real Aegis wrote — see [Verification](#what-the-encrypted-formats-are-verified-against) |
| 2FAS, plain JSON | **complete** | `TOTP`, `HOTP`, `STEAM`; groups |
| 2FAS, encrypted JSON | **partial, unverified** | PBKDF2 + AES-256-GCM with parameters this crate could not confirm. Both PBKDF2 hashes are tried; a wrong guess fails the AEAD rather than producing garbage |
| andOTP, plain JSON | **complete** | Tags, last-used time |
| andOTP, encrypted backup | **complete, self-verified** | Both layouts: PBKDF2 + AES-256-GCM, and the older SHA-256-of-password one |
| FreeOTP (`tokens.xml`) | **complete** | Reads Gson's **signed** `byte[]` secret correctly, and adds one to the stored HOTP counter — see [Two corrections](#two-corrections-other-importers-get-wrong) |
| FreeOTP+ JSON backup | **complete** | Same token objects in an array, same counter correction |
| FreeOTP+ encrypted backup | **not implemented** | See [What is deliberately not here](#what-is-deliberately-not-here) |
| Bitwarden Authenticator JSON | **complete** | Also reads Bitwarden's password-manager export: `login.totp` as a URI, a bare secret, or `steam://SECRET` |
| Bitwarden encrypted export | **not implemented** | Sealed with the account key inside the Bitwarden client. Its own UI offers an unencrypted export |
| Ente Auth, plaintext export | **complete** | Including the `codeDisplay` blob: pinned, trashed, tags, note |
| Ente Auth, encrypted export | **not implemented** | libsodium secretstream; see below |
| Raivo OTP JSON | **complete** | Every value in a Raivo export is a string, numbers included |
| Raivo encrypted ZIP | **not implemented** | Needs a ZIP reader |
| LastPass Authenticator JSON | **complete** | Keeps the user's renaming *and* the original as a nickname |
| Proton Pass JSON | **complete** | One item may hold several TOTP secrets; each becomes its own row |
| Proton Pass encrypted export | **not implemented** | PGP, with the key inside the Proton client |
| KeePassXC XML export | **complete** | `otp` URIs, KeeOtp query strings, and the legacy `TOTP Seed` + `TOTP Settings` pair including `30;S` for Steam. `<History>` is skipped |
| KeePassXC CSV export | **complete** | Through the generic CSV reader and `ColumnMapping::keepassxc_csv()` |
| KDBX (`.kdbx`) database files | **infeasible as specified** | The crate's one substantive deviation from SPEC 8 — see below |
| Twilio Authy | **best effort by construction** | Authy has no export. See [Authy](#authy) |
| Microsoft Authenticator | **infeasible** | No export of TOTP secrets exists at any layer |
| Generic CSV | **complete** | Caller-supplied mapping, or inference from a header row |
| Generic JSON | **complete** | Caller-supplied dotted-path mapping |

Export: `otpauth://` URI list, printable-QR-sheet data, and a plaintext JSON
export behind a typed confirmation phrase. `.mistybak` is **not** here — it is
`misty_crypto::backup`'s format and is not reimplemented.

## Quick start

```rust
use misty_importers::{ImportContext, Importer};

let file = std::fs::read("aegis-backup.json").expect("read the export");

// Sniff first: this is what tells the UI whether to ask for a password.
let found = misty_importers::detect_format(&file).expect("a recognizable format");
println!("looks like {} (needs a password: {})", found.format, found.needs_passphrase);

let importer = misty_importers::importer_for(found.format).expect("registered");
let ctx = ImportContext::new().with_passphrase(b"the user's vault password");

// Dry run. Holds no secrets, so it is safe to serialize into the UI.
let preview = importer.preview(&file, &ctx).expect("preview");
println!("{} accounts, {} skipped, {} unreadable",
         preview.would_import(), preview.skipped(), preview.failed());

// Then the real thing, and the caller inserts what it gets.
let report = importer.import(&file, &ctx).expect("import");
for outcome in &report.outcomes {
    println!("{outcome}");
}
```

## Why the model is not SPEC 3's `Item`

`ImportedItem` carries no `ItemId`, no `GroupId`s, no `Hlc` and no
`UsageCounter`, and groups and icons arrive as the vendor's own *names*. Minting
ids and clocks is the vault's job, and this crate deliberately does not depend on
`misty-vault`: it emits plain values plus a per-row outcome list and lets the
caller insert them. That keeps Phase 3 independent of Phase 2, testable without a
database, and usable from the browser extension, which has no SQLite.

## What you lose in a lossy import

Every one of these is reported per row as an `ImportWarning`, so a UI can show it
rather than leaving the user to find out later.

| What | Why |
|---|---|
| Embedded icon images (Aegis, Ente) | Misty's model holds an icon *reference*, not a bitmap. The vendor's slug is kept in `icon_hint` where there is one |
| Unknown `otpauth://` parameters | Somebody's vendor extension. `misty-otp` preserves them for its own round-trip; this model has nowhere to put them, and `DroppedField("uri parameters")` says so |
| Ente's `lastUsedAt` | Ente records times in microseconds in some places and milliseconds in others, and this crate has no real export to confirm which this field is. A last-used time wrong by a factor of a thousand mis-sorts a list forever, and SPEC 3.1 leans on that field to tell same-issuer accounts apart. Dropped rather than guessed |
| Authy's period, and often its digit count | Authy's own records do not carry a period. See [Authy](#authy) |
| Assumed parameters, everywhere | Any format that omits `algorithm`, `digits` or `period` gets this crate's default *and* an `AssumedDefault` warning naming the field |
| A defaulted HOTP counter | A wrong counter produces codes the server rejects. Where an export omits it, `AssumedDefault("counter")` is attached — it cannot be refused, because zero is a real counter value |
| Only the first 16 bytes of a Yandex secret | `SecretPrefixUsed(16)`. Yandex prints 26 bytes: 16 of key plus a checksum, and every interoperable client truncates (SPEC 7) |
| Trashed entries (Ente, Proton) | Imported **archived**, not dropped, with `ImportedAsArchived`. Their trash is recoverable; a token silently discarded during a migration is not |
| Organisation-owned Bitwarden items | The item imports; `DroppedField("organizationId")` records that its sharing did not |

Nothing here silently changes a *credential*. Where a value that affects code
generation is unknown, the row either carries a warning naming the field or fails.

## Authy

Authy has no export function. Twilio's only documented seed-export endpoint is a
*provider-side* API, gated behind a support request and rate-limited to a handful
of calls per user per month; nothing an account holder can invoke. Twilio has since
discontinued the desktop application whose developer tools were the community's way
out, which means that for many users **no path out exists at all**.

What this importer reads is therefore a file the user has to produce themselves,
from that application's own data, in either of the two shapes that circulate
(`authenticator_tokens` with snake_case fields, or a bare array with camelCase
ones). Within that:

* **An Authy-native token gets a ten-second step, and everything else gets 30.**
  Authy's records carry no period field at all. Its own tokens (`account_type` of
  `authy`, or a hex `secretSeed`) use a 7-digit code on a 10-second step:
  `alexzorin/authy` declares `totpTimeStep = 10` and `totpDigits = 7`, its
  `authy-export` writes `period=10` for the native `apps[]` and no period for
  third-party `authenticator_tokens[]`, and Aegis's importer keys on the same
  discriminator. Third-party tokens therefore take the `otpauth://` default of 30.
  Both cases carry `AssumedDefault("period")`, because in neither case did the row
  say. **Check one live code before deleting Authy.** A wrong period produces codes
  that look right and never work, and by then the app is gone.
* **It will not decrypt `encrypted_seed`.** Authy's backup-password wrapping is
  undocumented and the circulating parameters could not be verified. An unverified
  decryptor reports "wrong password" for a correct password, which for a user whose
  only copy is in that file is worse than a clear refusal. Those rows are skipped
  as `EncryptedSecret`.
* **It will not choose between two readings of one seed.** A seed is decoded as
  base32; only where that is impossible is it read as hex, and the row says so. The
  rule is deterministic and documented rather than clever, because the two
  decodings of one string are two different keys.

## Two corrections other importers get wrong

Both were verified by reading the vendor's source, not by repute, because both are
the kind of mistake that produces a token which imports cleanly and then fails to
log the user in.

* **FreeOTP's HOTP counter is one behind the `otpauth://` convention.**
  `Token.java` v1.5 parses `counter = uri_counter - 1` (line 120), generates with
  `getHOTP(counter++)` (line 241) and writes `counter + 1` back out (line 273). So
  the stored number is the counter it last *used*, and an `otpauth://` counter is
  the one to use *next*. This crate adds one. Aegis's FreeOTP importer reads the
  field raw and is off by one.
* **Authy's own tokens are 7 digits on a 10-second step**, not 6 on 30. See
  [Authy](#authy).

## KDBX: the one substantive deviation from SPEC 8

SPEC 8 lists "KeePassXC/KDBX TOTP entries". This crate reads KeePassXC's **XML and
CSV exports** and does **not** open a `.kdbx` file.

A KDBX4 reader needs Argon2id *and* AES-KDF, AES-256-CBC *and* ChaCha20, an
HMAC-SHA-256 block chain, an inner Salsa20/ChaCha20 stream cipher for protected
values, and gzip, all before the XML this crate already parses is reachable. That
is a large amount of new cryptographic surface inside the crate whose input is
hostile by definition, to replace two clicks in KeePassXC's own export menu — and
KeePassXC users are, by selection, people who can use their own export menu.

The trade is not worth it at Phase 3. If it is revisited, the argument to beat is
that number of primitives, not the difficulty.

## What is deliberately not here

Each of these is a refusal rather than an omission, and the reasoning is the same
in every case: **an unverified decryptor tells a user with the correct password
that it is wrong**, which for a 2FA export is worse than a clear "not supported"
pointing at the vendor's plaintext option.

| Not implemented | Why |
|---|---|
| Ente's encrypted export | A libsodium `crypto_secretstream_xchacha20poly1305` payload under an Argon2id key. The chunked framing — 24-byte header, 17-byte per-chunk overhead, implicit nonce advance — is not something to reimplement from memory against a file this crate has never seen. Ente offers a plaintext export in the same menu |
| Raivo's encrypted ZIP | Needs a ZIP reader: a large parser to add to a crate that parses hostile files, for one vendor's convenience wrapper. Raivo's plain JSON is in the same menu |
| FreeOTP+'s encrypted backup | Same reasoning as Ente's, with less public documentation |
| Bitwarden's and Proton's encrypted exports | Sealed with keys that live inside the vendor's client. No passphrase can substitute; both vendors offer an unencrypted export |
| `.mistybak` | `misty_crypto::backup::seal_bytes`. Reimplementing Misty's own backup format in a second crate is how two implementations drift apart |
| SLIP-39 splitting | Splits the *Recovery Key*, not an item list. `misty-crypto`'s business |
| A PDF writer | `export::qr_sheet` returns the label and the URI per item, which is everything a renderer needs. A font stack and a PDF serializer do not belong in a crate that must compile to wasm32 |

## Where the fixtures come from

`tests/fixtures/<slug>/`. **Every secret is an obvious dummy** —
`AAAAAAAAAAAAAAAA` and friends, `aaaaaaaaaaaaaaaa` for the hex mOTP one — and no
real enrolment appears anywhere in this repository. Sixteen fixtures are
hand-written from the format descriptions cited in each module's documentation.
Four cannot be, and are generated:

| Fixture | How |
|---|---|
| `google-migration/batch.txt` | `tests/fixture_provenance.rs` encodes the protobuf with a writer independent of the reader under test, base64s it, and percent-escapes it the way Google does |
| `aegis/encrypted.json` | Same file: scrypt at `n = 8192, r = 8, p = 1` over a fixed salt, AES-256-GCM at fixed nonces. **Its plaintext is byte-for-byte the `db` object of `aegis/plain.json`**, which is what makes "the two fixtures are the same vault" a claim the test checks rather than asserts |
| `andotp/encrypted.bin` | Same file: PBKDF2-HMAC-SHA-1 at 1000 iterations over a fixed salt, then AES-256-GCM. Its plaintext is `andotp/plain.json` verbatim |
| `2fas/encrypted.json` | Same file: PBKDF2-HMAC-SHA-256 at 10 000 iterations, AES-256-GCM, base64 triple. Its plaintext is the `services` array of `2fas/backup.json` |

The passphrase for all three encrypted fixtures is `misty test passphrase`,
committed on purpose: a fixture nobody can decrypt is a fixture nobody can check,
and it protects nothing but dummies.

Regenerate, and diff what changed:

```sh
MISTY_WRITE_FIXTURES=1 cargo test -p misty-importers --test fixture_provenance
```

Run without that variable — which is what CI does — the same test *asserts* the
committed bytes are exactly what the recipe produces. That is what "reproducible
rather than magic" means here: nobody has to trust a blob, and a format change is a
diff in the recipe next to a diff in the fixture.

Cost parameters in the fixtures are deliberately low (Aegis defaults to
`n = 32768`, andOTP to six figures of iterations) so the suite stays quick in a
debug build. `real_world_cost_parameters_are_accepted` runs one derivation at
Aegis's actual default to prove the readers accept it.

## What the encrypted formats are verified against

Precisely, because this is the part where it would be easy to imply more than is
true.

* The **primitives** are anchored to published vectors: RFC 7914 §12 for scrypt,
  RFC 6070 for PBKDF2-HMAC-SHA-1, and a seal/open round trip plus a
  flipped-bit rejection for AES-256-GCM. Those tests are in `src/interop.rs`.
* The **file layouts** are from each vendor's own source or documentation, cited in
  the module that reads them (`src/formats/aegis.rs`, `andotp.rs`, `twofas.rs`).
* The **assembly** — which field is hex and which is base64, where the GCM tag
  lives, what the plaintext is — is verified against a writer built from the same
  description, at fixed salts and nonces. That catches a reader that disagrees with
  its own writer. It cannot catch a description that is wrong.

**No encrypted vault written by a real installation of Aegis, andOTP or 2FAS has
ever been fed to this crate.** If you hold one, importing it and reporting the
result is the single most valuable contribution anyone can make here — exactly as
`misty-otp` says about a captured Steam or Yandex vector.

## Notes for reviewers

* **The protobuf reader is hand-written** (`src/protobuf.rs`). `prost` needs
  `protoc` at build time, which is a C++ toolchain in a crate that must compile to
  `wasm32-unknown-unknown`, and the message has five fields. It refuses
  non-terminating varints, lengths past the end of the buffer *before allocating*,
  field number 0, and group wire types — a group cannot be skipped without a
  matching end tag, so refusing is honest where guessing would not be. Unknown
  field *numbers* are skipped, which is what keeps a newer Google export readable.
* **The CSV reader is hand-written too** (`src/csv.rs`), and that is a closer call.
  The `csv` crate is good and well fuzzed; the reason not to use it is that the
  bounds have to be *inside* the scanner. A general-purpose reader produces the
  100 000-column row and then lets this crate reject it, by which point the
  allocation has happened.
* **`quick-xml` is floored at 0.41.** 0.38 and earlier carry RUSTSEC-2026-0194
  (quadratic time checking a start tag for duplicate attribute names) and an
  unbounded namespace-declaration allocation in `NsReader`. Both land squarely on
  this crate's threat model, so the floor is enforced rather than the advisory
  ignored, and `tests/hostile_inputs.rs` covers both shapes with a *time budget*
  rather than only asserting an error — a quadratic parser also returns an error,
  eventually. This crate uses `Reader`, not `NsReader`.
* **Text validation is uniform and lives in the collector.** SPEC 7.2's rule about
  control characters, bidi overrides, zero-width characters and the BOM applies to
  every field of every format, not only to URIs: an issuer with an embedded NUL is a
  log-injection vector wherever it came from. Ordinary non-ASCII is **not**
  hostile — `日本銀行` is a real bank — and there is a test for exactly that.
* **KDF parameters from a file's own header are rejected, never clamped**
  (SPEC 2.3). Clamping a hostile 64 GiB scrypt cost derives a *different* key, so
  the user is told their password is wrong when the header is what is wrong.
  `ImportError::KdfParam` names the parameter.
* **Aegis tries at most eight password slots.** A vault claiming a thousand would
  otherwise be a thousand scrypt derivations.
* **`ImportReport` and `PreviewReport` are separate types** rather than one type
  with an `Option`. The preview is produced by importing and dropping the items,
  which zeroizes them, so a caller cannot accidentally hold secrets it asked not to
  see.
* **The plaintext export is gated in the library**, not only in the UI:
  `export::plaintext_json` refuses without `PLAINTEXT_EXPORT_CONFIRMATION` typed
  exactly. SPEC 2.5 also requires a fresh biometric or PIN check, which is the
  application's to make — this crate does not know what platform it is on. JSON has
  no comment syntax, so the "loud header comment" is a `_WARNING` string written
  first, which is why the document is serialized by hand: `serde_json`'s map orders
  by key, and a warning nobody scrolls to is not a warning.
* **Duplicates are skipped by default and the policy is a caller's choice.** SPEC
  3.1.5 wants identical triples merged and same-`(issuer, account)`-different-secret
  kept as two accounts; the second case imports with `CollidesWithExisting` so the
  UI can require a distinguishing nickname. Issuer and account are compared trimmed
  but **not** case-folded: a false duplicate is a silently dropped account, which is
  worse than one listed twice.

## Running the checks

```sh
export CARGO_TARGET_DIR=target/agent-importers        # optional
cargo fmt -p misty-importers --check
cargo clippy -p misty-importers --all-targets --all-features -- -D warnings
cargo test -p misty-importers --all-features
cargo doc -p misty-importers --no-deps
cargo build -p misty-importers --target wasm32-unknown-unknown
cargo deny check                                     # from the repo root
python3 ci/check-otp-permissive.py                   # from the repo root
```

The fuzz targets live in `fuzz/`, which is its own workspace so they stay out of
`cargo build --workspace`:

```sh
cargo install cargo-fuzz
cd crates/misty-importers
mkdir -p fuzz/corpus/detect_any
cargo +nightly fuzz run --sanitizer=none detect_any fuzz/corpus/detect_any
```

Five targets: `migration_protobuf`, `aegis_json`, `andotp`, `csv_mapping`, and
`detect_any`, which runs every importer over every input because `detect` does too.
Each asserts more than "did not crash": an import either fails or produces tokens
that generate, the outcome list stays consistent with the item list, and anything
that imported re-exports and re-imports to an identical model. `--sanitizer=none`
is deliberate, for the reason `misty-otp`'s README gives: every crate here is
`forbid(unsafe_code)`, so what these targets find is panics and over-allocation, and
ASan only costs throughput.




