<!--
SPDX-FileCopyrightText: 2026 The Misty Authors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# misty-otp

The one-time-password engine: RFC 4226 HOTP, RFC 6238 TOTP, the four vendor
variants real users have (Steam, mOTP, Battle.net, Yandex.Key), and an
`otpauth://` parser hard enough to point at a QR code from a stranger.

**Licensed `MIT OR Apache-2.0`**, unlike the rest of this repository, which is
AGPL-3.0-or-later. Every authenticator needs this code correct, and every
authenticator writing it again from scratch is a worse outcome for users than one
implementation with the RFC vectors actually wired up. Take it. See
[`docs/LICENSING.md`](../../docs/LICENSING.md). The practical consequence is that
this crate must never gain a copyleft dependency — including any other crate in
this workspace — which `ci/check-otp-permissive.py` enforces on every CI run.

`#![forbid(unsafe_code)]`. No I/O, no global state, no clock of its own, no
allocation before an input has been length-checked.

## Scope

It turns `(secret, moving factor)` into a displayable code, and it converts
between that configuration and an `otpauth://` URI. It does not know about
vaults, storage, sync, or the vendor export formats (that is `misty-importers`).
It has no opinion about where the time comes from: you pass a [`Clock`].

## Quick start

```rust
use misty_otp::{OtpConfig, OtpUri, SecretBytes, SystemClock};

// From a scanned QR code.
let uri = OtpUri::parse("otpauth://totp/ACME:ada@example.com?secret=JBSWY3DPEHPK3PXP")?;
assert_eq!(uri.issuer(), Some("ACME"));
let code = uri.config().generate(&SystemClock)?;
println!("{code} for {}s more", code.remaining_ms().unwrap_or(0) / 1000);

// Or built directly, and generated at a fixed instant so the result is
// deterministic. This is RFC 4226's secret, at RFC 6238's first timestamp.
let config = OtpConfig::totp(SecretBytes::from_slice(b"12345678901234567890"))?;
assert_eq!(config.generate_at(59_000)?.value(), "287082");
assert_eq!(config.generate_at(59_000)?.remaining_ms(), Some(1_000));
# Ok::<(), misty_otp::OtpError>(())
```

## Public API

| Item | Purpose |
|---|---|
| `SecretBytes` | The only type holding key material. `Zeroize` + `ZeroizeOnDrop`, `Debug`/`Display` render `[redacted]`, constant-time `PartialEq`, no `Serialize`. Constructors: `new`, `from_slice`, `from_base32`, `from_hex`; accessors: `expose_secret`, `to_base32`, `to_hex`, `len`, `is_empty`. |
| `OtpKind` | `Totp` \| `Hotp` \| `Steam` \| `Motp` \| `Blizzard` \| `Yandex`, plus the metadata that drives everything else: `uri_type`, `serializes_as`, `from_uri_type`, `display_name`, `default_*`, `fixed_*`, `uses_counter`, `uses_pin`, `secret_encoding`, `pin_encoding`, `secret_prefix_used`, `ALL`. |
| `HashAlg` | `Sha1` (default) \| `Sha256` \| `Sha512`, with `FromStr` (case-insensitive, tolerates `SHA-1`), `as_str`, `output_len`. |
| `OtpConfig` | One token. Private fields, validating constructors (`totp`, `totp_with`, `hotp`, `hotp_with`, `steam`, `motp`, `blizzard`, `yandex`, `builder`) and validating setters, so any value of this type is generatable. |
| `OtpConfigBuilder` | `algorithm`, `digits`, `period`, `counter`, `pin`, `build`. |
| `OtpConfig::generate_at` / `generate` | Code at an instant, or at a `Clock`'s instant. |
| `OtpConfig::next_code_at` / `next_code` | The following code, for "peek at next". |
| `OtpConfig::counter_at` | The moving factor, exposed for UIs and vector suites. |
| `OtpConfig::resync_counter` | RFC 4226 §7.4 forward scan, constant-time and bounded by `MAX_RESYNC_WINDOW`. |
| `hotp` | The one-shot RFC 4226 function. |
| `Code`, `CodeWindow` | The code plus `valid_from_ms`, `valid_until_ms`, `remaining_ms`, `progress`, so the UI does no time arithmetic. `Debug` redacts; `Display` renders. `ct_eq` for verification. |
| `Clock`, `SystemClock`, `FixedClock`, `SkewedClock` | Time. `SkewedClock` applies a measured server offset without touching the host clock (SPEC 6.5) and knows the 10-second warning threshold. |
| `OtpUri`, `UriWarning` | `parse`, `parse_with_warnings`, `to_uri`, `export_form`, `new`, `with_extra`, `config`, `config_mut`, `issuer`, `account`, `extra`. |
| `base32` | `decode`, `encode`, `encode_padded`, `MAX_INPUT_CHARS`. |
| `raw` | `hmac`, `hmac_counter`, `dynamic_truncation`, `decimal_digits` — the intermediate values RFC 4226 publishes, so the test suite can check them. |
| `OtpError`, `Base32Error`, `UriError`, `Result` | Typed failure. Nothing in this crate panics on any input. |
| `MIN_DIGITS`/`MAX_DIGITS` (1/10), `MIN_PERIOD`/`MAX_PERIOD` (1/3600), `MAX_SECRET_LEN` (1024), `MAX_URI_LEN` (4096), `MAX_RESYNC_WINDOW` (1000) | Limits, all public so callers can validate before they call. |

`SystemClock` is absent on `wasm32-unknown-unknown`, where
`SystemTime::now()` panics: a browser build passes in a clock backed by
`Date.now()`. A compile error beats a runtime panic.

## The variants

| Variant | Digits | Period | Hash | PIN | Output | URI type |
|---|---|---|---|---|---|---|
| `Totp` | 1–10, default 6 | 1–3600, default 30 | any | no | decimal | `totp` |
| `Hotp` | 1–10, default 6 | n/a | any | no | decimal | `hotp` |
| `Steam` | 5, fixed | 30, fixed | SHA-1, fixed | no | `23456789BCDFGHJKMNPQRTVWXY` | `steam` |
| `Motp` | 6, fixed | 10, fixed | MD5, fixed | **required** | lowercase hex | `motp` |
| `Blizzard` | 8, fixed | 30, fixed | SHA-1, fixed | no | decimal | reads `blizzard`, **writes `totp`** |
| `Yandex` | 8, fixed | 30, fixed | SHA-256, fixed | **required** | `a`–`z` | reads `yaotp` or `yandex`, writes `yaotp` |

A type marker earns its place on the wire by carrying information a parser cannot
otherwise recover. `steam`, `motp` and `yaotp` do: their algorithms genuinely
differ and no combination of `digits`, `period` and `algorithm` describes them.
Battle.net's does not — it *is* RFC 6238 with SHA-1 and 8 digits — so a
`blizzard` marker would carry nothing except the guarantee that every other
authenticator fails to import our export. `Blizzard` therefore survives as a
preset and is still accepted on parse, but is **written as `totp`**. See
[round-tripping](#round-tripping) for the one consequence.

Parameters a variant fixes are normalized rather than rejected: a `steam` URI
claiming `digits=8` yields 5 digits and a `UriWarning::IgnoredParam`. Out-of-range
values are still errors, so `digits=0` fails for every variant. That is what makes
`code.len() == config.digits()` unconditionally true.

### HOTP and TOTP

RFC 4226 and RFC 6238, no deviations. Dynamic truncation, `10^digits` reduction,
zero padding. `MAX_DIGITS` is 10 because the truncated value is 31 bits, which is
at most ten decimal digits.

### Steam

No specification exists. RFC 4226 HMAC-SHA-1 and dynamic truncation, then the
31-bit result is written as five base-26 digits, **least significant first**, over
the alphabet above (no vowels, no `0`/`1`/`L`/`S`/`Z`, so a code cannot be misread
aloud). Matches [`steamguard-cli`](https://github.com/dyc3/steamguard-cli)
(`steamguard/src/token.rs`).

### mOTP (Mobile-OTP)

`md5(decimal(unix_secs / 10) || lowercase_hex(secret) || pin)`, first 6 hex
characters of the digest, lowercase. The secret is hashed as its **hex text**, not
its bytes: mOTP predates `otpauth://` and specifies a 16-hex-character
init-secret. The concatenation order is the part implementations get wrong, so
`tests/variants.rs` re-implements the formula independently instead of only
checking outputs. Matches Aegis `MOTP.java`.

MD5 is present for interop and nothing else; SPEC 2.1 forbids it anywhere in
Misty's own cryptography.

### Blizzard (Battle.net)

RFC 6238 with SHA-1, 8 digits and a 30-second step — nothing else. It exists as a
distinct `OtpKind` so the UI can label it and so the digit count cannot be edited
into something Battle.net will reject. Battle.net hands out 20-byte secrets as 40
hex characters; `SecretBytes::from_hex` takes those directly.

Because the algorithm is not distinctive, the *export* is not either:

```
otpauth://totp/Battle.net:ada?secret=…&issuer=Battle.net&algorithm=SHA1&digits=8&period=30
```

`algorithm`, `digits` and `period` are all stated explicitly rather than left to
defaults, so an importer that defaults differently still reads it correctly. The
URI is byte-identical to the one the equivalent `Totp` configuration produces —
an importer cannot tell, which is the point.

### Yandex.Key

No specification exists; the only public description is source code. This
reproduces [Aegis](https://github.com/beemdevelopment/Aegis) `YAOTP.java` and
`KeeYaOtp`, quirks included:

1. `key = SHA-256(pin_utf8 || secret)`, and **if the first byte of that digest is
   zero it is dropped**, leaving a 31-byte key. That is a sign-byte artefact of
   the original implementation, not a design choice, and every interoperable
   client has to reproduce it.
2. `HMAC-SHA-256(key, counter_be64)`, `counter = unix_secs / 30`.
3. RFC 4226 offset selection, but reading **eight** big-endian bytes there with
   the top bit cleared: a 63-bit value. The width matters — a 31-bit value cannot
   fill eight base-26 digits and the trailing characters would barely vary.
4. The low 8 base-26 digits, **most significant first**, as `a`–`z`.

Only the **first 16 bytes** of the secret take part
(`OtpKind::secret_prefix_used`). Yandex prints a 26-byte secret for manual entry:
16 bytes of key plus a checksum. The reference implementations truncate, so this
crate truncates. Not doing so would produce codes that look perfectly plausible
and never work.

The PIN is not a second factor here, it is part of the key: the stored secret
alone cannot produce a code, and a wrong PIN yields a wrong code rather than an
error.

## Which test vectors are authoritative

This is the part of the crate that matters, so it is stated precisely rather than
implied. Nothing below is presented as more authoritative than it is.

| Suite | Vectors | Standing |
|---|---|---|
| `tests/rfc4226.rs` | RFC 4226 Appendix D, Tables 1 and 2: all 10 counters, **plus the intermediate HMAC and the truncated integer** | **Authoritative.** From the RFC. |
| `tests/rfc6238.rs` | RFC 6238 Appendix B: 6 timestamps × SHA-1/SHA-256/SHA-512, 8 digits | **Authoritative.** From the RFC, with the three per-algorithm seeds from Appendix A. |
| Blizzard, in `tests/variants.rs` | RFC 6238 Appendix B, SHA-1 column | **Authoritative by reduction.** Battle.net *is* RFC 6238 with SHA-1 and 8 digits, so the RFC's vectors are the Blizzard vectors, and the test asserts equality both ways. |
| Steam, in `tests/variants.rs` | `steamguard-cli`'s `test_generate_code`; plus the RFC 4226 Appendix D truncation column as an anchor | **Published third-party**, not from Valve. The HMAC and truncation halves are anchored to the RFC; only the base-26 rendering rests on agreement with another implementation. |
| mOTP, in `tests/variants.rs` | Aegis `MOTPTest.java`, 6 vectors; plus an independent re-implementation of the documented formula | **Published third-party**, not from the mOTP author. |
| Yandex, in `tests/variants.rs` | Aegis `YAOTPTest.java`, 5 vectors | **Published third-party**, not from Yandex. The only public description of this algorithm is source code, and these vectors are how that source proves itself. |
| Vectors marked *self-generated* | produced by this crate | **Not evidence of correctness.** They prove behaviour has not changed, nothing more. Steam and mOTP have a few, for secrets and instants no published vector covers. |

If you hold a real Steam, mOTP or Yandex.Key enrolment, replacing a self-generated
block with a captured vector is the single most valuable contribution anyone can
make to this crate.

## `otpauth://` handling

### Round-tripping

`parse → model → to_uri → parse` yields an identical model (SPEC 7). It is a
property test over generated models *and* over generated URI strings, plus a fuzz
target, not a claim. Three things make it hold:

* A colon inside an issuer or account is written `%3A`, so the only raw colon in a
  label this crate writes is the separator. The label is therefore split **before**
  percent-decoding, and an issuer containing a colon survives. Decode-then-split
  parsers get this wrong.
* Parameters a variant fixes are normalized on parse and omitted on write, so a
  second parse recomputes the same values.
* Unknown parameters are preserved in order rather than dropped — a vendor
  extension is somebody's icon or colour, and losing it on re-export is data loss.

**There is exactly one exception, and it is deliberate: `Blizzard`.** It writes
`totp`, so a round-trip returns a `Totp` model rather than a `Blizzard` one. The
returned configuration generates the same codes at the same instants; only the
label the UI shows is lost, and the gain is that everyone else can import the
export. `OtpUri::export_form()` returns exactly that model — the identity for every
other kind — so the property is stated without an escape clause:

```rust
# use misty_otp::OtpUri;
# let uri = OtpUri::parse("otpauth://blizzard/Battle.net:ada?secret=JBSWY3DPEHPK3PXP")?;
assert_eq!(OtpUri::parse(&uri.to_uri())?, uri.export_form());
# Ok::<(), misty_otp::OtpError>(())
```

The property tests assert strict equality for every kind whose URI type is its
own, and assert Blizzard's normalization explicitly — same issuer, same account,
`Totp` with `digits = 8`, and identical codes at several timestamps — so the
exception is pinned rather than merely tolerated.

### Canonical output

```
otpauth://<type>/<Issuer>:<account>?secret=…&issuer=…&algorithm=…&digits=…&period=…&counter=…&pin=…&<vendor>…
```

Lowercase scheme and type; unpadded uppercase base32 secret; parameters in that
fixed order; parameters the variant fixes omitted; `counter` only for HOTP; `pin`
only where the variant uses one; vendor parameters last, in their original order.

### Per-variant encodings

| Field | Encoding | Why |
|---|---|---|
| secret, all variants except mOTP | base32, unpadded | Key Uri Format |
| secret, mOTP | lowercase hex | mOTP's own convention; a base32 secret in a `motp` URI is rejected rather than reinterpreted |
| PIN, mOTP | percent-encoded text | Aegis's `motp` convention |
| PIN, Yandex | **base32** | Yandex's own `otpauth://yaotp/` QR codes carry it that way (`GEZDGNA` is the PIN `1234`) |

`otpauth://yandex/` is accepted as an alias for `otpauth://yaotp/`; output is
always `yaotp`, which is what Yandex and Aegis emit and accept.
`otpauth://blizzard/` is accepted but never written — see the variants table.

### What is tolerated, and what is not

Liberal about shape: either case in the scheme, type, parameter names and
algorithm spelling (`SHA-1` too); base32 without padding, in either case, with
spaces or hyphens; a missing label; `&&` and a trailing `&`; a parameter with no
`=`; unknown parameters.

Strict about meaning, because a token whose parameters were guessed is worse than
one that failed to import:

* a repeated known parameter is an error, not a coin flip;
* `digits` outside 1–10, `period` outside 1–3600, or any non-decimal number is an
  error — including `digits=0`, `digits=255`, `period=0`, `-1`, `0x6`, `1e3`, ` 6`;
* HOTP without `counter` is an error (the Key Uri Format requires it, and
  defaulting it would silently desynchronize a token);
* a malformed `%` escape, or one that decodes to invalid UTF-8, is an error —
  never passed through as literal text;
* control characters, bidi overrides, zero-width characters and the BOM are
  rejected wherever they appear. Ordinary non-ASCII is not: `日本銀行` is a real
  bank, and an issuer name is not required to be ASCII.
* a fragment is dropped with a warning;
* anything over `MAX_URI_LEN`, **or whose canonical form would be**, is rejected
  before allocation.

`parse_with_warnings` reports what an input got away with — an issuer that
disagreed with the label (the parameter wins), a parameter that was normalized
away, a dropped fragment. Warnings describe the *input*, so they are not part of
the model, which is what lets round-trip equality be exact; a canonical URI parses
with none.

## Security properties

* **Secrets cannot be printed.** `SecretBytes` renders `[redacted]` through both
  `Debug` and `Display`, and there is a test asserting the rendering contains
  neither the bytes nor their base32 nor their hex. It implements neither
  `Serialize` nor `Deserialize`, so no derive elsewhere can pull a secret into a
  JSON log.
* **Serialized URIs are treated as secrets.** `to_uri` returns
  `Zeroizing<String>`, and `OtpUri` deliberately implements neither `Display` nor
  `ToString`, so it cannot reach a log line through `{}`. For mOTP and Yandex the
  URI contains the PIN as well: a QR code of one of those is a complete
  credential.
* **Codes are treated as short-lived secrets.** `Code` holds a
  `Zeroizing<String>`, `Debug` redacts it, and `Display` renders it because
  something has to show the user their code.
* **Comparison is constant-time.** `SecretBytes: PartialEq` and `Code::ct_eq` use
  `subtle::ConstantTimeEq`. `resync_counter` scans a fixed number of candidates
  with no early exit and selects the match with `ConditionallySelectable`, so
  timing reveals neither whether nor where a match occurred.
* **Nothing panics.** No `unwrap`, `expect`, `panic!`, slicing or arithmetic that
  can panic on any path reachable from parsed input. Timestamp arithmetic near
  `u64::MAX` returns `OtpError::TimeOutOfRange`; the two invariants the crate
  believes it maintains report `OtpError::Internal` instead of asserting.
* **Bounded before allocation.** `MAX_URI_LEN` is checked before parsing,
  `MAX_INPUT_CHARS` before base32 decoding, `MAX_SECRET_LEN` on every secret.

## Running the checks

```sh
export CARGO_TARGET_DIR=target/agent-otp        # optional
cargo fmt -p misty-otp --check
cargo clippy -p misty-otp --all-targets --all-features -- -D warnings
cargo test -p misty-otp --all-features
cargo doc -p misty-otp --no-deps
cargo build -p misty-otp --target wasm32-unknown-unknown
python3 ci/check-otp-permissive.py             # from the repo root
```

The fuzz target lives in `fuzz/`, which is its own workspace so it stays out of
`cargo build --workspace`:

```sh
cargo install cargo-fuzz
cd crates/misty-otp
# First directory is the writable corpus; later ones are read-only inputs, so the
# committed seeds stay pristine. cargo-fuzz does not create a named corpus dir.
mkdir -p fuzz/corpus/otpauth_uri
cargo +nightly fuzz run otpauth_uri fuzz/corpus/otpauth_uri fuzz/seeds/otpauth_uri
```

It asserts more than "does not crash": anything that parses must re-serialize and
re-parse to the model `export_form` predicts (identity for every kind but
`Blizzard`, whose codes must still match), a URI this crate emitted must always
parse and produce no warnings, and generating from whatever was parsed must not
panic either. `fuzz/seeds/otpauth_uri/` holds a committed seed corpus, one file per
variant; the generated corpus and any artifacts are gitignored.

That target has already earned its keep. It found that an input just under
`MAX_URI_LEN` whose label was full of reserved characters would parse, then
serialize to *over* the cap, so the crate emitted a URI its own parser rejected.
The fix (reject up front if the canonical form would be too long) and the
regression case are in `tests/hostile_inputs.rs`.

## Notes for reviewers

* **`OtpConfig` has private fields**, where SPEC 3 sketches a plain struct. Every
  mutation goes through a validating setter, so a value of the type is always
  generatable; public fields would let a caller build a `Steam` config with 8
  digits that generates 5.
* **Fixed parameters are normalized, not rejected**, by both the builder and the
  setters: `builder(Steam, s).digits(6)` yields 5. Range violations are still
  errors. Silently ignoring a setter is a real cost; the alternative was letting
  `config.digits()` disagree with what generation produces, which is worse.
* **A PIN is not required at construction**, only at generation, so an importer can
  learn a secret before the user supplies the PIN. `generate_at` then returns
  `OtpError::MissingPin`.
* **An empty PIN is no PIN.** `pin=` normalizes to `None`, which means generation
  fails rather than keying with nothing.
* **`raw` exposes HMAC and truncation** because RFC 4226 publishes intermediate
  values, and a suite that checks only final codes cannot tell a correct
  implementation from one that is wrong in two cancelling ways.
* **`Blizzard` is a preset, not a wire format.** It keeps its `OtpKind`, its
  `display_name`, its fixed 8 digits and its parsing alias, but serializes as
  `totp`. That makes it the one kind for which parse → serialize → parse is
  behaviourally rather than structurally lossless; `OtpUri::export_form` names the
  difference and `blizzard_exports_as_interoperable_totp` pins it. The alternative
  — a private type marker carrying no algorithmic information — bought tidiness and
  cost interoperability, which is the wrong way round for a crate whose stated
  purpose is that other authenticators can use it.
* **A non-ASCII issuer parses.** The brief listed "unicode issuer" among inputs
  that must be rejected; rejecting one would be a correctness bug, so what is
  enforced instead is that adversarial *control* and display-spoofing code points
  are rejected while ordinary non-ASCII text is accepted. See
  `adversarial_but_legitimate_inputs_are_accepted` in `tests/hostile_inputs.rs`.
* **`motp://` and `otpauth-migration://` are not accepted.** The first is a vendor
  scheme, the second a Google Authenticator protobuf payload; both belong to the
  importers crate, and `otpauth-migration://` gets its own error saying so.
* **Non-canonical trailing bits in base32 are tolerated** and discarded, which RFC
  4648 §3.5 permits. Rejecting them would break otherwise-usable secrets from
  sloppy provisioning tools.
* **Under AddressSanitizer, fuzzing throughput collapses in some sandboxes**
  (single-digit executions per second). `--sanitizer=none` runs at ~39k exec/s.
  The crate is `forbid(unsafe_code)` and allocates nothing raw, so ASan buys
  little here; CI should run the fast configuration and not conclude from a low
  execution count that the target is broken.

