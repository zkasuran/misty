<!--
SPDX-FileCopyrightText: 2026 The Misty Authors

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# `misty-crypto` — Misty cryptographic core

> **Crate naming:** the directory and crate are still `misty-crypto`; the
> brand-derived byte constants below are already `Misty`. The crate rename is a
> separate atomic sweep.

Implements [`docs/SPEC.md`](../../docs/SPEC.md) §2 byte for byte. This is the
only place in Misty where cryptography happens: every other crate gets keys and
envelopes from here and never touches a primitive directly.

* `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`
* Pure Rust, no C: builds for `wasm32-unknown-unknown`
* No `unwrap`/`expect`/`panic!`/slice-indexing outside tests — enforced by
  clippy lints in `src/lib.rs`, not by convention
* No `ed25519_dalek`, `x25519_dalek`, `argon2` or `chacha20poly1305` type appears
  in the public API, so a dependency bump is not a breaking change for callers

## Threat-model obligations

| ID | What this crate is responsible for |
|---|---|
| `A1` | A hostile sync server sees only signed, padded, opaque envelopes. Sizes leak in 256-byte buckets; nothing else does. |
| `A6` | A device absent from the client-signed roster is rejected **before** any decryption is attempted. Proved by test, not asserted by comment. |
| `A8` | Backups are sealed under a separate Argon2id-derived passphrase key, independent of every vault unlock factor. |

## Key hierarchy (SPEC §2.2)

```text
Recovery Key (RK)   32B random. Shown once. Wraps VK. Never stored unwrapped.
Vault Key (VK)      32B random. Root of all item encryption.
Epoch Key (EK_n)    HKDF-SHA512(ikm=VK, salt="misty/epoch/v1", info=LE32(n))
Item Key (IK)       32B random per item. Wrapped by EK_current.
KDF Key             Argon2id(passphrase, salt, tier), or an HKDF output used
                    as a KEK (the enrollment sealing key).
```

`wrap(outer, inner, ctx) = XChaCha20Poly1305(key=outer, nonce=random24,
pt=inner, aad=ctx)`.

Every key type — `VaultKey`, `EpochKey`, `ItemKey`, `RecoveryKey`, `KdfKey` —
is `Zeroize + ZeroizeOnDrop`, renders as `[redacted]` in `Debug` **and**
`Display`, and implements neither `Serialize`, `Clone`, nor `PartialEq`. `==` on
a key does not compile; use `constant_time_eq`. Keys leave the process only
through `envelope`, `backup`, `recovery::wrap_vault_key` or `enrollment`.

`EpochKey` additionally carries its epoch number. That is not in the spec: it
lets `envelope::open` return a typed `EpochMismatch` instead of an opaque AEAD
failure, and makes "decrypt with the key for its own epoch" the only easy thing
to write.

## Argon2id tiers (SPEC §2.3)

| Tier | Memory | Iterations | Lanes |
|---|---|---|---|
| `Interactive` | 64 MiB | 3 | 4 |
| `Moderate` | 256 MiB | 3 | 4 |
| `Sensitive` | 1 GiB | 4 | 4 |

`KdfTier::recommended_for(free_bytes)`: ≥4 GiB → `Sensitive`, ≥1 GiB →
`Moderate`, otherwise `Interactive` (~4× headroom over each tier's working set).
Parameters read from a file are attacker-controlled and are bounded by
`KdfParams::validate` before any allocation: 8 KiB–2 GiB memory, 1–16
iterations, 1–16 lanes, and at least 8 KiB per lane. Out-of-range parameters are
**rejected, not clamped** — clamping would derive a different key and report
"wrong passphrase" for a merely unusual file.
## Envelope format, as implemented (`ENVELOPE_FORMAT_VERSION = 1`)

All integers little-endian. Total length is always
`186 + 256n` for `n ≥ 1`; the minimum is 458 bytes.

```text
Header — 74 bytes, authenticated, not encrypted
  off  len  field
    0    4  magic = b"MSTY"
    4    1  format_version = 1
    5    1  kind: 1=Item 2=DeviceRoster 3=Settings 4=Group 5=CustomIcon
    6    4  epoch: u32
   10   16  signer_device_id
   26   24  wik_nonce
   50   24  payload_nonce

Body
   74   48  wrapped_item_key
              = XChaCha20Poly1305(key=EK_epoch, nonce=wik_nonce,
                                  pt=IK[32], aad=Header || item_id[16])
  122   ..  ciphertext            (always 256n + 16 bytes)
              = XChaCha20Poly1305(key=IK, nonce=payload_nonce,
                                  pt=pad(payload), aad=Header || item_id[16])
   ..   64  signature
              = Ed25519(signer_priv,
                        Header || item_id || wrapped_item_key || ciphertext)

pad(x) = LE32(x.len()) || x || 0x00 * k,  k least such that the total is a
                                          multiple of 256
```

`item_id` is **not** stored: it is the storage key, and it is bound into both
AEAD contexts and into the signature. An envelope cannot be relocated to another
item id, and a server that swaps two items' bytes produces two envelopes that do
not open.

`open` does exactly this, in this order:

1. parse the header and check the body's shape;
2. look the signer up in the roster — unknown signer, stop;
3. verify the Ed25519 signature (`verify_strict`) — bad signature, stop;
4. only now unwrap the item key, and only then decrypt and unpad.

The order is enforced by the type system: decryption lives on `Verified`, and the
only way to obtain one is `Envelope::verify` or `Envelope::verify_with_signer`,
because it holds a private field of a private type. `parse().open()` does not
compile.

`unpad` validates rather than trusts: the buffer must be a positive multiple of
256, the length prefix must fit, the padding must be the *minimal* amount for
the declared length, and every filler byte must be zero.

## Backup file, as implemented (`BACKUP_FORMAT_VERSION = 1`, `.mistybak`)

```text
  off  len  field
    0    8  magic = b"MISTYBAK"
    8    1  format_version = 1
    9    1  kdf_id = 1 (Argon2id)
   10    4  argon2_memory_kib: u32
   14    4  argon2_iterations: u32
   18    4  argon2_parallelism: u32
   22   16  salt
   38   24  nonce
   62    8  reserved, MUST be zero
   70   ..  XChaCha20Poly1305(key=Argon2id(passphrase, salt, params),
                              nonce, pt=deflate(CBOR(payload)), aad=Header)
```

Rejection order in `BackupHeader::parse`: too short → wrong magic → unknown
`format_version` → unknown `kdf_id` → non-zero `reserved` → out-of-range costs.
DEFLATE is `miniz_oxide` at level 6 (pure Rust; `zstd` carries C and would break
the wasm build). Decompression is capped at 64 MiB — a compression bomb gets
`InflateLimit`, not an allocation.

## Recovery Kit, as implemented (SPEC §2.6)

| Encoding | Layout |
|---|---|
| Words | 24 BIP-39 English words: `RK[32] \|\| SHA-256(RK)[0]` as 24 × 11-bit indices |
| Compact | Crockford Base32 of `RK[32] \|\| CRC32(RK)` big-endian, 58 characters in groups of 8 |
| QR | `misty-recovery:v1:` followed by the compact form |
| `recovery_blob` | `nonce[24] \|\| XChaCha20Poly1305(key=RK, nonce, pt=VK, aad="misty/recovery/v1")`, 72 bytes |

Decoding is deliberately forgiving of humans and unforgiving of corruption: any
case, any whitespace, `-`/`_` separators ignored, Crockford's `O`→`0` and
`I`/`L`→`1` foldings applied — but a wrong character is always caught by the
alphabet, the trailing-bit check, or the CRC32.
`suggest_word_repairs` handles the common failure (exactly one mistyped word) by
trying wordlist neighbours within one edit — two if what was typed is not a word
at all — and returning only substitutions whose checksum validates. Candidates
are restricted to near neighbours on purpose: the checksum is 8 bits, so an
unrestricted search would return ~192 plausible "fixes".

`english.txt` is the canonical BIP-39 English wordlist, shipped verbatim; its
SHA-256 (`2f5eed53…24dbda`) is asserted at test time. It is third-party content:
BIP-39 is MIT-licensed, so the file carries an `english.txt.license` sidecar
naming the BIP authors rather than inheriting the project's AGPL default.
## Identity, roster, enrollment

A device is an Ed25519 keypair (signs envelopes and server challenges), an X25519
keypair (agrees a key during enrollment), and 16 random bytes of `device_id`.

The roster signature covers a canonical encoding defined in `identity.rs`, not
the CBOR of the item, so re-serialising with a different CBOR writer cannot
invalidate it:

```text
"misty/roster/v1" || LE32(device_count) || signer_device_id[16]
per device, in order:
  device_id[16] || ed25519_pub[32]
  LE32(name_len)     || name (UTF-8)
  LE32(platform_len) || platform (UTF-8)
  LE64(enrolled_at)
  0x00, or 0x01 || enrolled_by[16]
```

`Roster::add` and `Roster::remove` clear the signature, so a revoked device
cannot be resurrected by replaying an old one.

Enrollment (SPEC §6.3) derives its sealing key as
`HKDF-SHA512(ikm=X25519(shared), salt=enroll_id, info="misty/enroll/v1" ||
approver_x25519_pub || new_device_x25519_pub)`, so a sealed grant cannot be
replayed into another enrollment and neither side can be misled about whose key
it agreed with. The 6-digit confirmation code is
`BLAKE2b-256(canonical_request)[0..4]` as a big-endian `u32` mod 10⁶, and
`approve` refuses to seal unless the code the user compared matches the request.
`NewDeviceEnrollment::open` checks, in order: `enroll_id`, the AEAD, the CBOR,
the roster's shape, the approver's presence in the delivered roster, the
approver's signature, the roster's own signature, and finally that this device is
in that roster under its own key.

## Which vectors are authoritative and which are ours

| Vector | Status | Location |
|---|---|---|
| Argon2id, RFC 9106 §5.3 (with secret and associated data) | **authoritative** | `src/kdf.rs` |
| XChaCha20-Poly1305, draft-irtf-cfrg-xchacha-03 §A.3.1 | **authoritative** | `src/aead.rs` |
| HKDF-SHA-256, RFC 5869 §A.1–A.3 | **authoritative** | `src/derive.rs` |
| Ed25519, RFC 8032 §7.1 TEST 1–3 | **authoritative** | `tests/kat_authoritative.rs` |
| BIP-39 English, eight 256-bit reference vectors | **authoritative** | `tests/kat_authoritative.rs` |
| CRC-32 catalogue check value | **authoritative** | `src/recovery/crc32.rs` |
| Epoch keys `EK_0`, `EK_7` | self-generated, cross-checked | `src/derive.rs` |
| Whole envelope, 458 bytes | self-generated, cross-checked | `src/envelope/tests.rs` |
| Backup header, 70 bytes | self-generated | `src/backup/tests.rs` |
| Whole backup file | self-generated, cross-checked | `src/backup/tests.rs` |
| `miniz_oxide` DEFLATE output at level 6 | self-generated | `src/backup/tests.rs` |
| Compact and QR encodings | self-generated, cross-checked | `src/recovery/tests.rs` |
| `recovery_blob` | self-generated, cross-checked | `src/recovery/tests.rs` |

"Cross-checked" means the expected bytes were reproduced by an independent
implementation before being frozen here — libsodium's
`crypto_aead_xchacha20poly1305_ietf` and Ed25519 via PyNaCl, Argon2id via
`argon2-cffi` (the reference C implementation), HKDF-SHA-512 and BIP-39 written
directly on Python's `hmac`/`hashlib`, CRC-32 via `zlib`, and Crockford Base32
written from the specification. Those implementations cannot be used in the
product — libsodium does not build for `wasm32-unknown-unknown` (SPEC §0) — but
they make good oracles, and it means the golden vectors pin the format against
something other than themselves.

Two caveats an auditor should know:

* There are no published HKDF-**SHA-512** vectors. RFC 5869 covers SHA-1 and
  SHA-256, so those run instead, and the SHA-512 wiring is pinned by a
  cross-checked frozen vector.
* The whole-file backup vector embeds `miniz_oxide`'s exact DEFLATE output. A
  `miniz_oxide` bump that changes the encoder breaks that test and
  `frozen_deflate_output` together, which is the signal to re-freeze both. Files
  written by the old version still open: inflating does not care how they were
  deflated.
## What an auditor should look at first

In this order. The first three are where a mistake would be both catastrophic and
invisible.

1. **`src/envelope/mod.rs`, `Verified` and `Envelope::verify`.** Everything in
   threat model `A1`/`A6` rests on decryption being unreachable before the roster
   and signature checks. Check that `SignatureProof` cannot be constructed
   outside the module, that `Verified::open` is the only decrypting function, and
   that the AAD is `Header || item_id` in both AEAD calls. The tests named
   `*_fails_before_any_decryption` count AEAD attempts through a thread-local
   counter and assert zero — read those next.
2. **`src/envelope/pad.rs`, `unpad`.** The one parser that runs on
   *authenticated but attacker-chosen* plaintext, reachable by anyone holding one
   item key. Every rejection there is load-bearing.
3. **`src/keys.rs`.** Confirm no key type gained `Serialize`, `Clone`,
   `PartialEq`, or a derived `Debug`. `tests/redaction.rs` asserts the rendering;
   the missing trait impls are what make a leak hard in the first place.
4. **`src/kdf.rs`, `KdfParams::validate`.** The denial-of-service boundary for
   attacker-supplied Argon2 costs, and the only place where the "reject, do not
   clamp" decision lives.
5. **`src/backup/mod.rs`, `BackupHeader::parse`.** Rejection order, the
   `reserved` check, and that the AAD is the header *as read from the file*
   rather than a re-serialisation of the parsed struct.
6. **`src/random.rs`.** The single entropy choke point. The only call to
   `getrandom::getrandom` in the crate is there; the only other mentions are the
   error conversion in `src/error.rs` and prose.
7. **The frozen golden vectors** (`src/envelope/tests.rs`,
   `src/backup/tests.rs`, `src/recovery/tests.rs`). If a change breaks one and the
   format was not deliberately changed, something drifted. If the format *was*
   changed, the matching `*_FORMAT_VERSION` must move in the same commit.
8. **`src/derive.rs` and the domain-separation strings.** `misty/epoch/v1`,
   `misty/recovery/v1`, `misty/roster/v1`, `misty/enroll/v1`,
   `misty/enroll-request/v1`, `misty/enroll-seal/v1`. Every one of them is baked
   into key material or a signature; changing one is a format break.

Deliberate strictness that might look like over-reach: non-minimal padding is
rejected, non-zero padding filler is rejected, non-zero `reserved` is rejected,
unknown envelope `kind` values are rejected rather than ignored, and ciphertext
lengths that are not `256n + 16` are rejected at parse time. All are
consequences of the format as specified; each of them turns a silent
misinterpretation into a typed error.

## Deviations from `docs/SPEC.md`

1. **`envelope::seal`/`open` take and return raw bytes, not CBOR.** SPEC §2.4
   writes `pt=pad(CBOR(payload))`. This crate pads and encrypts bytes the caller
   already serialised, because it deliberately knows nothing about the item
   model; CBOR happens at the vault layer. `backup::seal`/`open` do run the CBOR
   step, since the payload there is opaque to the caller too.
2. **`envelope::open` returns `Zeroizing<Vec<u8>>`, not `Vec<u8>`.** The
   decrypted payload is secret material and SPEC §9 requires secrets to be
   zeroized. It derefs to `Vec<u8>`, so this costs callers nothing.
3. **`EpochKey` carries its epoch number.** See the key-hierarchy section.
   `seal` also takes an explicit `epoch` and rejects it if it disagrees with the
   key, so the two cannot silently diverge.
4. **`EnrollmentRequest` carries `device_id`.** SPEC §6.3.1 lists five QR fields
   and no `device_id`, but the roster record in §6.2 requires one and ids belong
   to the device that generates them (§3). Without it the approver would have to
   invent an id for someone else's device. It is covered by the confirmation
   code, so it cannot be substituted in transit unnoticed. **This is a spec gap,
   not a disagreement — §6.3.1 should list it.**
5. **The exact enrollment HKDF inputs are defined here.** SPEC §6.3 says only
   "X25519 + HKDF"; the salt, info string and key-commitment are this crate's
   choice, documented in `src/derive.rs`.

## Layout

```text
src/lib.rs            crate docs, lint policy, module wiring
src/error.rs          every typed error; no variant carries secret material
src/types.rs          ItemId, DeviceId, VaultId, EnrollId, SignatureBytes
src/keys.rs           the key hierarchy
src/random.rs         the only entropy source
src/aead.rs           XChaCha20-Poly1305, wrapped once  (private)
src/kdf.rs            Argon2id tiers and parameter bounds
src/derive.rs         HKDF-SHA-512 epoch and enrollment schedules
src/envelope/         the envelope format, padding, golden vectors
src/backup/           the .mistybak format, golden vectors
src/recovery/         words, Crockford Base32, CRC-32, wordlist, golden vectors
src/identity.rs       DeviceIdentity, DeviceRecord, Roster
src/enrollment.rs     device-to-device enrollment
tests/                see below
fuzz/                 cargo-fuzz targets (own workspace, nightly)
```

| Test file | What it covers |
|---|---|
| `kat_authoritative.rs` | RFC 8032 and BIP-39 published vectors |
| `negative_paths.rs` | one assertion per typed error, through the public API |
| `hostile_inputs.rs` | malformed corpus, every truncation and bit flip |
| `properties.rs` | `proptest` round trips, padding boundaries, no-relocation |
| `recovery_kit.rs` | the three encodings agree, over random keys |
| `enrollment_flow.rs` | the §6.3 flow end to end, plus every refusal |
| `redaction.rs` | no key type prints its bytes |

## Running the gates

```sh
cargo fmt -p misty-crypto --check
cargo clippy -p misty-crypto --all-targets --all-features -- -D warnings
cargo test -p misty-crypto --all-features
cargo doc -p misty-crypto --no-deps
cargo build -p misty-crypto --target wasm32-unknown-unknown
```

The fuzz targets need nightly and live in their own workspace:

```sh
cd crates/misty-crypto/fuzz
cargo +nightly fuzz run envelope_open
cargo +nightly fuzz run backup_header
```

`tests/hostile_inputs.rs` covers the same two entry points on stable, so CI has
coverage of them on every commit without a fuzzing run.
