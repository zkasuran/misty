<!--
SPDX-FileCopyrightText: 2026 The Misty Authors

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# `misty-vault` — the item model, the CRDT merge engine, and encrypted storage

Implements [`docs/SPEC.md`](../../docs/SPEC.md) §3 (data model), §3.1 (multiple
accounts on one site), §4 (CRDT and merge rules) and §5 (storage).

This crate is a **consumer** of `misty-crypto` and `misty-otp`, not a
re-implementer of either. No cryptographic primitive is touched here: keys,
envelopes and signatures all come from `misty-crypto`, and `OtpConfig` /
`SecretBytes` are `misty-otp`'s types. What this crate owns is the CBOR encoding
of a payload, the merge rules over it, and the rows it lands in.

* `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`,
  `#![warn(missing_debug_implementations)]`
* No `unwrap`/`expect`/`panic!`/slice indexing outside tests — enforced by clippy
  lints in `src/lib.rs`, not by convention
* AGPL-3.0-or-later. This is not the permissive crate; `misty-otp` is, and
  `ci/check-otp-permissive.py` exists to keep the dependency arrow pointing this
  way only

## Threat-model obligations

| ID | What this crate is responsible for |
|---|---|
| `A1` | The schema has no searchable plaintext column and no index over anything but the primary key, so there is no data structure whose *shape* answers "does this vault have an account at `binance.com`". Search runs over the decrypted in-memory model. |
| `A1` | A hostile server's rewrite of the two plaintext columns it can see (`kind`, `hlc_max`) is detected: both are cross-checked against the authenticated payload on load. |
| `A1` | The server's `deleted` flag from SPEC §6.1 is **not read**. A delete is a signed tombstone inside the encrypted payload, so a server cannot erase a vault it cannot read. |
| `A4` | Secrets live in `SecretBytes` (zeroized on drop, renders `[redacted]`). The CBOR buffer that briefly holds one is `Zeroizing`, and the transient wire struct is wiped explicitly after encoding. |
| `A9` | `requires_reveal_auth` and `hidden` are per-item, replicated fields, so a reveal gate set on one device holds on all of them. |
| `A11` | `origins` is an OR-Set of folded domain names, so a concurrent add on two devices does not lose one — an origin list that silently shrank would turn the extension's mismatch warning off. |

## The model (SPEC §3)

SPEC §3 lists `Item`'s fields as plain values. SPEC §4 then requires that
"mutable fields carry a hybrid logical clock", and the two cannot both be
literally true, so each field is wrapped in the replicated type that implements
its rule. `Item` is that wrapped struct; every field is private and the only way
in is `Vault::update`, which stamps a clock.

| SPEC §3 field | Type here | Merge rule |
|---|---|---|
| `id` | `ItemId` | immutable; the storage key |
| `otp.secret` | `SecretBytes` | **immutable**; divergence forks the item |
| `otp.kind`, `otp.algorithm`, `otp.digits`, `otp.period`, `otp.pin` | `Lww<_>` | last writer wins |
| `otp.counter` | `MaxWins<u64>` | greater value wins |
| `issuer`, `account`, `nickname`, `note`, `icon`, `color`, `favorite`, `manual_order`, `archived`, `hidden`, `requires_reveal_auth` | `Lww<_>` | last writer wins |
| `groups`, `tags`, `origins` | `OrSet<_>` | per-element add/remove clocks, add wins on tie |
| `usage` | `UsageCounter` | per-device maximum, read as the sum |
| `last_used_at` | `MaxWins<Option<i64>>` | later *reading* wins |
| `created_at` | `MinWins<i64>` | earlier claim wins |
| `deleted` | `Option<Tombstone>` | wins only over strictly earlier field edits |
| — | `trashed_at: Lww<Option<i64>>` | the 30-day trash, added here |

`otp: OtpConfig` is **decomposed** rather than wrapped, because its fields do not
share one rule: the secret is immutable, the counter is max-wins, and the rest are
last-writer-wins. `Item::otp()` reassembles a real `OtpConfig` on demand, so
callers still get the type SPEC §3 promises and `misty-otp` stays the only
definition of it.

`Group` is its own encrypted object (`kind = 4`), not a string on each item: a
rename would otherwise have to rewrite every member, which is a multi-item write
with no cross-device transaction, and two devices renaming concurrently would
split the group in two. Membership lives on the item side, so joining a group is
one item write.

Ids are 16 CSPRNG bytes from `misty_crypto::random`, never UUIDv7 — a timestamp
prefix would leak item creation order to the server.

## The hybrid logical clock (SPEC §4)

```rust
struct Hlc { wall_ms: u64, counter: u16, device_id: [u8; 16] }  // Ord = lexicographic
```

On the wire it is one 26-byte big-endian byte string, chosen so that **byte order
equals `Ord`**. That is what lets the SQLite backend store `hlc_max` as a `BLOB`
and still get a correct `ORDER BY` out of SQLite's own memcmp, without teaching the
database anything about the vault.

**A clock that goes backwards must not produce a regressing `Hlc`.** An NTP
correction, a wrong RTC or a user setting the date by hand all move the wall clock
backwards, and a regressing clock lets an *older* edit beat a newer one — silent
data loss that no error surfaces. `HlcClock::tick` therefore never emits a value
below the last one it emitted: if the wall clock has not advanced the counter does,
and if the counter saturates at 65 535 writes in one millisecond it borrows a
millisecond from the future rather than wrapping.

**`wall_ms` is bounded, and the bounds are absolute:**
`[2020-01-01, 2100-01-01)`. Fixed constants rather than "now ± skew" on purpose —
a merge whose outcome depended on the reader's own clock would not converge,
because two devices reading the same pair of writes at different moments would
disagree about which to keep. The write path *clamps* into the window so a device
with a broken clock still records its edits; the read path *rejects*, so a corrupt
or hostile payload never enters the model.

## Every merge rule, and why it is that rule

### `Lww` — last writer wins, by `Hlc`

For plain user edits, where the most recent intent simply is the right answer. The
`device_id` tiebreak means two devices resolve a same-millisecond tie identically
without exchanging anything but the two values.

Two differing values under one *identical* clock is reported as
`VaultError::ClockCollision` rather than resolved. It cannot arise from writes this
crate made — `HlcClock` never issues the same `(device, ms, counter)` triple twice —
and it cannot arise from a forged envelope, because envelopes are Ed25519-signed by
a rostered device. Resolving it by keeping `self` would make merge
non-commutative, which is the property the whole crate rests on, and would bury the
writer bug that caused it.

*Tested:* `crdt/lww.rs` unit tests; `merge_rules::same_millisecond_edits_resolve_the_same_way_on_both_devices`.

### `otp.counter` — max wins

A lower HOTP counter replays a code the issuer has already consumed and desyncs the
token. `MaxWins` refuses a losing write rather than applying it, so
`set_hotp_counter(id, 1)` on a counter at 3 returns 3.

*Tested:* `merge_rules::a_hotp_counter_never_regresses_under_any_interleaving`
(three offline advances against one, synced in both directions, repeatedly);
`same_site_accounts::folding_a_duplicate_never_rolls_a_counter_back`.

### `usage` — per-device G-counter, merge is per-key max, read is the sum

One shared integer under last-writer-wins would silently discard everything an
offline device counted, and usage is what drives "most used" sorting and the
"used 2m ago" hint SPEC §3.1 relies on to tell two same-issuer accounts apart.
Merging takes the maximum per device and never a sum, because merging twice would
otherwise double-count.

*Tested:* `merge_rules::usage_counts_from_three_offline_devices_sum` (4 + 7 + 1 = 12
through a fan-in, then re-merged twice to prove no double count);
`crdt/usage.rs` unit tests.

### `groups`, `tags`, `origins` — OR-Set, add wins on tie

Last-writer-wins over the whole vector loses concurrent additions: two devices each
adding one tag offline would keep only one. Each element carries an `added` clock
and an optional `removed` clock; merge takes the maximum of each independently, and
an element is present when `added >= removed`. Taking each maximum independently is
what makes this a *join* — there is no branch on which side is newer, so the result
cannot depend on the order or grouping of merges.

Entries for removed elements are retained. Dropping them would break convergence
rather than save space: a peer that still holds the add would re-introduce the
element on the next sync, forever.

*Tested:* `merge_rules::concurrent_tag_add_and_remove_keeps_both_additions`,
`merge_rules::a_later_tag_removal_sticks`.

### `deleted` — a tombstone wins only over strictly earlier edits

Resurrection-by-edit is worse than a stale delete, but a delete must not beat a
*later* edit: a user who deletes an item on their phone and then renames it on their
laptop meant to keep it.

Deletedness is a **derived predicate**, `tombstone.hlc > max_field_hlc()`, evaluated
fresh from the merged state — never a flag written during merge. Writing a flag
would mean discarding either the tombstone or the edit that beat it, and the next
peer to sync would resurrect the loser. `usage`, `otp.counter` and `last_used_at`
carry no clock and are deliberately absent from `max_field_hlc()`: generating a code
on a device that had not yet seen the delete must not undelete the item.

*Tested:* `merge_rules::a_delete_loses_to_a_later_edit`,
`merge_rules::a_delete_beats_an_earlier_edit`,
`vault_lifecycle::a_restore_works_before_and_after_the_tombstone`.

### `otp.secret` — immutable; divergence keeps **both** items

> Silently picking one can destroy the only working token. Never guess with a
> credential. — SPEC §4

`Item::merge` refuses two different secrets outright, so no caller can reach a code
path that would have to choose. `ItemSet::absorb` resolves it by keeping both as
separate items and raising `Conflict::DivergentSecret`.

The forked id has to be **derived, not drawn**. A fresh random id would break
convergence — two devices performing the same split would invent different ids — and
break idempotence, because re-running the merge would fork again. So:

```text
forked_id = HKDF-SHA512(ikm = VK,
                        salt = "misty/vault/fork-id/v1",
                        info = original_item_id || secret)[0..16]
```

Keying it on the **vault key** rather than on the secret alone is deliberate. An
item id is stored in the clear and a hostile server sees it (`A1`).
`H(secret)[0..16]` would hand that server an oracle: guess a secret, compute the id,
and a match confirms the guess. Under `VK` the id is a PRF output the server cannot
compute at all, while every device that holds `VK` derives the same value.

Which credential keeps the original id is decided by comparing the two secrets
bytewise — the smaller keeps it. Arbitrary, but total and agreed on by every device,
which is all convergence requires.

*Tested:* `merge_rules::divergent_secrets_produce_two_items_and_a_conflict` (both
directions reach the same two ids), `merge_rules::forking_is_idempotent`,
`convergence::three_divergent_secrets_converge_from_every_direction` (all six
orderings of three divergent secrets), and the `RepairSecret` op in the property
tests.

### `otp.pin` — last writer wins, *and* a conflict is reported

Not in SPEC §4's table. See "Deviations" below for the reasoning.

*Tested:* `merge_rules::a_divergent_pin_is_reported_but_resolved`.

### Trash: 30 days, then a tombstone; tombstones purge at 90

`trash_item` sets `trashed_at`, an ordinary last-writer-wins field, so a restore is
just a later write to it and propagates like any other edit. `sweep_trash` converts
expired trash to tombstones; `purge_tombstones` drops the row 90 days after the
tombstone.

The purge is the one operation in the crate that is **not** a CRDT join, because
"forget that this ever existed" has no representation that survives a merge. A peer
offline for more than 90 days that still holds the item will reintroduce it. That is
the standard tombstone-GC trade-off, and the 90-day window is what makes it
acceptable: far longer than any plausible offline period, and the cost of being
wrong is a resurrected item the user can delete again rather than a lost one.

*Tested:* `vault_lifecycle::trash_retention_runs_for_thirty_days_before_a_tombstone`,
`vault_lifecycle::tombstones_are_purged_after_ninety_days`,
`vault_lifecycle::a_restore_on_one_device_reaches_the_other`.

## Multiple accounts on one site (SPEC §3.1)

The rule enforced is the weakest one that guarantees a human can name which item
they mean: **nicknames within one `(issuer, account)` cluster must be pairwise
distinct, with "no nickname" counting as one of the values.** Comparison is
case-folded and trimmed, or the rule would be bypassed by the shift key.

| Situation | Result |
|---|---|
| `(issuer, account, secret)` all match | `VaultError::DuplicateAccount { existing }` — one credential seen twice. `Vault::merge_duplicate` folds the incoming metadata into the existing item. |
| `(issuer, account)` match, secret differs, nickname would collide | `VaultError::AmbiguousAccount { existing }` — two real accounts. Set a distinguishing nickname and retry. |
| `(issuer, account)` match, nicknames distinct | both kept |
| a rename would produce a colliding pair | `AmbiguousAccount`, and nothing is written |

The rule is enforced on `update` as well as `add`, because it is a statement about
the *state* of the vault: renaming one item onto another's pair produces exactly the
ambiguity rule 1 exists to prevent. A trashed item does not block an add — refusing
because of something in the bin would be inexplicable — so restoring it can
recreate a cluster, which the UI has to handle. Refusing the restore would be
worse: the alternative is telling the user their item is gone.

`Vault::same_site_cluster` is the query behind rules 2–4, and each item carries its
own `color`, `icon` and `last_used_at` so the distinction survives a glance.

*Tested:* all of `tests/same_site_accounts.rs`.

## Storage (SPEC §5)

```sql
CREATE TABLE items (
    item_id  BLOB    PRIMARY KEY NOT NULL,  -- 16 bytes, the envelope's AAD binds it
    kind     INTEGER NOT NULL,              -- envelope kind; cross-checked on load
    seq      INTEGER,                       -- the server's, NULL until synced
    version  BLOB,                          -- the server's If-Match token, opaque
    envelope BLOB    NOT NULL,              -- exactly what envelope::seal produced
    hlc_max  BLOB    NOT NULL               -- 26 bytes, byte order == Hlc order
) WITHOUT ROWID;

CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,        -- currently only "epoch"
    value BLOB NOT NULL
) WITHOUT ROWID;
```

`WITHOUT ROWID` because the primary key is a 16-byte blob: a rowid table would
carry a second index over it for nothing.

There is **no issuer column, no account column, no tag table, and no index over
anything but the primary key**. An index is a data structure whose shape answers
questions about its contents, and "does this vault contain an entry for
`binance.com`" is exactly the question the envelope format spends its whole design
refusing to answer. Search, sort and filter run over the decrypted in-memory model;
vaults are under 10 000 items, so that is both simpler and quieter than any
encrypted-index scheme.

`hlc_max` is the one derived value stored in the clear. It exists so a sync layer can
order changes without decrypting, and it leaks only what `seq` already does: that
something changed, and roughly when. Both it and `kind` are recomputed from the
authenticated payload on load and compared, so a server that rewrites either — to
hide an item by relabelling it a settings blob, or to reorder a sync — is caught.

Pragmas, applied on every open: `journal_mode=WAL`, `synchronous=FULL`,
`foreign_keys=ON`, `busy_timeout=5000`. There is no foreign key in v1;
`foreign_keys` is set anyway because SQLite defaults it *off* per connection, so a
future table that needs it would otherwise silently not get it.

**One writer** is the borrow checker's job, not a mutex's: every mutating method
takes `&mut self`, `Vault` owns its store by value, and no backend has `Clone` or
interior mutability. Two concurrent writers do not compile.

`VaultStore` is generic rather than `dyn`, and `transaction` is a *provided* method
over `begin`/`commit`/`rollback`. That split is what makes a wrapper backend
possible — the crash-injection store in `tests/crash_injection.rs` fails the Nth
write and delegates the rest — which would be impossible if `transaction` were the
only primitive, because a wrapper cannot hand its inner store a closure that expects
the wrapper.

### Crash safety

SPEC §5: "Every merge is a single transaction. A crash mid-sync MUST leave the vault
at its pre-merge state."

The storage half is the transaction. The in-memory half is the shape of every write
path: mutate a **clone**, seal every envelope *before* the transaction opens, and
adopt the clone only after the commit returns. A rolled-back database behind a model
that already adopted the merge is the worse of the two bugs — the user sees the
change and it silently vanishes on the next restart — so both are asserted, at every
write position, in `tests/crash_injection.rs`.

Cloning the model for a merge costs O(n). SPEC §5 caps a vault well under 10 000
items, so that is a few megabytes on an operation that happens at sync time, and it
buys an exactly-correct rollback with nothing to reconstruct.

### Migrations

Forward-only, versioned by `PRAGMA user_version` — which cannot be out of step with
the schema it describes, because it is written inside the same transaction as the
DDL and there is no table to be missing on a half-created database.
`store::MIGRATIONS` is indexed by the version it upgrades *from*, so applying every
script from `user_version` onwards is the whole algorithm. A file whose version is
higher than this build's is **refused**: SPEC §9 requires a checkpoint and an
integrity check before any destructive migration, and an old binary cannot perform
one it has never heard of.

`tests/fixtures/schema_v1.sql` is a frozen copy of v1's DDL, and
`migrations::the_frozen_fixture_matches_the_released_migration` compares it to
`MIGRATIONS[0]`. That test exists before it is needed on purpose: it fails the moment
someone edits a released migration in place instead of appending a step, which is the
mistake that silently breaks every install that already migrated.

## The CBOR wire format

The vault layer owns CBOR (SPEC §2.4: the envelope "treats `payload` as opaque bytes
and MUST NOT know how it is encoded"). Field names are two to three characters,
because payloads are padded to 256-byte buckets before encryption: roughly 300 bytes
of spelled-out field names is the difference between a typical item costing one
bucket and costing two, on every write, forever, and visibly to a server that counts
buckets.

| Key | Field | Key | Field |
|---|---|---|---|
| `v` | `format_version` | `icn` | `icon` |
| `id` | `id` | `col` | `color` |
| `sec` | `otp.secret` | `fav` | `favorite` |
| `knd` | `otp.kind` | `ord` | `manual_order` |
| `alg` | `otp.algorithm` | `arc` | `archived` |
| `dig` | `otp.digits` | `hid` | `hidden` |
| `per` | `otp.period` | `rva` | `requires_reveal_auth` |
| `pin` | `otp.pin` | `trs` | `trashed_at` |
| `cnt` | `otp.counter` | `usg` | `usage` |
| `isr` | `issuer` | `lus` | `last_used_at` |
| `acc` | `account` | `crt` | `created_at` |
| `nck` | `nickname` | `del` | `deleted` |
| `nte` | `note` | `nam` | `name` (group) |
| `grp` | `groups` | `tag` | `tags` |
| `org` | `origins` | | |

`tests/wire_format.rs` pins that exact key set, in order. `OtpKind` and `HashAlg`
are mapped to explicit wire bytes here rather than derived from their declaration
order upstream, so reordering a variant in `misty-otp` cannot change what is already
on disk.

Strictness: unknown keys are rejected rather than ignored, the format version is read
by a separate tolerant pass first so a future payload reports
`UnsupportedFormatVersion` instead of a parse error, and a repeated OR-Set or usage
key is rejected rather than resolved — the two entries carry different clocks, so
"last one wins" would make the decoded value depend on encoder order.

`encode_item` **validates before it writes**, so this crate never stores a payload it
would refuse to load. The fuzz target additionally asserts that anything which
decodes re-encodes, and that re-encoding is canonical.

## Deviations from `docs/SPEC.md`

Six, in descending order of how much they matter.

1. **§6.4 and §2.4 contradict each other about epoch rotation. This is a spec bug.**
   §2.4 and §6.4 both say rotation "re-wraps 48-byte item keys rather than
   re-encrypting payloads", and with the envelope as §2.4 specifies it that is not
   achievable: the payload's AEAD binds `aad = Header || item_id`, and `Header`
   contains `epoch` at offset 6. Changing `epoch` invalidates the payload's Poly1305
   tag as well as the wrapped key's, so the payload must be re-encrypted — or at
   minimum re-authenticated, which `misty-crypto` exposes no API for and should not.

   `Vault::rewrap_to_current_epoch` therefore decrypts and re-seals. The cost is
   real but small: payloads are one or two 256-byte buckets, so a 1 000-item vault is
   roughly **500 KB of writes rather than the 48 KB §6.4 claims**. The *lazy* and
   *interruptible* properties §6.4 asks for are preserved exactly — every envelope
   names its own epoch, mixed epochs open fine, and each item is its own transaction.

   Either §6.4 should state the real cost, or §2.4 should move `epoch` out of the
   payload's AAD — and it should not, because an epoch that is not authenticated is
   an epoch an attacker can relabel.

2. **§4's merge table is missing four fields, and one of them matters.**
   The table covers neither `otp.kind`, `otp.pin`, `last_used_at` nor `created_at`.
   The choices made here, and why:

   * `last_used_at` is **max-wins, not last-writer-wins**. If device A generates a
     code at 12:00 while offline and device B generates one at 11:00 but syncs
     first, last-writer-wins reports 11:00, which is simply false. This is the one
     of the four where LWW would be an outright bug, and §4 should say so.
   * `created_at` is **min-wins**. Two devices should never disagree, but if they
     do, the earlier claim is the one that can be true, and "earliest wins" is a
     join, so it converges.
   * `otp.kind` is **last-writer-wins**, alongside `algorithm`/`digits`/`period`. A
     wrong kind is a mis-detected import; it is visibly wrong, and correcting it
     loses nothing.
   * `otp.pin` is **last-writer-wins, but a `Conflict::DivergentPin` is still
     reported.** This is the one judgement call in the crate. The argument for
     treating it like the secret — forking the item — is that an mOTP or Yandex code
     cannot be generated without the PIN, so a wrong PIN is as fatal as a wrong
     secret. The argument against, which won, is that a PIN is *chosen and
     remembered by the user* while a secret is issued by the service and cannot be
     read back out of it: the losing PIN can simply be typed again, whereas forking
     on every PIN correction would produce a phantom duplicate every time somebody
     fixed a typo. Reporting the conflict without forking gets both: nothing is
     silently lost, and no phantom item appears. **§4 should list `otp.pin`
     explicitly, whichever way it decides.**

3. **§4 does not say how the second item of a divergent-secret split gets its id, and
   it needs a new domain-separation constant.** `misty/vault/fork-id/v1` is
   wire-visible — it decides an id a server stores — so by §6.6's own rule it belongs
   in the spec's constants table. The derivation and the reasoning for keying it on
   `VK` are above.

4. **§4 does not bound `Hlc.wall_ms`, and it has to be bounded.** Without a bound, a
   single write dated 2200 wins every comparison forever, and a device with an unset
   RTC writes edits at 1970 that lose every comparison. The window
   `[2020-01-01, 2100-01-01)` is enforced on decode and clamped on write. The bounds
   are absolute rather than relative to the reader's clock, because a merge whose
   outcome depended on when it ran would not converge.

5. **§5's `VaultStore` sketch has `put(&mut self, id, env, hlc)`; this takes a whole
   `StoredEnvelope`.** The schema in the same section has six columns, and a
   three-argument `put` cannot write `kind`, `seq` or `version`. A sync layer that
   could not persist the concurrency token it had just received would have to
   re-fetch after every crash.

6. **§6.1's change feed carries a `deleted` flag; `RemoteChange` does not have it.**
   A delete is a signed tombstone inside the encrypted payload. Honouring a bare flag
   from the transport would hand a hostile server the ability to erase a vault it
   cannot read, which is the one destructive power the whole design is built to deny
   it. The flag can stay in the protocol as a hint; it must not be load-bearing, and
   §6.1 should say so.

Smaller, non-contradictory additions: `trashed_at` (§4 requires a 30-day trash but
gives it no field), `Group` as its own object (§3 references `GroupId` without
defining what it points at), and `Vault::repair_secret` as the single documented way
a secret ever changes.

## Layout

```text
src/lib.rs           crate docs, lint policy, module wiring
src/error.rs         every typed error; no variant carries item content
src/limits.rs        every bound a decoder enforces, and why there are two of some
src/text.rs          what counts as acceptable text; the anti-spoofing rules
src/hlc.rs           the hybrid logical clock and the monotonic local clock
src/ids.rs           GroupId, BlobId — newtypes over the storage key
src/crdt/            Lww, OrSet, UsageCounter, MaxWins, MinWins, and the Merge trait
src/model/           Item, Group, IconRef, Tombstone
src/edit.rs          NewItem and Edit: one call, one clock
src/codec/           the CBOR wire format, frozen
src/conflict.rs      what a merge could not decide
src/merge.rs         ItemSet, the fork-id derivation, the immutable-secret rule
src/store/           the VaultStore trait, the memory backend, SQLite, migrations
src/vault/           the handle: open, read, write, merge, rotate
fuzz/                cargo-fuzz target (own workspace, nightly)
```

| Test file | What it covers |
|---|---|
| `convergence.rs` | the SPEC §4 gate: commutativity, associativity and idempotence asserted **separately**, plus every application order, under `proptest` |
| `merge_rules.rs` | one test per row of SPEC §4's table, through two real vaults exchanging real envelopes |
| `crash_injection.rs` | a failure at every write position of a multi-item merge, against both backends |
| `same_site_accounts.rs` | all five SPEC §3.1 rules |
| `envelope_roundtrip.rs` | the real envelope; tampering with the ciphertext, the `kind` column and the `hlc_max` column; an unrostered signer; mixed epochs |
| `hostile_inputs.rs` | malformed CBOR, every truncation and bit flip, absurd lengths, 10 000 tags, clocks in 1970 and 2200, a tombstone from the future |
| `wire_format.rs` | the frozen key set and the byte-string encodings |
| `migrations.rs` | the v1 fixture, a refused newer schema, the required pragmas, both backends agreeing |
| `vault_lifecycle.rs` | trash, restore, the sweeps, groups, sorting, search, redaction |

## What an auditor should look at first

In this order. The first three are where a mistake would be both catastrophic and
invisible.

1. **`src/merge.rs`, `ItemSet::absorb`.** The immutable-secret rule lives here, and
   it is the one place in the crate where getting it wrong destroys a credential
   rather than merely confusing a field. Check that the only two outcomes are "merge"
   and "keep both", that `Item::merge` refuses divergent secrets so no third path
   exists, that the forked id is derived from `(original_id, secret)` under `VK` and
   never drawn, and that the "which side keeps the id" rule reads only the two
   secrets. Then read `convergence::three_divergent_secrets_converge_from_every_direction`,
   which pins the associativity of that path explicitly.

2. **`src/model/item.rs`, `Item::is_deleted` and `max_field_hlc`.** SPEC §4's delete
   rule is a *derived* comparison, and the list of fields it compares against is
   hand-written. A field added to the struct and forgotten in `max_field_hlc` would
   silently stop protecting that field from a stale delete. Confirm the list matches
   the struct, and that `usage`, `otp.counter` and `last_used_at` are absent from it
   on purpose.

3. **`src/vault/sync.rs`, `merge_remote`.** Four phases, and the order is the crash
   guarantee: verify and decode everything, merge into a copy, seal and write in one
   transaction, adopt only after the commit. Check that nothing between phase 1 and
   phase 4 touches `self.items` or `self.groups`, and that sealing happens before
   `begin`. `tests/crash_injection.rs` asserts the consequence at every write
   position; this is the code it is asserting about.

4. **`src/hlc.rs`, `HlcClock::tick` and the window constants.** The monotonicity
   guarantee under a backwards clock, and the reason the `wall_ms` bounds are
   absolute rather than relative to the reader.

5. **`src/codec/`, `decode_item`.** The hostile-input boundary. Everything past it
   assumes the model's invariants hold, so this is where they are established: the
   length cap before parsing, the version probe before the strict parse, the
   duplicate-key rejection, and `Item::validate`. Note that `encode_item` validates
   too, which is what makes "the crate never writes what it cannot read" true rather
   than hoped for.

6. **`src/store/mod.rs`, the schema comment, and `src/store/schema.rs`.** Confirm
   there is still no plaintext column and no index beyond the primary key, and that
   the pragmas SPEC §5 requires are applied on every open rather than once at
   creation.

7. **`src/vault/mod.rs`, `Vault::load` and `check_identity`.** The cross-checks on
   the two plaintext columns a hostile server can rewrite. If `kind` were trusted, an
   item could be hidden by relabelling it; if `hlc_max` were trusted, a sync could be
   reordered.

8. **`src/text.rs`.** The one place that decides what a label may contain. The
   rejections are all anti-spoofing (`A11`); the *acceptances* matter just as much,
   because refusing `日本銀行` would be a correctness bug wearing a hardening
   costume.

Deliberate strictness that might look like over-reach: unknown CBOR keys are
rejected rather than ignored, repeated OR-Set keys are rejected rather than
resolved, unknown enum wire bytes are rejected rather than defaulted, an
identical-clock-different-value collision is reported rather than resolved, and a
database from a newer build is refused rather than opened. Each turns a silent
misinterpretation into a typed error.

## Running the gates

```sh
cargo fmt -p misty-vault --check
cargo clippy -p misty-vault --all-targets --all-features -- -D warnings
cargo test -p misty-vault --all-features
cargo doc -p misty-vault --no-deps
cargo build -p misty-vault --target wasm32-unknown-unknown
```

The wasm build is the gate that keeps SQLite out of the web core. `rusqlite` is a
target-conditional dependency, not an off-by-default feature, so a native build gets
it automatically and a wasm build never sees it.

The fuzz target needs nightly and lives in its own workspace:

```sh
cd crates/misty-vault/fuzz
cargo +nightly fuzz run item_decode
```

`tests/hostile_inputs.rs` covers the same entry point on stable, so CI has coverage
of it on every commit without a fuzzing run.
