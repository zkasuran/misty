<!--
SPDX-FileCopyrightText: 2026 The Misty Authors

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# `misty-sync` — the offline-first sync client

Implements the client half of [`docs/SPEC.md`](../../docs/SPEC.md) §6: the
endpoints (§6.1), the device roster on the wire (§6.2), device-to-device
enrollment (§6.3), revocation and epoch rotation (§6.4), and time drift (§6.5).

The server is a versioned blob store that knows nothing. This crate is the half
that knows everything and trusts none of it.

* `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`,
  `#![warn(missing_debug_implementations)]`
* Builds for `wasm32-unknown-unknown`. The web app and the browser extension sync
  too, and that constraint drove the transport design rather than being retrofitted
  to it
* No `unwrap`/`expect`/`panic!`/slice indexing outside tests — enforced by clippy
  lints in `src/lib.rs`, not by convention
* **Emits no log records at all.** No `tracing` dependency, no `log` call. What
  happened comes back as a `SyncReport`; what went wrong comes back as a
  `SyncError`, and `tests/redaction.rs` asserts that no variant of it names a
  secret, an envelope byte or an `item_id` in `Display` *or* `Debug`
* A consumer of `misty-crypto` and `misty-vault`, not a re-implementer. Merge is
  `misty-vault`'s and is property-tested there; cryptography is `misty-crypto`'s,
  with [one exception](#the-one-primitive-this-crate-touches) that should not exist

## Threat-model obligations

| ID | What this crate is responsible for |
|---|---|
| `A1` | A hostile server cannot get an unverified envelope merged, cannot delete an item, cannot rewind or reorder the change feed, cannot make the client overwrite a write it could not attribute, and cannot make it allocate or loop without bound. |
| `A2` | TLS 1.3 with certificate pinning on native builds. **Absent on wasm**, where the platform owns TLS — see [the gap](#certificate-pinning-and-the-wasm-gap). |
| `A6` | Every envelope's signer is looked up in the client-signed roster *before* anything is decrypted, and a roster is adopted only when it is signed by a device the current roster already vouches for. |

## The state machine

```text
                ┌──────────────────── sync_once ────────────────────┐
                │                                                   │
  Idle ──▶ Delete ──▶ Pull ──▶ verify ──▶ merge ──▶ record ──▶ Push ──▶ 409? ──▶ Idle
                │     │  ▲       │                    │         │        │
     purged rows,     │  └─ has_more                  │         │        └─ merge,
     If-Match'd       │                               │         │           retry,
                      └── page too large: halve       │         │           bounded
                          the page, do not            │         └─ 200: record,
                          count it as a page          │            next item
                                                      └─ one durable save per page
```

Four invariants hold at every arrow, and the tests are named after them.

**A write is never lost.** The outbound queue is *derived*, not remembered — see
below.

**A write is never applied twice.** Every push carries `If-Match`, so a resend
after an interruption either lands once (`200`) or is told what it missed (`409`),
and a `409` is resolved by a merge, which is idempotent.

**Progress is committed before it is claimed.** A page is merged into the vault —
one vault transaction — and only then is the cursor saved. Crash in between and the
page is re-fetched and re-merged, which changes nothing. The opposite order would
silently skip a page.

**Nothing unverified is merged.** A change whose signer is absent from the roster,
or whose signature does not verify, is dropped from the batch and counted rather
than aborting the page. One bad row cannot stall a sync, and it cannot get merged
either.

The delete pass runs *before* the pull, and that is the one place the order is not
"pull, then push". A row this device purged after SPEC §4's ninety days is still in
the change feed until it is gone from the server, so pulling first would hand the
device its own tombstone back and re-create the row it had just collected — forever,
on every sync. Deleting first is safe because the delete carries `If-Match`: if any
device has written that item since, the server answers `409`, nothing is destroyed,
and the pull that follows brings the newer value in. *Tested:*
`engine::a_purged_tombstone_is_deleted_server_side`.

### The outbound queue is derived, not remembered

The obvious design is a list of "writes I still owe the server", appended to on
every local edit. It has a failure mode that is silent and permanent: if the
process dies between the vault's commit and the queue's append, that write is never
sent, and nothing afterwards notices. The app also has to remember to enqueue, on
every path, forever.

So the queue here is computed on demand from two durable facts:

* the envelope `misty-vault` currently stores for an item, committed in the vault's
  own transaction;
* a 32-byte fingerprint of the envelope the **server** last confirmed, recorded in
  this crate's state.

An item is pending exactly when those disagree. The vault's commit *is* the
enqueue, so there is no window in which a write exists locally and is not queued;
there is nothing for an app to forget to call; and epoch rotation needs no
bookkeeping at all, because a re-sealed object differs from what the server
confirmed and therefore becomes pending by construction.

*Tested:* `interruption::the_derived_queue_is_empty_exactly_when_the_server_is_current`,
and every sweep in `tests/interruption.rs`.

## Every hostile-server property, and the test that proves it

`tests/hostile_server.rs`. Every fault is something an attacker who holds the
database, or who sits on the wire, can do **without any key**.

| What the server does | What the client does | Test |
|---|---|---|
| serves an envelope signed by a device absent from the roster | rejects it before decrypting, merges nothing, and keeps syncing | `an_envelope_from_an_unrostered_device_is_rejected` |
| flips one ciphertext byte | rejects it on the Ed25519 check, before any decryption | `a_tampered_envelope_is_rejected` |
| rewinds `seq` below the client's cursor | refuses the page and leaves the cursor where it was | `a_rolled_back_seq_is_refused` |
| serves a page in descending `seq` order | refuses the page | `a_descending_page_is_refused` |
| answers with an absurd `next_seq` | refuses the page; the cursor never takes the value | `an_absurd_next_seq_is_refused` |
| claims `has_more` forever while advancing | stops after a bounded number of pages | `an_endless_feed_is_bounded` |
| claims `has_more` forever while standing still | stops cleanly — an off-by-one is not an attack | `an_overclaimed_has_more_that_stands_still_ends_cleanly` |
| replays a signed `/v1/time` response | refuses it: the nonce does not answer this request | `a_replayed_time_response_is_refused` |
| signs `/v1/time` with a key the client has not pinned | refuses it, and stores nothing | `a_time_response_from_the_wrong_key_is_refused` |
| walks server time backwards | refuses it | `server_time_may_not_go_backwards` |
| sets `deleted: true` on every change, with no signed tombstone | ignores the flag entirely, including on a full re-read | `a_server_set_deleted_flag_deletes_nothing` |
| serves a roster signed by a device we do not trust | refuses to adopt it and does not offer it | `a_roster_signed_by_an_unknown_device_is_refused` |
| rewrites a roster's bytes | refuses to open it | `a_rewritten_roster_does_not_open` |
| serves the roster at another item's address | refuses it | `a_roster_at_the_wrong_address_is_refused` |
| answers `409` forever with a fresh `version` each time | stops after a bounded number of attempts | `a_conflict_loop_that_never_converges_is_bounded` |
| answers `409` forever with the same state | stops after **one** attempt: nothing more can be learned | `a_conflict_that_makes_no_progress_stops_at_once` |
| answers `409` with an envelope we cannot attribute | stops rather than overwriting it | `a_conflict_we_cannot_attribute_is_not_overwritten` |
| puts CR-LF in a `version` token, aiming at the next `If-Match` | refuses the token where it arrives | `a_version_token_with_crlf_is_refused` |
| answers `401` to a session it just issued, forever | re-challenges exactly once, then stops | `an_unauthenticated_client_is_told_so_rather_than_looping` |
| returns a ten-megabyte error body | reads no part of it into the error | `hostile_input::a_ten_megabyte_error_body_is_not_read_into_the_error` |
| returns HTML where JSON was promised | errors, and the cursor does not move | `hostile_input::a_garbage_feed_body_reaches_the_engine_as_an_error` |

Two of these deserve a note.

**The `deleted` flag.** SPEC §6.1 says it is advisory and MUST NOT be acted on. It
*is* decoded — `FeedChange::deleted` exists — so that the type is honest about what
the wire carries and so a test can set it and prove nothing happens. Nothing reads
it. Real deletion is a signed tombstone inside the encrypted payload (§4).

**Refusing to overwrite an unattributable `409`.** A conflict is a claim that
someone else wrote first. If the client cannot attribute that write to a rostered
device it stops, because overwriting is the one way a hostile server gets a client
to destroy data on its behalf. The honest case that looks the same — a device
enrolled since the last roster fetch — is fixed by fetching the roster, which is
what the error tells the caller to do.

## Certificate pinning, and the wasm gap

**Natively:** `hyper` over `rustls`, TLS 1.3 only, with a custom
`ServerCertVerifier` that requires the leaf certificate's SHA-256 to be in a
`PinSet`. Three properties are structural rather than configured:

* **TLS 1.2 does not exist.** `rustls` and `hyper-rustls` are built without their
  `tls12` features, so SPEC §9's "TLS 1.3 only" is a fact about the build.
* **There is no root certificate store.** No `webpki-roots`, no platform verifier.
  The only trust anchor is the pin set, so there is no certificate authority in the
  trust path and therefore none to mis-issue. A deployment that wants chain
  validation as well supplies its own roots through `PinnedVerifier::with_roots`,
  and both checks run.
* **`native-tls` and `openssl` are unreachable.** `cargo deny` bans them for the
  whole workspace and the `ring` provider satisfies it.

The pin is over the **leaf certificate as DER**, not the SPKI. SPKI pinning
survives re-issuance with the same key, which is the operational win, but it needs
an X.509 parser to find `subjectPublicKeyInfo`. Leaf pinning needs one SHA-256 over
bytes rustls already handed us and adds no parser to a client whose whole job is to
distrust the network. The operational cost is paid by publishing the next
certificate's pin alongside the current one before rotating — which is the same
discipline SPKI pinning needs for a key rotation anyway. That is why a `PinSet`
holds several pins.

What pinning does not do: with no roots supplied, nothing checks `notAfter`. An
expired certificate whose pin still matches is accepted. The pin names one
certificate, so that means trusting the operator's own retired key, and the fix is
to remove the pin — the same action expiry would force.

**On wasm there is no pinning, and there cannot be.** `fetch` gives a page no
access to the TLS session, the peer certificate, or the verification decision. The
browser validates against its own trust store and reports success or an opaque
network error. There is no Web API that would let a page inspect, override or add
to that. So threat model `A2`'s certificate pinning is **absent** on
`wasm32-unknown-unknown`, and this crate says so rather than implementing something
adjacent and calling it done.

What holds the line instead, and why the gap is survivable:

* Payloads are end-to-end encrypted and Ed25519-signed by a rostered device
  (SPEC §2.4). An attacker who defeats TLS with a certificate the browser accepts
  sees opaque envelopes, cannot forge one, and cannot get one merged — every check
  in the table above is enforced *above* the transport and holds identically on
  wasm.
* `/v1/time` is verified against a key pinned in the client bundle (SPEC §6.5), so
  the one thing a TLS attacker could otherwise do — walk the effective clock — is
  still refused.

**Residual risk, stated plainly:** on wasm, a successful TLS attacker learns what
SPEC §1 `A1` already grants the server — envelope sizes in 256-byte buckets, item
ids, and write timing. That is a real widening of `A1`'s accepted leak from "the
server" to "the server, or anyone who obtains a certificate the browser trusts for
this origin". It is not a widening of what can be *read* or *forged*.

## The wire format is SPEC §6.1.1's, not this crate's

An earlier draft of this file carried a normative encoding table. It should not
have: §6.1 left the encoding unspecified, this crate and `misty-server` each fixed
it independently and reasonably, and the two did not interoperate. **SPEC §6.1.1 is
now normative and this crate implements it.** The table below is a copy for
convenience; where it and §6.1.1 disagree, §6.1.1 wins.

| Field kind | Encoding |
|---|---|
| `vault_id`, `device_id`, `item_id`, `enroll_id`, nonces | lowercase hex |
| signatures, public keys | lowercase hex |
| envelopes, sealed blobs | standard base64 with padding (**not** base64url) |
| `version` | opaque printable-ASCII token; never parsed, and rejected if it contains CR, LF or a quote |
| `seq`, `unix_ms`, counts | JSON numbers, integer-valued |

```text
POST /v1/auth/challenge  {vault_id, device_id}             -> {nonce, expires_at}
POST /v1/auth/verify     {vault_id, device_id, nonce, sig, ed25519_pub?}
                                                           -> {access_token, refresh_token, expires_in}
POST /v1/auth/refresh    {refresh_token}                   -> {access_token, refresh_token}
POST /v1/vaults/{vid}/devices  {device_id, ed25519_pub}     -> 201 | 409
GET  /v1/vaults/{vid}/changes?since={seq}&limit={n}
                         -> {changes: [{item_id, seq, version, envelope, deleted}], next_seq, has_more}
PUT  /v1/vaults/{vid}/items/{item_id}   If-Match: "{version}" | If-None-Match: *
                         {envelope} -> 200 {seq, version} | 409 {version, envelope} | 428 | 507
DELETE /v1/vaults/{vid}/items/{item_id} If-Match: "{version}"
GET  /v1/time?nonce={nonce}                                -> {unix_ms, nonce, sig}
POST /v1/enroll/begin    {enroll_id, x25519_pub, enroll_request}   create-only
GET  /v1/enroll/poll/{enroll_id}?want=request|response      single-use per blob
POST /v1/enroll/complete {enroll_id, sealed_response}       create-only
GET  /v1/quota           -> {bytes_used, item_count, row_count, limits}
```

The two signed messages are byte-exact, and
`interop_server::the_signed_payloads_are_byte_identical_on_both_sides` compares
them against `misty-server`'s own builders rather than against a transcription:

```text
auth:  "misty/server/auth/v1" ‖ vault_id[16] ‖ device_id[16] ‖ LE32(nonce.len()) ‖ nonce
time:  "misty/time/v1"        ‖ LE32(nonce.len()) ‖ nonce ‖ LE64(unix_ms)
```

**Unknown response fields are ignored**, per §6.1.1, and that is deliberately
unlike `misty-vault`: at rest an unexpected field means corruption, on the wire it
means a newer peer. Everything acted on is still bounded before it is decoded.

### Where `misty-server` and §6.1.1 still disagree

Four places, all found by the interop test, all with the client tolerant on decode
and peer-compatible on encode. `src/encoding.rs` is the single place this lives and
`interop_server::the_servers_wire_form_still_differs_from_spec_6_1_1` asserts each
one **against the running server**, so the moment the server is brought in line that
test fails and points at the tolerance to delete.

| Field | §6.1.1 | `misty-server` | What this client does |
|---|---|---|---|
| `/v1/auth/challenge` → `nonce` | hex | standard base64 (`routes/auth.rs:125`) | base64 only — see below |
| `/v1/auth/verify` ← `nonce`, `sig`, `ed25519_pub` | hex | standard base64 (`routes/auth.rs:184`) | accepts either, sends base64 |
| `/v1/time` → `nonce`, `sig` | hex | base64url and base64 (`routes/meta.rs:71`) | accepts either, sends base64url |
| `version` | opaque token | JSON number (`routes/items.rs:55`) | accepts either, echoes it back verbatim |
| `POST /v1/enroll/begin` field | `enroll_request` | `sealed_request` (`routes/enroll.rs:59`) | sends §6.1's name, retries once with the legacy one |

The challenge nonce is the one field where tolerance is **impossible**, and the
reason is `misty-server`'s own argument for picking one alphabet, which is correct:
*a variable-width binary field cannot be encoding-agnostic.* Hex of `N` bytes is
`2N` characters and every hex character is also a base64 character, so hex of any
even `N` — including the 32 bytes both sides use — is also well-formed base64 of
`3N/2` bytes. Trying hex first fails the other way: standard base64 of 129 zero
bytes is 172 `A`s, and `A` is a hex digit, so it reads as 86 bytes of `0xAA`. Both
readings are well-formed and nothing in the string says which was meant. So this
client follows the peer and asks for arbitration; `encoding::challenge_nonce_from_wire`
carries the argument and a test that demonstrates both collisions.

The fixed-width fields are unaffected: `encoding::fixed_from_wire` keys on a known
decoded length, and for the widths this protocol uses — 16, 32, 64 — hex, padded
base64 and unpadded base64url are three different string lengths, so there is
exactly one reading. `encoding::tests::the_widths_this_protocol_uses_never_collide`
proves it rather than asserting it.

**Recommendation for arbitration:** make the server hex, not the spec base64. Hex is
unambiguous in a JSON body *and* in a query string, where standard base64's `+`
arrives as a space — which is why the server had to reach for base64url in the first
place. One encoding for every fixed-width and variable-width binary field removes
this whole section.

## Interoperation with the real server

`tests/interop_server.rs`. SPEC §6.1.1 requires it: "An implementation of either
side MUST have a test proving interoperation with the other, running the real code
on both sides. Two independently green test suites against two different mocks prove
nothing about whether the halves fit together."

`misty-server` is a **target-conditional dev-dependency** and the file is gated
`#![cfg(not(target_arch = "wasm32"))]`, so the published crate and the wasm build
never see it. It boots the real `axum` router on an ephemeral port against a real
SQLite file in a temporary directory, and drives the real engine against it.

| What it proves | Test |
|---|---|
| both signed messages are byte-identical to the server's own builders | `the_signed_payloads_are_byte_identical_on_both_sides` |
| the challenge-response is accepted by the server's real `verify_strict` | `a_client_authenticates_against_the_real_ed25519_verifier` |
| `/v1/auth/refresh` rotates, and reuse is fatal to the family | `a_refresh_token_rotates_the_session_and_reuse_is_fatal` |
| `/v1/time` verifies under **both** verifiers over the same bytes | `time_is_verified_end_to_end_by_both_verifiers` |
| items push and pull, with real `seq` and real `version` tokens | `items_push_and_pull_through_the_real_server` |
| a genuine server-side precondition failure is merged and the retry lands | `a_real_409_is_merged_and_the_retry_lands` |
| two devices reach byte-identical models, fork included | `two_clients_converge_to_byte_identical_state_through_the_real_server` |
| the enrollment relay works end to end, single-use both ways | `the_enrollment_relay_works_end_to_end_through_the_real_server` |
| a bogus bearer token is refused before the precondition is read | `a_write_with_no_precondition_is_refused_by_the_real_server` |
| the four remaining encoding divergences, asserted live | `the_servers_wire_form_still_differs_from_spec_6_1_1` |

**Only TLS is stubbed**, and only because the server does not speak it: its
`README.md` says "This process does not speak TLS … Run it behind nginx, Caddy, or
Traefik". `NativeTransport` refuses a non-`https` origin rather than downgrading,
which is right for the shipped client, so the test carries fifty lines of plaintext
`hyper` instead of weakening that invariant.

## Deviations from `docs/SPEC.md`

Five findings from the first pass have been **corrected in the spec** and this
section now records what the client does about each, not an argument for it.

### 1. `/v1/time` was replayable as originally specified — now §6.1.1

A signature over a timestamp alone is a static bearer token for that instant:
record one response, serve it back, and every client that reaches you is pinned to a
fixed past moment — exactly what §6.5 says the signature prevents. §6.1.1 now
requires a caller nonce inside the signed message. This client sends 32 fresh bytes
and checks the echo, and `DriftTracker` additionally refuses a reading more than a
second below the previous one, so a server that cooperates with the nonce protocol
and then lies still cannot walk the clock backwards.

*Tested:* `hostile_server::a_replayed_time_response_is_refused`,
`server_time_may_not_go_backwards`, `interop_server::time_is_verified_end_to_end_by_both_verifiers`.

### 2. The auth signature was unspecified, and the obvious reading is a signing oracle

Signing a bare nonce hands the server a signing oracle for the device identity key
— the same key that signs every envelope and every roster, over messages with no
domain prefix. §6.1.1 now fixes the message byte-exactly, with `/server/` in the
context to separate this from the key's other two jobs and an LE32 length prefix so a
future appended field cannot make two messages encode identically.

*Tested:* `client::tests::the_auth_message_binds_the_context_the_vault_and_the_device`,
`interop_server::the_signed_payloads_are_byte_identical_on_both_sides`.

### 3. §6.4's epoch bump is not a read revocation

`EK_n = HKDF(VK, …)`, so a revoked device that kept `VK` derives every future epoch
key. §6.4 now says so and requires a `VK` rotation after every revocation.
`misty-vault` exposes no `VK` rotation, so `SyncEngine::revoke_device` does what it
can — bump, re-seal, re-sign — and its documentation states plainly that the heavier
operation is not optional.

*Tested:* `rotation::revocation_is_not_a_read_revocation`, which has the revoked
device read an envelope re-sealed under the new epoch.

### 4. Lazy rotation and the roster check interact

`Vault::open` verifies every stored row's signer, so dropping a revoked device's key
outright makes the vault refuse to open until rotation finishes. §6.4 now keeps
retired keys in the roster for verification only — active and retired lists — which
is the better fix than this crate's original advice of "finish rotating before you
adopt the successor". Until `misty-crypto`'s `Roster` grows the second list, the
client still needs that ordering, and `SyncEngine::revoke_device` documents it.

*Tested:* `rotation::a_vault_will_not_reopen_under_the_successor_until_rotation_finishes`,
which pins both halves — it fails before rotation and passes after.

### 5. `sealed_request` could not be sealed

The sealing key is derived from the *approver's* ephemeral X25519 key, which does not
exist at step 1, and the payload is a QR code on the new device's screen. §6.3 now
says "authenticated, not confidential — and it cannot be otherwise" and the field is
`enroll_request`. What protects it is the 6-digit code, which the approver
recomputes over what the *server* delivered.

*Tested:* `enrollment::a_substituted_request_cannot_be_approved_by_a_user_who_compared_the_code`,
which covers both defences: `begin` is create-only, and if the impostor publishes
first the code no longer matches.

### Still open, and small

* **A reclaimed row is not in SPEC §6.1's change feed.** A `DELETE` keeps the row so
  `version` stays monotonic, so the feed can carry `envelope: null`. §6.1's feed
  shape does not admit that. This client decodes it, records the `version` without a
  fingerprint — which keeps the item pending, so its own copy is offered back — and
  never treats it as a delete. `FeedChange::envelope` is therefore `Option`.
* **`GET /v1/quota`'s `limits` field names come from the server**, since §6.1 writes
  `limits` without naming its contents. `row_count` is the number to compare against
  `max_items_per_vault`, because reclaimed rows still count.
* **Domain constants added to §6.6 in the first pass:** `misty/roster-id/v1` for the
  roster's derived address (§6.2 gives the roster no address, and it cannot be
  random: a device joining from a grant has no way to learn one), and
  `misty-enroll:v1:` for the QR prefix by symmetry with §2.6's recovery prefix.

### One finding about `misty-vault` rather than the spec

`StoredEnvelope.version` is documented as the token "the sync layer owns … stored
verbatim so a crash cannot lose it", but after a merge that produces a value neither
side had, `Vault::merge_remote` carries the **pre-merge** token onto the new row —
which is the token the server no longer has. Using it as the next `If-Match` would
produce a guaranteed `409` after every real merge. This crate therefore keeps the
authoritative token in its own state (`KnownRow::version`) and does not read the
vault's column. Not a correctness problem here; the column does not achieve what its
documentation claims.

### The one primitive this crate touches

SPEC §6.5 requires verifying a detached Ed25519 signature over a **server-chosen
message** against a **pinned key**, and `misty-crypto` exposes no detached
verification: its two verifying entry points, `Envelope::verify_with_signer` and
`Roster::verify`, each verify a signature over bytes *they* construct. So
`src/signature.rs` calls `ed25519-dalek` directly — one function, `verify_strict`
only, never signing, and no `ed25519_dalek` type in this crate's public API.

**This should not exist.** The fix is a
`misty_crypto::identity::verify_detached(public_key, message, signature)`, after
which that file is deleted and `ed25519-dalek` leaves this crate's manifest. It is a
missing API in the crypto core, not a disagreement with the spec.

## What an auditor should look at first

In this order. The first three are where a mistake would be both catastrophic and
invisible.

1. **`src/engine.rs`, `verify_change` and `verify_conflict`.** Everything in `A1`
   and `A6` rests on nothing reaching `Vault::merge_remote` that has not had its
   signer looked up in the roster. Confirm that both functions go through
   `Envelope::verify` — the only door to decryption in `misty-crypto`, and one
   guarded by a private witness type — that `apply_page` builds its batch *only*
   from what they returned, and that `verify_conflict` refuses rather than
   overwriting. Then read `a_conflict_we_cannot_attribute_is_not_overwritten`.

2. **`src/engine.rs`, `pull`.** Three things in one function, and each is a distinct
   attack: the `seq` comparisons against the stored cursor (the decoder has already
   proved the page ascends internally; this is the half that needs the cursor), the
   ordering of `merge_remote` → `known` → `save` (a crash between any two of them
   must be safe, and only this order is), and the halt on a roster change (a change
   of trust anchor must be adopted before anything after it is judged, or the cursor
   advances past writes the new roster would have accepted). Confirm
   `change.deleted` is read nowhere.

3. **`src/wire.rs`, `decode_change_feed`.** The crate's hostile-input boundary, and
   the only decoder that runs on bytes nothing has authenticated. Every bound is
   load-bearing: the body cap before the parse, the entry count, the exact id length,
   the `seq` range, the strict ascent, the envelope cap checked on the *encoded*
   length before decoding, and `ServerVersion::parse`'s refusal of anything that is
   not a legal header value. `fuzz/fuzz_targets/change_feed.rs` re-asserts the
   post-conditions; `tests/hostile_input.rs` is the stable-toolchain half.

4. **`src/state.rs`, and the derivation in `SyncEngine::pending`.** The claim that no
   write can be lost rests entirely on the queue being derived from the vault rather
   than remembered. Check that `pending` reads the vault's rows as its source of
   truth, that `known` is only ever written for changes that were *accepted* (a
   rejected envelope must leave the previous fingerprint in place, so the item stays
   pending and the local copy is offered back), and that `StateStore::save` takes the
   whole state so there is no half-saved intermediate.

5. **`src/encoding.rs`.** The only place SPEC §6.1.1 and `misty-server` disagree
   about bytes, and the only place in this crate where two readings of one field are
   accepted. Confirm that tolerance is confined to fields of **fixed** decoded width,
   where the length selects the alphabet with no guessing; that the one
   variable-width field picks a single encoding and says why; and that
   `tests/interop_server.rs` asserts each divergence against the live server so the
   tolerance cannot outlive the reason for it.

6. **`src/transport/pin.rs`, `PinnedVerifier::verify_server_cert`.** The pin is
   checked first and unconditionally; the chain check is additional, never
   alternative. Confirm there is no code path that returns
   `ServerCertVerified::assertion()` without `PinSet::accepts` having returned true,
   that `accepts` is constant-time across the whole set, and that
   `verify_tls12_signature` refuses rather than delegating.

7. **`src/client.rs`, `auth_signing_bytes`, and `src/time.rs`,
   `time_signing_bytes`.** SPEC §6.1.1 makes both byte-exact. Check the domain
   separators are distinct from every other one in the project —
   `client::tests::the_context_is_not_shared_with_any_other_construction` asserts it —
   that the LE32 length prefixes are there, and that
   `interop_server::the_signed_payloads_are_byte_identical_on_both_sides` compares
   them to the server's own builders rather than to a transcription.

8. **`src/engine.rs`, `push_one` and `resolve_conflict`.** Three shapes of `409`
   arrive and only one involves a merge; the other two — a row whose bytes were
   reclaimed, and a row that does not exist — must retry rather than refuse. The bound on the retry
   loop, and the two different ways it can be reached: a rotating `version` exhausts
   the budget, an unchanged one stops after a single attempt. Confirm the loop head
   re-reads the vault row each time, because a merge may have changed it.

9. **`src/enroll.rs` and `SyncEngine::approve_enrollment`.** The ordering: seal (which
   is where the code is checked and which sends nothing), then push the roster, then
   deliver the grant. An earlier draft of this crate pushed the roster first and
   `enrollment::a_substituted_request_cannot_be_approved_by_a_user_who_compared_the_code`
   caught it publishing a roster naming the impostor.

Deliberate strictness that might look like over-reach: a `version` token that is not
a valid header value is refused rather than escaped, a bearer token with a control
character is refused, a page whose `seq` values repeat is refused rather than
deduplicated, a `409` without an envelope is refused rather than treated as a
permission to overwrite, and a state file from a newer build is refused rather than
opened. Each turns a silent misinterpretation into a typed error.

## Layout

```text
src/lib.rs             crate docs, lint policy, module wiring
src/error.rs           every typed error; no variant names a secret or an item id
src/limits.rs          every bound enforced on something a server chose
src/wire.rs            SPEC §6.1.1's encoding and the strict decoders
src/encoding.rs        the only place §6.1.1 and misty-server disagree about bytes
src/transport/mod.rs   the Transport trait, and why its future is not Send
src/transport/native.rs  hyper + rustls, TLS 1.3 only, bounded bodies, timeouts
src/transport/pin.rs     certificate pinning (native)
src/transport/fetch.rs   the browser's fetch, and the pinning gap (wasm)
src/transport/mock.rs    an in-process SPEC §6.1 server, plus the Faults switches
src/client.rs          SPEC §6.1's endpoints, one method each
src/engine.rs          the state machine
src/state.rs           what survives a restart; the derived queue
src/roster.rs          SPEC §6.2 on the wire, and what it takes to replace one
src/enroll.rs          SPEC §6.3, both sides
src/time.rs            SPEC §6.5, and the nonce that makes the signature mean something
src/backoff.rs         the retry schedule as a pure function, and the Sleeper trait
src/signature.rs       the one primitive call, and why it should not be here
src/runtime.rs         a thirty-line executor so tests need no async runtime
fuzz/                  cargo-fuzz targets (own workspace, nightly)
```

| Test file | What it covers | Tests |
|---|---|---|
| `convergence.rs` | two clients through a mock server: independent edits, an offline period, an interrupted batch, a `409` on one item, a divergent-secret fork, a HOTP counter. Byte-identical final state asserted on both | 7 |
| `hostile_server.rs` | the table above, one test per property | 21 |
| `interruption.rs` | a transport failure at every request index, a state-save failure at every save index, the stale-token resend, and the derived queue's exact predicate | 5 |
| `hostile_input.rs` | malformed JSON, non-UTF-8, absurd `next_seq`, oversized envelopes, oversized pages, a 10 MB error body, unusable version tokens, plus two `proptest` sweeps | 14 |
| `enrollment.rs` | SPEC §6.3 end to end both ways, the QR round trip, a substituted request, a cross-enrollment grant | 5 |
| `rotation.rs` | SPEC §6.4: revocation, laziness, resumability across a restart, and the two findings above | 5 |
| `engine.rs` | the retry loop's schedule, a non-transient failure not being retried, the server-side delete after a purge, and the guard that keeps it away from the roster | 5 |
| `interop_server.rs` | SPEC §6.1.1's gate: the real `misty-server` on a real socket over a real SQLite file. Native only | 10 |
| `redaction.rs` | every error variant's `Display` and `Debug`, a real wrapped `VaultError`, and a secret through seven live faults | 5 |
| unit tests in `src/` | the backoff schedule (including a `proptest` band property), the state format, the wire decoders, the encoding tolerance, the pin set, the time signature, the auth message | 46 |

`cargo test -p misty-sync --all-features` runs 124 tests including the doctest.

## Running the gates

```sh
cargo fmt -p misty-sync --check
cargo clippy -p misty-sync --all-targets --all-features -- -D warnings
cargo test -p misty-sync --all-features
cargo doc -p misty-sync --no-deps
cargo build -p misty-sync --target wasm32-unknown-unknown
cargo deny check
```

The wasm build is the gate that keeps `hyper`, `tokio` and `rustls` out of the web
core: they are target-conditional dependencies, not off-by-default features, so a
native build gets them automatically and a wasm build never sees them.

`cargo test` builds `misty-server` too: it is a target-conditional dev-dependency
for `tests/interop_server.rs`, which is SPEC §6.1.1's interoperation gate. The wasm
build never sees it.

The fuzz targets need nightly and live in their own workspace:

```sh
cd crates/misty-sync/fuzz
cargo +nightly fuzz run change_feed
cargo +nightly fuzz run enroll_qr
```

`tests/hostile_input.rs` covers the same entry points on stable, so CI has coverage
of them on every commit without a fuzzing run.



