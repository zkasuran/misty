// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every bound this crate enforces on something a server chose.
//!
//! A sync server is untrusted (SPEC §1, `A1`): every byte it sends is
//! attacker-controlled, including the lengths. Each constant here exists so a
//! hostile response is rejected by a comparison before it can become an
//! allocation, a loop, or a parse.
//!
//! The pattern to notice is that the caps come in pairs — a *request* bound this
//! client will ask for and a *response* bound it will accept — and the response
//! bound is always the larger of the two. A server is allowed to be generous
//! within reason; it is not allowed to be unbounded.

/// Largest envelope this client will accept from a server, in bytes.
///
/// `misty-vault` decodes item payloads up to
/// [`MAX_ITEM_PAYLOAD_LEN`](misty_vault::limits::MAX_ITEM_PAYLOAD_LEN) (512 KiB).
/// An envelope adds a 74-byte header, a 48-byte wrapped key, up to 255 bytes of
/// padding, a 4-byte length prefix, a 16-byte tag and a 64-byte signature, so
/// the true worst case is a little over 512 KiB. This rounds that up rather than
/// computing it, because a bound that tracks another crate's constant to the
/// byte breaks on an unrelated change there.
pub const MAX_ENVELOPE_LEN: usize = 528 * 1024;

/// Largest response body a transport will read, in bytes.
///
/// Sized for a full page of realistically sized items — an item is normally
/// 458 or 714 bytes on the wire — with two orders of magnitude of headroom. A
/// vault holding items near [`MAX_ENVELOPE_LEN`] can still sync: the change-feed
/// reader halves its page size and retries when a page does not fit, down to a
/// single change, so this cap cannot wedge a sync.
pub const MAX_RESPONSE_BODY_LEN: usize = 8 * 1024 * 1024;

/// Changes this client asks for per page by default.
pub const DEFAULT_PAGE_LIMIT: u32 = 64;

/// Most changes this client will accept in one page, however many it asked for.
pub const MAX_CHANGES_PER_PAGE: usize = 512;

/// Most pages one pull will walk before giving up.
///
/// `has_more` is the server's claim, so a hostile server can offer an endless
/// feed. At the default page size this is over two million changes, which is two
/// orders of magnitude past a full vault.
pub const MAX_PAGES_PER_SYNC: usize = 4096;

/// Most times one push will re-fetch, merge and retry after a `409`.
///
/// SPEC §6.1's conflict resolution converges in one round against an honest
/// server, and in a few against a busy one. A server that answers `409` forever
/// is either broken or hostile, and either way the client must stop rather than
/// spin.
pub const MAX_CONFLICT_RETRIES: usize = 8;

/// Largest plausible `seq`, exclusive.
///
/// `seq` is a per-vault counter, so a value anywhere near this is a server
/// error or an attempt to make the client's own arithmetic overflow. Rejecting
/// it keeps every later `checked_add` trivially safe.
pub const MAX_SEQ: i64 = 1 << 48;

/// Longest opaque `version` token accepted, in bytes.
pub const MAX_VERSION_LEN: usize = 128;

/// Longest bearer token accepted, in bytes.
pub const MAX_TOKEN_LEN: usize = 4096;

/// Longest authentication challenge nonce accepted, in bytes.
pub const MAX_CHALLENGE_NONCE_LEN: usize = 128;

/// Shortest authentication challenge nonce accepted, in bytes.
///
/// A one-byte "nonce" is not a nonce. The floor is what makes a replayed
/// challenge infeasible rather than merely unlikely.
pub const MIN_CHALLENGE_NONCE_LEN: usize = 16;

/// Bytes of client entropy in a `/v1/time` request.
pub const TIME_NONCE_LEN: usize = 32;

/// Largest roster payload this client will decode, in bytes.
///
/// A roster record is at most 16 + 32 + 64 + 32 + 8 + 17 bytes plus CBOR
/// framing, so this leaves room for far more devices than any person owns.
pub const MAX_ROSTER_PAYLOAD_LEN: usize = 64 * 1024;

/// Largest sealed enrollment grant this client will decode, in bytes.
pub const MAX_ENROLLMENT_PAYLOAD_LEN: usize = 128 * 1024;

/// SPEC §6.5: warn the user once the measured offset passes this.
pub const DRIFT_WARNING_MS: i64 = 10_000;

/// SPEC §6.5: say so when drift was last measured longer ago than this.
pub const DRIFT_STALE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Objects re-sealed per [`rotate_step`](crate::SyncEngine::rotate_step) call.
///
/// Rotation is lazy and resumable (SPEC §6.4), so the step size is a latency
/// knob rather than a correctness one: a smaller step interleaves better with a
/// foreground UI, and interrupting between any two steps is safe.
pub const DEFAULT_ROTATION_STEP: usize = 32;
