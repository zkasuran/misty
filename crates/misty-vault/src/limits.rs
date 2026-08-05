// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hard bounds on everything a decoder can be handed.
//!
//! Every constant here exists because an item payload is attacker-influenced:
//! it arrives from a sync server (threat model `A1`) or from an importer, and it
//! is only *authenticated*, never *trusted*. A signed envelope from one of your
//! own devices can still carry a field that a buggy or compromised client
//! produced, so the decoder bounds every length before it builds a model.
//!
//! Two limits often exist for one thing, and the pair is deliberate:
//!
//! * a **mutation** limit, enforced by this device's own editing API, and
//! * a **decode** limit, much larger, enforced when reading a payload.
//!
//! They differ because merge takes the union of two OR-Sets, so a merged item can
//! legitimately hold more entries than any single writer was allowed to add: 32
//! devices with disjoint tag sets is unlikely but not impossible. If the decode
//! limit equalled the mutation limit, an ordinary merge could produce an item that
//! this crate had just written and could no longer read. The encoder checks the
//! decode limits too — [`encode_item`](crate::codec::encode_item) validates
//! before it writes — so the crate never stores a payload it would refuse to
//! load, and an overflow surfaces as a typed error on a transaction that rolls
//! back rather than as a corrupt row.

/// Longest `issuer`, in bytes of UTF-8.
pub const MAX_ISSUER_LEN: usize = 256;

/// Longest `account`, in bytes of UTF-8.
pub const MAX_ACCOUNT_LEN: usize = 256;

/// Longest `nickname`, in bytes of UTF-8. Short by design: SPEC §3.1 requires it
/// to stay visible next to the account name without truncation.
pub const MAX_NICKNAME_LEN: usize = 128;

/// Longest `note`, in bytes of UTF-8.
pub const MAX_NOTE_LEN: usize = 8 * 1024;

/// Longest single tag, in bytes of UTF-8.
pub const MAX_TAG_LEN: usize = 64;

/// Longest single origin. 253 is the maximum length of a DNS name.
pub const MAX_ORIGIN_LEN: usize = 253;

/// Longest bundled-icon slug.
pub const MAX_ICON_SLUG_LEN: usize = 64;

/// Longest group name, in bytes of UTF-8.
pub const MAX_GROUP_NAME_LEN: usize = 128;

/// Most entries this device's own API will add to one OR-Set.
pub const MAX_SET_ENTRIES: usize = 256;

/// Most entries a decoder will accept in one OR-Set, merged tombstones
/// included. See the [module docs](self) for why this is so much larger than
/// [`MAX_SET_ENTRIES`]: it bounds allocation, and it has to leave room for the
/// union of every device's set.
pub const MAX_DECODED_SET_ENTRIES: usize = 32 * MAX_SET_ENTRIES;

/// Most devices a usage G-counter may name.
pub const MAX_USAGE_DEVICES: usize = 256;

/// Largest CBOR item payload, before padding and encryption.
///
/// Checked before the CBOR parser runs, so a hostile payload is rejected by a
/// length comparison rather than by a parse. Chosen to leave headroom above the
/// worst case the limits above allow: three full OR-Sets, a full note, and a
/// full usage counter.
pub const MAX_ITEM_PAYLOAD_LEN: usize = 512 * 1024;

/// Largest CBOR group payload, before padding and encryption.
pub const MAX_GROUP_PAYLOAD_LEN: usize = 8 * 1024;

/// How long a trashed item stays recoverable before a tombstone is written
/// (SPEC §4): 30 days, in milliseconds.
pub const TRASH_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// How long a tombstone is retained before the row is purged (SPEC §4): 90
/// days, in milliseconds.
pub const TOMBSTONE_RETENTION_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// Ceiling on how many times one merge may fork an item.
///
/// Forking is driven by `otp.secret` divergence and each fork lands on a
/// content-derived id, so a chain longer than this needs a 128-bit id collision.
/// The bound exists so a pathological or hostile input cannot loop.
pub const MAX_MERGE_STEPS: usize = 64;
