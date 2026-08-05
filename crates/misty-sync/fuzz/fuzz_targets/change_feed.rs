// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

#![no_main]
//! Fuzzes the change-feed decoder (SPEC §10 rule 7).
//!
//! Run with:
//!
//! ```text
//! cd crates/misty-sync/fuzz
//! cargo +nightly fuzz run change_feed
//! ```
//!
//! This is the crate's hostile-input boundary. Every other decoder here reads
//! something a *device* produced — an envelope, a roster, a grant — and is
//! protected by a signature check before it runs. The change feed is different:
//! it is the framing itself, chosen entirely by the server (threat model `A1`),
//! and it is parsed before anything has been authenticated. It turns a stranger's
//! bytes into item ids, sequence numbers and envelope buffers, and everything
//! above it assumes those are well formed.
//!
//! The contract: for **any** byte string, [`decode_change_feed`] either succeeds
//! or returns a typed error. No panic, no unbounded allocation, no loop.
//!
//! Three invariants are asserted on success rather than merely exercised, because
//! each one is something the engine relies on without re-checking:
//!
//! * `seq` strictly ascends within a page — the engine's cursor arithmetic assumes
//!   it, and equal sequence numbers would make "resume after *n*" ambiguous;
//! * `next_seq` is not below the last change delivered, or the client would be
//!   told to re-read what it has just read, forever;
//! * every `seq` is in `0..MAX_SEQ` and every envelope is within the cap, so no
//!   later arithmetic can overflow and no allocation is unbounded.
//!
//! `tests/hostile_input.rs` covers the same entry point on stable, including a
//! `proptest` sweep, so CI has coverage of it on every commit without a fuzzing
//! run.

use libfuzzer_sys::fuzz_target;
use misty_sync::limits;
use misty_sync::wire::decode_change_feed;

fuzz_target!(|data: &[u8]| {
    let Ok(feed) = decode_change_feed(data) else {
        return;
    };

    assert!(
        feed.changes.len() <= limits::MAX_CHANGES_PER_PAGE,
        "a page larger than the cap was accepted"
    );
    assert!(
        (0..limits::MAX_SEQ).contains(&feed.next_seq),
        "next_seq {} is outside the plausible range",
        feed.next_seq
    );

    let mut previous: Option<i64> = None;
    for change in &feed.changes {
        assert!(
            (0..limits::MAX_SEQ).contains(&change.seq),
            "seq {} is outside the plausible range",
            change.seq
        );
        if let Some(previous) = previous {
            assert!(
                change.seq > previous,
                "seq {} does not exceed {previous}",
                change.seq
            );
        }
        previous = Some(change.seq);
        // Absent when the server has reclaimed a row's bytes but kept the row so
        // `version` stays monotonic; present envelopes are within the cap.
        if let Some(envelope) = change.envelope.as_deref() {
            assert!(
                envelope.len() <= limits::MAX_ENVELOPE_LEN,
                "an envelope of {} bytes was accepted",
                envelope.len()
            );
        }
    }
    if let Some(last) = previous {
        assert!(
            feed.next_seq >= last,
            "next_seq {} is below the last change {last}",
            feed.next_seq
        );
    }
});
