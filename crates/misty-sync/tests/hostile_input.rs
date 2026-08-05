// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile input from the network. **All of these error; none of them panic.**
//!
//! The change-feed decoder is the widest attacker-controlled surface in the crate:
//! it is the one function that turns a stranger's bytes into ids, sequence numbers
//! and envelopes. Everything above it assumes those are well formed, so this is
//! where that becomes true rather than hoped for. `fuzz/fuzz_targets/change_feed.rs`
//! points a fuzzer at exactly this entry point; this file is the stable-toolchain
//! half, so CI covers it on every commit.
//!
//! The `proptest` case at the end is the one that matters most: it asserts nothing
//! about *which* error comes back, only that some error does and the process
//! survives.

mod support;

use misty_sync::wire::{decode_change_feed, ServerVersion};
use misty_sync::{limits, SyncError};
use proptest::prelude::*;
use support::Fixture;

/// Everything a decoder may return here is an error; what must never happen is a
/// panic, an unbounded allocation, or a success.
fn refuses(body: &str) {
    let result = decode_change_feed(body.as_bytes());
    assert!(result.is_err(), "accepted {body:?}");
}

#[test]
fn malformed_json_is_refused() {
    for body in [
        "",
        "{",
        "[]",
        "null",
        "\"a string\"",
        "{\"changes\":",
        "{\"changes\":{}}",
        "{\"changes\":[{}],\"next_seq\":0}",
        "{\"next_seq\":\"not a number\"}",
        "{\"changes\":[],\"next_seq\":1.5}",
    ] {
        refuses(body);
    }
}

#[test]
fn a_non_utf8_body_is_refused_rather_than_lossily_decoded() {
    let body = [0x7b, 0xff, 0xfe, 0x7d];
    let error = decode_change_feed(&body).expect_err("not UTF-8");
    assert!(matches!(error, SyncError::Malformed { .. }), "{error:?}");
}

#[test]
fn a_body_over_the_cap_is_refused_before_it_is_parsed() {
    let body = vec![b'x'; limits::MAX_RESPONSE_BODY_LEN + 1];
    let error = decode_change_feed(&body).expect_err("over the cap");
    assert!(
        matches!(error, SyncError::ResponseTooLarge { .. }),
        "{error:?}"
    );
}

#[test]
fn an_absurd_next_seq_is_refused() {
    // Beyond `i64`: serde refuses the number itself.
    refuses("{\"changes\":[],\"next_seq\":99999999999999999999999}");
    // Negative, and huge but representable: the range check catches both.
    for value in [-1i64, i64::MIN, i64::MAX, limits::MAX_SEQ] {
        let body = format!("{{\"changes\":[],\"next_seq\":{value}}}");
        let error = decode_change_feed(body.as_bytes()).expect_err("out of range");
        assert!(
            matches!(error, SyncError::SeqOutOfRange { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn a_page_that_is_not_strictly_ascending_is_refused() {
    let entry = |seq: i64| {
        format!(
            "{{\"item_id\":\"{}\",\"seq\":{seq},\"envelope\":\"\"}}",
            "11".repeat(16)
        )
    };
    for (first, second) in [(2i64, 1i64), (2, 2)] {
        let body = format!(
            "{{\"changes\":[{},{}],\"next_seq\":9}}",
            entry(first),
            entry(second)
        );
        let error = decode_change_feed(body.as_bytes()).expect_err("not ascending");
        assert!(
            matches!(error, SyncError::FeedOutOfOrder { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn a_next_seq_below_the_last_change_is_refused() {
    let body = format!(
        "{{\"changes\":[{{\"item_id\":\"{}\",\"seq\":7,\"envelope\":\"\"}}],\"next_seq\":3}}",
        "11".repeat(16)
    );
    let error = decode_change_feed(body.as_bytes()).expect_err("resume point moved back");
    assert!(
        matches!(error, SyncError::FeedOutOfOrder { .. }),
        "{error:?}"
    );
}

#[test]
fn an_item_id_of_the_wrong_length_is_refused() {
    for id in [
        "",
        "11",
        &"11".repeat(15),
        &"11".repeat(17),
        &"zz".repeat(16),
    ] {
        let body = format!(
            "{{\"changes\":[{{\"item_id\":\"{id}\",\"seq\":1,\"envelope\":\"\"}}],\"next_seq\":1}}"
        );
        let error = decode_change_feed(body.as_bytes()).expect_err("bad id");
        assert!(matches!(error, SyncError::Malformed { .. }), "{error:?}");
    }
}

#[test]
fn an_envelope_over_the_cap_is_refused() {
    // Base64 of something a little over the envelope limit. Rejected on the
    // encoded length, before any allocation the size of the decoded value.
    let oversized = "A".repeat((limits::MAX_ENVELOPE_LEN + 1024) * 4 / 3);
    let body = format!(
        "{{\"changes\":[{{\"item_id\":\"{}\",\"seq\":1,\"envelope\":\"{oversized}\"}}],\"next_seq\":1}}",
        "11".repeat(16)
    );
    let error = decode_change_feed(body.as_bytes()).expect_err("oversized envelope");
    assert!(
        matches!(error, SyncError::EnvelopeTooLarge { .. }),
        "{error:?}"
    );
}

#[test]
fn a_page_with_too_many_changes_is_refused() {
    let entry = |seq: usize| {
        format!(
            "{{\"item_id\":\"{}\",\"seq\":{seq},\"envelope\":\"\"}}",
            "11".repeat(16)
        )
    };
    let entries: Vec<String> = (1..=limits::MAX_CHANGES_PER_PAGE + 1).map(entry).collect();
    let body = format!("{{\"changes\":[{}],\"next_seq\":99999}}", entries.join(","));
    let error = decode_change_feed(body.as_bytes()).expect_err("too many changes");
    assert!(
        matches!(error, SyncError::ResponseTooLarge { .. }),
        "{error:?}"
    );
}

#[test]
fn a_version_token_that_is_not_a_header_value_is_refused() {
    for token in [
        "",
        "with space",
        "with\rcr",
        "with\nlf",
        "with\0nul",
        "with\"quote",
        &"v".repeat(limits::MAX_VERSION_LEN + 1),
    ] {
        assert!(
            ServerVersion::parse(token).is_err(),
            "accepted {token:?} as a version"
        );
    }
    assert!(ServerVersion::parse("W/\\-abc123").is_ok());
}

#[test]
fn a_ten_megabyte_error_body_is_not_read_into_the_error() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    // Two requests of honest authentication, then a 500 with ten megabytes.
    fixture.server.set_faults(misty_sync::Faults {
        status_after: Some((2, 500, vec![b'x'; 10 * 1024 * 1024])),
        ..misty_sync::Faults::default()
    });
    let error = alice.sync().expect_err("the server failed");
    match error {
        SyncError::Server { status, .. } => assert_eq!(status, 500),
        other => panic!("{other:?}"),
    }
    // The body is not in the message, and the message is short.
    let rendered = alice.sync().expect_err("again").to_string();
    assert!(rendered.len() < 120, "{rendered}");
    assert!(!rendered.contains('x'), "{rendered}");
}

#[test]
fn a_garbage_feed_body_reaches_the_engine_as_an_error() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    fixture.server.set_faults(misty_sync::Faults {
        feed_body: Some(b"<html>not json at all</html>".to_vec()),
        ..misty_sync::Faults::default()
    });
    let error = alice.sync().expect_err("garbage feed");
    assert!(matches!(error, SyncError::Malformed { .. }), "{error:?}");
    assert_eq!(alice.engine.cursor(), None, "the cursor did not move");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Arbitrary bytes: some error, no panic. Nothing is asserted about which.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_change_feed(&bytes);
    }

    /// Arbitrary *JSON-shaped* bytes, which get much further into the decoder.
    #[test]
    fn arbitrary_json_shaped_bytes_never_panic(
        seq in any::<i64>(),
        next in any::<i64>(),
        id in "[0-9a-fA-F]{0,40}",
        envelope in "[A-Za-z0-9+/=]{0,64}",
        version in ".{0,40}",
        deleted in any::<bool>(),
    ) {
        let body = format!(
            "{{\"changes\":[{{\"item_id\":\"{id}\",\"seq\":{seq},\"version\":{},\"envelope\":\"{envelope}\",\"deleted\":{deleted}}}],\"next_seq\":{next}}}",
            serde_json::to_string(&version).unwrap_or_else(|_| "null".to_owned()),
        );
        let _ = decode_change_feed(body.as_bytes());
    }
}
