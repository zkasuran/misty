// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The core of this crate: one test per thing a compromised server or a network
//! attacker can do, and the client's answer to it.
//!
//! Every fault here is something an attacker who holds the database, or who sits
//! on the wire, can do **without any key**. That is the whole point of SPEC §1's
//! `A1` and `A6`: the server is assumed hostile, so "the server would not do that"
//! is never a defence.
//!
//! | What the server does | What the client does | Test |
//! |---|---|---|
//! | serves an envelope signed by a device absent from the roster | rejects it, merges nothing, keeps syncing | `an_envelope_from_an_unrostered_device_is_rejected` |
//! | flips one ciphertext byte | rejects it on the signature, before any decryption | `a_tampered_envelope_is_rejected` |
//! | rewinds `seq` below the client's cursor | refuses the page | `a_rolled_back_seq_is_refused` |
//! | serves a page in descending `seq` order | refuses the page | `a_descending_page_is_refused` |
//! | answers with an absurd `next_seq` | refuses the page | `an_absurd_next_seq_is_refused` |
//! | claims `has_more` forever | stops after a bounded number of pages | `an_endless_feed_is_bounded` |
//! | replays a signed `/v1/time` | refuses it: the nonce does not match | `a_replayed_time_response_is_refused` |
//! | signs `/v1/time` with another key | refuses it | `a_time_response_from_the_wrong_key_is_refused` |
//! | walks server time backwards | refuses it | `server_time_may_not_go_backwards` |
//! | sets `deleted` with no signed tombstone | ignores the flag entirely | `a_server_set_deleted_flag_deletes_nothing` |
//! | serves a roster signed by a device we do not trust | refuses to adopt it | `a_roster_signed_by_an_unknown_device_is_refused` |
//! | rewrites a roster's bytes | refuses to open it | `a_rewritten_roster_does_not_open` |
//! | serves the roster at another address | refuses it | `a_roster_at_the_wrong_address_is_refused` |
//! | answers `409` forever with a fresh version | stops, bounded | `a_conflict_loop_that_never_converges_is_bounded` |
//! | answers `409` forever with the same state | stops immediately | `a_conflict_that_makes_no_progress_stops_at_once` |
//! | answers `409` with an envelope we cannot attribute | stops rather than overwriting | `a_conflict_we_cannot_attribute_is_not_overwritten` |
//! | puts CR-LF in a `version` token | refuses the token | `a_version_token_with_crlf_is_refused` |

mod support;

use misty_crypto::envelope::EnvelopeKind;
use misty_crypto::identity::Roster;
use misty_crypto::ItemId;
use misty_otp::Clock;
use misty_sync::runtime::block_on;
use misty_sync::transport::Faults;
use misty_sync::{Rejection, RosterRejection, SyncError};
use support::{converge, device, record, seal, vault_key, Fixture};

/// A device that holds the vault key but is not in the roster — the `A6`
/// adversary who obtained the server database and tried to enrol itself.
fn stranger() -> misty_crypto::identity::DeviceIdentity {
    device(200)
}

#[test]
fn an_envelope_from_an_unrostered_device_is_rejected() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);

    let intruder_item = ItemId::from_bytes([0x77; 16]);
    fixture.server.inject(
        intruder_item,
        seal(
            EnvelopeKind::Item,
            &intruder_item,
            b"whatever this says, nobody read it",
            &stranger(),
        ),
    );

    let report = alice.sync_ok();
    assert_eq!(report.rejected_count(Rejection::UnknownSigner), 1);
    assert_eq!(report.applied, 0);
    assert!(
        alice.vault.get(&intruder_item).is_none(),
        "nothing an unrostered device signed reaches the vault"
    );
    // And the sync did not stall: the cursor moved past the bad row.
    assert!(alice.engine.cursor().is_some_and(|seq| seq > 0));
}

#[test]
fn a_tampered_envelope_is_rejected() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    let id = alice.add("GitHub", "ada", b"aaaaaaaaaaaaaaaa");
    alice.sync_ok();

    fixture.server.set_faults(Faults {
        tamper_envelopes: true,
        ..Faults::default()
    });
    let report = bob.sync_ok();
    assert_eq!(report.rejected_count(Rejection::SignatureInvalid), 1);
    assert_eq!(report.applied, 0);
    assert!(bob.vault.get(&id).is_none());

    // Healing: once the server stops lying, the same row merges. A rejected
    // change did not poison the cursor or the known-state map.
    fixture.server.heal();
    bob.engine.reset().expect("reset");
    converge(&mut alice, &mut bob);
    assert!(bob.vault.get(&id).is_some());
}

#[test]
fn a_rolled_back_seq_is_refused() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    alice.add("First", "ada", b"aaaaaaaaaaaaaaaa");
    converge(&mut alice, &mut bob);
    let cursor = bob.engine.cursor().expect("bob has a cursor");
    assert!(cursor > 0);

    alice.add("Second", "ada", b"bbbbbbbbbbbbbbbb");
    alice.sync_ok();

    fixture.server.set_faults(Faults {
        rollback_seq: true,
        ..Faults::default()
    });
    let error = bob.sync().expect_err("the feed went backwards");
    assert!(
        matches!(error, SyncError::SeqRollback { cursor: c, .. } if c == cursor),
        "{error:?}"
    );
    assert_eq!(
        bob.engine.cursor(),
        Some(cursor),
        "a refused page does not move the cursor"
    );
}

#[test]
fn a_descending_page_is_refused() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    for index in 0..3u8 {
        alice.add(&format!("Issuer {index}"), "ada", &[b'a' + index; 16]);
    }
    alice.sync_ok();

    fixture.server.set_faults(Faults {
        descending_page: true,
        ..Faults::default()
    });
    let error = bob.sync().expect_err("descending page");
    assert!(
        matches!(error, SyncError::FeedOutOfOrder { .. }),
        "{error:?}"
    );
}

#[test]
fn an_absurd_next_seq_is_refused() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");
    alice.sync_ok();

    fixture.server.set_faults(Faults {
        absurd_next_seq: true,
        ..Faults::default()
    });
    let error = bob.sync().expect_err("absurd next_seq");
    assert!(
        matches!(error, SyncError::SeqOutOfRange { .. }),
        "{error:?}"
    );
    assert_eq!(bob.engine.cursor(), None, "the cursor never took the value");
}

#[test]
fn an_endless_feed_is_bounded() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");
    alice.sync_ok();

    fixture.server.set_faults(Faults {
        endless_feed: true,
        ..Faults::default()
    });
    let error = bob.sync().expect_err("endless feed");
    assert!(matches!(error, SyncError::FeedTooLong { .. }), "{error:?}");
}

#[test]
fn an_overclaimed_has_more_that_stands_still_ends_cleanly() {
    // The benign half of the same lie: a server whose `has_more` is off by one
    // must not turn every sync into an error. A page that delivers nothing and
    // does not move `next_seq` means the client has read everything there is, so
    // it stops without complaining.
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    fixture.server.set_faults(Faults {
        stalled_feed: true,
        ..Faults::default()
    });
    let report = alice.sync_ok();
    assert_eq!(report.pages, 1);
    assert!(report.is_quiet());
}

#[test]
fn a_replayed_time_response_is_refused() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    fixture.server.set_faults(Faults {
        replay_time: true,
        ..Faults::default()
    });

    // The first exchange is honest and the mock caches its answer verbatim.
    let first = block_on(alice.engine.measure_time(alice.vault.clock())).expect("first reading");
    assert_eq!(first.server_ms, support::NOW as i64);

    // The second gets that same answer back, nonce and all. The signature is
    // perfectly valid — it is just an answer to a question nobody asked twice.
    let error = block_on(alice.engine.measure_time(alice.vault.clock()))
        .expect_err("a replay is not an answer");
    assert!(matches!(error, SyncError::TimeNonceMismatch), "{error:?}");
}

#[test]
fn a_time_response_from_the_wrong_key_is_refused() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    fixture.server.set_faults(Faults {
        wrong_time_key: true,
        ..Faults::default()
    });
    let error =
        block_on(alice.engine.measure_time(alice.vault.clock())).expect_err("wrong signing key");
    assert!(
        matches!(error, SyncError::TimeSignatureInvalid),
        "{error:?}"
    );
    assert_eq!(
        alice.engine.drift().sample(),
        None,
        "a refused reading is not stored"
    );
}

#[test]
fn server_time_may_not_go_backwards() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    block_on(alice.engine.measure_time(alice.vault.clock())).expect("first reading");

    // A minute of rollback is far more than the load-balancer tolerance and far
    // less than a TOTP step, which is exactly the range this check exists for.
    fixture.server.set_faults(Faults {
        time_offset_ms: -60_000,
        ..Faults::default()
    });
    let error =
        block_on(alice.engine.measure_time(alice.vault.clock())).expect_err("time went backwards");
    assert!(
        matches!(error, SyncError::TimeWentBackwards { .. }),
        "{error:?}"
    );
}

#[test]
fn a_measured_offset_is_applied_without_touching_any_clock() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    let local = alice.vault.clock().now_unix_ms();
    fixture.server.set_time_ms(local as i64 + 45_000);

    let sample = block_on(alice.engine.measure_time(alice.vault.clock())).expect("reading");
    assert_eq!(sample.offset_ms, 45_000);
    assert!(alice.engine.drift().exceeds_warning_threshold());
    assert_eq!(
        alice.vault.clock().now_unix_ms(),
        local,
        "the device clock was not written"
    );
    assert_eq!(
        alice.engine.drift().effective_now_ms(local as i64),
        local as i64 + 45_000
    );
}

#[test]
fn drift_is_stale_before_any_measurement_and_after_seven_days() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    let local = alice.vault.clock().now_unix_ms() as i64;
    assert!(alice.engine.drift().is_stale(local), "never measured");

    block_on(alice.engine.measure_time(alice.vault.clock())).expect("reading");
    assert!(!alice.engine.drift().is_stale(local));
    let week = 7 * 24 * 60 * 60 * 1000;
    assert!(!alice.engine.drift().is_stale(local + week));
    assert!(alice.engine.drift().is_stale(local + week + 1));
}

#[test]
fn a_server_set_deleted_flag_deletes_nothing() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    let id = alice.add("GitHub", "ada", b"aaaaaaaaaaaaaaaa");
    converge(&mut alice, &mut bob);
    assert!(bob.vault.get(&id).is_some());

    // Every change now claims `deleted: true`, and no payload contains a
    // tombstone. SPEC §6.1 makes the flag advisory precisely so that this is
    // survivable: deletion would otherwise be the one destructive operation
    // available to an attacker holding the database and no keys.
    fixture.server.set_faults(Faults {
        force_deleted_flag: true,
        ..Faults::default()
    });
    alice.rename(&id, "still here");
    alice.sync_ok();
    let report = bob.sync_ok();
    assert_eq!(report.applied, 1);

    let item = bob.vault.item(&id).expect("the item is still there");
    assert!(!item.is_deleted(), "no tombstone was invented");
    assert_eq!(item.nickname(), Some("still here"));
    assert_eq!(bob.vault.list().count(), 1);

    // And a full re-read from seq 0 with the flag still set changes nothing.
    bob.engine.reset().expect("reset");
    bob.sync_ok();
    assert!(bob.vault.get(&id).is_some());
    assert!(!bob.vault.item(&id).expect("item").is_deleted());
}

#[test]
fn a_roster_signed_by_an_unknown_device_is_refused() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    let intruder = stranger();

    // The server invents a roster listing itself, signs it with its own key, and
    // seals it at the roster's real address. It holds the vault key in this test,
    // which is more than `A6` grants it — and it still gets nowhere.
    let mut forged = Roster::new(vec![
        record(fixture.identity(0), "alice"),
        record(&intruder, "the server"),
    ]);
    forged.sign(&intruder).expect("sign");
    let address = misty_sync::roster::roster_item_id(&vault_key()).expect("address");
    let payload = misty_sync::roster::encode_roster(&forged).expect("encode");
    fixture.server.inject(
        address,
        seal(EnvelopeKind::DeviceRoster, &address, &payload, &intruder),
    );

    let report = alice.sync_ok();
    assert_eq!(report.rejected_count(Rejection::UnknownSigner), 1);
    assert!(
        report.roster_update.is_none(),
        "a roster we cannot attribute is not offered for adoption"
    );

    // And the direct path refuses it too, for the same reason.
    let error =
        misty_sync::roster::check_successor(&alice.roster, &forged).expect_err("does not chain");
    assert!(
        matches!(
            error,
            SyncError::RosterRejected {
                reason: RosterRejection::SignerNotTrusted
            }
        ),
        "{error:?}"
    );
}

#[test]
fn a_rewritten_roster_does_not_open() {
    let fixture = Fixture::new(1);
    let alice = fixture.peer(0);
    let key = vault_key();

    let (address, mut envelope) =
        misty_sync::roster::seal_roster(&alice.roster, &key, 0, fixture.identity(0))
            .expect("seal roster");
    assert!(misty_sync::roster::open_roster(&envelope, &address, &key, &alice.roster).is_ok());

    // One byte of ciphertext. The signature covers it, so this cannot be repaired
    // without the signing key.
    if let Some(byte) = envelope.get_mut(130) {
        *byte ^= 0x01;
    }
    let error = misty_sync::roster::open_roster(&envelope, &address, &key, &alice.roster)
        .expect_err("rewritten roster");
    assert!(
        matches!(
            error,
            SyncError::Crypto(misty_crypto::Error::SignatureInvalid)
        ),
        "{error:?}"
    );
}

#[test]
fn a_roster_at_the_wrong_address_is_refused() {
    let fixture = Fixture::new(1);
    let alice = fixture.peer(0);
    let key = vault_key();
    let (_, envelope) =
        misty_sync::roster::seal_roster(&alice.roster, &key, 0, fixture.identity(0))
            .expect("seal roster");
    let elsewhere = ItemId::from_bytes([0x01; 16]);
    let error = misty_sync::roster::open_roster(&envelope, &elsewhere, &key, &alice.roster)
        .expect_err("wrong address");
    assert!(
        matches!(
            error,
            SyncError::RosterRejected {
                reason: RosterRejection::WrongAddress
            }
        ),
        "{error:?}"
    );
}

#[test]
fn a_conflict_loop_that_never_converges_is_bounded() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    let id = alice.add("Shared", "ada", b"aaaaaaaaaaaaaaaa");
    converge(&mut alice, &mut bob);
    fixture.server.clear_log();

    // Every `PUT` is answered `409` with a fresh `version` each time, so a client
    // that only noticed "the same state twice" would spin forever.
    fixture.server.set_faults(Faults {
        conflict_forever: true,
        conflict_rotates_version: true,
        ..Faults::default()
    });
    alice.vault.clock().advance(1_000);
    alice.rename(&id, "mine");

    let error = alice.sync().expect_err("the server never accepts");
    assert!(matches!(error, SyncError::ConflictLoop { .. }), "{error:?}");
    assert!(
        fixture.server.puts_for(&id) <= misty_sync::limits::MAX_CONFLICT_RETRIES + 1,
        "the client stopped rather than hammering: {} puts",
        fixture.server.puts_for(&id)
    );
}

#[test]
fn a_conflict_that_makes_no_progress_stops_at_once() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    let id = alice.add("Shared", "ada", b"aaaaaaaaaaaaaaaa");
    converge(&mut alice, &mut bob);
    fixture.server.clear_log();

    // Same envelope, same version, forever: after the first answer there is
    // nothing left to learn, so the client does not spend its retry budget.
    fixture.server.set_faults(Faults {
        conflict_forever: true,
        ..Faults::default()
    });
    alice.vault.clock().advance(1_000);
    alice.rename(&id, "mine");
    let error = alice.sync().expect_err("no progress");
    assert!(matches!(error, SyncError::ConflictLoop { .. }), "{error:?}");
    assert_eq!(
        fixture.server.puts_for(&id),
        1,
        "one attempt is enough to know the answer will not change"
    );
}

#[test]
fn a_conflict_we_cannot_attribute_is_not_overwritten() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    let id = alice.add("Shared", "ada", b"aaaaaaaaaaaaaaaa");
    alice.sync_ok();

    // The server replaces the row with an envelope signed by a device the roster
    // does not list, then reports a conflict. Overwriting would be the one way a
    // hostile server gets a client to destroy data for it; refusing is a signal to
    // refresh the roster instead.
    let intruder = seal(
        EnvelopeKind::Item,
        &id,
        b"not from a device you trust",
        &stranger(),
    );
    fixture.server.inject(id, intruder.clone());
    alice.vault.clock().advance(1_000);
    alice.rename(&id, "mine");

    let error = alice.sync().expect_err("unattributable conflict");
    assert!(
        matches!(error, SyncError::UnknownSigner { .. })
            || matches!(error, SyncError::Malformed { .. })
            || matches!(error, SyncError::SeqRollback { .. }),
        "{error:?}"
    );
    // Whatever else happened, the client did not push over it.
    assert_eq!(fixture.server.envelope_of(&id), Some(intruder));
}

#[test]
fn a_version_token_with_crlf_is_refused() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");
    alice.sync_ok();

    // A `version` is opaque and goes straight into the next `If-Match` header. A
    // token carrying CR-LF would be request smuggling, so it is refused where it
    // arrives rather than where it is used.
    fixture.server.set_faults(Faults {
        inject_header_in_version: true,
        ..Faults::default()
    });
    let error = bob.sync().expect_err("unusable version token");
    assert!(
        matches!(error, SyncError::UnusableVersionToken),
        "{error:?}"
    );
}

#[test]
fn an_unauthenticated_client_is_told_so_rather_than_looping() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);
    alice.add("Issuer", "ada", b"aaaaaaaaaaaaaaaa");

    // The server accepts the challenge-response and then rejects the session
    // anyway, forever. One re-challenge, then stop.
    fixture.server.set_faults(Faults {
        status_after: Some((0, 401, Vec::new())),
        ..Faults::default()
    });
    let error = alice.sync().expect_err("authentication refused");
    assert!(
        matches!(
            error,
            SyncError::AuthRefused { .. } | SyncError::Server { .. }
        ),
        "{error:?}"
    );
}
