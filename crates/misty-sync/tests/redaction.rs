// SPDX-FileCopyrightText: 2026 The Misty Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Nothing leaks.
//!
//! SPEC §9 makes a secret in a log line a release blocker, and this crate goes
//! further than a convention: it emits **no log records at all** — there is no
//! `tracing` or `log` dependency in its manifest — so the only way anything could
//! escape is through a value someone formatted. That leaves two things to check,
//! and both are checked here over the whole error enum:
//!
//! * no [`SyncError`] names a secret, an envelope byte or an `item_id`, in
//!   `Display` **or** `Debug`;
//! * the wrapper around a `misty-vault` failure keeps that crate's own messages —
//!   which do name item ids, reasonably, since an id is cleartext on the wire —
//!   out of anything this crate renders.

mod support;

use misty_crypto::envelope::EnvelopeKind;
use misty_crypto::{DeviceId, ItemId};
use misty_sync::error::{RosterRejection, TransportKind};
use misty_sync::SyncError;
use support::{seal, Fixture};

/// A secret distinctive enough that finding it in a string is unambiguous.
const SECRET: &[u8] = b"NEVERAPPEARSINALOG";

/// One of every variant, with values chosen so that a leak is recognisable.
fn every_variant() -> Vec<SyncError> {
    let item = ItemId::from_bytes([0xab; 16]);
    vec![
        SyncError::Crypto(misty_crypto::Error::SignatureInvalid),
        SyncError::Crypto(misty_crypto::Error::UnknownSigner {
            signer: DeviceId::from_bytes([0x0d; 16]),
        }),
        SyncError::Transport {
            operation: "changes",
            kind: TransportKind::PinMismatch,
        },
        SyncError::Server {
            operation: "changes",
            status: 503,
        },
        SyncError::AuthRefused {
            operation: "authenticate",
        },
        SyncError::Malformed {
            operation: "changes",
            field: "next_seq",
        },
        SyncError::ResponseTooLarge {
            operation: "changes",
            max: 1,
        },
        SyncError::EnvelopeTooLarge { len: 2, max: 1 },
        SyncError::SeqRollback {
            offered: 1,
            cursor: 9,
        },
        SyncError::FeedOutOfOrder {
            offered: 1,
            previous: 9,
        },
        SyncError::SeqOutOfRange {
            offered: -1,
            max: 9,
        },
        SyncError::FeedTooLong { max: 9 },
        SyncError::UnknownSigner {
            signer: DeviceId::from_bytes([0x0d; 16]),
        },
        SyncError::RosterRejected {
            reason: RosterRejection::SignerNotTrusted,
        },
        SyncError::Revoked {
            device: DeviceId::from_bytes([0x0d; 16]),
        },
        SyncError::TimeSignatureInvalid,
        SyncError::TimeNonceMismatch,
        SyncError::TimeWentBackwards {
            offered: 1,
            previous: 2,
        },
        SyncError::ConflictLoop { max: 8 },
        SyncError::ConflictWithoutEnvelope,
        SyncError::UnusableVersionToken,
        SyncError::StateStore { operation: "save" },
        SyncError::StateTooNew {
            found: 2,
            supported: 1,
        },
        SyncError::BadServerUrl,
        SyncError::BadPin {
            expected: 32,
            found: 3,
        },
        // Not constructible from here — `SyncError::vault` is crate-private — so a
        // real one is produced by `a_vault_failure_does_not_carry_its_message` below.
        SyncError::Malformed {
            operation: "merge",
            field: "payload",
        },
    ]
    .into_iter()
    .chain(core::iter::once(SyncError::EnvelopeTooLarge {
        len: item.as_bytes().len(),
        max: 0,
    }))
    .collect()
}

#[test]
fn no_error_variant_names_a_secret_an_envelope_or_an_item_id() {
    let item = ItemId::from_bytes([0xab; 16]);
    let poison: Vec<String> = vec![
        item.to_hex(),
        String::from_utf8_lossy(SECRET).into_owned(),
        // A base64 fragment of the kind an envelope would produce.
        String::from("MSTY"),
    ];
    for error in every_variant() {
        for rendering in [error.to_string(), format!("{error:?}")] {
            for needle in &poison {
                assert!(
                    !rendering.contains(needle.as_str()),
                    "{needle:?} leaked into {rendering:?}"
                );
            }
        }
    }
}

#[test]
fn a_vault_failure_does_not_carry_its_message() {
    let fixture = Fixture::new(1);
    let mut alice = fixture.peer(0);

    // An envelope that verifies — a rostered device really did sign it — but whose
    // payload is not an item. `misty-vault` refuses it and names the item id in its
    // own error; this crate must not repeat that.
    let id = ItemId::from_bytes([0xab; 16]);
    fixture.server.inject(
        id,
        seal(
            EnvelopeKind::Item,
            &id,
            b"not CBOR at all",
            fixture.identity(0),
        ),
    );

    let error = alice.sync().expect_err("the vault refuses the payload");
    let SyncError::Vault { operation, source } = &error else {
        panic!("expected a vault failure, got {error:?}");
    };
    assert_eq!(*operation, "merge remote changes");

    for rendering in [error.to_string(), format!("{error:?}")] {
        assert!(
            !rendering.contains(&id.to_hex()),
            "the item id leaked into {rendering:?}"
        );
        assert!(rendering.len() < 160, "too much detail: {rendering:?}");
    }
    // The detail is still reachable, deliberately and explicitly.
    assert!(
        matches!(source.get(), misty_vault::VaultError::Cbor { .. }),
        "the underlying error is preserved for a caller that asks for it: {:?}",
        source.get()
    );
}

#[test]
fn a_secret_never_reaches_an_error_through_a_real_sync() {
    let fixture = Fixture::new(2);
    let mut alice = fixture.peer(0);
    let mut bob = fixture.peer(1);
    let id = alice.add("Issuer", "ada@example.com", SECRET);
    alice.sync_ok();

    // Every fault we have, one after another, and none of the resulting errors may
    // mention the secret, the account, or the item id.
    let faults = [
        misty_sync::Faults {
            tamper_envelopes: true,
            ..misty_sync::Faults::default()
        },
        misty_sync::Faults {
            rollback_seq: true,
            ..misty_sync::Faults::default()
        },
        misty_sync::Faults {
            descending_page: true,
            ..misty_sync::Faults::default()
        },
        misty_sync::Faults {
            absurd_next_seq: true,
            ..misty_sync::Faults::default()
        },
        misty_sync::Faults {
            inject_header_in_version: true,
            ..misty_sync::Faults::default()
        },
        misty_sync::Faults {
            feed_body: Some(vec![0xff; 64]),
            ..misty_sync::Faults::default()
        },
        misty_sync::Faults {
            offline_after: Some(0),
            ..misty_sync::Faults::default()
        },
    ];
    let secret = String::from_utf8_lossy(SECRET).into_owned();
    for fault in faults {
        fixture.server.set_faults(fault);
        bob.engine.reset().ok();
        let rendered = match bob.sync() {
            Ok(report) => format!("{report:?}"),
            Err(error) => format!("{error} / {error:?}"),
        };
        for needle in [secret.as_str(), "ada@example.com", &id.to_hex()] {
            assert!(
                !rendered.contains(needle),
                "{needle:?} leaked into {rendered:?}"
            );
        }
    }
}

#[test]
fn a_fingerprint_does_not_print_itself() {
    let rendered = format!(
        "{:?}",
        misty_sync::Fingerprint::of(b"an envelope").expect("hash")
    );
    assert!(rendered.starts_with("Fingerprint("), "{rendered}");
    // Four bytes of prefix, eight hex characters, and an ellipsis.
    assert_eq!(rendered.len(), "Fingerprint(12345678…)".len(), "{rendered}");
}

#[test]
fn a_report_does_not_dump_an_envelope() {
    let fixture = Fixture::new(1);
    let alice = fixture.peer(0);
    let key = support::vault_key();
    let (address, envelope) =
        misty_sync::roster::seal_roster(&alice.roster, &key, 0, fixture.identity(0))
            .expect("seal roster");
    fixture.server.inject(address, envelope);

    let mut alice = alice;
    let report = alice.sync_ok();
    assert!(report.roster_update.is_some(), "the roster was offered");
    let rendered = format!("{report:?}");
    assert!(
        rendered.contains("roster_update_bytes: Some("),
        "a length, not the bytes: {rendered}"
    );
    assert!(rendered.len() < 400, "{rendered}");
}
