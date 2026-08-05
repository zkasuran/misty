// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CBOR, which is this layer's business and nobody else's.
//!
//! SPEC §2.4 is explicit that the envelope "treats `payload` as **opaque bytes**
//! and MUST NOT know how it is encoded", and SPEC §5 puts the encoding here. So
//! `misty-crypto` pads and encrypts bytes, and this module decides they are CBOR.
//! The split is what lets an envelope carry a roster, a settings blob or a future
//! format without a change in the crypto crate.
//!
//! # The wire schema is frozen, and short
//!
//! Field names are two to three characters. That is not premature optimisation:
//! payloads are padded to 256-byte buckets before encryption (SPEC §2.4), so
//! roughly 300 bytes of spelled-out field names is the difference between a
//! typical item costing one bucket and costing two — on every write, forever,
//! and visibly to a hostile server that counts buckets.
//!
//! The mapping from field name to meaning is therefore part of the format:
//!
//! | Key | Field | Key | Field |
//! |---|---|---|---|
//! | `v` | `format_version` | `icn` | `icon` |
//! | `id` | `id` | `col` | `color` |
//! | `sec` | `otp.secret` | `fav` | `favorite` |
//! | `knd` | `otp.kind` | `ord` | `manual_order` |
//! | `alg` | `otp.algorithm` | `arc` | `archived` |
//! | `dig` | `otp.digits` | `hid` | `hidden` |
//! | `per` | `otp.period` | `rva` | `requires_reveal_auth` |
//! | `pin` | `otp.pin` | `trs` | `trashed_at` |
//! | `cnt` | `otp.counter` | `usg` | `usage` |
//! | `isr` | `issuer` | `lus` | `last_used_at` |
//! | `acc` | `account` | `crt` | `created_at` |
//! | `nck` | `nickname` | `del` | `deleted` |
//! | `nte` | `note` | `nam` | `name` (group) |
//! | `grp` | `groups` | `tag` | `tags` |
//! | `org` | `origins` | | |
//!
//! `tests/wire_format.rs` asserts that exact key set, so a rename cannot happen
//! by accident: it would silently orphan every stored item.
//!
//! # Enum values are pinned here, not inherited
//!
//! `OtpKind` and `HashAlg` are `misty-otp`'s types and neither derives
//! `Serialize` — deliberately, since that crate has no persistence story. This
//! module maps them to explicit wire bytes, which also means reordering a variant
//! upstream cannot change what is already on disk.
//!
//! # Strictness
//!
//! Unknown keys are rejected rather than ignored, and the format version is read
//! by a separate tolerant pass first so that a payload from a future build
//! reports [`VaultError::UnsupportedFormatVersion`] instead of an opaque parse
//! error. Every length and count is bounded by [`crate::limits`] before a model is
//! built, and [`encode_item`] validates before it writes, so this crate never
//! stores a payload it would refuse to load.

mod group;
mod item;

pub use group::{decode_group, encode_group, GROUP_FORMAT_VERSION};
pub use item::{decode_item, encode_item, ITEM_FORMAT_VERSION};

use serde::Deserialize;

use crate::error::{Result, VaultError};

/// Reads only `v` from a payload, tolerating every other key.
///
/// Run before the strict pass so that a newer format version is reported as
/// exactly that.
#[derive(Deserialize)]
struct VersionProbe {
    v: u8,
}

/// Checks a payload's declared format version.
fn check_version(context: &'static str, payload: &[u8], supported: u8) -> Result<()> {
    let probe: VersionProbe = ciborium::from_reader(payload).map_err(|error| VaultError::Cbor {
        operation: "decode",
        detail: error.to_string(),
    })?;
    if probe.v == supported {
        Ok(())
    } else {
        Err(VaultError::UnsupportedFormatVersion {
            context,
            found: probe.v,
            supported,
        })
    }
}

/// Rejects a payload larger than this crate will decode, before parsing it.
fn check_payload_len(context: &'static str, len: usize, max: usize) -> Result<()> {
    if len > max {
        return Err(VaultError::PayloadTooLarge { context, len, max });
    }
    Ok(())
}

/// Maps a `ciborium` failure onto [`VaultError::Cbor`].
fn cbor_error<E: core::fmt::Display>(operation: &'static str) -> impl Fn(E) -> VaultError {
    move |error| VaultError::Cbor {
        operation,
        detail: error.to_string(),
    }
}
