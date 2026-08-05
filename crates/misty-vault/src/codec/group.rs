// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The group payload's CBOR shape. Small, and holds no secret.

use serde::{Deserialize, Serialize};

use crate::codec::{cbor_error, check_payload_len, check_version};
use crate::crdt::{Lww, MinWins};
use crate::error::Result;
use crate::ids::GroupId;
use crate::limits;
use crate::model::{Group, Tombstone};

/// Version of the group payload schema.
pub const GROUP_FORMAT_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupWire {
    v: u8,
    id: GroupId,
    nam: Lww<String>,
    col: Lww<Option<u32>>,
    ord: Lww<Option<i64>>,
    crt: MinWins<i64>,
    del: Option<Tombstone>,
}

/// Encodes a group as a CBOR payload.
///
/// # Errors
///
/// Anything [`Group::validate`] rejects, [`VaultError::Cbor`](crate::VaultError::Cbor),
/// or [`VaultError::PayloadTooLarge`](crate::VaultError::PayloadTooLarge).
pub fn encode_group(group: &Group) -> Result<Vec<u8>> {
    group.validate()?;
    let wire = GroupWire {
        v: GROUP_FORMAT_VERSION,
        id: group.id,
        nam: Lww::new(group.name.get().clone(), group.name.hlc()),
        col: group.color,
        ord: group.manual_order,
        crt: group.created_at,
        del: group.deleted,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&wire, &mut buf).map_err(cbor_error("encode"))?;
    check_payload_len("group", buf.len(), limits::MAX_GROUP_PAYLOAD_LEN)?;
    Ok(buf)
}

/// Decodes a group payload.
///
/// # Errors
///
/// As [`decode_item`](crate::codec::decode_item), minus the item-only variants.
pub fn decode_group(payload: &[u8]) -> Result<Group> {
    check_payload_len("group", payload.len(), limits::MAX_GROUP_PAYLOAD_LEN)?;
    check_version("group", payload, GROUP_FORMAT_VERSION)?;
    let wire: GroupWire = ciborium::from_reader(payload).map_err(cbor_error("decode"))?;
    let group = Group {
        id: wire.id,
        name: wire.nam,
        color: wire.col,
        manual_order: wire.ord,
        created_at: wire.crt,
        deleted: wire.del,
    };
    group.validate()?;
    Ok(group)
}
