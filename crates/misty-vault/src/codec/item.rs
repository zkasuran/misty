// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The item payload's CBOR shape. See the [module docs](super) for the key map.

use core::fmt;
use std::collections::BTreeMap;

use misty_crypto::{DeviceId, ItemId};
use misty_otp::{HashAlg, OtpKind, SecretBytes};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use crate::codec::{cbor_error, check_payload_len, check_version};
use crate::crdt::{Lww, MaxWins, MinWins, OrSet, OrSetEntry, UsageCounter};
use crate::error::{Result, VaultError};
use crate::hlc::Hlc;
use crate::ids::GroupId;
use crate::limits;
use crate::model::{IconRef, Item, Tombstone};

/// Version of the item payload schema. Bump on any change to the keys or their
/// meanings, and add a decoder for the old shape in the same change.
pub const ITEM_FORMAT_VERSION: u8 = 1;

/// One OR-Set element: the element, its add clock, and its remove clock if any.
type SetEntry<T> = (T, Hlc, Option<Hlc>);

/// A byte buffer that serialises as a CBOR **byte string**, not as an array of
/// integers.
///
/// Serde's default for `Vec<u8>` is a sequence, which costs one to two bytes per
/// secret byte: a 64-byte secret would occupy 128. The secret is the largest
/// single field in a typical payload, so this is the difference between one
/// 256-byte padding bucket and two.
#[derive(Clone, PartialEq, Eq)]
struct WireBytes(Vec<u8>);

impl Serialize for WireBytes {
    fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for WireBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = WireBytes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a byte string")
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> core::result::Result<WireBytes, E> {
                Ok(WireBytes(v.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(
                self,
                v: Vec<u8>,
            ) -> core::result::Result<WireBytes, E> {
                Ok(WireBytes(v))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> core::result::Result<WireBytes, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1024));
                while let Some(byte) = seq.next_element::<u8>()? {
                    out.push(byte);
                }
                Ok(WireBytes(out))
            }
        }
        d.deserialize_bytes(V)
    }
}

impl Zeroize for WireBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemWire {
    v: u8,
    id: ItemId,
    sec: WireBytes,
    knd: Lww<u8>,
    alg: Lww<u8>,
    dig: Lww<u8>,
    per: Lww<u16>,
    pin: Lww<Option<WireBytes>>,
    cnt: MaxWins<u64>,
    isr: Lww<String>,
    acc: Lww<String>,
    nck: Lww<Option<String>>,
    nte: Lww<Option<String>>,
    grp: Vec<SetEntry<GroupId>>,
    tag: Vec<SetEntry<String>>,
    org: Vec<SetEntry<String>>,
    icn: Lww<IconRef>,
    col: Lww<Option<u32>>,
    fav: Lww<bool>,
    ord: Lww<Option<i64>>,
    arc: Lww<bool>,
    hid: Lww<bool>,
    rva: Lww<bool>,
    trs: Lww<Option<i64>>,
    usg: Vec<(DeviceId, u64)>,
    lus: MaxWins<Option<i64>>,
    crt: MinWins<i64>,
    del: Option<Tombstone>,
}

/// Wire byte for each OTP construction.
///
/// Pinned here rather than derived from `OtpKind`'s declaration order: reordering
/// that enum upstream must not change what is already on disk.
const fn kind_to_wire(kind: OtpKind) -> u8 {
    match kind {
        OtpKind::Totp => 1,
        OtpKind::Hotp => 2,
        OtpKind::Steam => 3,
        OtpKind::Motp => 4,
        OtpKind::Blizzard => 5,
        OtpKind::Yandex => 6,
    }
}

fn kind_from_wire(byte: u8) -> Result<OtpKind> {
    match byte {
        1 => Ok(OtpKind::Totp),
        2 => Ok(OtpKind::Hotp),
        3 => Ok(OtpKind::Steam),
        4 => Ok(OtpKind::Motp),
        5 => Ok(OtpKind::Blizzard),
        6 => Ok(OtpKind::Yandex),
        found => Err(VaultError::UnknownEnumValue {
            field: "otp.kind",
            found,
        }),
    }
}

const fn algorithm_to_wire(algorithm: HashAlg) -> u8 {
    match algorithm {
        HashAlg::Sha1 => 1,
        HashAlg::Sha256 => 2,
        HashAlg::Sha512 => 3,
    }
}

fn algorithm_from_wire(byte: u8) -> Result<HashAlg> {
    match byte {
        1 => Ok(HashAlg::Sha1),
        2 => Ok(HashAlg::Sha256),
        3 => Ok(HashAlg::Sha512),
        found => Err(VaultError::UnknownEnumValue {
            field: "otp.algorithm",
            found,
        }),
    }
}

/// Rebuilds an [`OrSet`] from wire entries, rejecting a repeated element.
///
/// A repeat cannot be resolved: the two entries carry different clocks, so
/// "the last one wins" would make the decoded value depend on encoder order, and
/// two devices could disagree about a set they both decoded from the same bytes.
fn set_from_wire<T: Ord>(field: &'static str, entries: Vec<SetEntry<T>>) -> Result<OrSet<T>> {
    if entries.len() > limits::MAX_DECODED_SET_ENTRIES {
        return Err(VaultError::TooManyElements {
            field,
            max: limits::MAX_DECODED_SET_ENTRIES,
            found: entries.len(),
        });
    }
    let mut map = BTreeMap::new();
    for (element, added, removed) in entries {
        if map.insert(element, OrSetEntry { added, removed }).is_some() {
            return Err(VaultError::DuplicateKey { field });
        }
    }
    Ok(OrSet::from_entries(map))
}

fn set_to_wire<T: Ord + Clone>(set: &OrSet<T>) -> Vec<SetEntry<T>> {
    set.entries()
        .map(|(element, entry)| (element.clone(), entry.added, entry.removed))
        .collect()
}

impl ItemWire {
    fn from_item(item: &Item) -> Self {
        Self {
            v: ITEM_FORMAT_VERSION,
            id: item.id,
            sec: WireBytes(item.secret.expose_secret().to_vec()),
            knd: Lww::new(kind_to_wire(*item.kind.get()), item.kind.hlc()),
            alg: Lww::new(
                algorithm_to_wire(*item.algorithm.get()),
                item.algorithm.hlc(),
            ),
            dig: Lww::new(*item.digits.get(), item.digits.hlc()),
            per: Lww::new(*item.period.get(), item.period.hlc()),
            pin: Lww::new(
                item.pin
                    .get()
                    .as_ref()
                    .map(|pin| WireBytes(pin.expose_secret().to_vec())),
                item.pin.hlc(),
            ),
            cnt: item.hotp_counter,
            isr: Lww::new(item.issuer.get().clone(), item.issuer.hlc()),
            acc: Lww::new(item.account.get().clone(), item.account.hlc()),
            nck: Lww::new(item.nickname.get().clone(), item.nickname.hlc()),
            nte: Lww::new(item.note.get().clone(), item.note.hlc()),
            grp: set_to_wire(&item.groups),
            tag: set_to_wire(&item.tags),
            org: set_to_wire(&item.origins),
            icn: Lww::new(item.icon.get().clone(), item.icon.hlc()),
            col: item.color,
            fav: item.favorite,
            ord: item.manual_order,
            arc: item.archived,
            hid: item.hidden,
            rva: item.requires_reveal_auth,
            trs: item.trashed_at,
            usg: item
                .usage
                .iter()
                .map(|(device, count)| (*device, count))
                .collect(),
            lus: item.last_used_at,
            crt: item.created_at,
            del: item.deleted,
        }
    }

    /// Consumes the wire struct into a model item.
    ///
    /// Consuming rather than borrowing is what keeps the secret to one copy: the
    /// `Vec<u8>` is *moved* into [`SecretBytes`], which zeroizes it on drop.
    fn into_item(self) -> Result<Item> {
        let mut usage = BTreeMap::new();
        if self.usg.len() > limits::MAX_USAGE_DEVICES {
            return Err(VaultError::TooManyElements {
                field: "usage",
                max: limits::MAX_USAGE_DEVICES,
                found: self.usg.len(),
            });
        }
        for (device, count) in self.usg {
            if usage.insert(device, count).is_some() {
                return Err(VaultError::DuplicateKey { field: "usage" });
            }
        }

        let kind_hlc = self.knd.hlc();
        let algorithm_hlc = self.alg.hlc();
        let pin_hlc = self.pin.hlc();
        Ok(Item {
            id: self.id,
            secret: SecretBytes::new(self.sec.0),
            kind: Lww::new(kind_from_wire(self.knd.into_value())?, kind_hlc),
            algorithm: Lww::new(algorithm_from_wire(self.alg.into_value())?, algorithm_hlc),
            digits: self.dig,
            period: self.per,
            pin: Lww::new(
                self.pin.into_value().map(|pin| SecretBytes::new(pin.0)),
                pin_hlc,
            ),
            hotp_counter: self.cnt,
            issuer: self.isr,
            account: self.acc,
            nickname: self.nck,
            note: self.nte,
            groups: set_from_wire("groups", self.grp)?,
            tags: set_from_wire("tags", self.tag)?,
            origins: set_from_wire("origins", self.org)?,
            icon: self.icn,
            color: self.col,
            favorite: self.fav,
            manual_order: self.ord,
            archived: self.arc,
            hidden: self.hid,
            requires_reveal_auth: self.rva,
            trashed_at: self.trs,
            usage: UsageCounter::from_counts(usage),
            last_used_at: self.lus,
            created_at: self.crt,
            deleted: self.del,
        })
    }

    /// Wipes the two secret copies this transient struct holds.
    fn zeroize_secrets(&mut self) {
        self.sec.zeroize();
        if let Some(pin) = self.pin.value_mut() {
            pin.zeroize();
        }
    }
}

/// Encodes an item as a CBOR payload, ready for
/// [`misty_crypto::envelope::seal`].
///
/// Validates first, so this crate never stores a payload it would refuse to load.
/// The returned buffer holds the secret in the clear and is
/// [`Zeroizing`](zeroize::Zeroizing) for that reason.
///
/// # Errors
///
/// Anything [`Item::validate`] rejects, [`VaultError::Cbor`] if serialisation
/// fails, or [`VaultError::PayloadTooLarge`] past
/// [`MAX_ITEM_PAYLOAD_LEN`](crate::limits::MAX_ITEM_PAYLOAD_LEN).
pub fn encode_item(item: &Item) -> Result<Zeroizing<Vec<u8>>> {
    item.validate()?;
    let mut wire = ItemWire::from_item(item);
    let mut buf = Zeroizing::new(Vec::new());
    let written = ciborium::into_writer(&wire, &mut *buf);
    // Before the `?`: an encode that failed part way through still copied the
    // secret into `wire`.
    wire.zeroize_secrets();
    written.map_err(cbor_error("encode"))?;
    check_payload_len("item", buf.len(), limits::MAX_ITEM_PAYLOAD_LEN)?;
    Ok(buf)
}

/// Decodes an item payload.
///
/// This is the crate's hostile-input entry point: the bytes have been
/// authenticated by the envelope layer, which proves a rostered device signed
/// them, and proves nothing at all about whether that device's build was correct.
/// It is a fuzz target (`fuzz/fuzz_targets/item_decode.rs`).
///
/// # Errors
///
/// [`VaultError::PayloadTooLarge`], [`VaultError::UnsupportedFormatVersion`],
/// [`VaultError::Cbor`], [`VaultError::UnknownEnumValue`],
/// [`VaultError::DuplicateKey`], [`VaultError::TooManyElements`], or anything
/// [`Item::validate`] rejects.
pub fn decode_item(payload: &[u8]) -> Result<Item> {
    check_payload_len("item", payload.len(), limits::MAX_ITEM_PAYLOAD_LEN)?;
    check_version("item", payload, ITEM_FORMAT_VERSION)?;
    let wire: ItemWire = ciborium::from_reader(payload).map_err(cbor_error("decode"))?;
    let item = wire.into_item()?;
    item.validate()?;
    Ok(item)
}
