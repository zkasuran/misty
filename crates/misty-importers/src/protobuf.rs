// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A minimal protobuf wire-format reader, hand-rolled on purpose.
//!
//! # Why not `prost`
//!
//! `prost` generates its types with `protoc`, a C++ program that would have to be
//! present at build time. This crate must compile for
//! `wasm32-unknown-unknown` (SPEC 0: the browser extension imports files too), and
//! a build-time C toolchain dependency is exactly what SPEC 2.1 forbids the core
//! from acquiring. `prost-build`'s vendored `protoc` does not change the argument:
//! it adds a second build system to a crate whose whole job is parsing hostile
//! input.
//!
//! The message this needs to read — Google Authenticator's `MigrationPayload` — has
//! five fields, one of which is a repeated sub-message with seven. A decoder small
//! enough to read in one sitting, whose every rejection is a deliberate decision,
//! is the right trade for a parser that eats QR codes from strangers.
//!
//! # What it refuses
//!
//! * a varint that does not terminate within ten bytes, or whose tenth byte carries
//!   bits above 64
//! * a length-delimited field declaring more bytes than remain — the "4 GB declared
//!   length" case, rejected *before* any allocation
//! * field number 0, which the wire format does not permit
//! * wire types 3 and 4 (deprecated groups) and 6 and 7 (unassigned). A group
//!   cannot be skipped without a matching end tag, so refusing is honest where
//!   guessing would not be
//! * nesting past [`MAX_DEPTH`]
//!
//! Unknown *field numbers* are not refused: the caller simply ignores them, which
//! is what protobuf compatibility means. Reading a payload from a newer Google
//! Authenticator that added a field must keep working.

use crate::error::ProtobufError;

/// Deepest nesting this reader will follow. The migration payload is two levels;
/// anything deeper is not that message.
pub(crate) const MAX_DEPTH: u32 = 4;

/// One field's value, still undecoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    /// Wire type 0.
    Varint(u64),
    /// Wire type 5.
    Fixed32([u8; 4]),
    /// Wire type 1.
    Fixed64([u8; 8]),
    /// Wire type 2.
    Bytes(&'a [u8]),
}

impl<'a> Value<'a> {
    /// The value as a varint, or `None` if it was not one.
    pub(crate) fn varint(self) -> Option<u64> {
        match self {
            Self::Varint(value) => Some(value),
            _ => None,
        }
    }

    /// The value as a length-delimited byte string, or `None`.
    pub(crate) fn bytes(self) -> Option<&'a [u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// The value as a UTF-8 string.
    pub(crate) fn string(self, field: u32) -> core::result::Result<&'a str, ProtobufError> {
        let bytes = self.bytes().ok_or(ProtobufError::WrongType { field })?;
        core::str::from_utf8(bytes).map_err(|_| ProtobufError::NotUtf8 { field })
    }
}

/// A cursor over a protobuf message.
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: u32,
}

impl<'a> Reader<'a> {
    /// A reader over a whole message.
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            depth: 0,
        }
    }

    /// A reader over a nested message, one level deeper.
    ///
    /// The nested buffer's lifetime is independent of this reader's: in practice
    /// it is a sub-slice of the same message, but saying so is not this function's
    /// business.
    pub(crate) fn nested<'b>(
        &self,
        buf: &'b [u8],
    ) -> core::result::Result<Reader<'b>, ProtobufError> {
        let depth = self.depth + 1;
        if depth > MAX_DEPTH {
            return Err(ProtobufError::TooDeep { max: MAX_DEPTH });
        }
        Ok(Reader { buf, pos: 0, depth })
    }

    /// Whether every byte has been read.
    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Read the next field, or `None` at the end of the message.
    pub(crate) fn next_field(
        &mut self,
    ) -> Option<core::result::Result<(u32, Value<'a>), ProtobufError>> {
        if self.is_empty() {
            return None;
        }
        Some(self.read_field())
    }

    fn read_field(&mut self) -> core::result::Result<(u32, Value<'a>), ProtobufError> {
        let tag_at = self.pos;
        let tag = self.read_varint()?;
        let field = u32::try_from(tag >> 3)
            .map_err(|_| ProtobufError::VarintOverflow { offset: tag_at })?;
        if field == 0 {
            return Err(ProtobufError::ZeroField { offset: tag_at });
        }
        // `tag & 7` is 0..=7, so the cast cannot lose information.
        let wire = (tag & 7) as u8;
        let value = match wire {
            0 => Value::Varint(self.read_varint()?),
            1 => Value::Fixed64(self.read_array::<8>()?),
            2 => {
                let len = self.read_varint()?;
                Value::Bytes(self.read_bytes(field, len)?)
            }
            5 => Value::Fixed32(self.read_array::<4>()?),
            other => return Err(ProtobufError::UnsupportedWireType { wire: other, field }),
        };
        Ok((field, value))
    }

    fn read_byte(&mut self) -> core::result::Result<u8, ProtobufError> {
        let byte = *self
            .buf
            .get(self.pos)
            .ok_or(ProtobufError::Truncated { offset: self.pos })?;
        self.pos += 1;
        Ok(byte)
    }

    /// Base-128 varint, little-endian groups of seven bits.
    ///
    /// Ten bytes is the maximum a 64-bit value can occupy; the tenth may carry
    /// only one significant bit. Both limits are enforced with checked shifts
    /// rather than by trusting the input's length.
    fn read_varint(&mut self) -> core::result::Result<u64, ProtobufError> {
        let start = self.pos;
        let mut value: u64 = 0;
        for group in 0..10u32 {
            let byte = self.read_byte()?;
            let bits = u64::from(byte & 0x7f);
            let shifted = bits
                .checked_shl(group * 7)
                .filter(|shifted| shifted >> (group * 7) == bits)
                .ok_or(ProtobufError::VarintOverflow { offset: start })?;
            value |= shifted;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ProtobufError::VarintOverflow { offset: start })
    }

    fn read_array<const N: usize>(&mut self) -> core::result::Result<[u8; N], ProtobufError> {
        let end = self
            .pos
            .checked_add(N)
            .ok_or(ProtobufError::Truncated { offset: self.pos })?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(ProtobufError::Truncated { offset: self.pos })?;
        let array: [u8; N] = slice
            .try_into()
            .map_err(|_| ProtobufError::Truncated { offset: self.pos })?;
        self.pos = end;
        Ok(array)
    }

    /// A length-delimited run. The declared length is checked against what is
    /// actually left **before** anything is taken, so a header claiming four
    /// gigabytes costs nothing.
    fn read_bytes(
        &mut self,
        field: u32,
        len: u64,
    ) -> core::result::Result<&'a [u8], ProtobufError> {
        let remaining = self.buf.len().saturating_sub(self.pos);
        let too_large = || ProtobufError::LengthTooLarge {
            field,
            len,
            remaining,
        };
        let len = usize::try_from(len).map_err(|_| too_large())?;
        if len > remaining {
            return Err(too_large());
        }
        let end = self.pos.checked_add(len).ok_or_else(too_large)?;
        let slice = self.buf.get(self.pos..end).ok_or_else(too_large)?;
        self.pos = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a varint, for building test messages.
    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = u8::try_from(value & 0x7f).expect("masked to 7 bits");
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn tag(field: u32, wire: u8) -> Vec<u8> {
        varint(u64::from(field) << 3 | u64::from(wire))
    }

    fn field_bytes(field: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = tag(field, 2);
        out.extend(varint(payload.len() as u64));
        out.extend(payload);
        out
    }

    #[test]
    fn reads_every_wire_type_this_decoder_supports() {
        let mut message = tag(1, 0);
        message.extend(varint(300));
        message.extend(field_bytes(2, b"hello"));
        message.extend(tag(3, 5));
        message.extend([1, 0, 0, 0]);
        message.extend(tag(4, 1));
        message.extend([2, 0, 0, 0, 0, 0, 0, 0]);

        let mut reader = Reader::new(&message);
        let mut seen = Vec::new();
        while let Some(field) = reader.next_field() {
            seen.push(field.expect("valid"));
        }
        assert_eq!(
            seen,
            vec![
                (1, Value::Varint(300)),
                (2, Value::Bytes(b"hello")),
                (3, Value::Fixed32([1, 0, 0, 0])),
                (4, Value::Fixed64([2, 0, 0, 0, 0, 0, 0, 0])),
            ]
        );
        assert!(reader.is_empty());
    }

    #[test]
    fn unknown_field_numbers_are_the_callers_business_not_an_error() {
        // Field 999 with a length-delimited payload: readable, and the caller
        // ignores it. This is what forward compatibility means.
        let message = field_bytes(999, b"future");
        let mut reader = Reader::new(&message);
        assert_eq!(
            reader.next_field().expect("a field").expect("valid"),
            (999, Value::Bytes(b"future"))
        );
    }

    #[test]
    fn a_varint_that_never_terminates_is_rejected() {
        let message = vec![0x80; 32];
        let mut reader = Reader::new(&message);
        assert_eq!(
            reader.next_field().expect("a field"),
            Err(ProtobufError::VarintOverflow { offset: 0 })
        );
    }

    #[test]
    fn a_varint_wider_than_64_bits_is_rejected() {
        // Ten continuation groups whose tenth byte carries more than one bit.
        let mut message = tag(1, 0);
        message.extend([0xff; 9]);
        message.push(0x7f);
        let mut reader = Reader::new(&message);
        assert!(matches!(
            reader.next_field().expect("a field"),
            Err(ProtobufError::VarintOverflow { .. })
        ));
    }

    #[test]
    fn the_largest_legal_varint_still_reads() {
        let mut message = tag(1, 0);
        message.extend(varint(u64::MAX));
        let mut reader = Reader::new(&message);
        assert_eq!(
            reader.next_field().expect("a field").expect("valid"),
            (1, Value::Varint(u64::MAX))
        );
    }

    #[test]
    fn a_four_gigabyte_declared_length_costs_nothing() {
        let mut message = tag(1, 2);
        message.extend(varint(4 * 1024 * 1024 * 1024));
        message.extend(b"only a few bytes here");
        let mut reader = Reader::new(&message);
        assert_eq!(
            reader.next_field().expect("a field"),
            Err(ProtobufError::LengthTooLarge {
                field: 1,
                len: 4 * 1024 * 1024 * 1024,
                remaining: 21,
            })
        );
    }

    #[test]
    fn truncation_is_reported_not_guessed() {
        // Length says 5, only 2 bytes follow.
        let mut message = tag(1, 2);
        message.extend(varint(5));
        message.extend(b"ab");
        let mut reader = Reader::new(&message);
        assert!(matches!(
            reader.next_field().expect("a field"),
            Err(ProtobufError::LengthTooLarge { .. })
        ));

        // A fixed64 with four bytes left.
        let mut short = tag(2, 1);
        short.extend([1, 2, 3, 4]);
        let mut reader = Reader::new(&short);
        assert!(matches!(
            reader.next_field().expect("a field"),
            Err(ProtobufError::Truncated { .. })
        ));

        // A tag with nothing after it.
        let mut bare = tag(3, 0);
        bare.truncate(1);
        let mut reader = Reader::new(&bare);
        assert!(matches!(
            reader.next_field().expect("a field"),
            Err(ProtobufError::Truncated { .. })
        ));
    }

    #[test]
    fn groups_and_unassigned_wire_types_are_refused() {
        for wire in [3u8, 4, 6, 7] {
            let message = tag(1, wire);
            let mut reader = Reader::new(&message);
            assert_eq!(
                reader.next_field().expect("a field"),
                Err(ProtobufError::UnsupportedWireType { wire, field: 1 })
            );
        }
    }

    #[test]
    fn field_number_zero_is_refused() {
        let message = vec![0x00, 0x01];
        let mut reader = Reader::new(&message);
        assert_eq!(
            reader.next_field().expect("a field"),
            Err(ProtobufError::ZeroField { offset: 0 })
        );
    }

    #[test]
    fn nesting_is_bounded() {
        let reader = Reader::new(b"");
        let mut current = reader.clone();
        for _ in 0..MAX_DEPTH {
            current = current.nested(b"").expect("within the limit");
        }
        assert_eq!(
            current.nested(b"").err(),
            Some(ProtobufError::TooDeep { max: MAX_DEPTH })
        );
    }

    #[test]
    fn an_empty_message_yields_no_fields() {
        let mut reader = Reader::new(b"");
        assert!(reader.next_field().is_none());
        assert!(reader.is_empty());
    }

    #[test]
    fn a_string_field_must_be_utf8() {
        let message = field_bytes(2, &[0xff, 0xfe]);
        let mut reader = Reader::new(&message);
        let (field, value) = reader.next_field().expect("a field").expect("valid");
        assert_eq!(
            value.string(field).err(),
            Some(ProtobufError::NotUtf8 { field: 2 })
        );
    }
}
