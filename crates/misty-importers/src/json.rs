// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A thin, deliberately hand-written accessor layer over [`serde_json::Value`].
//!
//! Nine of the fourteen importers read JSON, and none of them uses `#[derive(
//! Deserialize)]`. Two reasons, both about safety rather than taste:
//!
//! 1. **Per-row isolation.** A derived `Vec<Entry>` aborts the whole batch on the
//!    first malformed element. Reading a [`serde_json::Value`] and interpreting one
//!    row at a time is what lets row 7 fail while rows 1–6 and 8–200 import.
//! 2. **No value ever reaches an error message.** `serde_json` renders the
//!    offending value into its own errors — `invalid type: string "JBSWY…"` — and
//!    that value is routinely the secret. Every accessor here fails with a field
//!    *name* instead.
//!
//! Vendors are also sloppy in ways a derive cannot absorb: Raivo writes every
//! number as a string, 2FAS writes booleans as booleans and andOTP writes them as
//! `0`/`1`. Coercion lives here, once.

use serde_json::Value;

use crate::context::Limits;
use crate::error::{ImportError, Result, RowError};
use crate::model::SourceFormat;
use crate::text;

/// Parse a whole document.
///
/// `serde_json`'s own 128-level recursion limit is what stops deeply nested input
/// from exhausting the stack; it reports an error rather than overflowing, which is
/// why this crate does not need its own depth counter here.
pub(crate) fn parse(input: &[u8], limits: &Limits) -> Result<Value> {
    let text = text::decode(input, limits)?;
    serde_json::from_str(text).map_err(|error| ImportError::Json {
        line: error.line(),
        column: error.column(),
    })
}

/// Follow a dot-separated path from a value.
pub(crate) fn path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut at = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }
        at = match at {
            Value::Object(map) => map.get(segment)?,
            // A numeric segment indexes an array, so `vaults.0.items` works.
            Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(at)
}

/// Render a scalar as text. Objects and arrays have no text form; `null` is
/// absence, not the string "null".
pub(crate) fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// Coerce a scalar to `u64`, accepting a number, a numeric string, or a float
/// with no fractional part (a spreadsheet habit: `6.0`).
pub(crate) fn scalar_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64().or_else(|| {
            number
                .as_f64()
                .filter(|float| float.is_finite() && *float >= 0.0 && float.fract() == 0.0)
                .and_then(|float| {
                    // `as` on a float is a saturating cast in Rust, so bound it
                    // first rather than relying on that.
                    (float <= 9_007_199_254_740_992.0).then_some(float as u64)
                })
        }),
        Value::String(text) => {
            let text = text.trim();
            text.parse::<u64>().ok().or_else(|| {
                text.parse::<f64>().ok().and_then(|float| {
                    (float.is_finite() && float >= 0.0 && float.fract() == 0.0)
                        .then_some(float as u64)
                })
            })
        }
        _ => None,
    }
}

/// Coerce a scalar to `bool`, accepting `true`, `"true"`, `1` and `"1"`.
pub(crate) fn scalar_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::Number(number) => number.as_u64().map(|number| number != 0),
        Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Some(true),
            "false" | "no" | "0" | "" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// One record from a JSON export.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Rec<'a> {
    value: &'a Value,
    format: SourceFormat,
}

impl<'a> Rec<'a> {
    /// Wrap a value that must be a JSON object.
    pub(crate) fn object(
        value: &'a Value,
        format: SourceFormat,
    ) -> core::result::Result<Self, RowError> {
        if value.is_object() {
            Ok(Self { value, format })
        } else {
            Err(RowError::WrongShape(format))
        }
    }

    /// Wrap a value without requiring a shape, for nested lookups.
    pub(crate) fn raw(value: &'a Value, format: SourceFormat) -> Self {
        Self { value, format }
    }

    pub(crate) fn value(&self) -> &'a Value {
        self.value
    }

    /// A sub-record at a dot-separated path.
    pub(crate) fn at(&self, key: &str) -> Option<Self> {
        path(self.value, key).map(|value| Self {
            value,
            format: self.format,
        })
    }

    /// A string field, trimmed, `None` if absent or empty.
    pub(crate) fn str(&self, key: &str) -> Option<&'a str> {
        path(self.value, key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
    }

    /// Any scalar field as owned text, trimmed, `None` if absent or empty.
    pub(crate) fn text(&self, key: &str) -> Option<String> {
        path(self.value, key)
            .and_then(scalar_text)
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    }

    /// A required string field.
    pub(crate) fn require_str(&self, key: &'static str) -> core::result::Result<&'a str, RowError> {
        self.str(key).ok_or(RowError::MissingField(key))
    }

    /// An unsigned field. Absent is `Ok(None)`; present but not a number is an
    /// error naming the field, never showing it.
    pub(crate) fn u64(&self, key: &'static str) -> core::result::Result<Option<u64>, RowError> {
        match path(self.value, key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) if text.trim().is_empty() => Ok(None),
            Some(value) => scalar_u64(value)
                .map(Some)
                .ok_or(RowError::InvalidField(key)),
        }
    }

    /// A `u8` field, range-checked.
    pub(crate) fn u8(&self, key: &'static str) -> core::result::Result<Option<u8>, RowError> {
        match self.u64(key)? {
            Some(value) => u8::try_from(value)
                .map(Some)
                .map_err(|_| RowError::InvalidField(key)),
            None => Ok(None),
        }
    }

    /// A `u16` field, range-checked.
    pub(crate) fn u16(&self, key: &'static str) -> core::result::Result<Option<u16>, RowError> {
        match self.u64(key)? {
            Some(value) => u16::try_from(value)
                .map(Some)
                .map_err(|_| RowError::InvalidField(key)),
            None => Ok(None),
        }
    }

    /// A signed timestamp field. Milliseconds are the caller's business.
    pub(crate) fn i64(&self, key: &str) -> Option<i64> {
        match path(self.value, key)? {
            Value::Number(number) => number.as_i64(),
            Value::String(text) => text.trim().parse::<i64>().ok(),
            _ => None,
        }
    }

    /// A boolean field, tolerating the several spellings vendors use.
    pub(crate) fn bool(&self, key: &str) -> Option<bool> {
        path(self.value, key).and_then(scalar_bool)
    }

    /// An array field.
    pub(crate) fn array(&self, key: &str) -> Option<&'a Vec<Value>> {
        path(self.value, key).and_then(Value::as_array)
    }

    /// A list of strings, accepting either an array or one delimited string.
    pub(crate) fn strings(&self, key: &str, limits: &Limits) -> Vec<String> {
        match path(self.value, key) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(scalar_text)
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty())
                .take(limits.max_tags)
                .collect(),
            Some(Value::String(text)) => text::split_list(text, ',', limits.max_tags),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> Value {
        serde_json::from_str(text).expect("test json")
    }

    #[test]
    fn paths_walk_objects_and_arrays() {
        let doc = value(r#"{"a":{"b":[{"c":1}]}}"#);
        assert_eq!(path(&doc, "a.b.0.c").and_then(Value::as_u64), Some(1));
        assert!(path(&doc, "a.b.1.c").is_none());
        assert!(path(&doc, "a.z").is_none());
        assert!(path(&doc, "").is_some());
    }

    #[test]
    fn numbers_may_arrive_as_strings_or_whole_floats() {
        let rec = value(r#"{"a":6,"b":"6","c":6.0,"d":" 30 ","e":"","f":null,"g":"six","h":-1}"#);
        let rec = Rec::object(&rec, SourceFormat::Json).unwrap();
        assert_eq!(rec.u64("a").unwrap(), Some(6));
        assert_eq!(rec.u64("b").unwrap(), Some(6));
        assert_eq!(rec.u64("c").unwrap(), Some(6));
        assert_eq!(rec.u64("d").unwrap(), Some(30));
        assert_eq!(rec.u64("e").unwrap(), None);
        assert_eq!(rec.u64("f").unwrap(), None);
        assert_eq!(rec.u64("g"), Err(RowError::InvalidField("g")));
        assert_eq!(rec.u64("h"), Err(RowError::InvalidField("h")));
    }

    #[test]
    fn an_error_names_the_field_and_never_the_value() {
        let doc = value(r#"{"secret":{"nested":"JBSWY3DPEHPK3PXP"}}"#);
        let rec = Rec::object(&doc, SourceFormat::Json).unwrap();
        let error = rec.u64("secret").expect_err("an object is not a number");
        let rendered = error.to_string();
        assert!(rendered.contains("secret"), "{rendered}");
        assert!(!rendered.contains("JBSWY3DPEHPK3PXP"), "{rendered}");
    }

    #[test]
    fn booleans_come_in_three_spellings() {
        let doc = value(r#"{"a":true,"b":"false","c":1,"d":"yes","e":"maybe"}"#);
        let rec = Rec::object(&doc, SourceFormat::Json).unwrap();
        assert_eq!(rec.bool("a"), Some(true));
        assert_eq!(rec.bool("b"), Some(false));
        assert_eq!(rec.bool("c"), Some(true));
        assert_eq!(rec.bool("d"), Some(true));
        assert_eq!(rec.bool("e"), None);
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_stack_overflow() {
        let deep = format!("{}1{}", "[".repeat(2000), "]".repeat(2000));
        let error = parse(deep.as_bytes(), &Limits::default())
            .expect_err("serde_json enforces a recursion limit");
        assert!(matches!(error, ImportError::Json { .. }));
    }

    #[test]
    fn a_row_that_is_not_an_object_is_reported_as_a_shape_problem() {
        let doc = value("[1,2,3]");
        assert_eq!(
            Rec::object(&doc, SourceFormat::Aegis).err(),
            Some(RowError::WrongShape(SourceFormat::Aegis))
        );
    }
}
