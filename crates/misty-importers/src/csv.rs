// SPDX-FileCopyrightText: 2026 The Misty Authors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A small RFC 4180 reader, hand-rolled so the limits are ours.
//!
//! The `csv` crate is good and well fuzzed, and this is deliberately not it. The
//! guarantee this crate has to make is that a hostile file cannot make it allocate
//! — a row with 100 000 columns, a field with ten megabytes of quoted garbage, an
//! unterminated quote that swallows the rest of the file. Enforcing those bounds
//! *inside* the scanner means the allocation never happens; enforcing them after a
//! general-purpose reader has already produced the row means it already did.
//!
//! What it accepts: `,` or any other single-byte ASCII delimiter, `CRLF` and `LF`,
//! quoted fields containing delimiters and newlines, `""` as an escaped quote,
//! blank lines (skipped), and a missing final newline.
//!
//! What it refuses, per row, without ending the batch: more than
//! [`Limits::max_csv_columns`] fields, a field longer than
//! [`Limits::max_note_bytes`], and a quote that is never closed.

use crate::context::Limits;
use crate::error::RowError;

/// One row of a CSV file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    /// One-based line number where the row started.
    pub(crate) line: usize,
    /// The fields, or why the row could not be read.
    pub(crate) fields: core::result::Result<Vec<String>, RowError>,
}

/// Split a CSV document into rows.
///
/// Stops after `max_rows` rows; the caller reports that as
/// [`ImportError::TooManyRows`](crate::ImportError) if it wants to.
pub(crate) fn rows(text: &str, delimiter: u8, limits: &Limits) -> Vec<Row> {
    let delimiter = char::from(delimiter);
    let mut out: Vec<Row> = Vec::new();
    let mut chars = text.chars().peekable();

    let mut line = 1usize;
    let mut row_line = 1usize;
    let mut fields: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut at_field_start = true;
    let mut overflow: Option<RowError> = None;

    // `push_field` is a macro rather than a closure because a closure capturing all
    // of this state mutably could not then be called from the row-ending branch.
    // It deliberately does not touch `at_field_start`: the call after the loop has
    // no next field, and a dead store there is a warning worth not having.
    macro_rules! push_field {
        () => {{
            if fields.len() >= limits.max_csv_columns {
                overflow = overflow.take().or(Some(RowError::FieldTooLong {
                    field: "row",
                    len: fields.len() + 1,
                    max: limits.max_csv_columns,
                }));
                // Keep scanning to find the end of the row, but stop storing.
                field.clear();
            } else {
                fields.push(core::mem::take(&mut field));
            }
        }};
    }

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    push_char(&mut field, '"', limits, &mut overflow);
                } else {
                    in_quotes = false;
                }
            } else {
                if ch == '\n' {
                    line += 1;
                }
                push_char(&mut field, ch, limits, &mut overflow);
            }
            continue;
        }

        if ch == delimiter {
            push_field!();
            at_field_start = true;
            continue;
        }
        match ch {
            '"' if at_field_start => {
                in_quotes = true;
                at_field_start = false;
            }
            '\r' | '\n' => {
                if ch == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                line += 1;
                push_field!();
                at_field_start = true;
                let blank = fields.len() == 1 && fields.first().is_some_and(String::is_empty);
                if !blank || overflow.is_some() {
                    out.push(finish(
                        row_line,
                        core::mem::take(&mut fields),
                        overflow.take(),
                    ));
                } else {
                    fields.clear();
                }
                row_line = line;
                if out.len() >= limits.max_rows {
                    return out;
                }
            }
            _ => {
                at_field_start = false;
                push_char(&mut field, ch, limits, &mut overflow);
            }
        }
    }

    if in_quotes {
        // An unterminated quote means everything after it was swallowed. Report
        // the row rather than pretending the truncated text was the data.
        out.push(Row {
            line: row_line,
            fields: Err(RowError::InvalidField("unterminated quote")),
        });
        return out;
    }

    if !field.is_empty() || !fields.is_empty() || overflow.is_some() {
        push_field!();
        let blank = fields.len() == 1 && fields.first().is_some_and(String::is_empty);
        if !blank || overflow.is_some() {
            out.push(finish(row_line, fields, overflow));
        }
    }
    out
}

/// Append one character, or record that the field is over its limit.
fn push_char(field: &mut String, ch: char, limits: &Limits, overflow: &mut Option<RowError>) {
    if field.len() + ch.len_utf8() > limits.max_note_bytes {
        if overflow.is_none() {
            *overflow = Some(RowError::FieldTooLong {
                field: "field",
                len: field.len() + ch.len_utf8(),
                max: limits.max_note_bytes,
            });
        }
        return;
    }
    field.push(ch);
}

fn finish(line: usize, fields: Vec<String>, overflow: Option<RowError>) -> Row {
    Row {
        line,
        fields: match overflow {
            Some(error) => Err(error),
            None => Ok(fields),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_rows(text: &str) -> Vec<Vec<String>> {
        rows(text, b',', &Limits::default())
            .into_iter()
            .map(|row| row.fields.expect("row parses"))
            .collect()
    }

    #[test]
    fn reads_the_shapes_real_files_have() {
        let text = "a,b,c\r\n1,\"two, still two\",3\n\n4,\"line\nbreak\",6\n7,,";
        assert_eq!(
            ok_rows(text),
            vec![
                vec!["a", "b", "c"],
                vec!["1", "two, still two", "3"],
                vec!["4", "line\nbreak", "6"],
                vec!["7", "", ""],
            ]
        );
    }

    #[test]
    fn escaped_quotes_and_quotes_inside_unquoted_fields() {
        assert_eq!(
            ok_rows("\"say \"\"hi\"\"\",b\n5\" tall,x"),
            vec![vec!["say \"hi\"", "b"], vec!["5\" tall", "x"]]
        );
    }

    #[test]
    fn line_numbers_survive_quoted_newlines() {
        let parsed = rows("a\n\"b\nc\"\nd\n", b',', &Limits::default());
        assert_eq!(
            parsed.iter().map(|row| row.line).collect::<Vec<_>>(),
            vec![1, 2, 4]
        );
    }

    #[test]
    fn a_hundred_thousand_columns_fails_one_row_and_no_more() {
        let wide = "x,".repeat(100_000);
        let text = format!("{wide}\na,b\n");
        let parsed = rows(&text, b',', &Limits::default());
        assert_eq!(parsed.len(), 2);
        assert!(matches!(
            parsed.first().map(|row| &row.fields),
            Some(Err(RowError::FieldTooLong { field: "row", .. }))
        ));
        assert_eq!(
            parsed.get(1).and_then(|row| row.fields.as_ref().ok()),
            Some(&vec!["a".to_owned(), "b".to_owned()])
        );
    }

    #[test]
    fn an_enormous_field_fails_its_row_without_being_stored() {
        let limits = Limits {
            max_note_bytes: 32,
            ..Limits::default()
        };
        let text = format!("{}\nb\n", "a".repeat(10_000));
        let parsed = rows(&text, b',', &limits);
        assert!(matches!(
            parsed.first().map(|row| &row.fields),
            Some(Err(RowError::FieldTooLong { field: "field", .. }))
        ));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn an_unterminated_quote_is_a_row_error_not_silent_truncation() {
        let parsed = rows("a,\"unclosed\nb,c", b',', &Limits::default());
        assert_eq!(
            parsed.last().map(|row| row.fields.clone()),
            Some(Err(RowError::InvalidField("unterminated quote")))
        );
    }

    #[test]
    fn the_row_limit_stops_reading() {
        let limits = Limits {
            max_rows: 3,
            ..Limits::default()
        };
        let text = "a\nb\nc\nd\ne\n";
        assert_eq!(rows(text, b',', &limits).len(), 3);
    }

    #[test]
    fn other_delimiters_work() {
        assert_eq!(
            rows("a\tb\n", b'\t', &Limits::default())
                .into_iter()
                .map(|row| row.fields.expect("parses"))
                .collect::<Vec<_>>(),
            vec![vec!["a", "b"]]
        );
        assert_eq!(
            rows("a;b\n", b';', &Limits::default())
                .into_iter()
                .map(|row| row.fields.expect("parses"))
                .collect::<Vec<_>>(),
            vec![vec!["a", "b"]]
        );
    }

    #[test]
    fn an_empty_document_has_no_rows() {
        assert!(rows("", b',', &Limits::default()).is_empty());
        assert!(rows("\n\n\n", b',', &Limits::default()).is_empty());
    }
}
