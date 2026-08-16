//! A minimal RFC 4180 reader.
//!
//! Not the `csv` crate: this crate is deliberately small and dependency-light,
//! and `deny.toml` gates every addition to the supply chain. What a password
//! export needs is quoted fields, embedded commas, and one escaped-quote rule
//! — a few dozen lines, not a general-purpose parser pulled in for them.
//!
//! `parse_rows` never fails. A malformed quote just runs the field past where
//! a person would expect it to end, the same way it would in a spreadsheet
//! that opened the same file — there is no wrong input to reject here, only
//! rows that come out shaped strangely, and it is the caller's job to notice
//! a row that does not have the columns it needs.

use std::collections::HashMap;

/// Splits `text` into rows of fields.
///
/// Handles quoted fields containing commas, `""` as an escaped quote inside a
/// quoted field, a literal newline inside a quoted field, CRLF and LF line
/// endings in the same file, a trailing empty field, and a trailing newline or
/// its absence. Getting any of these wrong does not fail loudly — it shifts
/// every column after the mistake by one, and quietly imports somebody's note
/// as their password.
pub(crate) fn parse_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    // Whether `field`/`row` hold something not yet flushed — the signal for
    // whether the very last line, with no newline after it, is a row too.
    let mut pending = false;

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }

        match c {
            '"' => {
                in_quotes = true;
                pending = true;
            }
            ',' => {
                row.push(std::mem::take(&mut field));
                pending = true;
            }
            '\r' => {
                // CRLF is one line ending, not two.
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                pending = false;
            }
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                pending = false;
            }
            other => {
                field.push(other);
                pending = true;
            }
        }
    }

    if pending {
        row.push(field);
        rows.push(row);
    }

    rows
}

/// Maps a header row's column names to their position, lowercased and
/// trimmed so a header written `Login_Password` or ` password ` still
/// matches — real exports are not consistent about either.
pub(crate) fn header_index(header: &[String]) -> HashMap<String, usize> {
    header
        .iter()
        .enumerate()
        .map(|(index, name)| (name.trim().to_ascii_lowercase(), index))
        .collect()
}

/// Whether every column in `required` appears somewhere in the header.
///
/// Membership, not position or count: exporters reorder columns between
/// versions, and matching by index would silently misread a file the moment
/// one did.
pub(crate) fn has_columns(index: &HashMap<String, usize>, required: &[&str]) -> bool {
    required.iter().all(|column| index.contains_key(*column))
}

/// A row's value for `column`, by name. `None` only when the row is too short
/// to have reached that column at all — a present-but-blank cell is `Some("")`,
/// which callers are expected to tell apart from a missing one.
pub(crate) fn field<'a>(
    index: &HashMap<String, usize>,
    row: &'a [String],
    column: &str,
) -> Option<&'a str> {
    index
        .get(column)
        .and_then(|&position| row.get(position))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(text: &str) -> Vec<Vec<String>> {
        parse_rows(text)
    }

    #[test]
    fn a_quoted_field_may_contain_a_comma() {
        assert_eq!(rows("\"a,b\",c"), vec![vec!["a,b", "c"]]);
    }

    #[test]
    fn a_doubled_quote_is_one_literal_quote() {
        assert_eq!(rows("\"say \"\"hi\"\"\",c"), vec![vec!["say \"hi\"", "c"]]);
    }

    #[test]
    fn a_newline_inside_quotes_stays_in_the_field_rather_than_ending_the_row() {
        assert_eq!(rows("\"line1\nline2\",c"), vec![vec!["line1\nline2", "c"]]);
    }

    #[test]
    fn crlf_and_lf_line_endings_are_both_understood_in_the_same_file() {
        assert_eq!(rows("a,b\r\nc,d\n"), vec![vec!["a", "b"], vec!["c", "d"]]);
    }

    #[test]
    fn a_trailing_empty_field_is_kept_not_dropped() {
        assert_eq!(rows("a,b,\n"), vec![vec!["a", "b", ""]]);
    }

    #[test]
    fn a_trailing_newline_does_not_produce_a_phantom_empty_row() {
        assert_eq!(rows("a,b\n"), vec![vec!["a", "b"]]);
    }

    #[test]
    fn the_last_row_is_read_even_with_no_trailing_newline_at_all() {
        assert_eq!(rows("a,b"), vec![vec!["a", "b"]]);
    }

    #[test]
    fn an_empty_file_has_no_rows() {
        assert_eq!(rows(""), Vec::<Vec<String>>::new());
    }

    #[test]
    fn header_lookup_ignores_case_and_surrounding_space() {
        let header = vec![" Login_Password ".to_string(), "Name".to_string()];
        let index = header_index(&header);
        assert_eq!(index.get("login_password"), Some(&0));
        assert_eq!(index.get("name"), Some(&1));
    }

    #[test]
    fn has_columns_is_membership_not_order() {
        let header = vec!["password".to_string(), "name".to_string()];
        let index = header_index(&header);
        assert!(has_columns(&index, &["name", "password"]));
        assert!(!has_columns(&index, &["name", "url"]));
    }

    #[test]
    fn field_is_none_only_when_the_row_is_too_short_to_reach_the_column() {
        let header = vec!["name".to_string(), "password".to_string()];
        let index = header_index(&header);
        let short_row = vec!["only-name".to_string()];
        assert_eq!(field(&index, &short_row, "name"), Some("only-name"));
        assert_eq!(field(&index, &short_row, "password"), None);

        let blank_row = vec!["a".to_string(), String::new()];
        assert_eq!(field(&index, &blank_row, "password"), Some(""));
    }
}
