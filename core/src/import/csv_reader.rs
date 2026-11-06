//! A small RFC 4180 CSV reader.
//!
//! Hand-written on purpose: the repo does not pull a CSV framework for six
//! importers, and a reader that only accepts the standard form (quoted fields,
//! doubled quotes, CRLF or LF, no stray characters after a closing quote) is
//! easier to audit than a general one. Limits are hard: 256 columns, 1 MiB per
//! field, 200k rows.

use crate::error::{CoreError, CoreResult};

/// Most columns a row may have.
pub const MAX_COLUMNS: usize = 256;
/// Most bytes one field may hold.
pub const MAX_FIELD_BYTES: usize = 1024 * 1024;
/// Most rows a file may hold.
pub const MAX_ROWS: usize = 200_000;

/// Parses RFC 4180 CSV into rows of fields, stripping a UTF-8 BOM.
pub fn parse(text: &str) -> CoreResult<Vec<Vec<String>>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut just_closed_quote = false;
    let mut characters = text.chars().peekable();

    while let Some(character) = characters.next() {
        if in_quotes {
            match character {
                '"' => {
                    if characters.peek() == Some(&'"') {
                        characters.next();
                        field.push('"');
                    } else {
                        in_quotes = false;
                        just_closed_quote = true;
                    }
                }
                _ => field.push(character),
            }
            if field.len() > MAX_FIELD_BYTES {
                return Err(CoreError::TooManyEntries);
            }
            continue;
        }

        match character {
            '"' if field.is_empty() => {
                in_quotes = true;
                just_closed_quote = false;
            }
            ',' => {
                push_field(&mut row, &mut field)?;
                just_closed_quote = false;
            }
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                end_row(&mut rows, &mut row, &mut field)?;
                just_closed_quote = false;
            }
            '\n' => {
                end_row(&mut rows, &mut row, &mut field)?;
                just_closed_quote = false;
            }
            _other if just_closed_quote => {
                // RFC 4180 has no syntax for text after a closing quote.
                return Err(CoreError::InvalidImport);
            }
            other => {
                field.push(other);
                if field.len() > MAX_FIELD_BYTES {
                    return Err(CoreError::TooManyEntries);
                }
            }
        }
    }

    if in_quotes {
        return Err(CoreError::InvalidImport);
    }
    if !field.is_empty() || !row.is_empty() {
        push_field(&mut row, &mut field)?;
        if row.iter().any(|value| !value.is_empty()) {
            if rows.len() >= MAX_ROWS {
                return Err(CoreError::TooManyEntries);
            }
            rows.push(row);
        }
    }
    Ok(rows)
}

fn push_field(row: &mut Vec<String>, field: &mut String) -> CoreResult<()> {
    if row.len() >= MAX_COLUMNS {
        return Err(CoreError::TooManyEntries);
    }
    row.push(std::mem::take(field));
    Ok(())
}

fn end_row(
    rows: &mut Vec<Vec<String>>,
    row: &mut Vec<String>,
    field: &mut String,
) -> CoreResult<()> {
    push_field(row, field)?;
    if row.iter().all(|value| value.is_empty()) {
        row.clear();
        return Ok(());
    }
    if rows.len() >= MAX_ROWS {
        return Err(CoreError::TooManyEntries);
    }
    rows.push(std::mem::take(row));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_table() {
        let rows = parse("a,b\n1,2\n").expect("parse");
        assert_eq!(rows, vec![vec!["a", "b"], vec!["1", "2"]]);
    }

    #[test]
    fn handles_quotes_embedded_newlines_and_crlf() {
        let rows = parse("name,notes\r\n\"Demo, Inc.\",\"line one\nline two\"\r\n").expect("parse");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1][0], "Demo, Inc.");
        assert_eq!(rows[1][1], "line one\nline two");
    }

    #[test]
    fn handles_doubled_quotes_and_bom() {
        let rows = parse("\u{feff}a\n\"say \"\"hi\"\"\"\n").expect("parse");
        assert_eq!(rows[0], vec!["a"]);
        assert_eq!(rows[1], vec!["say \"hi\""]);
    }

    #[test]
    fn rejects_a_stray_character_after_a_closing_quote() {
        assert_eq!(
            parse("\"a\"b,c\n").expect_err("stray"),
            CoreError::InvalidImport
        );
    }

    #[test]
    fn rejects_an_unterminated_quote() {
        assert_eq!(
            parse("\"a,b\n").expect_err("unterminated"),
            CoreError::InvalidImport
        );
    }

    #[test]
    fn skips_blank_lines_and_keeps_empty_cells() {
        let rows = parse("a,,c\n\n\n1,2,3\n").expect("parse");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec!["a", "", "c"]);
    }

    #[test]
    fn a_trailing_newline_does_not_create_a_row() {
        assert_eq!(parse("a,b\n").expect("parse").len(), 1);
        assert_eq!(parse("a,b").expect("parse").len(), 1);
    }
}
