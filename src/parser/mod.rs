use super::*;

mod comments;

use comments::comment_passthrough_end;
pub(crate) use comments::{
    extract_rust_comments, strip_rust_comments_after_string_mask, RustComment,
};

pub(crate) fn static_regex(lock: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    lock.get_or_init(|| Regex::new(pattern).expect("static regex compiles"))
}

pub(crate) fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(index + 1);
        }
    }
    starts
}

pub(crate) fn byte_line_from_starts(line_starts: &[usize], byte_index: usize) -> usize {
    line_starts.partition_point(|line_start| *line_start <= byte_index)
}

pub(crate) fn strip_rust_string_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if let Some(raw_end) = raw_string_end(bytes, index) {
            mask_bytes(bytes, index, raw_end, &mut output);
            index = raw_end;
            continue;
        }

        if let Some(comment_end) = comment_passthrough_end(bytes, index) {
            output.push_str(&source[index..comment_end]);
            index = comment_end;
            continue;
        }

        if let Some(char_end) = char_literal_end(bytes, index) {
            mask_bytes(bytes, index, char_end, &mut output);
            index = char_end;
            continue;
        }

        if bytes[index] == b'"' {
            index = mask_double_quoted_string(bytes, index, &mut output);
            continue;
        }

        index = push_original_char(source, index, &mut output);
    }

    output
}

pub(crate) fn push_original_char(source: &str, index: usize, output: &mut String) -> usize {
    let character = source[index..]
        .chars()
        .next()
        .expect("index is on a UTF-8 boundary");
    output.push(character);
    index + character.len_utf8()
}

pub(crate) fn rust_code_reference_source(source: &str) -> String {
    let masked_source = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    let mut reference_source = String::with_capacity(masked_source.len() + 64);
    reference_source.push_str(&masked_source);
    append_serde_default_references(source, &mut reference_source);
    reference_source
}

fn append_serde_default_references(source: &str, output: &mut String) {
    static SERDE_ATTRIBUTE_REGEX: OnceLock<Regex> = OnceLock::new();
    static DEFAULT_REFERENCE_REGEX: OnceLock<Regex> = OnceLock::new();
    let serde_attribute = static_regex(
        &SERDE_ATTRIBUTE_REGEX,
        r#"(?s)#\s*\[\s*serde\s*\((.*?)\)\s*\]"#,
    );
    let default_reference = static_regex(
        &DEFAULT_REFERENCE_REGEX,
        r#"\bdefault\s*=\s*"([A-Za-z_][A-Za-z0-9_:]*)""#,
    );

    for attribute in serde_attribute.captures_iter(source) {
        let Some(body) = attribute.get(1) else {
            continue;
        };
        for reference in default_reference.captures_iter(body.as_str()) {
            let Some(path) = reference.get(1) else {
                continue;
            };
            output.push(' ');
            output.push_str(path.as_str());
        }
    }
}

/// Masks a `"..."` Rust string literal starting at the opening quote at
/// `start`. Handles backslash escapes so `\"` does not terminate the
/// string. Returns the byte index just past the closing quote (or
/// `bytes.len()` if the source is malformed and the quote is unclosed).
fn mask_double_quoted_string(bytes: &[u8], start: usize, output: &mut String) -> usize {
    output.push(' ');
    let mut index = start + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        mask_byte(byte, output);
        index += 1;
        if byte == b'\\' && index < bytes.len() {
            mask_byte(bytes[index], output);
            index += 1;
            continue;
        }
        if byte == b'"' {
            break;
        }
    }
    index
}

/// Returns the byte index just past a Rust character literal that starts at
/// `start`. Recognises `'X'`, escape sequences (`'\n'`, `'\''`), byte escapes
/// (`'\x41'`), and unicode escapes (`'\u{0041}'`). Returns `None` for
/// lifetimes (`'a`, `'static`) and any other shape, so the masker leaves
/// them alone.
pub(crate) fn char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start).copied()? != b'\'' {
        return None;
    }
    let cursor = char_literal_body_end(bytes, start + 1, start)?;
    (bytes.get(cursor).copied()? == b'\'').then_some(cursor + 1)
}

/// Advances past the character payload between the opening and closing
/// quotes of a char literal. Handles escape sequences (`\n`, `\x41`,
/// `\u{0041}`, etc.) plus plain single-byte chars. `start` is the literal's
/// opening-quote index, kept around for unicode-escape sanity bounds.
fn char_literal_body_end(bytes: &[u8], cursor: usize, start: usize) -> Option<usize> {
    if bytes.get(cursor).copied()? != b'\\' {
        return Some(cursor + 1);
    }
    let escape = bytes.get(cursor + 1).copied()?;
    let after_escape = cursor + 2;
    match escape {
        b'x' => after_escape.checked_add(2),
        b'u' => unicode_escape_end(bytes, after_escape, start),
        _ => Some(after_escape),
    }
}

/// Advances past a `\u{XXXX}` unicode escape. `cursor` is the byte after
/// the `\u`; on success, returns the byte after the closing brace.
fn unicode_escape_end(bytes: &[u8], cursor: usize, start: usize) -> Option<usize> {
    if bytes.get(cursor).copied()? != b'{' {
        return None;
    }
    let mut walk = cursor + 1;
    while bytes.get(walk).copied()? != b'}' {
        walk += 1;
        if walk.saturating_sub(start) > 12 {
            return None;
        }
    }
    Some(walk + 1)
}

pub(crate) fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let (hashes, cursor) = raw_string_opening(bytes, start)?;
    find_raw_string_end(bytes, hashes, cursor).or(Some(bytes.len()))
}

pub(crate) fn raw_string_opening(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    (bytes.get(start).copied()? == b'r').then_some(())?;
    let mut cursor = start + 1;
    let hashes = count_raw_string_hashes(bytes, &mut cursor);
    (bytes.get(cursor) == Some(&b'"')).then_some((hashes, cursor + 1))
}

pub(crate) fn count_raw_string_hashes(bytes: &[u8], cursor: &mut usize) -> usize {
    let mut hashes = 0usize;
    while bytes.get(*cursor) == Some(&b'#') {
        hashes += 1;
        *cursor += 1;
    }
    hashes
}

pub(crate) fn find_raw_string_end(bytes: &[u8], hashes: usize, mut cursor: usize) -> Option<usize> {
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' && has_raw_string_hashes_at(bytes, cursor + 1, hashes) {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    None
}

pub(crate) fn has_raw_string_hashes_at(bytes: &[u8], start: usize, hashes: usize) -> bool {
    bytes
        .get(start..start + hashes)
        .is_some_and(|slice| slice.iter().all(|byte| *byte == b'#'))
}

pub(crate) fn mask_bytes(bytes: &[u8], start: usize, end: usize, output: &mut String) {
    for byte in &bytes[start..end] {
        mask_byte(*byte, output);
    }
}

pub(crate) fn mask_byte(byte: u8, output: &mut String) {
    if byte == b'\n' {
        output.push('\n');
    } else {
        output.push(' ');
    }
}
