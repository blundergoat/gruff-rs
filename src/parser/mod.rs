//! Mask Rust strings and comments and extract identifier references for rule detectors.
//!
//! Callers run these helpers before text-level checks and dead-code scans so commented-out examples
//! and string payloads do not produce false findings, while serde paths and format captures still count as uses.

use super::*;

mod comments;
mod format_captures;

use comments::comment_passthrough_end;
pub(crate) use comments::{
    extract_rust_comments, strip_rust_comments_after_string_mask, RustComment,
};
use format_captures::append_format_macro_references;

/// Compile a fixed regex once and hand back the cached copy on every later call.
///
/// `lock` is the static cell that caches the compiled regex, and `pattern` is compiled only when `lock` is still empty.
/// Returns the cached regex; it panics through `expect` if `pattern` fails to compile.
pub(crate) fn static_regex(lock: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    lock.get_or_init(|| Regex::new(pattern).expect("static regex compiles"))
}

/// List the byte offset at which each line of a source text starts.
///
/// `source` is the text to scan; the byte after each newline begins a new line.
/// Returns the offsets in order, always starting with 0; a trailing newline adds an offset equal to the length of `source`.
pub(crate) fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(index + 1);
        }
    }
    starts
}

/// Translate a byte offset into a 1-based line number.
///
/// `line_starts` is the sorted offset list the `line_starts` function builds, and `byte_index` is the offset to locate.
/// Returns the number of line starts at or before `byte_index`, which is that offset's 1-based line.
pub(crate) fn byte_line_from_starts(line_starts: &[usize], byte_index: usize) -> usize {
    line_starts.partition_point(|line_start| *line_start <= byte_index)
}

/// Blank out Rust double-quoted strings, raw strings and recognised char literals, delimiters included, leaving code and comments in place.
///
/// `source` is Rust source text; comments are copied through unchanged so a quote inside one does not start a literal.
/// Returns text of the same byte length in which each masked byte becomes a space, except newlines, which are kept.
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

/// Copy the character that starts at a byte offset into the output unchanged.
///
/// `source` is the text being masked, `index` the byte offset of the character, and `output` the masked text that gains it.
/// Returns the byte offset just past that character; it panics if `index` is not a character boundary inside `source`.
pub(crate) fn push_original_char(source: &str, index: usize, output: &mut String) -> usize {
    let character = source[index..]
        .chars()
        .next()
        .expect("index is on a UTF-8 boundary");
    output.push(character);
    index + character.len_utf8()
}

/// Build the text searched for identifier references by dead-code analysis.
///
/// Keeps Rust code with strings and comments blanked, then appends selected serde attribute paths and std formatting macro captures.
///
/// `source` is the raw Rust file text.
/// Returns the masked source followed by space-separated references from `append_serde_default_references` and `append_format_macro_references`.
pub(crate) fn rust_code_reference_source(source: &str) -> String {
    let masked_source = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    let mut reference_source = String::with_capacity(masked_source.len() + 64);
    reference_source.push_str(&masked_source);
    let uncommented = source_without_comments(source);
    append_serde_default_references(&uncommented, &mut reference_source);
    append_format_macro_references(&uncommented, &mut reference_source);
    reference_source
}

/// Source with every comment blanked and string literals kept, so comments do not affect literal-aware scans.
///
/// The two maskers keep byte offsets, so they differ only on comments.
///
/// Returns the rebuilt text; each blanked comment character becomes one space, so a multi-byte character in a comment shortens it.
pub(crate) fn source_without_comments(source: &str) -> String {
    let string_masked = strip_rust_string_literals(source);
    let code_only = comments::strip_rust_comments_after_string_mask(&string_masked);
    source
        .char_indices()
        .map(|(index, character)| {
            if code_only.as_bytes().get(index) == string_masked.as_bytes().get(index) {
                character
            } else {
                ' '
            }
        })
        .collect()
}

/// Append the fn and module paths that serde attributes, including those applied through `cfg_attr`, name by string.
///
/// A path with `::` is skipped when its first segment is `std`, `core` or `alloc`, or is not `Self` and starts with an ASCII uppercase letter,
/// as in `Option::is_none`, so it cannot stand in for a same-named private fn here.
///
/// `source` is the text to scan, passed with comments blanked, and `output` gains a space then the path for each kept reference.
fn append_serde_default_references(source: &str, output: &mut String) {
    static SERDE_ATTRIBUTE_REGEX: OnceLock<Regex> = OnceLock::new();
    static DEFAULT_REFERENCE_REGEX: OnceLock<Regex> = OnceLock::new();
    let serde_attribute = static_regex(
        &SERDE_ATTRIBUTE_REGEX,
        r#"(?s)#\s*\[\s*(?:cfg_attr\s*\([^\[\]]*?,\s*)?serde\s*\((.*?)\)\s*\)?\s*\]"#,
    );
    // Only the keys whose value names a function or module count; `#[cfg(feature = "x")]` and
    // `#[doc = "name"]` values are prose, and the serde attribute scope above already excludes them.
    let default_reference = static_regex(
        &DEFAULT_REFERENCE_REGEX,
        r#"\b(?:default|deserialize_with|serialize_with|with|skip_serializing_if)\s*=\s*"([A-Za-z_][A-Za-z0-9_:]*)""#,
    );

    for attribute in serde_attribute.captures_iter(source) {
        let Some(body) = attribute.get(1) else {
            continue;
        };
        for reference in default_reference.captures_iter(body.as_str()) {
            let Some(path) = reference.get(1).map(|path| path.as_str()) else {
                continue;
            };
            let first_segment = path.split("::").next().unwrap_or(path);
            let is_foreign_item = path.contains("::")
                && first_segment != "Self"
                && (first_segment.starts_with(|character: char| character.is_ascii_uppercase())
                    || ["std", "core", "alloc"].contains(&first_segment));
            if !is_foreign_item {
                output.push(' ');
                output.push_str(path);
            }
        }
    }
}

/// Masks a `"..."` Rust string literal starting at the opening quote at `start`.
///
/// Handles backslash escapes so `\"` does not terminate the string.
/// Returns the byte index just past the closing quote (or `bytes.len()` if the source is malformed and the quote is unclosed).
/// `bytes` is the source being masked; `output` gains a space for each byte from the opening quote through the closing one, newlines kept.
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

/// Returns the byte index just past a Rust character literal that starts at `start`.
///
/// Recognises single-byte and multi-byte UTF-8 chars (`'X'`, `'é'`) and escape sequences (`'\n'`, `'\''`).
/// Byte escapes (`'\x41'`) and unicode escapes (`'\u{0041}'`) are recognised too.
///
/// `bytes` is the source being scanned.
/// Returns `None` for lifetimes (`'a`, `'static`) and any other shape, so the masker copies this quote and scans on from the next character.
pub(crate) fn char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start).copied()? != b'\'' {
        return None;
    }
    let cursor = char_literal_body_end(bytes, start + 1, start)?;
    (bytes.get(cursor).copied()? == b'\'').then_some(cursor + 1)
}

/// Advance past the character payload between the opening and closing quotes of a Rust char literal.
///
/// Handles escape sequences (`\n`, `\x41`, `\u{0041}`) plus single- and multi-byte UTF-8 scalars (such as `'é'`).
/// `bytes` is the source buffer, `cursor` is right after the opening quote, and `start` bounds `\u{...}` scans.
///
/// Returns the byte offset where the closing quote should sit (caller verifies `'`), or `None` when:
/// - The input ends early, a non-escaped byte is not valid UTF-8, or a `\u` escape lacks `{` or exceeds bounds.
/// - Note: `\x` advances two bytes without checking that they are hex digits.
fn char_literal_body_end(bytes: &[u8], cursor: usize, start: usize) -> Option<usize> {
    let first = bytes.get(cursor).copied()?;
    if first != b'\\' {
        return Some(cursor + utf8_char_len(bytes, cursor)?);
    }
    let escape = bytes.get(cursor + 1).copied()?;
    let after_escape = cursor + 2;
    match escape {
        b'x' => after_escape.checked_add(2),
        b'u' => unicode_escape_end(bytes, after_escape, start),
        _ => Some(after_escape),
    }
}

/// Return the UTF-8 byte length of the single scalar character starting at `cursor` in `bytes`.
///
/// `bytes` holds valid UTF-8 source bytes and `cursor` points at the first byte of the character.
/// Returns 1 to 4 when the slice forms one valid UTF-8 character, or `None` on invalid or truncated bytes.
fn utf8_char_len(bytes: &[u8], cursor: usize) -> Option<usize> {
    let width = match bytes.get(cursor).copied()? {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let slice = bytes.get(cursor..cursor + width)?;
    std::str::from_utf8(slice).ok()?;
    Some(width)
}

/// Advances past a `\u{XXXX}` unicode escape.
///
/// `cursor` is the byte after the `\u`; on success, returns the byte after the closing brace.
/// `bytes` is the source being scanned and `start` the char literal's opening-quote index, which bounds how far the escape may run.
/// Returns None when `cursor` is not on `{`, the source ends first, or the closing brace lies more than 12 bytes past `start`.
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

/// Find the end of a raw string literal whose `r` sits at a given offset.
///
/// `bytes` is the source being scanned and `start` the offset that must hold the `r` of `r"..."` or `r#"..."#`.
/// Returns the index just past the closing quote and its matching hashes, or `bytes.len()` when the literal never closes.
/// Returns None when no raw string opens at `start`.
pub(crate) fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let (hashes, cursor) = raw_string_opening(bytes, start)?;
    find_raw_string_end(bytes, hashes, cursor).or(Some(bytes.len()))
}

/// Recognise the opening of a raw string literal at a given offset.
///
/// `bytes` is the source being scanned and `start` the offset that must hold `r`, followed by any number of `#` and then a quote.
/// Returns the hash count and the index just past the opening quote, or None when that shape is not there.
pub(crate) fn raw_string_opening(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    (bytes.get(start).copied()? == b'r').then_some(())?;
    let mut cursor = start + 1;
    let hashes = count_raw_string_hashes(bytes, &mut cursor);
    (bytes.get(cursor) == Some(&b'"')).then_some((hashes, cursor + 1))
}

/// Count the run of `#` bytes at the cursor of a raw string opening.
///
/// `bytes` is the source being scanned, and `cursor` is advanced past every `#` it counts so the caller reads where the run stopped.
/// Returns the number of `#` bytes, 0 when `cursor` is not on one.
pub(crate) fn count_raw_string_hashes(bytes: &[u8], cursor: &mut usize) -> usize {
    let mut hashes = 0usize;
    while bytes.get(*cursor) == Some(&b'#') {
        hashes += 1;
        *cursor += 1;
    }
    hashes
}

/// Search for the closing delimiter of a raw string literal.
///
/// `bytes` is the source being scanned, `hashes` the number of `#` the opening used, and `cursor` the index to start searching from.
/// Returns the index just past the first quote followed by `hashes` hash bytes, or None when the source ends first.
pub(crate) fn find_raw_string_end(bytes: &[u8], hashes: usize, mut cursor: usize) -> Option<usize> {
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' && has_raw_string_hashes_at(bytes, cursor + 1, hashes) {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    None
}

/// Check whether enough hash bytes to close a raw string follow a quote.
///
/// `bytes` is the source being scanned, `start` the offset just after the quote, and `hashes` how many `#` must follow.
/// Returns true when the `hashes` bytes from `start` lie within `bytes` and are all `#`, including an empty range, and false otherwise.
pub(crate) fn has_raw_string_hashes_at(bytes: &[u8], start: usize, hashes: usize) -> bool {
    bytes
        .get(start..start + hashes)
        .is_some_and(|slice| slice.iter().all(|byte| *byte == b'#'))
}

/// Mask a byte range of the source into the output.
///
/// `bytes` is the source being masked, `start` and `end` bound the half-open range, and `output` gains one space per byte, newlines kept.
/// It panics if the range is out of order or runs past the end of `bytes`.
pub(crate) fn mask_bytes(bytes: &[u8], start: usize, end: usize, output: &mut String) {
    for byte in &bytes[start..end] {
        mask_byte(*byte, output);
    }
}

/// Mask one source byte, keeping line breaks so masked text stays line-aligned.
///
/// `output` gains a newline when `byte` is a newline and a space otherwise.
pub(crate) fn mask_byte(byte: u8, output: &mut String) {
    if byte == b'\n' {
        output.push('\n');
    } else {
        output.push(' ');
    }
}
