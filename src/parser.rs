use super::*;

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

/// Masks Rust comments (`//`, `///`, `//!`, `/* */`, `/** */`) into spaces
/// while preserving newlines, so line indices stay aligned. Intended to be
/// run AFTER `strip_rust_string_literals`, so comment-shaped sequences
/// inside string literals are already spaces and do not false-trigger the
/// comment detector.
pub(crate) fn strip_rust_comments_after_string_mask(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if starts_with_two(bytes, index, b'/', b'/') {
            index = mask_line_comment(bytes, index, &mut output);
            continue;
        }
        if starts_with_two(bytes, index, b'/', b'*') {
            index = mask_block_comment(bytes, index, &mut output);
            continue;
        }
        index = push_original_char(input, index, &mut output);
    }
    output
}

/// Masks a `//` line comment with spaces (preserving the newline). Returns
/// the byte index of the newline (or `bytes.len()`).
fn mask_line_comment(bytes: &[u8], start: usize, output: &mut String) -> usize {
    let mut index = start;
    while index < bytes.len() && bytes[index] != b'\n' {
        output.push(' ');
        index += 1;
    }
    index
}

/// Masks a `/* ... */` block comment with spaces, preserving newlines so
/// the line counter stays aligned. Returns the byte index just past the
/// closing `*/` (or `bytes.len()` if unterminated).
fn mask_block_comment(bytes: &[u8], start: usize, output: &mut String) -> usize {
    output.push(' ');
    output.push(' ');
    let mut index = start + 2;
    let mut depth = 1usize;
    while index < bytes.len() {
        if starts_with_two(bytes, index, b'/', b'*') {
            output.push(' ');
            output.push(' ');
            depth += 1;
            index += 2;
            continue;
        }
        if starts_with_two(bytes, index, b'*', b'/') {
            output.push(' ');
            output.push(' ');
            depth = depth.saturating_sub(1);
            index += 2;
            if depth == 0 {
                return index;
            }
            continue;
        }
        let byte = bytes[index];
        if byte == b'\n' {
            output.push('\n');
        } else {
            output.push(' ');
        }
        index += 1;
    }
    index
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

/// Lightweight comment record: line of the comment opener, the trimmed
/// payload text (with marker bytes stripped), and whether the comment is a
/// rustdoc form (`///` or `//!` for line, `/**` for block). Block comments
/// keep their first-line index so findings point to the opening byte.
pub(crate) struct RustComment {
    pub(crate) line: usize,
    pub(crate) text: String,
    pub(crate) is_doc: bool,
}

/// Walks the string-masked Rust source and returns every comment span.
/// String contents are already spaces in `masked_source`, so any `//` or
/// `/*` we see is a real Rust comment. Newlines are preserved by the
/// upstream `strip_rust_string_literals`, so line counts match the source.
pub(crate) fn extract_rust_comments(masked_source: &str) -> Vec<RustComment> {
    let bytes = masked_source.as_bytes();
    let mut comments = Vec::new();
    let mut line = 1usize;
    let mut index = 0usize;
    while index < bytes.len() {
        advance_comment_extraction(bytes, &mut comments, &mut index, &mut line);
    }
    comments
}

fn advance_comment_extraction(
    bytes: &[u8],
    comments: &mut Vec<RustComment>,
    index: &mut usize,
    line: &mut usize,
) {
    if starts_with_two(bytes, *index, b'/', b'/') {
        let (comment, next_index) = consume_line_comment(bytes, *index, *line);
        comments.push(comment);
        *index = next_index;
        return;
    }
    if starts_with_two(bytes, *index, b'/', b'*') {
        let (comment, next_index, next_line) = consume_block_comment(bytes, *index, *line);
        comments.push(comment);
        *index = next_index;
        *line = next_line;
        return;
    }
    if bytes[*index] == b'\n' {
        *line += 1;
    }
    *index += 1;
}

fn starts_with_two(bytes: &[u8], index: usize, first: u8, second: u8) -> bool {
    index + 1 < bytes.len() && bytes[index] == first && bytes[index + 1] == second
}

/// Consumes a `//` line comment starting at `index` (with current `line`)
/// and returns the captured comment and the new cursor position. The new
/// position points at the trailing newline (or EOF) so the outer loop
/// increments `line` on the next pass.
fn consume_line_comment(bytes: &[u8], index: usize, line: usize) -> (RustComment, usize) {
    let is_doc = bytes
        .get(index + 2)
        .copied()
        .map(|byte| byte == b'/' || byte == b'!')
        .unwrap_or(false);
    let text_start = if is_doc { index + 3 } else { index + 2 };
    let mut end = text_start;
    while end < bytes.len() && bytes[end] != b'\n' {
        end += 1;
    }
    let text = std::str::from_utf8(&bytes[text_start..end])
        .unwrap_or("")
        .trim()
        .to_string();
    (RustComment { line, text, is_doc }, end)
}

/// Consumes a `/* ... */` block comment starting at `index` (with current
/// `line`) and returns the captured comment, the new cursor position
/// (past the closing `*/` if present), and the updated line counter.
fn consume_block_comment(bytes: &[u8], index: usize, line: usize) -> (RustComment, usize, usize) {
    let is_doc = bytes.get(index + 2).copied() == Some(b'*');
    let text_start = if is_doc { index + 3 } else { index + 2 };
    let (end, current_line) = scan_block_comment_body(bytes, text_start, line);
    let text = std::str::from_utf8(&bytes[text_start..end])
        .unwrap_or("")
        .trim()
        .to_string();
    let next_index = (end + 2).min(bytes.len());
    (RustComment { line, text, is_doc }, next_index, current_line)
}

/// Scans forward through a block-comment body starting at `text_start`,
/// returning the byte index of the closing `*/` (or one past the last
/// scanned byte if unterminated) plus the updated line counter for
/// embedded newlines.
fn scan_block_comment_body(bytes: &[u8], text_start: usize, line: usize) -> (usize, usize) {
    let mut end = text_start;
    let mut current_line = line;
    let mut depth = 1usize;
    while end + 1 < bytes.len() {
        match block_comment_token(bytes, end) {
            BlockCommentToken::Open => {
                depth += 1;
                end += 2;
            }
            BlockCommentToken::Close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return (end, current_line);
                }
                end += 2;
            }
            BlockCommentToken::Newline => {
                current_line += 1;
                end += 1;
            }
            BlockCommentToken::Other => end += 1,
        }
    }
    (end, current_line)
}

enum BlockCommentToken {
    Open,
    Close,
    Newline,
    Other,
}

fn block_comment_token(bytes: &[u8], index: usize) -> BlockCommentToken {
    if starts_with_two(bytes, index, b'/', b'*') {
        BlockCommentToken::Open
    } else if starts_with_two(bytes, index, b'*', b'/') {
        BlockCommentToken::Close
    } else if bytes[index] == b'\n' {
        BlockCommentToken::Newline
    } else {
        BlockCommentToken::Other
    }
}
