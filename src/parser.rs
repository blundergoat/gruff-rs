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
            output.push(' ');
            index += 1;
            while index < bytes.len() {
                let byte = bytes[index];
                mask_byte(byte, &mut output);
                index += 1;
                if byte == b'\\' && index < bytes.len() {
                    mask_byte(bytes[index], &mut output);
                    index += 1;
                    continue;
                }
                if byte == b'"' {
                    break;
                }
            }
            continue;
        }

        output.push(bytes[index] as char);
        index += 1;
    }

    output
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
    let mut cursor = start + 1;
    if bytes.get(cursor).copied()? == b'\\' {
        cursor += 1;
        let escape = bytes.get(cursor).copied()?;
        cursor += 1;
        match escape {
            b'x' => cursor = cursor.checked_add(2)?,
            b'u' => {
                if bytes.get(cursor).copied()? == b'{' {
                    cursor += 1;
                    while bytes.get(cursor).copied()? != b'}' {
                        cursor += 1;
                        if cursor.saturating_sub(start) > 12 {
                            return None;
                        }
                    }
                    cursor += 1;
                } else {
                    return None;
                }
            }
            _ => {}
        }
    } else {
        cursor += 1;
    }
    (bytes.get(cursor).copied()? == b'\'').then_some(cursor + 1)
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
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            output.push(' ');
            output.push(' ');
            index += 2;
            while index < bytes.len() {
                if index + 1 < bytes.len() && bytes[index] == b'*' && bytes[index + 1] == b'/' {
                    output.push(' ');
                    output.push(' ');
                    index += 2;
                    break;
                }
                let byte = bytes[index];
                if byte == b'\n' {
                    output.push('\n');
                } else {
                    output.push(' ');
                }
                index += 1;
            }
            continue;
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
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
        if bytes[cursor] == b'"' && raw_string_hashes_match(bytes, cursor + 1, hashes) {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    None
}

pub(crate) fn raw_string_hashes_match(bytes: &[u8], start: usize, hashes: usize) -> bool {
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
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            let comment_line = line;
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
            comments.push(RustComment {
                line: comment_line,
                text,
                is_doc,
            });
            index = end;
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            let comment_line = line;
            let is_doc = bytes.get(index + 2).copied() == Some(b'*');
            let text_start = if is_doc { index + 3 } else { index + 2 };
            let mut end = text_start;
            while end + 1 < bytes.len() {
                if bytes[end] == b'*' && bytes[end + 1] == b'/' {
                    break;
                }
                if bytes[end] == b'\n' {
                    line += 1;
                }
                end += 1;
            }
            let text = std::str::from_utf8(&bytes[text_start..end])
                .unwrap_or("")
                .trim()
                .to_string();
            comments.push(RustComment {
                line: comment_line,
                text,
                is_doc,
            });
            index = (end + 2).min(bytes.len());
            continue;
        }
        if bytes[index] == b'\n' {
            line += 1;
        }
        index += 1;
    }
    comments
}
