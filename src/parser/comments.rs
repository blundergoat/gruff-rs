use super::*;

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
        index = advance_mask_block_comment(bytes, index, &mut depth, output);
        if depth == 0 {
            return index;
        }
    }
    index
}

fn advance_mask_block_comment(
    bytes: &[u8],
    index: usize,
    depth: &mut usize,
    output: &mut String,
) -> usize {
    if starts_with_two(bytes, index, b'/', b'*') {
        output.push(' ');
        output.push(' ');
        *depth += 1;
        return index + 2;
    }
    if starts_with_two(bytes, index, b'*', b'/') {
        output.push(' ');
        output.push(' ');
        *depth = depth.saturating_sub(1);
        return index + 2;
    }
    let byte = bytes[index];
    if byte == b'\n' {
        output.push('\n');
    } else {
        output.push(' ');
    }
    index + 1
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

pub(super) fn starts_with_two(bytes: &[u8], index: usize, first: u8, second: u8) -> bool {
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

/// If `index` starts a `//` or `/* */` Rust comment, returns the byte index
/// just past the comment so the string-mask pass can hand the bytes through
/// unchanged. Without this, a comment like `/// \"` would flip the string
/// masker into string mode and consume real code until the next `"`.
pub(super) fn comment_passthrough_end(bytes: &[u8], index: usize) -> Option<usize> {
    if starts_with_two(bytes, index, b'/', b'/') {
        return Some(line_comment_end(bytes, index));
    }
    if starts_with_two(bytes, index, b'/', b'*') {
        return Some(block_comment_passthrough_end(bytes, index));
    }
    None
}

fn line_comment_end(bytes: &[u8], index: usize) -> usize {
    let mut end = index + 2;
    while end < bytes.len() && bytes[end] != b'\n' {
        end += 1;
    }
    end
}

fn block_comment_passthrough_end(bytes: &[u8], index: usize) -> usize {
    let mut end = index + 2;
    let mut depth = 1usize;
    while end + 1 < bytes.len() {
        if starts_with_two(bytes, end, b'/', b'*') {
            depth += 1;
            end += 2;
        } else if starts_with_two(bytes, end, b'*', b'/') {
            depth -= 1;
            end += 2;
            if depth == 0 {
                return end;
            }
        } else {
            end += 1;
        }
    }
    bytes.len()
}
