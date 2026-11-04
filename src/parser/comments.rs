use super::*;

/// Masks every `//` and nested `/* */` comment in string-masked Rust source with spaces, keeping newlines so lines still line up.
///
/// `input` is source whose string literals are already masked, so a `//` inside a string is not taken for a comment.
/// Returns the copy of `input` with each comment byte replaced by a space and each newline inside a comment kept.
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

/// Masks a `//` line comment with spaces (preserving the newline).
///
/// `start` is the byte index of the `//` opener in `bytes`, and `output` receives one space for each byte up to the newline.
/// Returns the byte index of the newline (or `bytes.len()`).
fn mask_line_comment(bytes: &[u8], start: usize, output: &mut String) -> usize {
    let mut index = start;
    while index < bytes.len() && bytes[index] != b'\n' {
        output.push(' ');
        index += 1;
    }
    index
}

/// Masks a `/* ... */` block comment with spaces, preserving newlines so the line counter stays aligned.
///
/// `start` is the byte index of the `/*` opener in `bytes`, and `output` receives a space for each comment byte and a newline for each newline.
/// Nested comments are followed, so only the `*/` that closes the outermost one ends the mask.
/// Returns the byte index just past the closing `*/` (or `bytes.len()` if unterminated).
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

/// Masks one token of a block comment body and tracks nesting so `mask_block_comment` knows when the outermost comment closes.
///
/// A `/*` at `index` in `bytes` raises `depth` and a `*/` lowers it, never below zero; either writes two spaces to `output`.
/// Any other byte writes one space to `output`, or a newline when the byte is a newline.
/// Returns the byte index after the consumed token, and panics if `index` is past the end of `bytes`.
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
#[derive(Debug)]
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

/// Takes one step of `extract_rust_comments`, recording a comment that starts at the cursor or else moving past one byte.
///
/// A `//` or `/*` comment starting at `index` in the string-masked `bytes` is pushed onto `comments`.
/// `index` moves past the comment or the single byte and `line` counts the newlines passed, so both carry the cursor into the next call.
/// A newline that is the last byte of an unterminated block comment is skipped without being counted.
///
/// Panics if `index` is past the end of `bytes`.
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

/// Checks whether the two-byte token `first` then `second` starts at `index` in `bytes`.
///
/// Returns true only when both bytes are present and match, and false when fewer than two bytes remain from `index`.
pub(super) fn starts_with_two(bytes: &[u8], index: usize, first: u8, second: u8) -> bool {
    index + 1 < bytes.len() && bytes[index] == first && bytes[index + 1] == second
}

/// Consumes a `//` line comment starting at `index` (with current `line`) and returns the captured comment and the new cursor position.
///
/// `bytes` is the string-masked source; a third `/` or a `!` after the opener marks the comment as doc, and its text is the trimmed rest of the line.
/// `line` is the 1-based line of the opener and is stored on the comment.
/// The new position points at the trailing newline (or EOF) so the outer loop increments `line` on the next pass.
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

/// Reads one block comment out of the string-masked source, following nested comments to the matching close.
///
/// Consumes a `/* ... */` block comment starting at `index` (with current `line`) and returns the captured comment, the new cursor position
/// (past the closing `*/` if present), and the updated line counter.
///
/// `bytes` is the string-masked source; a `*` right after the opener marks the comment as doc, and `line` is the opener's line.
/// Its text is the trimmed body inside the outer markers, and is empty when that byte range is not valid UTF-8.
/// An unterminated comment can drop its last byte from the range, which can split a multibyte character and so empty the text.
///
/// An empty `/**/` counts as doc and its scan starts after the closing star, so the text and the cursor can run on into the following source.
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

/// Finds where a possibly nested block comment ends, counting the newlines inside it.
///
/// Scans forward through a block-comment body starting at `text_start`, returning the byte index of the closing `*/` (or one past the last
/// scanned byte if unterminated) plus the updated line counter for embedded newlines.
///
/// `bytes` is the string-masked source, and `line` is the line number at `text_start`, raised by one for each newline scanned.
/// A `/*` inside the body opens a nested level, so only the `*/` that closes the outermost level ends the scan.
/// A byte is only examined when another byte follows it, so a newline that ends an unterminated comment is not counted.
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

/// Classifies the bytes at `index` in `bytes` for `scan_block_comment_body` as a nested opener, a closer, a newline or anything else.
///
/// Returns `Open` for `/*`, `Close` for `*/`, `Newline` for a newline byte and `Other` otherwise, and panics if `index` is past the end of `bytes`.
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

/// Finds where a `//` comment starting at `index` in `bytes` ends, so the string-mask pass can hand it through unchanged.
///
/// Returns the byte index of the newline that ends the comment, or `bytes.len()` when the comment runs to the end of the source.
fn line_comment_end(bytes: &[u8], index: usize) -> usize {
    let mut end = index + 2;
    while end < bytes.len() && bytes[end] != b'\n' {
        end += 1;
    }
    end
}

/// Finds the end of a block comment starting at `index` in `bytes` for the string-mask pass, following nested `/*` and `*/` pairs.
///
/// Returns the byte index just past the `*/` that closes the outermost comment, or `bytes.len()` when the comment is unterminated.
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
