//! Extract inline identifier captures from standard Rust formatting macros for dead-code reference counting.
//!
//! Comments must already be blanked before calling this scanner so doc examples and commented-out macros stay ignored.
//! Plain string literals are skipped at the top level so quoted text resembling a formatting macro never creates references.

use super::{char_literal_end, find_raw_string_end, raw_string_end, raw_string_opening};

/// Append every inline identifier capture referenced in standard Rust formatting macro templates to `output`.
///
/// `source` is Rust file text with comments blanked and string literals preserved.
/// Each extracted capture from `format!`, `println!`, `eprintln!`, `print!`, `eprint!`, `write!`, `writeln!`, `panic!`, or `format_args!`
/// is appended to `output` after a leading space so dead-code reference counting observes it.
pub(super) fn append_format_macro_references(source: &str, output: &mut String) {
    let bytes = source.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if let Some(next) = skip_non_macro_literal(bytes, index) {
            index = next;
            continue;
        }
        if !is_ident_start(bytes[index]) {
            index += 1;
            continue;
        }
        let ident_end = scan_ident_end(bytes, index);
        let ident = &source[index..ident_end];
        let Some(template_arg_index) = format_macro_template_arg_index(ident) else {
            index = ident_end;
            continue;
        };
        index = scan_macro_template(source, ident_end, template_arg_index, output);
    }
}

/// Skip a raw string (including `br` and `cr` prefixes), char literal, or double-quoted string outside a macro template position.
///
/// `bytes` is the full source byte slice and `index` is the byte offset to test.
/// Returns `Some(end)` just past the literal when one starts at `index`, or `None` otherwise.
fn skip_non_macro_literal(bytes: &[u8], index: usize) -> Option<usize> {
    if let Some(raw_end) = raw_string_end(bytes, index) {
        return Some(raw_end);
    }
    if matches!(bytes.get(index), Some(b'b' | b'c')) {
        if let Some(raw_end) = raw_string_end(bytes, index + 1) {
            return Some(raw_end);
        }
    }
    if let Some(char_end) = char_literal_end(bytes, index) {
        return Some(char_end);
    }
    if bytes.get(index) == Some(&b'"') {
        return Some(double_quoted_string_end(bytes, index));
    }
    None
}

/// Return the zero-based argument index of the format template string for a recognised std formatting macro.
///
/// `macro_name` is the bare macro identifier immediately before `!`.
/// Returns `Some(0)` for single-template macros, `Some(1)` for writer-first `write!`/`writeln!`, or `None` for any other name.
fn format_macro_template_arg_index(macro_name: &str) -> Option<usize> {
    match macro_name {
        "format" | "println" | "eprintln" | "print" | "eprint" | "panic" | "format_args" => Some(0),
        "write" | "writeln" => Some(1),
        _ => None,
    }
}

/// Inspect a candidate formatting macro invocation after its identifier and extract captures from its template literal.
///
/// `source` is comment-blanked Rust source, `after_ident` is the byte offset after the macro name,
/// `template_arg_index` is 0 or 1, and `output` receives each extracted identifier after a leading space.
/// Returns the byte offset where the caller's outer scan should resume so nested format macros stay reachable.
fn scan_macro_template(
    source: &str,
    after_ident: usize,
    template_arg_index: usize,
    output: &mut String,
) -> usize {
    let bytes = source.as_bytes();
    let Some((open_delim, body_start)) = macro_opening_delimiter(bytes, after_ident) else {
        return after_ident;
    };
    let close_delim = matching_delimiter(open_delim);
    let Some(arg_start) =
        locate_template_argument(bytes, body_start, close_delim, template_arg_index)
    else {
        return body_start;
    };
    let Some((template, is_raw)) = read_string_literal(source, arg_start) else {
        return body_start;
    };
    extract_template_captures(template, is_raw, output);
    body_start
}

/// Match optional whitespace, `!`, optional whitespace, and an opening macro delimiter `(`, `[`, or `{`.
///
/// `bytes` is the full source byte slice and `start` is the offset right after a candidate macro identifier.
/// Returns `Some((open_byte, next_offset))` when a macro invocation opens, or `None` otherwise.
fn macro_opening_delimiter(bytes: &[u8], start: usize) -> Option<(u8, usize)> {
    let bang = skip_ascii_whitespace(bytes, start);
    if bytes.get(bang) != Some(&b'!') {
        return None;
    }
    let delim_pos = skip_ascii_whitespace(bytes, bang + 1);
    let delim = *bytes.get(delim_pos)?;
    matches!(delim, b'(' | b'[' | b'{').then_some((delim, delim_pos + 1))
}

/// Advance from the start of a macro argument list to the beginning of the requested argument.
///
/// `bytes` is the source byte slice, `start` is the byte right after the macro's opening delimiter,
/// `close_delim` is the macro's matching closing delimiter, and `arg_index` is 0 or 1.
/// Returns `Some(offset)` at the first non-whitespace byte of the target argument, or `None` if the macro closes first.
fn locate_template_argument(
    bytes: &[u8],
    start: usize,
    close_delim: u8,
    arg_index: usize,
) -> Option<usize> {
    if arg_index == 0 {
        return Some(skip_ascii_whitespace(bytes, start));
    }
    let after_comma = skip_first_macro_argument(bytes, start, close_delim)?;
    Some(skip_ascii_whitespace(bytes, after_comma))
}

/// Skip the first comma-delimited expression inside a macro invocation while respecting nested delimiters and literals.
///
/// `bytes` is the source byte slice, `start` is the first byte inside the macro, and `close_delim` is its closing delimiter.
/// Returns `Some(offset)` immediately after the top-level comma, or `None` when the macro closes or input ends first.
fn skip_first_macro_argument(bytes: &[u8], start: usize, close_delim: u8) -> Option<usize> {
    let mut index = start;
    let mut depth = 0usize;

    while index < bytes.len() {
        if let Some(next) = skip_non_macro_literal(bytes, index) {
            index = next;
            continue;
        }
        let byte = bytes[index];
        if depth == 0 && byte == b',' {
            return Some(index + 1);
        }
        if depth == 0 && byte == close_delim {
            return None;
        }
        depth = updated_delimiter_depth(depth, byte);
        index += 1;
    }
    None
}

/// Update nested delimiter depth for one source byte inside a macro argument expression.
///
/// `depth` is the current nesting depth and `byte` is the scanned ASCII byte.
/// Returns the incremented depth for `(`, `[`, or `{`, saturating-decremented depth for `)`, `]`, or `}`, and `depth` otherwise.
fn updated_delimiter_depth(depth: usize, byte: u8) -> usize {
    match byte {
        b'(' | b'[' | b'{' => depth.saturating_add(1),
        b')' | b']' | b'}' => depth.saturating_sub(1),
        _ => depth,
    }
}

/// Read a normal or raw Rust string literal starting at `start` and return its inner text and raw-string flag.
///
/// `source` is comment-blanked Rust source and `start` is the byte offset where a template string must begin.
/// Returns `Some((inner_str, is_raw))` on match, or `None` when `start` does not open a string literal.
fn read_string_literal(source: &str, start: usize) -> Option<(&str, bool)> {
    let bytes = source.as_bytes();
    if let Some((hashes, content_start)) = raw_string_opening(bytes, start) {
        let end = find_raw_string_end(bytes, hashes, content_start)?;
        let content_end = end.checked_sub(1 + hashes)?;
        return Some((&source[content_start..content_end], true));
    }
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let end = double_quoted_string_end(bytes, start);
    let content_end = if end > start + 1 && bytes.get(end - 1) == Some(&b'"') {
        end - 1
    } else {
        end
    };
    Some((&source[start + 1..content_end], false))
}

/// Scan a format template's inner text for `{ident}`, `{ident:...}`, and `{...:WIDTH$.PREC$}` captures.
///
/// `template` is the string literal's body, `is_raw` disables backslash escape skipping when true,
/// and `output` receives each extracted identifier preceded by a space.
fn extract_template_captures(template: &str, is_raw: bool, output: &mut String) {
    let bytes = template.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if !is_raw && bytes[index] == b'\\' {
            index = skip_string_escape(bytes, index);
            continue;
        }
        if bytes[index] == b'{' {
            index = consume_brace_placeholder(template, is_raw, index, output);
            continue;
        }
        if bytes[index] == b'}' && bytes.get(index + 1) == Some(&b'}') {
            index += 2;
            continue;
        }
        index += 1;
    }
}

/// Skip one Rust string escape sequence starting at `backslash_index`, including `\u{...}` unicode escapes.
///
/// `bytes` is the template body byte slice and `backslash_index` points at `\`.
/// Returns the byte offset immediately after the skipped escape sequence.
fn skip_string_escape(bytes: &[u8], backslash_index: usize) -> usize {
    if bytes.get(backslash_index + 1) == Some(&b'u')
        && bytes.get(backslash_index + 2) == Some(&b'{')
    {
        let mut cursor = backslash_index + 3;
        while cursor < bytes.len() && bytes[cursor] != b'}' {
            cursor += 1;
        }
        return (cursor + 1).min(bytes.len());
    }
    (backslash_index + 2).min(bytes.len())
}

/// Handle a `{` inside a format template, skipping `{{` escapes and extracting identifier captures from `{...}`.
///
/// `template` is the template body, `is_raw` disables escape handling when true, `open_brace` points at `{`,
/// and `output` receives any extracted captures preceded by a space.
/// Returns the byte offset right after the escaped brace or closing `}`, or `template.len()` if unclosed.
fn consume_brace_placeholder(
    template: &str,
    is_raw: bool,
    open_brace: usize,
    output: &mut String,
) -> usize {
    let bytes = template.as_bytes();
    if bytes.get(open_brace + 1) == Some(&b'{') {
        return open_brace + 2;
    }
    let Some(close_brace) = find_placeholder_close(bytes, open_brace + 1, is_raw) else {
        return bytes.len();
    };
    append_placeholder_captures(&template[open_brace + 1..close_brace], output);
    close_brace + 1
}

/// Locate the closing `}` of a format placeholder without crossing an escaped character or nested `{`.
///
/// `bytes` is the template body, `start` is the byte right after `{`, and `is_raw` disables `\` escapes when true.
/// Returns `Some(index)` of the closing `}`, or `None` when none closes cleanly.
fn find_placeholder_close(bytes: &[u8], start: usize, is_raw: bool) -> Option<usize> {
    let mut index = start;
    while index < bytes.len() {
        if !is_raw && bytes[index] == b'\\' {
            index = skip_string_escape(bytes, index);
            continue;
        }
        if bytes[index] == b'}' {
            return Some(index);
        }
        if bytes[index] == b'{' {
            return None;
        }
        index += 1;
    }
    None
}

/// Extract the primary capture identifier and any `$`-suffixed width/precision captures from one `{...}` body.
///
/// `placeholder` is the slice between `{` and `}`, and `output` receives each valid identifier after a space.
fn append_placeholder_captures(placeholder: &str, output: &mut String) {
    let (argument, specifier) = match placeholder.split_once(':') {
        Some((arg, spec)) => (arg, Some(spec)),
        None => (placeholder, None),
    };
    if is_capture_identifier(argument) {
        output.push(' ');
        output.push_str(argument);
    }
    if let Some(spec) = specifier {
        append_dollar_specifier_captures(spec, output);
    }
}

/// Extract dynamic width or precision identifier captures (`WIDTH$`, `PREC$`) from a format specifier slice.
///
/// `specifier` is the text after `:` inside `{...}`, and `output` receives each identifier followed by `$`.
fn append_dollar_specifier_captures(specifier: &str, output: &mut String) {
    let bytes = specifier.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if !is_ident_start(bytes[index]) {
            index += 1;
            continue;
        }
        let end = scan_ident_end(bytes, index);
        if bytes.get(end) == Some(&b'$') {
            let ident = &specifier[index..end];
            if is_capture_identifier(ident) {
                output.push(' ');
                output.push_str(ident);
            }
            index = end + 1;
            continue;
        }
        index = end;
    }
}

/// Find the byte offset just past a double-quoted Rust string literal starting at `start`.
///
/// `bytes` is the source byte slice and `start` points at the opening `"`.
/// Returns the index after the closing `"`, or `bytes.len()` when unclosed.
fn double_quoted_string_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        if byte == b'\\' && index < bytes.len() {
            index += 1;
            continue;
        }
        if byte == b'"' {
            break;
        }
    }
    index
}

/// Return the matching closing delimiter byte for `(`, `[`, or `{`.
///
/// `open` is an ASCII opening delimiter byte.
/// Returns `)`, `]`, or `}` for those delimiters, and `open` otherwise.
fn matching_delimiter(open: u8) -> u8 {
    match open {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => open,
    }
}

/// Advance past consecutive ASCII whitespace bytes starting at `start`.
///
/// `bytes` is the source byte slice and `start` is the initial byte offset.
/// Returns the first offset at or after `start` whose byte is not ASCII whitespace, or `bytes.len()`.
fn skip_ascii_whitespace(bytes: &[u8], start: usize) -> usize {
    let mut index = start;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

/// Scan from `start` past all consecutive ASCII identifier continuation bytes.
///
/// `bytes` is the source byte slice and `start` points at the identifier's first byte.
/// Returns the byte offset immediately after the identifier.
fn scan_ident_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    while index < bytes.len() && is_ident_continue(bytes[index]) {
        index += 1;
    }
    index
}

/// Report whether `candidate` is a valid non-wildcard Rust format-capture identifier.
///
/// `candidate` is the slice extracted from a placeholder argument or `$`-suffixed width/precision slot.
/// Returns true when `candidate` starts with an ASCII letter or `_`, contains only ASCII identifier bytes, and is not `_`.
fn is_capture_identifier(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    candidate != "_" && is_ident_start(first) && bytes[1..].iter().copied().all(is_ident_continue)
}

/// Report whether `byte` can begin an ASCII Rust identifier.
///
/// Returns true for `A-Z`, `a-z`, or `_`, and false otherwise.
fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

/// Report whether `byte` can continue an ASCII Rust identifier.
///
/// Returns true for `A-Z`, `a-z`, `0-9`, or `_`, and false otherwise.
fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
