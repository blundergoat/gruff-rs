use super::*;
use std::borrow::Cow;

/// Run every enabled custom rule from the project configuration against one source unit.
///
/// `unit` is the file being scanned: its display path selects the rules that apply and its source text is what the patterns search.
/// `config` supplies the custom rules and says which of them are enabled.
///
/// A rule is skipped when its include or exclude path patterns rule the file out, or when `scoped_source` gives no text for its scope.
/// Returns one finding per pattern match across every applicable rule, or an empty vector when no rule applies or matches.
pub(crate) fn analyse(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in &config.custom_rules {
        if !config.is_rule_enabled(&rule.id) || !custom_rule_matches_path(rule, unit.file) {
            continue;
        }
        let Some(scope_source) = scoped_source(rule.scope, unit) else {
            continue;
        };
        findings.extend(evaluate_rule(
            unit,
            rule,
            scope_source.as_ref(),
            unit.line_starts(),
        ));
    }
    findings
}

/// Turn each match of one custom rule's pattern in the scoped text into a finding.
///
/// `unit` supplies the file path each finding reports.
/// `rule` supplies the compiled pattern and the id, message, severity, pillar, confidence and remediation copied into each finding.
/// `source` is the scoped text the pattern searches, and `line_starts` maps the first non-whitespace byte of each match to its line number.
///
/// Returns one finding per match, in order, with the match's start byte as its `byte:` symbol, or an empty vector when nothing matches.
fn evaluate_rule(
    unit: &SourceUnit<'_>,
    rule: &CustomRule,
    source: &str,
    line_starts: &[usize],
) -> Vec<Finding> {
    rule.compiled_pattern
        .find_iter(source)
        .map(|matched| {
            Finding::new(FindingDescriptor {
                rule_id: rule.id.clone(),
                message: rule.message.clone(),
                file_path: unit.file.display_path.clone(),
                line: Some(finding_line_for_match(
                    source,
                    line_starts,
                    matched.start(),
                    matched.end(),
                )),
                severity: rule.severity,
                pillar: rule.pillar,
                confidence: rule.confidence,
                symbol: Some(format!("byte:{}", matched.start())),
                remediation: rule.remediation.clone(),
                metadata: json!({ "scope": rule.scope.as_str() }),
            })
        })
        .collect()
}

/// Choose the line a custom-rule match is reported on, so a match that begins with whitespace or a newline points at its first real text.
///
/// `source` is the scoped text that was searched and `line_starts` holds the byte offset where each line begins.
/// `start` and `end` are the byte range of the match within `source`.
///
/// Returns the line holding the match's first non-whitespace byte, or the line of `start` when the match is empty or only whitespace.
fn finding_line_for_match(source: &str, line_starts: &[usize], start: usize, end: usize) -> usize {
    let line_byte = source
        .as_bytes()
        .get(start..end)
        .and_then(|matched| {
            matched
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .map(|offset| start + offset)
        })
        .unwrap_or(start)
        .min(source.len());
    byte_line_from_starts(line_starts, line_byte)
}

/// Decide whether a custom rule applies to a file by testing the file's path against the rule's include and exclude patterns.
///
/// `rule` carries the include and exclude path matchers, and `file` is the scanned file whose display path is normalised before matching.
///
/// Returns true when the rule has no include patterns or one of them matches, and no exclude pattern matches, so an exclude always wins.
fn custom_rule_matches_path(rule: &CustomRule, file: &SourceFile) -> bool {
    let path = normalize_report_path(&file.display_path);
    (rule.include_path_matchers.is_empty()
        || rule
            .include_path_matchers
            .iter()
            .any(|pattern| pattern.matches(&path)))
        && !rule
            .exclude_path_matchers
            .iter()
            .any(|pattern| pattern.matches(&path))
}

/// Build the text a custom rule's pattern searches, chosen by the rule's scope.
///
/// `scope` picks the whole source, Rust code with string literals and comments stripped, or Rust comments only.
/// `unit` supplies the source text, whether the file is Rust, and whether it is under a bounded deep scan.
///
/// Returns the source as-is for the text scope or an owned filtered copy for a Rust scope, and None for a Rust scope on a non-Rust file.
/// A bounded deep scan also yields None for every scope except text.
fn scoped_source<'a>(scope: CustomRuleScope, unit: &'a SourceUnit<'_>) -> Option<Cow<'a, str>> {
    if unit.bounded_deep_scan && scope != CustomRuleScope::Text {
        return None;
    }
    match scope {
        CustomRuleScope::Text => Some(Cow::Borrowed(unit.source)),
        CustomRuleScope::RustCode => unit.file.is_rust.then(|| {
            Cow::Owned(crate::parser::strip_rust_comments_after_string_mask(
                &crate::parser::strip_rust_string_literals(unit.source),
            ))
        }),
        CustomRuleScope::Comments => unit
            .file
            .is_rust
            .then(|| Cow::Owned(rust_comment_scope_source(unit.source))),
    }
}

/// Build the text a comment-scoped custom rule searches: a space-filled copy of a Rust source with the comments it recognises copied back in.
///
/// `source` is the Rust file's text; string, raw string and char literals are skipped so a `//` inside one is not taken for a comment.
///
/// Returns a string the same length as `source` that keeps newlines and each recognised comment in place and blanks every other byte.
/// Byte offsets and line numbers therefore match the original source.
/// The char-literal lookahead can swallow a comment that sits a few bytes after a lifetime tick, such as one between two lifetime parameters.
pub(crate) fn rust_comment_scope_source(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = build_blank_scope_output(bytes);
    let mut index = 0usize;
    while index < bytes.len() {
        index = advance_comment_scope(bytes, &mut output, index);
    }
    String::from_utf8(output).expect("comment scope source stays utf-8")
}

/// Start the comment-scope output as a blank copy of the source that keeps only its line breaks.
///
/// `bytes` is the source being filtered.
/// Returns a buffer the same length as `bytes` with every newline kept and every other byte replaced by a space.
fn build_blank_scope_output(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|byte| if *byte == b'\n' { b'\n' } else { b' ' })
        .collect()
}

/// Take one step of the comment-scope walk: copy a comment that starts at `index` into `output`, or step over a literal or an ordinary byte.
///
/// `bytes` is the source and `output` is the blank buffer that receives comment bytes at their own offsets.
/// `index` is the current position and must be inside `bytes`, or the byte lookup panics.
/// `output` must be at least as long as `bytes`, or copying a comment panics.
///
/// Returns where the walk resumes: past the comment, string or raw string that starts at `index`, otherwise `index + 1`.
/// At a `'` it resumes past whatever span `char_literal_end` accepts, which after a lifetime tick may not be a char literal.
fn advance_comment_scope(bytes: &[u8], output: &mut [u8], index: usize) -> usize {
    if let Some(raw_end) = crate::parser::raw_string_end(bytes, index) {
        return raw_end;
    }
    if bytes[index] == b'\'' {
        // A char literal such as `'"'` must be consumed whole, or its quote would open phantom
        // string state and swallow every following comment; lifetimes fall through unharmed.
        if let Some(end) = char_literal_end(bytes, index) {
            return end;
        }
        return index + 1;
    }
    if bytes[index] == b'"' {
        return skip_quoted_string(bytes, index);
    }
    if starts_with_pair(bytes, index, b'/', b'/') {
        return copy_line_comment(bytes, output, index);
    }
    if starts_with_pair(bytes, index, b'/', b'*') {
        return copy_block_comment(bytes, output, index);
    }
    index + 1
}

/// Check whether a two-byte token such as `//` or `/*` begins at a given position.
///
/// `bytes` is the source and `index` the position to test, which must be inside `bytes` or the lookup panics.
/// `first` and `second` are the two bytes of the token, in order.
///
/// Returns true when the byte at `index` is `first` and a following byte exists and is `second`.
fn starts_with_pair(bytes: &[u8], index: usize, first: u8, second: u8) -> bool {
    bytes[index] == first && bytes.get(index + 1) == Some(&second)
}

/// Bounded lookahead for a char literal: a closing `'` within the eleven bytes after the opening one, skipping the byte after a backslash.
/// Lifetimes (`&'a str`, `<'a>`) fall through as ordinary code unless another `'` follows within that window, as in `<'a>(x: &'a str)`.
///
/// `bytes` is the source and `start` is the index of the opening `'`.
///
/// Returns the index just past the closing `'`, or None when an unescaped newline or the search limit comes first, or the quotes enclose nothing.
fn char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let limit = (start + 12).min(bytes.len());
    let mut index = start + 1;
    let mut has_content = false;
    while index < limit {
        match bytes[index] {
            b'\n' => return None,
            b'\\' => {
                index += 2;
                has_content = true;
            }
            b'\'' => return has_content.then_some(index + 1),
            _ => {
                index += 1;
                has_content = true;
            }
        }
    }
    None
}

/// Step over a double-quoted string literal so a `//` or `/*` inside it is not read as a comment.
///
/// `bytes` is the source and `start` is the index of the opening `"`; a backslash skips the byte after it.
/// Returns the index just past the closing quote, or the length of `bytes` when the string is never closed.
fn skip_quoted_string(bytes: &[u8], start: usize) -> usize {
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

/// Copy a `//` line comment into the comment-scope output so comment-scoped rules can match its text.
///
/// `bytes` is the source, `start` is the index of the leading `/`, and `output` receives the comment's bytes at the same offsets.
/// `output` must be at least as long as `bytes`, or the copy panics.
///
/// Returns the index of the newline that ends the comment, or the length of `bytes` when the comment runs to the end of the source.
fn copy_line_comment(bytes: &[u8], output: &mut [u8], start: usize) -> usize {
    let mut index = start;
    while index < bytes.len() && bytes[index] != b'\n' {
        output[index] = bytes[index];
        index += 1;
    }
    index
}

/// Copy a `/* */` block comment, nested comments included, into the comment-scope output.
///
/// `bytes` is the source, `start` is the index of the opening `/*`, and `output` receives the comment's bytes at the same offsets.
/// `output` must be at least as long as `bytes`, or the copy panics.
///
/// Returns the index just past the `*/` that closes the outermost comment, or the length of `bytes` when it is never closed.
fn copy_block_comment(bytes: &[u8], output: &mut [u8], start: usize) -> usize {
    let mut index = start;
    let mut depth = 0usize;
    while index < bytes.len() {
        output[index] = bytes[index];
        if starts_with_pair(bytes, index, b'/', b'*') {
            if let Some(next) = bytes.get(index + 1) {
                output[index + 1] = *next;
            }
            depth += 1;
            index += 2;
            continue;
        }
        if starts_with_pair(bytes, index, b'*', b'/') {
            output[index + 1] = bytes[index + 1];
            depth = depth.saturating_sub(1);
            index += 2;
            if depth == 0 {
                return index;
            }
            continue;
        }
        index += 1;
    }
    index
}
