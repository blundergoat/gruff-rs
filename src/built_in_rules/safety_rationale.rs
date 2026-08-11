//! Safety-rationale helpers preserve nearby comments for unsafe-block rules.
//! The line analyzer resolves case-insensitive markers through a bounded comment
//! prelude, then decides whether the combined rationale explains enough.

const SAFETY_MARKER: &[u8] = b"SAFETY:";
const SAFETY_RATIONALE_LOOKBACK_LINES: usize = 16;

/// Return the nearest rationale in the bounded comment prelude before an unsafe line.
/// `None` means no marker is connected to the block without crossing executable code.
pub(crate) fn find_nearby_safety_rationale(lines: &[&str], line_index: usize) -> Option<String> {
    let first_candidate = line_index.saturating_sub(SAFETY_RATIONALE_LOOKBACK_LINES);
    let mut continuation_lines: Vec<&str> = Vec::new();

    // Walk toward the marker so continuation comments can be restored to source order.
    for candidate_index in (first_candidate..=line_index).rev() {
        let line = lines[candidate_index];

        // The string masker keeps a same-line literal from posing as a rationale comment.
        if candidate_index == line_index {
            if let Some(rationale) = safety_rationale_in_comment(line) {
                return Some(rationale);
            }
            continue;
        }

        let comment_text = rust_comment_text(line);
        if let Some(marker_position) =
            safety_marker_position(line).filter(|_| comment_text.is_some())
        {
            return Some(join_safety_rationale(
                line,
                marker_position,
                &continuation_lines,
            ));
        }

        match comment_text {
            Some(comment) => continuation_lines.push(comment),
            // Attributes may sit between a safety comment and the unsafe expression they annotate.
            None if is_rust_attribute_line(line) => {}
            None => break,
        }
    }

    // No marker leaves the unsafe block visible to the missing-rationale rule.
    None
}

/// Return a rationale only when the unsafe line contains a real Rust comment marker.
fn safety_rationale_in_comment(line: &str) -> Option<String> {
    let string_masked_line = crate::strip_rust_string_literals(line);
    crate::extract_rust_comments(&string_masked_line)
        .into_iter()
        .find_map(|comment| {
            let marker_position = safety_marker_position(&comment.text)?;
            let marker_end = marker_position + SAFETY_MARKER.len();
            Some(trim_comment_suffix(&comment.text[marker_end..]).to_string())
        })
}

/// Join marker text and following comment lines in their original source order.
fn join_safety_rationale<'a>(
    marker_line: &'a str,
    marker_position: usize,
    continuation_lines: &[&'a str],
) -> String {
    let marker_end = marker_position + SAFETY_MARKER.len();
    let marker_text = trim_comment_suffix(&marker_line[marker_end..]);
    let mut rationale_parts = Vec::with_capacity(continuation_lines.len() + 1);
    if !marker_text.is_empty() {
        rationale_parts.push(marker_text);
    }
    // Backward discovery is reversed so the final rationale reads like the source comment.
    for continuation in continuation_lines.iter().rev() {
        if !continuation.is_empty() {
            rationale_parts.push(continuation);
        }
    }
    rationale_parts.join(" ")
}

/// Find the byte offset of an ASCII case-insensitive `SAFETY:` marker.
fn safety_marker_position(line: &str) -> Option<usize> {
    line.as_bytes()
        .windows(SAFETY_MARKER.len())
        .position(|candidate| candidate.eq_ignore_ascii_case(SAFETY_MARKER))
}

/// Return user-written text from a standalone Rust line-comment or block-comment line.
fn rust_comment_text(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if let Some(comment) = trimmed.strip_prefix("//") {
        return Some(trim_comment_suffix(
            comment.trim_start_matches(['/', '!']).trim(),
        ));
    }
    if let Some(comment) = trimmed.strip_prefix("/*") {
        return Some(trim_comment_suffix(comment));
    }
    if trimmed == "*/" {
        return Some("");
    }
    trimmed
        .strip_prefix('*')
        .map(|comment| trim_comment_suffix(comment))
}

/// Remove a closing block-comment delimiter without changing rationale punctuation.
fn trim_comment_suffix(comment: &str) -> &str {
    comment.trim().trim_end_matches("*/").trim()
}

/// Return whether one complete outer attribute may connect a comment to an unsafe expression.
fn is_rust_attribute_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("#[") && trimmed.ends_with(']')
}

/// Returns whether nearby `SAFETY:` text is empty, ceremonial, or too brief.
/// ASCII word spans keep `same-thread access` punctuation-stable.
pub(crate) fn is_weak_safety_rationale(rationale: &str) -> bool {
    let normalized = rationale.trim().to_ascii_lowercase();
    let words = safety_rationale_words(&normalized);

    // No word spans means the user supplied only whitespace or punctuation.
    if words.is_empty() {
        return true;
    }

    let normalized_phrase = words.join(" ");
    const WEAK_PHRASES: &[&str] = &[
        "safe",
        "required",
        "needed",
        "ok",
        "okay",
        "yes",
        "trivial",
        "obvious",
        "n a",
        "none",
        "see above",
        "see below",
        "this is safe",
        "it is safe",
        "safe because safe",
    ];

    // Exact normalized matches keep generic and circular assurances weak.
    if WEAK_PHRASES.contains(&normalized_phrase.as_str()) {
        return true;
    }

    words.len() < 3 || normalized_phrase.len() < 12
}

/// Extracts ASCII-alphanumeric words before the weak-rationale policy runs.
fn safety_rationale_words(rationale: &str) -> Vec<&str> {
    // Punctuation delimits words, so hyphens and slashes cannot hide spans.
    rationale
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect()
}
