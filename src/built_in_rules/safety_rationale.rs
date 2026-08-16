//! Safety-rationale helpers preserve nearby comments for unsafe-block rules.
//! The line analyzer resolves case-insensitive markers through a bounded comment
//! prelude, then decides whether the combined rationale explains enough.

const SAFETY_MARKER: &[u8] = b"SAFETY:";
const SAFETY_RATIONALE_LOOKBACK_LINES: usize = 16;

/// Return the nearest rationale in the bounded comment prelude before an unsafe line.
/// `None` means no marker is connected to the block without crossing executable code.
pub(crate) fn find_nearby_safety_rationale(lines: &[&str], line_index: usize) -> Option<String> {
    let first_candidate = line_index.saturating_sub(SAFETY_RATIONALE_LOOKBACK_LINES);
    let mut prelude = SafetyPreludeScanner::default();

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

        match prelude.scan_line(line) {
            SafetyPreludeStep::Found(rationale) => return Some(rationale),
            SafetyPreludeStep::Continue => {}
            SafetyPreludeStep::Boundary => break,
        }
    }

    // No marker leaves the unsafe block visible to the missing-rationale rule.
    None
}

/// A marker found while walking backwards through a block comment, pending its opener.
struct PendingBlockMarker<'a> {
    line: &'a str,
    marker_position: usize,
    continuation_count: usize,
}

/// Stateful backward scan of the comment prelude attached to one unsafe expression.
#[derive(Default)]
struct SafetyPreludeScanner<'a> {
    continuation_lines: Vec<&'a str>,
    inside_block_comment: bool,
    pending_block_marker: Option<PendingBlockMarker<'a>>,
}

enum SafetyPreludeStep {
    Found(String),
    Continue,
    Boundary,
}

impl<'a> SafetyPreludeScanner<'a> {
    /// Consume one earlier line without accepting a block marker until its opener is validated.
    fn scan_line(&mut self, line: &'a str) -> SafetyPreludeStep {
        let was_inside_block_comment = self.inside_block_comment;
        let comment_text = backward_comment_text(line, &mut self.inside_block_comment);
        let marker_position = safety_marker_position(line).filter(|_| comment_text.is_some());
        self.remember_pending_marker(line, marker_position);

        let validated_block_opener =
            was_inside_block_comment && !self.inside_block_comment && comment_text.is_some();
        if validated_block_opener {
            if let Some(rationale) = self.take_pending_rationale() {
                return SafetyPreludeStep::Found(rationale);
            }
        }
        if let Some(marker_position) = marker_position.filter(|_| !self.inside_block_comment) {
            return SafetyPreludeStep::Found(join_safety_rationale(
                line,
                marker_position,
                &self.continuation_lines,
            ));
        }

        self.continue_or_stop(line, comment_text)
    }

    /// Retain the nearest inner marker while the scan searches for a standalone block opener.
    fn remember_pending_marker(&mut self, line: &'a str, marker_position: Option<usize>) {
        if !self.inside_block_comment || self.pending_block_marker.is_some() {
            return;
        }
        if let Some(marker_position) = marker_position {
            self.pending_block_marker = Some(PendingBlockMarker {
                line,
                marker_position,
                continuation_count: self.continuation_lines.len(),
            });
        }
    }

    /// Build a stored marker using only continuation text discovered below that marker.
    fn take_pending_rationale(&mut self) -> Option<String> {
        let pending = self.pending_block_marker.take()?;
        Some(join_safety_rationale(
            pending.line,
            pending.marker_position,
            &self.continuation_lines[..pending.continuation_count],
        ))
    }

    /// Keep contiguous comment text and complete attributes; executable code ends the prelude.
    fn continue_or_stop(
        &mut self,
        line: &'a str,
        comment_text: Option<&'a str>,
    ) -> SafetyPreludeStep {
        match comment_text {
            Some(comment) if self.pending_block_marker.is_none() => {
                self.continuation_lines.push(comment);
                SafetyPreludeStep::Continue
            }
            Some(_) => SafetyPreludeStep::Continue,
            None if is_rust_attribute_line(line) => SafetyPreludeStep::Continue,
            None => SafetyPreludeStep::Boundary,
        }
    }
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

/// Return comment text while walking backwards through a standalone comment prelude.
fn backward_comment_text<'a>(line: &'a str, inside_block_comment: &mut bool) -> Option<&'a str> {
    let trimmed = line.trim();
    // After a closing delimiter, every preceding line is comment text until its opener.
    if *inside_block_comment {
        if let Some((prefix, comment)) = trimmed.split_once("/*") {
            *inside_block_comment = false;
            return prefix
                .trim()
                .is_empty()
                .then(|| trim_block_comment_line(comment));
        }
        return Some(trim_block_comment_line(trimmed));
    }
    if let Some(comment) = trimmed.strip_prefix("//") {
        return Some(trim_comment_suffix(
            comment.trim_start_matches(['/', '!']).trim(),
        ));
    }
    // A complete one-line block comment needs no backward continuation state.
    if let Some(comment) = trimmed
        .strip_prefix("/*")
        .filter(|_| trimmed.ends_with("*/"))
    {
        return Some(trim_comment_suffix(comment));
    }
    // A block comment following executable code cannot bridge that code to the unsafe block.
    if trimmed.contains("/*") {
        return None;
    }
    if let Some(comment) = trimmed.strip_suffix("*/") {
        *inside_block_comment = true;
        return Some(trim_block_comment_line(comment));
    }
    None
}

/// Remove optional decorative `*` syntax from one known block-comment line.
fn trim_block_comment_line(comment: &str) -> &str {
    let trimmed = comment.trim();
    trim_comment_suffix(trimmed.strip_prefix('*').unwrap_or(trimmed))
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
