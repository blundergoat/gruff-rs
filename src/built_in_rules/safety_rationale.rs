//! Safety-rationale helpers preserve nearby comments for unsafe-block rules.
//! The line analyzer resolves case-insensitive markers through the contiguous comment
//! prelude, then decides whether the combined rationale explains enough.

const SAFETY_MARKER: &[u8] = b"SAFETY:";
/// Lines read inside an opened `unsafe {` block for a rationale written as its first comment.
const SAFETY_RATIONALE_LOOKAHEAD_LINES: usize = 2;

/// Return the nearest rationale in the comment prelude before an unsafe line. The prelude ends at the
/// first line that is not comment, attribute or lead-in code, not at a line count (FAMILY-CONTRACT section 12,
/// search `A SAFETY rationale is found by comment block`), so a longer explanation is never read as a missing one.
/// `None` means no marker is connected to the block without crossing executable code.
///
/// `lines` holds the source lines being scanned and `line_index` is the 0-based index of the unsafe line; an out-of-range index panics.
///
/// Returns a marker's text from the unsafe line itself, without continuation lines, when that line has one.
/// Otherwise returns a nearby marker's text joined with its continuation comment lines in source order.
/// A marker with no rationale text gives `Some` of an empty string, which `is_weak_safety_rationale` rates weak, unlike `None`.
pub(crate) fn find_nearby_safety_rationale(lines: &[&str], line_index: usize) -> Option<String> {
    let mut prelude = SafetyPreludeScanner::default();

    // Walk toward the marker so continuation comments can be restored to source order.
    for candidate_index in (0..=line_index).rev() {
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

    // A rationale written as the first comment inside the opened block explains it just as well.
    forward_safety_rationale(lines, line_index)
}

/// Read the first lines inside an `unsafe {` that the unsafe line opens, stopping at the first line not starting with `//` or `/*`.
/// The line must end with the block's own `unsafe {`: in `while unsafe { next(it) } != 0 {` the brace opens the loop body,
/// whose comments are about other statements. `None` leaves the block visible to the missing-rationale rule.
///
/// `lines` holds the source lines being scanned and `line_index` is the 0-based index of the unsafe line; an out-of-range index panics.
///
/// Returns the marker's text joined with the line comments under it, searching two lines after the opener; an empty string means neither has text.
/// `None` means the line does not end in `unsafe {` or `unsafe{`, or no marker appears in the two-line lookahead before a line
/// that starts, after indentation, with neither `//` nor `/*`, such as the ` * ` middle line of a block comment.
fn forward_safety_rationale(lines: &[&str], line_index: usize) -> Option<String> {
    let opener = lines[line_index].trim_end();
    if !opener.ends_with("unsafe {") && !opener.ends_with("unsafe{") {
        return None;
    }
    for (index, line) in lines
        .iter()
        .enumerate()
        .skip(line_index + 1)
        .take(SAFETY_RATIONALE_LOOKAHEAD_LINES)
    {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("//") && !trimmed.starts_with("/*") {
            return None;
        }
        if let Some(rationale) = safety_rationale_in_comment(line) {
            return Some(with_following_comment_lines(
                &rationale,
                &lines[index + 1..],
            ));
        }
    }
    None
}

/// Append the line comments directly under a marker, in source order, so a rationale written below an empty
/// `// SAFETY:` line is read whole. The run ends at the first line that is not a line comment, or at another
/// marker.
///
/// `marker_text` is the text already read after the marker, left out when empty, and `following` holds the lines below the marker line.
/// Returns the non-empty pieces joined with single spaces, which is an empty string when neither the marker nor the run holds text.
fn with_following_comment_lines(marker_text: &str, following: &[&str]) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if !marker_text.is_empty() {
        parts.push(marker_text);
    }
    for line in following {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("//") || safety_marker_end(trimmed).is_some() {
            break;
        }
        let text = trim_comment_suffix(&trimmed[comment_content_start(trimmed)..]);
        if !text.is_empty() {
            parts.push(text);
        }
    }
    parts.join(" ")
}

/// A marker found while walking backwards through a block comment, pending its opener.
struct PendingBlockMarker<'a> {
    line: &'a str,
    marker_end: usize,
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
    ///
    /// `line` is the next source line above those already scanned.
    /// Returns `Found` with the rationale once a marker is accepted, `Continue` while the prelude goes on, or `Boundary` when `line` ends it.
    fn scan_line(&mut self, line: &'a str) -> SafetyPreludeStep {
        let was_inside_block_comment = self.inside_block_comment;
        let comment_text = backward_comment_text(line, &mut self.inside_block_comment);
        let marker_end = safety_marker_end(line).filter(|_| comment_text.is_some());
        self.remember_pending_marker(line, marker_end);

        let validated_block_opener =
            was_inside_block_comment && !self.inside_block_comment && comment_text.is_some();
        if validated_block_opener {
            if let Some(rationale) = self.take_pending_rationale() {
                return SafetyPreludeStep::Found(rationale);
            }
        }
        if let Some(marker_end) = marker_end.filter(|_| !self.inside_block_comment) {
            return SafetyPreludeStep::Found(join_safety_rationale(
                line,
                marker_end,
                &self.continuation_lines,
            ));
        }

        self.continue_or_stop(line, comment_text)
    }

    /// Retain the nearest inner marker while the scan searches for a standalone block opener.
    ///
    /// `line` is the scanned line and `marker_end` is the byte offset where its marker ends, or `None` when it has none.
    /// Only the first marker found inside a block comment is kept, with the count of continuation lines read before it.
    fn remember_pending_marker(&mut self, line: &'a str, marker_end: Option<usize>) {
        if !self.inside_block_comment || self.pending_block_marker.is_some() {
            return;
        }
        if let Some(marker_end) = marker_end {
            self.pending_block_marker = Some(PendingBlockMarker {
                line,
                marker_end,
                continuation_count: self.continuation_lines.len(),
            });
        }
    }

    /// Build a stored marker using only continuation text discovered below that marker.
    ///
    /// Returns the joined rationale and clears the stored marker, or `None` when no marker is pending.
    fn take_pending_rationale(&mut self) -> Option<String> {
        let pending = self.pending_block_marker.take()?;
        Some(join_safety_rationale(
            pending.line,
            pending.marker_end,
            &self.continuation_lines[..pending.continuation_count],
        ))
    }

    /// Keep contiguous comment text, complete attributes and code that leads into the unsafe expression;
    /// a blank line or a line that completes a statement ends the prelude.
    ///
    /// `line` is the scanned source line and `comment_text` is its comment text, or `None` when `line` is not standalone comment text.
    /// Comment text is recorded as continuation only while no block marker is pending.
    /// Returns `Continue` for comment, attribute and lead-in lines, or `Boundary` for any other line.
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
            None if is_rust_attribute_line(line) || is_continuation_line(line) => {
                SafetyPreludeStep::Continue
            }
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
            let marker_end = safety_marker_end(&comment.text)?;
            Some(trim_comment_suffix(&comment.text[marker_end..]).to_string())
        })
}

/// Join marker text and following comment lines in their original source order.
///
/// `marker_line` is the line holding the marker and `marker_end` is the byte offset where the marker ends; an invalid offset panics.
/// `continuation_lines` holds the comment texts below the marker in the bottom-up order the backward scan read them.
/// Returns the text after the marker followed by the continuation texts top-down, joined with single spaces and skipping empty parts.
fn join_safety_rationale<'a>(
    marker_line: &'a str,
    marker_end: usize,
    continuation_lines: &[&'a str],
) -> String {
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

/// Find where a safety marker ends, so the caller reads the rationale from there: `SAFETY:` in any case
/// anywhere in the comment, or a comment that is only an uppercase `SAFETY` or a `# Safety` heading, whose
/// rationale is the comment lines around it. Prose that only mentions safety, such as `thread safety is
/// handled by the lock`, `TODO: safety review`, `SAFETY is not guaranteed here` or `SAFETY Cannot be
/// guaranteed`, carries no marker: without its colon, text after `SAFETY` may as well be a warning.
///
/// `line` is the comment line or comment text to search.
/// Returns the byte offset just past the marker, the length of `line` for a heading, or `None` when `line` holds no marker.
fn safety_marker_end(line: &str) -> Option<usize> {
    if let Some(position) = line
        .as_bytes()
        .windows(SAFETY_MARKER.len())
        .position(|candidate| candidate.eq_ignore_ascii_case(SAFETY_MARKER))
    {
        return Some(position + SAFETY_MARKER.len());
    }
    let content_start = comment_content_start(line);
    let content = &line[content_start..];
    if let Some(rest) = content.strip_prefix("SAFETY") {
        if trim_comment_suffix(rest).is_empty() {
            return Some(content_start + "SAFETY".len());
        }
    }
    if content.trim_end().eq_ignore_ascii_case("# safety") {
        return Some(line.len());
    }
    None
}

/// Byte offset where a comment's text begins, past its opener (`///`, `//!`, `//`, `/**`, `/*!`, `/*` or
/// a block comment's leading `*`) and the spaces after it; text with no opener starts at its first non-space.
///
/// `line` is the comment line or comment text to measure.
/// Returns a byte offset into `line`, equal to its length when nothing follows the opener.
fn comment_content_start(line: &str) -> usize {
    let mut rest = line.trim_start();
    for opener in ["///", "//!", "//", "/**", "/*!", "/*", "*"] {
        if let Some(stripped) = rest.strip_prefix(opener) {
            rest = stripped;
            break;
        }
    }
    line.len() - rest.trim_start().len()
}

/// Report whether a code line leads into the unsafe expression below it rather than completing a
/// statement: `let value =`, an open call or list, a match arm opening a block, or a control-flow header
/// such as `match tag {`. A line ending in `,` completes a sibling arm, argument or field, a line opening
/// with `}` (such as `} else {`) closes the previous branch, and a line with its own `unsafe` belongs to that
/// block, so none of them carries a rationale past it.
///
/// `line` is one source line, judged by its trimmed text after `without_trailing_comment` drops a trailing `//` comment.
/// Returns `true` when `line` leads into the unsafe expression below it, and `false` for any other line.
fn is_continuation_line(line: &str) -> bool {
    let code = crate::built_in_rules::without_trailing_comment(line).trim();
    if code.starts_with('}') {
        return false;
    }
    let has_own_unsafe = code
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|word| word == "unsafe");
    if has_own_unsafe {
        return false;
    }
    if ["=", "(", "[", "=>", "=> {"]
        .iter()
        .any(|ending| code.ends_with(ending))
    {
        return true;
    }
    code.ends_with('{')
        && ["if ", "match ", "while ", "for ", "loop ", "loop{"]
            .iter()
            .any(|header| code.starts_with(header))
}

/// Return comment text while walking backwards through a standalone comment prelude.
///
/// `line` is the next earlier source line in the walk and `inside_block_comment` tracks whether the walk is inside a block comment.
/// The flag is set when `line` closes a block comment and cleared when it opens one, so the caller carries it to the next line.
/// Returns the trimmed comment text, or `None` when `line` is not standalone comment text, such as code or a block comment after code.
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
///
/// `comment` is the line's text inside the block comment.
/// Returns the text trimmed, without one leading `*` or any trailing `*/`, borrowed from `comment`.
fn trim_block_comment_line(comment: &str) -> &str {
    let trimmed = comment.trim();
    trim_comment_suffix(trimmed.strip_prefix('*').unwrap_or(trimmed))
}

/// Remove a closing block-comment delimiter without changing rationale punctuation.
///
/// `comment` is comment text that may end in `*/`.
/// Returns the text trimmed of surrounding whitespace and any trailing `*/` delimiters.
fn trim_comment_suffix(comment: &str) -> &str {
    comment.trim().trim_end_matches("*/").trim()
}

/// Return whether one complete outer attribute may connect a comment to an unsafe expression.
///
/// `line` is a source line, judged by its trimmed text.
/// Returns `true` when that text starts with a hash and an opening square bracket and ends with a closing one; nothing between is validated.
fn is_rust_attribute_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("#[") && trimmed.ends_with(']')
}

/// Returns whether nearby `SAFETY:` text is empty, ceremonial, a placeholder whose first word is a
/// work-in-progress marker (`todo`, `fixme`, `xxx` or `hack`, in any case), or too brief.
/// ASCII word spans keep `same-thread access` punctuation-stable.
///
/// `rationale` is the text found after the marker, compared in lowercase as ASCII-alphanumeric words.
/// Too brief means fewer than three words, or fewer than twelve characters once the words are joined with single spaces.
pub(crate) fn is_weak_safety_rationale(rationale: &str) -> bool {
    let normalized = rationale.trim().to_ascii_lowercase();
    let words = safety_rationale_words(&normalized);

    // No word spans means the user supplied only whitespace or punctuation.
    if words.is_empty() {
        return true;
    }
    // A placeholder promises a rationale without giving one, however long it is.
    if ["todo", "fixme", "xxx", "hack"].contains(&words[0]) {
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
///
/// `rationale` is the text to split, already lowercased by the caller; every character that is not ASCII alphanumeric separates words.
/// Returns the non-empty words in order, borrowed from `rationale`, or an empty vector when it has no ASCII alphanumeric character.
fn safety_rationale_words(rationale: &str) -> Vec<&str> {
    // Punctuation delimits words, so hyphens and slashes cannot hide spans.
    rationale
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect()
}
