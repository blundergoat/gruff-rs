//! Safety-rationale helpers preserve nearby comments for unsafe-block rules.
//! The line analyzer uses this module to find `SAFETY:` text and decide whether
//! that text explains enough for a documentation finding to stay silent.

/// Returns the first `SAFETY:` rationale in an unsafe line's three-line window.
/// `None` means the user supplied no marker for `security.unsafe-block`.
pub(crate) fn find_nearby_safety_rationale(lines: &[&str], line_index: usize) -> Option<String> {
    let start = line_index.saturating_sub(3);

    // Inspect raw lines so the scan can see comments removed from Rust code text.
    for line in lines[start..=line_index].iter() {
        // The first marker owns the rationale reported for this unsafe block.
        if let Some(position) = line.find("SAFETY:") {
            let rationale = &line[position + "SAFETY:".len()..];
            return Some(rationale.to_string());
        }
    }

    // No marker leaves the unsafe block visible to the missing-rationale rule.
    None
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
