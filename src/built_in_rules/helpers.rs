use super::*;

pub(crate) fn find_nearby_safety_rationale(lines: &[&str], line_index: usize) -> Option<String> {
    let start = line_index.saturating_sub(3);
    for line in lines[start..=line_index].iter() {
        if let Some(pos) = line.find("SAFETY:") {
            let after = &line[pos + "SAFETY:".len()..];
            return Some(after.to_string());
        }
    }
    None
}

/// `SAFETY:` rationale counts as weak when it is too short to convey an
/// invariant or matches a known low-content phrase. Keep the deny list
/// small and exact so private comments with brief but meaningful text
/// (`SAFETY: same-thread access` etc.) still pass.
pub(crate) fn is_weak_safety_rationale(rationale: &str) -> bool {
    let trimmed = rationale.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return true;
    }
    const WEAK_PHRASES: &[&str] = &[
        "safe",
        "required",
        "needed",
        "ok",
        "okay",
        "yes",
        "trivial",
        "obvious",
        "n/a",
        "none",
        "see above",
        "see below",
    ];
    if WEAK_PHRASES.contains(&trimmed.as_str()) {
        return true;
    }
    let word_count = trimmed
        .split_whitespace()
        .filter(|word| word.len() >= 2)
        .count();
    word_count < 3 || trimmed.len() < 12
}

pub(crate) fn has_nearby_invariant_comment(source: &str) -> bool {
    source
        .lines()
        .any(|line| line.contains("PANIC:") || line.contains("INVARIANT:"))
}

pub(crate) fn has_trivial_assertion(source: &str) -> bool {
    let literal_assert = static_regex(&TRIVIAL_ASSERT_REGEX, r"\bassert!\s*\(\s*(true|false)\s*\)");
    if literal_assert.is_match(source) {
        return true;
    }

    let same_literal = static_regex(
        &SAME_LITERAL_ASSERT_REGEX,
        r#"\bassert_eq!\s*\(\s*([0-9]+|"[^"]*"|'[^']*')\s*,\s*([0-9]+|"[^"]*"|'[^']*')\s*\)"#,
    );
    let has_same_literal = same_literal.captures_iter(source).any(|captures| {
        captures.get(1).map(|left| left.as_str()) == captures.get(2).map(|right| right.as_str())
    });
    has_same_literal
}

pub(crate) fn finding(
    rule_id: &str,
    message: impl Into<String>,
    file: &SourceFile,
    line: Option<usize>,
    severity: Severity,
    pillar: Pillar,
) -> Finding {
    Finding::new(
        rule_id,
        message,
        file.display_path.clone(),
        line,
        severity,
        pillar,
        Confidence::High,
        None,
        None,
        json!({}),
    )
}

pub(crate) fn block_finding(
    rule_id: &str,
    message: impl Into<String>,
    file: &SourceFile,
    block: &FunctionBlock,
    severity: Severity,
    pillar: Pillar,
) -> Finding {
    block_finding_with_metadata(rule_id, message, file, block, severity, pillar, json!({}))
}

pub(crate) fn block_finding_with_metadata(
    rule_id: &str,
    message: impl Into<String>,
    file: &SourceFile,
    block: &FunctionBlock,
    severity: Severity,
    pillar: Pillar,
    metadata: Value,
) -> Finding {
    block_finding_with_extras(
        rule_id,
        message,
        file,
        block,
        severity,
        pillar,
        BlockFindingExtras {
            confidence: Confidence::High,
            remediation: None,
            metadata,
        },
    )
}

pub(crate) struct BlockFindingExtras {
    pub(crate) confidence: Confidence,
    pub(crate) remediation: Option<String>,
    pub(crate) metadata: Value,
}

pub(crate) fn block_finding_with_extras(
    rule_id: &str,
    message: impl Into<String>,
    file: &SourceFile,
    block: &FunctionBlock,
    severity: Severity,
    pillar: Pillar,
    extras: BlockFindingExtras,
) -> Finding {
    Finding::new(
        rule_id,
        message,
        file.display_path.clone(),
        Some(block.start_line),
        severity,
        pillar,
        extras.confidence,
        Some(block.name.clone()),
        extras.remediation,
        extras.metadata,
    )
}

pub(crate) fn count_regex(source: &str, pattern: &Regex) -> usize {
    pattern.find_iter(source).count()
}

pub(crate) fn first_matching_line(source: &str, needle: &str) -> Option<usize> {
    source
        .lines()
        .enumerate()
        .find_map(|(index, line)| line.contains(needle).then_some(index + 1))
}

pub(crate) fn byte_line(source: &str, byte_index: usize) -> usize {
    source[..byte_index.min(source.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

pub(crate) fn redact(value: &str) -> String {
    let char_count = value.chars().count();
    if char_count <= 8 {
        return format!("{} (redacted, {char_count} chars)", "*".repeat(char_count));
    }
    let start: String = value.chars().take(4).collect();
    let end: String = value
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{start}...{end} (redacted, {char_count} chars)")
}

pub(crate) fn looks_high_entropy(value: &str) -> bool {
    if value.chars().count() < 32 {
        return false;
    }
    let has_upper = value
        .chars()
        .any(|character| character.is_ascii_uppercase());
    let has_lower = value
        .chars()
        .any(|character| character.is_ascii_lowercase());
    let has_digit = value.chars().any(|character| character.is_ascii_digit());
    has_upper && has_lower && has_digit && shannon_entropy(value) >= 4.2
}

pub(crate) fn shannon_entropy(value: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for character in value.chars() {
        *counts.entry(character).or_default() += 1;
    }
    let length = value.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}
