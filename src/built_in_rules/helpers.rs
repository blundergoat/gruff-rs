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

/// Detects a trivial assertion - a literal tautology (`assert!(true)`,
/// `assert_eq!(1, 1)`) or a literal-binding tautology (`let x = 5;
/// assert_eq!(x, 5)`). `source` must already be string- AND comment-masked (as
/// `analyse_test_block` prepares it); an unmasked comment would let a
/// commented-out assertion be mistaken for real code.
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
    if has_same_literal {
        return true;
    }

    has_literal_binding_tautology(source)
}

/// Detects the "literal-binding tautology": an immutable binding to a
/// numeric or boolean literal (`let answer = 42;`) whose value is then
/// asserted to equal that same literal (`assert_eq!(answer, 42)`), with no
/// shadowing of the name in between. The assertion proves only what the
/// binding already fixed, so it exercises no behavior.
///
/// Sound without dataflow analysis: an immutable, non-`mut` binding to a
/// `Copy` literal cannot be reassigned or mutated (the compiler forbids
/// both), so the only way the asserted name could differ from its
/// initializer is a later `let name = ...` shadow. `source` is already
/// string-masked, so only numeric and boolean literals survive to be
/// compared textually; `let mut`, computed initializers (`2 + 2`), and
/// values derived into a different name therefore stay silent.
fn has_literal_binding_tautology(source: &str) -> bool {
    let binding = static_regex(
        &LITERAL_BINDING_REGEX,
        r"\blet\s+(mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;\n]+)?=\s*(true|false|[0-9][0-9_]*(?:\.[0-9][0-9_]*)?)\s*;",
    );
    binding.captures_iter(source).any(|captures| {
        if captures.get(1).is_some() {
            return false; // `let mut` — the value may change before the assert.
        }
        let (Some(name), Some(literal), Some(whole)) =
            (captures.get(2), captures.get(3), captures.get(0))
        else {
            return false;
        };
        literal_is_asserted_before_shadow(&source[whole.end()..], name.as_str(), literal.as_str())
    })
}

/// True when `rest` (the body after a `let name = literal;` binding) asserts
/// `name` equal to `literal` before any later `let` rebinds `name`. The shadow
/// guard matches `name` in the binding position of any later `let` - including
/// pattern forms such as `let (name) = ...`, `let mut name = ...`, or
/// `let Foo { name } = ...` - because a rebind hides the original literal.
/// Both `assert_eq!` argument orders count; the trailing `[,)]` allows the
/// message form `assert_eq!(name, literal, "...")`.
///
/// Conservative by design: an inner-scope shadow (`{ let name = ...; }`) also
/// stops the scan, so an outer tautology after the block is a miss, not a false
/// positive. Type-suffixed (`1u32`), hex/negative, and separator-different
/// (`1000` vs `1_000`) literals are compared textually and likewise missed -
/// all safe directions for a rule whose findings command code changes.
fn literal_is_asserted_before_shadow(rest: &str, name: &str, literal: &str) -> bool {
    let escaped_name = regex::escape(name);
    let escaped_literal = regex::escape(literal);

    // Match `name` bound in the pattern of any later `let` (before its `=`),
    // covering `let (name)`, `let mut name`, `let Foo { name }`, etc.
    let shadow = Regex::new(&format!(r"\blet\b[^;=]*\b{escaped_name}\b[^;=]*="))
        .expect("literal-binding shadow regex compiles");
    let window_end = shadow.find(rest).map_or(rest.len(), |found| found.start());

    let assertion = Regex::new(&format!(
        r"\bassert_eq!\s*\(\s*(?:\b{escaped_name}\b\s*,\s*\b{escaped_literal}\b|\b{escaped_literal}\b\s*,\s*\b{escaped_name}\b)\s*[,)]"
    ))
    .expect("literal-binding assertion regex compiles");
    assertion.is_match(&rest[..window_end])
}

pub(crate) struct SimpleFindingDescriptor<'a> {
    pub(crate) rule_id: &'a str,
    pub(crate) message: String,
    pub(crate) file: &'a SourceFile,
    pub(crate) line: Option<usize>,
    pub(crate) severity: Severity,
    pub(crate) pillar: Pillar,
}

pub(crate) fn finding(descriptor: SimpleFindingDescriptor<'_>) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: descriptor.rule_id.to_string(),
        message: descriptor.message,
        file_path: descriptor.file.display_path.clone(),
        line: descriptor.line,
        severity: descriptor.severity,
        pillar: descriptor.pillar,
        confidence: Confidence::High,
        symbol: None,
        remediation: None,
        metadata: json!({}),
    })
}

pub(crate) struct BlockFindingDescriptor<'a> {
    pub(crate) rule_id: &'a str,
    pub(crate) message: String,
    pub(crate) file: &'a SourceFile,
    pub(crate) block: &'a FunctionBlock,
    pub(crate) severity: Severity,
    pub(crate) pillar: Pillar,
}

pub(crate) fn block_finding(descriptor: BlockFindingDescriptor<'_>) -> Finding {
    block_finding_with_metadata(descriptor, json!({}))
}

pub(crate) fn block_finding_with_metadata(
    descriptor: BlockFindingDescriptor<'_>,
    metadata: Value,
) -> Finding {
    block_finding_with_extras(
        descriptor,
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
    descriptor: BlockFindingDescriptor<'_>,
    extras: BlockFindingExtras,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: descriptor.rule_id.to_string(),
        message: descriptor.message,
        file_path: descriptor.file.display_path.clone(),
        line: Some(descriptor.block.start_line),
        severity: descriptor.severity,
        pillar: descriptor.pillar,
        confidence: extras.confidence,
        symbol: Some(descriptor.block.name.clone()),
        remediation: extras.remediation,
        metadata: extras.metadata,
    })
}

pub(crate) fn count_regex(source: &str, pattern: &Regex) -> usize {
    pattern.find_iter(source).count()
}

#[allow(dead_code)]
pub(crate) fn first_matching_line(source: &str, needle: &str) -> Option<usize> {
    source
        .lines()
        .enumerate()
        .find_map(|(index, line)| line.contains(needle).then_some(index + 1))
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

pub(crate) fn is_high_entropy(value: &str) -> bool {
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

/// Returns true when the file is part of the rule calibration harness.
/// Calibration files exist to prove rules fire (positive cases) or stay
/// silent (negative cases); they intentionally embed deliberately-bad
/// patterns and would otherwise produce sensitive-data and metric noise.
/// Path-based so the same skip applies regardless of file kind.
pub(crate) fn path_is_calibration_fixture(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    if normalized.contains("/tests/calibration/") || normalized.starts_with("tests/calibration/") {
        return true;
    }
    if normalized.ends_with("/calibration_extras.rs") || normalized == "calibration_extras.rs" {
        return true;
    }
    false
}

/// Returns true when the file lives in Rust test infrastructure: anything
/// under a `tests/` directory or a sibling `tests.rs` file. Rule scanners
/// parse files individually and miss the parent-level `#[cfg(test)]`
/// gating, so this path heuristic catches helpers that panic, unwrap, or
/// otherwise behave in ways that would be production-bad but are normal
/// for test scaffolding.
///
/// `**/fixtures/**` is explicitly excluded - those files are inputs that
/// rules scan on purpose (e.g. `tests/fixtures/parser/invalid.rs` exists
/// to prove the AWS access key rule fires).
pub(crate) fn path_is_test_infrastructure(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    if normalized.contains("/fixtures/") || normalized.starts_with("fixtures/") {
        return false;
    }
    normalized.contains("/tests/")
        || normalized.starts_with("tests/")
        || normalized.ends_with("/tests.rs")
        || normalized == "tests.rs"
}
