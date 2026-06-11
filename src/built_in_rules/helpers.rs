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
    finding_with_metadata(descriptor, json!({}))
}

pub(crate) fn finding_with_metadata(
    descriptor: SimpleFindingDescriptor<'_>,
    metadata: Value,
) -> Finding {
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
        metadata,
    })
}

pub(crate) fn threshold_metadata(measured: usize, threshold: usize, unit: &str) -> Value {
    json!({
        "measured": measured,
        "threshold": threshold,
        "unit": unit,
        "direction": "above"
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

/// Recognises subresource-integrity hash literals (`sha1-...`,
/// `sha256-...`, `sha384-...`, `sha512-...`, generic `sri-...`) that
/// lockfiles and integrity manifests commit on purpose. The byte body
/// of these is always a base64 cryptographic digest, so it trivially
/// trips entropy thresholds.
pub(crate) fn is_integrity_hash(value: &str) -> bool {
    const PREFIXES: &[&str] = &["sha1-", "sha256-", "sha384-", "sha512-", "sri-"];
    PREFIXES.iter().any(|prefix| value.starts_with(prefix))
}

pub(crate) fn is_structured_high_entropy_non_secret(value: &str) -> bool {
    is_base64_alphabet_table(value) || is_word_segment_slug(value) || is_model_identifier(value)
}

fn is_base64_alphabet_table(value: &str) -> bool {
    const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &str = "0123456789";
    if value.len() != UPPER.len() + LOWER.len() + DIGITS.len() + 2 {
        return false;
    }
    let Some(after_upper) = value.strip_prefix(UPPER) else {
        return false;
    };
    let Some(after_lower) = after_upper.strip_prefix(LOWER) else {
        return false;
    };
    after_lower == "0123456789+/" || after_lower == "0123456789-_"
}

fn is_word_segment_slug(value: &str) -> bool {
    if value.contains(['+', '=']) {
        return false;
    }
    let segments: Vec<&str> = value.split(['/', '_', '-']).collect();
    if segments.len() < 2 || segments.iter().any(|segment| segment.is_empty()) {
        return false;
    }
    segments.iter().all(|segment| {
        segment_has_letters_then_optional_short_digits(segment)
            && segment_has_word_like_case_runs(segment)
    })
}

fn is_model_identifier(value: &str) -> bool {
    let Some(segments) = model_identifier_segments(value) else {
        return false;
    };
    let Some((word_segments, code_segments)) = count_model_segment_kinds(&segments) else {
        return false;
    };
    segments.len() >= 5 && word_segments >= 3 && code_segments >= 2
}

fn model_identifier_segments(value: &str) -> Option<Vec<&str>> {
    if value.contains(['+', '=', '_']) || !value.contains('/') || !value.contains('-') {
        return None;
    }
    let slash_parts: Vec<&str> = value.split('/').collect();
    if slash_parts.len() < 3 || !is_lowercase_word(slash_parts[0]) {
        return None;
    }
    let segments: Vec<&str> = slash_parts
        .iter()
        .flat_map(|part| part.split('-'))
        .collect();
    (!segments.iter().any(|segment| segment.is_empty())).then_some(segments)
}

fn count_model_segment_kinds(segments: &[&str]) -> Option<(usize, usize)> {
    let mut word_segments = 0;
    let mut code_segments = 0;
    for segment in segments {
        match model_segment_kind(segment)? {
            ModelSegmentKind::Word => word_segments += 1,
            ModelSegmentKind::Code => code_segments += 1,
        }
    }
    Some((word_segments, code_segments))
}

enum ModelSegmentKind {
    Word,
    Code,
}

fn model_segment_kind(segment: &str) -> Option<ModelSegmentKind> {
    if is_model_word_segment(segment) {
        Some(ModelSegmentKind::Word)
    } else if is_model_code_segment(segment) {
        Some(ModelSegmentKind::Code)
    } else {
        None
    }
}

fn segment_has_letters_then_optional_short_digits(segment: &str) -> bool {
    let mut letter_count = 0;
    let mut digit_count = 0;
    let mut seen_digit = false;
    for character in segment.chars() {
        if character.is_ascii_alphabetic() {
            if seen_digit {
                return false;
            }
            letter_count += 1;
        } else if character.is_ascii_digit() {
            seen_digit = true;
            digit_count += 1;
        } else {
            return false;
        }
    }
    letter_count > 0 && digit_count <= 4
}

fn segment_has_word_like_case_runs(segment: &str) -> bool {
    let alpha_prefix: String = segment
        .chars()
        .take_while(|character| character.is_ascii_alphabetic())
        .collect();
    let runs = camel_case_runs(&alpha_prefix);
    !runs.is_empty() && runs.iter().filter(|run| run.len() >= 3).count() * 2 > runs.len()
}

fn camel_case_runs(value: &str) -> Vec<String> {
    let mut runs: Vec<String> = Vec::new();
    for character in value.chars() {
        if character.is_ascii_uppercase()
            && runs.last().is_some_and(|run| {
                run.chars()
                    .last()
                    .is_some_and(|last| last.is_ascii_lowercase())
            })
        {
            runs.push(String::new());
        }
        if let Some(run) = runs.last_mut() {
            run.push(character);
        } else {
            runs.push(character.to_string());
        }
    }
    runs
}

fn is_lowercase_word(value: &str) -> bool {
    value.len() >= 3
        && value
            .chars()
            .all(|character| character.is_ascii_lowercase())
}

fn is_model_word_segment(segment: &str) -> bool {
    segment_has_letters_then_optional_short_digits(segment)
        && segment_has_word_like_case_runs(segment)
}

fn is_model_code_segment(segment: &str) -> bool {
    if !(2..=8).contains(&segment.len())
        || !segment
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
        || !segment.chars().any(|character| character.is_ascii_digit())
    {
        return false;
    }
    segment.chars().all(|character| character.is_ascii_digit())
        || segment
            .chars()
            .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
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

#[cfg(test)]
mod high_entropy_tests {
    use super::*;

    const CLASSIC_BASE64_SECRET: &str =
        concat!("mF9qL2sT8vX3pR6n", "Y0aB4cD7eG1hJ5k", "M9pQ2rS+T=");
    const BASE64URL_SECRET: &str = concat!("Az9qL2sT8vX3pR6n", "Y0aB4cD7eG1hJ5k", "M9pQ2rS");
    const JWT_PAYLOAD_SEGMENT: &str =
        concat!("eyJzdWIiOiIxMjM0", "NTY3ODkwIiwibmFt", "ZSI6IkpvaG4ifQ");
    const GITHUB_PAT_LIKE_SECRET: &str = concat!("ghp_Az9qL2sT8vX", "3pR6nY0aB4cD7eG", "1hJ5kM9");
    const REPO_SLUG: &str = concat!("Microsoft/Type", "Script-Website-", "Builder12");
    const STANDARD_BASE64_ALPHABET: &str = concat!(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "+/"
    );
    const URL_SAFE_BASE64_ALPHABET: &str = concat!(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "-_"
    );
    const MODEL_IDENTIFIER: &str = concat!("deepinfra/Qwen/", "Qwen3-235B-A22B-", "Instruct-2507");

    #[test]
    fn high_entropy_structured_predicates_accept_only_inert_shapes() {
        assert!(is_structured_high_entropy_non_secret(REPO_SLUG));
        assert!(is_structured_high_entropy_non_secret(
            STANDARD_BASE64_ALPHABET
        ));
        assert!(is_structured_high_entropy_non_secret(
            URL_SAFE_BASE64_ALPHABET
        ));
        assert!(is_structured_high_entropy_non_secret(MODEL_IDENTIFIER));

        assert!(!is_structured_high_entropy_non_secret(
            CLASSIC_BASE64_SECRET
        ));
        assert!(!is_structured_high_entropy_non_secret(BASE64URL_SECRET));
        assert!(!is_structured_high_entropy_non_secret(
            GITHUB_PAT_LIKE_SECRET
        ));
    }

    #[test]
    fn high_entropy_predicates_keep_jwt_segment_flaggable() {
        assert!(is_high_entropy(JWT_PAYLOAD_SEGMENT));
        assert!(!is_structured_high_entropy_non_secret(JWT_PAYLOAD_SEGMENT));
    }

    #[test]
    fn high_entropy_integrity_hashes_include_sha1() {
        assert!(is_integrity_hash(concat!(
            "sha1-",
            "3GuHKO69A8db",
            "+HYIftzVDpy1aZQ="
        )));
        assert!(is_integrity_hash(concat!(
            "sha512-",
            "j51egjPa7/i+HYI",
            "ftzVDpy1aZQ=="
        )));
    }
}
