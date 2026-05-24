use super::*;

pub(crate) static PATH_TRAVERSAL_CONSTRUCTOR_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PATH_TRAVERSAL_JOIN_REGEX: OnceLock<Regex> = OnceLock::new();

/// `security.path-traversal-candidate` — flags filesystem path
/// construction where the input is a bare identifier (likely a function
/// parameter or runtime value) rather than a static literal. Two shapes:
/// `Path::new(var)` / `PathBuf::from(var)` and `base.join(var)`. As a
/// `-candidate` rule the message is hedged; the goal is to surface
/// review-worthy joins, not to claim a proven traversal bug.
///
/// Skips that keep the rule precise (see `path_traversal_finding_is_suppressed`):
/// - file lives under test infrastructure
/// - argument matches a known safe identifier
/// - argument was declared as `&Path` / `&PathBuf` / `impl AsRef<Path>` upstream
/// - argument is a loop variable bound to a literal array
/// - argument is `let`-bound to a string literal in the preceding lines
/// - a `validate_*` / `verify_*` / `sanitize_*` / `check_*` call took the
///   argument in the preceding 30 lines
/// - the function performs `.canonicalize()` followed by `.starts_with(`
///   within 25 lines after the join (validate-then-trust pattern)
pub(crate) fn analyse_path_traversal_candidate(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    if path_is_test_infrastructure(&file.display_path) {
        return;
    }
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    let lines: Vec<&str> = searchable.lines().collect();
    let starts = line_starts(&searchable);
    let mut emitted = std::collections::BTreeSet::new();

    scan_path_traversal_constructors(file, &searchable, &lines, &starts, &mut emitted, findings);
    scan_path_traversal_joins(file, &searchable, &lines, &starts, &mut emitted, findings);
}

fn scan_path_traversal_constructors(
    file: &SourceFile,
    searchable: &str,
    lines: &[&str],
    starts: &[usize],
    emitted: &mut std::collections::BTreeSet<usize>,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &PATH_TRAVERSAL_CONSTRUCTOR_REGEX,
        r"\b(?:Path|PathBuf)\s*::\s*(?:new|from)\s*\(\s*&?\s*(?P<arg>[a-z_][a-z0-9_]*)\s*\)",
    );
    record_path_traversal_matches(file, searchable, lines, starts, regex, emitted, findings);
}

fn scan_path_traversal_joins(
    file: &SourceFile,
    searchable: &str,
    lines: &[&str],
    starts: &[usize],
    emitted: &mut std::collections::BTreeSet<usize>,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &PATH_TRAVERSAL_JOIN_REGEX,
        r"\.join\s*\(\s*&?\s*(?P<arg>[a-z_][a-z0-9_]*)\s*\)",
    );
    record_path_traversal_matches(file, searchable, lines, starts, regex, emitted, findings);
}

fn record_path_traversal_matches(
    file: &SourceFile,
    searchable: &str,
    lines: &[&str],
    starts: &[usize],
    regex: &Regex,
    emitted: &mut std::collections::BTreeSet<usize>,
    findings: &mut Vec<Finding>,
) {
    for captures in regex.captures_iter(searchable) {
        let Some(arg) = captures.name("arg") else {
            continue;
        };
        let Some(full) = captures.get(0) else {
            continue;
        };
        let line = byte_line_from_starts(starts, full.start());
        if path_traversal_finding_is_suppressed(arg.as_str(), lines, line) {
            continue;
        }
        if !emitted.insert(line) {
            continue;
        }
        push_path_traversal_candidate_finding(file, line, arg.as_str(), findings);
    }
}

fn path_traversal_finding_is_suppressed(arg: &str, lines: &[&str], line: usize) -> bool {
    path_traversal_arg_is_safe(arg)
        || arg_is_typed_path_in_nearby_signature(arg, lines, line)
        || arg_is_loop_var_from_literal_array(arg, lines, line)
        || arg_is_let_bound_to_literal(arg, lines, line)
        || arg_was_validated_in_nearby_call(arg, lines, line)
        || window_has_validation_after(lines, line)
}

fn path_traversal_arg_is_safe(arg: &str) -> bool {
    matches!(
        arg,
        "self"
            | "root"
            | "cwd"
            | "tmp"
            | "tempdir"
            | "temp_dir"
            | "out"
            | "out_dir"
            | "outdir"
            | "dir"
            | "parent"
            | "manifest_dir"
            | "target"
            | "prefix"
            | "safe"
            | "sanitized"
            | "normalized"
            | "validated"
            | "file_name"
            | "filename"
            | "display_path"
    )
}

/// True iff `arg` appears in a function signature within the 30 lines
/// preceding `line` (1-based) typed as `&Path`, `&PathBuf`, `Path`,
/// `PathBuf`, or `impl AsRef<Path>`. Path-typed parameters cannot carry
/// an unconstrained string segment; any external input was widened to a
/// path-typed value upstream.
fn arg_is_typed_path_in_nearby_signature(arg: &str, lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let zero_based = line.saturating_sub(1);
    let lookback_start = zero_based.saturating_sub(30);
    let needle = format!("{arg}:");
    lines[lookback_start..=zero_based]
        .iter()
        .rev()
        .any(|source_line| line_declares_path_typed_param(source_line, &needle))
}

fn line_declares_path_typed_param(source_line: &str, needle: &str) -> bool {
    let Some((_, after)) = source_line.split_once(needle) else {
        return false;
    };
    let trimmed = after.trim_start();
    trimmed.starts_with("&Path")
        || trimmed.starts_with("&PathBuf")
        || trimmed.starts_with("Path")
        || trimmed.starts_with("PathBuf")
        || trimmed.starts_with("impl AsRef<Path>")
        || trimmed.starts_with("&impl AsRef<Path>")
}

/// True iff the 25 lines after `line` contain both `.canonicalize()` and
/// `.starts_with(`. That sequence is the validate-then-trust pattern
/// (resolve symlinks, then check the resolved path is inside the trusted
/// root); recognising it lets the rule stay silent on intentionally-
/// defended joins.
fn window_has_validation_after(lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let zero_based = line.saturating_sub(1);
    let end = (zero_based + 25).min(lines.len());
    let window: String = lines[zero_based..end].join("\n");
    window.contains(".canonicalize(") && window.contains(".starts_with(")
}

/// True iff `arg` was passed to a validation-shaped call in the 30 lines
/// before `line`. Recognises `(validate|verify|sanitize|check)_*(arg)`
/// calls or inline `if arg.contains(...)` taint checks.
fn arg_was_validated_in_nearby_call(arg: &str, lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let zero_based = line.saturating_sub(1);
    let lookback_start = zero_based.saturating_sub(30);
    let window: String = lines[lookback_start..=zero_based].join("\n");
    arg_has_validator_call(arg, &window) || arg_has_inline_taint_check(arg, &window)
}

fn arg_has_validator_call(arg: &str, window: &str) -> bool {
    let pattern = format!(
        r"(?:validate|verify|sanitize|check)_\w+\s*\([^)]*\b{}\b[^)]*\)",
        regex::escape(arg)
    );
    Regex::new(&pattern)
        .map(|re| re.is_match(window))
        .unwrap_or(false)
}

fn arg_has_inline_taint_check(arg: &str, window: &str) -> bool {
    let pattern = format!(r"if\s+{}\s*\.\s*contains\s*\(", regex::escape(arg));
    Regex::new(&pattern)
        .map(|re| re.is_match(window))
        .unwrap_or(false)
}

/// True iff `arg` is bound by a `for ARG in [...]` or `for ARG in &ITER`
/// statement in the 3 lines before `line`. Loop variables bound to a
/// local array (literal or borrowed from a same-function `let` binding)
/// cannot carry user input.
fn arg_is_loop_var_from_literal_array(arg: &str, lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let zero_based = line.saturating_sub(1);
    let lookback_start = zero_based.saturating_sub(3);
    lines[lookback_start..=zero_based]
        .iter()
        .any(|source_line| line_is_for_loop_over_local_array(source_line, arg))
}

fn line_is_for_loop_over_local_array(source_line: &str, arg: &str) -> bool {
    let trimmed = source_line.trim_start();
    let Some(after_for) = trimmed.strip_prefix("for ") else {
        return false;
    };
    let Some(after_arg) = after_for.strip_prefix(arg) else {
        return false;
    };
    let after = after_arg.trim_start();
    let Some(after_in) = after.strip_prefix("in ").map(str::trim_start) else {
        return false;
    };
    after_in.starts_with('[') || after_in.starts_with('&')
}

/// True iff `arg` is bound to a string literal in the 4 lines before
/// `line`. Detection runs against the string-masked source, so
/// `let ARG = "literal"` and `let ARG = r"literal"` both appear as
/// `let ARG = ;` (literal contents become whitespace via
/// `strip_rust_string_literals`).
fn arg_is_let_bound_to_literal(arg: &str, lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let zero_based = line.saturating_sub(1);
    let lookback_start = zero_based.saturating_sub(4);
    let window: String = lines[lookback_start..=zero_based].join("\n");
    let needle = format!("let {arg}");
    let Some(let_pos) = window.find(&needle) else {
        return false;
    };
    let after = &window[let_pos + needle.len()..];
    let after_type = match strip_type_annotation(after) {
        Some(rest) => rest,
        None => return false,
    };
    let between = after_type.trim_start();
    let Some(without_eq) = between.strip_prefix('=') else {
        return false;
    };
    let Some(semicolon_pos) = without_eq.find(';') else {
        return false;
    };
    without_eq[..semicolon_pos]
        .chars()
        .all(|character| character.is_whitespace())
}

fn strip_type_annotation(after: &str) -> Option<&str> {
    let trimmed = after.trim_start();
    if let Some(stripped) = trimmed.strip_prefix(':') {
        let eq_pos = stripped.find('=')?;
        Some(&stripped[eq_pos..])
    } else {
        Some(trimmed)
    }
}

fn push_path_traversal_candidate_finding(
    file: &SourceFile,
    line: usize,
    arg: &str,
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding::new(FindingDescriptor {
        rule_id: "security.path-traversal-candidate".to_string(),
        message: format!(
            "Filesystem path constructed from `{arg}`; review whether the value can escape the intended directory."
        ),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::Medium,
        symbol: None,
        remediation: Some(
            "Validate the segment with `Path::components`, reject `..` and absolute paths, or canonicalise and re-check the prefix."
                .to_string(),
        ),
        metadata: json!({ "argument": arg }),
    }));
}
