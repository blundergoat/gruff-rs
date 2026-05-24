use super::*;

pub(crate) static PATH_TRAVERSAL_CONSTRUCTOR_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PATH_TRAVERSAL_JOIN_REGEX: OnceLock<Regex> = OnceLock::new();

/// `security.path-traversal-candidate` — flags filesystem path
/// construction where the input is a bare identifier. Two shapes match:
/// `Path::new(var)`/`PathBuf::from(var)` and `base.join(var)`. See
/// `path_traversal_finding_is_suppressed` for the precision guards.
pub(crate) fn analyse_path_traversal_candidate(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    if path_is_test_infrastructure(&file.display_path) {
        return;
    }
    PathTraversalScan::from(file, source).emit_findings(findings);
}

struct PathTraversalScan<'a> {
    file: &'a SourceFile,
    searchable: String,
    lines: Vec<&'a str>,
    starts: Vec<usize>,
}

impl<'a> PathTraversalScan<'a> {
    fn from(file: &'a SourceFile, source: &'a str) -> Self {
        let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
        let lines: Vec<&'a str> = source.lines().collect();
        let starts = line_starts(&searchable);
        Self {
            file,
            searchable,
            lines,
            starts,
        }
    }

    fn emit_findings(&self, findings: &mut Vec<Finding>) {
        let mut emitted = std::collections::BTreeSet::new();
        self.scan_with(constructor_regex(), &mut emitted, findings);
        self.scan_with(join_regex(), &mut emitted, findings);
    }

    fn scan_with(
        &self,
        compiled: &Regex,
        emitted: &mut std::collections::BTreeSet<usize>,
        findings: &mut Vec<Finding>,
    ) {
        for captures in compiled.captures_iter(&self.searchable) {
            let Some(arg) = captures.name("arg") else {
                continue;
            };
            let Some(full) = captures.get(0) else {
                continue;
            };
            let line = byte_line_from_starts(&self.starts, full.start());
            if path_traversal_finding_is_suppressed(arg.as_str(), &self.lines, line) {
                continue;
            }
            if !emitted.insert(line) {
                continue;
            }
            push_path_traversal_candidate_finding(self.file, line, arg.as_str(), findings);
        }
    }
}

fn constructor_regex() -> &'static Regex {
    static_regex(
        &PATH_TRAVERSAL_CONSTRUCTOR_REGEX,
        r"\b(?:Path|PathBuf)\s*::\s*(?:new|from)\s*\(\s*&?\s*(?P<arg>[a-z_][a-z0-9_]*)\s*\)",
    )
}

fn join_regex() -> &'static Regex {
    static_regex(
        &PATH_TRAVERSAL_JOIN_REGEX,
        r"\.join\s*\(\s*&?\s*(?P<arg>[a-z_][a-z0-9_]*)\s*\)",
    )
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

/// True iff `arg` appears in a nearby fn signature typed as `&Path` /
/// `&PathBuf` / `Path` / `PathBuf` / `impl AsRef<Path>`. Path-typed
/// parameters cannot carry an unconstrained string segment.
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
        .any(|source_line| line_has_path_typed_param(source_line, &needle))
}

fn line_has_path_typed_param(source_line: &str, needle: &str) -> bool {
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
/// `.starts_with(` (validate-then-trust pattern).
fn window_has_validation_after(lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let zero_based = line.saturating_sub(1);
    let end = (zero_based + 25).min(lines.len());
    let window: String = lines[zero_based..end].join("\n");
    window.contains(".canonicalize(") && window.contains(".starts_with(")
}

/// True iff `arg` was passed to a `(validate|verify|sanitize|check)_*`
/// call or `if arg.contains(...)` inline taint check in the 30 preceding
/// lines.
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
        .map(|compiled| compiled.is_match(window))
        .unwrap_or(false)
}

fn arg_has_inline_taint_check(arg: &str, window: &str) -> bool {
    let pattern = format!(r"if\s+{}\s*\.\s*contains\s*\(", regex::escape(arg));
    Regex::new(&pattern)
        .map(|compiled| compiled.is_match(window))
        .unwrap_or(false)
}

/// True iff `arg` is bound by `for ARG in [...]` or `for ARG in &ITER`
/// within the 3 preceding lines.
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
    let Some(after_in) = after_arg.trim_start().strip_prefix("in ") else {
        return false;
    };
    let trimmed_in = after_in.trim_start();
    trimmed_in.starts_with('[') || trimmed_in.starts_with('&')
}

/// True iff `arg` is bound to a string literal in the 4 preceding lines.
/// Detection runs against string-masked source, so `let ARG = "lit"` and
/// `let ARG = r"lit"` both appear as `let ARG = ;` after masking.
fn arg_is_let_bound_to_literal(arg: &str, lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let zero_based = line.saturating_sub(1);
    let lookback_start = zero_based.saturating_sub(4);
    let window: String = lines[lookback_start..=zero_based].join("\n");
    let needle = format!("let {arg}");
    let_rhs_is_whitespace_only(&window, &needle).unwrap_or(false)
}

fn let_rhs_is_whitespace_only(window: &str, needle: &str) -> Option<bool> {
    let let_pos = window.find(needle)?;
    let after = &window[let_pos + needle.len()..];
    let after_type = strip_type_annotation(after)?;
    let after_eq = after_type.trim_start().strip_prefix('=')?;
    let semicolon_pos = after_eq.find(';')?;
    Some(after_eq[..semicolon_pos].chars().all(char::is_whitespace))
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
