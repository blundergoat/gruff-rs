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
    PathTraversalScan::new(file, source).emit_findings(findings);
}

struct PathTraversalScan<'a> {
    file: &'a SourceFile,
    searchable: String,
    raw_lines: Vec<&'a str>,
    starts: Vec<usize>,
}

impl<'a> PathTraversalScan<'a> {
    fn new(file: &'a SourceFile, source: &'a str) -> Self {
        let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
        let raw_lines = source.lines().collect();
        let starts = line_starts(&searchable);
        Self {
            file,
            searchable,
            raw_lines,
            starts,
        }
    }

    fn emit_findings(&self, findings: &mut Vec<Finding>) {
        let lines: Vec<&str> = self.searchable.lines().collect();
        let mut emitted = std::collections::BTreeSet::new();
        self.scan_with(constructor_regex(), &lines, &mut emitted, findings);
        self.scan_with(join_regex(), &lines, &mut emitted, findings);
    }

    fn scan_with(
        &self,
        compiled: &Regex,
        lines: &[&str],
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
            if let Some(receiver) = captures.name("receiver") {
                if !join_receiver_has_filesystem_evidence(receiver.as_str(), lines, line) {
                    continue;
                }
            }
            if path_traversal_finding_is_suppressed(arg.as_str(), lines, &self.raw_lines, line) {
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
        r"\b(?P<receiver>(?:(?:std\s*::\s*path\s*::\s*)?(?:Path|PathBuf)\s*::\s*(?:new|from)\s*\([^;\n)]*\)|(?:self|[A-Za-z_][A-Za-z0-9_]*)(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*\(\s*\))?)*))\s*\.\s*join\s*\(\s*&?\s*(?P<arg>[a-z_][a-z0-9_]*)\s*\)",
    )
}

fn path_traversal_finding_is_suppressed(
    arg: &str,
    lines: &[&str],
    raw_lines: &[&str],
    line: usize,
) -> bool {
    path_traversal_arg_is_safe(arg)
        || arg_is_typed_path_in_nearby_signature(arg, lines, line)
        || arg_is_loop_var_from_literal_array(arg, lines, line)
        || arg_is_let_bound_to_literal(arg, lines, line)
        || arg_is_sanitized_segment_binding(arg, raw_lines, line)
        || arg_was_validated_in_nearby_call(arg, lines, line)
        || window_has_validation_after(lines, line)
}

fn join_receiver_has_filesystem_evidence(receiver: &str, lines: &[&str], line: usize) -> bool {
    let normalized: String = receiver
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if receiver_is_inline_path_constructor(&normalized) {
        return true;
    }
    let Some(segment) = normalized.rsplit('.').next() else {
        return false;
    };
    // Strip a trailing accessor call so `self.root()` resolves to `root`.
    let name = segment.strip_suffix("()").unwrap_or(segment);
    path_traversal_receiver_name_is_filesystem(name)
        || arg_is_typed_path_in_nearby_signature(name, lines, line)
        || receiver_is_path_binding(name, lines, line)
}

fn receiver_is_inline_path_constructor(receiver: &str) -> bool {
    let receiver = receiver.strip_prefix("std::path::").unwrap_or(receiver);
    receiver.starts_with("PathBuf::from(") || receiver.starts_with("Path::new(")
}

fn path_traversal_receiver_name_is_filesystem(name: &str) -> bool {
    matches!(
        name,
        "root"
            | "project_root"
            | "workspace_root"
            | "repo_root"
            | "crate_root"
            | "base"
            | "base_dir"
            | "base_path"
            | "dir"
            | "directory"
            | "out_dir"
            | "target_dir"
            | "manifest_dir"
            | "temp_dir"
            | "tmp_dir"
    )
}

fn receiver_is_path_binding(receiver: &str, lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let zero_based = line.saturating_sub(1);
    let lookback_start = zero_based.saturating_sub(12);
    let window: String = lines[lookback_start..=zero_based].join("\n");
    ["let ", "let mut "]
        .iter()
        .any(|prefix| window_has_receiver_path_binding(&window, prefix, receiver))
}

/// True when `window` binds exactly `receiver` (after `prefix`) to a filesystem
/// path. A non-identifier char must follow the name so a `files` receiver is not
/// proven by an unrelated `files_backup` binding, and `let mut` bindings count.
fn window_has_receiver_path_binding(window: &str, prefix: &str, receiver: &str) -> bool {
    let needle = format!("{prefix}{receiver}");
    let mut search_from = 0;
    while let Some(position) = window[search_from..].find(&needle) {
        let after_name = search_from + position + needle.len();
        search_from = after_name;
        if boundary_is_word_break(window, after_name)
            && statement_after_is_path_binding(&window[after_name..])
        {
            return true;
        }
    }
    false
}

/// True when the char at `index` is not an identifier char, so a name match ends
/// on a word boundary (`files` must not match inside `files_backup`).
fn boundary_is_word_break(window: &str, index: usize) -> bool {
    !window[index..]
        .chars()
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphanumeric())
}

/// True when the statement starting at `after` (up to the next `;`) assigns a
/// filesystem path via `PathBuf::from`/`Path::new` or a `: Path` type annotation.
fn statement_after_is_path_binding(after: &str) -> bool {
    let Some(end) = after.find(';') else {
        return false;
    };
    let statement = &after[..end];
    statement.contains("PathBuf::from(")
        || statement.contains("Path::new(")
        || statement.trim_start().starts_with(": Path")
        || statement.trim_start().starts_with(": std::path::Path")
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
            | "manifest_dir"
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

/// True iff the 25 lines after `line` show the validate-then-trust pattern:
/// `.canonicalize()` (which resolves `..`) paired with a containment check
/// (`.starts_with(` or `.strip_prefix(`). Canonicalization is required —
/// `.strip_prefix(root)` on an un-canonicalized path is purely lexical and
/// does not stop `..` traversal, and a lone `.strip_prefix(` may be an
/// unrelated `str::strip_prefix`, so neither counts as validation on its own.
fn window_has_validation_after(lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let zero_based = line.saturating_sub(1);
    let end = (zero_based + 25).min(lines.len());
    let window: String = lines[zero_based..end].join("\n");
    window.contains(".canonicalize(")
        && (window.contains(".starts_with(") || window.contains(".strip_prefix("))
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

/// True iff `arg` is bound by `for ARG in [LIT, ...]` or
/// `for ARG in &[LIT, ...]` within the 3 preceding lines. Iterating over
/// any other reference (e.g. `for x in &user_supplied_paths`) is not
/// suppressed - the source of the iterator may be attacker-controlled.
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
    trimmed_in.starts_with('[') || trimmed_in.starts_with("&[")
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

fn arg_is_sanitized_segment_binding(arg: &str, raw_lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let zero_based = line.saturating_sub(1);
    let lookback_start = zero_based.saturating_sub(12);
    let window: String = raw_lines[lookback_start..=zero_based].join("\n");
    let pattern = format!(
        r"(?s)\blet\s+(?:mut\s+)?{}\b(?:\s*:\s*[^=;]+)?\s*=\s*(?P<rhs>[^;]+);",
        regex::escape(arg)
    );
    let Ok(compiled) = Regex::new(&pattern) else {
        return false;
    };
    let Some(captures) = compiled.captures(&window) else {
        return false;
    };
    let Some(rhs) = captures.name("rhs") else {
        return false;
    };
    is_segment_sanitizer_for_traversal(rhs.as_str())
}

fn is_segment_sanitizer_for_traversal(rhs: &str) -> bool {
    let compact: String = rhs
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let removes_parent = compact.contains(r#".replace("..","#);
    let removes_forward =
        compact.contains(r#".replace('/',"#) || compact.contains(r#".replace("/","#);
    let removes_back =
        compact.contains(r#".replace('\\',"#) || compact.contains(r#".replace("\\","#);
    removes_parent && removes_forward && removes_back
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
            "Validate the segment with `Path::components`, reject `..` and absolute paths, or canonicalise and re-check the prefix. If this call is in a test that intentionally constructs untrusted paths, add the host path to `paths.ignore` in `.gruff-rs.yaml`."
                .to_string(),
        ),
        metadata: json!({ "argument": arg }),
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The candidate `.join(...)` sits on line 1; validation is searched from
    /// there across the following lines.
    fn validated_after_join(lines: &[&str]) -> bool {
        window_has_validation_after(lines, 1)
    }

    #[test]
    fn canonicalize_with_containment_check_counts_as_validation() {
        assert!(validated_after_join(&[
            "let joined = root.join(name);",
            "let real = joined.canonicalize()?;",
            "if real.starts_with(&root) { ok() }",
        ]));
        assert!(validated_after_join(&[
            "let joined = root.join(name);",
            "let real = joined.canonicalize()?;",
            "real.strip_prefix(&root)?;",
        ]));
    }

    #[test]
    fn strip_prefix_without_canonicalize_is_not_validation() {
        // Lexical strip_prefix on an un-canonicalized path does not stop `..`.
        assert!(!validated_after_join(&[
            "let joined = root.join(name);",
            "joined.strip_prefix(&root)?;",
        ]));
        // An unrelated str::strip_prefix must not suppress the candidate.
        assert!(!validated_after_join(&[
            "let joined = root.join(name);",
            "let token = header.strip_prefix(\"Bearer \");",
        ]));
        // canonicalize alone, with no containment check, is not enough.
        assert!(!validated_after_join(&[
            "let joined = root.join(name);",
            "let real = joined.canonicalize()?;",
        ]));
    }
}
