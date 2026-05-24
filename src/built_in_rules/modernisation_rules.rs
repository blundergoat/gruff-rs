use super::*;

pub(crate) static MANUAL_IS_EMPTY_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static MANUAL_CONTAINS_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static MANUAL_STRIP_PREFIX_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static MANUAL_UNWRAP_OR_DEFAULT_REGEX: OnceLock<Regex> = OnceLock::new();

/// Entry point for the four `modernisation.manual-*` rules. Each rule
/// scans the comment-stripped source to avoid matching inside string
/// literals or doc comments.
pub(crate) fn analyse_modernisation_rules(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    analyse_manual_is_empty(file, &searchable, findings);
    analyse_manual_contains(file, &searchable, findings);
    analyse_manual_strip_prefix(file, &searchable, findings);
    analyse_manual_unwrap_or_default(file, &searchable, findings);
}

/// `coll.len() == 0`, `coll.len() != 0`, and the swapped forms should
/// use `is_empty()` / `!is_empty()`. Matches the comparison shape even
/// when the receiver is a method chain (`self.cache.len() == 0`). Stays
/// silent for non-zero comparisons.
pub(crate) fn analyse_manual_is_empty(
    file: &SourceFile,
    searchable: &str,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &MANUAL_IS_EMPTY_REGEX,
        r"(?:\.len\s*\(\s*\)\s*(?:==|!=)\s*0\b|\b0\s*(?:==|!=)\s*[A-Za-z_][\w\.]*\.len\s*\(\s*\))",
    );
    for (line_index, line) in searchable.lines().enumerate() {
        if regex.is_match(line) {
            findings.push(finding(SimpleFindingDescriptor {
                rule_id: "modernisation.manual-is-empty",
                message: "Use `.is_empty()` instead of comparing `.len()` against zero.".into(),
                file,
                line: Some(line_index + 1),
                severity: Severity::Advisory,
                pillar: Pillar::Modernisation,
            }));
        }
    }
}

/// `iter().any(|x| x == y)` and the dereference variant `|x| *x == y`
/// should use `.contains(&y)`. Requires that the closure parameter is the
/// left-hand side of the comparison so we do not flag closures whose
/// argument is unrelated to the comparison (`|_| target == other`).
pub(crate) fn analyse_manual_contains(
    file: &SourceFile,
    searchable: &str,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &MANUAL_CONTAINS_REGEX,
        r"\.iter\s*\(\s*\)\s*\.any\s*\(\s*\|\s*(?P<arg>[A-Za-z_][A-Za-z0-9_]*)\s*\|\s*\*?\s*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*==\s*[A-Za-z_&][\w\.]*\s*\)",
    );
    let line_starts = line_starts(searchable);
    for captures in regex.captures_iter(searchable) {
        let arg = captures
            .name("arg")
            .map(|capture| capture.as_str())
            .unwrap_or("");
        let lhs = captures
            .name("lhs")
            .map(|capture| capture.as_str())
            .unwrap_or("");
        if arg != lhs {
            continue;
        }
        let Some(full) = captures.get(0) else {
            continue;
        };
        let line = byte_line_from_starts(&line_starts, full.start());
        findings.push(finding(SimpleFindingDescriptor {
            rule_id: "modernisation.manual-contains",
            message: "Use `.contains(&value)` instead of `.iter().any(|x| x == value)`.".into(),
            file,
            line: Some(line),
            severity: Severity::Advisory,
            pillar: Pillar::Modernisation,
        }));
    }
}

/// `if s.starts_with(p) { &s[p.len()..] }` should use `s.strip_prefix(p)`.
/// Matches the slice-return shape only; longer multi-statement bodies are
/// intentionally NOT detected because slicing semantics may differ once
/// other statements run.
pub(crate) fn analyse_manual_strip_prefix(
    file: &SourceFile,
    searchable: &str,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &MANUAL_STRIP_PREFIX_REGEX,
        r"if\s+(?P<a>[A-Za-z_][A-Za-z0-9_]*)\s*\.starts_with\s*\(\s*(?P<b>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\{\s*&\s*(?P<a2>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<b2>[A-Za-z_][A-Za-z0-9_]*)\s*\.len\s*\(\s*\)\s*\.\.\s*\]",
    );
    let line_starts = line_starts(searchable);
    for captures in regex.captures_iter(searchable) {
        let a = captures
            .name("a")
            .map(|capture| capture.as_str())
            .unwrap_or("");
        let b = captures
            .name("b")
            .map(|capture| capture.as_str())
            .unwrap_or("");
        let a2 = captures
            .name("a2")
            .map(|capture| capture.as_str())
            .unwrap_or("");
        let b2 = captures
            .name("b2")
            .map(|capture| capture.as_str())
            .unwrap_or("");
        if a != a2 || b != b2 {
            continue;
        }
        let Some(full) = captures.get(0) else {
            continue;
        };
        let line = byte_line_from_starts(&line_starts, full.start());
        findings.push(finding(SimpleFindingDescriptor {
            rule_id: "modernisation.manual-strip-prefix",
            message: "Use `strip_prefix` instead of slicing after `starts_with`.".into(),
            file,
            line: Some(line),
            severity: Severity::Advisory,
            pillar: Pillar::Modernisation,
        }));
    }
}

/// `match opt { Some(v) => v, None => Default::default() }` and variants
/// using `String::new()`, `Vec::new()`, `0`, or `""` for the `None` arm
/// should use `opt.unwrap_or_default()`.
pub(crate) fn analyse_manual_unwrap_or_default(
    file: &SourceFile,
    searchable: &str,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &MANUAL_UNWRAP_OR_DEFAULT_REGEX,
        r"match\s+[A-Za-z_][\w\.]*\s*\{\s*Some\s*\(\s*(?P<arg>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=>\s*(?P<ret>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*None\s*=>\s*(?:Default\s*::\s*default\s*\(\s*\)|String\s*::\s*new\s*\(\s*\)|Vec\s*::\s*new\s*\(\s*\)|0|0_[a-z0-9]+)\s*,?\s*\}",
    );
    let line_starts = line_starts(searchable);
    for captures in regex.captures_iter(searchable) {
        let arg = captures
            .name("arg")
            .map(|capture| capture.as_str())
            .unwrap_or("");
        let ret = captures
            .name("ret")
            .map(|capture| capture.as_str())
            .unwrap_or("");
        if arg != ret {
            continue;
        }
        let Some(full) = captures.get(0) else {
            continue;
        };
        let line = byte_line_from_starts(&line_starts, full.start());
        findings.push(finding(SimpleFindingDescriptor {
            rule_id: "modernisation.manual-unwrap-or-default",
            message:
                "Use `.unwrap_or_default()` instead of a manual `match` with `Default::default()`."
                    .into(),
            file,
            line: Some(line),
            severity: Severity::Advisory,
            pillar: Pillar::Modernisation,
        }));
    }
}
