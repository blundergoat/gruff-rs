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
/// use `is_empty()`. Stays silent for non-zero comparisons.
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
            push_modernisation_finding(
                file,
                line_index + 1,
                "modernisation.manual-is-empty",
                "Use `.is_empty()` instead of comparing `.len()` against zero.",
                findings,
            );
        }
    }
}

/// `iter().any(|x| *x == y)` and `iter().any(|x| x == &y)` should use
/// `.contains(&y)`. See `manual_contains_match_is_valid` for the
/// closure-arg / comparand binding check.
pub(crate) fn analyse_manual_contains(
    file: &SourceFile,
    searchable: &str,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &MANUAL_CONTAINS_REGEX,
        r"\.iter\s*\(\s*\)\s*\.any\s*\(\s*\|\s*(?P<arg>[A-Za-z_][A-Za-z0-9_]*)\s*\|\s*(?:\*\s*(?P<deref>[A-Za-z_][A-Za-z0-9_]*)\s*==\s*[A-Za-z_][\w\.]*|(?P<noderef>[A-Za-z_][A-Za-z0-9_]*)\s*==\s*&\s*[A-Za-z_][\w\.]*)\s*\)",
    );
    let check = ModernisationCheck {
        compiled: regex,
        is_valid: manual_contains_match_is_valid,
        rule_id: "modernisation.manual-contains",
        message: "Use `.contains(&value)` instead of `.iter().any(|x| x == &value)`.",
    };
    scan_modernisation_matches(&check, searchable, file, findings);
}

fn manual_contains_match_is_valid(captures: &regex::Captures<'_>) -> bool {
    let arg = capture_named(captures, "arg");
    let lhs = match capture_named(captures, "deref") {
        "" => capture_named(captures, "noderef"),
        deref => deref,
    };
    !arg.is_empty() && arg == lhs
}

/// `if s.starts_with(p) { &s[p.len()..] }` should use `s.strip_prefix(p)`.
pub(crate) fn analyse_manual_strip_prefix(
    file: &SourceFile,
    searchable: &str,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &MANUAL_STRIP_PREFIX_REGEX,
        r"if\s+(?P<first>[A-Za-z_][A-Za-z0-9_]*)\s*\.starts_with\s*\(\s*(?P<second>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\{\s*&\s*(?P<first_again>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<second_again>[A-Za-z_][A-Za-z0-9_]*)\s*\.len\s*\(\s*\)\s*\.\.\s*\]",
    );
    let check = ModernisationCheck {
        compiled: regex,
        is_valid: manual_strip_prefix_match_is_valid,
        rule_id: "modernisation.manual-strip-prefix",
        message: "Use `strip_prefix` instead of slicing after `starts_with`.",
    };
    scan_modernisation_matches(&check, searchable, file, findings);
}

fn manual_strip_prefix_match_is_valid(captures: &regex::Captures<'_>) -> bool {
    let first = capture_named(captures, "first");
    let second = capture_named(captures, "second");
    !first.is_empty()
        && !second.is_empty()
        && first == capture_named(captures, "first_again")
        && second == capture_named(captures, "second_again")
}

/// `match opt { Some(v) => v, None => Default::default() }` and variants
/// using `String::new()`, `Vec::new()`, or `0` should use
/// `opt.unwrap_or_default()`.
pub(crate) fn analyse_manual_unwrap_or_default(
    file: &SourceFile,
    searchable: &str,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &MANUAL_UNWRAP_OR_DEFAULT_REGEX,
        r"match\s+[A-Za-z_][\w\.]*\s*\{\s*Some\s*\(\s*(?P<arg>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=>\s*(?P<ret>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*None\s*=>\s*(?:Default\s*::\s*default\s*\(\s*\)|String\s*::\s*new\s*\(\s*\)|Vec\s*::\s*new\s*\(\s*\)|0|0_[a-z0-9]+)\s*,?\s*\}",
    );
    let check = ModernisationCheck {
        compiled: regex,
        is_valid: manual_unwrap_or_default_match_is_valid,
        rule_id: "modernisation.manual-unwrap-or-default",
        message:
            "Use `.unwrap_or_default()` instead of a manual `match` with `Default::default()`.",
    };
    scan_modernisation_matches(&check, searchable, file, findings);
}

fn manual_unwrap_or_default_match_is_valid(captures: &regex::Captures<'_>) -> bool {
    let arg = capture_named(captures, "arg");
    !arg.is_empty() && arg == capture_named(captures, "ret")
}

struct ModernisationCheck {
    compiled: &'static Regex,
    is_valid: fn(&regex::Captures<'_>) -> bool,
    rule_id: &'static str,
    message: &'static str,
}

fn scan_modernisation_matches(
    check: &ModernisationCheck,
    searchable: &str,
    file: &SourceFile,
    findings: &mut Vec<Finding>,
) {
    let starts = line_starts(searchable);
    for captures in check.compiled.captures_iter(searchable) {
        if !(check.is_valid)(&captures) {
            continue;
        }
        let Some(full) = captures.get(0) else {
            continue;
        };
        let line = byte_line_from_starts(&starts, full.start());
        push_modernisation_finding(file, line, check.rule_id, check.message, findings);
    }
}

fn capture_named<'a>(captures: &regex::Captures<'a>, name: &str) -> &'a str {
    captures.name(name).map(|m| m.as_str()).unwrap_or("")
}

fn push_modernisation_finding(
    file: &SourceFile,
    line: usize,
    rule_id: &'static str,
    message: &'static str,
    findings: &mut Vec<Finding>,
) {
    findings.push(finding(SimpleFindingDescriptor {
        rule_id,
        message: message.into(),
        file,
        line: Some(line),
        severity: Severity::Advisory,
        pillar: Pillar::Modernisation,
    }));
}
