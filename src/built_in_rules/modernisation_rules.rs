use super::*;

pub(crate) static MANUAL_CONTAINS_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static MANUAL_STRIP_PREFIX_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static MANUAL_UNWRAP_OR_DEFAULT_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static QUESTION_MARK_MATCH_OK_FIRST_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static QUESTION_MARK_MATCH_ERR_FIRST_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static QUESTION_MARK_IF_LET_REGEX: OnceLock<Regex> = OnceLock::new();

/// Entry point for the `modernisation.*` rules. Each rule scans the
/// comment-stripped source to avoid matching inside string literals or
/// doc comments.
///
/// `file` is the file reported on, `source` its unmasked text, and each of the four rules appends what it finds to `findings`.
pub(crate) fn analyse_modernisation_rules(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    analyse_manual_contains(file, &searchable, findings);
    analyse_manual_strip_prefix(file, &searchable, findings);
    analyse_manual_unwrap_or_default(file, &searchable, findings);
    analyse_question_mark_candidate(file, &searchable, findings);
}

/// `iter().any(|x| *x == y)` and `iter().any(|x| x == &y)` should use
/// `.contains(&y)`. See `manual_contains_match_is_valid` for the
/// closure-arg / comparand binding check.
///
/// `file` is the file reported on and `searchable` its text with string literals and comments masked.
/// Each advisory finding is appended to `findings`.
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
        remediation: "Replace the manual membership check with the collection's `contains` method.",
    };
    scan_modernisation_matches(&check, searchable, file, findings);
}

/// Confirm that a manual-contains match compares the closure's own argument rather than some other name.
///
/// `captures` holds the `arg` capture and either the `deref` or the `noderef` comparand capture.
/// Returns true when `arg` is non-empty and equals the comparand, so `|x| *x == y` qualifies but `|x| *y == x` does not.
fn manual_contains_match_is_valid(captures: &regex::Captures<'_>) -> bool {
    let arg = capture_named(captures, "arg");
    let lhs = match capture_named(captures, "deref") {
        "" => capture_named(captures, "noderef"),
        deref => deref,
    };
    !arg.is_empty() && arg == lhs
}

/// `if s.starts_with(p) { &s[p.len()..] }` should use `s.strip_prefix(p)`.
///
/// `file` is the file reported on and `searchable` its text with string literals and comments masked.
/// Each advisory finding is appended to `findings`.
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
        remediation: "Replace the `starts_with` check and manual slice with `strip_prefix`, which returns the remainder only when the prefix matches.",
    };
    scan_modernisation_matches(&check, searchable, file, findings);
}

/// Confirm that a manual strip-prefix match slices the same string by the same prefix it tested.
///
/// `captures` holds the `first` and `second` names from the `starts_with` call and their repeats in the slice.
/// Returns true only when both names are non-empty and each repeat equals its original.
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
///
/// `file` is the file reported on and `searchable` its text with string literals and comments masked.
/// Each advisory finding is appended to `findings`.
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
        remediation: "Replace the manual match or `unwrap_or` with `unwrap_or_default()`.",
    };
    scan_modernisation_matches(&check, searchable, file, findings);
}

/// Confirm that a manual unwrap-or-default match returns the value its `Some` arm binds.
///
/// `captures` holds the `arg` bound by `Some(...)` and the `ret` name that arm returns.
/// Returns true when `arg` is non-empty and equals `ret`.
fn manual_unwrap_or_default_match_is_valid(captures: &regex::Captures<'_>) -> bool {
    let arg = capture_named(captures, "arg");
    !arg.is_empty() && arg == capture_named(captures, "ret")
}

/// Three Result-propagation shapes that should use `?`:
/// - `match res { Ok(v) => v, Err(e) => return Err(e) }`
/// - `match res { Err(e) => return Err(e), Ok(v) => v }`
/// - `if let Err(e) = f() { return Err(e); }`
///
/// `file` is the file reported on and `searchable` its text with string literals and comments masked.
/// Each advisory finding is appended to `findings`.
pub(crate) fn analyse_question_mark_candidate(
    file: &SourceFile,
    searchable: &str,
    findings: &mut Vec<Finding>,
) {
    for check in question_mark_checks() {
        scan_question_mark(check, searchable, file, findings);
    }
}

/// List the three `?`-candidate shapes, each paired with the check that its bound names repeat.
///
/// Returns the Ok-first `match`, the Err-first `match` and the `if let Err` checks, in that order.
fn question_mark_checks() -> [QuestionMarkCheck; 3] {
    [
        QuestionMarkCheck {
            compiled: question_mark_ok_first_regex(),
            is_valid: is_match_arm_balanced,
        },
        QuestionMarkCheck {
            compiled: question_mark_err_first_regex(),
            is_valid: is_match_arm_balanced,
        },
        QuestionMarkCheck {
            compiled: question_mark_if_let_regex(),
            is_valid: is_if_let_balanced,
        },
    ]
}

/// Compile once the pattern for a `match` that lists an `Ok` arm yielding its binding before an `Err` arm returning `Err(..)`.
///
/// Returns the shared compiled regex, with `ok_a`, `ok_b`, `err_a` and `err_b` captures for the binding check.
fn question_mark_ok_first_regex() -> &'static Regex {
    static_regex(
        &QUESTION_MARK_MATCH_OK_FIRST_REGEX,
        r"match\s+[A-Za-z_][\w\.()]*\s*\{\s*Ok\s*\(\s*(?P<ok_a>[A-Za-z_]\w*)\s*\)\s*=>\s*(?P<ok_b>[A-Za-z_]\w*)\s*,\s*Err\s*\(\s*(?P<err_a>[A-Za-z_]\w*)\s*\)\s*=>\s*return\s+Err\s*\(\s*(?P<err_b>[A-Za-z_]\w*)\s*\)\s*,?\s*\}",
    )
}

/// Compile once the pattern for a `match` that lists an `Err` arm returning `Err(..)` before an `Ok` arm yielding its binding.
///
/// Returns the shared compiled regex, with `err_a`, `err_b`, `ok_a` and `ok_b` captures for the binding check.
fn question_mark_err_first_regex() -> &'static Regex {
    static_regex(
        &QUESTION_MARK_MATCH_ERR_FIRST_REGEX,
        r"match\s+[A-Za-z_][\w\.()]*\s*\{\s*Err\s*\(\s*(?P<err_a>[A-Za-z_]\w*)\s*\)\s*=>\s*return\s+Err\s*\(\s*(?P<err_b>[A-Za-z_]\w*)\s*\)\s*,\s*Ok\s*\(\s*(?P<ok_a>[A-Za-z_]\w*)\s*\)\s*=>\s*(?P<ok_b>[A-Za-z_]\w*)\s*,?\s*\}",
    )
}

/// Compile once the pattern for `if let Err(e) = expr { return Err(e); }` with nothing else in the block.
///
/// Returns the shared compiled regex, with `e` and `e2` captures for the binding check.
fn question_mark_if_let_regex() -> &'static Regex {
    static_regex(
        &QUESTION_MARK_IF_LET_REGEX,
        r"if\s+let\s+Err\s*\(\s*(?P<e>[A-Za-z_]\w*)\s*\)\s*=\s*[^{;]+?\s*\{\s*return\s+Err\s*\(\s*(?P<e2>[A-Za-z_]\w*)\s*\)\s*;?\s*\}",
    )
}

struct QuestionMarkCheck {
    compiled: &'static Regex,
    is_valid: fn(&regex::Captures<'_>) -> bool,
}

/// Confirm that a `match` candidate yields the value its `Ok` arm binds and returns the error its `Err` arm binds.
///
/// `captures` holds the `ok_a`, `ok_b`, `err_a` and `err_b` names from either `match` pattern.
/// Returns true when both bindings are non-empty, `ok_a` equals `ok_b` and `err_a` equals `err_b`.
fn is_match_arm_balanced(captures: &regex::Captures<'_>) -> bool {
    let ok_a = capture_named(captures, "ok_a");
    let err_a = capture_named(captures, "err_a");
    !ok_a.is_empty()
        && !err_a.is_empty()
        && ok_a == capture_named(captures, "ok_b")
        && err_a == capture_named(captures, "err_b")
}

/// Confirm that an `if let Err` candidate returns the same error it binds.
///
/// `captures` holds the bound name `e` and the returned name `e2`.
/// Returns true when `e` is non-empty and equals `e2`.
fn is_if_let_balanced(captures: &regex::Captures<'_>) -> bool {
    let first = capture_named(captures, "e");
    !first.is_empty() && first == capture_named(captures, "e2")
}

/// Report a `modernisation.question-mark-candidate` finding for every match of one `?` shape that passes its binding check.
///
/// `check` pairs the shape's regex with its binding check, and `searchable` is the masked text it runs over.
/// `file` is the file reported on, and each advisory finding, on the line where the match starts, is appended to `findings`.
fn scan_question_mark(
    check: QuestionMarkCheck,
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
        push_modernisation_finding(
            file,
            line,
            "modernisation.question-mark-candidate",
            "Use `?` instead of a manual `match` / `if let Err` that returns the same error.",
            "Replace the manual match that returns the error or None with the `?` operator.",
            findings,
        );
    }
}

struct ModernisationCheck {
    compiled: &'static Regex,
    is_valid: fn(&regex::Captures<'_>) -> bool,
    rule_id: &'static str,
    message: &'static str,
    remediation: &'static str,
}

/// Report one finding for every match of a modernisation rule's pattern that passes the rule's binding check.
///
/// `check` carries the rule's regex, binding check, rule id, message and remediation, and `searchable` is the masked text it runs over.
/// `file` is the file reported on, and each advisory finding, on the line where the match starts, is appended to `findings`.
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
        push_modernisation_finding(
            file,
            line,
            check.rule_id,
            check.message,
            check.remediation,
            findings,
        );
    }
}

/// Read one named capture group as text, treating a missing group as empty.
///
/// `captures` is one regex match and `name` the group to read.
/// Returns the group's matched text, or an empty string when the group did not take part in the match or does not exist.
fn capture_named<'a>(captures: &regex::Captures<'a>, name: &str) -> &'a str {
    captures.name(name).map(|m| m.as_str()).unwrap_or("")
}

/// Build one modernisation finding with its remediation text and append it to the caller's list.
///
/// `file` and the 1-based `line` locate the finding, and `rule_id`, `message` and `remediation` fill its text.
/// The finding is advisory, in the modernisation pillar, and is appended to `findings`.
fn push_modernisation_finding(
    file: &SourceFile,
    line: usize,
    rule_id: &'static str,
    message: &'static str,
    remediation: &'static str,
    findings: &mut Vec<Finding>,
) {
    let mut result = finding(SimpleFindingDescriptor {
        rule_id,
        message: message.into(),
        file,
        line: Some(line),
        severity: Severity::Advisory,
        pillar: Pillar::Modernisation,
    });
    result.remediation = Some(remediation.to_string());
    findings.push(result);
}
