use super::*;

pub(crate) fn analyse_performance_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    let code_only_body = strip_rust_comments_after_string_mask(searchable_body);
    for check in PERFORMANCE_CHECKS {
        let regex = static_regex(check.regex, check.pattern);
        let occurrences = loop_pattern_count_filtered(&code_only_body, regex, |line| {
            should_count_perf_line(check.rule_id, line)
        });
        if occurrences > 0 {
            push_performance_finding(file, block, check, occurrences, findings);
        }
    }
}

/// Returns true when the line genuinely represents a wasteful in-loop
/// call. Lines that look structural (struct-field initialisers, owned
/// API arguments, `Finding::new(...)` builders, format-as-message
/// constructors) are excluded so the rule fires only on real per-tick
/// allocations. Distinct from the broader `waste.*` guard: per-iteration
/// `let _owned = value.clone();` IS the canonical hoist-able waste this
/// rule is designed to catch.
fn should_count_perf_line(rule_id: &str, line: &str) -> bool {
    match rule_id {
        "performance.clone-in-loop" => !clone_is_structural_in_loop(line),
        "performance.format-in-loop" => !format_is_owned_value(line),
        _ => true,
    }
}

/// Narrower clone exemption for `performance.clone-in-loop`. Only the
/// strictly structural patterns (struct field, `Some()` wrap, hashmap
/// key, multi-line method-chain continuation) are skipped — let-bindings
/// and standalone clones in the loop body still fire.
fn clone_is_structural_in_loop(line: &str) -> bool {
    PERF_CLONE_STRUCTURAL_PATTERNS
        .iter()
        .any(|pattern| pattern.matches(line))
}

static PERF_FIELD_REGEX: OnceLock<Regex> = OnceLock::new();
static PERF_SOME_REGEX: OnceLock<Regex> = OnceLock::new();
static PERF_LOOKUP_REGEX: OnceLock<Regex> = OnceLock::new();
static PERF_CHAIN_REGEX: OnceLock<Regex> = OnceLock::new();

const PERF_CLONE_STRUCTURAL_PATTERNS: &[CloneOwnershipPattern] = &[
    CloneOwnershipPattern {
        cell: &PERF_FIELD_REGEX,
        pattern: r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s+[^=]*\.clone\(\)\s*\)*\s*,?\s*$",
    },
    CloneOwnershipPattern {
        cell: &PERF_SOME_REGEX,
        pattern: r"\bSome\(\s*[^()]*\.clone\(\)\s*\)",
    },
    CloneOwnershipPattern {
        cell: &PERF_LOOKUP_REGEX,
        pattern: r"\.(?:entry|insert)\(\s*&?\s*\(?[^=;]*\.clone\(\)[^;]*\)",
    },
    CloneOwnershipPattern {
        cell: &PERF_CHAIN_REGEX,
        pattern: r"^\s*\.clone\(\)\s*$",
    },
];

/// Returns true when a `format!()` call sits in a position whose caller
/// requires an owned `String` (struct field initialiser, error message
/// returned via `Err(format!(...))`, `return` expression, or
/// `String::push_str(&format!())` text-buffer growth). It also skips
/// standalone multi-line `format!` arguments and match arms used to
/// assemble labels/messages for report output. These uses are
/// not avoidable: each iteration legitimately produces a distinct owned
/// string and there is no shared buffer to hoist into. Note that
/// same-line `Vec::push(format!())` IS still flagged — that pattern
/// usually signals collecting per-item strings that could be hoisted to
/// `.iter().map(...).collect()`.
fn format_is_owned_value(line: &str) -> bool {
    FORMAT_OWNED_VALUE_PATTERNS
        .iter()
        .any(|pattern| pattern.matches(line))
}

static FORMAT_FIELD_REGEX: OnceLock<Regex> = OnceLock::new();
static FORMAT_ERR_REGEX: OnceLock<Regex> = OnceLock::new();
static FORMAT_RETURN_REGEX: OnceLock<Regex> = OnceLock::new();
static FORMAT_PUSH_STR_REGEX: OnceLock<Regex> = OnceLock::new();
static FORMAT_STANDALONE_ARGUMENT_REGEX: OnceLock<Regex> = OnceLock::new();
static FORMAT_MATCH_ARM_REGEX: OnceLock<Regex> = OnceLock::new();
static FORMAT_LABEL_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();

const FORMAT_OWNED_VALUE_PATTERNS: &[CloneOwnershipPattern] = &[
    CloneOwnershipPattern {
        cell: &FORMAT_FIELD_REGEX,
        pattern: r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s+[^=]*format!\s*\(",
    },
    CloneOwnershipPattern {
        cell: &FORMAT_ERR_REGEX,
        pattern: r"\bErr\(\s*format!\s*\(",
    },
    CloneOwnershipPattern {
        cell: &FORMAT_RETURN_REGEX,
        pattern: r"^\s*return\s+format!\s*\(",
    },
    CloneOwnershipPattern {
        cell: &FORMAT_PUSH_STR_REGEX,
        pattern: r"\.(?:push_str|insert_str|write_str|write_all|write_fmt)\s*\(\s*&?\s*format!\s*\(",
    },
    CloneOwnershipPattern {
        cell: &FORMAT_STANDALONE_ARGUMENT_REGEX,
        pattern: r"^\s*&?format!\s*\(",
    },
    CloneOwnershipPattern {
        cell: &FORMAT_MATCH_ARM_REGEX,
        pattern: r"^\s*[^=;]+=>\s*&?format!\s*\(",
    },
    CloneOwnershipPattern {
        cell: &FORMAT_LABEL_BINDING_REGEX,
        pattern: r"^\s*let\s+[A-Za-z_][A-Za-z0-9_]*(?:label|message|desc|summary|title|name)[A-Za-z0-9_]*\s*=\s*&?format!\s*\(",
    },
];

pub(crate) fn push_performance_finding(
    file: &SourceFile,
    block: &FunctionBlock,
    check: &PerformanceCheck,
    occurrences: usize,
    findings: &mut Vec<Finding>,
) {
    findings.push(block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: check.rule_id,
            message: format!(
                "Function `{}` calls {} inside a loop {} time(s).",
                block.name, check.label, occurrences
            ),
            file,
            block,
            severity: check.severity,
            pillar: Pillar::Waste,
        },
        BlockFindingExtras {
            confidence: check.confidence,
            remediation: Some(check.remediation.to_string()),
            metadata: json!({ "pattern": check.label, "occurrences": occurrences }),
        },
    ));
}
