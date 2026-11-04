use super::*;

/// Run every performance check over one function body and record a finding for each check whose loop-pattern count is above zero.
///
/// `file` and `block` are the source file and function the findings point at, and `searchable_body` is the body text to search.
/// Rust comments are stripped from `searchable_body` before any pattern is counted.
///
/// `findings` gains one finding per check in `PERFORMANCE_CHECKS` whose pattern `loop_pattern_count_filtered` counts at least once.
/// That helper decides which loops count; this function calls it with a filter that accepts everything.
pub(crate) fn analyse_performance_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    let code_only_body = strip_rust_comments_after_string_mask(searchable_body);
    for check in PERFORMANCE_CHECKS {
        let regex = static_regex(check.regex, check.pattern);
        let occurrences = loop_pattern_count_filtered(&code_only_body, regex, |_| true);
        if occurrences > 0 {
            push_performance_finding(file, block, check, occurrences, findings);
        }
    }
}

/// Record one maintainability finding for a performance check whose pattern a function calls inside a loop.
///
/// `file` and `block` locate the finding, and the function name from `block` appears in its message.
/// `check` supplies the rule id, label, severity, confidence and remediation text.
/// `occurrences` is the in-loop match count shown in the message and metadata, and the new finding is appended to `findings`.
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
            pillar: Pillar::Maintainability,
        },
        BlockFindingExtras {
            confidence: check.confidence,
            remediation: Some(check.remediation.to_string()),
            metadata: json!({ "pattern": check.label, "occurrences": occurrences }),
        },
    ));
}
