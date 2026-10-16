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
        let occurrences = loop_pattern_count_filtered(&code_only_body, regex, |_| true);
        if occurrences > 0 {
            push_performance_finding(file, block, check, occurrences, findings);
        }
    }
}

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
