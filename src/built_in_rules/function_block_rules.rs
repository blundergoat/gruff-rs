use super::*;

pub(crate) fn analyse_placeholder_block_name(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let extras = config.string_array_option("naming.placeholder-identifier", "extraPlaceholders");
    let extra_match = extras.contains(&block.name);
    if is_placeholder_identifier(&block.name) || extra_match {
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id: "naming.placeholder-identifier",
                message: format!(
                    "Function `{}` uses a placeholder name instead of domain language.",
                    block.name
                ),
                file,
                block,
                severity: Severity::Advisory,
                pillar: Pillar::Naming,
            },
            BlockFindingExtras {
                confidence: Confidence::Medium,
                remediation: Some(
                    "Rename the function to describe its domain role. If the placeholder is intentional (test fixture, generated stub), add the host path to `paths.ignore` in `.gruff-rs.yaml`."
                        .to_string(),
                ),
                metadata: json!({}),
            },
        ));
    }
}

pub(crate) fn analyse_error_handling_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    analyse_panic_block(file, block, searchable_body, findings);
    analyse_placeholder_block(file, block, searchable_body, findings);
    analyse_public_unwrap_block(file, block, searchable_body, findings);
}

pub(crate) fn analyse_panic_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    if block.is_test || block.test_context || path_is_test_infrastructure(&file.display_path) {
        return;
    }
    let has_panic = static_regex(&PANIC_MACRO_REGEX, r"\bpanic!\s*\(").is_match(searchable_body);
    if has_panic && !has_nearby_invariant_comment(searchable_body) {
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id: "error-handling.production-panic",
                message: format!("Function `{}` calls panic! in production code.", block.name),
                file,
                block,
                severity: Severity::Warning,
                pillar: Pillar::Maintainability,
            },
            BlockFindingExtras {
                confidence: Confidence::High,
                remediation: Some(
                    "Return an error or document the invariant that makes the panic unreachable."
                        .to_string(),
                ),
                metadata: json!({ "macro": "panic!" }),
            },
        ));
    }
}

pub(crate) fn analyse_placeholder_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    if static_regex(&PLACEHOLDER_MACRO_REGEX, r"\b(todo!|unimplemented!)\s*\(")
        .is_match(searchable_body)
    {
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id: "error-handling.unimplemented-placeholder",
                message: format!(
                    "Function `{}` contains todo!/unimplemented! placeholder code.",
                    block.name
                ),
                file,
                block,
                severity: Severity::Warning,
                pillar: Pillar::Maintainability,
            },
            BlockFindingExtras {
                confidence: Confidence::High,
                remediation: Some(
                    "Replace the placeholder with implemented behavior before shipping."
                        .to_string(),
                ),
                metadata: json!({ "macros": ["todo!", "unimplemented!"] }),
            },
        ));
    }
}

pub(crate) fn analyse_public_unwrap_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    let has_unwrap = static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(")
        .is_match(searchable_body);
    if block.is_externally_public && has_unwrap {
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id: "error-handling.public-unwrap",
                message: format!(
                    "Public function `{}` uses unwrap()/expect() in its implementation.",
                    block.name
                ),
                file,
                block,
                severity: Severity::Warning,
                pillar: Pillar::Maintainability,
            },
            BlockFindingExtras {
                confidence: Confidence::High,
                remediation: Some(
                    "Return a Result or map the failure into the public API contract.".to_string(),
                ),
                metadata: json!({}),
            },
        ));
    }
}

pub(crate) struct PerformanceCheck {
    pub(crate) rule_id: &'static str,
    pub(crate) regex: &'static OnceLock<Regex>,
    pub(crate) pattern: &'static str,
    pub(crate) severity: Severity,
    pub(crate) confidence: Confidence,
    pub(crate) label: &'static str,
    pub(crate) remediation: &'static str,
}

pub(crate) const PERFORMANCE_CHECKS: &[PerformanceCheck] = &[
    PerformanceCheck {
        rule_id: "performance.regex-in-loop",
        regex: &PERF_REGEX_IN_LOOP_REGEX,
        pattern: r"\bRegex::new\s*\(",
        severity: Severity::Warning,
        confidence: Confidence::High,
        label: "Regex::new",
        remediation: "Move regex construction out of the loop or cache the compiled regex.",
    },
    PerformanceCheck {
        rule_id: "performance.format-in-loop",
        regex: &PERF_FORMAT_IN_LOOP_REGEX,
        pattern: r"\bformat!\s*\(",
        severity: Severity::Advisory,
        confidence: Confidence::Medium,
        label: "format!",
        remediation: "Reuse buffers or move formatting out of the loop when allocation matters.",
    },
    PerformanceCheck {
        rule_id: "performance.clone-in-loop",
        regex: &PERF_CLONE_IN_LOOP_REGEX,
        pattern: r"\.clone\s*\(",
        severity: Severity::Advisory,
        confidence: Confidence::Medium,
        label: "clone()",
        remediation: "Clone outside the loop or borrow values when ownership permits.",
    },
];
