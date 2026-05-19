use super::*;

pub(crate) fn analyse_placeholder_block_name(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let extras = config.string_array_option("naming.placeholder-identifier", "extraPlaceholders");
    let extra_match = extras.iter().any(|name| name == &block.name);
    if is_placeholder_identifier(&block.name) || extra_match {
        findings.push(block_finding_with_extras(
            "naming.placeholder-identifier",
            format!(
                "Function `{}` uses a placeholder name instead of domain language.",
                block.name
            ),
            file,
            block,
            Severity::Advisory,
            Pillar::Naming,
            BlockFindingExtras {
                confidence: Confidence::Medium,
                remediation: None,
                metadata: json!({}),
            },
        ));
    }
}

pub(crate) fn analyse_public_function_doc(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if block.is_externally_public && !has_doc_comment_before(&block.body) {
        findings.push(block_finding(
            "docs.missing-public-doc",
            format!(
                "Public function `{}` is missing a Rust doc comment.",
                block.name
            ),
            file,
            block,
            Severity::Advisory,
            Pillar::Documentation,
        ));
    }
}

/// Externally-public functions returning syntactic `Result<...>` should
/// document the error contract. The rule fires when the preceding rustdoc
/// (if any) does not contain `# Errors` or `## Errors`. Type-alias `Result`
/// shapes are intentionally not detected — see `fn returns_result`.
pub(crate) fn analyse_missing_errors_section(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !block.is_externally_public || !block.returns_result {
        return;
    }
    if doc_comment_text(&block.body).contains_errors_section() {
        return;
    }
    findings.push(block_finding_with_extras(
        "docs.missing-errors-section",
        format!(
            "Public function `{}` returns Result but its rustdoc lacks a `# Errors` section.",
            block.name
        ),
        file,
        block,
        Severity::Advisory,
        Pillar::Documentation,
        BlockFindingExtras {
            confidence: Confidence::High,
            remediation: Some(
                "Add a `# Errors` rustdoc section describing when this function returns Err."
                    .to_string(),
            ),
            metadata: json!({}),
        },
    ));
}

/// Returns the concatenated text of `///` and `//!` doc-comment lines that
/// appear before the `fn ` keyword in `block_body`, with the marker bytes
/// stripped. Used to look for rustdoc sections like `# Errors`.
pub(crate) fn doc_comment_text(block_body: &str) -> DocCommentText {
    let mut text = String::new();
    for line in block_body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("///") {
            text.push_str(trimmed.trim_start_matches("///").trim());
            text.push('\n');
        } else if trimmed.starts_with("//!") {
            text.push_str(trimmed.trim_start_matches("//!").trim());
            text.push('\n');
        } else if trimmed.contains("fn ") {
            break;
        }
    }
    DocCommentText(text)
}

pub(crate) struct DocCommentText(String);

impl DocCommentText {
    fn contains_errors_section(&self) -> bool {
        self.0.lines().any(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("# Errors")
                || trimmed.starts_with("## Errors")
                || trimmed.starts_with("### Errors")
        })
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
    let has_panic = static_regex(&PANIC_MACRO_REGEX, r"\bpanic!\s*\(").is_match(searchable_body);
    if has_panic && !has_nearby_invariant_comment(searchable_body) {
        findings.push(block_finding_with_extras(
            "error-handling.production-panic",
            format!("Function `{}` calls panic! in production code.", block.name),
            file,
            block,
            Severity::Warning,
            Pillar::Waste,
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
            "error-handling.unimplemented-placeholder",
            format!(
                "Function `{}` contains todo!/unimplemented! placeholder code.",
                block.name
            ),
            file,
            block,
            Severity::Warning,
            Pillar::Waste,
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
            "error-handling.public-unwrap",
            format!(
                "Public function `{}` uses unwrap()/expect() in its implementation.",
                block.name
            ),
            file,
            block,
            Severity::Warning,
            Pillar::Waste,
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

pub(crate) fn analyse_metric_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    cyclomatic: usize,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let metrics = function_metrics(searchable_body, cyclomatic);
    analyse_halstead_volume(file, block, &metrics, config, findings);
    analyse_maintainability_pressure(file, block, &metrics, cyclomatic, config, findings);
}

pub(crate) fn analyse_halstead_volume(
    file: &SourceFile,
    block: &FunctionBlock,
    metrics: &FunctionMetrics,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let volume_threshold = config.threshold("metrics.halstead-volume", 1500.0);
    if metrics.halstead_volume > volume_threshold {
        let rule_id = "metrics.halstead-volume";
        findings.push(block_finding_with_extras(
            rule_id,
            format!(
                "Function `{}` has Halstead-style volume {:.1}, above the threshold of {:.1}.",
                block.name, metrics.halstead_volume, volume_threshold
            ),
            file,
            block,
            config.severity(rule_id, Severity::Advisory),
            Pillar::Complexity,
            BlockFindingExtras {
                confidence: Confidence::Medium,
                remediation: Some(
                    "Split dense logic into smaller functions with simpler token flow.".to_string(),
                ),
                metadata: json!({
                    "totalTokens": metrics.total_tokens,
                    "uniqueTokens": metrics.unique_tokens,
                    "halsteadVolume": round_one_decimal(metrics.halstead_volume),
                    "threshold": volume_threshold
                }),
            },
        ));
    }
}

pub(crate) fn analyse_maintainability_pressure(
    file: &SourceFile,
    block: &FunctionBlock,
    metrics: &FunctionMetrics,
    cyclomatic: usize,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let minimum_score = config.threshold("metrics.maintainability-pressure", 45.0);
    if metrics.maintainability_score < minimum_score {
        let rule_id = "metrics.maintainability-pressure";
        findings.push(block_finding_with_extras(
                rule_id,
                format!(
                    "Function `{}` has maintainability pressure score {:.1}, below the minimum of {:.1}.",
                    block.name, metrics.maintainability_score, minimum_score
                ),
                file,
                block,
                config.severity(rule_id, Severity::Advisory),
                Pillar::Complexity,
                BlockFindingExtras {
                    confidence: Confidence::Medium,
                    remediation: Some(
                        "Reduce line count, branching, or token volume before relying on this function as stable hot-path code."
                            .to_string(),
                    ),
                    metadata: json!({
                        "score": round_one_decimal(metrics.maintainability_score),
                        "minimum": minimum_score,
                        "totalTokens": metrics.total_tokens,
                        "cyclomatic": cyclomatic,
                        "halsteadVolume": round_one_decimal(metrics.halstead_volume)
                    }),
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
