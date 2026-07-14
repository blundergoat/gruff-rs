//! Block rules turn each parsed function into size, complexity, documentation,
//! behavior, performance, and test findings. Users reach this layer after a
//! Rust source parses successfully and before findings enter the shared report.

use super::*;

pub(crate) fn analyse_blocks(
    file: &SourceFile,
    blocks: &[FunctionBlock],
    config: &Config,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    for block in blocks {
        analyse_block(file, block, config, families, findings);
    }
}

pub(crate) fn analyse_block(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    let searchable_body = strip_rust_string_literals(&block.body);
    analyse_block_test_rules(file, block, config, families, findings);
    if block.is_test_context() {
        return;
    }
    analyse_block_metric_rules(file, block, config, families, &searchable_body, findings);
    analyse_block_documentation_rules(file, block, config, families, findings);
    analyse_block_behavior_rules(file, block, families, &searchable_body, findings);
}

fn analyse_block_test_rules(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    if block.is_test && families.block_test_quality {
        analyse_test_block(file, block, config, findings);
    }
}

fn analyse_block_metric_rules(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    families: EnabledBuiltinFamilies,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    if families.block_size {
        analyse_block_size(file, block, config, findings);
    }
    if families.block_complexity {
        analyse_block_complexity(file, block, searchable_body, config, findings);
    }
    if families.block_performance {
        analyse_performance_block(file, block, searchable_body, findings);
    }
}

fn analyse_block_documentation_rules(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    if families.block_naming {
        analyse_block_naming(file, block, config, findings);
    }
    if families.block_docs {
        analyse_public_function_doc(file, block, findings);
        analyse_missing_errors_section(file, block, findings);
        analyse_missing_panics_section(file, block, findings);
        analyse_missing_safety_section(file, block, findings);
        analyse_missing_param_doc(file, block, findings);
        analyse_missing_return_doc(file, block, findings);
    }
}

fn analyse_block_behavior_rules(
    file: &SourceFile,
    block: &FunctionBlock,
    families: EnabledBuiltinFamilies,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    if families.block_error_handling {
        analyse_error_handling_block(file, block, searchable_body, findings);
    }
    if families.block_concurrency {
        analyse_concurrency_block(file, block, searchable_body, findings);
    }
    if families.block_security {
        analyse_insecure_rng_for_secrets(file, block, searchable_body, findings);
    }
}

/// Report declaration/body size and parameter-count findings for one function.
pub(crate) fn analyse_block_size(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "size.function-length";
    let threshold = config.threshold(rule_id, 50.0) as usize;
    // Only executable source above the threshold asks the user to split a function.
    if block.executable_line_count > threshold && !block.body_is_declarative_literal {
        findings.push(block_finding_with_metadata(
            BlockFindingDescriptor {
                rule_id,
                message: format!(
                    "Function `{}` has {} lines, above the threshold of {threshold}.",
                    block.name, block.executable_line_count
                ),
                file,
                block,
                severity: config.severity(rule_id, Severity::Warning),
                pillar: Pillar::Size,
            },
            threshold_metadata(block.executable_line_count, threshold, "lines"),
        ));
    }

    let params = block.param_count;
    let rule_id = "size.parameter-count";
    let threshold = config.threshold(rule_id, 7.0) as usize;
    // Functions over the parameter limit ask the user for a clearer input contract.
    if params > threshold {
        findings.push(block_finding_with_metadata(
            BlockFindingDescriptor {
                rule_id,
                message: format!("Function `{}` declares {params} parameters.", block.name),
                file,
                block,
                severity: config.severity(rule_id, Severity::Warning),
                pillar: Pillar::Size,
            },
            threshold_metadata(params, threshold, "parameters"),
        ));
    }
}

pub(crate) fn analyse_block_complexity(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    config: &Config,
    findings: &mut Vec<Finding>,
) -> usize {
    let code_only_body = strip_rust_comments_after_string_mask(searchable_body);
    let cyclomatic = count_regex(
        &code_only_body,
        static_regex(
            &CYCLOMATIC_COMPLEXITY_REGEX,
            r"\b(if|else if|match|for|while|loop)\b|&&|\|\|",
        ),
    ) + 1;
    analyse_cyclomatic_complexity(file, block, cyclomatic, config, findings);
    let nesting = max_nesting_depth(&code_only_body);
    analyse_nesting_depth(file, block, nesting, config, findings);
    analyse_cognitive_complexity(
        BlockAnalysisContext {
            file,
            block,
            config,
        },
        cyclomatic,
        nesting,
        findings,
    );
    cyclomatic
}

pub(crate) fn analyse_cyclomatic_complexity(
    file: &SourceFile,
    block: &FunctionBlock,
    cyclomatic: usize,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "complexity.cyclomatic";
    let threshold = config.threshold(rule_id, 10.0) as usize;
    if cyclomatic <= threshold {
        return;
    }
    findings.push(block_finding_with_metadata(
        BlockFindingDescriptor {
            rule_id,
            message: format!(
                "Function `{}` has cyclomatic complexity {cyclomatic}.",
                block.name
            ),
            file,
            block,
            severity: config.severity(rule_id, Severity::Warning),
            pillar: Pillar::Complexity,
        },
        json!({
            "complexity": cyclomatic,
            "measured": cyclomatic,
            "threshold": threshold,
            "unit": "branches",
            "direction": "above"
        }),
    ));
}

pub(crate) fn analyse_nesting_depth(
    file: &SourceFile,
    block: &FunctionBlock,
    nesting: usize,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "complexity.nesting-depth";
    let threshold = config.threshold(rule_id, 4.0) as usize;
    if nesting <= threshold {
        return;
    }
    findings.push(block_finding_with_metadata(
        BlockFindingDescriptor {
            rule_id,
            message: format!("Function `{}` has nesting depth {nesting}.", block.name),
            file,
            block,
            severity: config.severity(rule_id, Severity::Warning),
            pillar: Pillar::Complexity,
        },
        json!({
            "nestingDepth": nesting,
            "measured": nesting,
            "threshold": threshold,
            "unit": "levels",
            "direction": "above"
        }),
    ));
}

pub(crate) struct BlockAnalysisContext<'a> {
    pub(crate) file: &'a SourceFile,
    pub(crate) block: &'a FunctionBlock,
    pub(crate) config: &'a Config,
}

pub(crate) fn analyse_cognitive_complexity(
    ctx: BlockAnalysisContext<'_>,
    cyclomatic: usize,
    nesting: usize,
    findings: &mut Vec<Finding>,
) {
    let cognitive = cyclomatic + nesting.saturating_mul(2);
    let rule_id = "complexity.cognitive";
    let threshold = ctx.config.threshold(rule_id, 15.0) as usize;
    if cognitive <= threshold {
        return;
    }
    findings.push(block_finding_with_metadata(
        BlockFindingDescriptor {
            rule_id,
            message: format!(
                "Function `{}` has cognitive complexity {cognitive}.",
                ctx.block.name
            ),
            file: ctx.file,
            block: ctx.block,
            severity: ctx.config.severity(rule_id, Severity::Warning),
            pillar: Pillar::Complexity,
        },
        json!({
            "complexity": cognitive,
            "cyclomatic": cyclomatic,
            "nestingDepth": nesting,
            "measured": cognitive,
            "threshold": threshold,
            "unit": "points",
            "direction": "above"
        }),
    ));
}

pub(crate) fn analyse_block_naming(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let extra_generic = config.string_array_option("naming.generic-function", "extraGenericNames");
    if is_generic_name(&block.name) || extra_generic.contains(&block.name) {
        findings.push(block_finding(BlockFindingDescriptor {
            rule_id: "naming.generic-function",
            message: format!(
                "Function `{}` is too generic to explain intent.",
                block.name
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Naming,
        }));
    }
    analyse_boolean_block_name(file, block, config, findings);
    analyse_placeholder_block_name(file, block, config, findings);
}

pub(crate) fn analyse_boolean_block_name(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let extra_prefixes = config.string_array_option("naming.boolean-prefix", "predicatePrefixes");
    let accepts_extra = extra_prefixes
        .iter()
        .any(|prefix| block.name.starts_with(prefix.as_str()));
    if block.returns_bool && !is_boolean_predicate_name(&block.name) && !accepts_extra {
        findings.push(block_finding(BlockFindingDescriptor {
            rule_id: "naming.boolean-prefix",
            message: format!(
                "Boolean function `{}` should read like a predicate.",
                block.name
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Naming,
        }));
    }
}
