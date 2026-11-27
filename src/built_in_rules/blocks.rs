//! Block rules turn each parsed function into size, complexity, documentation,
//! behavior, performance, and test findings. Users reach this layer after a
//! Rust source parses successfully and before findings enter the shared report.

use super::*;

/// Dispatches the enabled block rule groups for each parsed function; functions in test context get at most the test-quality rules.
///
/// `unit` is the parsed source file and `blocks` are its functions, each passed to `analyse_block`.
/// `config` supplies thresholds and severities, and `families` selects which rule groups run.
/// Findings from every function are pushed onto `findings`.
pub(crate) fn analyse_blocks(
    unit: &SourceUnit<'_>,
    blocks: &[FunctionBlock],
    config: &Config,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    for block in blocks {
        analyse_block(unit, block, config, families, findings);
    }
}

/// Runs the enabled test, metric, documentation and behavior rules for one parsed function.
///
/// `unit` is the source file holding `block`, `config` supplies thresholds and severities, and `families` selects which rule groups run.
/// Test-quality rules run first, and a block in test context gets no other rules.
/// Findings are pushed onto `findings`.
pub(crate) fn analyse_block(
    unit: &SourceUnit<'_>,
    block: &FunctionBlock,
    config: &Config,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    let file = unit.file;
    let searchable_body = strip_rust_string_literals(&block.body);
    analyse_block_test_rules(file, block, config, families, findings);
    if block.is_test_context() {
        return;
    }
    analyse_block_metric_rules(file, block, config, families, &searchable_body, findings);
    analyse_block_documentation_rules(file, block, config, families, findings);
    analyse_block_behavior_rules(unit, block, families, &searchable_body, findings);
}

/// Runs the test-quality rules on a function marked as a test when that rule group is enabled.
///
/// `file` and `block` locate the function, `config` supplies rule settings, and `families` enables the group through `block_test_quality`.
/// Findings are pushed onto `findings`.
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

/// Runs the enabled size, complexity and performance rules for one function outside test context.
///
/// `file` and `block` locate the function, `config` supplies thresholds and severities, and `families` selects which groups run.
/// `searchable_body` is the body with string literals stripped, read only by the performance rules.
/// Findings are pushed onto `findings`.
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
        analyse_block_complexity(file, block, config, findings);
    }
    if families.block_performance {
        analyse_performance_block(file, block, searchable_body, findings);
    }
}

/// Runs the enabled naming and documentation rules for one function outside test context.
///
/// `file` and `block` locate the function, `config` supplies rule settings, and `families` gates naming and doc rules separately.
/// Doc rules cover public docs, errors, panics and safety sections, parameters and returns; findings are pushed onto `findings`.
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
        analyse_public_function_doc(file, block, config, findings);
        analyse_missing_errors_section(file, block, findings);
        analyse_missing_panics_section(file, block, findings);
        analyse_missing_safety_section(file, block, findings);
        analyse_missing_param_doc(file, block, config, findings);
        analyse_missing_return_doc(file, block, config, findings);
    }
}

/// Runs the enabled error-handling, concurrency and insecure-randomness rules for one function outside test context.
///
/// `unit` is the source file holding `block`, `families` selects the groups, and `searchable_body` is the body with string literals stripped.
/// Findings are pushed onto `findings`.
fn analyse_block_behavior_rules(
    unit: &SourceUnit<'_>,
    block: &FunctionBlock,
    families: EnabledBuiltinFamilies,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    let file = unit.file;
    if families.block_error_handling {
        analyse_error_handling_block(file, block, searchable_body, findings);
    }
    if families.block_concurrency {
        analyse_concurrency_block(unit, block, searchable_body, findings);
    }
    if families.block_security {
        analyse_insecure_rng_for_secrets(file, block, searchable_body, findings);
    }
}

/// Report declaration/body size and parameter-count findings for one function.
///
/// `file` and `block` give the function's location and executable line count, and `config` supplies thresholds and severities.
/// A body over the `size.function-length` limit that is not a declarative literal gets a finding with a limit band.
/// Findings, including the parameter-count check, are pushed onto `findings`.
pub(crate) fn analyse_block_size(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "size.function-length";
    let threshold = config.threshold(rule_id) as usize;
    // Only executable source above the threshold reports; its band decides whether the advice is not to grow or to split.
    if block.executable_line_count > threshold && !block.body_is_declarative_literal {
        let mut finding = block_finding_with_metadata(
            BlockFindingDescriptor {
                rule_id,
                message: format!(
                    "Function `{}` has {} lines, above the threshold of {threshold}.",
                    block.name, block.executable_line_count
                ),
                file,
                block,
                severity: config.severity(rule_id, rules::builtin_severity(rule_id)),
                pillar: Pillar::Size,
            },
            threshold_metadata(block.executable_line_count, threshold, "lines"),
        );
        apply_limit_band(
            &mut finding,
            block.executable_line_count,
            config.threshold(rule_id),
            LOWER_BAND_FUNCTION,
            SPLIT_FUNCTION,
        );
        findings.push(finding);
    }
    analyse_parameter_count(file, block, config, findings);
}

/// Report a function that declares more parameters than the configured limit.
///
/// `file` and `block` give the function's location and parameter count; `config` supplies the `size.parameter-count` limit and severity.
/// A finding over the limit carries a limit band and is pushed onto `findings`.
fn analyse_parameter_count(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let params = block.param_count;
    let rule_id = "size.parameter-count";
    let threshold = config.threshold(rule_id) as usize;
    // Functions over the parameter limit ask the user for a clearer input contract.
    if params > threshold {
        let mut finding = block_finding_with_metadata(
            BlockFindingDescriptor {
                rule_id,
                message: format!("Function `{}` declares {params} parameters.", block.name),
                file,
                block,
                severity: config.severity(rule_id, rules::builtin_severity(rule_id)),
                pillar: Pillar::Size,
            },
            threshold_metadata(params, threshold, "parameters"),
        );
        apply_limit_band(
            &mut finding,
            params,
            config.threshold(rule_id),
            LOWER_BAND_PARAMETER,
            GROUP_PARAMETERS,
        );
        findings.push(finding);
    }
}

/// Report cyclomatic, nesting and cognitive complexity for one function, each counted on its parsed body.
///
/// `file` and `block` give the function and its precomputed measures, and `config` supplies each rule's threshold and severity.
/// Each measure above its threshold pushes one finding onto `findings`.
pub(crate) fn analyse_block_complexity(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let measures = block.complexity;
    analyse_cyclomatic_complexity(file, block, measures.cyclomatic, config, findings);
    analyse_nesting_depth(file, block, measures.nesting, config, findings);
    analyse_cognitive_complexity(
        BlockAnalysisContext {
            file,
            block,
            config,
        },
        measures,
        findings,
    );
}

/// Measure trait default methods and closures assigned to `const` items for size and complexity only: each body is code
/// a reader reviews like any function, while the documentation and behavior rules read these items through their own
/// paths.
///
/// `file` is the source file, `blocks` are the measure-only bodies, and `config` supplies thresholds and severities.
/// `families` gates the size and complexity groups; blocks in test context are skipped, and findings are pushed onto `findings`.
pub(crate) fn analyse_measure_only_blocks(
    file: &SourceFile,
    blocks: &[FunctionBlock],
    config: &Config,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    for block in blocks.iter().filter(|block| !block.is_test_context()) {
        if families.block_size {
            analyse_block_size(file, block, config, findings);
        }
        if families.block_complexity {
            analyse_block_complexity(file, block, config, findings);
        }
    }
}

/// Reports a function whose cyclomatic complexity is above the configured `complexity.cyclomatic` threshold.
///
/// `file` and `block` locate the function, `cyclomatic` is its measured complexity, and `config` supplies the threshold and severity.
/// A finding with a limit band is pushed onto `findings`; nothing is added at or below the threshold.
pub(crate) fn analyse_cyclomatic_complexity(
    file: &SourceFile,
    block: &FunctionBlock,
    cyclomatic: usize,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "complexity.cyclomatic";
    let threshold = config.threshold(rule_id) as usize;
    if cyclomatic <= threshold {
        return;
    }
    let mut finding = block_finding_with_metadata(
        BlockFindingDescriptor {
            rule_id,
            message: format!(
                "Function `{}` has cyclomatic complexity {cyclomatic}.",
                block.name
            ),
            file,
            block,
            severity: config.severity(rule_id, rules::builtin_severity(rule_id)),
            pillar: Pillar::Complexity,
        },
        json!({
            "complexity": cyclomatic,
            "measured": cyclomatic,
            "threshold": threshold,
            "unit": "branches",
            "direction": "above"
        }),
    );
    apply_limit_band(
        &mut finding,
        cyclomatic,
        config.threshold(rule_id),
        LOWER_BAND_FUNCTION,
        SIMPLIFY_PATH,
    );
    findings.push(finding);
}

/// Reports a function whose nesting depth is above the configured `complexity.nesting-depth` threshold.
///
/// `file` and `block` locate the function, `nesting` is its measured depth in levels, and `config` supplies the threshold and severity.
/// A finding with a limit band is pushed onto `findings`; nothing is added at or below the threshold.
pub(crate) fn analyse_nesting_depth(
    file: &SourceFile,
    block: &FunctionBlock,
    nesting: usize,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "complexity.nesting-depth";
    let threshold = config.threshold(rule_id) as usize;
    if nesting <= threshold {
        return;
    }
    let mut finding = block_finding_with_metadata(
        BlockFindingDescriptor {
            rule_id,
            message: format!("Function `{}` has nesting depth {nesting}.", block.name),
            file,
            block,
            severity: config.severity(rule_id, rules::builtin_severity(rule_id)),
            pillar: Pillar::Complexity,
        },
        json!({
            "nestingDepth": nesting,
            "measured": nesting,
            "threshold": threshold,
            "unit": "levels",
            "direction": "above"
        }),
    );
    apply_limit_band(
        &mut finding,
        nesting,
        config.threshold(rule_id),
        LOWER_BAND_FUNCTION,
        SIMPLIFY_PATH,
    );
    findings.push(finding);
}

pub(crate) struct BlockAnalysisContext<'a> {
    pub(crate) file: &'a SourceFile,
    pub(crate) block: &'a FunctionBlock,
    pub(crate) config: &'a Config,
}

/// Reports a function whose cognitive complexity is above the configured `complexity.cognitive` threshold.
///
/// `ctx` carries the file, function and config; `measures` holds the cognitive score, with cyclomatic and nesting values kept as metadata.
/// A finding with a limit band is pushed onto `findings`; nothing is added at or below the threshold.
pub(crate) fn analyse_cognitive_complexity(
    ctx: BlockAnalysisContext<'_>,
    measures: SyntaxComplexity,
    findings: &mut Vec<Finding>,
) {
    let SyntaxComplexity {
        cyclomatic,
        nesting,
        cognitive,
    } = measures;
    let rule_id = "complexity.cognitive";
    let threshold = ctx.config.threshold(rule_id) as usize;
    if cognitive <= threshold {
        return;
    }
    let mut finding = block_finding_with_metadata(
        BlockFindingDescriptor {
            rule_id,
            message: format!(
                "Function `{}` has cognitive complexity {cognitive}.",
                ctx.block.name
            ),
            file: ctx.file,
            block: ctx.block,
            severity: ctx
                .config
                .severity(rule_id, rules::builtin_severity(rule_id)),
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
    );
    apply_limit_band(
        &mut finding,
        cognitive,
        ctx.config.threshold(rule_id),
        LOWER_BAND_FUNCTION,
        SIMPLIFY_PATH,
    );
    findings.push(finding);
}

/// Runs the naming rules for one function, currently only the placeholder-name check.
///
/// `file` and `block` locate the function and its name, and `config` supplies rule settings; findings are pushed onto `findings`.
pub(crate) fn analyse_block_naming(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_placeholder_block_name(file, block, config, findings);
}
