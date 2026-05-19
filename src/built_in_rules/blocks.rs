use super::*;

pub(crate) fn analyse_blocks(
    file: &SourceFile,
    blocks: &[FunctionBlock],
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    for block in blocks {
        analyse_block(file, block, config, findings);
    }
}

pub(crate) fn analyse_block(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let searchable_body = strip_rust_string_literals(&block.body);
    if block.is_test {
        analyse_test_block(file, block, config, findings);
    }
    if block.is_test_context() {
        return;
    }

    analyse_block_size(file, block, config, findings);
    let cyclomatic = analyse_block_complexity(file, block, &searchable_body, config, findings);
    analyse_metric_block(file, block, &searchable_body, cyclomatic, config, findings);
    analyse_performance_block(file, block, &searchable_body, findings);
    analyse_design_block(file, block, cyclomatic, findings);
    analyse_block_naming(file, block, config, findings);
    analyse_public_function_doc(file, block, findings);
    analyse_missing_errors_section(file, block, findings);
    analyse_error_handling_block(file, block, &searchable_body, findings);
    analyse_concurrency_block(file, block, &searchable_body, findings);
}

pub(crate) fn analyse_block_size(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "size.function-length";
    let threshold = config.threshold(rule_id, 50.0) as usize;
    if block.line_count > threshold && !block.body_is_declarative_literal {
        findings.push(block_finding(
            rule_id,
            format!(
                "Function `{}` has {} lines, above the threshold of {threshold}.",
                block.name, block.line_count
            ),
            file,
            block,
            config.severity(rule_id, Severity::Warning),
            Pillar::Size,
        ));
    }

    let params = block.param_count;
    let rule_id = "size.parameter-count";
    if params > config.threshold(rule_id, 5.0) as usize {
        findings.push(block_finding(
            rule_id,
            format!("Function `{}` declares {params} parameters.", block.name),
            file,
            block,
            config.severity(rule_id, Severity::Warning),
            Pillar::Size,
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
    let cyclomatic = count_regex(
        searchable_body,
        static_regex(
            &CYCLOMATIC_COMPLEXITY_REGEX,
            r"\b(if|else if|match|for|while|loop)\b|\?|&&|\|\|",
        ),
    ) + 1;
    analyse_cyclomatic_complexity(file, block, cyclomatic, config, findings);
    let nesting = max_nesting_depth(searchable_body);
    analyse_nesting_depth(file, block, nesting, config, findings);
    analyse_npath_complexity(
        file,
        block,
        approximate_npath(searchable_body),
        config,
        findings,
    );
    analyse_cognitive_complexity(file, block, cyclomatic, nesting, config, findings);
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
    if cyclomatic <= config.threshold(rule_id, 10.0) as usize {
        return;
    }
    findings.push(block_finding_with_metadata(
        rule_id,
        format!(
            "Function `{}` has cyclomatic complexity {cyclomatic}.",
            block.name
        ),
        file,
        block,
        config.severity(rule_id, Severity::Warning),
        Pillar::Complexity,
        json!({ "complexity": cyclomatic }),
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
    if nesting <= config.threshold(rule_id, 4.0) as usize {
        return;
    }
    findings.push(block_finding_with_metadata(
        rule_id,
        format!("Function `{}` has nesting depth {nesting}.", block.name),
        file,
        block,
        config.severity(rule_id, Severity::Warning),
        Pillar::Complexity,
        json!({ "nestingDepth": nesting }),
    ));
}

pub(crate) fn analyse_npath_complexity(
    file: &SourceFile,
    block: &FunctionBlock,
    npath: usize,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "complexity.npath";
    if npath <= config.threshold(rule_id, 100.0) as usize {
        return;
    }
    findings.push(block_finding_with_extras(
        rule_id,
        format!(
            "Function `{}` has approximate NPath complexity {npath}.",
            block.name
        ),
        file,
        block,
        config.severity(rule_id, Severity::Warning),
        Pillar::Complexity,
        BlockFindingExtras {
            confidence: Confidence::Medium,
            remediation: None,
            metadata: json!({ "npath": npath, "approximation": "branch-doubling" }),
        },
    ));
}

pub(crate) fn analyse_cognitive_complexity(
    file: &SourceFile,
    block: &FunctionBlock,
    cyclomatic: usize,
    nesting: usize,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let cognitive = cyclomatic + nesting.saturating_mul(2);
    let rule_id = "complexity.cognitive";
    if cognitive <= config.threshold(rule_id, 15.0) as usize {
        return;
    }
    findings.push(block_finding_with_metadata(
        rule_id,
        format!(
            "Function `{}` has cognitive complexity {cognitive}.",
            block.name
        ),
        file,
        block,
        config.severity(rule_id, Severity::Warning),
        Pillar::Complexity,
        json!({ "complexity": cognitive, "cyclomatic": cyclomatic, "nestingDepth": nesting }),
    ));
}

pub(crate) fn analyse_design_block(
    file: &SourceFile,
    block: &FunctionBlock,
    cyclomatic: usize,
    findings: &mut Vec<Finding>,
) {
    if block.line_count > 45 && cyclomatic > 10 {
        findings.push(block_finding(
            "design.god-function",
            format!("Function `{}` is both long and complex.", block.name),
            file,
            block,
            Severity::Warning,
            Pillar::Design,
        ));
    }
}

pub(crate) fn analyse_block_naming(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let extra_generic = config.string_array_option("naming.generic-function", "extraGenericNames");
    if is_generic_name(&block.name) || extra_generic.iter().any(|name| name == &block.name) {
        findings.push(block_finding(
            "naming.generic-function",
            format!(
                "Function `{}` is too generic to explain intent.",
                block.name
            ),
            file,
            block,
            Severity::Advisory,
            Pillar::Naming,
        ));
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
        findings.push(block_finding(
            "naming.boolean-prefix",
            format!(
                "Boolean function `{}` should read like a predicate.",
                block.name
            ),
            file,
            block,
            Severity::Advisory,
            Pillar::Naming,
        ));
    }
}
