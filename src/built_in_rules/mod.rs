//! Built-in rule dispatch and shared analyzer vocabulary.
//! Focused sibling modules evaluate source units, then this parent combines
//! their deterministic findings for the configured report pipeline.

pub(crate) use super::*;

mod helpers;
mod naming_rules;
mod predicates;
mod rust_block_rules;
mod rust_other_rules;
mod secret_rules;
mod test_context;
mod text_rules;

pub(crate) use helpers::*;
pub(crate) use naming_rules::*;
pub(crate) use predicates::*;
pub(crate) use rust_block_rules::*;
pub(crate) use rust_other_rules::*;
pub(crate) use secret_rules::*;
pub(crate) use test_context::*;
pub(crate) use text_rules::*;

// Shared OnceLock<Regex> statics consumed by multiple submodules. Kept
// here so `pub(crate) use X::*;` re-exports above make them reachable to
// every sibling submodule via `use super::*;`.
pub(crate) static PROCESS_COMMAND_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PANIC_MACRO_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PLACEHOLDER_MACRO_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static UNWRAP_EXPECT_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static UNSAFE_BLOCK_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static CLONE_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static CYCLOMATIC_COMPLEXITY_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static LOOP_START_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PERF_REGEX_IN_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PERF_FORMAT_IN_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PERF_CLONE_IN_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static UNBOUNDED_CHANNEL_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static LOCK_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static UNREACHABLE_TERMINATOR_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static NON_WHITESPACE_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static TRIVIAL_ASSERT_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static SAME_LITERAL_ASSERT_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static LITERAL_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) struct SourceAnalysisArtifacts {
    pub(crate) findings: Vec<Finding>,
    pub(crate) function_blocks: Option<Vec<FunctionBlock>>,
}

/// Enabled built-in Rust rule families, derived from the public rule selector
/// contract before dispatch so disabled families do not pay their scan cost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EnabledBuiltinFamilies {
    pub(crate) block_size: bool,
    pub(crate) block_complexity: bool,
    pub(crate) block_performance: bool,
    pub(crate) block_naming: bool,
    pub(crate) block_docs: bool,
    pub(crate) block_error_handling: bool,
    pub(crate) block_concurrency: bool,
    pub(crate) block_security: bool,
    pub(crate) block_test_quality: bool,
    pub(crate) process_commands: bool,
    pub(crate) sql_dynamic_query: bool,
    pub(crate) tls_verification: bool,
    pub(crate) weak_crypto: bool,
    pub(crate) bind_all_interfaces: bool,
    pub(crate) path_traversal: bool,
    pub(crate) network_block_security: bool,
    pub(crate) xxe_candidate: bool,
    pub(crate) modernisation_source: bool,
    pub(crate) line_rules: bool,
    pub(crate) item_rules: bool,
    pub(crate) dead_code: bool,
    pub(crate) comments: bool,
    pub(crate) naming_patterns: bool,
}

impl EnabledBuiltinFamilies {
    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            block_size: any_rule_is_enabled(
                config,
                &["size.function-length", "size.parameter-count"],
            ),
            block_complexity: any_rule_is_enabled(
                config,
                &[
                    "complexity.cognitive",
                    "complexity.cyclomatic",
                    "complexity.nesting-depth",
                ],
            ),
            block_performance: any_rule_is_enabled(
                config,
                &[
                    "performance.clone-in-loop",
                    "performance.format-in-loop",
                    "performance.regex-in-loop",
                ],
            ),
            block_naming: any_rule_is_enabled(
                config,
                &[
                    "naming.boolean-prefix",
                    "naming.generic-function",
                    "naming.placeholder-identifier",
                ],
            ),
            block_docs: any_rule_is_enabled(
                config,
                &[
                    "docs.missing-errors-section",
                    "docs.missing-panics-section",
                    "docs.missing-param-doc",
                    "docs.missing-public-doc",
                    "docs.missing-return-doc",
                    "docs.missing-safety-section",
                ],
            ),
            block_error_handling: any_rule_is_enabled(
                config,
                &[
                    "error-handling.production-panic",
                    "error-handling.public-unwrap",
                    "error-handling.unimplemented-placeholder",
                ],
            ),
            block_concurrency: any_rule_is_enabled(
                config,
                &[
                    "concurrency.blocking-call-in-async",
                    "concurrency.lock-across-await",
                    "concurrency.unbounded-channel",
                ],
            ),
            block_security: config.is_rule_enabled("security.insecure-rng-for-secrets"),
            block_test_quality: any_rule_is_enabled(
                config,
                &[
                    "test-quality.conditional-logic",
                    "test-quality.ignored-without-reason",
                    "test-quality.long-test",
                    "test-quality.should-panic-without-expected",
                    "test-quality.sleep-in-test",
                    "test-quality.trivial-assertion",
                    "test-quality.unwrap-in-test",
                ],
            ),
            process_commands: config.is_rule_enabled("security.process-command"),
            sql_dynamic_query: config.is_rule_enabled("security.sql-dynamic-query"),
            tls_verification: config.is_rule_enabled("security.tls-verification-disabled"),
            weak_crypto: config.is_rule_enabled("security.weak-crypto"),
            bind_all_interfaces: config.is_rule_enabled("security.hardcoded-bind-all-interfaces"),
            path_traversal: config.is_rule_enabled("security.path-traversal-candidate"),
            network_block_security: any_rule_is_enabled(
                config,
                &[
                    "security.ssrf-candidate",
                    "security.template-injection-xss",
                    "security.unsafe-deserialization",
                ],
            ),
            xxe_candidate: config.is_rule_enabled("security.xxe-candidate"),
            modernisation_source: any_rule_is_enabled(
                config,
                &[
                    "modernisation.manual-contains",
                    "modernisation.manual-is-empty",
                    "modernisation.manual-strip-prefix",
                    "modernisation.manual-unwrap-or-default",
                    "modernisation.question-mark-candidate",
                ],
            ),
            line_rules: any_rule_is_enabled(
                config,
                &[
                    "docs.weak-safety-rationale",
                    "security.unsafe-block",
                    "waste.unnecessary-clone-candidate",
                    "waste.unreachable-code",
                    "waste.unwrap-expect",
                ],
            ),
            item_rules: config.is_rule_enabled("docs.missing-public-doc"),
            dead_code: config.is_rule_enabled("dead-code.unused-private-function"),
            comments: any_rule_is_enabled(config, &["docs.commented-out-code", "docs.stale-todo"]),
            naming_patterns: any_rule_is_enabled(
                config,
                &[
                    "naming.identifier-shadow",
                    "naming.placeholder-identifier",
                    "naming.short-variable",
                ],
            ),
        }
    }

    pub(crate) fn needs_function_blocks(self) -> bool {
        [
            self.block_size,
            self.block_complexity,
            self.block_performance,
            self.block_naming,
            self.block_docs,
            self.block_error_handling,
            self.block_concurrency,
            self.block_security,
            self.block_test_quality,
            self.network_block_security,
            self.line_rules,
        ]
        .into_iter()
        .any(std::convert::identity)
    }

    pub(crate) fn has_block_rules(self) -> bool {
        [
            self.block_size,
            self.block_complexity,
            self.block_performance,
            self.block_naming,
            self.block_docs,
            self.block_error_handling,
            self.block_concurrency,
            self.block_security,
            self.block_test_quality,
        ]
        .into_iter()
        .any(std::convert::identity)
    }
}

fn any_rule_is_enabled(config: &Config, rule_ids: &[&str]) -> bool {
    rule_ids
        .iter()
        .any(|rule_id| config.is_rule_enabled(rule_id))
}

/// Run enabled text and Rust rules for one parsed source unit.
pub(crate) fn analyse(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    analyse_with_artifacts(unit, config, false).findings
}

pub(crate) fn analyse_with_artifacts(
    unit: &SourceUnit<'_>,
    config: &Config,
    retain_function_blocks: bool,
) -> SourceAnalysisArtifacts {
    let mut findings = Vec::with_capacity(8);
    analyse_text_rules(unit, config, &mut findings);
    let mut function_blocks = None;
    if let Some(ast) = unit.rust_ast {
        let families = EnabledBuiltinFamilies::from_config(config);
        analyse_rust_rules(
            unit,
            ast,
            config,
            families,
            &mut function_blocks,
            &mut findings,
        );
        if retain_function_blocks && function_blocks.is_none() {
            function_blocks = Some(rust_function_blocks(ast, unit.source));
        }
    }
    let findings = findings
        .into_iter()
        .filter(|finding| config.is_rule_enabled(&finding.rule_id))
        .map(|finding| apply_configured_severity(finding, config))
        .collect();
    SourceAnalysisArtifacts {
        findings,
        function_blocks,
    }
}

fn analyse_rust_rules(
    unit: &SourceUnit<'_>,
    ast: &syn::File,
    config: &Config,
    families: EnabledBuiltinFamilies,
    function_blocks: &mut Option<Vec<FunctionBlock>>,
    findings: &mut Vec<Finding>,
) {
    let blocks = families.needs_function_blocks().then(|| {
        function_blocks
            .get_or_insert_with(|| rust_function_blocks(ast, unit.source))
            .as_slice()
    });
    analyse_block_dependent_rust_rules(unit, config, families, blocks, findings);
    analyse_rust_source_rules(unit, families, findings);
    analyse_rust_ast_rules(unit, ast, config, families, findings);
}

fn analyse_block_dependent_rust_rules(
    unit: &SourceUnit<'_>,
    config: &Config,
    families: EnabledBuiltinFamilies,
    blocks: Option<&[FunctionBlock]>,
    findings: &mut Vec<Finding>,
) {
    let Some(blocks) = blocks else {
        return;
    };
    if families.has_block_rules() {
        analyse_blocks(unit.file, blocks, config, families, findings);
    }
    if families.network_block_security {
        analyse_ssrf_candidate(unit.file, blocks, findings);
        analyse_unsafe_deserialization(unit.file, blocks, findings);
        analyse_template_injection_xss(unit.file, blocks, findings);
    }
    if families.line_rules {
        analyse_line_rules(unit.file, unit.source, blocks, findings);
    }
}

fn analyse_rust_source_rules(
    unit: &SourceUnit<'_>,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    if families.process_commands {
        analyse_process_commands(unit.file, unit.source, findings);
    }
    if families.sql_dynamic_query {
        analyse_sql_dynamic_query(unit.file, unit.source, findings);
    }
    if families.tls_verification {
        analyse_tls_verification_disabled(unit.file, unit.source, findings);
    }
    if families.weak_crypto {
        analyse_weak_crypto(unit.file, unit.source, findings);
    }
    if families.bind_all_interfaces {
        analyse_hardcoded_bind_all_interfaces(unit.file, unit.source, findings);
    }
    if families.path_traversal {
        analyse_path_traversal_candidate(unit.file, unit.source, findings);
    }
    if families.xxe_candidate {
        analyse_xxe_candidate(unit.file, unit.source, findings);
    }
    if families.modernisation_source {
        analyse_modernisation_rules(unit.file, unit.source, findings);
    }
}

fn analyse_rust_ast_rules(
    unit: &SourceUnit<'_>,
    ast: &syn::File,
    config: &Config,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    if families.item_rules {
        analyse_item_rules(unit.file, ast, findings);
    }
    if families.dead_code {
        analyse_dead_code(unit.file, ast, unit.source, findings);
    }
    if families.comments {
        analyse_comment_rules(unit.file, unit.source, findings);
    }
    if families.naming_patterns {
        analyse_naming_patterns(unit.file, ast, config, findings);
    }
}

fn apply_configured_severity(mut finding: Finding, config: &Config) -> Finding {
    finding.severity = config.severity(&finding.rule_id, finding.severity);
    finding
}
