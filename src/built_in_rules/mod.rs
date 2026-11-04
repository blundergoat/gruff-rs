//! Built-in rule dispatch and shared analyzer vocabulary.
//!
//! Focused sibling modules evaluate source units, then this parent combines their deterministic findings for the configured report pipeline.
//! A user reaches this layer when a scan enables Rust and text rule families.

pub(crate) use super::*;

mod helpers;
mod limit_band;
mod naming_rules;
mod predicates;
mod rust_block_rules;
mod rust_other_rules;
mod secret_rules;
mod text_rules;

pub(crate) use helpers::*;
pub(crate) use limit_band::*;
pub(crate) use naming_rules::*;
pub(crate) use predicates::*;
pub(crate) use rust_block_rules::*;
pub(crate) use rust_other_rules::*;
pub(crate) use secret_rules::*;
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
pub(crate) static LOOP_START_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PERF_REGEX_IN_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static LOCK_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
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
    pub(crate) duplicate_tests: bool,
    pub(crate) process_commands: bool,
    pub(crate) sql_dynamic_query: bool,
    pub(crate) tls_verification: bool,
    pub(crate) weak_crypto: bool,
    pub(crate) bind_all_interfaces: bool,
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
    /// Work out which built-in rule families have at least one enabled rule, so disabled families skip their scan cost.
    ///
    /// `config` answers `is_rule_enabled` for each rule id; a family's flag is true when any rule it runs is enabled.
    /// Returns one flag per family, all false when the configuration enables none of the listed rules.
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
            block_performance: any_rule_is_enabled(config, &["performance.regex-in-loop"]),
            block_naming: any_rule_is_enabled(config, &["naming.placeholder-identifier"]),
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
                    "error-handling.unimplemented-placeholder",
                ],
            ),
            block_concurrency: any_rule_is_enabled(
                config,
                &[
                    "concurrency.blocking-call-in-async",
                    "concurrency.lock-across-await",
                ],
            ),
            block_security: config.is_rule_enabled("security.insecure-rng-for-secrets"),
            block_test_quality: any_rule_is_enabled(
                config,
                &[
                    "test-quality.ignored-without-reason",
                    "test-quality.long-test",
                    "test-quality.should-panic-without-expected",
                    "test-quality.trivial-assertion",
                    "test-quality.unwrap-in-test",
                ],
            ),
            process_commands: config.is_rule_enabled("security.process-command"),
            duplicate_tests: config.is_rule_enabled("test-quality.duplicate-test-body"),
            sql_dynamic_query: config.is_rule_enabled("security.sql-dynamic-query"),
            tls_verification: config.is_rule_enabled("security.tls-verification-disabled"),
            weak_crypto: config.is_rule_enabled("security.weak-crypto"),
            bind_all_interfaces: config.is_rule_enabled("security.hardcoded-bind-all-interfaces"),
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
                    "waste.unwrap-expect",
                ],
            ),
            item_rules: config.is_rule_enabled("docs.missing-public-doc"),
            dead_code: config.is_rule_enabled("dead-code.unused-private-function"),
            comments: config.is_rule_enabled("docs.commented-out-code"),
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

    /// Say whether any enabled family reads parsed function blocks, so a scan can skip building them when none does.
    ///
    /// Returns true when a block family, the network block security rules or the line rules are enabled; false otherwise.
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

    /// Say whether any family that checks each function block is enabled, which gates the shared block analysis.
    ///
    /// Returns true when any `block_` family is enabled; unlike `needs_function_blocks` it ignores the network and line rules.
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

/// Check whether a family's rules include one the configuration enables, so the family runs only when needed.
///
/// `config` holds the user's rule selection and `rule_ids` lists the identifiers of one family's rules.
/// Returns true when at least one of `rule_ids` is enabled in `config`, and false for an empty list.
fn any_rule_is_enabled(config: &Config, rule_ids: &[&str]) -> bool {
    rule_ids
        .iter()
        .any(|rule_id| config.is_rule_enabled(rule_id))
}

/// Run enabled text and Rust rules for one parsed source unit.
///
/// `unit` is the source unit to scan and `config` selects the enabled rules and their severities.
/// Returns the findings of enabled rules after `apply_configured_severity`; any function blocks built on the way are dropped.
pub(crate) fn analyse(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    analyse_with_artifacts(unit, config, false).findings
}

/// Run enabled text and Rust rules for one source unit, optionally keeping the function blocks built for a Rust file.
///
/// `unit` is the source unit, carrying a Rust syntax tree when one is available, and `config` selects enabled rules and their severities.
/// When `retain_function_blocks` is true and the unit has a syntax tree, the blocks are built even if no rule needed them.
///
/// Returns the findings of enabled rules after `apply_configured_severity`, plus the function blocks if a rule or the caller needed them.
/// The blocks are `None` without a syntax tree, or when neither an enabled rule nor `retain_function_blocks` asked for them.
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

/// Run every enabled Rust rule family on one parsed file, building the function blocks only when some family reads them.
///
/// `unit` is the source unit, `ast` its syntax tree, `config` the rule settings, and `families` the enabled family flags.
/// `function_blocks` caches the blocks, filled here when empty and needed, and findings are appended to `findings`.
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
    analyse_block_dependent_rust_rules(unit, ast, config, families, blocks, findings);
    analyse_rust_source_rules(unit, ast, families, findings);
    analyse_rust_ast_rules(unit, ast, config, families, findings);
}

/// Run the Rust rule families that read function blocks, such as the block rules, closure docs, network security and line rules.
///
/// `blocks` holds the file's function blocks, or `None` when no family needs them, in which case nothing runs.
/// `ast` is the syntax tree, also walked for closure items, trait default methods and the template-injection check.
/// `unit` supplies the file and source, `config` the rule settings and `families` the enabled flags; findings go to `findings`.
fn analyse_block_dependent_rust_rules(
    unit: &SourceUnit<'_>,
    ast: &syn::File,
    config: &Config,
    families: EnabledBuiltinFamilies,
    blocks: Option<&[FunctionBlock]>,
    findings: &mut Vec<Finding>,
) {
    let Some(blocks) = blocks else {
        return;
    };
    if families.has_block_rules() {
        analyse_blocks(unit, blocks, config, families, findings);
    }
    if families.block_docs {
        let closure_items = rust_closure_item_blocks(ast, unit.source);
        analyse_closure_item_docs(unit.file, &closure_items, config, findings);
    }
    if families.block_size || families.block_complexity {
        let trait_defaults = rust_trait_default_blocks(ast, unit.source);
        analyse_measure_only_blocks(unit.file, &trait_defaults, config, families, findings);
        let const_closures = rust_const_closure_blocks(ast, unit.source);
        analyse_measure_only_blocks(unit.file, &const_closures, config, families, findings);
    }
    if families.network_block_security {
        analyse_ssrf_candidate(unit.file, blocks, findings);
        analyse_unsafe_deserialization(unit.file, blocks, findings);
        analyse_template_injection_xss(unit.file, ast, blocks, findings);
    }
    if families.line_rules {
        analyse_line_rules(
            unit.file,
            unit.source,
            blocks,
            unit.external_test_module,
            findings,
        );
    }
}

/// Run the enabled Rust security and modernisation rules that scan the whole file rather than its function blocks.
///
/// `unit` supplies the file and text, `ast` serves the process-command and bind-all-interfaces checks, and `families` gates each check.
/// Findings are appended to `findings`.
fn analyse_rust_source_rules(
    unit: &SourceUnit<'_>,
    ast: &syn::File,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    if families.process_commands {
        analyse_process_commands(unit.file, unit.source, ast, findings);
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
        analyse_hardcoded_bind_all_interfaces(unit, ast, findings);
    }
    if families.xxe_candidate {
        analyse_xxe_candidate(unit.file, unit.source, findings);
    }
    if families.modernisation_source {
        analyse_modernisation_rules(unit.file, unit.source, findings);
    }
}

/// Run the enabled Rust rule families that walk items or comments: duplicate tests, public docs, dead code, comments and naming patterns.
///
/// `unit` supplies the file and source, `ast` is its syntax tree, `config` feeds the naming patterns, and `families` gates each family.
/// Findings are appended to `findings`.
fn analyse_rust_ast_rules(
    unit: &SourceUnit<'_>,
    ast: &syn::File,
    config: &Config,
    families: EnabledBuiltinFamilies,
    findings: &mut Vec<Finding>,
) {
    if families.duplicate_tests {
        analyse_duplicate_tests(unit, ast, findings);
    }
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

/// Apply the severity configured for a finding's rule, except to a lower-band size or complexity finding, which keeps its own.
///
/// `finding` is the finding to adjust, and `config` gives its rule's severity, defaulting to the severity the finding already has.
/// Returns `finding` with the configured severity, or unchanged when `is_lower_band` reports it as lower band.
fn apply_configured_severity(mut finding: Finding, config: &Config) -> Finding {
    // A lower-band size or complexity finding is advisory whatever severity the user configured for its rule.
    if !is_lower_band(&finding) {
        finding.severity = config.severity(&finding.rule_id, finding.severity);
    }
    finding
}
