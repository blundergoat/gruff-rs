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
pub(crate) static NPATH_BRANCH_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static NPATH_BOOLEAN_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static METRIC_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
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

/// Run enabled text and Rust rules for one parsed source unit.
pub(crate) fn analyse(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::with_capacity(8);
    analyse_text_rules(unit, config, &mut findings);
    if let Some(ast) = unit.rust_ast {
        let blocks = rust_function_blocks(ast, unit.source);
        analyse_blocks(unit.file, &blocks, config, &mut findings);
        analyse_process_commands(unit.file, unit.source, &mut findings);
        analyse_tls_verification_disabled(unit.file, unit.source, &mut findings);
        analyse_line_rules(unit.file, unit.source, &blocks, &mut findings);
        analyse_item_rules(unit.file, ast, &mut findings);
        analyse_dead_code(unit.file, ast, unit.source, &mut findings);
        analyse_comment_rules(unit.file, unit.source, &mut findings);
        analyse_naming_patterns(unit.file, ast, config, &mut findings);
    }
    findings
        .into_iter()
        .filter(|finding| config.is_rule_enabled(&finding.rule_id))
        .collect()
}
