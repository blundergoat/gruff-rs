//! General deterministic text-rule orchestration and file-size checks.
//! The analyzer reaches this module after source discovery; GitHub workflow and
//! explicit action metadata checks are delegated to their focused sibling module.

#[path = "github_metadata_rules.rs"]
mod github_metadata_rules;

use self::github_metadata_rules::{
    analyse_ci_github_event_shell_interpolation, analyse_github_actions_rules,
};
use super::*;

/// Route one discovered text source through general and metadata-specific rules.
pub(crate) fn analyse_text_rules(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_file_length(unit.file, unit.source, config, findings);
    analyse_ci_github_event_shell_interpolation(unit, findings);
    analyse_github_actions_rules(unit, findings);
    analyse_sensitive_data(unit, config, findings);
    analyse_pii_test_fixture(unit, findings);
}

/// Report a source file whose review surface exceeds the configured line threshold.
fn analyse_file_length(
    file: &SourceFile,
    source: &str,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    // Exempt formats have separate generated, prose, or declarative review contracts.
    if file_length_is_exempt(&file.display_path) {
        return;
    }
    let line_count = source.lines().count();
    let rule_id = "size.file-length";
    let threshold = config.threshold(rule_id, 600.0) as usize;
    // Only files beyond the user's threshold add a size finding to the report.
    if line_count > threshold {
        findings.push(finding_with_metadata(
            SimpleFindingDescriptor {
                rule_id,
                message: format!(
                    "File has {line_count} lines, above the threshold of {threshold}."
                ),
                file,
                line: Some(1),
                severity: config.severity(rule_id, Severity::Warning),
                pillar: Pillar::Size,
            },
            threshold_metadata(line_count, threshold, "lines"),
        ));
    }
}

/// Identify file shapes whose length is not a useful source-review signal.
fn file_length_is_exempt(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    // `rsplit` always yields one segment; the fallback names an unexpected empty iterator safely.
    let file_name = normalized
        .rsplit('/')
        .next()
        .unwrap_or(&normalized)
        .to_ascii_lowercase();
    file_name_is_lockfile(&file_name)
        || file_name_is_markdown(&file_name)
        || file_name.ends_with(".sh")
        || path_is_rule_definition_table(&normalized)
        || path_is_calibration_case_table(&normalized)
        || path_is_agent_hook(&normalized)
}

/// Recognise dependency lockfiles governed by their package manager.
fn file_name_is_lockfile(file_name: &str) -> bool {
    matches!(
        file_name,
        "cargo.lock" | "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml"
    ) || file_name.ends_with(".lock")
}

/// Recognise Markdown prose governed by documentation review.
fn file_name_is_markdown(file_name: &str) -> bool {
    file_name.ends_with(".md") || file_name.ends_with(".markdown")
}

/// Recognise declarative rule tables that intentionally centralise many entries.
fn path_is_rule_definition_table(normalized: &str) -> bool {
    normalized.starts_with("src/rules/") && normalized.ends_with("_definitions.rs")
}

/// Recognise calibration case tables whose repeated fixtures are intentional.
fn path_is_calibration_case_table(normalized: &str) -> bool {
    normalized.starts_with("src/tests/calibration/") && normalized.ends_with("_cases.rs")
}

/// Recognise agent hook scripts governed by shell and hook-specific checks.
fn path_is_agent_hook(normalized: &str) -> bool {
    normalized.contains("/.codex/hooks/")
        || normalized.contains("/.claude/hooks/")
        || normalized.starts_with(".codex/hooks/")
        || normalized.starts_with(".claude/hooks/")
}
