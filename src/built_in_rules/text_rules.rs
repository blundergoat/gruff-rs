//! General deterministic text-rule orchestration and file-size checks.
//! The analyzer reaches this module after source discovery; GitHub workflow and
//! explicit action metadata checks are delegated to their focused sibling module.

#[path = "github_metadata_rules.rs"]
mod github_metadata_rules;

use self::github_metadata_rules::{
    analyse_ci_github_event_shell_interpolation, analyse_github_actions_rules,
};
use super::*;
use crate::custom_rules::rust_comment_scope_source;

/// Route one discovered text source through general and metadata-specific rules.
pub(crate) fn analyse_text_rules(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_file_length(unit, config, findings);
    analyse_ci_github_event_shell_interpolation(unit, findings);
    analyse_github_actions_rules(unit, findings);
    analyse_sensitive_data(unit, config, findings);
    analyse_pii_test_fixture(unit, findings);
}

/// Report a source file whose substantive review surface exceeds the configured line threshold.
fn analyse_file_length(unit: &SourceUnit<'_>, config: &Config, findings: &mut Vec<Finding>) {
    // Exempt formats have separate generated, prose, or declarative review contracts.
    if file_length_is_exempt(&unit.file.display_path) {
        return;
    }
    // Bounded Rust sources cannot enter the string-aware comment projection: that
    // masking pass is part of the deep work the budget removes. Raw non-blank lines
    // retain the size signal without reconstructing syntax.
    let line_count = if unit.bounded_deep_scan && unit.file.is_rust {
        unit.source
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
    } else {
        substantive_line_count(&unit.file.display_path, unit.source)
    };
    let rule_id = "size.file-length";
    let threshold = config.threshold(rule_id) as usize;
    // Only files beyond the user's threshold add a size finding to the report.
    if line_count > threshold {
        findings.push(finding_with_metadata(
            SimpleFindingDescriptor {
                rule_id,
                message: format!(
                    "File has {line_count} substantive lines, above the threshold of {threshold}."
                ),
                file: unit.file,
                line: Some(1),
                severity: config.severity(rule_id, rules::builtin_severity(rule_id)),
                pillar: Pillar::Size,
            },
            threshold_metadata(line_count, threshold, "lines"),
        ));
    }
}

/// Count lines that carry code or data: blank lines and comment-only lines are free (family
/// ratification, 2026-08-05), so required documentation cannot push a file over the size bar.
/// Rust sources drop `//` lines and nested `/* */` blocks via the string-aware comment
/// projection; hash-comment formats drop full-line `#` (and `;` for ini-style) comments; other
/// formats count every non-blank line.
fn substantive_line_count(display_path: &str, source: &str) -> usize {
    let normalized = display_path.replace('\\', "/").to_ascii_lowercase();
    if normalized.ends_with(".rs") {
        return rust_substantive_line_count(source);
    }
    let hash_comments = normalized.ends_with(".yaml")
        || normalized.ends_with(".yml")
        || normalized.ends_with(".toml");
    let semicolon_comments = normalized.ends_with(".ini");
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return false;
            }
            if hash_comments && trimmed.starts_with('#') {
                return false;
            }
            if semicolon_comments && (trimmed.starts_with(';') || trimmed.starts_with('#')) {
                return false;
            }
            true
        })
        .count()
}

/// Rust-aware count built on the custom-rule comment projection, which is string- and
/// raw-string-aware and tracks nested block comments. A byte is code when it is non-whitespace
/// in the source and blank in the projection, so a comment marker inside a string stays code
/// and a trailing comment cannot hide the statement in front of it.
fn rust_substantive_line_count(source: &str) -> usize {
    let comment_projection = rust_comment_scope_source(source);
    source
        .lines()
        .zip(comment_projection.lines())
        .filter(|(source_line, comment_line)| {
            source_line
                .bytes()
                .zip(comment_line.bytes())
                .any(|(source_byte, comment_byte)| {
                    !source_byte.is_ascii_whitespace() && comment_byte == b' '
                })
        })
        .count()
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
