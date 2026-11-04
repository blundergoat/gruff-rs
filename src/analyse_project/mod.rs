use super::*;

mod architecture;
mod dead_code;
mod dependencies;

pub(crate) use architecture::analyse_architecture_rules;
pub(crate) use dead_code::analyse_project_dead_code_rules;
pub(crate) use dependencies::analyse_dependency_rules;

/// Runs the project-level rules (cross-file dead code, architecture, dependency,
/// missing-README) over an already-built `ProjectContext`.
///
/// Usage: called once per analysis after `ProjectContext` is assembled from the
/// discovered, parsed sources.
///
/// Contract: returns the project-scope findings and appends any run diagnostics
/// (such as partial-context suppression) to `diagnostics`; each rule honours its
/// `config` enablement.
///
/// Failure behaviour: never returns an error - a rule that cannot produce an
/// authoritative result suppresses itself and records a diagnostic instead.
pub(crate) fn analyse_project(
    context: &ProjectContext,
    config: &Config,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !project_has_readme(&context.root_path) && config.is_rule_enabled("docs.missing-readme") {
        findings.push(Finding::new(FindingDescriptor {
            rule_id: "docs.missing-readme".to_string(),
            message: "Project root does not contain a README.md file.".to_string(),
            file_path: "README.md".to_string(),
            line: Some(1),
            severity: Severity::Advisory,
            pillar: Pillar::Documentation,
            confidence: Confidence::High,
            symbol: None,
            remediation: Some(
                "Add a README.md that explains the project purpose and local commands.".to_string(),
            ),
            metadata: json!({}),
        }));
    }

    analyse_dependency_rules(context, config, &mut findings);
    analyse_architecture_rules(context, config, &mut findings);
    analyse_project_dead_code_rules(context, config, diagnostics, &mut findings);

    findings
        .into_iter()
        .map(|finding| apply_configured_severity(finding, config))
        .collect()
}

/// Sets a finding's severity to what `Config::severity` returns for its rule id and current severity, so configured overrides take effect.
///
/// `finding` is the finding to re-rate, taken by value, and `config` is the loaded config consulted for the rule's severity.
///
/// Returns the same finding with only its severity replaced.
fn apply_configured_severity(mut finding: Finding, config: &Config) -> Finding {
    finding.severity = config.severity(&finding.rule_id, finding.severity);
    finding
}

/// Checks whether the project root directly contains an entry named `README.md`, ignoring ASCII case.
///
/// `root_path` is the project root directory; only its immediate entries are listed, so a README in a subdirectory does not count.
/// Unreadable entries and names that are not valid UTF-8 are skipped.
///
/// Returns `true` when such an entry exists, and `false` when none does or the directory cannot be read.
pub(crate) fn project_has_readme(root_path: &Path) -> bool {
    fs::read_dir(root_path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("README.md"))
        })
}

/// Picks a display label for a module, preferring its module path and falling back to its file path.
///
/// `file_path` is the module's source file path and `module_path` its module path, which wins whenever it is not empty.
///
/// Returns an owned copy of `module_path`, or of `file_path` when `module_path` is empty.
pub(crate) fn module_label(file_path: &str, module_path: &str) -> String {
    if module_path.is_empty() {
        file_path.to_string()
    } else {
        module_path.to_string()
    }
}

/// Builds the qualified symbol name for an item by joining its module path, method container and name with `::`.
///
/// `item` is the item summary; its `container` is used only for methods, and its `module_path` prefix only when non-empty.
///
/// Returns the joined name, which is just the item's name when it has no module path and is not a method with a container.
pub(crate) fn item_symbol(item: &ItemSummary) -> String {
    if item.kind == "method" {
        let qualified_method = match &item.container {
            Some(container) => format!("{container}::{}", item.name),
            None => item.name.to_string(),
        };
        return if item.module_path.is_empty() {
            qualified_method
        } else {
            format!("{}::{qualified_method}", item.module_path)
        };
    }
    if item.module_path.is_empty() {
        item.name.to_string()
    } else {
        format!("{}::{}", item.module_path, item.name)
    }
}

impl ProjectContext {
    /// Looks up how many times an identifier was recorded in the project's `identifier_counts` index.
    ///
    /// `name` is the identifier text to look up, matched exactly.
    ///
    /// Returns the recorded count, or `0` when `name` has no entry.
    pub(crate) fn identifier_count(&self, name: &str) -> usize {
        self.identifier_counts
            .get(name)
            .copied()
            .unwrap_or_default()
    }
}

/// Treats optional text as missing when it is absent or contains only whitespace.
///
/// `value` is the optional text to test.
///
/// Returns `true` when `value` is `None`, empty or whitespace-only, and `false` when it has any non-whitespace character.
pub(crate) fn is_missing_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

/// Detects whether a version requirement string uses a wildcard in any of its comma-separated parts.
///
/// `requirement` is the requirement text; it is split on commas and each part is trimmed before checking.
///
/// Returns `true` when any part is exactly `*` or ends with `.*`, and `false` otherwise, including for an empty string.
pub(crate) fn is_wildcard_requirement(requirement: &str) -> bool {
    requirement
        .split(',')
        .any(|part| part.trim() == "*" || part.trim().ends_with(".*"))
}
