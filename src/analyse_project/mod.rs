use super::*;

mod architecture;
mod dead_code;
mod dependencies;

pub(crate) use architecture::analyse_architecture_rules;
pub(crate) use dead_code::analyse_project_dead_code_rules;
pub(crate) use dependencies::analyse_dependency_rules;

pub(crate) fn analyse_project(context: &ProjectContext, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !context.root_path.join("README.md").exists()
        && config.is_rule_enabled("docs.missing-readme")
    {
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
    analyse_project_dead_code_rules(context, config, &mut findings);

    findings
}

pub(crate) fn module_label(file_path: &str, module_path: &str) -> String {
    if module_path.is_empty() {
        file_path.to_string()
    } else {
        module_path.to_string()
    }
}

pub(crate) fn item_symbol(item: &ItemSummary) -> String {
    if item.module_path.is_empty() {
        item.name.to_string()
    } else {
        format!("{}::{}", item.module_path, item.name)
    }
}

pub(crate) fn rust_identifier_occurrences(context: &ProjectContext, name: &str) -> usize {
    context
        .rust_sources
        .iter()
        .map(|source| identifier_occurrences(&source.source, name))
        .sum()
}

pub(crate) fn identifier_occurrences(source: &str, name: &str) -> usize {
    let pattern = format!(r"\b{}\b", regex::escape(name));
    Regex::new(&pattern)
        .expect("escaped identifier regex compiles")
        .find_iter(source)
        .count()
}

pub(crate) fn is_missing_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

pub(crate) fn is_wildcard_requirement(requirement: &str) -> bool {
    requirement
        .split(',')
        .any(|part| part.trim() == "*" || part.trim().ends_with(".*"))
}
