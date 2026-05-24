use super::*;

pub(crate) fn expand_rule_selectors(
    selectors_value: &Value,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    path: &str,
) -> Result<BTreeSet<String>, String> {
    let selectors = string_array(selectors_value, path)?;
    let mut expanded = BTreeSet::new();
    for (index, selector) in selectors.iter().enumerate() {
        let selector_path = selector_config_path(path, index);
        expanded.extend(expand_rule_selector_with_custom(
            selector,
            registry,
            custom_rules,
            &selector_path,
        )?);
    }
    Ok(expanded)
}

pub(crate) fn selector_config_path(path: &str, index: usize) -> String {
    format!("{path}[{index}]")
}

#[cfg(test)]
pub(crate) fn expand_rule_selector(
    selector: &str,
    registry: &rules::RuleRegistry,
    path: &str,
) -> Result<BTreeSet<String>, String> {
    expand_rule_selector_with_custom(selector, registry, &[], path)
}

pub(crate) fn expand_rule_selector_with_custom(
    selector: &str,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    path: &str,
) -> Result<BTreeSet<String>, String> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(format!(
            "empty selector in `{path}`; expected exact rule id, dotted prefix, or public pillar"
        ));
    }
    reject_unsupported_selector_syntax(selector, path)?;
    let catalog = rule_selector_catalog(registry, custom_rules);
    exact_rule_selector(selector, &catalog)
        .or_else(|| pillar_rule_selector(selector, &catalog))
        .or_else(|| prefix_rule_selector(selector, &catalog))
        .ok_or_else(|| {
            format!(
                "unknown selector `{selector}` in `{path}`; expected exact rule id, dotted prefix, or public pillar such as Security"
            )
        })
}

pub(crate) fn reject_unsupported_selector_syntax(selector: &str, path: &str) -> Result<(), String> {
    if selector.contains(':') {
        return Err(format!(
            "unsupported selector `{selector}` in `{path}`; tier/profile selectors are reserved for future registry metadata"
        ));
    }
    if selector.contains('*') && !selector.ends_with(".*") {
        return Err(format!(
            "unsupported selector `{selector}` in `{path}`; only dotted prefix selectors such as `security.*` are supported"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct RuleSelectorEntry {
    id: String,
    pillar: Pillar,
}

pub(crate) fn rule_selector_catalog(
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
) -> Vec<RuleSelectorEntry> {
    let mut entries: Vec<RuleSelectorEntry> = registry
        .definitions()
        .iter()
        .map(|definition| RuleSelectorEntry {
            id: definition.id.to_string(),
            pillar: definition.pillar,
        })
        .collect();
    entries.extend(custom_rules.iter().map(|rule| RuleSelectorEntry {
        id: rule.id.clone(),
        pillar: rule.pillar,
    }));
    entries
}

pub(crate) fn exact_rule_selector(
    selector: &str,
    entries: &[RuleSelectorEntry],
) -> Option<BTreeSet<String>> {
    if entries.iter().any(|entry| entry.id == selector) {
        return Some(BTreeSet::from([selector.to_string()]));
    }
    None
}

pub(crate) fn pillar_rule_selector(
    selector: &str,
    entries: &[RuleSelectorEntry],
) -> Option<BTreeSet<String>> {
    let pillar = parse_pillar_selector(selector)?;
    Some(
        entries
            .iter()
            .filter(|entry| entry.pillar == pillar)
            .map(|entry| entry.id.clone())
            .collect(),
    )
}

pub(crate) fn prefix_rule_selector(
    selector: &str,
    entries: &[RuleSelectorEntry],
) -> Option<BTreeSet<String>> {
    let prefix = selector.strip_suffix(".*").unwrap_or(selector);
    let prefix_with_dot = format!("{prefix}.");
    let matches: BTreeSet<String> = entries
        .iter()
        .filter(|entry| entry.id.starts_with(&prefix_with_dot))
        .map(|entry| entry.id.clone())
        .collect();
    if !matches.is_empty() {
        return Some(matches);
    }
    None
}

pub(crate) fn parse_pillar_selector(selector: &str) -> Option<Pillar> {
    let normalized = normalize_selector_name(selector);
    PILLAR_SELECTOR_NAMES
        .iter()
        .find_map(|(name, pillar)| (normalize_selector_name(name) == normalized).then_some(*pillar))
}

pub(crate) fn normalize_selector_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(|character| character.to_lowercase())
        .collect()
}

const PILLAR_SELECTOR_NAMES: &[(&str, Pillar)] = &[
    ("Size", Pillar::Size),
    ("Complexity", Pillar::Complexity),
    ("DeadCode", Pillar::DeadCode),
    ("Dead code", Pillar::DeadCode),
    ("Waste", Pillar::Waste),
    ("Maintainability", Pillar::Maintainability),
    ("Naming", Pillar::Naming),
    ("Documentation", Pillar::Documentation),
    ("Modernisation", Pillar::Modernisation),
    ("Security", Pillar::Security),
    ("SensitiveData", Pillar::SensitiveData),
    ("Sensitive data", Pillar::SensitiveData),
    ("TestQuality", Pillar::TestQuality),
    ("Test quality", Pillar::TestQuality),
    ("Design", Pillar::Design),
];
