use super::*;

/// Expands a config list of rule selectors into the set of built-in and custom rule ids they select.
///
/// `selectors_value` is the JSON value, which must be an array of selector strings.
/// `registry` supplies the built-in rule ids and their pillars.
/// `custom_rules` are the configured custom rules, which selectors can also select.
///
/// `path` is the config key path of the list; each selector's errors name its indexed path.
///
/// Returns the union of ids selected by all entries, or an `Err` when the value is not a string array or any selector fails.
/// The union is empty when the list is empty or names only pillars that have no rules.
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

/// Builds the config key path of one selector within a selector list, for error messages.
///
/// `path` is the config key path of the list.
/// `index` is the selector's zero-based position in the list.
///
/// Returns `path` followed by `index` in square brackets.
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

/// Expands one rule selector into the ids it selects from the built-in and custom rule catalog.
///
/// The trimmed selector is tried as an exact rule id, then a pillar name, then a dotted prefix with or without a trailing `.*`.
///
/// `selector` is the selector text; surrounding whitespace is ignored.
/// `registry` supplies the built-in rule ids and their pillars.
/// `custom_rules` are the configured custom rules, added to the catalog.
///
/// `path` is the config key path named in error messages.
///
/// Returns the selected ids, or an `Err` when the selector is empty, uses unsupported syntax, or is no known id, pillar name or id prefix.
/// A known pillar with no rules selects an empty set rather than failing.
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
            if is_config_selector_path(path) && crate::migrate_config::is_retired_0_5_rule(selector)
            {
                format!(
                    "unknown selector `{selector}` in `{path}` (retired in 0.6.0). {}",
                    crate::migrate_config::MIGRATE_CONFIG_HINT
                )
            } else {
                format!(
                    "unknown selector `{selector}` in `{path}`; expected exact rule id, dotted prefix, or public pillar such as Security"
                )
            }
        })
}

/// Tell whether selector `path` originates from a config file section rather than a CLI flag.
///
/// `path` is the diagnostic location passed into selector expansion.
/// Returns true for `rules.select[...]`, `rules.ignore[...]`, and `exclude[...].rule`, and false for CLI flags such as `rules --selector`.
fn is_config_selector_path(path: &str) -> bool {
    path.starts_with("rules.select[")
        || path.starts_with("rules.ignore[")
        || (path.starts_with("exclude[") && path.ends_with("].rule"))
}

/// Rejects selectors that use the reserved colon syntax for tiers and profiles, or a `*` without ending in `.*`.
///
/// `selector` is the selector text to check.
/// `path` is the config key path named in error messages.
///
/// Returns `Ok(())` when neither check fails, or an `Err` that names the selector and why it is unsupported.
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

/// Lists every selectable rule with its pillar so selectors can match built-in and custom rules alike.
///
/// `registry` supplies the built-in rule definitions.
/// `custom_rules` are the configured custom rules, listed after the built-in rules.
///
/// Returns one id and pillar entry per built-in rule in registry order, followed by one per custom rule.
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

/// Matches a selector that names one rule id exactly, comparing case-sensitively.
///
/// `selector` is the selector text to look up.
/// `entries` is the catalog of selectable rules.
///
/// Returns a set holding just `selector` when an entry has that id, or `None` otherwise.
pub(crate) fn exact_rule_selector(
    selector: &str,
    entries: &[RuleSelectorEntry],
) -> Option<BTreeSet<String>> {
    if entries.iter().any(|entry| entry.id == selector) {
        return Some(BTreeSet::from([selector.to_string()]));
    }
    None
}

/// Matches a selector that names a public pillar and selects every rule in that pillar.
///
/// `selector` is the selector text, compared with pillar names ignoring case and non-alphanumeric characters.
/// `entries` is the catalog of selectable rules.
///
/// Returns the ids of all entries in the named pillar, possibly empty, or `None` when `selector` names no pillar.
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

/// Matches a dotted prefix selector against the rule ids, with or without a trailing `.*`.
///
/// `selector` is the selector text; a trailing `.*` is dropped and the remaining prefix must be followed by a dot in a matching id.
/// `entries` is the catalog of selectable rules.
///
/// Returns the ids that start with the prefix and a dot, or `None` when no id does.
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

/// Resolves a pillar name, such as `DeadCode` or `Dead code`, to its pillar while ignoring case and non-alphanumeric characters.
///
/// `selector` is the text to resolve, from a rule selector or a pillar config field.
///
/// Returns the matching `Pillar`, or `None` when the text names no public pillar.
pub(crate) fn parse_pillar_selector(selector: &str) -> Option<Pillar> {
    let normalized = normalize_selector_name(selector);
    PILLAR_SELECTOR_NAMES
        .iter()
        .find_map(|(name, pillar)| (normalize_selector_name(name) == normalized).then_some(*pillar))
}

/// Reduces a name to its lowercased ASCII letters and digits so pillar names compare loosely.
///
/// `value` is the name to normalize.
///
/// Returns `value` with every character that is not an ASCII letter or digit removed and the rest lowercased.
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
