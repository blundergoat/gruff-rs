//! Load and validate the `sensitiveExclusions` section that suppresses sensitive-data findings.
//!
//! Each entry names one exact sensitive-data rule id, one project-relative path, an optional
//! symbol, and a required rationale. The section is deliberately separate from `exclude` so the
//! ban on value matching is structural rather than a conditional: no key here can reference a
//! matched secret (FAMILY-CONTRACT.md section 13a). A malformed entry stops the user's command
//! with exit code 2 before any finding can be hidden.

use super::*;

/// The only keys one `sensitiveExclusions` entry may carry.
/// Every message- and value-matching key is therefore rejected as unknown.
const SENSITIVE_EXCLUSION_KEYS: &[&str] = &["rule", "path", "symbol", "reason"];

/// Characters that turn a rule id into a pattern rather than one exact id.
const RULE_PATTERN_CHARACTERS: &[char] = &[
    '*', '?', '[', ']', '{', '}', '(', ')', '|', '^', '$', '+', '\\', '/',
];

/// Characters that turn a path into a glob rather than one exact file.
const PATH_GLOB_CHARACTERS: &[char] = &['*', '?', '[', ']', '{', '}'];

#[derive(Debug, Clone, PartialEq, Eq)]
/// Describe one user-configured sensitive-data suppression from `sensitiveExclusions`.
///
/// The scope is one exact sensitive-data rule id plus one project-relative display path,
/// optionally narrowed to one symbol. An absent symbol means every occurrence of that rule
/// in that file is suppressed, and nothing outside that scope changes.
/// The section carries no message or value matcher, so a user can never express a
/// suppression in terms of the matched secret (FAMILY-CONTRACT.md section 13a).
pub(crate) struct SensitiveExclusionRule {
    pub(crate) rule_id: String,
    pub(crate) path: String,
    pub(crate) symbol: Option<String>,
    pub(crate) reason: String,
}

/// Validate every configured sensitive exclusion and store the resolved scopes.
/// An empty list means the user suppresses no sensitive-data finding.
pub(crate) fn apply_sensitive_exclusions_section(
    section_value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    let registry = rules::builtin_registry();
    let entries = section_value
        .as_array()
        .ok_or_else(|| "config key `sensitiveExclusions` must be an array".to_string())?;
    // The resolved list starts empty so only validated entries can suppress a user's finding.
    let mut sensitive_exclusions: Vec<SensitiveExclusionRule> = Vec::new();
    // Each entry is validated with its list position so every diagnostic names an editable entry.
    for (index, entry_value) in entries.iter().enumerate() {
        let exclusion =
            parse_sensitive_exclusion(index, entry_value, &registry, &config.custom_rules)?;
        reject_duplicate_scope(&sensitive_exclusions, &exclusion, index)?;
        sensitive_exclusions.push(exclusion);
    }
    config.sensitive_exclusions = sensitive_exclusions;
    Ok(())
}

/// Parse one entry into a validated rule, path, optional symbol, and rationale.
/// Any key outside the four supported names fails before analysis begins.
fn parse_sensitive_exclusion(
    index: usize,
    entry_value: &Value,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
) -> Result<SensitiveExclusionRule, String> {
    let entry_path = format!("sensitiveExclusions[{index}]");
    let entry = entry_value
        .as_object()
        .ok_or_else(|| format!("config key `{entry_path}` must be an object"))?;
    reject_unknown_keys(
        entry,
        SENSITIVE_EXCLUSION_KEYS,
        &format!("config key `{entry_path}`"),
    )?;

    Ok(SensitiveExclusionRule {
        rule_id: parse_sensitive_rule_id(entry, &entry_path, registry, custom_rules)?,
        path: parse_sensitive_path(entry, &entry_path)?,
        symbol: parse_sensitive_symbol(entry, &entry_path)?,
        reason: required_non_empty_config_string(entry, "reason", &entry_path)?,
    })
}

/// Accept exactly one registered sensitive-data rule id.
/// Patterns, pillar selectors, unknown ids, and other pillars each fail with their own diagnostic.
fn parse_sensitive_rule_id(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
) -> Result<String, String> {
    let key_path = format!("{entry_path}.rule");
    let rule_id = required_non_empty_config_string(entry, "rule", entry_path)?;
    reject_rule_pattern(&rule_id, &key_path)?;
    let pillar = rule_pillar(&rule_id, registry, custom_rules)
        .ok_or_else(|| format!("unknown rule id `{rule_id}` in config key `{key_path}`"))?;
    // Only the sensitive-data pillar is governed here; every other rule keeps its normal channel.
    if pillar != Pillar::SensitiveData {
        return Err(format!(
            "config key `{key_path}` must name a sensitive-data rule; `{rule_id}` belongs to the {} pillar",
            pillar_label(pillar)
        ));
    }
    Ok(rule_id)
}

/// Reject any rule value that selects more than one rule.
/// A blanket suppression would hide findings nobody reviewed.
fn reject_rule_pattern(rule_id: &str, key_path: &str) -> Result<(), String> {
    // Wildcard, glob, and regular-expression syntax all name a set rather than one rule.
    if rule_id.contains(RULE_PATTERN_CHARACTERS) {
        return Err(format!(
            "config key `{key_path}` must name one exact rule id; `{rule_id}` uses wildcard, glob, or regular-expression syntax"
        ));
    }
    // A pillar name is a selector wearing a rule id and would suppress the whole pillar.
    if parse_pillar_selector(rule_id).is_some() {
        return Err(format!(
            "config key `{key_path}` must name one exact rule id, not the pillar selector `{rule_id}`"
        ));
    }
    Ok(())
}

/// Find the pillar of one built-in or project-defined rule id.
/// `None` means the user named a rule this build does not know.
fn rule_pillar(
    rule_id: &str,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
) -> Option<Pillar> {
    registry
        .get(rule_id)
        .map(|definition| definition.pillar)
        .or_else(|| {
            custom_rules
                .iter()
                .find(|custom_rule| custom_rule.id == rule_id)
                .map(|custom_rule| custom_rule.pillar)
        })
}

/// Accept one project-relative file path and return it in report display form.
/// Absolute paths, parent traversals, and globs each fail before analysis begins.
fn parse_sensitive_path(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
) -> Result<String, String> {
    let key_path = format!("{entry_path}.path");
    let configured = required_non_empty_config_string(entry, "path", entry_path)?;
    let path = normalize_report_path(&configured);
    // An absolute path escapes the analysed project and records the author's machine layout.
    if is_absolute_display_path(&path) {
        return Err(format!(
            "config key `{key_path}` must be a project-relative path; `{configured}` is absolute"
        ));
    }
    // A parent traversal claims a scope outside the project the user asked gruff-rs to analyse.
    if path.split('/').any(|component| component == "..") {
        return Err(format!(
            "config key `{key_path}` must not contain a `..` path component; found `{configured}`"
        ));
    }
    // A glob would suppress findings across files nobody enumerated in review.
    if path.contains(PATH_GLOB_CHARACTERS) {
        return Err(format!(
            "config key `{key_path}` must name one exact file; `{configured}` uses glob syntax"
        ));
    }
    Ok(path)
}

/// Decide whether a normalised display path is absolute on any platform gruff-rs reports for.
/// A leading separator covers POSIX and UNC forms; a single-letter drive prefix covers Windows.
fn is_absolute_display_path(path: &str) -> bool {
    path.starts_with('/')
        || path.split_once(":/").is_some_and(|(drive, _)| {
            drive.len() == 1 && drive.chars().all(|letter| letter.is_ascii_alphabetic())
        })
}

/// Accept the optional symbol that narrows an entry further.
/// `None` means every occurrence of the rule in the named file is in scope.
fn parse_sensitive_symbol(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
) -> Result<Option<String>, String> {
    let key_path = format!("{entry_path}.symbol");
    entry
        .get("symbol")
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("config key `{key_path}` must be a string"))
        })
        .transpose()
}

/// Reject a second entry claiming a scope an earlier entry already owns.
/// Two entries over one scope would split the audit count arbitrarily.
fn reject_duplicate_scope(
    existing: &[SensitiveExclusionRule],
    candidate: &SensitiveExclusionRule,
    index: usize,
) -> Result<(), String> {
    let claimed = existing.iter().position(|entry| {
        entry.rule_id == candidate.rule_id
            && entry.path == candidate.path
            && entry.symbol == candidate.symbol
    });
    match claimed {
        // The earlier index is named so the user can delete or narrow the right entry.
        Some(first_index) => Err(format!(
            "duplicate sensitive exclusion scope in config key `sensitiveExclusions[{index}]`; the same rule, path, and symbol are already claimed by `sensitiveExclusions[{first_index}]`"
        )),
        None => Ok(()),
    }
}
