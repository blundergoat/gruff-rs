//! Validate the exclusions a project writes in `.gruff-rs.yaml` before analysis starts.
//!
//! Ordinary exclusions hide reviewed findings by rule and scope, with a reason in the report.
//! Sensitive-data exclusions need their dedicated section so callers can audit exactly what was removed.

use super::*;

/// Parses the config's `exclude` array into exclusion rules and installs them on the loaded config.
///
/// `exclude_value` is the raw `exclude` value, which must be an array whose entries are each parsed by `parse_exclusion_rule`.
/// `config` supplies the custom rules selectors may name besides built-in rules; on success its `exclusions` list is replaced.
///
/// Returns `Ok(())` once every entry parses, or an `Err` message when `exclude` is not an array or any entry is invalid.
/// On error `config` is left unchanged.
pub(crate) fn apply_exclusions_section(
    exclude_value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    let registry = rules::builtin_registry();
    let entries = exclude_value
        .as_array()
        .ok_or_else(|| "config key `exclude` must be an array".to_string())?;
    let mut exclusions = Vec::new();
    for (index, entry_value) in entries.iter().enumerate() {
        exclusions.push(parse_exclusion_rule(
            index,
            entry_value,
            &registry,
            &config.custom_rules,
        )?);
    }
    config.exclusions = exclusions;
    Ok(())
}

/// Validates one `exclude` entry from the config and builds the `ExclusionRule` it describes.
///
/// `index` is the entry's position in the `exclude` array and is used only to name the entry in error messages.
/// `entry_value` is the raw entry, which must be an object using only the keys `rule`, `paths`, `message_contains` and `reason`.
/// `registry` and `custom_rules` are the built-in and custom rules that the entry's `rule` selector is expanded against.
///
/// Returns the parsed rule with its selector, expanded rule ids, normalized paths, optional message filter and reason.
/// Returns an `Err` message instead when the entry is not an object, has an unknown key, or has an invalid field.
pub(crate) fn parse_exclusion_rule(
    index: usize,
    entry_value: &Value,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
) -> Result<ExclusionRule, String> {
    let entry_path = format!("exclude[{index}]");
    let entry = entry_value
        .as_object()
        .ok_or_else(|| format!("config key `{entry_path}` must be an object"))?;
    reject_unknown_keys(
        entry,
        &["rule", "paths", "message_contains", "reason"],
        &format!("config key `{entry_path}`"),
    )?;

    let (selector, rule_ids) =
        parse_exclusion_selector(entry, &entry_path, registry, custom_rules)?;
    let paths = parse_exclusion_paths(entry, &entry_path)?;
    let message_contains = parse_exclusion_message_filter(entry, &entry_path)?;
    let reason = parse_exclusion_reason(entry, &entry_path)?;

    Ok(ExclusionRule {
        selector,
        rule_ids,
        paths,
        message_contains,
        reason,
    })
}

/// Reads an exclusion entry's required `rule` selector and expands it into the concrete rule ids it covers.
///
/// `entry` is the exclusion object, and `entry_path` is its config path prefix used to name `rule` in error messages.
/// `registry` and `custom_rules` are the built-in and custom rules the selector is resolved against by `expand_rule_selector_with_custom`.
///
/// Returns the selector as written together with its expanded rule ids.
/// Returns an `Err` message instead when `rule` is missing, is not a string, or the selector fails to expand.
fn parse_exclusion_selector(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
) -> Result<(String, BTreeSet<String>), String> {
    let selector = required_config_string(entry, "rule", &format!("{entry_path}.rule"))?;
    let rule_ids = expand_rule_selector_with_custom(
        &selector,
        registry,
        custom_rules,
        &format!("{entry_path}.rule"),
    )?;
    // A broad selector cannot silently hide a sensitive finding. Ask for the exact rule and path in its own audit section.
    if rule_ids.iter().any(|id| id.starts_with("sensitive-data.")) {
        return Err(format!(
            "`{entry_path}.rule` matches a sensitive-data rule; use `sensitiveExclusions` with an exact rule and path"
        ));
    }
    Ok((selector, rule_ids))
}

/// Reads an exclusion entry's optional `paths` list and normalizes each path with `normalize_report_path`.
///
/// `entry` is the exclusion object, and `entry_path` is its config path prefix used to name `paths` in error messages.
///
/// Returns the normalized paths, or an empty list when `paths` is absent.
/// Returns an `Err` message instead when `string_array` rejects the `paths` value.
fn parse_exclusion_paths(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
) -> Result<Vec<String>, String> {
    let paths: Vec<String> = entry
        .get("paths")
        .map(|value| {
            string_array(value, &format!("{entry_path}.paths")).map(|paths| {
                paths
                    .into_iter()
                    .map(|path| normalize_report_path(&path))
                    .collect()
            })
        })
        .transpose()?
        .unwrap_or_default();
    // An exclusion such as `../other-project/**` cannot describe a scope in this report.
    if paths
        .iter()
        .any(|path| !crate::diff::is_relative_scan_path(path))
    {
        return Err(format!(
            "`{entry_path}.paths` must contain project-relative patterns"
        ));
    }
    Ok(paths)
}

/// Reads an exclusion entry's optional `message_contains` filter, rejecting a value that is not a string or is empty.
///
/// `entry` is the exclusion object, and `entry_path` is its config path prefix used to name `message_contains` in error messages.
///
/// Returns `Some` filter text when the key holds a non-empty string, or `None` when `message_contains` is absent.
/// Returns an `Err` message instead when the value is not a string or is the empty string; whitespace-only text is accepted.
fn parse_exclusion_message_filter(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
) -> Result<Option<String>, String> {
    let message_contains = entry
        .get("message_contains")
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                format!("config key `{entry_path}.message_contains` must be a string")
            })
        })
        .transpose()?;
    if message_contains
        .as_deref()
        .is_some_and(|message| message.is_empty())
    {
        return Err(format!(
            "config key `{entry_path}.message_contains` must be a non-empty string"
        ));
    }
    Ok(message_contains)
}

/// Reads an exclusion entry's required `reason`, which must be a string with at least one non-whitespace character.
///
/// `entry` is the exclusion object, and `entry_path` is its config path prefix used to name `reason` in error messages.
///
/// Returns the reason exactly as written, without trimming, or an `Err` message when `reason` is missing, not a string, or blank.
fn parse_exclusion_reason(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
) -> Result<String, String> {
    let reason = required_config_string(entry, "reason", &format!("{entry_path}.reason"))?;
    if reason.trim().is_empty() {
        return Err(format!(
            "config key `{entry_path}.reason` must be a non-empty string"
        ));
    }
    Ok(reason)
}

/// Reads a required string field from a config object and rejects it when it is empty or whitespace-only.
///
/// `object` is the config object to read, and `key` is the name of the required field.
/// `entry_path` is the object's config path; error messages name the field as `entry_path` and `key` joined by a dot.
///
/// Returns the field value without trimming, or an `Err` message when the field is missing, not a string, or blank.
pub(crate) fn required_non_empty_config_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    entry_path: &str,
) -> Result<String, String> {
    let path = format!("{entry_path}.{key}");
    let value = required_config_string(object, key, &path)?;
    if value.trim().is_empty() {
        return Err(format!("config key `{path}` must be a non-empty string"));
    }
    Ok(value)
}

/// Reads a required string field from a config object, reporting a config error when it is missing or not a string.
///
/// `object` is the config object to read, `key` is the field to look up, and `path` is the field's full config path used in error messages.
///
/// Returns an owned copy of the value, which may be empty, or an `Err` message when `key` is missing or its value is not a string.
pub(crate) fn required_config_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<String, String> {
    object
        .get(key)
        .ok_or_else(|| format!("missing required config key `{path}`"))?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("config key `{path}` must be a string"))
}
