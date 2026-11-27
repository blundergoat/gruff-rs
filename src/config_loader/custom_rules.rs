use super::*;

const CUSTOM_RULE_KEYS: &[&str] = &[
    "id",
    "pillar",
    "severity",
    "confidence",
    "message",
    "scope",
    "pattern",
    "include_paths",
    "exclude_paths",
    "remediation",
];

struct CustomRuleIdentity {
    id: String,
    message: String,
}

struct CustomRuleClassification {
    pillar: Pillar,
    severity: Severity,
    confidence: Confidence,
}

struct CustomRulePattern {
    scope: CustomRuleScope,
    pattern: String,
    compiled_pattern: Regex,
}

struct CustomRulePathsAndDoc {
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    remediation: Option<String>,
}

/// Parses one entry of the `custom_rules` config list into a validated custom rule.
///
/// `index` is the entry's position in the list, used to build the config key path named in error messages.
/// `entry_value` is the raw JSON entry, which must be an object using only the known custom rule keys.
/// `registry` holds the built-in rule ids that the custom rule id must not reuse.
///
/// Returns the `CustomRule` with its regex and path matchers compiled, or an `Err` naming the config key that failed validation.
/// Panics when a wildcard in `include_paths` or `exclude_paths` yields a path matcher regex that fails to compile.
pub(crate) fn parse_custom_rule(
    index: usize,
    entry_value: &Value,
    registry: &rules::RuleRegistry,
) -> Result<CustomRule, String> {
    let entry_path = format!("custom_rules[{index}]");
    let entry = entry_value
        .as_object()
        .ok_or_else(|| format!("config key `{entry_path}` must be an object"))?;
    reject_unknown_keys(
        entry,
        CUSTOM_RULE_KEYS,
        &format!("config key `{entry_path}`"),
    )?;

    let identity = parse_custom_rule_identity(entry, &entry_path, registry)?;
    let classification = parse_custom_rule_classification(entry, &entry_path)?;
    let pattern = parse_custom_rule_pattern(entry, &entry_path)?;
    let paths_and_doc = parse_custom_rule_paths_and_doc(entry, &entry_path)?;

    Ok(CustomRule {
        id: identity.id,
        message: identity.message,
        pillar: classification.pillar,
        severity: classification.severity,
        confidence: classification.confidence,
        scope: pattern.scope,
        pattern: pattern.pattern,
        compiled_pattern: pattern.compiled_pattern,
        include_path_matchers: compile_path_matchers(&paths_and_doc.include_paths),
        exclude_path_matchers: compile_path_matchers(&paths_and_doc.exclude_paths),
        remediation: paths_and_doc.remediation,
    })
}

/// Reads and validates the required `id` and `message` fields of a custom rule entry.
///
/// `entry` is the custom rule's JSON object.
/// `entry_path` is the entry's config key path, used as the prefix of the key paths in error messages.
/// `registry` holds the built-in rule ids that the custom `id` must not reuse.
///
/// Returns the id and message, or an `Err` when either field is missing or invalid or the id fails `validate_custom_rule_id`.
fn parse_custom_rule_identity(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
    registry: &rules::RuleRegistry,
) -> Result<CustomRuleIdentity, String> {
    let id = required_config_string(entry, "id", &format!("{entry_path}.id"))?;
    validate_custom_rule_id(&id, &format!("{entry_path}.id"), registry)?;
    let message = required_non_empty_config_string(entry, "message", entry_path)?;
    Ok(CustomRuleIdentity { id, message })
}

/// Reads a custom rule entry's required `pillar` and `severity` fields and its optional `confidence` score.
///
/// `entry` is the custom rule's JSON object.
/// `entry_path` is the entry's config key path, used as the prefix of the key paths in error messages.
///
/// Returns the pillar, severity and confidence, or an `Err` when `pillar` or `severity` is missing or unknown or `confidence` is invalid.
/// A missing `confidence` defaults to `Confidence::Medium`.
fn parse_custom_rule_classification(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
) -> Result<CustomRuleClassification, String> {
    let pillar = parse_required_pillar(entry, "pillar", &format!("{entry_path}.pillar"))?;
    let severity = parse_required_severity(entry, "severity", &format!("{entry_path}.severity"))?;
    let confidence = entry
        .get("confidence")
        .map(|value| parse_custom_confidence(value, &format!("{entry_path}.confidence")))
        .transpose()?
        .unwrap_or(Confidence::Medium);
    Ok(CustomRuleClassification {
        pillar,
        severity,
        confidence,
    })
}

/// Reads a custom rule entry's `scope` and `pattern` fields and compiles the pattern as a regular expression.
///
/// `entry` is the custom rule's JSON object.
/// `entry_path` is the entry's config key path, used as the prefix of the key paths in error messages.
///
/// Returns the scope, pattern source and compiled `Regex`, or an `Err` when either field is missing or invalid or the regex fails to compile.
fn parse_custom_rule_pattern(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
) -> Result<CustomRulePattern, String> {
    let scope = parse_custom_rule_scope(
        &required_config_string(entry, "scope", &format!("{entry_path}.scope"))?,
        &format!("{entry_path}.scope"),
    )?;
    let pattern = required_non_empty_config_string(entry, "pattern", entry_path)?;
    let compiled_pattern = Regex::new(&pattern).map_err(|error| {
        format!("config key `{entry_path}.pattern` failed to compile regex: {error}")
    })?;
    Ok(CustomRulePattern {
        scope,
        pattern,
        compiled_pattern,
    })
}

/// Reads a custom rule entry's optional `include_paths`, `exclude_paths` and `remediation` fields.
///
/// `entry` is the custom rule's JSON object.
/// `entry_path` is the entry's config key path, used as the prefix of the key paths in error messages.
///
/// Returns the normalized include and exclude paths, empty when absent, and the remediation text, `None` when absent.
/// An `Err` is returned instead when a path list is not a valid string array or `remediation` is not a string.
fn parse_custom_rule_paths_and_doc(
    entry: &serde_json::Map<String, Value>,
    entry_path: &str,
) -> Result<CustomRulePathsAndDoc, String> {
    let include_paths = optional_normalized_string_array(
        entry,
        "include_paths",
        &format!("{entry_path}.include_paths"),
    )?;
    let exclude_paths = optional_normalized_string_array(
        entry,
        "exclude_paths",
        &format!("{entry_path}.exclude_paths"),
    )?;
    let remediation = entry
        .get("remediation")
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("config key `{entry_path}.remediation` must be a string"))
        })
        .transpose()?;
    Ok(CustomRulePathsAndDoc {
        include_paths,
        exclude_paths,
        remediation,
    })
}

/// Checks that a custom rule id is in the reserved `custom.` namespace and does not collide with a built-in rule id.
///
/// The slug after `custom.` must be non-empty lowercase ASCII letters, digits and hyphens, not starting or ending with a hyphen.
///
/// `id` is the configured rule id to check.
/// `path` is the config key path named in error messages.
/// `registry` holds the built-in rule ids that `id` must not match.
///
/// Returns `Ok(())` for a valid id, or an `Err` saying whether the prefix, the slug or a built-in collision failed.
pub(crate) fn validate_custom_rule_id(
    id: &str,
    path: &str,
    registry: &rules::RuleRegistry,
) -> Result<(), String> {
    let Some(slug) = id.strip_prefix("custom.") else {
        return Err(format!(
            "config key `{path}` must start with the reserved `custom.` namespace"
        ));
    };
    if slug.is_empty()
        || slug.starts_with('-')
        || slug.ends_with('-')
        || !slug.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    {
        return Err(format!(
            "config key `{path}` must use `custom.<slug>` with lowercase ASCII letters, digits, and hyphens"
        ));
    }
    if registry.contains(id) {
        return Err(format!(
            "config key `{path}` collides with built-in rule id `{id}`"
        ));
    }
    Ok(())
}

/// Reads a required string field from a config object and resolves it to a public pillar.
///
/// `object` is the JSON object holding the field.
/// `key` is the field name to read.
/// `path` is the full config key path named in error messages.
///
/// Returns the `Pillar` matched by `parse_pillar_selector`, or an `Err` when the field is missing or invalid or names no known pillar.
pub(crate) fn parse_required_pillar(
    object: &serde_json::Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Pillar, String> {
    let pillar = required_config_string(object, key, path)?;
    parse_pillar_selector(&pillar).ok_or_else(|| {
        format!(
            "unknown pillar `{pillar}` in `{path}`; expected a public pillar such as Documentation"
        )
    })
}

/// Reads a required string field from a config object and resolves it to a finding severity.
///
/// `object` is the JSON object holding the field.
/// `key` is the field name to read.
/// `path` is the full config key path named in error messages.
///
/// Returns the `Severity` matched by `parse_severity_name`, or an `Err` when the field is missing, invalid or not advisory, warning or error.
pub(crate) fn parse_required_severity(
    object: &serde_json::Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Severity, String> {
    let severity = required_config_string(object, key, path)?;
    parse_severity_name(&severity).ok_or_else(|| {
        format!("unknown severity `{severity}` in `{path}`; expected advisory, warning, or error")
    })
}

/// Parses a severity name, ignoring surrounding whitespace and letter case.
///
/// `value` is the severity text from config, expected to be advisory, warning or error.
///
/// Returns the matching `Severity`, or `None` for any other text.
pub(crate) fn parse_severity_name(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "advisory" => Some(Severity::Advisory),
        "warning" => Some(Severity::Warning),
        "error" => Some(Severity::Error),
        _ => None,
    }
}

/// Converts a custom rule's numeric confidence score into a confidence band.
///
/// `value` is the configured JSON value, which must be a number from 0.0 to 1.0 inclusive.
/// `path` is the config key path named in error messages.
///
/// Returns `Confidence::High` from 0.85, `Confidence::Medium` from 0.5 and `Confidence::Low` below that.
/// An `Err` is returned instead when `value` is not a number or lies outside 0.0 to 1.0.
pub(crate) fn parse_custom_confidence(value: &Value, path: &str) -> Result<Confidence, String> {
    let number = value
        .as_f64()
        .ok_or_else(|| format!("config key `{path}` must be a number from 0.0 to 1.0"))?;
    if !(0.0..=1.0).contains(&number) {
        return Err(format!("config key `{path}` must be between 0.0 and 1.0"));
    }
    if number >= 0.85 {
        Ok(Confidence::High)
    } else if number >= 0.5 {
        Ok(Confidence::Medium)
    } else {
        Ok(Confidence::Low)
    }
}

/// Maps a custom rule's configured scope name, ignoring surrounding whitespace, to its `CustomRuleScope` variant.
///
/// `value` is the scope text, one of text, rust-code or comments, matched case-sensitively.
/// `path` is the config key path named in error messages.
///
/// Returns `CustomRuleScope::Text`, `CustomRuleScope::RustCode` or `CustomRuleScope::Comments`, or an `Err` for any other name.
pub(crate) fn parse_custom_rule_scope(value: &str, path: &str) -> Result<CustomRuleScope, String> {
    match value.trim() {
        "text" => Ok(CustomRuleScope::Text),
        "rust-code" => Ok(CustomRuleScope::RustCode),
        "comments" => Ok(CustomRuleScope::Comments),
        other => Err(format!(
            "unknown custom rule scope `{other}` in `{path}`; expected text, rust-code, or comments"
        )),
    }
}

/// Reads an optional array of path strings from a config object and normalizes each with `normalize_report_path`.
///
/// `object` is the JSON object that may hold the field.
/// `key` is the field name to read.
/// `path` is the config key path named in error messages.
///
/// Returns the normalized paths, an empty list when the field is absent, or an `Err` when the value is not a valid string array.
pub(crate) fn optional_normalized_string_array(
    object: &serde_json::Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Vec<String>, String> {
    object
        .get(key)
        .map(|value| {
            string_array(value, path).map(|paths| {
                paths
                    .into_iter()
                    .map(|path| normalize_report_path(&path))
                    .collect()
            })
        })
        .transpose()
        .map(Option::unwrap_or_default)
}
