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

pub(crate) fn parse_severity_name(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "advisory" => Some(Severity::Advisory),
        "warning" => Some(Severity::Warning),
        "error" => Some(Severity::Error),
        _ => None,
    }
}

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
