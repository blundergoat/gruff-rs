use super::*;

pub(crate) fn apply_selector_settings(
    rules: &serde_json::Map<String, Value>,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    selectors: &mut SelectorSet,
) -> Result<(), String> {
    if let Some(select_value) = rules.get("select") {
        selectors.positive =
            expand_rule_selectors(select_value, registry, custom_rules, "rules.select")?;
        selectors.has_positive = !selectors.positive.is_empty();
    }
    if let Some(ignore_value) = rules.get("ignore") {
        selectors.negative =
            expand_rule_selectors(ignore_value, registry, custom_rules, "rules.ignore")?;
    }
    Ok(())
}

pub(crate) fn apply_custom_rule_settings(
    rules: &serde_json::Map<String, Value>,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    settings: &mut HashMap<String, RuleSetting>,
) -> Result<(), String> {
    let Some(custom_value) = rules.get("custom") else {
        return Ok(());
    };
    let custom = custom_value
        .as_object()
        .ok_or_else(|| "config key `rules.custom` must be an object".to_string())?;
    for (rule_id, rule_value) in custom {
        insert_rule_setting(
            rule_id,
            rule_value,
            registry,
            custom_rules,
            settings,
            "rules.custom",
        )?;
    }
    Ok(())
}

pub(crate) fn insert_rule_setting(
    rule_id: &str,
    rule_value: &Value,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    settings: &mut HashMap<String, RuleSetting>,
    context: &str,
) -> Result<(), String> {
    let is_builtin = registry.contains(rule_id);
    let is_custom = custom_rules.iter().any(|rule| rule.id == rule_id);
    if !is_builtin && !is_custom {
        return Err(format!(
            "unknown rule id `{rule_id}` in config key `{context}`"
        ));
    }
    if settings.contains_key(rule_id) {
        return Err(format!("duplicate rule config for `{rule_id}`"));
    }
    let setting = parse_rule_setting(rule_id, rule_value, registry, is_custom)?;
    settings.insert(rule_id.to_string(), setting);
    Ok(())
}

pub(crate) fn parse_rule_setting(
    rule_id: &str,
    rule_value: &Value,
    registry: &rules::RuleRegistry,
    is_custom: bool,
) -> Result<RuleSetting, String> {
    let rule_object = rule_value
        .as_object()
        .ok_or_else(|| format!("config for rule `{rule_id}` must be an object"))?;
    reject_unknown_keys(
        rule_object,
        &["enabled", "threshold", "severity", "options"],
        &format!("config for rule `{rule_id}`"),
    )?;

    let mut setting = RuleSetting {
        enabled: parse_rule_enabled(rule_id, rule_object)?,
        ..RuleSetting::default()
    };
    if is_custom {
        if rule_object
            .keys()
            .any(|key| !matches!(key.as_str(), "enabled"))
        {
            return Err(format!(
                "custom rule `{rule_id}` only supports `enabled` under `rules`"
            ));
        }
        return Ok(setting);
    }
    apply_rule_thresholds(rule_id, rule_object, registry, &mut setting)?;
    validate_optional_rule_options(rule_id, rule_object, registry, &mut setting)?;
    Ok(setting)
}

pub(crate) fn parse_rule_enabled(
    rule_id: &str,
    rule_object: &serde_json::Map<String, Value>,
) -> Result<Option<bool>, String> {
    rule_object
        .get("enabled")
        .map(|enabled| {
            enabled
                .as_bool()
                .ok_or_else(|| format!("config key `rules.{rule_id}.enabled` must be a boolean"))
        })
        .transpose()
}

pub(crate) fn apply_rule_thresholds(
    rule_id: &str,
    rule_object: &serde_json::Map<String, Value>,
    registry: &rules::RuleRegistry,
    setting: &mut RuleSetting,
) -> Result<(), String> {
    match (rule_object.get("threshold"), rule_object.get("severity")) {
        (Some(threshold_value), Some(severity_value)) => {
            apply_threshold(rule_id, threshold_value, severity_value, registry, setting)?;
        }
        (Some(_), None) => {
            return Err(format!(
                "config key `rules.{rule_id}.severity` is required when `threshold` is configured"
            ));
        }
        (None, Some(_)) => {
            return Err(format!(
                "config key `rules.{rule_id}.severity` requires `threshold`"
            ));
        }
        (None, None) => {}
    }
    Ok(())
}

pub(crate) fn validate_optional_rule_options(
    rule_id: &str,
    rule_object: &serde_json::Map<String, Value>,
    registry: &rules::RuleRegistry,
    setting: &mut RuleSetting,
) -> Result<(), String> {
    if let Some(options_value) = rule_object.get("options") {
        let parsed = validate_rule_options(rule_id, options_value, registry)?;
        setting.string_array_options = parsed;
    }
    Ok(())
}

pub(crate) fn apply_threshold(
    rule_id: &str,
    threshold_value: &Value,
    severity_value: &Value,
    registry: &rules::RuleRegistry,
    setting: &mut RuleSetting,
) -> Result<(), String> {
    ensure_rule_supports_threshold(registry, rule_id)?;
    let number = threshold_value
        .as_f64()
        .ok_or_else(|| format!("threshold `rules.{rule_id}.threshold` must be a number"))?;
    let severity = severity_value
        .as_str()
        .and_then(parse_severity_name)
        .ok_or_else(|| {
            format!("config key `rules.{rule_id}.severity` must be advisory, warning, or error")
        })?;
    setting.threshold = Some(number);
    setting.severity = Some(severity);
    Ok(())
}

pub(crate) fn validate_rule_options(
    rule_id: &str,
    options_value: &Value,
    registry: &rules::RuleRegistry,
) -> Result<HashMap<String, Vec<String>>, String> {
    let options = options_value
        .as_object()
        .ok_or_else(|| format!("config key `rules.{rule_id}.options` must be an object"))?;
    let mut string_arrays = HashMap::new();
    for (name, value) in options {
        let kind = registry
            .option_value_kind(rule_id, name)
            .ok_or_else(|| format!("unknown option `{name}` for rule `{rule_id}`"))?;
        match kind {
            rules::OptionValueKind::StringArray => {
                let parsed = string_array(value, &format!("rules.{rule_id}.options.{name}"))?;
                string_arrays.insert(name.clone(), parsed);
            }
            rules::OptionValueKind::Boolean => {
                value.as_bool().ok_or_else(|| {
                    format!("config key `rules.{rule_id}.options.{name}` must be a boolean")
                })?;
            }
        }
    }
    Ok(string_arrays)
}
