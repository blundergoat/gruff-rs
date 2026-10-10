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
            RuleSources {
                registry,
                custom_rules,
            },
            settings,
            "rules.custom",
        )?;
    }
    Ok(())
}

pub(crate) struct RuleSources<'a> {
    pub(crate) registry: &'a rules::RuleRegistry,
    pub(crate) custom_rules: &'a [CustomRule],
}

pub(crate) fn insert_rule_setting(
    rule_id: &str,
    rule_value: &Value,
    sources: RuleSources<'_>,
    settings: &mut HashMap<String, RuleSetting>,
    context: &str,
) -> Result<(), String> {
    let is_builtin = sources.registry.contains(rule_id);
    let is_custom = sources.custom_rules.iter().any(|rule| rule.id == rule_id);
    if !is_builtin && !is_custom {
        return Err(format!(
            "unknown rule id `{rule_id}` in config key `{context}`"
        ));
    }
    if settings.contains_key(rule_id) {
        return Err(format!("duplicate rule config for `{rule_id}`"));
    }
    let setting = parse_rule_setting(rule_id, rule_value, sources.registry, is_custom)?;
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
    // `thresholds` is a key only for a rule that declares named detector parameters; for every other
    // rule it stays unknown, so a rubric keeps ADR-011's single `threshold`.
    let mut allowed_keys = vec![
        "enabled",
        "threshold",
        "severity",
        "options",
        "excludeFromScore",
    ];
    if !is_custom && !rules::detector_parameters(rule_id).is_empty() {
        allowed_keys.push("thresholds");
    }
    reject_unknown_keys(
        rule_object,
        &allowed_keys,
        &format!("config for rule `{rule_id}`"),
    )?;

    let mut setting = RuleSetting {
        enabled: parse_rule_enabled(rule_id, rule_object)?,
        exclude_from_score: parse_rule_exclude_from_score(rule_id, rule_object)?,
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
    apply_detector_parameters(rule_id, rule_object, &mut setting)?;
    validate_optional_rule_options(rule_id, rule_object, registry, &mut setting)?;
    Ok(setting)
}

fn parse_rule_exclude_from_score(
    rule_id: &str,
    rule_object: &serde_json::Map<String, Value>,
) -> Result<Option<bool>, String> {
    rule_object
        .get("excludeFromScore")
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                format!("config key `rules.{rule_id}.excludeFromScore` must be a boolean")
            })
        })
        .transpose()
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
        (None, Some(severity_value)) => {
            // ADR-011: a standalone `severity` override is for non-threshold rules
            // only. For a thresholded rule it must be paired with `threshold` (the
            // mirror of the `(threshold, None)` error above) so a lone severity
            // can't silently leave the default threshold in place.
            if rule_is_thresholded(rule_id, registry) {
                return Err(format!(
                    "config key `rules.{rule_id}.threshold` is required when `severity` is configured for a thresholded rule"
                ));
            }
            apply_severity_override(rule_id, severity_value, setting)?;
        }
        (None, None) => {}
    }
    Ok(())
}

/// Read `rules.<id>.thresholds` for a rule that declares named detector parameters. Each value is
/// checked against its declared kind and refused, not clamped, so a typo cannot quietly move a bar.
fn apply_detector_parameters(
    rule_id: &str,
    rule_object: &serde_json::Map<String, Value>,
    setting: &mut RuleSetting,
) -> Result<(), String> {
    let Some(thresholds_value) = rule_object.get("thresholds") else {
        return Ok(());
    };
    let thresholds = thresholds_value
        .as_object()
        .ok_or_else(|| format!("config key `rules.{rule_id}.thresholds` must be an object"))?;
    let declared = rules::detector_parameters(rule_id);
    for (name, raw) in thresholds {
        let Some(parameter) = declared.iter().find(|parameter| parameter.name == name) else {
            let names: Vec<&str> = declared.iter().map(|parameter| parameter.name).collect();
            return Err(format!(
                "unknown key `{name}` in config key `rules.{rule_id}.thresholds`; expected one of: {}",
                names.join(", ")
            ));
        };
        let value = parse_detector_parameter(rule_id, parameter, raw)?;
        setting.detector_parameters.insert(name.clone(), value);
    }
    Ok(())
}

/// Check one detector parameter against its declared kind and return it as the analyser reads it.
fn parse_detector_parameter(
    rule_id: &str,
    parameter: &rules::DetectorParameter,
    raw: &Value,
) -> Result<f64, String> {
    let key = format!("rules.{rule_id}.thresholds.{}", parameter.name);
    match parameter.kind {
        rules::DetectorParameterKind::WholeNumber { min, max } => raw
            .as_u64()
            .filter(|value| (min..=max).contains(value))
            .map(|value| value as f64)
            .ok_or_else(|| {
                format!("config key `{key}` must be a whole number from {min} to {max}")
            }),
        rules::DetectorParameterKind::NonNegative => raw
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 0.0)
            .ok_or_else(|| format!("config key `{key}` must be a finite number of zero or more")),
    }
}

// The lookup lives beside the parser that fills it, so reading and validating a detector parameter stay in
// one place.
impl Config {
    /// Return the user's value for a named detector parameter, or the catalogue default `list-rules` and `init` show.
    pub(crate) fn detector_parameter(&self, rule_id: &str, name: &str) -> f64 {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.detector_parameters.get(name).copied())
            .unwrap_or_else(|| rules::builtin_detector_parameter(rule_id, name))
    }
}

fn rule_is_thresholded(rule_id: &str, registry: &rules::RuleRegistry) -> bool {
    registry
        .get(rule_id)
        .is_some_and(|definition| definition.threshold.is_some())
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

pub(crate) fn apply_severity_override(
    rule_id: &str,
    severity_value: &Value,
    setting: &mut RuleSetting,
) -> Result<(), String> {
    let severity = severity_value
        .as_str()
        .and_then(parse_severity_name)
        .ok_or_else(|| {
            format!("config key `rules.{rule_id}.severity` must be advisory, warning, or error")
        })?;
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
        validate_rule_option_entry(rule_id, name, value, registry, &mut string_arrays)?;
    }
    Ok(string_arrays)
}

fn validate_rule_option_entry(
    rule_id: &str,
    name: &str,
    value: &Value,
    registry: &rules::RuleRegistry,
    string_arrays: &mut HashMap<String, Vec<String>>,
) -> Result<(), String> {
    let kind = registry
        .option_value_kind(rule_id, name)
        .ok_or_else(|| format!("unknown option `{name}` for rule `{rule_id}`"))?;
    match kind {
        rules::OptionValueKind::StringArray => {
            let parsed = string_array(value, &format!("rules.{rule_id}.options.{name}"))?;
            string_arrays.insert(name.to_string(), parsed);
        }
        rules::OptionValueKind::Boolean => {
            value.as_bool().ok_or_else(|| {
                format!("config key `rules.{rule_id}.options.{name}` must be a boolean")
            })?;
        }
    }
    Ok(())
}
