use super::*;

/// Read the `rules.select` and `rules.ignore` config keys into the positive and negative rule selectors.
///
/// `rules` is the parsed `rules` config object; `registry` and `custom_rules` are the built-in and custom rules a selector can name.
/// `selectors` is changed in place: `select` replaces its positive list and sets `has_positive` to whether that list is non-empty.
/// `ignore` replaces its negative list, and an absent key leaves its list untouched.
///
/// Returns Err with the message from `expand_rule_selectors` when either key fails to expand.
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

/// Read the `rules.custom` config object into per-rule settings, one entry per configured rule id.
///
/// `rules` is the parsed `rules` config object, and `registry` and `custom_rules` are the rule sources each id must belong to.
/// Each parsed setting is inserted into `settings` by `insert_rule_setting`; an absent `rules.custom` key changes nothing.
///
/// Returns Err when `rules.custom` is not an object, or with the first error from `insert_rule_setting` for an unknown, duplicate or invalid entry.
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

/// Validate and store the config for one rule id, refusing ids no rule source knows and ids that already have a setting.
///
/// `rule_id` is the configured rule id and `rule_value` is its config value, parsed by `parse_rule_setting`.
/// `sources` holds the registry and custom rules that decide whether the id is built-in or custom; the parsed setting goes into `settings`.
/// `context` is the config key named in the unknown-id message, such as `rules.custom`.
///
/// Returns Err for an unknown id, for an id already in `settings`, or with the error from `parse_rule_setting`.
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
        if crate::migrate_config::is_retired_0_5_rule(rule_id) {
            return Err(crate::migrate_config::retired_rule_config_error(
                rule_id, context,
            ));
        }
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

/// Parse one rule's config object into a `RuleSetting`, accepting only the keys that kind of rule supports.
///
/// `rule_id` names the rule in error messages and selects its detector parameters, and `registry` supplies its threshold and option metadata.
/// `rule_value` must be an object; `is_custom` marks a custom rule, which accepts only `enabled`.
/// A built-in rule also takes `threshold`, `severity`, `options` and `excludeFromScore`, plus `thresholds` when it declares detector parameters.
///
/// Returns the parsed setting, or Err when the value is not an object, holds a key the rule does not accept, or fails a value check.
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

/// Read a rule's optional `excludeFromScore` flag from its config object.
///
/// `rule_id` names the rule in the error message and `rule_object` is the rule's config object.
/// Returns None when the key is absent, Some with the flag when it is a boolean, and Err when it holds any other value.
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

/// Read a rule's optional `enabled` switch from its config object.
///
/// `rule_id` names the rule in the error message and `rule_object` is the rule's config object.
/// Returns None when the key is absent, Some with the switch when it is a boolean, and Err when it holds any other value.
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

/// Apply a rule's `threshold` and `severity` config keys under the ADR-011 pairing rules.
///
/// `rule_id` names the rule, `rule_object` is its config object, and `registry` tells whether the rule is thresholded.
/// With both keys `setting` gets the threshold and severity; a lone `severity` on a non-thresholded rule sets only its severity.
///
/// Returns Err for `threshold` without `severity` or a lone `severity` on a thresholded rule.
/// Errors from `apply_threshold` and `apply_severity_override` are passed through.
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
///
/// `rule_id` names the rule whose declared parameters are looked up, `rule_object` is its config object, and accepted values go into `setting`.
/// Returns Ok when `thresholds` is absent, and Err when it is not an object, names an undeclared parameter, or holds a refused value.
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
///
/// `rule_id` and the declared name of `parameter` form the config key named in errors, and the kind of `parameter` sets the accepted range.
/// `raw` is the configured value: a whole-number kind needs an integer within its inclusive bounds, a non-negative kind a finite number >= 0.
/// Returns the accepted value as an f64, or Err naming the key and the accepted range when `raw` has the wrong type or is out of range.
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
    ///
    /// `rule_id` is the rule whose settings are searched and `name` is the detector parameter name under its `thresholds`.
    /// Returns the configured value when that rule's settings hold `name`, otherwise `rules::builtin_detector_parameter` for the same pair.
    /// Panics, through `rules::builtin_detector_parameter`, when no value is configured and the rule does not declare `name`.
    pub(crate) fn detector_parameter(&self, rule_id: &str, name: &str) -> f64 {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.detector_parameters.get(name).copied())
            .unwrap_or_else(|| rules::builtin_detector_parameter(rule_id, name))
    }

    /// Return whether a boolean rule option is on; an option left unset takes its native default.
    ///
    /// `rule_id` is the rule whose settings are searched and `option` is the boolean option name under its `options`.
    /// Returns the configured boolean, or `boolean_option_default` when the rule has no settings or never set `option`.
    pub(crate) fn is_rule_option_enabled(&self, rule_id: &str, option: &str) -> bool {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.boolean_options.get(option).copied())
            .unwrap_or_else(|| Self::boolean_option_default(rule_id, option))
    }

    /// Return the value a boolean rule option takes when config leaves it unset. `everyCallable` is on by default
    /// for the three documentation rules, so every callable is checked unless a project sets it to false.
    ///
    /// `rule_id` names the rule and `option` the boolean option under its `options`.
    /// Returns true for `everyCallable` on the three documentation rules, and false for every other option.
    pub(crate) fn boolean_option_default(rule_id: &str, option: &str) -> bool {
        option == "everyCallable"
            && matches!(
                rule_id,
                "docs.missing-public-doc" | "docs.missing-param-doc" | "docs.missing-return-doc"
            )
    }
}

/// Tell whether a built-in rule has a threshold, so `apply_rule_thresholds` can refuse a lone `severity` for it.
///
/// `rule_id` is the rule looked up in `registry`, the built-in rule catalogue.
/// Returns true when the rule's definition carries a threshold, and false for a rule without one or an id the registry does not hold.
fn rule_is_thresholded(rule_id: &str, registry: &rules::RuleRegistry) -> bool {
    registry
        .get(rule_id)
        .is_some_and(|definition| definition.threshold.is_some())
}

/// Validate a rule's `options` key when it is present and store the parsed option values.
///
/// `rule_id` names the rule, `rule_object` is its config object, `registry` declares each option's value kind, and parsed values go into `setting`.
/// Returns Ok when `options` is absent, otherwise the result of `validate_rule_options`.
pub(crate) fn validate_optional_rule_options(
    rule_id: &str,
    rule_object: &serde_json::Map<String, Value>,
    registry: &rules::RuleRegistry,
    setting: &mut RuleSetting,
) -> Result<(), String> {
    if let Some(options_value) = rule_object.get("options") {
        validate_rule_options(rule_id, options_value, registry, setting)?;
    }
    Ok(())
}

/// Apply a paired `threshold` and `severity` override to a rule that supports a threshold.
///
/// `rule_id` names the rule and `registry` must list it as accepting a threshold; `threshold_value` must be a number.
/// `severity_value` must name a severity such as warning, and both values are written into `setting` only when every check passes.
///
/// Returns Err when `ensure_rule_supports_threshold` refuses the rule, the threshold is not a number, or the severity name is not recognised.
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

/// Parse a standalone `severity` value and store it as the rule's severity override.
///
/// `rule_id` names the rule in the error message, `severity_value` is the configured value, and the parsed severity is written into `setting`.
/// Returns Err when the value is not a recognised severity name such as warning, leaving `setting` unchanged.
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

/// Check every entry of a rule's `options` object against the option kinds the registry declares and store the parsed values.
///
/// `rule_id` names the rule, `options_value` is the `options` value, `registry` declares each option's kind, and values go into `setting`.
/// Returns Err when `options_value` is not an object, or with the first error from `validate_rule_option_entry`; earlier entries stay in `setting`.
pub(crate) fn validate_rule_options(
    rule_id: &str,
    options_value: &Value,
    registry: &rules::RuleRegistry,
    setting: &mut RuleSetting,
) -> Result<(), String> {
    let options = options_value
        .as_object()
        .ok_or_else(|| format!("config key `rules.{rule_id}.options` must be an object"))?;
    for (name, value) in options {
        validate_rule_option_entry(rule_id, name, value, registry, setting)?;
    }
    Ok(())
}

/// Parse one rule option by the value kind the registry declares for it and store it in the matching options map.
///
/// `rule_id` and `name` identify the option looked up in `registry`, and `value` is its configured value.
/// A string-array option goes into the string-array options of `setting` and a boolean option into its boolean options.
/// Returns Err for an option the rule does not declare, a string array that `string_array` refuses, or a boolean option set to a non-boolean.
fn validate_rule_option_entry(
    rule_id: &str,
    name: &str,
    value: &Value,
    registry: &rules::RuleRegistry,
    setting: &mut RuleSetting,
) -> Result<(), String> {
    let kind = registry
        .option_value_kind(rule_id, name)
        .ok_or_else(|| format!("unknown option `{name}` for rule `{rule_id}`"))?;
    match kind {
        rules::OptionValueKind::StringArray => {
            let parsed = string_array(value, &format!("rules.{rule_id}.options.{name}"))?;
            setting
                .string_array_options
                .insert(name.to_string(), parsed);
        }
        rules::OptionValueKind::Boolean => {
            let enabled = value.as_bool().ok_or_else(|| {
                format!("config key `rules.{rule_id}.options.{name}` must be a boolean")
            })?;
            setting.boolean_options.insert(name.to_string(), enabled);
        }
    }
    Ok(())
}
