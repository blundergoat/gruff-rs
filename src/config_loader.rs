use super::*;

pub(crate) fn load_config(project_root: &Path, options: &AnalysisOptions) -> Result<Config, String> {
    let mut config = Config::default();
    if options.no_config {
        return Ok(config);
    }

    let Some((path, value)) = read_config_value(project_root, options)? else {
        return Ok(config);
    };
    apply_config_value(&path, &value, &mut config)?;
    Ok(config)
}

pub(crate) fn read_config_value(
    project_root: &Path,
    options: &AnalysisOptions,
) -> Result<Option<(PathBuf, Value)>, String> {
    let config_path = options
        .config
        .as_ref()
        .map(|path| absolutize(project_root, path))
        .or_else(|| default_config_path(project_root));
    let Some(path) = config_path else {
        return Ok(None);
    };

    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("unable to read config {}: {error}", path.display()))?;
    let value = parse_config_value(&path, &raw)?;
    Ok(Some((path, value)))
}

pub(crate) fn apply_config_value(path: &Path, value: &Value, config: &mut Config) -> Result<(), String> {
    let root = value
        .as_object()
        .ok_or_else(|| format!("config {} must be a JSON object", path.display()))?;
    reject_unknown_keys(
        root,
        &["paths", "allowlists", "rules", "exclude", "custom_rules"],
        "config root",
    )?;

    if let Some(paths_value) = root.get("paths") {
        apply_paths_section(paths_value, config)?;
    }
    if let Some(allowlists_value) = root.get("allowlists") {
        apply_allowlists_section(allowlists_value, config)?;
    }
    if let Some(custom_rules_value) = root.get("custom_rules") {
        apply_custom_rules_section(custom_rules_value, config)?;
    }
    if let Some(rules_value) = root.get("rules") {
        apply_rules_section(rules_value, config)?;
    }
    if let Some(exclude_value) = root.get("exclude") {
        apply_exclusions_section(exclude_value, config)?;
    }
    Ok(())
}

pub(crate) fn apply_paths_section(paths_value: &Value, config: &mut Config) -> Result<(), String> {
    let paths = paths_value
        .as_object()
        .ok_or_else(|| "config key `paths` must be an object".to_string())?;
    reject_unknown_keys(paths, &["ignore"], "config key `paths`")?;
    if let Some(ignore) = paths.get("ignore") {
        config.ignored_paths = string_array(ignore, "paths.ignore")?;
    }
    Ok(())
}

pub(crate) fn apply_allowlists_section(allowlists_value: &Value, config: &mut Config) -> Result<(), String> {
    let allowlists = allowlists_value
        .as_object()
        .ok_or_else(|| "config key `allowlists` must be an object".to_string())?;
    reject_unknown_keys(
        allowlists,
        &["acceptedAbbreviations", "secretPreviews"],
        "config key `allowlists`",
    )?;
    if let Some(abbreviations) = allowlists.get("acceptedAbbreviations") {
        config.accepted_abbreviations =
            string_array(abbreviations, "allowlists.acceptedAbbreviations")?
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect();
    }
    if let Some(previews) = allowlists.get("secretPreviews") {
        config.secret_previews = string_array(previews, "allowlists.secretPreviews")?
            .into_iter()
            .collect();
    }
    Ok(())
}

pub(crate) fn apply_rules_section(rules_value: &Value, config: &mut Config) -> Result<(), String> {
    let registry = rules::builtin_registry();
    let rules = rules_value
        .as_object()
        .ok_or_else(|| "config key `rules` must be an object".to_string())?;

    apply_selector_settings(
        rules,
        &registry,
        &config.custom_rules,
        &mut config.selectors,
    )?;
    apply_custom_rule_settings(
        rules,
        &registry,
        &config.custom_rules,
        &mut config.rule_settings,
    )?;
    for (key, rule_value) in rules {
        if matches!(key.as_str(), "select" | "ignore" | "custom") {
            continue;
        }
        insert_rule_setting(
            key,
            rule_value,
            &registry,
            &config.custom_rules,
            &mut config.rule_settings,
            "rules",
        )?;
    }
    Ok(())
}

pub(crate) fn apply_custom_rules_section(
    custom_rules_value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    let registry = rules::builtin_registry();
    let entries = custom_rules_value
        .as_array()
        .ok_or_else(|| "config key `custom_rules` must be an array".to_string())?;
    let mut custom_rules = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, entry_value) in entries.iter().enumerate() {
        let custom_rule = parse_custom_rule(index, entry_value, &registry)?;
        if !seen.insert(custom_rule.id.clone()) {
            return Err(format!(
                "duplicate custom rule id `{}` in config key `custom_rules[{index}].id`",
                custom_rule.id
            ));
        }
        custom_rules.push(custom_rule);
    }
    custom_rules.sort_by(|left, right| left.id.cmp(&right.id));
    config.custom_rules = custom_rules;
    Ok(())
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
        &[
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
        ],
        &format!("config key `{entry_path}`"),
    )?;

    let id = required_config_string(entry, "id", &format!("{entry_path}.id"))?;
    validate_custom_rule_id(&id, &format!("{entry_path}.id"), registry)?;
    let pillar = parse_required_pillar(entry, "pillar", &format!("{entry_path}.pillar"))?;
    let severity = parse_required_severity(entry, "severity", &format!("{entry_path}.severity"))?;
    let confidence = entry
        .get("confidence")
        .map(|value| parse_custom_confidence(value, &format!("{entry_path}.confidence")))
        .transpose()?
        .unwrap_or(Confidence::Medium);
    let message = required_non_empty_config_string(entry, "message", &entry_path)?;
    let scope = parse_custom_rule_scope(
        &required_config_string(entry, "scope", &format!("{entry_path}.scope"))?,
        &format!("{entry_path}.scope"),
    )?;
    let pattern = required_non_empty_config_string(entry, "pattern", &entry_path)?;
    let compiled_pattern = Regex::new(&pattern).map_err(|error| {
        format!("config key `{entry_path}.pattern` failed to compile regex: {error}")
    })?;
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

    Ok(CustomRule {
        id,
        pillar,
        severity,
        confidence,
        message,
        scope,
        pattern,
        compiled_pattern,
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

pub(crate) fn apply_exclusions_section(exclude_value: &Value, config: &mut Config) -> Result<(), String> {
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

    let selector = required_config_string(entry, "rule", &format!("{entry_path}.rule"))?;
    let rule_ids = expand_rule_selector_with_custom(
        &selector,
        registry,
        custom_rules,
        &format!("{entry_path}.rule"),
    )?;
    let paths = entry
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
    let message_contains = entry
        .get("message_contains")
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                format!("config key `{entry_path}.message_contains` must be a string")
            })
        })
        .transpose()?;
    let reason = required_config_string(entry, "reason", &format!("{entry_path}.reason"))?;
    if reason.trim().is_empty() {
        return Err(format!(
            "config key `{entry_path}.reason` must be a non-empty string"
        ));
    }
    if message_contains
        .as_deref()
        .is_some_and(|message| message.is_empty())
    {
        return Err(format!(
            "config key `{entry_path}.message_contains` must be a non-empty string"
        ));
    }

    Ok(ExclusionRule {
        selector,
        rule_ids,
        paths,
        message_contains,
        reason,
    })
}

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

pub(crate) fn exact_rule_selector(selector: &str, entries: &[RuleSelectorEntry]) -> Option<BTreeSet<String>> {
    if entries.iter().any(|entry| entry.id == selector) {
        return Some(BTreeSet::from([selector.to_string()]));
    }
    None
}

pub(crate) fn pillar_rule_selector(selector: &str, entries: &[RuleSelectorEntry]) -> Option<BTreeSet<String>> {
    let pillar = parse_pillar_selector(selector)?;
    Some(
        entries
            .iter()
            .filter(|entry| entry.pillar == pillar)
            .map(|entry| entry.id.clone())
            .collect(),
    )
}

pub(crate) fn prefix_rule_selector(selector: &str, entries: &[RuleSelectorEntry]) -> Option<BTreeSet<String>> {
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

pub(crate) fn default_config_path(project_root: &Path) -> Option<PathBuf> {
    DEFAULT_CONFIG_FILES
        .iter()
        .map(|name| project_root.join(name))
        .find(|path| path.exists())
}

pub(crate) fn parse_config_value(path: &Path, raw: &str) -> Result<Value, String> {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "yaml" | "yml" => serde_yaml::from_str(raw)
            .map_err(|error| format!("invalid config YAML {}: {error}", path.display())),
        "json" => Err(format!(
            "unsupported config extension `json`; use .gruff-rs.yaml or another YAML config path instead: {}",
            path.display()
        )),
        _ => serde_yaml::from_str(raw)
            .map_err(|error| format!("invalid config YAML {}: {error}", path.display())),
    }
}

pub(crate) fn ensure_rule_supports_threshold(
    registry: &rules::RuleRegistry,
    rule_id: &str,
) -> Result<(), String> {
    let definition = registry
        .get(rule_id)
        .ok_or_else(|| format!("unknown rule id `{rule_id}` in config"))?;
    if definition.threshold.is_some() {
        Ok(())
    } else {
        Err(format!(
            "config key `rules.{rule_id}.threshold` is only supported for rules with one numeric threshold"
        ))
    }
}

pub(crate) fn reject_unknown_keys(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    for key in object.keys() {
        if !allowed.iter().any(|allowed_key| allowed_key == key) {
            return Err(format!("unknown key `{key}` in {context}"));
        }
    }
    Ok(())
}

pub(crate) fn string_array(value: &Value, path: &str) -> Result<Vec<String>, String> {
    let array = value
        .as_array()
        .ok_or_else(|| format!("config key `{path}` must be an array"))?;
    array
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_str()
                .map(String::from)
                .ok_or_else(|| format!("config key `{path}[{index}]` must be a string"))
        })
        .collect()
}
