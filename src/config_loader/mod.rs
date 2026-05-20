use super::*;

mod custom_rules;
mod exclusions;
mod rule_settings;
mod selectors;

pub(crate) use custom_rules::{parse_custom_rule, parse_severity_name};
pub(crate) use exclusions::{
    apply_exclusions_section, required_config_string, required_non_empty_config_string,
};
pub(crate) use rule_settings::{
    apply_custom_rule_settings, apply_selector_settings, insert_rule_setting,
};
#[cfg(test)]
pub(crate) use selectors::expand_rule_selector;
pub(crate) use selectors::{
    expand_rule_selector_with_custom, expand_rule_selectors, parse_pillar_selector,
};

pub(crate) fn load_config(
    project_root: &Path,
    options: &AnalysisOptions,
) -> Result<Config, String> {
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

pub(crate) fn apply_config_value(
    path: &Path,
    value: &Value,
    config: &mut Config,
) -> Result<(), String> {
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

pub(crate) fn apply_allowlists_section(
    allowlists_value: &Value,
    config: &mut Config,
) -> Result<(), String> {
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
