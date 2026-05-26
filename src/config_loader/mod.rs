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
    apply_custom_rule_settings, apply_selector_settings, insert_rule_setting, RuleSources,
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

type ConfigSectionHandler = fn(&Value, &mut Config) -> Result<(), String>;

/// Ordered list of section handlers. `schemaVersion` runs first so other
/// handlers can assume a versioned config. `custom_rules` must run before
/// `rules` so rule-id validation in `rules` can see the configured custom
/// rules; `exclude` runs last so its selectors can reference both
/// built-in and custom rules.
const CONFIG_SECTIONS: &[(&str, ConfigSectionHandler)] = &[
    ("schemaVersion", apply_schema_version_section),
    ("minimumSeverity", apply_minimum_severity_section),
    ("paths", apply_paths_section),
    ("allowlists", apply_allowlists_section),
    ("custom_rules", apply_custom_rules_section),
    ("rules", apply_rules_section),
    ("exclude", apply_exclusions_section),
];

pub(crate) fn apply_config_value(
    path: &Path,
    value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    let root = value
        .as_object()
        .ok_or_else(|| format!("config {} must be a JSON object", path.display()))?;
    let known_keys: Vec<&str> = CONFIG_SECTIONS.iter().map(|(key, _)| *key).collect();
    reject_unknown_keys(root, &known_keys, "config root")?;
    if !root.contains_key("schemaVersion") {
        return Err(format!(
            "config {} is missing the required `schemaVersion` field; this build expects `schemaVersion: {}`. Run `gruff-rs init --force` to regenerate.",
            path.display(),
            SCHEMA_VERSION
        ));
    }
    for (key, handler) in CONFIG_SECTIONS {
        if let Some(section_value) = root.get(*key) {
            handler(section_value, config)?;
        }
    }
    Ok(())
}

pub(crate) fn apply_schema_version_section(
    value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    let version = value.as_str().ok_or_else(|| {
        "config key `schemaVersion` must be a string (expected `gruff-rs.config.v1`)".to_string()
    })?;
    if version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported schemaVersion `{version}`; this build expects `{SCHEMA_VERSION}`. Run `gruff-rs init --force` to regenerate."
        ));
    }
    config.schema_version = version.to_string();
    Ok(())
}

pub(crate) fn apply_minimum_severity_section(
    value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    let mapping = value
        .as_object()
        .ok_or_else(|| "config key `minimumSeverity` must be an object".to_string())?;
    for (command, threshold_value) in mapping {
        let threshold = parse_minimum_severity_entry(command, threshold_value)?;
        config.minimum_severity.insert(command.clone(), threshold);
    }
    Ok(())
}

fn parse_minimum_severity_entry(
    command: &str,
    threshold_value: &Value,
) -> Result<FailThreshold, String> {
    const GATING_COMMANDS: &[&str] = &["analyse", "report"];
    if !GATING_COMMANDS.contains(&command) {
        return Err(format!(
            "unknown command `{command}` in `minimumSeverity`: gruff-rs's `{command}` does not gate exit code. Valid keys: analyse, report."
        ));
    }
    let threshold_str = threshold_value.as_str().ok_or_else(|| {
        format!(
            "config key `minimumSeverity.{command}` must be a string (one of advisory, warning, error, none)"
        )
    })?;
    threshold_str
        .parse()
        .map_err(|error| format!("config key `minimumSeverity.{command}`: {error}"))
}

pub(crate) fn apply_paths_section(paths_value: &Value, config: &mut Config) -> Result<(), String> {
    let paths = paths_value
        .as_object()
        .ok_or_else(|| "config key `paths` must be an object".to_string())?;
    reject_unknown_keys(paths, &["ignore"], "config key `paths`")?;
    if let Some(ignore) = paths.get("ignore") {
        config.ignored_paths = string_array(ignore, "paths.ignore")?;
        config.ignored_path_matchers = compile_path_matchers(&config.ignored_paths);
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
            RuleSources {
                registry: &registry,
                custom_rules: &config.custom_rules,
            },
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
        .map(|file_name| project_root.join(file_name))
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
