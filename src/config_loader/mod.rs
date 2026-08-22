//! Load strict user configuration for analysis and non-analysis commands.
//!
//! The loader validates each public section before it can affect findings,
//! report output, or exit status. Missing config falls back to safe defaults.

use super::*;

mod custom_rules;
mod exclusions;
mod rule_settings;
mod selectors;
mod sensitive_exclusions;

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
pub(crate) use sensitive_exclusions::{apply_sensitive_exclusions_section, SensitiveExclusionRule};

pub(crate) const LEGACY_SECRET_PREVIEWS_ERROR: &str =
    "Config key \"allowlists.secretPreviews\" only accepts an empty list; remove all configured entries because secret previews no longer suppress findings.";

/// Load the resolved config used by one analysis command.
/// An absent config path falls back to project discovery, while `--no-config` keeps safe defaults.
pub(crate) fn load_config(
    project_root: &Path,
    options: &AnalysisOptions,
) -> Result<Config, String> {
    load_config_for(project_root, options.config.as_deref(), options.no_config)
}

/// Load config from an explicit path or project default for both analysing and support commands.
/// This keeps `check-ignore` explanations consistent with the settings users see in `analyse`.
pub(crate) fn load_config_for(
    project_root: &Path,
    config_path: Option<&Path>,
    no_config: bool,
) -> Result<Config, String> {
    let mut config = Config::default();
    // `--no-config` means the user explicitly requested registered defaults and no project file lookup.
    if no_config {
        return Ok(config);
    }

    // No explicit or discovered file means the command can proceed with the same safe defaults.
    let Some((path, value)) = read_config_value(project_root, config_path)? else {
        return Ok(config);
    };
    apply_config_value(&path, &value, &mut config)?;
    Ok(config)
}

/// Read and parse the explicit config file or the first supported project default.
/// `None` means no config file exists; read errors explain practical issues such as a deleted or unreadable selected file.
pub(crate) fn read_config_value(
    project_root: &Path,
    config: Option<&Path>,
) -> Result<Option<(PathBuf, Value)>, String> {
    let config_path = config
        .map(|path| absolutize(project_root, path))
        .or_else(|| default_config_path(project_root));
    // When the user has no config file, callers retain defaults rather than treating setup as an error.
    let Some(path) = config_path else {
        return Ok(None);
    };

    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("unable to read config {}: {error}", path.display()))?;
    let value = parse_config_value(&path, &raw)?;
    Ok(Some((path, value)))
}

type ConfigSectionHandler = fn(&Value, &mut Config) -> Result<(), String>;

/// Apply config sections in dependency order: schema first, custom rules before their settings, and exclusions after all rule IDs exist.
/// This order keeps every user-facing validation error deterministic.
const CONFIG_SECTIONS: &[(&str, ConfigSectionHandler)] = &[
    ("schemaVersion", apply_schema_version_section),
    ("minimumSeverity", apply_minimum_severity_section),
    ("deepScanBudget", apply_deep_scan_budget_section),
    ("paths", apply_paths_section),
    ("allowlists", apply_allowlists_section),
    ("custom_rules", apply_custom_rules_section),
    ("rules", apply_rules_section),
    ("exclude", apply_exclusions_section),
    ("sensitiveExclusions", apply_sensitive_exclusions_section),
    ("gate", apply_gate_section),
];

/// Apply the paired deep-analysis limits after validating their public shape.
/// Missing members retain the defaults while the diagnostic still records that
/// the effective budget came from configuration.
pub(crate) fn apply_deep_scan_budget_section(
    value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    let mapping = value
        .as_object()
        .ok_or_else(|| "config key `deepScanBudget` must be an object".to_string())?;
    reject_unknown_keys(
        mapping,
        &["enabled", "maxLines", "maxBytes"],
        "deepScanBudget",
    )?;
    let enabled = match mapping.get("enabled") {
        Some(value) => value.as_bool().ok_or_else(|| {
            "config key `deepScanBudget.enabled` must be true or false".to_string()
        })?,
        None => config.deep_scan_budget.enabled,
    };
    let max_lines = parse_positive_budget_limit(
        mapping.get("maxLines"),
        "deepScanBudget.maxLines",
        config.deep_scan_budget.max_lines,
    )?;
    let max_bytes = parse_positive_budget_limit(
        mapping.get("maxBytes"),
        "deepScanBudget.maxBytes",
        config.deep_scan_budget.max_bytes,
    )?;
    config.deep_scan_budget = DeepScanBudget {
        enabled,
        max_lines,
        max_bytes,
        override_state: "config",
    };
    Ok(())
}

fn parse_positive_budget_limit(
    value: Option<&Value>,
    path: &str,
    default: usize,
) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    let limit = value
        .as_u64()
        .and_then(|limit| usize::try_from(limit).ok())
        .filter(|limit| *limit > 0)
        .ok_or_else(|| format!("config key `{path}` must be a positive integer"))?;
    Ok(limit)
}

/// Validate a parsed config root and apply each present section to the command settings.
/// Missing required schema or unknown keys stop the user's command before analysis begins.
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
    // Without a schema version, the analyser cannot safely interpret what the user intended.
    if !root.contains_key("schemaVersion") {
        return Err(format!(
            "config {} is missing the required `schemaVersion` field; this build expects `schemaVersion: {}`. Run `gruff-rs init --force` to regenerate.",
            path.display(),
            SCHEMA_VERSION
        ));
    }
    // Every supplied section is validated and applied in the stable dependency order above.
    for (key, handler) in CONFIG_SECTIONS {
        // An absent optional section leaves its current default or previously established value unchanged.
        if let Some(section_value) = root.get(*key) {
            handler(section_value, config)?;
        }
    }
    Ok(())
}

/// Validate the required config schema before any user setting can affect analysis.
pub(crate) fn apply_schema_version_section(
    value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    let version = value.as_str().ok_or_else(|| {
        "config key `schemaVersion` must be a string (expected `gruff-rs.config.v1`)".to_string()
    })?;
    // A different version may have incompatible UI meaning, so the user must regenerate before continuing.
    if version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported schemaVersion `{version}`; this build expects `{SCHEMA_VERSION}`. Run `gruff-rs init --force` to regenerate."
        ));
    }
    config.schema_version = version.to_string();
    Ok(())
}

/// Apply the optional finding-count gate that determines the user's command outcome.
/// A null gate leaves gating disabled; an empty object uses unlimited caps and the registered behavior.
pub(crate) fn apply_gate_section(value: &Value, config: &mut Config) -> Result<(), String> {
    // A YAML null means the user has not enabled a finding-count gate.
    if !value.is_null() {
        config.gate = Some(parse_gate(value)?);
    }
    Ok(())
}

/// Parse one gate object into total, severity, outcome, and changed-scope limits.
/// Missing members retain the defaults users see when the gate section is empty.
fn parse_gate(value: &Value) -> Result<Gate, String> {
    let mapping = value
        .as_object()
        .ok_or_else(|| "config key `gate` must be an object".to_string())?;
    reject_unknown_keys(mapping, &["total", "severity", "onMatch", "scope"], "gate")?;
    let mut gate = Gate {
        total: parse_gate_count(mapping, "total", "gate.total")?,
        ..Gate::default()
    };
    // Missing severity caps leave each severity unlimited for the user.
    if let Some(severity) = mapping.get("severity") {
        apply_gate_severity(severity, &mut gate)?;
    }
    // Missing `onMatch` retains the default command outcome when a cap is exceeded.
    if let Some(on_match) = mapping.get("onMatch") {
        gate.on_match = parse_gate_on_match(on_match)?;
    }
    // Missing scope keeps the historical current-report behavior rather than new-only comparison.
    if let Some(scope) = mapping.get("scope") {
        gate.scope = parse_gate_scope(scope)?;
    }
    Ok(gate)
}

/// Apply optional per-severity finding caps within the user's gate.
/// Missing caps remain unlimited and do not change the command outcome.
fn apply_gate_severity(value: &Value, gate: &mut Gate) -> Result<(), String> {
    let mapping = value
        .as_object()
        .ok_or_else(|| "config key `gate.severity` must be an object".to_string())?;
    reject_unknown_keys(mapping, &["error", "warning", "advisory"], "gate.severity")?;
    gate.error = parse_gate_count(mapping, "error", "gate.severity.error")?;
    gate.warning = parse_gate_count(mapping, "warning", "gate.severity.warning")?;
    gate.advisory = parse_gate_count(mapping, "advisory", "gate.severity.advisory")?;
    Ok(())
}

/// Parse one non-negative gate cap using its full config path for user errors.
/// `None` means the user left that count unlimited.
fn parse_gate_count(
    mapping: &serde_json::Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<u64>, String> {
    mapping
        .get(key)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("config key `{path}` must be a non-negative integer"))
        })
        .transpose()
}

/// Parse whether a matched gate fails the command or only warns the user.
fn parse_gate_on_match(value: &Value) -> Result<GateOnMatch, String> {
    match value.as_str() {
        Some("fail") => Ok(GateOnMatch::Fail),
        Some("warn") => Ok(GateOnMatch::Warn),
        _ => Err("config key `gate.onMatch` must be `fail` or `warn`".to_string()),
    }
}

/// Parse whether the gate counts new findings or every finding in the user's report.
/// An absent key is handled earlier and preserves the historical current-report scope.
fn parse_gate_scope(value: &Value) -> Result<GateScope, String> {
    match value.as_str() {
        Some("new") => Ok(GateScope::New),
        Some("all") => Ok(GateScope::All),
        _ => Err("config key `gate.scope` must be `new` or `all`".to_string()),
    }
}

/// Apply per-command severity thresholds that control whether findings produce a failing exit code.
/// A null section means the user wants no config override for any command.
pub(crate) fn apply_minimum_severity_section(
    value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    // YAML null leaves every command on its CLI or built-in severity behavior.
    if value.is_null() {
        return Ok(());
    }
    let mapping = value
        .as_object()
        .ok_or_else(|| "config key `minimumSeverity` must be an object".to_string())?;
    // Each supported command receives its independently configured user threshold.
    for (command, threshold_value) in mapping {
        let threshold = parse_minimum_severity_entry(command, threshold_value)?;
        config.minimum_severity.insert(command.clone(), threshold);
    }
    Ok(())
}

/// Parse one supported command threshold from user config.
/// Unknown commands fail because they cannot change an exit code and would otherwise mislead the user.
fn parse_minimum_severity_entry(
    command: &str,
    threshold_value: &Value,
) -> Result<FailThreshold, String> {
    const GATING_COMMANDS: &[&str] = &["analyse", "report"];
    // Commands without a severity gate cannot honor this setting in the UI or exit status.
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

/// Apply user path ignores and compile them for discovery and `check-ignore` explanations.
/// A missing ignore list leaves project discovery on its registered defaults.
pub(crate) fn apply_paths_section(paths_value: &Value, config: &mut Config) -> Result<(), String> {
    let paths = paths_value
        .as_object()
        .ok_or_else(|| "config key `paths` must be an object".to_string())?;
    reject_unknown_keys(paths, &["ignore"], "config key `paths`")?;
    // Only a supplied list changes which discovered paths the user sees in analysis.
    if let Some(ignore) = paths.get("ignore") {
        config.ignored_paths = string_array(ignore, "paths.ignore")?;
        config.ignored_path_matchers = compile_path_matchers(&config.ignored_paths);
    }
    Ok(())
}

/// Apply active naming allowlists and validate the retained empty preview key.
/// Invalid shapes stop the user's command before any setting can hide a finding.
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
    // A supplied abbreviation list replaces the defaults shown to naming rules.
    if let Some(abbreviations) = allowlists.get("acceptedAbbreviations") {
        config.accepted_abbreviations =
            string_array(abbreviations, "allowlists.acceptedAbbreviations")?
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect();
    }
    // Users may retain the retired key as [], but any other value stops the command before analysis.
    if let Some(legacy_secret_previews_value) = allowlists.get("secretPreviews") {
        validate_legacy_secret_previews(legacy_secret_previews_value)?;
    }
    Ok(())
}

/// Accept only the empty legacy preview list retained in generated user config.
/// Every non-empty or differently shaped value returns one value-independent diagnostic.
fn validate_legacy_secret_previews(legacy_secret_previews_value: &Value) -> Result<(), String> {
    // Only an exact empty array means the retired setting has no effect on the user's findings.
    match legacy_secret_previews_value.as_array() {
        Some(configured_preview_entries) if configured_preview_entries.is_empty() => Ok(()),
        _ => Err(LEGACY_SECRET_PREVIEWS_ERROR.to_string()),
    }
}

/// Apply selectors, custom settings, and per-rule overrides from the user's `rules` object.
/// Missing entries retain registry defaults, while unknown or malformed entries fail before analysis.
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
    // Remaining keys are individual rule settings after the three reserved selector groups.
    for (key, rule_value) in rules {
        // Reserved groups were applied above and are not individual rule IDs.
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

/// Parse, deduplicate, and order the custom rules users added to project config.
/// An empty list means no project-defined rules are added to the built-in catalogue.
pub(crate) fn apply_custom_rules_section(
    custom_rules_value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    let registry = rules::builtin_registry();
    let entries = custom_rules_value
        .as_array()
        .ok_or_else(|| "config key `custom_rules` must be an array".to_string())?;
    // The resolved custom catalogue starts empty and receives only validated user entries.
    let mut custom_rules = Vec::new();
    let mut seen = BTreeSet::new();
    // Each configured rule is validated with its list position for actionable user errors.
    for (index, entry_value) in entries.iter().enumerate() {
        let custom_rule = parse_custom_rule(index, entry_value, &registry)?;
        // Duplicate IDs would make rule settings and report entries ambiguous for the user.
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

/// Find the first supported default config file in the user's project root.
/// `None` means the project has not created Gruff config yet.
pub(crate) fn default_config_path(project_root: &Path) -> Option<PathBuf> {
    DEFAULT_CONFIG_FILES
        .iter()
        .map(|file_name| project_root.join(file_name))
        .find(|path| path.exists())
}

/// Parse YAML config selected by the user and reject the retired JSON format with a migration hint.
/// Syntax errors can occur after a user edits indentation, quotes, or list structure in the config UI or editor.
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

/// Confirm a rule exposes a numeric threshold before accepting the user's override.
/// Rules without that option fail closed so config never promises an unsupported UI control.
pub(crate) fn ensure_rule_supports_threshold(
    registry: &rules::RuleRegistry,
    rule_id: &str,
) -> Result<(), String> {
    let definition = registry
        .get(rule_id)
        .ok_or_else(|| format!("unknown rule id `{rule_id}` in config"))?;
    // Only catalogue rules with one numeric threshold can honor this user setting.
    if definition.threshold.is_some() {
        Ok(())
    } else {
        Err(format!(
            "config key `rules.{rule_id}.threshold` is only supported for rules with one numeric threshold"
        ))
    }
}

/// Reject config fields this build cannot interpret in the named user-facing section.
/// An empty object is valid when the section itself permits it.
pub(crate) fn reject_unknown_keys(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    // Every supplied key must map to a documented setting before the command may continue.
    for key in object.keys() {
        // An unknown key likely reflects a typo or newer schema and must not be silently ignored.
        if !allowed.iter().any(|allowed_key| allowed_key == key) {
            return Err(format!("unknown key `{key}` in {context}"));
        }
    }
    Ok(())
}

/// Parse a user config list whose entries must all be strings.
/// An empty array is valid and means the user configured no values for that setting.
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
