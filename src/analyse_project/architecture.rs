use super::*;

/// Runs the module fan-out, public API surface and large module rules over the indexed project.
///
/// `context` is the indexed project, with its module declarations and item summaries.
/// `config` decides which of the rules run and supplies their thresholds and severities.
/// `findings` receives one finding per file or module above a rule's threshold.
pub(crate) fn analyse_architecture_rules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_module_fan_out(context, config, findings);
    analyse_public_api_surface(context, config, findings);
    analyse_large_modules(context, config, findings);
}

/// Reports files that declare more child modules than the `architecture.module-fan-out` threshold allows.
///
/// Modules gated behind `cfg` are not counted, files named `main.rs` are skipped, and nothing runs when the rule is disabled.
///
/// `context` is the indexed project whose module declarations are grouped by declaring file.
/// `config` decides whether the rule is enabled and supplies its threshold and severity.
/// `findings` receives one finding per file above the threshold.
pub(crate) fn analyse_module_fan_out(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "architecture.module-fan-out";
    if !config.is_rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id) as usize;
    let by_file = group_modules_by_file(context);
    for (file_path, modules) in by_file {
        if is_binary_crate_root(file_path) {
            continue;
        }
        if modules.len() > threshold {
            findings.push(module_fan_out_finding(
                rule_id, file_path, &modules, threshold, config,
            ));
        }
    }
}

// Binary crate roots (`main.rs`) wire every top-level module together,
// so high fan-out is the norm there, not a smell. Library roots
// (`lib.rs`) keep the fan-out check on - their job is composition.
/// Tells whether a file is a `main.rs` binary crate root, which the module fan-out rule exempts.
///
/// `file_path` is the report path to check, with backslashes treated as forward slashes.
///
/// Returns `true` when the path is `main.rs` or ends in `/main.rs`, otherwise `false`.
fn is_binary_crate_root(file_path: &str) -> bool {
    let normalized = file_path.replace('\\', "/");
    normalized.ends_with("/main.rs") || normalized == "main.rs"
}

/// Groups the project's module declarations by the file that declares them, leaving out `cfg`-gated modules.
///
/// `context` is the indexed project whose module summaries are grouped.
///
/// Returns a map from declaring file path to its counted module declarations, ordered by path.
fn group_modules_by_file(context: &ProjectContext) -> BTreeMap<&str, Vec<&ModuleSummary>> {
    let mut by_file: BTreeMap<&str, Vec<&ModuleSummary>> = BTreeMap::new();
    for module in context.modules.iter().filter(|module| !module.cfg_gated) {
        by_file
            .entry(module.file_path.as_str())
            .or_default()
            .push(module);
    }
    by_file
}

/// Builds the module fan-out finding for one file that declares too many child modules.
///
/// `rule_id` is the fan-out rule id, used for the finding and its severity lookup.
/// `file_path` is the declaring file, used as the finding's path and symbol.
/// `modules` are the file's counted module declarations; the earliest line anchors the finding, or line 1 when empty.
///
/// `threshold` is the configured maximum, reported in the message and metadata.
/// `config` supplies the configured severity for `rule_id`, falling back to the built-in severity.
///
/// Returns a high-confidence Design finding whose message and metadata carry the module count and threshold.
fn module_fan_out_finding(
    rule_id: &str,
    file_path: &str,
    modules: &[&ModuleSummary],
    threshold: usize,
    config: &Config,
) -> Finding {
    let first_line = modules.iter().map(|module| module.line).min().unwrap_or(1);
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!(
            "File `{file_path}` declares {} child modules, above the threshold of {threshold}.",
            modules.len()
        ),
        file_path: file_path.to_string(),
        line: Some(first_line),
        severity: config.severity(rule_id, rules::builtin_severity(rule_id)),
        pillar: Pillar::Design,
        confidence: Confidence::High,
        symbol: Some(file_path.to_string()),
        remediation: Some(
            "Split module declarations across clearer parent modules when the fan-out grows."
                .to_string(),
        ),
        metadata: json!({
            "modules": modules.len(),
            "measured": modules.len(),
            "threshold": threshold,
            "unit": "modules",
            "direction": "above"
        }),
    })
}

/// Reports modules that expose more public items than the `architecture.public-api-surface` threshold allows.
///
/// Only items declared with unrestricted `pub` count; `cfg`-gated items, test-context items and methods are left out.
/// Nothing runs when the rule is disabled.
///
/// `context` is the indexed project whose items are grouped by file and module path.
/// `config` decides whether the rule is enabled and supplies its threshold and severity.
/// `findings` receives one finding per module above the threshold.
pub(crate) fn analyse_public_api_surface(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "architecture.public-api-surface";
    if !config.is_rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id) as usize;
    let by_module = group_public_items_by_module(context);
    for ((file_path, module_path), items) in by_module {
        if items.len() > threshold {
            findings.push(public_api_surface_finding(
                rule_id,
                ModuleItemGroup {
                    file_path,
                    module_path,
                    items: &items,
                },
                threshold,
                config,
            ));
        }
    }
}

/// Groups items declared with unrestricted `pub` by module, leaving out `cfg`-gated items, test-context items and methods.
///
/// `context` is the indexed project whose item summaries are grouped.
///
/// Returns a map from each file path and module path pair to that module's counted items, ordered by the pair.
fn group_public_items_by_module(
    context: &ProjectContext,
) -> BTreeMap<(String, String), Vec<&ItemSummary>> {
    let mut by_module: BTreeMap<(String, String), Vec<&ItemSummary>> = BTreeMap::new();
    for item in context.items.iter().filter(|item| {
        item.externally_public && !item.cfg_gated && !item.test_context && item.kind != "method"
    }) {
        by_module
            .entry((item.file_path.clone(), item.module_path.clone()))
            .or_default()
            .push(item);
    }
    by_module
}

pub(crate) struct ModuleItemGroup<'a> {
    pub(crate) file_path: String,
    pub(crate) module_path: String,
    pub(crate) items: &'a [&'a ItemSummary],
}

/// Builds the public API surface finding for one module that exposes too many public items.
///
/// `rule_id` is the public API surface rule id, used for the finding and its severity lookup.
/// `group` holds the module's file path, module path and counted items; the earliest item line anchors the finding, or line 1 when empty.
///
/// `threshold` is the configured maximum, reported in the message and metadata.
/// `config` supplies the configured severity for `rule_id`, falling back to the built-in severity.
///
/// Returns a high-confidence Design finding, labelled by `module_label`, whose message and metadata carry the item count and threshold.
fn public_api_surface_finding(
    rule_id: &str,
    group: ModuleItemGroup<'_>,
    threshold: usize,
    config: &Config,
) -> Finding {
    let first_line = group.items.iter().map(|item| item.line).min().unwrap_or(1);
    let module = module_label(&group.file_path, &group.module_path);
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!(
            "Module `{module}` exposes {} public items, above the threshold of {threshold}.",
            group.items.len()
        ),
        file_path: group.file_path,
        line: Some(first_line),
        severity: config.severity(rule_id, rules::builtin_severity(rule_id)),
        pillar: Pillar::Design,
        confidence: Confidence::High,
        symbol: Some(module.clone()),
        remediation: Some(
            "Group related public API items behind smaller modules or facade types.".to_string(),
        ),
        metadata: json!({
            "publicItems": group.items.len(),
            "module": module,
            "measured": group.items.len(),
            "threshold": threshold,
            "unit": "items",
            "direction": "above"
        }),
    })
}

/// Reports modules that contain more counted items than the `architecture.large-module` threshold allows.
///
/// Items count when marked `public` in the index, methods included, unless they are `cfg`-gated or in a test context.
/// Nothing runs when the rule is disabled.
///
/// `context` is the indexed project whose items are grouped by file and module path.
/// `config` decides whether the rule is enabled and supplies its threshold and severity.
/// `findings` receives one finding per module above the threshold.
pub(crate) fn analyse_large_modules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "architecture.large-module";
    if !config.is_rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id) as usize;
    let by_module = group_indexed_items_by_module(context);
    for ((file_path, module_path), items) in by_module {
        if items.len() > threshold {
            findings.push(large_module_finding(
                rule_id,
                ModuleItemGroup {
                    file_path,
                    module_path,
                    items: &items,
                },
                threshold,
                config,
            ));
        }
    }
}

/// Groups the project's items marked `public` by module, leaving out `cfg`-gated and test-context items.
///
/// `context` is the indexed project whose item summaries are grouped.
///
/// Returns a map from each file path and module path pair to that module's counted items, ordered by the pair.
fn group_indexed_items_by_module(
    context: &ProjectContext,
) -> BTreeMap<(String, String), Vec<&ItemSummary>> {
    let mut by_module: BTreeMap<(String, String), Vec<&ItemSummary>> = BTreeMap::new();
    for item in context
        .items
        .iter()
        .filter(|item| item.public && !item.cfg_gated && !item.test_context)
    {
        by_module
            .entry((item.file_path.clone(), item.module_path.clone()))
            .or_default()
            .push(item);
    }
    by_module
}

/// Builds the large module finding for one module that contains too many counted items.
///
/// `rule_id` is the large module rule id, used for the finding and its severity lookup.
/// `group` holds the module's file path, module path and counted items; the earliest item line anchors the finding, or line 1 when empty.
///
/// `threshold` is the configured maximum, reported in the message and metadata.
/// `config` supplies the configured severity for `rule_id`, falling back to the built-in severity.
///
/// Returns a high-confidence Design finding, labelled by `module_label`, whose message and metadata carry the item count and threshold.
fn large_module_finding(
    rule_id: &str,
    group: ModuleItemGroup<'_>,
    threshold: usize,
    config: &Config,
) -> Finding {
    let first_line = group.items.iter().map(|item| item.line).min().unwrap_or(1);
    let module = module_label(&group.file_path, &group.module_path);
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!(
            "Module `{module}` contains {} indexed items, above the threshold of {threshold}.",
            group.items.len()
        ),
        file_path: group.file_path,
        line: Some(first_line),
        severity: config.severity(rule_id, rules::builtin_severity(rule_id)),
        pillar: Pillar::Design,
        confidence: Confidence::High,
        symbol: Some(module.clone()),
        remediation: Some(
            "Split unrelated responsibilities into smaller modules with narrower APIs.".to_string(),
        ),
        metadata: json!({
            "items": group.items.len(),
            "module": module,
            "measured": group.items.len(),
            "threshold": threshold,
            "unit": "items",
            "direction": "above"
        }),
    })
}
