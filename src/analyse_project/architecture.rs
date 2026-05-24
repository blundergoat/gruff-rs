use super::*;

pub(crate) fn analyse_architecture_rules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_module_fan_out(context, config, findings);
    analyse_public_api_surface(context, config, findings);
    analyse_large_modules(context, config, findings);
}

pub(crate) fn analyse_module_fan_out(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "architecture.module-fan-out";
    if !config.is_rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id, 8.0) as usize;
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
fn is_binary_crate_root(file_path: &str) -> bool {
    let normalized = file_path.replace('\\', "/");
    normalized.ends_with("/main.rs") || normalized == "main.rs"
}

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
        severity: config.severity(rule_id, Severity::Advisory),
        pillar: Pillar::Design,
        confidence: Confidence::High,
        symbol: Some(file_path.to_string()),
        remediation: Some(
            "Split module declarations across clearer parent modules when the fan-out grows."
                .to_string(),
        ),
        metadata: json!({ "modules": modules.len(), "threshold": threshold }),
    })
}

pub(crate) fn analyse_public_api_surface(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "architecture.public-api-surface";
    if !config.is_rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id, 12.0) as usize;
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
        severity: config.severity(rule_id, Severity::Advisory),
        pillar: Pillar::Design,
        confidence: Confidence::High,
        symbol: Some(module.clone()),
        remediation: Some(
            "Group related public API items behind smaller modules or facade types.".to_string(),
        ),
        metadata: json!({ "publicItems": group.items.len(), "threshold": threshold, "module": module }),
    })
}

pub(crate) fn analyse_large_modules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "architecture.large-module";
    if !config.is_rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id, 25.0) as usize;
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

fn group_indexed_items_by_module(
    context: &ProjectContext,
) -> BTreeMap<(String, String), Vec<&ItemSummary>> {
    let mut by_module: BTreeMap<(String, String), Vec<&ItemSummary>> = BTreeMap::new();
    for item in context
        .items
        .iter()
        .filter(|item| !item.cfg_gated && !item.test_context)
    {
        by_module
            .entry((item.file_path.clone(), item.module_path.clone()))
            .or_default()
            .push(item);
    }
    by_module
}

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
        severity: config.severity(rule_id, Severity::Advisory),
        pillar: Pillar::Design,
        confidence: Confidence::High,
        symbol: Some(module.clone()),
        remediation: Some(
            "Split unrelated responsibilities into smaller modules with narrower APIs.".to_string(),
        ),
        metadata: json!({ "items": group.items.len(), "threshold": threshold, "module": module }),
    })
}
