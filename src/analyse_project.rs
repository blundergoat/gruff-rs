use super::*;

pub(crate) fn analyse_project(context: &ProjectContext, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !context.root_path.join("README.md").exists() && config.rule_enabled("docs.missing-readme") {
        findings.push(Finding::new(
            "docs.missing-readme",
            "Project root does not contain a README.md file.",
            "README.md",
            Some(1),
            Severity::Advisory,
            Pillar::Documentation,
            Confidence::High,
            None,
            Some(
                "Add a README.md that explains the project purpose and local commands.".to_string(),
            ),
            json!({}),
        ));
    }

    analyse_dependency_rules(context, config, &mut findings);
    analyse_architecture_rules(context, config, &mut findings);
    analyse_project_dead_code_rules(context, config, &mut findings);

    findings
}

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
    if !config.rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id, 8.0) as usize;
    let mut by_file: BTreeMap<&str, Vec<&ModuleSummary>> = BTreeMap::new();
    for module in context.modules.iter().filter(|module| !module.cfg_gated) {
        by_file
            .entry(module.file_path.as_str())
            .or_default()
            .push(module);
    }

    for (file_path, modules) in by_file {
        if modules.len() <= threshold {
            continue;
        }
        let first_line = modules.iter().map(|module| module.line).min().unwrap_or(1);
        findings.push(Finding::new(
            rule_id,
            format!(
                "File `{file_path}` declares {} child modules, above the threshold of {threshold}.",
                modules.len()
            ),
            file_path.to_string(),
            Some(first_line),
            config.severity(rule_id, Severity::Advisory),
            Pillar::Design,
            Confidence::High,
            Some(file_path.to_string()),
            Some(
                "Split module declarations across clearer parent modules when the fan-out grows."
                    .to_string(),
            ),
            json!({ "modules": modules.len(), "threshold": threshold }),
        ));
    }
}

pub(crate) fn analyse_public_api_surface(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "architecture.public-api-surface";
    if !config.rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id, 12.0) as usize;
    let mut by_module: BTreeMap<(String, String), Vec<&ItemSummary>> = BTreeMap::new();
    for item in context.items.iter().filter(|item| {
        item.externally_public && !item.cfg_gated && !item.test_context && item.kind != "method"
    }) {
        by_module
            .entry((item.file_path.clone(), item.module_path.clone()))
            .or_default()
            .push(item);
    }

    for ((file_path, module_path), items) in by_module {
        if items.len() <= threshold {
            continue;
        }
        let first_line = items.iter().map(|item| item.line).min().unwrap_or(1);
        let module = module_label(&file_path, &module_path);
        findings.push(Finding::new(
            rule_id,
            format!(
                "Module `{module}` exposes {} public items, above the threshold of {threshold}.",
                items.len()
            ),
            file_path,
            Some(first_line),
            config.severity(rule_id, Severity::Advisory),
            Pillar::Design,
            Confidence::High,
            Some(module.clone()),
            Some(
                "Group related public API items behind smaller modules or facade types."
                    .to_string(),
            ),
            json!({ "publicItems": items.len(), "threshold": threshold, "module": module }),
        ));
    }
}

pub(crate) fn analyse_large_modules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "architecture.large-module";
    if !config.rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id, 25.0) as usize;
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

    for ((file_path, module_path), items) in by_module {
        if items.len() <= threshold {
            continue;
        }
        let first_line = items.iter().map(|item| item.line).min().unwrap_or(1);
        let module = module_label(&file_path, &module_path);
        findings.push(Finding::new(
            rule_id,
            format!(
                "Module `{module}` contains {} indexed items, above the threshold of {threshold}.",
                items.len()
            ),
            file_path,
            Some(first_line),
            config.severity(rule_id, Severity::Advisory),
            Pillar::Design,
            Confidence::High,
            Some(module.clone()),
            Some(
                "Split unrelated responsibilities into smaller modules with narrower APIs."
                    .to_string(),
            ),
            json!({ "items": items.len(), "threshold": threshold, "module": module }),
        ));
    }
}

pub(crate) fn module_label(file_path: &str, module_path: &str) -> String {
    if module_path.is_empty() {
        file_path.to_string()
    } else {
        module_path.to_string()
    }
}

pub(crate) fn analyse_project_dead_code_rules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "dead-code.unused-private-item-candidate";
    if !config.rule_enabled(rule_id) {
        return;
    }

    for item in context.items.iter().filter(|item| {
        !item.public
            && !item.cfg_gated
            && !item.test_context
            && matches!(item.kind.as_str(), "function" | "struct" | "enum" | "trait")
            && item.name != "main"
    }) {
        if rust_identifier_occurrences(context, &item.name) > 1 {
            continue;
        }
        let symbol = item_symbol(item);
        findings.push(Finding::new(
            rule_id,
            format!(
                "Private {} `{}` is an unused candidate; no other discovered Rust source references its name.",
                item.kind, item.name
            ),
            item.file_path.clone(),
            Some(item.line),
            Severity::Advisory,
            Pillar::DeadCode,
            Confidence::Medium,
            Some(symbol.clone()),
            Some(
                "Remove the item, make the reference explicit, or keep it documented if it is used through macros or cfg-specific builds."
                    .to_string(),
            ),
            json!({ "kind": item.kind.as_str(), "module": item.module_path.as_str(), "candidate": true }),
        ));
    }
}

pub(crate) fn item_symbol(item: &ItemSummary) -> String {
    if item.module_path.is_empty() {
        item.name.clone()
    } else {
        format!("{}::{}", item.module_path, item.name)
    }
}

pub(crate) fn rust_identifier_occurrences(context: &ProjectContext, name: &str) -> usize {
    context
        .rust_sources
        .iter()
        .map(|source| identifier_occurrences(&source.source, name))
        .sum()
}

pub(crate) fn identifier_occurrences(source: &str, name: &str) -> usize {
    let pattern = format!(r"\b{}\b", regex::escape(name));
    Regex::new(&pattern)
        .expect("escaped identifier regex compiles")
        .find_iter(source)
        .count()
}

pub(crate) fn analyse_dependency_rules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if let Some(manifest) = &context.manifest {
        analyse_manifest_metadata(manifest, config, findings);
        for dependency in &manifest.dependencies {
            analyse_manifest_dependency(manifest, dependency, config, findings);
        }
    }

    if let Some(lockfile) = &context.lockfile {
        analyse_lockfile_duplicates(lockfile, config, findings);
    }
}

pub(crate) fn analyse_manifest_metadata(
    manifest: &ManifestSummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "dependency.missing-package-metadata";
    if !config.rule_enabled(rule_id) {
        return;
    }

    let mut missing = Vec::new();
    if is_missing_text(manifest.package_description.as_deref()) {
        missing.push("description");
    }
    if is_missing_text(manifest.package_license.as_deref()) {
        missing.push("license");
    }
    if missing.is_empty() {
        return;
    }

    let package = manifest
        .package_name
        .clone()
        .unwrap_or_else(|| "package".to_string());
    findings.push(Finding::new(
        rule_id,
        format!(
            "Package `{package}` is missing Cargo metadata: {}.",
            missing.join(", ")
        ),
        manifest.file_path.clone(),
        Some(manifest.package_line),
        Severity::Advisory,
        Pillar::Documentation,
        Confidence::High,
        Some(package),
        Some("Add package description and license metadata to Cargo.toml.".to_string()),
        json!({ "missing": missing }),
    ));
}

pub(crate) fn analyse_manifest_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_git_dependency(manifest, dependency, config, findings);
    analyse_path_dependency(manifest, dependency, config, findings);
    analyse_wildcard_dependency(manifest, dependency, config, findings);
}

pub(crate) fn analyse_git_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if let Some(git) = &dependency.git {
        let rule_id = "dependency.git-source";
        if config.rule_enabled(rule_id) {
            findings.push(Finding::new(
                rule_id,
                format!(
                    "Dependency `{}` in `{}` uses a git source.",
                    dependency.name, dependency.section
                ),
                manifest.file_path.clone(),
                Some(dependency.line),
                Severity::Warning,
                Pillar::Security,
                Confidence::High,
                Some(dependency.name.clone()),
                Some(
                    "Prefer a crates.io release, or pin and review the git dependency.".to_string(),
                ),
                json!({ "section": dependency.section, "git": git }),
            ));
        }
    }
}

pub(crate) fn analyse_path_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if let Some(path) = &dependency.path {
        let rule_id = "dependency.path-source";
        if config.rule_enabled(rule_id) {
            findings.push(Finding::new(
                rule_id,
                format!(
                    "Dependency `{}` in `{}` uses a local path source.",
                    dependency.name, dependency.section
                ),
                manifest.file_path.clone(),
                Some(dependency.line),
                Severity::Advisory,
                Pillar::Security,
                Confidence::High,
                Some(dependency.name.clone()),
                Some("Confirm the path dependency is intentional and available in CI.".to_string()),
                json!({ "section": dependency.section, "path": path }),
            ));
        }
    }
}

pub(crate) fn analyse_wildcard_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if let Some(requirement) = &dependency.requirement {
        let rule_id = "dependency.wildcard-version";
        if config.rule_enabled(rule_id) && is_wildcard_requirement(requirement) {
            findings.push(Finding::new(
                rule_id,
                format!(
                    "Dependency `{}` in `{}` uses wildcard version `{requirement}`.",
                    dependency.name, dependency.section
                ),
                manifest.file_path.clone(),
                Some(dependency.line),
                Severity::Warning,
                Pillar::Security,
                Confidence::High,
                Some(dependency.name.clone()),
                Some("Use an explicit compatible version requirement.".to_string()),
                json!({ "section": dependency.section, "requirement": requirement }),
            ));
        }
    }
}

pub(crate) fn analyse_lockfile_duplicates(
    lockfile: &LockfileSummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "dependency.duplicate-locked-version";
    if !config.rule_enabled(rule_id) {
        return;
    }
    let allowed_versions = config.threshold(rule_id, 1.0) as usize;
    let mut by_name: BTreeMap<&str, Vec<&LockedPackageSummary>> = BTreeMap::new();
    for package in &lockfile.packages {
        by_name.entry(&package.name).or_default().push(package);
    }

    for (name, packages) in by_name {
        let versions: BTreeSet<&str> = packages
            .iter()
            .map(|package| package.version.as_str())
            .collect();
        if versions.len() <= allowed_versions {
            continue;
        }
        let first_line = packages
            .iter()
            .map(|package| package.line)
            .min()
            .unwrap_or(1);
        let versions: Vec<&str> = versions.into_iter().collect();
        findings.push(Finding::new(
            rule_id,
            format!(
                "Package `{name}` is locked at {} versions, above the threshold of {allowed_versions}.",
                versions.len()
            ),
            lockfile.file_path.clone(),
            Some(first_line),
            config.severity(rule_id, Severity::Advisory),
            Pillar::Security,
            Confidence::High,
            Some(name.to_string()),
            Some("Align dependency requirements so Cargo can resolve a single version when possible.".to_string()),
            json!({ "versions": versions }),
        ));
    }
}

pub(crate) fn is_missing_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

pub(crate) fn is_wildcard_requirement(requirement: &str) -> bool {
    requirement
        .split(',')
        .any(|part| part.trim() == "*" || part.trim().ends_with(".*"))
}
