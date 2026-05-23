use super::*;

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
    if !config.is_rule_enabled(rule_id) {
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
    findings.push(Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!(
            "Package `{package}` is missing Cargo metadata: {}.",
            missing.join(", ")
        ),
        file_path: manifest.file_path.clone(),
        line: Some(manifest.package_line),
        severity: Severity::Advisory,
        pillar: Pillar::Documentation,
        confidence: Confidence::High,
        symbol: Some(package),
        remediation: Some(
            "Add package description and license metadata to Cargo.toml.".to_string(),
        ),
        metadata: json!({ "missing": missing }),
    }));
}

pub(crate) fn analyse_manifest_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_git_dependency(manifest, dependency, config, findings);
    analyse_unpinned_git_dependency(manifest, dependency, config, findings);
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
        if config.is_rule_enabled(rule_id) {
            findings.push(Finding::new(FindingDescriptor {
                rule_id: rule_id.to_string(),
                message: format!(
                    "Dependency `{}` in `{}` uses a git source.",
                    dependency.name, dependency.section
                ),
                file_path: manifest.file_path.clone(),
                line: Some(dependency.line),
                severity: Severity::Warning,
                pillar: Pillar::Security,
                confidence: Confidence::High,
                symbol: Some(dependency.name.clone()),
                remediation: Some(
                    "Prefer a crates.io release, or pin and review the git dependency.".to_string(),
                ),
                metadata: json!({ "section": dependency.section, "git": git }),
            }));
        }
    }
}

pub(crate) fn analyse_unpinned_git_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if let Some(git) = &dependency.git {
        let rule_id = "dependency.git-unpinned-revision";
        if config.is_rule_enabled(rule_id) && is_missing_text(dependency.rev.as_deref()) {
            findings.push(Finding::new(FindingDescriptor {
                rule_id: rule_id.to_string(),
                message: format!(
                    "Dependency `{}` in `{}` uses a git source without a fixed rev.",
                    dependency.name, dependency.section
                ),
                file_path: manifest.file_path.clone(),
                line: Some(dependency.line),
                severity: Severity::Warning,
                pillar: Pillar::Security,
                confidence: Confidence::High,
                symbol: Some(dependency.name.clone()),
                remediation: Some(
                    "Pin git dependencies with a reviewed `rev` commit hash.".to_string(),
                ),
                metadata: json!({ "section": dependency.section, "git": git }),
            }));
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
        if config.is_rule_enabled(rule_id) {
            findings.push(Finding::new(FindingDescriptor {
                rule_id: rule_id.to_string(),
                message: format!(
                    "Dependency `{}` in `{}` uses a local path source.",
                    dependency.name, dependency.section
                ),
                file_path: manifest.file_path.clone(),
                line: Some(dependency.line),
                severity: Severity::Advisory,
                pillar: Pillar::Security,
                confidence: Confidence::High,
                symbol: Some(dependency.name.clone()),
                remediation: Some(
                    "Confirm the path dependency is intentional and available in CI.".to_string(),
                ),
                metadata: json!({ "section": dependency.section, "path": path }),
            }));
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
        if config.is_rule_enabled(rule_id) && is_wildcard_requirement(requirement) {
            findings.push(Finding::new(FindingDescriptor {
                rule_id: rule_id.to_string(),
                message: format!(
                    "Dependency `{}` in `{}` uses wildcard version `{requirement}`.",
                    dependency.name, dependency.section
                ),
                file_path: manifest.file_path.clone(),
                line: Some(dependency.line),
                severity: Severity::Warning,
                pillar: Pillar::Security,
                confidence: Confidence::High,
                symbol: Some(dependency.name.clone()),
                remediation: Some("Use an explicit compatible version requirement.".to_string()),
                metadata: json!({ "section": dependency.section, "requirement": requirement }),
            }));
        }
    }
}

pub(crate) fn analyse_lockfile_duplicates(
    lockfile: &LockfileSummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "dependency.duplicate-locked-version";
    if !config.is_rule_enabled(rule_id) {
        return;
    }
    let allowed_versions = config.threshold(rule_id, 1.0) as usize;
    let by_name = group_locked_packages_by_name(lockfile);
    for (name, packages) in by_name {
        let versions: Vec<&str> = packages
            .iter()
            .map(|package| package.version.as_str())
            .collect::<BTreeSet<&str>>()
            .into_iter()
            .collect();
        if versions.len() > allowed_versions {
            let summary = LockedPackageDuplicate {
                name,
                first_line: packages
                    .iter()
                    .map(|package| package.line)
                    .min()
                    .unwrap_or(1),
                versions,
            };
            findings.push(duplicate_locked_version_finding(
                rule_id,
                &lockfile.file_path,
                summary,
                allowed_versions,
                config,
            ));
        }
    }
}

fn group_locked_packages_by_name(
    lockfile: &LockfileSummary,
) -> BTreeMap<&str, Vec<&LockedPackageSummary>> {
    let mut by_name: BTreeMap<&str, Vec<&LockedPackageSummary>> = BTreeMap::new();
    for package in &lockfile.packages {
        by_name.entry(&package.name).or_default().push(package);
    }
    by_name
}

struct LockedPackageDuplicate<'a> {
    name: &'a str,
    first_line: usize,
    versions: Vec<&'a str>,
}

fn duplicate_locked_version_finding(
    rule_id: &str,
    file_path: &str,
    summary: LockedPackageDuplicate<'_>,
    allowed_versions: usize,
    config: &Config,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!(
            "Package `{}` is locked at {} versions, above the threshold of {allowed_versions}.",
            summary.name,
            summary.versions.len()
        ),
        file_path: file_path.to_string(),
        line: Some(summary.first_line),
        severity: config.severity(rule_id, Severity::Advisory),
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: Some(summary.name.to_string()),
        remediation: Some(
            "Align dependency requirements so Cargo can resolve a single version when possible."
                .to_string(),
        ),
        metadata: json!({ "versions": summary.versions }),
    })
}
