use super::*;

/// Run the dependency rules over a project's Cargo manifest and lockfile and append every finding they raise.
///
/// `context` supplies the parsed manifest and lockfile summaries; when either is absent, the rules that need it are skipped.
/// `config` decides which dependency rules run and supplies the duplicate-version threshold.
/// `findings` receives each new finding after its existing entries.
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

/// Report a package whose Cargo manifest lacks description or license text under the `dependency.missing-package-metadata` rule.
///
/// `manifest` supplies the package name, metadata, file path and package line; an unnamed package is reported as `package`.
/// `config` must enable the rule or nothing is checked, and `findings` receives at most one advisory finding listing the missing fields.
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

/// Run the git-source, unpinned-git-revision and wildcard-version checks on one dependency declared in the manifest.
///
/// `manifest` supplies the file path for findings, and `dependency` is the declaration checked by all three rules.
/// `config` enables each rule independently, and `findings` receives every finding the checks raise.
pub(crate) fn analyse_manifest_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_git_dependency(manifest, dependency, config, findings);
    analyse_unpinned_git_dependency(manifest, dependency, config, findings);
    analyse_wildcard_dependency(manifest, dependency, config, findings);
}

/// Report a manifest dependency that takes its code from a git source under the `dependency.git-source` rule.
///
/// `manifest` supplies the file path reported, and `dependency` supplies the git source, name, section and line.
/// `config` must enable the rule, and `findings` receives at most one warning for the dependency.
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

/// Report a git dependency that sets no fixed `rev` under the `dependency.git-unpinned-revision` rule.
///
/// `manifest` supplies the file path reported, and `dependency` supplies the git source, `rev`, name, section and line.
/// `config` must enable the rule, and `findings` receives at most one warning for the dependency.
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

/// Report a dependency with a wildcard version requirement under the `dependency.wildcard-version` rule.
///
/// `manifest` supplies the file path reported, and `dependency` supplies the requirement, name, section and line; no requirement means no check.
/// `config` must enable the rule, and `findings` receives at most one warning for the dependency.
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

/// Report each locked package whose count of distinct version strings exceeds the `dependency.duplicate-locked-version` threshold.
///
/// `lockfile` supplies the locked packages and the reported file path; `config` must enable the rule and sets the allowed version count.
/// `findings` receives one finding per package over the threshold, in package-name order, located at that package's earliest line.
pub(crate) fn analyse_lockfile_duplicates(
    lockfile: &LockfileSummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "dependency.duplicate-locked-version";
    if !config.is_rule_enabled(rule_id) {
        return;
    }
    let allowed_versions = config.threshold(rule_id) as usize;
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

/// Group a lockfile's packages by name so the versions locked for one crate can be counted together.
///
/// `lockfile` supplies the packages, which keep their stored order within each group.
/// Returns a map from package name to that name's package entries, ordered by name; a lockfile with no packages gives an empty map.
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

/// Build the duplicate-locked-version finding for one package locked at more versions than the threshold allows.
///
/// `rule_id` names the rule and selects its severity; it must be a built-in rule id, even when overridden, or this function panics.
/// `file_path` is the lockfile path reported, and `summary` supplies the package name, first line and distinct versions.
///
/// `allowed_versions` is the threshold quoted in the message and metadata; `config` resolves the severity, defaulting to the built-in one.
/// Returns a Security-pillar finding whose metadata records the versions, the measured count and the threshold.
fn duplicate_locked_version_finding(
    rule_id: &str,
    file_path: &str,
    summary: LockedPackageDuplicate<'_>,
    allowed_versions: usize,
    config: &Config,
) -> Finding {
    let measured = summary.versions.len();
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!(
            "Package `{}` is locked at {} versions, above the threshold of {allowed_versions}.",
            summary.name, measured
        ),
        file_path: file_path.to_string(),
        line: Some(summary.first_line),
        severity: config.severity(rule_id, rules::builtin_severity(rule_id)),
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: Some(summary.name.to_string()),
        remediation: Some(
            "Align dependency requirements so Cargo can resolve a single version when possible."
                .to_string(),
        ),
        metadata: json!({
            "versions": summary.versions,
            "measured": measured,
            "threshold": allowed_versions,
            "unit": "versions",
            "direction": "above"
        }),
    })
}
