use super::*;
use crate::changed_region::{git_args_with_paths, git_output};
use crate::cli::HookArgs;

pub(crate) const HOOK_CONTRACT_VERSION: &str = "gruff.hook.v1";

pub(crate) fn run_hook_command(args: HookArgs, writer: OutputWriter) -> ExitCode {
    if args.capabilities {
        writer.emit_unconditional(&render_capabilities());
        return ExitCode::SUCCESS;
    }

    let changed_region_active = args.changed_ranges.is_some();
    let new_only_active = args.baseline.is_some() || args.diff.is_some();
    let options = options_from_hook(&args, true);
    let (project_root, config) = match resolve_project_root_and_config(&options) {
        Ok(pair) => pair,
        Err(error) => {
            writer.emit_unconditional(&render_config_error(&error));
            return ExitCode::from(2);
        }
    };

    match run_analysis_in_project(&project_root, &options, &config) {
        Ok(mut report) => {
            if let Err(error) = apply_hook_new_only(
                &mut report,
                &args,
                &project_root,
                &options,
                &config,
                changed_region_active,
            ) {
                writer.emit_unconditional(&render_config_error(&error));
                return ExitCode::from(2);
            }
            let has_fatal_diagnostic = report.diagnostics.iter().any(RunDiagnostic::is_failure);
            writer.emit_unconditional(&render_hook_report(
                report,
                changed_region_active,
                new_only_active,
            ));
            if has_fatal_diagnostic {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            writer.emit_unconditional(&render_config_error(&error));
            ExitCode::from(2)
        }
    }
}

fn options_from_hook(args: &HookArgs, include_changed_ranges: bool) -> AnalysisOptions {
    let diff = match (&args.changed_ranges, include_changed_ranges) {
        (Some(ranges), true) => Some(DiffSelection::ExplicitRanges {
            ranges: ranges.clone(),
            scope: args.changed_scope,
        }),
        _ => None,
    };
    AnalysisOptions {
        paths: args.paths.clone(),
        config: args.config.clone(),
        no_config: args.no_config,
        format: OutputFormat::Json,
        fail_on: FailThreshold::None,
        include_ignored: false,
        diff,
        history_file: None,
        baseline: args.baseline.clone(),
        generate_baseline: None,
        no_baseline: args.baseline.is_none(),
    }
}

fn apply_hook_new_only(
    report: &mut AnalysisReport,
    args: &HookArgs,
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    changed_region_active: bool,
) -> Result<(), String> {
    if let Some(mode) = &args.diff {
        let base_identities = diff_base_stable_identities(project_root, options, config, mode)?;
        apply_stable_identity_new_only(report, &base_identities);
    }

    if !changed_region_active || args.baseline.is_none() && args.diff.is_none() {
        return Ok(());
    }

    let full_options = options_from_hook(args, false);
    let mut full_report = run_analysis_in_project(project_root, &full_options, config)?;
    if let Some(mode) = &args.diff {
        let base_identities =
            diff_base_stable_identities(project_root, &full_options, config, mode)?;
        apply_stable_identity_new_only(&mut full_report, &base_identities);
    }

    report
        .findings
        .retain(|finding| matches!(finding.scope, FindingScope::Line | FindingScope::Symbol));
    full_report
        .findings
        .retain(|finding| matches!(finding.scope, FindingScope::File | FindingScope::Project));
    report.findings.extend(full_report.findings);
    Ok(())
}

pub(crate) fn apply_stable_identity_new_only(
    report: &mut AnalysisReport,
    base_identities: &BTreeSet<String>,
) {
    report
        .findings
        .retain(|finding| !base_identities.contains(&finding.stable_identity));
}

pub(crate) fn diff_base_stable_identities(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    mode: &str,
) -> Result<BTreeSet<String>, String> {
    let base_ref = hook_diff_base_ref(mode);
    let base_tree = TempBaseTree::create()?;
    export_git_base_tree(project_root, base_ref, &options.paths, base_tree.path())?;
    let base_options = AnalysisOptions {
        paths: options.paths.clone(),
        config: None,
        no_config: true,
        format: OutputFormat::Json,
        fail_on: FailThreshold::None,
        include_ignored: false,
        diff: None,
        history_file: None,
        baseline: None,
        generate_baseline: None,
        no_baseline: true,
    };
    let base_report = run_analysis_in_project(base_tree.path(), &base_options, config)?;
    Ok(base_report
        .findings
        .into_iter()
        .map(|finding| finding.stable_identity)
        .collect())
}

fn hook_diff_base_ref(mode: &str) -> &str {
    match mode {
        "working-tree" | "staged" | "unstaged" => "HEAD",
        base => base,
    }
}

fn export_git_base_tree(
    project_root: &Path,
    base_ref: &str,
    paths: &[PathBuf],
    output_root: &Path,
) -> Result<(), String> {
    // `-z` makes git emit NUL-separated, unquoted paths. Without it git applies
    // `core.quotePath` and C-quotes non-ASCII names (e.g. `"caf\303\251.rs"`),
    // whose backslashes `safe_git_tree_path` rejects and which `git show` cannot
    // resolve - hard-erroring the hook on any tree with a non-ASCII filename.
    let listed = git_output(
        project_root,
        &git_args_with_paths(&["ls-tree", "-z", "-r", "--name-only", base_ref], paths),
    )?;
    for path in listed.split('\0').filter(|path| !path.trim().is_empty()) {
        let safe = safe_git_tree_path(path)?;
        let mut git_object = String::with_capacity(base_ref.len() + path.len() + 1);
        git_object.push_str(base_ref);
        git_object.push(':');
        git_object.push_str(path);
        let content = git_output(project_root, &["show".to_string(), git_object])?;
        let output_path = output_root.join(safe);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "unable to create base tree directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        fs::write(&output_path, content).map_err(|error| {
            format!(
                "unable to write base tree file {}: {error}",
                output_path.display()
            )
        })?;
    }
    Ok(())
}

fn safe_git_tree_path(path: &str) -> Result<PathBuf, String> {
    if path.starts_with('/') {
        return Err("git base tree path must be relative".to_string());
    }
    let mut safe = PathBuf::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." || component.contains('\\')
        {
            return Err(format!("git base tree path escapes root: {path}"));
        }
        safe.push(component);
    }
    Ok(safe)
}

struct TempBaseTree {
    path: PathBuf,
}

impl TempBaseTree {
    fn create() -> Result<Self, String> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("unable to create hook temp name: {error}"))?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("gruff-rs-hook-base-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).map_err(|error| {
            format!(
                "unable to create hook temp tree {}: {error}",
                path.display()
            )
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempBaseTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn render_capabilities() -> String {
    serde_json::to_string_pretty(&json!({
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": analyzer_json(),
        "supports": {
            "changedRanges": true,
            "diff": true,
            "baseline": true,
            "scopeField": true,
            "metadata": true,
            "stableIdentity": true,
            "ignoreReport": true,
            "newOnly": true
        },
        "flags": {
            "changedRanges": "--changed-ranges",
            "diff": "--diff",
            "baseline": "--baseline"
        },
        "flagOrder": "any"
    }))
    .expect("hook capabilities serialize")
}

pub(crate) fn render_config_error(error: &str) -> String {
    serde_json::to_string_pretty(&json!({
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": analyzer_json(),
        "findings": [],
        "suppressed": { "count": 0 },
        "ignored": { "paths": [] },
        "config": {
            "schemaOk": false,
            "error": {
                "message": error,
                "remediation": "Fix the gruff-rs configuration and rerun the hook."
            }
        }
    }))
    .expect("hook config error serialize")
}

pub(crate) fn render_hook_report(
    mut report: AnalysisReport,
    changed_region_active: bool,
    new_only_active: bool,
) -> String {
    apply_hook_changed_region_filter(&mut report, changed_region_active, new_only_active);

    let registry = rules::builtin_registry();
    let ignored_paths =
        serde_json::to_value(&report.paths.ignored_path_details).unwrap_or_else(|_| json!([]));
    let suppressed_count = report.suppressed_count.unwrap_or(0);
    let findings = hook_findings(report.findings, &registry);

    serde_json::to_string_pretty(&json!({
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": analyzer_json(),
        "findings": findings,
        "suppressed": { "count": suppressed_count },
        "ignored": { "paths": ignored_paths },
        "config": { "schemaOk": true, "error": null }
    }))
    .expect("hook report serialize")
}

pub(crate) fn apply_hook_changed_region_filter(
    report: &mut AnalysisReport,
    changed_region_active: bool,
    new_only_active: bool,
) {
    if !changed_region_active || new_only_active {
        return;
    }

    let before = report.findings.len();
    report
        .findings
        .retain(|finding| !matches!(finding.scope, FindingScope::File | FindingScope::Project));
    let removed = before.saturating_sub(report.findings.len());
    if removed > 0 {
        report.suppressed_count = Some(report.suppressed_count.unwrap_or(0) + removed);
    }
}

fn hook_findings(mut findings: Vec<Finding>, registry: &rules::RuleRegistry) -> Vec<Value> {
    findings.sort_by(|left, right| {
        severity_rank(left.severity)
            .cmp(&severity_rank(right.severity))
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| {
                left.line
                    .unwrap_or(usize::MAX)
                    .cmp(&right.line.unwrap_or(usize::MAX))
            })
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.stable_identity.cmp(&right.stable_identity))
    });

    findings
        .into_iter()
        .map(|finding| hook_finding(finding, registry))
        .collect()
}

fn hook_finding(finding: Finding, registry: &rules::RuleRegistry) -> Value {
    json!({
        "ruleId": finding.rule_id,
        "pillar": pillar_label(finding.pillar),
        "severity": severity_label(finding.severity),
        "scope": finding.scope.as_str(),
        "file": finding.file_path,
        "line": finding.line,
        "endLine": finding.end_line,
        "symbol": finding.symbol,
        "message": finding.message,
        "remediation": remediation_for(&finding, registry),
        "metadata": finding.metadata,
        "stableIdentity": finding.stable_identity,
        "fingerprint": finding.fingerprint
    })
}

fn remediation_for(finding: &Finding, registry: &rules::RuleRegistry) -> String {
    finding
        .remediation
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| {
            registry.get(&finding.rule_id).map(|definition| {
                format!(
                    "Review and address this finding: {}",
                    definition.description
                )
            })
        })
        .unwrap_or_else(|| format!("Review and address this {} finding.", finding.rule_id))
}

fn analyzer_json() -> Value {
    json!({ "name": "gruff-rs", "version": VERSION })
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

fn severity_rank(severity: Severity) -> usize {
    match severity {
        Severity::Error => 0,
        Severity::Warning => 1,
        Severity::Advisory => 2,
    }
}
