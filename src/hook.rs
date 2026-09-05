use super::*;
use crate::changed_region::{git_args_with_paths, git_output, git_output_bytes_with_stdin};
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
    let (project_root, options, config) =
        match resolve_project_root_and_config(options, args.deep_scan_budget.as_ref()) {
            Ok(triple) => triple,
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
        migrate_baseline: None,
        force_baseline_overwrite: false,
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
        return apply_hook_changed_region_new_only(
            report,
            args,
            project_root,
            options,
            config,
            changed_region_active,
            Some(base_identities),
        );
    }

    apply_hook_changed_region_new_only(
        report,
        args,
        project_root,
        options,
        config,
        changed_region_active,
        None,
    )
}

fn apply_hook_changed_region_new_only(
    report: &mut AnalysisReport,
    args: &HookArgs,
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    changed_region_active: bool,
    diff_base_identities: Option<BTreeMap<String, usize>>,
) -> Result<(), String> {
    if !changed_region_active || args.baseline.is_none() && args.diff.is_none() {
        return Ok(());
    }

    let full_options = AnalysisOptions {
        diff: None,
        ..options.clone()
    };
    let mut full_report = run_analysis_in_project(project_root, &full_options, config)?;
    if let Some(mode) = &args.diff {
        let base_identities = match &diff_base_identities {
            Some(base_identities) => base_identities.clone(),
            None => diff_base_stable_identities(project_root, &full_options, config, mode)?,
        };
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

/// Drop findings that already existed in the base, keyed on stable identity but
/// honouring how many times each identity occurred. Stable identities are not
/// unique: several findings can share `(rule_id, file_path, subject)` - e.g. two
/// secret matches with the same constant message in one file, or one crate
/// flagged in two manifest sections. A plain set-membership check would then
/// drop a newly added duplicate as if it were pre-existing, hiding a real new
/// finding. Consuming per-identity counts keeps `current - base` occurrences of
/// each identity, so a freshly introduced one still surfaces.
pub(crate) fn apply_stable_identity_new_only(
    report: &mut AnalysisReport,
    base_counts: &BTreeMap<String, usize>,
) {
    let mut remaining = base_counts.clone();
    report.findings.retain(
        |finding| match remaining.get_mut(&finding.stable_identity) {
            Some(count) if *count > 0 => {
                *count -= 1;
                false
            }
            _ => true,
        },
    );
}

/// Count occurrences of each stable identity in the base tree at `mode`, so
/// [`apply_stable_identity_new_only`] can suppress exactly the pre-existing
/// count and let genuinely new duplicates through.
pub(crate) fn diff_base_stable_identities(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    mode: &str,
) -> Result<BTreeMap<String, usize>, String> {
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
        migrate_baseline: None,
        force_baseline_overwrite: false,
        no_baseline: true,
    };
    let base_report = run_analysis_in_project(base_tree.path(), &base_options, config)?;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for finding in base_report.findings {
        *counts.entry(finding.stable_identity).or_default() += 1;
    }
    Ok(counts)
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
    let listed = git_base_tree_paths(project_root, base_ref, paths)?;
    let base_paths = listed.iter().map(String::as_str).collect::<Vec<_>>();
    let blobs = git_cat_file_batch(project_root, base_ref, &base_paths)?;
    let mut parser = CatFileBatchParser::new(&blobs);
    for path in base_paths {
        let safe = safe_git_tree_path(path)?;
        let content = parser.next_blob(path)?;
        write_base_tree_blob(output_root, &safe, content)?;
    }
    parser.finish()
}

fn git_base_tree_paths(
    project_root: &Path,
    base_ref: &str,
    paths: &[PathBuf],
) -> Result<Vec<String>, String> {
    let listed = git_output(
        project_root,
        &git_args_with_paths(&["ls-tree", "-z", "-r", "--name-only", base_ref], paths),
    )?;
    Ok(listed
        .split('\0')
        .filter(|path| !path.trim().is_empty())
        .map(str::to_string)
        .collect())
}

fn git_cat_file_batch(
    project_root: &Path,
    base_ref: &str,
    base_paths: &[&str],
) -> Result<Vec<u8>, String> {
    let mut queries = Vec::new();
    for path in base_paths {
        queries.extend_from_slice(base_ref.as_bytes());
        queries.push(b':');
        queries.extend_from_slice(path.as_bytes());
        queries.push(0);
    }
    git_output_bytes_with_stdin(
        project_root,
        &[
            "cat-file".to_string(),
            "--batch".to_string(),
            "-Z".to_string(),
        ],
        &queries,
    )
}

fn write_base_tree_blob(output_root: &Path, safe: &Path, content: &[u8]) -> Result<(), String> {
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
    })
}

struct CatFileBatchParser<'a> {
    output: &'a [u8],
    cursor: usize,
}

impl<'a> CatFileBatchParser<'a> {
    fn new(output: &'a [u8]) -> Self {
        Self { output, cursor: 0 }
    }

    fn next_blob(&mut self, path: &str) -> Result<&'a [u8], String> {
        let header = self.next_header(path)?;
        let (_, object_type, size) = parse_cat_file_header(header, path)?;
        if object_type != "blob" {
            return Err(format!(
                "git base tree path {path} resolved to {object_type}, expected blob"
            ));
        }
        let content_start = self.cursor;
        let content_end = content_start
            .checked_add(size)
            .ok_or_else(|| format!("git cat-file size overflow for {path}"))?;
        if content_end >= self.output.len() {
            return Err(format!("git cat-file output truncated for {path}"));
        }
        if self.output.get(content_end) != Some(&0) {
            return Err(format!(
                "git cat-file output missing blob terminator for {path}"
            ));
        }
        self.cursor = content_end + 1;
        Ok(&self.output[content_start..content_end])
    }

    fn next_header(&mut self, path: &str) -> Result<&'a str, String> {
        let Some(relative_end) = self.output[self.cursor..]
            .iter()
            .position(|byte| *byte == 0)
        else {
            return Err(format!("git cat-file output missing header for {path}"));
        };
        let header_start = self.cursor;
        let header_end = self.cursor + relative_end;
        self.cursor = header_end + 1;
        std::str::from_utf8(&self.output[header_start..header_end])
            .map_err(|error| format!("git cat-file header for {path} is not UTF-8: {error}"))
    }

    fn finish(&self) -> Result<(), String> {
        if self.cursor == self.output.len() {
            Ok(())
        } else {
            Err("git cat-file returned trailing batch output".to_string())
        }
    }
}

fn parse_cat_file_header<'a>(
    header: &'a str,
    path: &str,
) -> Result<(&'a str, &'a str, usize), String> {
    let mut parts = header.split(' ');
    let object_id = parts
        .next()
        .ok_or_else(|| format!("git cat-file header missing object id for {path}"))?;
    let object_type = parts
        .next()
        .ok_or_else(|| format!("git cat-file header missing object type for {path}"))?;
    if object_type == "missing" {
        return Err(format!("git cat-file could not read base tree path {path}"));
    }
    let size = parts
        .next()
        .ok_or_else(|| format!("git cat-file header missing size for {path}"))?
        .parse::<usize>()
        .map_err(|error| format!("git cat-file header size invalid for {path}: {error}"))?;
    Ok((object_id, object_type, size))
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
            "newOnly": true,
            "deepScanBudget": true
        },
        "flags": {
            "changedRanges": "--changed-ranges",
            "diff": "--diff",
            "baseline": "--baseline",
            "deepScanBudget": "--deep-scan-budget"
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
    let diagnostics = hook_diagnostics(report.diagnostics);
    let findings = hook_findings(report.findings, &registry);

    serde_json::to_string_pretty(&json!({
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": analyzer_json(),
        "findings": findings,
        "diagnostics": diagnostics,
        "suppressed": { "count": suppressed_count },
        "ignored": { "paths": ignored_paths },
        "config": { "schemaOk": true, "error": null }
    }))
    .expect("hook report serialize")
}

fn hook_diagnostics(diagnostics: Vec<RunDiagnostic>) -> Vec<Value> {
    diagnostics
        .into_iter()
        .map(|diagnostic| {
            let mut value = json!({
                "type": diagnostic.diagnostic_type,
                "message": diagnostic.message,
                "file": diagnostic.file_path,
                "line": diagnostic.line,
            });
            if let Some(invalidates_run) = diagnostic.invalidates_run {
                value
                    .as_object_mut()
                    .expect("hook diagnostic is an object")
                    .insert("invalidatesRun".to_string(), json!(invalidates_run));
            }
            value
        })
        .collect()
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
