use super::*;
use crate::changed_region::{git_args_with_paths, git_output, git_output_bytes_with_stdin};
use crate::cli::HookArgs;

pub(crate) const HOOK_CONTRACT_VERSION: &str = "gruff.hook.v2";

/// The one baseline schema this hook accepts; anything else is refused rather than read under the wrong rules.
pub(crate) const HOOK_BASELINE_SCHEMA_VERSION: &str = "gruff.baseline.v3";

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
                writer.emit_unconditional(&render_run_failure(&error));
                eprintln!("gruff-rs: {error}");
                return ExitCode::from(2);
            }
        };

    match run_analysis_in_project(&project_root, &options, &config) {
        Ok(mut report) => emit_hook_report(
            &mut report,
            &HookRun {
                args: &args,
                project_root: &project_root,
                options: &options,
                config: &config,
                changed_region_active,
                new_only_active,
            },
            &writer,
        ),
        Err(error) => {
            writer.emit_unconditional(&render_run_failure(&error));
            eprintln!("gruff-rs: {error}");
            ExitCode::from(2)
        }
    }
}

/// Apply the new-only base, publish the payload, and tell the calling agent what it means.
///
/// The gate reads the payload rather than the raw scan, so what blocks an edit is exactly what the agent was shown.
fn emit_hook_report(
    report: &mut AnalysisReport,
    run: &HookRun<'_>,
    writer: &OutputWriter,
) -> ExitCode {
    let args = run.args;
    if let Err(error) = apply_hook_new_only(
        report,
        args,
        run.project_root,
        run.options,
        run.config,
        run.changed_region_active,
    ) {
        // A baseline this port cannot read would otherwise suppress findings under rules nobody ratified.
        writer.emit_unconditional(&render_fatal("baseline", &error));
        eprintln!("gruff-rs: {error}");
        return ExitCode::from(2);
    }

    let has_fatal_diagnostic = report.diagnostics.iter().any(RunDiagnostic::is_failure);
    let context = HookRunContext {
        mode: hook_run_mode(args),
        paths: args
            .paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect(),
        baseline_path: args
            .baseline
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
    };
    let payload = render_hook_report_for(
        report,
        run.changed_region_active,
        run.new_only_active,
        &context,
    );
    writer.emit_unconditional(&payload);

    if has_fatal_diagnostic {
        return ExitCode::from(2);
    }
    ExitCode::from(hook_exit_code(&payload, args))
}

/// Render the payload for a run that could not happen, naming which kind of failure it was.
///
/// A baseline this port cannot read is not a configuration problem, and saying so would send the user to the wrong
/// file. Everything else is reported as a configuration failure, which is what it has always been.
fn render_run_failure(error: &str) -> String {
    if error.contains("baseline") {
        return render_fatal("baseline", error);
    }
    render_config_error(error)
}

/// Name which region selector chose the work, so a consumer can tell a targeted run from a whole-tree one.
fn hook_run_mode(args: &HookArgs) -> String {
    // Explicit ranges are the narrowest selector and win when both are given.
    if args.changed_ranges.is_some() {
        return "changed-ranges".to_string();
    }
    if args.diff.is_some() {
        return "diff".to_string();
    }
    "full".to_string()
}

/// Decide what the hook tells the calling agent, from the findings it actually published.
///
/// The gate reads the payload rather than the raw scan, so what blocks an edit is exactly what the agent was shown:
/// a finding the changed-region filter or the baseline removed is not in the payload and does not block.
fn hook_exit_code(payload: &str, args: &HookArgs) -> u8 {
    let Ok(parsed) = serde_json::from_str::<Value>(payload) else {
        return 0;
    };

    // A consumer may ask for any caveat to stop the edit, which is the only way a warning becomes blocking.
    if args.fail_on_diagnostics
        && parsed["diagnostics"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty())
    {
        return 1;
    }

    let Some(rows) = parsed["findings"].as_array() else {
        return 0;
    };

    for row in rows {
        // The baseline dimension is independent of both floors: an unreviewed finding blocks whatever its severity.
        if args.fail_on_new && row["baselineStatus"].as_str() == Some("new") {
            return 1;
        }
        if is_hook_gate_reached(row, args) {
            return 1;
        }
    }

    0
}

/// Report whether one published finding clears both independent floors the caller set.
fn is_hook_gate_reached(row: &Value, args: &HookArgs) -> bool {
    // A `none` threshold names no floor at all, so no severity reaches it and only --fail-on-new can block.
    let Some(severity_floor) = fail_threshold_rank(args.fail_on) else {
        return false;
    };
    let severity = severity_rank_of(row["severity"].as_str().unwrap_or(""));
    let confidence = confidence_rank_of(row["confidence"].as_str().unwrap_or(""));

    severity >= severity_floor && confidence >= confidence_rank_of(args.min_confidence.as_str())
}

fn fail_threshold_rank(threshold: FailThreshold) -> Option<usize> {
    match threshold {
        FailThreshold::None => None,
        FailThreshold::Advisory => Some(0),
        FailThreshold::Warning => Some(1),
        FailThreshold::Error => Some(2),
    }
}

fn severity_rank_of(label: &str) -> usize {
    match label {
        "warning" => 1,
        "error" => 2,
        _ => 0,
    }
}

/// Rank one confidence label; anything unrecognised ranks highest, so an unrated finding cannot slip under a gate.
fn confidence_rank_of(label: &str) -> usize {
    match label {
        "low" => 0,
        "medium" => 1,
        _ => 2,
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
        execution: ExecutionSelectors::default(),
        display: DisplaySelectors::default(),
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
        execution: ExecutionSelectors::default(),
        display: DisplaySelectors::default(),
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
            "baseline": true,
            "baselineV3": true,
            "changedRanges": true,
            "confidenceGate": true,
            "deepScanBudget": true,
            "diagnostics": true,
            "diff": true,
            "ignoreReport": true,
            "metadata": true,
            "newOnly": true,
            "scopeField": true,
            "stableIdentity": true
        },
        "flags": {
            "baseline": "--baseline",
            "changedRanges": "--changed-ranges",
            "deepScanBudget": "--deep-scan-budget",
            "diff": "--diff",
            "failOnDiagnostics": "--fail-on-diagnostics",
            "minConfidence": "--min-confidence"
        },
        "flagOrder": "any"
    }))
    .expect("hook capabilities serialize")
}

pub(crate) fn render_config_error(error: &str) -> String {
    let mut payload = fatal_payload("config", error);
    payload
        .as_object_mut()
        .expect("hook payload is an object")
        .insert(
            "config".to_string(),
            json!({
                "schemaOk": false,
                "error": {
                    "message": error,
                    "remediation": "Fix the gruff-rs configuration and rerun the hook."
                }
            }),
        );
    serde_json::to_string_pretty(&payload).expect("hook config error serialize")
}

/// Render the empty payload that accompanies a run which could not happen.
///
/// Every field the contract requires is present and empty, so a consumer parses one shape whether the run succeeded
/// or not and reads the reason from the fatal diagnostic rather than scraping stderr.
pub(crate) fn render_fatal(diagnostic_type: &str, message: &str) -> String {
    serde_json::to_string_pretty(&fatal_payload(diagnostic_type, message))
        .expect("hook fatal payload serialize")
}

fn fatal_payload(diagnostic_type: &str, message: &str) -> Value {
    json!({
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": analyzer_json(),
        "run": run_payload("full", "file", &[], 0, None),
        "findings": [],
        "diagnostics": [{
            "type": diagnostic_type,
            "severity": "fatal",
            "message": message,
            "file": Value::Null,
            "line": Value::Null
        }],
        "suppressed": { "count": 0 },
        "suppressions": [],
        "ignored": { "paths": [] },
        "config": { "schemaOk": true, "error": Value::Null }
    })
}

/// Build the audit block a consumer reads before trusting a verdict: what ran, over what, and against which baseline.
///
/// Without it a clean payload is ambiguous, because a run that analysed nothing and a run that found nothing look
/// identical on the wire.
fn run_payload(
    mode: &str,
    scope: &str,
    paths: &[String],
    analysed_files: usize,
    baseline_path: Option<&str>,
) -> Value {
    json!({
        "mode": mode,
        "scope": scope,
        "paths": paths,
        "analysedFiles": analysed_files,
        "baseline": {
            "applied": baseline_path.is_some(),
            "schemaVersion": baseline_path.map(|_| HOOK_BASELINE_SCHEMA_VERSION),
            "path": baseline_path
        }
    })
}

/// Render a hook payload with no run context, which is what a unit test that only inspects findings needs.
#[cfg(test)]
pub(crate) fn render_hook_report(
    mut report: AnalysisReport,
    changed_region_active: bool,
    new_only_active: bool,
) -> String {
    render_hook_report_for(
        &mut report,
        changed_region_active,
        new_only_active,
        &HookRunContext::default(),
    )
}

/// Everything one hook run was asked to do, so publishing it is one decision rather than eight arguments.
pub(crate) struct HookRun<'a> {
    pub(crate) args: &'a HookArgs,
    pub(crate) project_root: &'a Path,
    pub(crate) options: &'a AnalysisOptions,
    pub(crate) config: &'a Config,
    pub(crate) changed_region_active: bool,
    pub(crate) new_only_active: bool,
}

/// What one hook run did, so the payload's audit block reports it rather than assuming it.
#[derive(Default)]
pub(crate) struct HookRunContext {
    /// Which region selector chose the work: changed-ranges, diff, since, or full.
    pub(crate) mode: String,
    /// The operands as the caller gave them.
    pub(crate) paths: Vec<String>,
    /// Project-relative baseline that classified the run, or None when none applied.
    pub(crate) baseline_path: Option<String>,
}

pub(crate) fn render_hook_report_for(
    report: &mut AnalysisReport,
    changed_region_active: bool,
    new_only_active: bool,
    context: &HookRunContext,
) -> String {
    apply_hook_changed_region_filter(report, changed_region_active, new_only_active);

    let registry = rules::builtin_registry();
    let ignored_paths =
        serde_json::to_value(&report.paths.ignored_path_details).unwrap_or_else(|_| json!([]));
    let suppressed_count = report.suppressed_count.unwrap_or(0);
    let diagnostics = hook_diagnostics(std::mem::take(&mut report.diagnostics));
    let suppressions = hook_suppressions(&report.suppressions);
    let analysed_files = report.paths.analysed_files;
    let mode = if context.mode.is_empty() {
        "full".to_string()
    } else {
        context.mode.clone()
    };
    let scope = if mode == "full" { "file" } else { "symbol" };
    let findings = hook_findings(std::mem::take(&mut report.findings), &registry);

    serde_json::to_string_pretty(&json!({
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": analyzer_json(),
        "run": run_payload(
            &mode,
            scope,
            &context.paths,
            analysed_files,
            context.baseline_path.as_deref(),
        ),
        "findings": findings,
        "diagnostics": diagnostics,
        "suppressed": { "count": suppressed_count },
        "suppressions": suppressions,
        "ignored": { "paths": ignored_paths },
        "config": { "schemaOk": true, "error": null }
    }))
    .expect("hook report serialize")
}

/// Project the run's sensitive-exclusion audit into the section 13a rows the hook publishes.
///
/// A surface that applies an exclusion must report its count on that same surface: a hook may decline to filter, but
/// it may never filter in silence, because a consumer who cannot see the exclusion reads a clean payload as a clean file.
fn hook_suppressions(suppressions: &[SuppressionSummary]) -> Vec<Value> {
    suppressions
        .iter()
        .map(|summary| {
            json!({
                "rule": summary.rule,
                // Section 13a gives each entry exactly one path; the native audit carries it in the family's list shape.
                "path": summary.paths.first().cloned().unwrap_or_default(),
                "symbol": summary.symbol,
                "reason": summary.reason,
                "suppressed": summary.suppressed
            })
        })
        .collect()
}

fn hook_diagnostics(diagnostics: Vec<RunDiagnostic>) -> Vec<Value> {
    diagnostics
        .into_iter()
        .map(|diagnostic| {
            let mut value = json!({
                "type": diagnostic.diagnostic_type,
                // v1 left a consumer to infer severity from the type, so a budget note and a run that could not
                // happen looked alike.
                "severity": if diagnostic.invalidates_run == Some(false) { "warning" } else { "fatal" },
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
    let remediation = remediation_for(&finding, registry);
    json!({
        "ruleId": finding.rule_id,
        "pillar": pillar_label(finding.pillar),
        "severity": severity_label(finding.severity),
        "confidence": finding.confidence.as_str(),
        "scope": finding.scope.as_str(),
        "file": finding.file_path,
        "line": finding.line,
        // A consumer locating a finding cannot treat an absent span end as a single line by guessing.
        "endLine": finding.end_line.or(finding.line),
        "symbol": finding.symbol,
        "symbolOrdinal": symbol_ordinal_of(finding.baseline_subject.as_deref()),
        "message": finding.message,
        "remediation": remediation,
        "baselineStatus": finding.baseline_status,
        "metadata": finding.metadata,
        // The ratified family identity; a sensitive finding carries null, because the family never names one.
        "stableIdentity": finding.baseline_identity,
        "fingerprint": finding.fingerprint
    })
}

/// Read the declaration ordinal the ratified identity hashed, so a consumer can recompute the identity itself.
///
/// A finding naming no symbol reports 0, which is what the identity contract says a symbol-less subject carries.
fn symbol_ordinal_of(subject: Option<&str>) -> usize {
    subject
        .and_then(|value| value.rsplit_once('#'))
        .and_then(|(_, tail)| tail.parse::<usize>().ok())
        .unwrap_or(0)
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
