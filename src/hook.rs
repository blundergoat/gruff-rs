//! Run a scan for a coding-agent hook and return the `gruff.hook.v2` result.
//!
//! A hook caller can scan the full target, check changed code, or compare findings against a reviewed baseline.
//! The result reports findings and diagnostics with the exit status that tells the caller whether to continue.

use super::*;
use crate::changed_region::{git_args_with_paths, git_output, git_output_bytes_with_stdin};
use crate::cli::HookArgs;

pub(crate) const HOOK_CONTRACT_VERSION: &str = "gruff.hook.v2";

/// The one baseline schema this hook accepts; anything else is refused rather than read under the wrong rules.
pub(crate) const HOOK_BASELINE_SCHEMA_VERSION: &str = "gruff.baseline.v3";

/// Answer a capabilities request or scan the requested paths for a coding-agent hook.
///
/// `args` carries the parsed hook flags and paths; when `args.capabilities` is set, only the capabilities document is written.
/// `writer` receives every payload, including the failure payload of a run that could not happen.
///
/// Returns success after the capabilities document and exit code 2 when the project, its configuration or the analysis fails.
/// Otherwise it returns the code `emit_hook_report` decides from the published payload.
pub(crate) fn run_hook_command(args: HookArgs, writer: OutputWriter) -> ExitCode {
    // Hook integrations can check the supported contract before asking for a scan.
    if args.capabilities {
        writer.emit_unconditional(&render_capabilities());
        return ExitCode::SUCCESS;
    }

    // A new-only gate needs an earlier scan or baseline. Without one, it cannot tell the agent what changed.
    if args.fail_on_new && args.baseline.is_none() && args.diff.is_none() {
        writer.emit_unconditional(&render_fatal(
            "baseline",
            "--fail-on-new requires --baseline or --diff",
        ));
        return ExitCode::from(2);
    }

    let changed_region_active = args.changed_ranges.is_some();
    let new_only_active = args.baseline.is_some() || args.diff.is_some();
    let options = options_from_hook(&args, true);
    let (project_root, options, config) =
        match resolve_project_root_and_config(options, args.deep_scan_budget.as_ref()) {
            Ok(triple) => triple,
            // For example, a retired rule in the project's config prevents the agent from getting a trustworthy scan.
            Err(error) => {
                writer.emit_unconditional(&render_config_error(&error));
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
        // A missing reviewed baseline or an invalid changed path still gives the hook a machine-readable error.
        Err(error) => {
            writer.emit_unconditional(&render_run_failure(&error));
            eprintln!("gruff-rs: {error}");
            ExitCode::from(2)
        }
    }
}

/// Publish the hook payload and gate only the findings the calling agent can see.
///
/// `report` is the finished scan; the new-only base may drop findings from it, and its findings and diagnostics move into the payload.
/// `run` names the flags, project root, options, configuration and active selectors, and `writer` receives whichever payload is published.
///
/// Returns 2 when the new-only base cannot be applied or a diagnostic fails the run, else the 0 or 1 from `hook_exit_code`.
fn emit_hook_report(
    report: &mut AnalysisReport,
    run: &HookRun<'_>,
    writer: &OutputWriter,
) -> ExitCode {
    let args = run.args;
    // A failed comparison, such as an unavailable Git ref, prevents a reliable new-only decision.
    if let Err(error) = apply_hook_new_only(
        report,
        args,
        run.project_root,
        run.options,
        run.config,
        run.changed_region_active,
    ) {
        writer.emit_unconditional(&render_fatal("baseline", &error));
        eprintln!("gruff-rs: {error}");
        return ExitCode::from(2);
    }

    let has_fatal_diagnostic = report.diagnostics.iter().any(RunDiagnostic::is_failure);
    let context = HookRunContext {
        mode: hook_run_mode(args),
        changed_scope: run.changed_region_active.then_some(args.changed_scope),
        paths: args
            .paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect(),
        baseline_path: run.options.baseline.as_ref().and_then(|path| {
            let path = absolutize(run.project_root, path).canonicalize().ok()?;
            crate::machine_contract::relative_machine_path(
                &path.to_string_lossy(),
                &run.project_root.to_string_lossy(),
            )
        }),
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
/// Use the same diagnostic type as `analyse` so a hook caller knows whether to fix config, a baseline, or the changed-code selection.
///
/// `error` carries the category assigned by the failed operation.
/// Returns the pretty-printed hook JSON carrying one fatal `baseline`, changed-region or `config` diagnostic.
pub(crate) fn render_run_failure(error: &RunFailure) -> String {
    match error {
        RunFailure::Config(message) => render_config_error(message),
        _ => render_fatal(error.diagnostic_type(), error.message()),
    }
}

/// Name which region selector chose the work, so a consumer can tell a targeted run from a whole-tree one.
///
/// `args` holds the hook's region selectors.
/// Returns `changed-ranges` when `args.changed_ranges` is set, otherwise `diff` when `args.diff` is set, otherwise `full`.
fn hook_run_mode(args: &HookArgs) -> String {
    // Explicit ranges are the narrowest selector and win when both are given.
    if args.changed_ranges.is_some() {
        return "changed-ranges".to_string();
    }
    // When a hook names a Git comparison without explicit ranges, report that mode in the audit.
    if args.diff.is_some() {
        return "diff".to_string();
    }
    "full".to_string()
}

/// Decide whether visible hook output should block the agent from continuing.
///
/// `payload` is the published hook JSON, and `args` supplies `fail_on_diagnostics`, `fail_on_new` and the severity and confidence floors.
/// Returns 1 when the requested diagnostic, unreviewed-finding, or severity and confidence gate matches.
/// It returns 0 otherwise, including when `payload` is not valid JSON or has no findings array.
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

    // With no finding rows, only the diagnostic gate above can stop this request.
    let Some(rows) = parsed["findings"].as_array() else {
        return 0;
    };

    // Any visible finding can block the request under one of the gates the caller turned on.
    for row in rows {
        // The baseline dimension is independent of both floors: an unreviewed finding blocks whatever its severity.
        if args.fail_on_new
            && matches!(
                row["baselineStatus"].as_str(),
                Some("new" | "collision" | "notEligible")
            )
        {
            return 1;
        }
        // A hook can also block by severity and confidence, regardless of whether it asked for a comparison.
        if is_hook_gate_reached(row, args) {
            return 1;
        }
    }

    0
}

/// Report whether one published finding clears both independent floors the caller set.
///
/// `row` is one finding object from the payload, and `args` supplies the `fail_on` severity floor and the `min_confidence` floor.
/// Returns true only when the row's severity and confidence both reach their floors, and always false when `fail_on` is `none`.
/// A row without a severity ranks as advisory and one without a confidence ranks highest.
fn is_hook_gate_reached(row: &Value, args: &HookArgs) -> bool {
    // A `none` threshold names no floor at all, so no severity reaches it and only --fail-on-new can block.
    let Some(severity_floor) = fail_threshold_rank(args.fail_on) else {
        return false;
    };
    let severity = severity_rank_of(row["severity"].as_str().unwrap_or(""));
    let confidence = confidence_rank_of(row["confidence"].as_str().unwrap_or(""));

    severity >= severity_floor && confidence >= confidence_rank_of(args.min_confidence.as_str())
}

/// Map the caller's failure threshold onto the rank scale `severity_rank_of` gives a published severity.
///
/// `threshold` is the hook's severity floor.
/// Returns 0 for advisory, 1 for warning and 2 for error, or None for `FailThreshold::None`, which no severity can reach.
fn fail_threshold_rank(threshold: FailThreshold) -> Option<usize> {
    match threshold {
        FailThreshold::None => None,
        FailThreshold::Advisory => Some(0),
        FailThreshold::Warning => Some(1),
        FailThreshold::Error => Some(2),
    }
}

/// Rank a published severity label so it can be compared with the floor from `fail_threshold_rank`.
///
/// `label` is a finding's `severity` string from the payload.
/// Returns 2 for `error`, 1 for `warning` and 0 for anything else, so an advisory, missing or unknown label ranks lowest.
fn severity_rank_of(label: &str) -> usize {
    match label {
        "warning" => 1,
        "error" => 2,
        _ => 0,
    }
}

/// Rank one confidence label; anything unrecognised ranks highest, so an unrated finding cannot slip under a gate.
///
/// `label` is a finding's `confidence` string or the caller's minimum confidence.
/// Returns 0 for `low`, 1 for `medium` and 2 for anything else, including `high`, an empty string and unknown labels.
fn confidence_rank_of(label: &str) -> usize {
    match label {
        "low" => 0,
        "medium" => 1,
        _ => 2,
    }
}

/// Build the analysis options for a hook scan, which never fails on the analyser's own threshold because the hook gates the payload.
///
/// `args` supplies the paths, configuration choice, baseline and changed ranges.
/// `include_changed_ranges` decides whether `args.changed_ranges` becomes an explicit-ranges diff selection with `args.changed_scope`.
/// Returns JSON-format options with no failure threshold and default selectors, with the baseline disabled when `args` names none.
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

/// Apply the hook's new-only base: drop findings already in the `args.diff` base tree, then hand off to `apply_hook_changed_region_new_only`.
///
/// `report` is the scan being published and is changed in place; `args` supplies the `diff` base and the `baseline` choice.
/// `project_root`, `options` and `config` drive the base-tree export and any whole-scope rescan.
/// `changed_region_active` says a changed-region selector narrowed the scan.
///
/// Returns Err with the message when the base tree cannot be exported or analysed or the rescan fails.
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

/// Swap a narrowed run's file- and project-scope findings for those of an unnarrowed rescan when a baseline or diff base also applies.
///
/// `report` is changed in place and keeps only its line- and symbol-scope findings; `args` supplies the `baseline` and `diff` choices.
/// `project_root`, `options` and `config` drive the rescan, and `changed_region_active` must be true for anything to happen.
/// `diff_base_identities` are base counts already computed and subtracted from the rescan; when None under `args.diff`, they are recomputed.
///
/// Returns Err with the message when the rescan or the base-tree scan fails, and Ok without touching `report` when no rescan is needed.
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
    let mut full_report = run_analysis_in_project(project_root, &full_options, config)
        .map_err(|error| error.to_string())?;
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

/// Remove reviewed occurrences from a hook comparison while retaining any newly added duplicates.
/// For example, two occurrences of one rule in the current file still report once when the Git base had just one.
///
/// `report` is changed in place: for each stable identity, its first findings up to the base count are removed and the rest kept in order.
/// `base_counts` maps each stable identity to how often the base held it; it is cloned, not consumed.
pub(crate) fn apply_stable_identity_new_only(
    report: &mut AnalysisReport,
    base_counts: &BTreeMap<String, usize>,
) {
    let mut remaining_base_counts = base_counts.clone();
    report.findings.retain_mut(|finding| {
        match remaining_base_counts.get_mut(hook_comparison_identity(finding)) {
            // An earlier occurrence can cover one current occurrence of the same finding.
            Some(count) if *count > 0 => {
                *count -= 1;
                false
            }
            // With no earlier occurrence available, mark the finding for callers using `--fail-on-new`.
            _ => {
                finding.baseline_status = Some("new".to_string());
                true
            }
        }
    });
}

/// Use the finding's published v2 identity where available.
/// Returns the private comparison key for `finding` when the schema withholds its identity.
fn hook_comparison_identity(finding: &Finding) -> &str {
    finding
        .baseline_identity
        .as_deref()
        .unwrap_or(&finding.stable_identity)
}

/// Scan the pre-edit revision so a Git-backed hook can distinguish earlier findings from newly added ones.
///
/// `project_root` is the repository the base tree is exported from, and `options` supplies the paths to export and scan.
/// `config` is the configuration the base scan runs under.
/// `mode` is the `--diff` value; `working-tree`, `staged` and `unstaged` read `HEAD`, and any other value is used as the git ref.
///
/// Returns the count of each stable identity in the base scan, or Err when the temp tree, git export or base analysis fails.
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
    let base_report = run_analysis_in_project(base_tree.path(), &base_options, config)
        .map_err(|error| error.to_string())?;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    // Preserve duplicate counts so an added repeat can still appear in the caller's result.
    for finding in base_report.findings {
        *counts
            .entry(hook_comparison_identity(&finding).to_string())
            .or_default() += 1;
    }
    Ok(counts)
}

/// Pick the git ref whose tree holds the pre-change state for a `--diff` mode.
///
/// `mode` is the `--diff` value.
/// Returns `HEAD` for `working-tree`, `staged` and `unstaged`, and `mode` itself for any other value, which is treated as a ref.
fn hook_diff_base_ref(mode: &str) -> &str {
    match mode {
        "working-tree" | "staged" | "unstaged" => "HEAD",
        base => base,
    }
}

/// Write the files of the `base_ref` tree into `output_root`, so the pre-change state can be scanned like a working tree.
///
/// `project_root` is the repository git runs in, `base_ref` is the commit-ish to read, and `paths` narrows the `git ls-tree` listing.
/// `output_root` is the directory the files are written beneath, at their tree-relative paths.
///
/// Returns Err when git fails, a listed path is unsafe or not a blob, the batch output is malformed, or a file cannot be written.
fn export_git_base_tree(
    project_root: &Path,
    base_ref: &str,
    paths: &[PathBuf],
    output_root: &Path,
) -> Result<(), String> {
    // Ask Git for NUL-separated paths so a file such as `café.rs` reaches the comparison by its real name.
    // Git's display quoting can otherwise turn it into a name the path validator rejects.
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

/// List the paths in the `base_ref` tree recursively, using git's NUL-separated output so non-ASCII names arrive unquoted.
///
/// `project_root` is the repository git runs in, `base_ref` is the tree's commit-ish, and `paths` narrows the listing.
/// Returns the listed paths in git's order with blank entries dropped, or Err when the git command fails.
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

/// Read the content of every listed base-tree path in one `git cat-file --batch -Z` call.
///
/// `project_root` is the repository git runs in, and each of `base_paths` is queried at `base_ref` as a NUL-terminated `ref:path` query.
/// Returns the raw batch output, one header and content per query in order, or Err when the git command fails.
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

/// Write one base-tree blob to its place under the export root, creating parent directories as needed.
///
/// `output_root` is the export directory, `safe` is the validated tree-relative path, and `content` is the blob's bytes.
/// Returns Err naming the directory or file when it cannot be created or written.
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

/// Read the base revision's source files from one Git batch response.
///
/// Verify each blob length and terminator before the hook compares against it.
/// An incomplete response stops the comparison before missing files could be treated as clean.
struct CatFileBatchParser<'a> {
    output: &'a [u8],
    cursor: usize,
}

impl<'a> CatFileBatchParser<'a> {
    /// Start a parser at the beginning of one `git cat-file --batch -Z` output.
    ///
    /// `output` is the raw batch output from `git_cat_file_batch`.
    /// Returns a parser whose cursor sits at the start of `output`.
    fn new(output: &'a [u8]) -> Self {
        Self { output, cursor: 0 }
    }

    /// Consume the next header and blob from the batch output, checking the object is a blob followed by its NUL terminator.
    ///
    /// `path` is the tree path this entry was queried for, used only in error messages.
    /// Returns the blob's bytes, or Err when the header is missing or malformed or the object is missing or not a blob.
    /// It also fails when the output ends before the blob's size or its NUL terminator.
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

    /// Consume the next NUL-terminated header from the batch output and move the cursor past its terminator.
    ///
    /// `path` is the tree path this entry was queried for, used only in error messages.
    /// Returns the header text, or Err when no NUL terminator remains or the header is not UTF-8.
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

    /// Confirm the batch output was consumed exactly, so a stray extra object cannot go unnoticed.
    ///
    /// Returns Ok when the cursor sits at the end of the output, or Err when trailing batch output remains.
    fn finish(&self) -> Result<(), String> {
        if self.cursor == self.output.len() {
            Ok(())
        } else {
            Err("git cat-file returned trailing batch output".to_string())
        }
    }
}

/// Split one `git cat-file --batch` header into its object id, object type and size.
///
/// `header` is the space-separated header text, and `path` is the tree path it was queried for, used only in error messages.
/// Returns the object id, type and byte size, or Err when a field is missing, the object is reported `missing`, or the size is not a number.
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

/// Turn a git tree path into a relative filesystem path that cannot escape the export directory.
///
/// `path` is a slash-separated path as `git ls-tree` listed it.
/// Returns the joined components, or Err when `path` is absolute or has an empty, `.`, `..` or backslash-containing component.
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

/// Hold an exported revision for a Git-backed comparison.
///
/// The hook scans this separate tree so an agent's working files can stay in place.
/// Cleanup runs when the comparison finishes or exits early.
struct TempBaseTree {
    path: PathBuf,
}

impl TempBaseTree {
    /// Create a directory in the system temp dir to hold one exported base tree, named by process id and a nanosecond timestamp.
    ///
    /// Returns a guard that deletes the directory on drop, or Err when the clock is before the Unix epoch or the directory cannot be created.
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

    /// Expose the base tree's location so the export and the base scan use the same directory.
    ///
    /// Returns the temp directory's path, which is deleted when this guard drops.
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempBaseTree {
    /// Delete the exported base tree and everything in it when the guard goes out of scope, ignoring any removal error.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Describe what this hook supports, so a consumer can check the contract version, features and flag spellings before calling it.
///
/// Returns the pretty-printed capabilities JSON: contract version, analyzer, supported features, flag names and a flag order of `any`.
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

/// Render the fatal payload for a configuration failure, with a `config` block that marks the schema invalid and repeats the error.
///
/// `error` is the configuration error message, used both as the diagnostic message and in the `config` block.
/// Returns the pretty-printed hook JSON with a `config` fatal diagnostic, no findings, and a fix-the-configuration remediation.
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
///
/// `diagnostic_type` names the failure kind, such as `baseline`, and `message` is the reason the single fatal diagnostic carries.
/// Returns the pretty-printed hook JSON built by `fatal_payload`.
pub(crate) fn render_fatal(diagnostic_type: &str, message: &str) -> String {
    serde_json::to_string_pretty(&fatal_payload(diagnostic_type, message))
        .expect("hook fatal payload serialize")
}

/// Build the payload object for a run that could not happen, shared by `render_fatal` and `render_config_error`.
///
/// `diagnostic_type` and `message` fill the single diagnostic, whose severity is `fatal` and which names no file or line.
/// Returns a JSON object with a `full` run over no paths, empty findings, suppressions and ignored paths, and a clean `config` block.
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
///
/// `mode` is the region selector, `scope` the granularity the run reports at, and `paths` the operands as the caller gave them.
/// `analysed_files` counts the files scanned, and `baseline_path` is the baseline that classified the run, or None when none applied.
/// Returns the `run` JSON object, whose `baseline` block is applied and names the v3 schema only when `baseline_path` is set.
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

/// Keep the caller's targets, config, and options with the hook scan.
///
/// The comparison flags determine which findings reach the payload.
/// The same request supplies the audit and the gate that tells the agent whether to continue.
pub(crate) struct HookRun<'a> {
    pub(crate) args: &'a HookArgs,
    pub(crate) project_root: &'a Path,
    pub(crate) options: &'a AnalysisOptions,
    pub(crate) config: &'a Config,
    pub(crate) changed_region_active: bool,
    pub(crate) new_only_active: bool,
}

/// Describe the scope and comparison the hook reports to its caller.
///
/// The audit includes the requested paths and the changed scope when applicable.
/// An absent baseline path means there is no project-relative baseline path to publish.
#[derive(Default)]
pub(crate) struct HookRunContext {
    /// Scan mode reported to the caller: `changed-ranges`, `diff`, or `full`.
    pub(crate) mode: String,
    /// Requested scope used when a changed region is active.
    pub(crate) changed_scope: Option<ChangedScope>,
    /// The operands as the caller gave them.
    pub(crate) paths: Vec<String>,
    /// Project-relative baseline that classified the run, or None when none applied.
    pub(crate) baseline_path: Option<String>,
}

/// Render the hook payload for a finished scan: sorted findings, diagnostics, suppressions, ignored paths and the run's audit block.
///
/// `report` is changed in place: the changed-region filter may drop findings, and its findings and diagnostics are moved into the payload.
/// `changed_region_active` and `new_only_active` steer that filter; `context` gives the audit block its mode, operands and baseline path.
///
/// Returns the JSON payload with `file` for a full run, `hunk` for explicit hunk scope, and `symbol` for other changed scans.
/// An empty `context.mode` is reported as `full`.
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
    // A caller without a selected comparison mode sees a full run in the audit.
    let mode = if context.mode.is_empty() {
        "full".to_string()
    } else {
        context.mode.clone()
    };
    let scope = match (mode.as_str(), context.changed_scope) {
        ("full", _) => "file",
        (_, Some(ChangedScope::Hunk)) => "hunk",
        _ => "symbol",
    };
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

/// Publish sensitive exclusions and built-in or inline suppression rows so the agent can explain why findings are absent.
///
/// `suppressions` is the run's exclusion audit; only each summary's first path is published, as an empty string when it has none.
/// Returns one row per eligible summary with the rule, path, symbol, reason, count, and source when present.
fn hook_suppressions(suppressions: &[SuppressionSummary]) -> Vec<Value> {
    suppressions
        .iter()
        .filter(|row| row.config_key == "sensitiveExclusions" || row.source.is_some())
        .map(|summary| {
            let mut row = json!({
                "rule": summary.rule,
                // Section 13a gives each entry exactly one path; the native audit carries it in the family's list shape.
                "path": summary.paths.first().cloned().unwrap_or_default(),
                "symbol": summary.symbol,
                "reason": summary.reason,
                "suppressed": summary.suppressed,
            });
            // A built-in or inline suppression names its source. A configured sensitive exclusion leaves the key absent.
            if let Some(source) = summary.source {
                row.as_object_mut()
                    .expect("suppression row is an object")
                    .insert("source".to_string(), Value::String(source.to_string()));
            }
            row
        })
        .collect()
}

/// Project the run's diagnostics into hook diagnostic rows, giving each an explicit severity.
///
/// `diagnostics` are the run's diagnostics, consumed in order.
/// Returns one row per diagnostic. The same classification that determines exit status selects `warning` or `fatal`.
/// A row carries `invalidatesRun` only when the diagnostic sets it.
fn hook_diagnostics(diagnostics: Vec<RunDiagnostic>) -> Vec<Value> {
    diagnostics
        .into_iter()
        .map(|diagnostic| {
            let mut value = json!({
                "type": diagnostic.diagnostic_type,
                // A budget note can accompany a valid scan. A fatal diagnostic means the scan cannot support a decision.
                "severity": if diagnostic.is_failure() { "fatal" } else { "warning" },
                "message": diagnostic.message,
                "file": diagnostic.file_path,
                "line": diagnostic.line,
            });
            // Include this flag only when the scan explicitly says whether the diagnostic invalidates it.
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

/// Drop file- and project-scope findings from a changed-region run that has no new-only base, counting them as suppressed.
///
/// `report` is changed in place: those findings are removed and their number is added to `report.suppressed_count`.
/// Nothing changes unless `changed_region_active` is true and `new_only_active` is false.
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

/// Order the findings deterministically and project each into a hook finding row.
///
/// `findings` are consumed and sorted by severity, errors first, then file, line with lineless last, rule id and stable identity.
/// `registry` supplies each rule's description for findings that carry no remediation of their own.
/// Returns the rows from `hook_finding` in that order.
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

/// Project one finding into the hook contract's finding row.
///
/// `finding` is consumed, and `registry` supplies the fallback remediation through `remediation_for`.
/// Returns the JSON row, with `endLine` falling back to `line` and `stableIdentity` taken from the finding's baseline identity.
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
///
/// `subject` is the finding's baseline subject, whose ordinal follows its last `#`.
/// Returns that number, or 0 when `subject` is None, has no `#`, or its tail is not a number.
fn symbol_ordinal_of(subject: Option<&str>) -> usize {
    subject
        .and_then(|value| value.rsplit_once('#'))
        .and_then(|(_, tail)| tail.parse::<usize>().ok())
        .unwrap_or(0)
}

/// Choose the remediation text a hook finding row carries, with fallbacks when the finding brings none.
///
/// `finding` supplies its own remediation and rule id, and `registry` supplies the rule's description.
/// Returns the finding's non-blank remediation, else a review prompt with the rule description, else a generic one naming the rule id.
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

/// Identify this analyser in every hook payload.
///
/// Returns the `analyzer` JSON object naming `gruff-rs` and its `VERSION`.
fn analyzer_json() -> Value {
    json!({ "name": "gruff-rs", "version": VERSION })
}

/// Spell a severity the way the hook contract publishes it.
///
/// `severity` is the finding severity to label.
/// Returns `advisory`, `warning` or `error`.
fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// Order severities for the hook's finding sort so the most severe findings come first.
///
/// `severity` is the finding severity being sorted.
/// Returns 0 for error, 1 for warning and 2 for advisory, the reverse of the gate's `severity_rank_of` scale.
fn severity_rank(severity: Severity) -> usize {
    match severity {
        Severity::Error => 0,
        Severity::Warning => 1,
        Severity::Advisory => 2,
    }
}
