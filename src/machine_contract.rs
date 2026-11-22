//! Build v3 JSON for automation reading `analyse`, `report`, or `summary`.
//!
//! This is where the shared field names, counts, and project-relative paths are decided.
//! A failed scan still needs a diagnostic and an exit code so downstream tools can tell it apart from a clean scan.

use super::*;
use serde::Serializer;

const ANALYSIS_SCHEMA_VERSION: &str = "gruff.analysis.v3";
const SUMMARY_SCHEMA_VERSION: &str = "gruff.summary.v3";

/// Record the changed-code input that narrowed an analysis.
///
/// The mode identifies the source of the changes, such as a patch file or explicit ranges.
/// Changed files let downstream tools see what the caller asked to compare.
#[derive(Debug, Clone, Default)]
pub(crate) struct MachineDiffContext {
    pub(crate) mode: String,
    pub(crate) changed_files: Vec<String>,
}

/// Keep the settings and outcome needed to build a machine report.
///
/// Input and config paths tell automation what the scan used, when they can be represented under the project root.
/// Exit status and optional diff metadata let callers interpret the result without reading terminal output.
#[derive(Debug, Clone)]
pub(crate) struct MachineReportContext {
    pub(crate) project_root: String,
    pub(crate) inputs: Vec<String>,
    pub(crate) config_path: Option<String>,
    pub(crate) include_ignored: bool,
    pub(crate) exit_code: usize,
    pub(crate) diff: Option<MachineDiffContext>,
}

impl Default for MachineReportContext {
    /// Build the neutral machine context for a report that has no run-specific root, inputs, or options.
    ///
    /// Returns a context whose project root and only input are both `.`, with no config path, ignored paths excluded, exit code 0, and no diff.
    fn default() -> Self {
        Self {
            project_root: ".".to_string(),
            inputs: vec![".".to_string()],
            config_path: None,
            include_ignored: false,
            exit_code: 0,
            diff: None,
        }
    }
}

/// Capture the run facts the v3 machine envelopes publish: the analysed root, the requested inputs, the config path, and the diff context.
///
/// `project_root` becomes the context root in display form, and `diff` is stored unchanged.
/// `options` supplies the inputs (`.` when no paths were given), the config path (none when `no_config` is set), and `include_ignored`.
/// Returns the context with its exit code set to 0.
pub(crate) fn report_context(
    project_root: &Path,
    options: &AnalysisOptions,
    diff: Option<MachineDiffContext>,
) -> MachineReportContext {
    MachineReportContext {
        project_root: project_root.display().to_string(),
        inputs: if options.paths.is_empty() {
            vec![".".to_string()]
        } else {
            options
                .paths
                .iter()
                .map(|path| path.display().to_string())
                .collect()
        },
        config_path: options
            .config
            .as_ref()
            .filter(|_| !options.no_config)
            .and_then(|path| {
                let caller = std::env::current_dir().ok()?;
                let absolute = absolutize(&caller, path);
                Some(
                    absolute
                        .canonicalize()
                        .unwrap_or(absolute)
                        .display()
                        .to_string(),
                )
            }),
        include_ignored: options.include_ignored,
        exit_code: 0,
        diff,
    }
}

/// Reject a required path when JSON cannot express it without publishing an outside path.
/// Returns success for a representable `report` or an error naming only the invalid path's last component.
pub(crate) fn validate_required_paths(report: &AnalysisReport) -> Result<(), String> {
    let root = &report.machine_context.project_root;
    let paths = report
        .findings
        .iter()
        .map(|finding| finding.file_path.as_str())
        .chain(
            report
                .score
                .top_offenders
                .iter()
                .map(|row| row.file_path.as_str()),
        )
        .chain(
            report
                .paths
                .ignored_path_details
                .iter()
                .map(|row| row.path.as_str()),
        )
        .chain(report.paths.missing_paths.iter().map(String::as_str))
        .chain(
            report
                .suppressions
                .iter()
                .flat_map(|row| row.paths.iter().map(String::as_str)),
        )
        .chain(
            report
                .machine_context
                .diff
                .iter()
                .flat_map(|diff| diff.changed_files.iter().map(String::as_str)),
        );
    // A machine caller gets a structured error instead of a partial document or a host-specific path.
    if let Some(path) = paths
        .into_iter()
        .find(|path| relative_machine_path(path, root).is_none())
    {
        let name = Path::new(path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        return Err(format!(
            "unable to express report path {name:?} relative to the project"
        ));
    }
    Ok(())
}

/// Render the analysis v3 envelope for a finished report as pretty-printed JSON text.
///
/// `report` is the analysis whose run, counts, score, findings, paths, and suppressions the envelope publishes.
/// Returns the pretty-printed `gruff.analysis.v3` document.
///
/// Panics under the same conditions as `analysis_value`.
pub(crate) fn render_analysis(report: &AnalysisReport) -> String {
    serde_json::to_string_pretty(&analysis_value(report)).expect("analysis v3 serializes")
}

/// Render the summary v3 envelope for a finished report as pretty-printed JSON text.
///
/// `report` is the analysis to summarise; its findings list is left out of the summary.
/// Returns the pretty-printed `gruff.summary.v3` document.
///
/// Panics under the same conditions as `analysis_value`.
pub(crate) fn render_summary(report: &AnalysisReport) -> String {
    serde_json::to_string_pretty(&summary_value(report)).expect("summary v3 serializes")
}

/// Write the analysis v3 envelope for a report through any serde serializer instead of rendering it to a string.
///
/// `report` is the analysis to publish and `serializer` is the serde serializer that receives the envelope.
/// Returns the serializer's output, or its error when serialization fails.
///
/// Panics under the same conditions as `analysis_value`.
pub(crate) fn serialize_analysis<S>(
    report: &AnalysisReport,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    analysis_value(report).serialize(serializer)
}

/// Build the `gruff.analysis.v3` envelope for a finished report as a JSON value.
///
/// `report` supplies every section; its baseline, diff context, and per-rule deltas are added only when present.
/// Returns the envelope object, making path fields project-relative except for score cluster paths, which are copied unchanged.
///
/// Panics when a finding, suppression, top-offender, missing, ignored, or changed-file path has no project-relative form.
/// It also panics when the ignored paths and their details disagree, or when a default ignore has a pattern with no canonical reason.
pub(crate) fn analysis_value(report: &AnalysisReport) -> Value {
    let (details, ignored_paths) = path_details(report);
    let mut payload = json!({
        "schemaVersion": ANALYSIS_SCHEMA_VERSION,
        "tool": report.tool,
        "run": run_value(report),
        "summary": summary_counts_value(report, details.len()),
        "score": score_value(report),
        "diagnostics": report.diagnostics.iter().map(|diagnostic| {
            diagnostic_value(diagnostic, &report.machine_context.project_root)
        }).collect::<Vec<_>>(),
        "findings": report.findings.iter().map(|finding| {
            finding_value(finding, &report.machine_context.project_root)
        }).collect::<Vec<_>>(),
        "paths": {
            "analysedFiles": analysed_file_count(report),
            "details": details,
            "ignoredPaths": ignored_paths,
            "missingPaths": machine_paths(
                &report.paths.missing_paths,
                &report.machine_context.project_root,
            ),
        },
        "suppressions": report.suppressions.iter().map(|suppression| {
            suppression_value(suppression, &report.machine_context.project_root)
        }).collect::<Vec<_>>(),
    });
    add_optional_sections(&mut payload, report);
    payload
}

/// Build the `gruff.summary.v3` envelope: the analysis envelope with its schema version replaced and its findings list removed.
///
/// `report` is the finished analysis to summarise.
/// Returns the summary envelope object, which keeps every other analysis section, including the finding counts.
///
/// Panics under the same conditions as `analysis_value`.
fn summary_value(report: &AnalysisReport) -> Value {
    let mut payload = analysis_value(report);
    let object = payload
        .as_object_mut()
        .expect("analysis v3 root is an object");
    object.insert(
        "schemaVersion".to_string(),
        Value::String(SUMMARY_SCHEMA_VERSION.to_string()),
    );
    object.remove("findings");
    payload
}

/// Build the `run` section of the analysis envelope from the run settings and the report's machine context.
///
/// `report` supplies the fail-on threshold, output format, inputs, config path, and whether ignored paths were included.
/// Returns an object whose project root is always `.` and whose inputs omit any input with no project-relative form.
/// It carries `config` only when the config path has a project-relative form, and `includeIgnored` only when that flag is set.
fn run_value(report: &AnalysisReport) -> Value {
    let context = &report.machine_context;
    let mut payload = json!({
        "failOn": report.run.fail_on,
        "format": report.run.format,
        "inputs": machine_inputs(&context.inputs, &context.project_root),
        "projectRoot": ".",
    });
    let object = payload.as_object_mut().expect("run is an object");
    if let Some(config_path) = context.config_path.as_deref() {
        insert_optional_path(object, "config", config_path, &context.project_root);
    }
    if context.include_ignored {
        object.insert("includeIgnored".to_string(), Value::Bool(true));
    }
    payload
}

/// Build the `summary` counts section of the analysis envelope.
///
/// `report` supplies the file, diagnostic, finding, pillar, missing-path, and parse-error counts and any suppressed-finding count.
/// `ignored_count` is the number of ignored paths. Read and parse failures reduce coverage counts.
///
/// Returns the summary object. `suppressedFindings` appears only when the report carries a suppressed count.
fn summary_counts_value(report: &AnalysisReport, ignored_count: usize) -> Value {
    let analysed = analysed_file_count(report);
    let parse_errors = report
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.diagnostic_type == "parse-error")
        .count();
    let mut payload = json!({
        "analysedFiles": analysed,
        "diagnostics": report.diagnostics.len(),
        "discoveredFiles": report.paths.analysed_files,
        "exitCode": report.machine_context.exit_code,
        "findings": {
            "advisory": report.summary.advisory,
            "warning": report.summary.warning,
            "error": report.summary.error,
            "total": report.summary.total,
        },
        "findingsByPillar": findings_by_pillar(&report.score.pillars),
        "ignoredPaths": ignored_count,
        "missingPaths": report.paths.missing_paths.len(),
        "parseErrors": parse_errors,
        "parsedFiles": analysed.saturating_sub(parse_errors),
        "skippedFiles": ignored_count + (report.paths.analysed_files - analysed),
    });
    if let Some(count) = report.suppressed_count {
        payload
            .as_object_mut()
            .expect("summary is an object")
            .insert("suppressedFindings".to_string(), json!(count));
    }
    payload
}

/// Return the number of discovered files for which `report` has no read failure or skip.
fn analysed_file_count(report: &AnalysisReport) -> usize {
    let unread = report
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            matches!(
                diagnostic.diagnostic_type.as_str(),
                "read-error" | "read-skip-non-utf8"
            )
        })
        .count();
    report.paths.analysed_files.saturating_sub(unread)
}

/// Tally findings by their primary pillar for the summary's `findingsByPillar` map.
///
/// `pillars` contains the counts computed before display filtering.
/// Returns a map from pillar label to count, sorted by label; a pillar without findings has no key, so no findings give an empty map.
fn findings_by_pillar(pillars: &[PillarScore]) -> BTreeMap<String, usize> {
    pillars
        .iter()
        .filter(|pillar| pillar.findings != 0)
        .map(|pillar| (pillar_label(pillar.pillar).to_string(), pillar.findings))
        .collect()
}

/// Build the ignored-path details and the deduplicated ignored-path list for the envelope's `paths` section.
///
/// `report` supplies the ignored paths, their details, and the machine-context project root they are made relative to.
/// Returns the detail rows and their paths in matching order after normalization and deduplication.
fn path_details(report: &AnalysisReport) -> (Vec<Value>, Vec<String>) {
    let root = &report.machine_context.project_root;
    let mut seen = BTreeSet::new();
    let mut details = Vec::new();
    let mut ignored_paths = Vec::new();
    // Build both lists together so a repeated target cannot inflate the ignored count or lose its explanation.
    for detail in &report.paths.ignored_path_details {
        let path = machine_path(&detail.path, root);
        // The first reason for this normalized path supplies the audit row.
        if seen.insert(path.clone()) {
            details.push(path_detail_value(detail, &path));
            ignored_paths.push(path);
        }
    }
    (details, ignored_paths)
}

/// Describe one ignored path for the envelope's `paths.details` list.
///
/// `detail` supplies the ignore source and any matching pattern. `path` is the normalized report path.
/// Returns an object with `path`, `reason`, and `source`, plus `pattern` only when the detail carries a non-empty one.
///
fn path_detail_value(detail: &IgnoredPath, path: &str) -> Value {
    let mut payload = json!({
        "path": path,
        "reason": ignored_reason(detail),
        "source": detail.source.as_str(),
    });
    if let Some(pattern) = detail
        .pattern
        .as_deref()
        .filter(|pattern| !pattern.is_empty())
    {
        payload
            .as_object_mut()
            .expect("path detail is an object")
            .insert("pattern".to_string(), Value::String(pattern.to_string()));
    }
    payload
}

/// Map an ignored path's source to the reason code the envelope publishes for it.
///
/// `detail` supplies the ignore source and, for a default ignore, the pattern that picks the reason.
/// Returns `config-ignore` for a config ignore, `gitignored` for a gitignore match, and the canonical default reason otherwise.
///
/// Panics when a default ignore's pattern has no canonical reason.
fn ignored_reason(detail: &IgnoredPath) -> &'static str {
    match detail.source {
        IgnoreSource::Config => "config-ignore",
        IgnoreSource::Gitignore => "gitignored",
        IgnoreSource::Default => default_ignored_reason(detail.pattern.as_deref())
            .expect("default ignored path has a canonical reason"),
    }
}

/// Classify a built-in ignore pattern into the reason category the envelope publishes.
///
/// `pattern` is the default ignore pattern that claimed the path, if any.
/// Returns `vcs`, `dependency`, `build-output`, `generated`, or `local-tooling` for a known pattern, and None for an unknown or missing one.
fn default_ignored_reason(pattern: Option<&str>) -> Option<&'static str> {
    match pattern {
        Some(".git" | ".hg" | ".svn") => Some("vcs"),
        Some(
            "node_modules" | "vendor" | "vendors" | "third_party" | "third-party"
            | "bower_components",
        ) => Some("dependency"),
        Some("build" | "coverage" | "dist" | "target") => Some("build-output"),
        Some(crate::discovery::MINIFIED_FILE_PATTERN) => Some("generated"),
        Some(".fleet" | ".idea" | ".vscode") => Some("local-tooling"),
        _ => None,
    }
}

/// Project one finding into its `gruff.analysis.v3` finding object.
///
/// `finding` is the finding to publish; `root` is the project root its file path is made relative to.
/// Returns the object, with a line of at least 1, empty remediation when none, and `endLine` and `column` only when positive.
/// `symbol` appears only when non-empty, and the metadata gains `locationPrecision`, set by whether the finding has a positive column.
///
/// Panics when the finding's file path has no project-relative form under `root`.
pub(crate) fn finding_value(finding: &Finding, root: &str) -> Value {
    let has_column = finding.column.is_some_and(|column| column > 0);
    let mut metadata = finding.metadata.as_object().cloned().unwrap_or_default();
    metadata.insert(
        "locationPrecision".to_string(),
        Value::String(if has_column {
            "scanner-pinpointed".to_string()
        } else {
            "line-only".to_string()
        }),
    );
    let mut payload = json!({
        "ruleId": finding.rule_id,
        "message": finding.message,
        "file": machine_path(&finding.file_path, root),
        "line": finding.line.unwrap_or(1).max(1),
        "severity": finding.severity,
        "pillar": finding.pillar,
        "secondaryPillars": finding.secondary_pillars,
        "tier": finding.tier,
        "confidence": finding.confidence,
        "remediation": finding.remediation.as_deref().unwrap_or(""),
        "fingerprint": finding.fingerprint,
        "stableIdentity": finding.stable_identity,
        "metadata": metadata,
        "extensions": {"rs": {"finding": {"scope": finding.scope.as_str()}}},
    });
    let object = payload.as_object_mut().expect("finding is an object");
    insert_positive_usize(object, "endLine", finding.end_line);
    insert_positive_usize(object, "column", finding.column);
    if let Some(symbol) = finding
        .symbol
        .as_deref()
        .filter(|symbol| !symbol.is_empty())
    {
        object.insert("symbol".to_string(), Value::String(symbol.to_string()));
    }
    payload
}

/// Project one run diagnostic into its analysis v3 object.
///
/// `diagnostic` supplies the type, message, file, line, and any explicit run-invalidation flag; `root` is the project root for its file path.
/// Returns the object, with `invalidatesRun` defaulting to whether the diagnostic is a failure.
/// `file` is left out when the path has no project-relative form, and `line` appears only when positive.
fn diagnostic_value(diagnostic: &RunDiagnostic, root: &str) -> Value {
    let invalidates_run = diagnostic
        .invalidates_run
        .unwrap_or_else(|| diagnostic.is_failure());
    let mut payload = json!({
        "type": diagnostic.diagnostic_type,
        "message": diagnostic.message,
        "invalidatesRun": invalidates_run,
    });
    let object = payload.as_object_mut().expect("diagnostic is an object");
    if let Some(path) = diagnostic.file_path.as_deref() {
        insert_optional_path(object, "file", path, root);
    }
    insert_positive_usize(object, "line", diagnostic.line);
    payload
}

/// Build the `score` section of the analysis envelope.
///
/// `report` supplies the score; clusters, rule attribution, evaluated files, and scored pillars are copied as they are.
/// Returns the score object, with top-offender files made relative to the machine-context project root.
/// Composite, pillar, and file scores and penalties equal to zero are written as positive zero.
///
/// Panics when a top offender's file has no project-relative form.
fn score_value(report: &AnalysisReport) -> Value {
    let root = &report.machine_context.project_root;
    json!({
        "composite": {
            "grade": report.score.grade,
            "score": report.score.composite.map(machine_number),
        },
        "clusters": report.score.clusters,
        "ruleAttribution": report.score.rule_attribution,
        "evaluatedFiles": report.score.evaluated_files,
        "scoredPillars": report.score.scored_pillars,
        "pillars": report.score.pillars.iter().map(pillar_score_value).collect::<Vec<_>>(),
        "topOffenders": report.score.top_offenders.iter().take(scoring::TOP_OFFENDER_LIMIT).map(|score| {
            top_offender_value(score, root)
        }).collect::<Vec<_>>(),
    })
}

/// Project one pillar's score into its analysis v3 object.
///
/// `score` supplies the pillar, whether it applies, its finding count, penalty, optional score, and grade.
/// Returns the object, with a zero penalty or score written as positive zero and a missing score as null.
fn pillar_score_value(score: &PillarScore) -> Value {
    json!({
        "pillar": score.pillar,
        "applicable": score.applicable,
        "findings": score.findings,
        "penalty": machine_number(score.penalty),
        "score": score.score.map(machine_number),
        "grade": score.grade,
    })
}

/// Project one file's score into a top-offender object for the analysis envelope.
///
/// `score` supplies the file, finding count, penalty, and optional score; `root` is the project root the file is made relative to.
/// Returns the object, with a zero penalty or score written as positive zero and a missing score as null.
///
/// Panics when the file path has no project-relative form under `root`.
pub(crate) fn top_offender_value(score: &FileScore, root: &str) -> Value {
    json!({
        "file": machine_path(&score.file_path, root),
        "findings": score.findings,
        "penalty": machine_number(score.penalty),
        "score": score.score.map(machine_number),
    })
}

/// Project one suppression's summary into its analysis v3 object.
///
/// `suppression` supplies the index, rule, paths, reason, suppressed count, and optional symbol and source.
/// `root` is the project root its paths are made relative to, with duplicates then dropped.
/// Returns the object; `symbol` appears only when non-empty, and `source` only when the suppression names one.
///
/// Panics when any of its paths has no project-relative form under `root`.
fn suppression_value(suppression: &SuppressionSummary, root: &str) -> Value {
    let mut payload = json!({
        "index": suppression.index,
        "rule": suppression.rule,
        "paths": machine_paths(&suppression.paths, root),
        "reason": suppression.reason,
        "suppressed": suppression.suppressed,
    });
    if let Some(symbol) = suppression
        .symbol
        .as_deref()
        .filter(|symbol| !symbol.is_empty())
    {
        payload
            .as_object_mut()
            .expect("suppression is an object")
            .insert("symbol".to_string(), Value::String(symbol.to_string()));
    }
    // Only a built-in row names its source; a configured row is recognised by carrying none.
    if let Some(source) = suppression.source {
        payload
            .as_object_mut()
            .expect("suppression is an object")
            .insert("source".to_string(), Value::String(source.to_string()));
    }
    payload
}

/// Add the sections an analysis envelope carries only when the run produced them: baseline, diff, and per-rule deltas.
///
/// `payload` is the envelope object, extended in place with `baseline`, `diff`, and `extensions` for each section present.
/// `report` supplies the optional baseline report, diff context, and per-rule deltas.
///
/// Panics when `payload` is not a JSON object, or when a changed-file path has no project-relative form.
fn add_optional_sections(payload: &mut Value, report: &AnalysisReport) {
    let object = payload
        .as_object_mut()
        .expect("analysis v3 root is an object");
    if let Some(baseline) = report.baseline.as_ref() {
        object.insert("baseline".to_string(), baseline_value(baseline, report));
    }
    if let Some(diff) = report.machine_context.diff.as_ref() {
        object.insert("diff".to_string(), diff_value(diff, report));
    }
    if let Some(deltas) = report.per_rule_deltas.as_ref() {
        object.insert(
            "extensions".to_string(),
            json!({"rs": {"topLevel": {"perRuleDeltas": deltas}}}),
        );
    }
}

/// Build the `baseline` section that reports how this run met its baseline.
///
/// `baseline` supplies the counts, source, entry count, and path; `report` supplies the project root the path is made relative to.
/// Returns the section; `applied` is true unless this run generated the baseline, and `path` is left out without a project-relative form.
/// `newFindings` sums the new, collision, and not-eligible counts.
fn baseline_value(baseline: &BaselineReport, report: &AnalysisReport) -> Value {
    // newFindings is the gated count a user must still act on: new, plus collisions and secrets nothing may hide.
    let mut payload = json!({
        "applied": !baseline.generated,
        "entries": baseline.entries,
        "generated": baseline.generated,
        "newFindings": if baseline.generated { baseline.new_count } else { report.summary.total },
        "resolvedFindings": baseline.absent_count,
        "source": baseline.source,
        "suppressedFindings": baseline.suppressed,
        "unchangedFindings": baseline.unchanged_count,
    });
    insert_optional_path(
        payload.as_object_mut().expect("baseline is an object"),
        "path",
        &baseline.path,
        &report.machine_context.project_root,
    );
    payload
}

/// Build the `diff` section of the analysis envelope for a diff-mode run.
///
/// `diff` supplies the mode and changed files; `report` supplies the project root and its suppressed count, published as `filteredFindings`.
/// Returns the section with `enabled` always true and the changed files made project-relative and deduplicated.
///
/// Panics when a changed file has no project-relative form.
fn diff_value(diff: &MachineDiffContext, report: &AnalysisReport) -> Value {
    let changed_files = machine_paths(&diff.changed_files, &report.machine_context.project_root);
    json!({
        "changedFileCount": changed_files.len(),
        "changedFiles": changed_files,
        "enabled": true,
        "filteredFindings": report.suppressed_count.unwrap_or(0),
        "mode": diff.mode,
    })
}

/// Set an optional positive number on a JSON object, leaving zero and absent values out.
///
/// `object` gains `key` set to `value` only when `value` is present and above zero; otherwise it is left unchanged.
fn insert_positive_usize(object: &mut Map<String, Value>, key: &str, value: Option<usize>) {
    if let Some(value) = value.filter(|value| *value > 0) {
        object.insert(key.to_string(), json!(value));
    }
}

/// Normalise a number before it is published, so negative zero is written as plain zero.
///
/// `value` is the score or penalty to publish.
/// Returns positive zero when `value` equals zero, and `value` unchanged otherwise.
fn machine_number(value: f64) -> f64 {
    if value == 0.0 {
        0.0
    } else {
        value
    }
}

/// Publish a path field only when the path has a project-relative form, so no host path reaches the envelope.
///
/// `object` gains `key` set to `value` made relative to `root`; it is left unchanged when `value` has no such form.
fn insert_optional_path(object: &mut Map<String, Value>, key: &str, value: &str, root: &str) {
    if let Some(path) = relative_machine_path(value, root) {
        object.insert(key.to_string(), Value::String(path));
    }
}

/// Make a list of paths project-relative for publication, dropping duplicates.
///
/// `values` are the paths to publish, in order; `root` is the project root they are made relative to.
/// Returns the relative paths in first-seen order with later duplicates removed, and an empty list for no input.
///
/// Panics when any path has no project-relative form under `root`.
fn machine_paths(values: &[String], root: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut paths = Vec::new();
    for value in values {
        let path = machine_path(value, root);
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }
    paths
}

/// Publish the inputs that have a project-relative form and leave out the rest.
///
/// Failure envelopes recover the attempted project root when possible. An input outside that root is omitted,
/// just as an external config path is omitted by `insert_optional_path`.
///
/// `values` are the run's inputs as given, and `root` is the project root they are made relative to.
/// Returns the relative inputs in first-seen order without duplicates, and an empty list when none has a project-relative form.
fn machine_inputs(values: &[String], root: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .filter_map(|value| relative_machine_path(value, root))
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

/// Make one path project-relative for a field the envelope must always carry.
///
/// `value` is the path to publish and `root` is the project root it is made relative to.
/// Returns the slash-separated relative path, or `.` for the root itself.
///
/// Panics when `value` has no project-relative form under `root`.
fn machine_path(value: &str, root: &str) -> String {
    relative_machine_path(value, root).expect("machine path is project-relative")
}

/// Convert a path into the slash-separated project-relative form the machine envelopes publish.
///
/// An absolute `value` must start with `root`. A relative path is already relative to that root. No filesystem lookup is needed.
/// Returns the normalized path, or `.` for the root itself.
///
/// Returns None for empty input, an absolute path outside `root`, a climb above the root, or an invalid relative component.
pub(crate) fn relative_machine_path(value: &str, root: &str) -> Option<String> {
    // An empty value means there is no path to publish. A real project-root path is shown as `.` instead.
    if value.is_empty() {
        return None;
    }
    let root_path = Path::new(root);
    let candidate = Path::new(value);
    // An absolute path is safe to publish only after removing the matching project root.
    let relative = if candidate.is_absolute() {
        candidate.strip_prefix(root_path).ok()?
    } else {
        candidate
    };
    normalize_relative_path(relative)
}

/// Resolve `.` and `..` segments in a relative path and join what remains with forward slashes.
///
/// `path` is the relative path to normalise, without touching the filesystem.
/// Returns the joined path, or `.` when nothing remains.
/// Returns None when a `..` climbs above the start, when the path has a root or prefix, or when a segment is not valid UTF-8.
fn normalize_relative_path(path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => parts.push(part.to_str()?.to_string()),
            std::path::Component::ParentDir => {
                parts.pop()?;
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return None,
        }
    }
    Some(if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    })
}
