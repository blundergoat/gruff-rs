//! Project native Rust analysis state into the shared v3 machine contracts.

use super::*;
use serde::Serializer;

const ANALYSIS_SCHEMA_VERSION: &str = "gruff.analysis.v3";
const SUMMARY_SCHEMA_VERSION: &str = "gruff.summary.v3";

#[derive(Debug, Clone, Default)]
pub(crate) struct MachineDiffContext {
    pub(crate) mode: String,
    pub(crate) changed_files: Vec<String>,
}

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
        config_path: if options.no_config {
            None
        } else {
            options
                .config
                .as_ref()
                .map(|path| path.display().to_string())
        },
        include_ignored: options.include_ignored,
        exit_code: 0,
        diff,
    }
}

pub(crate) fn render_analysis(report: &AnalysisReport) -> String {
    serde_json::to_string_pretty(&analysis_value(report)).expect("analysis v3 serializes")
}

pub(crate) fn render_summary(report: &AnalysisReport) -> String {
    serde_json::to_string_pretty(&summary_value(report)).expect("summary v3 serializes")
}

pub(crate) fn serialize_analysis<S>(
    report: &AnalysisReport,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    analysis_value(report).serialize(serializer)
}

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
            "analysedFiles": report.paths.analysed_files,
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

fn run_value(report: &AnalysisReport) -> Value {
    let context = &report.machine_context;
    let mut payload = json!({
        "failOn": report.run.fail_on,
        "format": report.run.format,
        "inputs": machine_paths(&context.inputs, &context.project_root),
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

fn summary_counts_value(report: &AnalysisReport, ignored_count: usize) -> Value {
    let mut payload = json!({
        "analysedFiles": report.paths.analysed_files,
        "diagnostics": report.diagnostics.len(),
        "discoveredFiles": report.paths.analysed_files,
        "exitCode": report.machine_context.exit_code,
        "findings": {
            "advisory": report.summary.advisory,
            "warning": report.summary.warning,
            "error": report.summary.error,
            "total": report.summary.total,
        },
        "findingsByPillar": findings_by_pillar(&report.findings),
        "ignoredPaths": ignored_count,
        "missingPaths": report.paths.missing_paths.len(),
        "parseErrors": report.diagnostics.iter()
            .filter(|diagnostic| diagnostic.diagnostic_type == "parse-error")
            .count(),
        "parsedFiles": report.paths.analysed_files,
        "skippedFiles": ignored_count,
    });
    if let Some(count) = report.suppressed_count {
        payload
            .as_object_mut()
            .expect("summary is an object")
            .insert("suppressedFindings".to_string(), json!(count));
    }
    payload
}

fn findings_by_pillar(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts
            .entry(pillar_label(finding.pillar).to_string())
            .or_insert(0) += 1;
    }
    counts
}

fn path_details(report: &AnalysisReport) -> (Vec<Value>, Vec<String>) {
    let root = &report.machine_context.project_root;
    let details: Vec<Value> = report
        .paths
        .ignored_path_details
        .iter()
        .map(|detail| path_detail_value(detail, root))
        .collect();
    let ignored_paths = machine_paths(&report.paths.ignored_paths, root);
    let detail_paths: Vec<String> = details
        .iter()
        .map(|detail| {
            detail["path"]
                .as_str()
                .expect("path detail has a path")
                .to_string()
        })
        .collect();
    assert_eq!(
        ignored_paths, detail_paths,
        "ignored paths and details must describe identical paths"
    );
    (details, ignored_paths)
}

fn path_detail_value(detail: &IgnoredPath, root: &str) -> Value {
    let mut payload = json!({
        "path": machine_path(&detail.path, root),
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

fn ignored_reason(detail: &IgnoredPath) -> &'static str {
    match detail.source {
        IgnoreSource::Config => "config-ignore",
        IgnoreSource::Gitignore => "gitignored",
        IgnoreSource::Default => default_ignored_reason(detail.pattern.as_deref())
            .expect("default ignored path has a canonical reason"),
    }
}

fn default_ignored_reason(pattern: Option<&str>) -> Option<&'static str> {
    match pattern {
        Some(".git" | ".hg" | ".svn") => Some("vcs"),
        Some("node_modules" | "vendor") => Some("dependency"),
        Some("build" | "coverage" | "dist" | "target") => Some("build-output"),
        Some(".fleet" | ".idea" | ".vscode") => Some("local-tooling"),
        _ => None,
    }
}

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
        "topOffenders": report.score.top_offenders.iter().map(|score| {
            top_offender_value(score, root)
        }).collect::<Vec<_>>(),
    })
}

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

pub(crate) fn top_offender_value(score: &FileScore, root: &str) -> Value {
    json!({
        "file": machine_path(&score.file_path, root),
        "findings": score.findings,
        "penalty": machine_number(score.penalty),
        "score": score.score.map(machine_number),
    })
}

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
    payload
}

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

fn baseline_value(baseline: &BaselineReport, report: &AnalysisReport) -> Value {
    // newFindings is the gated count a user must still act on: new, plus collisions and secrets nothing may hide.
    let mut payload = json!({
        "applied": !baseline.generated,
        "entries": baseline.entries,
        "generated": baseline.generated,
        "newFindings": baseline.new_count + baseline.collision_count + baseline.not_eligible_count,
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

fn insert_positive_usize(object: &mut Map<String, Value>, key: &str, value: Option<usize>) {
    if let Some(value) = value.filter(|value| *value > 0) {
        object.insert(key.to_string(), json!(value));
    }
}

fn machine_number(value: f64) -> f64 {
    if value == 0.0 {
        0.0
    } else {
        value
    }
}

fn insert_optional_path(object: &mut Map<String, Value>, key: &str, value: &str, root: &str) {
    if let Some(path) = relative_machine_path(value, root) {
        object.insert(key.to_string(), Value::String(path));
    }
}

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

fn machine_path(value: &str, root: &str) -> String {
    relative_machine_path(value, root).expect("machine path is project-relative")
}

fn relative_machine_path(value: &str, root: &str) -> Option<String> {
    if value.is_empty() || value.contains('\\') || is_windows_drive_path(value) {
        return None;
    }
    let root_path = Path::new(root);
    let candidate = Path::new(value);
    let relative = if candidate.is_absolute() {
        let canonical_root = root_path
            .canonicalize()
            .unwrap_or_else(|_| root_path.to_path_buf());
        let canonical_candidate = candidate
            .canonicalize()
            .unwrap_or_else(|_| candidate.to_path_buf());
        canonical_candidate
            .strip_prefix(canonical_root)
            .ok()?
            .to_path_buf()
    } else {
        candidate.to_path_buf()
    };
    normalize_relative_path(&relative)
}

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

fn is_windows_drive_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}
