use super::*;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::tempdir;

mod calibration;
mod config_and_selectors;
mod m06_contract;
mod parser;
mod project_tests;
mod renderers;
mod rule_behaviours;
mod scenarios;

pub(crate) use calibration::*;

const PROCESS_COMMAND_NEW: &str = "std::process::Command::new";

/// Locks the process-wide mutex that analysis tests hold so they do not run analysis at the same time.
///
/// Returns the guard, which holds the lock until it is dropped; panics when an earlier holder panicked and poisoned the mutex.
fn analysis_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("analysis lock")
}

/// Analyses `paths` with the current directory as the project root, without reading a config file or baseline.
///
/// Returns the report from `analyse_project_paths`, which panics when config loading or the analysis fails.
fn analyse_test_paths(paths: Vec<PathBuf>) -> AnalysisReport {
    analyse_project_paths(Path::new("."), paths)
}

/// Analyses `paths` in the project at `project_root` with JSON output, no fail threshold, and no config file or baseline.
///
/// `paths` are the files or directories to analyse, and `project_root` is the directory the run treats as the project root.
/// Returns the analysis report; panics when config loading or the analysis returns an error.
fn analyse_project_paths(project_root: &Path, paths: Vec<PathBuf>) -> AnalysisReport {
    let options = AnalysisOptions {
        paths,
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
    let config = load_config(project_root, &options).expect("test config loads");
    run_analysis_in_project(project_root, &options, &config).expect("analysis succeeds")
}

/// Analyse a fixture copied into `src/` of a temporary project, so sensitive-data rules read it as production code.
///
/// `fixture` is the path of the file to copy; the copy keeps only its file name.
/// Returns the report for that one copied file.
/// Panics when `fixture` has no file name or when creating, copying into or analysing the temporary project fails.
fn analyse_fixture_as_production_code(fixture: &str) -> AnalysisReport {
    let dir = tempdir().expect("tempdir");
    let file_name = Path::new(fixture).file_name().expect("fixture file name");
    fs::create_dir_all(dir.path().join("src")).expect("src directory");
    fs::copy(fixture, dir.path().join("src").join(file_name)).expect("fixture copy");
    analyse_project_paths(dir.path(), vec![PathBuf::from("src").join(file_name)])
}

/// Loads config for `project_root` under `options` and analyses that project, passing failures back to the caller instead of panicking.
///
/// `project_root` is the project directory to analyse, and `options` holds the paths, config, baseline and diff choices for the run.
/// Returns the analysis report, or `Err` with the message from config loading or from the analysis when either fails.
fn run_project_analysis(
    project_root: &Path,
    options: AnalysisOptions,
) -> Result<AnalysisReport, String> {
    let config = load_config(project_root, &options)?;
    run_analysis_in_project(project_root, &options, &config)
}

/// Builds a high-confidence test finding with a placeholder message, symbol and remediation.
///
/// `rule_id` names the rule, `file_path` and `line` give its location, and `severity` and `pillar` classify it.
/// Returns the finding built by `test_finding_with_confidence` with `Confidence::High`.
fn test_finding(
    rule_id: &str,
    file_path: &str,
    line: usize,
    severity: Severity,
    pillar: Pillar,
) -> Finding {
    test_finding_with_confidence(
        rule_id,
        file_path,
        line,
        TestFindingClassification {
            severity,
            pillar,
            confidence: Confidence::High,
        },
    )
}

pub(crate) struct TestFindingClassification {
    pub(crate) severity: Severity,
    pub(crate) pillar: Pillar,
    pub(crate) confidence: Confidence,
}

/// Builds a test finding with the given severity, pillar and confidence and a placeholder message, symbol, remediation and metadata.
///
/// `rule_id` names the rule, `file_path` and `line` give its location, and `classification` sets severity, pillar and confidence.
/// Returns the new finding, whose message is the rule id followed by the word message and whose metadata is an empty JSON object.
fn test_finding_with_confidence(
    rule_id: &str,
    file_path: &str,
    line: usize,
    classification: TestFindingClassification,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!("{rule_id} message"),
        file_path: file_path.to_string(),
        line: Some(line),
        severity: classification.severity,
        pillar: classification.pillar,
        confidence: classification.confidence,
        symbol: Some("symbol".to_string()),
        remediation: Some("Remediate the issue.".to_string()),
        metadata: json!({}),
    })
}

/// Builds a fixed report with one `security.process-command` warning whose message contains angle brackets and an ampersand.
///
/// Returns that report, built by `sample_report_with` with no diagnostics.
fn sample_report() -> AnalysisReport {
    let findings = vec![Finding::new(FindingDescriptor {
        rule_id: "security.process-command".to_string(),
        message: "Use <escaped> command & args".to_string(),
        file_path: "src/lib.rs".to_string(),
        line: Some(7),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: Some("run".to_string()),
        remediation: Some("Validate command arguments.".to_string()),
        metadata: json!({}),
    })];
    sample_report_with(findings, Vec::new())
}

/// Builds a `gruff.analysis.v3` report from findings and diagnostics, with fixed tool and run details and a computed summary and score.
///
/// `findings` fill the report and feed its summary and score, and `diagnostics` are stored on it unchanged.
/// Returns the report, scored by `score_report` under the default config for 10 evaluated files and listing one analysed file.
fn sample_report_with(findings: Vec<Finding>, diagnostics: Vec<RunDiagnostic>) -> AnalysisReport {
    let summary = summarize(&findings);
    let score = score_report(&findings, &Config::default(), 10);
    AnalysisReport {
        schema_version: "gruff.analysis.v3".to_string(),
        tool: ToolInfo {
            name: "gruff-rs".to_string(),
            version: VERSION.to_string(),
        },
        run: RunInfo {
            project_root: ".".to_string(),
            format: "json".to_string(),
            fail_on: "none".to_string(),
            generated_at: "2026-05-13T00:00:00Z".to_string(),
        },
        summary,
        paths: PathSummary {
            analysed_files: 1,
            ignored_paths: Vec::new(),
            ignored_path_details: Vec::new(),
            missing_paths: Vec::new(),
        },
        diagnostics,
        suppressions: Vec::new(),
        findings,
        suppressed_count: None,
        score,
        baseline: None,
        per_rule_deltas: None,
        suppressed_findings: Vec::new(),
        all_findings_summary: None,
        machine_context: MachineReportContext::default(),
    }
}

/// Renders `report` in SARIF format and parses the text back into a JSON value for assertions.
///
/// Returns the parsed SARIF document; panics when the rendered output is not valid JSON.
fn sample_sarif(report: &AnalysisReport) -> Value {
    serde_json::from_str(&render_report(report, OutputFormat::Sarif)).expect("sarif report")
}

/// Collects the distinct rule ids of the findings in `report`.
///
/// Returns the ids as a sorted set borrowed from `report`, empty when the report has no findings.
fn rule_ids(report: &AnalysisReport) -> BTreeSet<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect()
}

/// Asserts that at least one finding in `report` carries the rule id `rule_id`.
///
/// Panics otherwise, listing the rule ids the report does contain.
fn assert_has_rule(report: &AnalysisReport, rule_id: &str) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == rule_id),
        "expected rule `{rule_id}` in findings: {:?}",
        rule_ids(report)
    );
}

/// Lists the type of every diagnostic in `report`, in report order.
///
/// Returns one entry per diagnostic, duplicates included, or an empty vector when the report has none.
fn diagnostic_types(report: &AnalysisReport) -> Vec<&str> {
    report
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.diagnostic_type.as_str())
        .collect()
}

/// Asserts that `report` has exactly one diagnostic and that its type is `partial-context-rule-suppressed`.
///
/// Panics otherwise, printing the report's diagnostics.
fn assert_only_partial_context_diagnostic(report: &AnalysisReport) {
    assert_eq!(
        diagnostic_types(report),
        vec!["partial-context-rule-suppressed"],
        "{:?}",
        report.diagnostics
    );
}

/// Asserts that no finding in `report` carries the rule id `rule_id`.
///
/// Panics otherwise, listing the rule ids the report contains.
fn assert_missing_rule(report: &AnalysisReport, rule_id: &str) {
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.rule_id == rule_id),
        "unexpected rule `{rule_id}` in findings: {:?}",
        rule_ids(report)
    );
}

/// Builds the starting analysis options that tests adjust with struct update syntax.
///
/// Returns options for the current directory with JSON output, config files read, no fail threshold, and no diff, history or baseline.
fn default_test_options() -> AnalysisOptions {
    AnalysisOptions {
        paths: vec![PathBuf::from(".")],
        config: None,
        no_config: false,
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
    }
}

/// Writes `body` to `.gruff-rs.yaml` in `dir`, adding a schema version unless `body` already mentions `schemaVersion`.
///
/// A `body` starting with a brace gets the version as its first JSON key; any other `body` gets a YAML version line prepended.
/// `dir` is the project directory and must already exist; any existing config there is replaced, and a failed write panics.
fn write_config(dir: &Path, body: &str) {
    let trimmed = body.trim_start();
    let body = if body.contains("schemaVersion") {
        body.to_string()
    } else if let Some(rest) = trimmed.strip_prefix('{') {
        format!("{{\"schemaVersion\": \"gruff-rs.config.v1\", {rest}")
    } else {
        format!("schemaVersion: gruff-rs.config.v1\n{body}")
    };
    fs::write(dir.join(".gruff-rs.yaml"), body).expect("yaml config write");
}

/// Writes a config to `dir` that enables the built-in rule `rule_id`, replacing any existing `.gruff-rs.yaml` there.
///
/// Panics when the config file cannot be written.
fn enable_builtin_rule(dir: &Path, rule_id: &str) {
    write_config(dir, &format!("rules:\n  {rule_id}:\n    enabled: true\n"));
}

/// Builds the project context for every source discovered under `project_root` with the default config.
///
/// Returns the context built with default coverage; panics when reading the discovered sources produces any diagnostic.
fn project_context_for_test(project_root: &Path) -> ProjectContext {
    let options = AnalysisOptions {
        paths: vec![PathBuf::from(".")],
        no_config: true,
        no_baseline: true,
        execution: ExecutionSelectors::default(),
        display: DisplaySelectors::default(),
        ..default_test_options()
    };
    let discovery = discover_sources(project_root, &options, &Config::default());
    let (parsed_sources, read_diagnostics) = read_and_parse_sources(&discovery.files);
    assert!(read_diagnostics.is_empty(), "{read_diagnostics:?}");
    build_project_context(project_root, &parsed_sources, ProjectCoverage::default())
}
