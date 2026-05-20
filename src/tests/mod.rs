use super::*;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::tempdir;

mod baseline;
mod calibration;
mod calibration_extras;
mod config;
mod custom_rules;
mod diff;
mod exclusions;
mod m33_regressions;
mod m35_m37_m38_regressions;
mod project_model;
mod project_rules;
mod renderers;
mod rust_rules;
mod sarif;
mod selectors;
mod smoke;

pub(crate) use calibration::*;

const PROCESS_COMMAND_NEW: &str = "std::process::Command::new";

fn analysis_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("analysis lock")
}

fn analyse_test_paths(paths: Vec<PathBuf>) -> AnalysisReport {
    analyse_project_paths(Path::new("."), paths)
}

fn analyse_project_paths(project_root: &Path, paths: Vec<PathBuf>) -> AnalysisReport {
    run_analysis_in_project(
        project_root,
        &AnalysisOptions {
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
            no_baseline: true,
        },
    )
    .expect("analysis succeeds")
}

fn run_project_analysis(
    project_root: &Path,
    options: AnalysisOptions,
) -> Result<AnalysisReport, String> {
    run_analysis_in_project(project_root, &options)
}

fn test_finding(
    rule_id: &str,
    file_path: &str,
    line: usize,
    severity: Severity,
    pillar: Pillar,
) -> Finding {
    test_finding_with_confidence(rule_id, file_path, line, severity, pillar, Confidence::High)
}

fn test_finding_with_confidence(
    rule_id: &str,
    file_path: &str,
    line: usize,
    severity: Severity,
    pillar: Pillar,
    confidence: Confidence,
) -> Finding {
    Finding::new(
        rule_id,
        format!("{rule_id} message"),
        file_path,
        Some(line),
        severity,
        pillar,
        confidence,
        Some("symbol".to_string()),
        Some("Remediate the issue.".to_string()),
        json!({}),
    )
}

fn sample_report() -> AnalysisReport {
    let findings = vec![Finding::new(
        "security.process-command",
        "Use <escaped> command & args",
        "src/lib.rs",
        Some(7),
        Severity::Warning,
        Pillar::Security,
        Confidence::High,
        Some("run".to_string()),
        Some("Validate command arguments.".to_string()),
        json!({}),
    )];
    sample_report_with(findings, Vec::new())
}

fn sample_report_with(findings: Vec<Finding>, diagnostics: Vec<RunDiagnostic>) -> AnalysisReport {
    let summary = summarize(&findings);
    let score = score_report(&findings);
    AnalysisReport {
        schema_version: "gruff.analysis.v1".to_string(),
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
            missing_paths: Vec::new(),
        },
        diagnostics,
        suppressions: Vec::new(),
        findings,
        score,
        baseline: None,
        suppressed_findings: Vec::new(),
    }
}

fn sample_sarif(report: &AnalysisReport) -> Value {
    serde_json::from_str(&render_report(report, OutputFormat::Sarif)).expect("sarif report")
}

fn rule_ids(report: &AnalysisReport) -> BTreeSet<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect()
}

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

fn metric_metadata_number(report: &AnalysisReport, rule_id: &str, symbol: &str, key: &str) -> f64 {
    report
        .findings
        .iter()
        .find(|finding| finding.rule_id == rule_id && finding.symbol.as_deref() == Some(symbol))
        .and_then(|finding| finding.metadata.get(key))
        .and_then(Value::as_f64)
        .unwrap_or_else(|| panic!("missing `{key}` metadata for `{rule_id}` `{symbol}`"))
}

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
        no_baseline: true,
    }
}

fn write_config(dir: &Path, body: &str) {
    fs::write(dir.join(".gruff-rs.yaml"), body).expect("yaml config write");
}

fn project_context_for_test(project_root: &Path) -> ProjectContext {
    let options = AnalysisOptions {
        paths: vec![PathBuf::from(".")],
        no_config: true,
        no_baseline: true,
        ..default_test_options()
    };
    let discovery = discover_sources(project_root, &options, &Config::default());
    let (parsed_sources, read_diagnostics) = read_and_parse_sources(&discovery.files);
    assert!(read_diagnostics.is_empty(), "{read_diagnostics:?}");
    build_project_context(project_root, &parsed_sources)
}
