use super::*;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::tempdir;

mod calibration;
mod config_and_selectors;
mod project_tests;
mod renderers;
mod rule_behaviours;
mod scenarios;

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
        no_baseline: true,
    };
    let config = load_config(project_root, &options).expect("test config loads");
    run_analysis_in_project(project_root, &options, &config).expect("analysis succeeds")
}

fn run_project_analysis(
    project_root: &Path,
    options: AnalysisOptions,
) -> Result<AnalysisReport, String> {
    let config = load_config(project_root, &options)?;
    run_analysis_in_project(project_root, &options, &config)
}

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

fn sample_report_with(findings: Vec<Finding>, diagnostics: Vec<RunDiagnostic>) -> AnalysisReport {
    let summary = summarize(&findings);
    let score = score_report(&findings, &Config::default());
    AnalysisReport {
        schema_version: "gruff.analysis.v2".to_string(),
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
