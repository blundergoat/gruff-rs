use super::*;
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

/// Build a synthetic project with enough Rust source to push findings past
/// the 50-finding hint threshold. Each `fn x{n}` triggers
/// `docs.missing-public-doc` and `dead-code.unused-private-item-candidate`.
fn project_with_many_findings(dir: &Path, function_count: usize) -> PathBuf {
    let mut body = String::new();
    for index in 1..=function_count {
        body.push_str(&format!("pub fn item_{index}() {{}}\n"));
    }
    let path = dir.join("src.rs");
    fs::write(&path, body).expect("write fixture");
    path
}

#[test]
pub(crate) fn analyse_text_shows_hint_above_threshold() {
    let dir = tempdir().expect("tempdir");
    let path = project_with_many_findings(dir.path(), 60);

    let options = AnalysisOptions {
        paths: vec![path],
        no_config: true,
        no_baseline: true,
        format: OutputFormat::Text,
        ..default_test_options()
    };
    let config = Config::default();
    let report = run_analysis_in_project(dir.path(), &options, &config).expect("analysis succeeds");
    assert!(
        report.findings.len() >= 50,
        "fixture must produce >= 50 findings to exercise the hint; got {}",
        report.findings.len()
    );

    let rendered = render_report(&report, OutputFormat::Text);
    assert!(
        rendered.contains("Hint:"),
        "text output above threshold must surface the volume hint:\n{rendered}",
    );
    assert!(
        rendered.contains("gruff-rs summary --top 20"),
        "hint must point at the summary subcommand as the triage path",
    );
}

#[test]
pub(crate) fn analyse_text_omits_hint_below_threshold() {
    let dir = tempdir().expect("tempdir");
    let path = project_with_many_findings(dir.path(), 10);

    let options = AnalysisOptions {
        paths: vec![path],
        no_config: true,
        no_baseline: true,
        format: OutputFormat::Text,
        ..default_test_options()
    };
    let config = Config::default();
    let report = run_analysis_in_project(dir.path(), &options, &config).expect("analysis succeeds");
    assert!(report.findings.len() < 50);

    let rendered = render_report(&report, OutputFormat::Text);
    assert!(
        !rendered.contains("Hint:"),
        "text output below threshold must NOT show the hint:\n{rendered}",
    );
}

#[test]
pub(crate) fn analyse_json_never_includes_hint() {
    let dir = tempdir().expect("tempdir");
    let path = project_with_many_findings(dir.path(), 60);

    let options = AnalysisOptions {
        paths: vec![path],
        no_config: true,
        no_baseline: true,
        format: OutputFormat::Json,
        ..default_test_options()
    };
    let config = Config::default();
    let report = run_analysis_in_project(dir.path(), &options, &config).expect("analysis succeeds");
    let rendered = render_report(&report, OutputFormat::Json);
    assert!(
        !rendered.contains("Hint:"),
        "JSON output must stay machine-readable; the hint is text-only",
    );
}

#[test]
pub(crate) fn summary_top_rules_carries_severity_confidence_description() {
    let dir = tempdir().expect("tempdir");
    let path = project_with_many_findings(dir.path(), 5);

    let options = AnalysisOptions {
        paths: vec![path],
        no_config: true,
        no_baseline: true,
        format: OutputFormat::Json,
        ..default_test_options()
    };
    let config = Config::default();
    let report = run_analysis_in_project(dir.path(), &options, &config).expect("analysis succeeds");
    let rendered = crate::summary::render(&report, 10, SummaryFormat::Json, 0);
    let value: Value = serde_json::from_str(&rendered).expect("summary JSON parses");

    let top_rules = value
        .get("topRules")
        .and_then(|v| v.as_array())
        .expect("topRules array present");
    assert!(!top_rules.is_empty());

    let entry = &top_rules[0];
    assert!(entry.get("ruleId").is_some());
    assert!(entry.get("count").is_some());
    assert!(
        entry.get("severity").is_some(),
        "topRules entry should expose severity for built-in rules",
    );
    assert!(
        entry.get("confidence").is_some(),
        "topRules entry should expose confidence for built-in rules",
    );
    assert!(
        entry.get("description").is_some(),
        "topRules entry should expose description for built-in rules",
    );
}
