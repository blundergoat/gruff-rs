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

#[test]
pub(crate) fn summary_top_rules_severity_reflects_configured_override() {
    // PR #3 review: top-rules severity must come from the actual
    // findings, not the registry's default severity. ADR-011 only
    // permits `severity` paired with `threshold`, so the override
    // scenario applies to thresholded rules — pick `size.function-length`
    // because the fixture triggers it deterministically. The override
    // should propagate to topRules.severity in the summary digest.
    let dir = tempdir().expect("tempdir");
    let source = (0..30)
        .map(|i| format!("    let value_{i} = {i};\n"))
        .collect::<String>();
    fs::write(
        dir.path().join("long.rs"),
        format!("pub fn long_function() {{\n{source}}}\n"),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        "rules:\n  size.function-length:\n    threshold: 10\n    severity: advisory\n",
    );

    let options = AnalysisOptions {
        paths: vec![PathBuf::from("long.rs")],
        no_config: false,
        no_baseline: true,
        format: OutputFormat::Json,
        ..default_test_options()
    };
    let config = load_config(dir.path(), &options).expect("config loads");
    let report = run_analysis_in_project(dir.path(), &options, &config).expect("analysis succeeds");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "size.function-length"),
        "fixture must trigger size.function-length so the override is exercised",
    );
    let rendered = crate::summary::render(&report, 10, SummaryFormat::Json, 0);
    let value: Value = serde_json::from_str(&rendered).expect("summary JSON parses");
    let top_rules = value["topRules"].as_array().expect("topRules array");
    let entry = top_rules
        .iter()
        .find(|entry| entry["ruleId"] == "size.function-length")
        .expect("size.function-length present in topRules");
    let entry_severity = entry["severity"].as_str().unwrap_or("");
    // size.function-length defaults to `warning` in the registry; the
    // configured override is `advisory`. topRules.severity must follow
    // the finding-level severity (advisory), not the registry default.
    assert_eq!(
        entry_severity, "advisory",
        "topRules.severity must reflect the configured override, not registry default: {entry}",
    );
    assert!(
        report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "size.function-length")
            .all(|finding| matches!(finding.severity, Severity::Advisory)),
        "all findings for the overridden rule must carry the override severity",
    );
}

#[test]
pub(crate) fn analyse_text_ranks_rule_deltas_by_absolute_net_then_rule_id() {
    let mut report = sample_report_with(Vec::new(), Vec::new());
    report.per_rule_deltas = Some(vec![
        rule_delta_fixture("a.rule", 0, 3),
        rule_delta_fixture("b.rule", 0, 3),
        rule_delta_fixture("c.rule", 0, 1),
        rule_delta_fixture("d.rule", 5, 0),
        rule_delta_fixture("e.rule", 0, 7),
        rule_delta_fixture("f.rule", 0, 0),
        rule_delta_fixture("g.rule", 2, 0),
        rule_delta_fixture("h.rule", 2, 0),
        rule_delta_fixture("i.rule", 4, 0),
        rule_delta_fixture("j.rule", 6, 0),
        rule_delta_fixture("k.rule", 3, 0),
        rule_delta_fixture("l.rule", 1, 0),
    ]);

    let rendered = render_report(&report, OutputFormat::Text);
    let improved_line = rendered
        .lines()
        .find(|line| line.starts_with("Top 5 improved:"))
        .expect("improved block present");
    assert!(improved_line.contains("-7 e.rule"));
    assert!(improved_line.contains("-3 a.rule"));
    assert!(improved_line.contains("-3 b.rule"));
    assert!(improved_line.contains("-1 c.rule"));
    assert!(
        !improved_line.contains("f.rule"),
        "zero-net rules must be omitted: {improved_line}"
    );
    let a_idx = improved_line.find("a.rule").expect("a.rule present");
    let b_idx = improved_line.find("b.rule").expect("b.rule present");
    assert!(
        a_idx < b_idx,
        "tied net deltas must sort by rule_id ASC: {improved_line}"
    );

    let regressed_line = rendered
        .lines()
        .find(|line| line.starts_with("Top 5 regressed:"))
        .expect("regressed block present");
    assert!(regressed_line.contains("+6 j.rule"));
    assert!(regressed_line.contains("+5 d.rule"));
    assert!(regressed_line.contains("+4 i.rule"));
    assert!(regressed_line.contains("+3 k.rule"));
    assert!(regressed_line.contains("+2 g.rule"));
    assert!(
        !regressed_line.contains("h.rule") && !regressed_line.contains("l.rule"),
        "regressed block caps at five: {regressed_line}"
    );
}

#[test]
pub(crate) fn analyse_text_renders_rule_deltas_before_the_composite_score_line() {
    let mut report = sample_report_with(Vec::new(), Vec::new());
    report.per_rule_deltas = Some(vec![rule_delta_fixture("docs.missing-public-doc", 0, 4)]);

    let rendered = render_report(&report, OutputFormat::Text);
    let improved_offset = rendered
        .find("Top 5 improved:")
        .expect("improved block present");
    let score_offset = rendered.find("Score:").expect("score line present");
    assert!(improved_offset < score_offset);
}

#[test]
pub(crate) fn rule_delta_blocks_omit_on_full_tree_runs() {
    let report = sample_report_with(Vec::new(), Vec::new());

    let rendered = render_report(&report, OutputFormat::Text);
    assert!(!rendered.contains("Top 5 improved:"));
    assert!(!rendered.contains("Top 5 regressed:"));
    let rendered_markdown = render_report(&report, OutputFormat::Markdown);
    assert!(!rendered_markdown.contains("Top 5 improved:"));
    assert!(!rendered_markdown.contains("Top 5 regressed:"));
}

#[test]
pub(crate) fn analyse_markdown_renders_rule_deltas_before_score_line() {
    let mut report = sample_report_with(Vec::new(), Vec::new());
    report.per_rule_deltas = Some(vec![
        rule_delta_fixture("size.method-length", 4, 0),
        rule_delta_fixture("docs.missing-public-doc", 0, 7),
    ]);

    let rendered = render_report(&report, OutputFormat::Markdown);
    let improved_offset = rendered
        .find("Top 5 improved:")
        .expect("improved markdown block present");
    let regressed_offset = rendered
        .find("Top 5 regressed:")
        .expect("regressed markdown block present");
    let score_offset = rendered.find("Score: **").expect("score line present");
    assert!(improved_offset < score_offset);
    assert!(regressed_offset < score_offset);
    assert!(rendered.contains("-7 `docs.missing-public-doc`"));
    assert!(rendered.contains("+4 `size.method-length`"));
}

#[test]
pub(crate) fn analyse_json_omits_per_rule_deltas_unless_populated() {
    let report = sample_report_with(Vec::new(), Vec::new());
    let json_full_tree = render_report(&report, OutputFormat::Json);
    let parsed_full_tree: Value =
        serde_json::from_str(&json_full_tree).expect("full-tree json parses");
    assert!(parsed_full_tree.get("perRuleDeltas").is_none());

    let mut report = sample_report_with(Vec::new(), Vec::new());
    report.per_rule_deltas = Some(vec![rule_delta_fixture("a.rule", 1, 0)]);
    let json_with_deltas = render_report(&report, OutputFormat::Json);
    let parsed_with_deltas: Value =
        serde_json::from_str(&json_with_deltas).expect("baseline json parses");
    let deltas = parsed_with_deltas
        .get("perRuleDeltas")
        .and_then(Value::as_array)
        .expect("perRuleDeltas array present");
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0]["ruleId"], "a.rule");
    assert_eq!(deltas[0]["introduced"], 1);
    assert_eq!(deltas[0]["removed"], 0);
    assert_eq!(deltas[0]["net"], 1);
}

#[test]
pub(crate) fn summary_surfaces_per_rule_deltas_in_text_and_json() {
    let mut report = sample_report_with(Vec::new(), Vec::new());
    report.per_rule_deltas = Some(vec![
        rule_delta_fixture("size.method-length", 2, 0),
        rule_delta_fixture("docs.missing-public-doc", 0, 5),
    ]);

    let summary_text = crate::summary::render(&report, 10, SummaryFormat::Text, 0);
    assert!(summary_text.contains("Top 5 improved: -5 docs.missing-public-doc"));
    assert!(summary_text.contains("Top 5 regressed: +2 size.method-length"));

    let summary_json = crate::summary::render(&report, 10, SummaryFormat::Json, 0);
    let parsed: Value = serde_json::from_str(&summary_json).expect("summary json parses");
    let deltas = parsed
        .get("perRuleDeltas")
        .and_then(Value::as_array)
        .expect("perRuleDeltas array present in summary json");
    assert_eq!(deltas.len(), 2);
}

#[test]
pub(crate) fn summary_omits_per_rule_deltas_when_absent() {
    let report = sample_report_with(Vec::new(), Vec::new());

    let summary_text = crate::summary::render(&report, 10, SummaryFormat::Text, 0);
    assert!(!summary_text.contains("Top 5 improved:"));
    assert!(!summary_text.contains("Top 5 regressed:"));

    let summary_json = crate::summary::render(&report, 10, SummaryFormat::Json, 0);
    let parsed: Value = serde_json::from_str(&summary_json).expect("summary json parses");
    assert!(parsed.get("perRuleDeltas").is_none());
}

#[test]
pub(crate) fn summary_text_renders_rule_deltas_above_the_score_line() {
    // PR #3 review: summary text emitted the `Top 5` delta block AFTER
    // the `Score:` line, opposite of ADR-014 (the analyse text and
    // Markdown reporters both put deltas BEFORE the score line). Pin
    // the position so the comparison signal stays above the score.
    let mut report = sample_report_with(Vec::new(), Vec::new());
    report.per_rule_deltas = Some(vec![rule_delta_fixture("docs.missing-public-doc", 0, 4)]);

    let summary_text = crate::summary::render(&report, 10, SummaryFormat::Text, 0);
    let improved_offset = summary_text
        .find("Top 5 improved:")
        .expect("improved block present");
    let score_offset = summary_text.find("Score:").expect("score line present");
    assert!(
        improved_offset < score_offset,
        "summary delta block must render above the Score line, got:\n{summary_text}",
    );
}
