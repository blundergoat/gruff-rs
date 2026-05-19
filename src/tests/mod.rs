use super::*;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::tempdir;

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

#[test]
fn diff_patch_parser_maps_new_side_lines_for_renames_crlf_and_deletions() {
    let patch = concat!(
        "diff --git a/src/old.rs b/src/new.rs\r\n",
        "similarity index 80%\r\n",
        "rename from src/old.rs\r\n",
        "rename to src/new.rs\r\n",
        "--- a/src/old.rs\r\n",
        "+++ b/src/new.rs\r\n",
        "@@ -1,3 +10,4 @@\r\n",
        " context\r\n",
        "-old\r\n",
        "+new\r\n",
        " keep\r\n",
        "+added\r\n",
        "diff --git a/src/delete.rs b/src/delete.rs\r\n",
        "--- a/src/delete.rs\r\n",
        "+++ b/src/delete.rs\r\n",
        "@@ -4,2 +4,0 @@\r\n",
        "-old\r\n",
        "-old\r\n",
        "diff --git a/bin.dat b/bin.dat\r\n",
        "Binary files a/bin.dat and b/bin.dat differ\r\n",
    );

    let parsed = parse_unified_diff(patch);

    assert_eq!(
        parsed.lines_by_file.get("src/new.rs"),
        Some(&BTreeSet::from([10, 11, 12, 13]))
    );
    assert_eq!(
        parsed.lines_by_file.get("src/delete.rs"),
        Some(&BTreeSet::new())
    );
    assert!(!parsed.lines_by_file.contains_key("bin.dat"));
    assert!(parse_unified_diff("").lines_by_file.is_empty());
}

#[test]
fn diff_patch_filter_keeps_only_changed_lines_and_line_less_findings() {
    let mut line_less = test_finding(
        "architecture.public-api-surface",
        "src/lib.rs",
        1,
        Severity::Advisory,
        Pillar::Design,
    );
    line_less.line = None;
    let report = sample_report_with(
        vec![
            test_finding(
                "security.process-command",
                "src/lib.rs",
                11,
                Severity::Warning,
                Pillar::Security,
            ),
            test_finding(
                "waste.unwrap-expect",
                "src/lib.rs",
                12,
                Severity::Advisory,
                Pillar::Waste,
            ),
            test_finding(
                "docs.missing-public-doc",
                "src/other.rs",
                11,
                Severity::Advisory,
                Pillar::Documentation,
            ),
            line_less,
        ],
        Vec::new(),
    );
    let patch = parse_unified_diff(
        "\
diff --git a/src/lib.rs b/src/lib.rs\n\
--- a/src/lib.rs\n\
+++ b/src/lib.rs\n\
@@ -10,2 +11,1 @@\n\
+changed\n\
diff --git a/missing.rs b/missing.rs\n\
--- a/missing.rs\n\
+++ b/missing.rs\n\
@@ -1,1 +1,1 @@\n\
-old\n\
+new\n",
    );
    let analysed = BTreeSet::from(["src/lib.rs".to_string()]);

    let filtered = apply_diff_patch_filter(report, &patch, &analysed);
    eprintln!(
        "diff_patch kept rule ids: {:?}; suppressed count: {}",
        filtered
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>(),
        2
    );

    assert_eq!(filtered.findings.len(), 2);
    assert!(filtered
        .findings
        .iter()
        .any(|finding| finding.rule_id == "security.process-command"));
    assert!(filtered
        .findings
        .iter()
        .any(|finding| finding.rule_id == "architecture.public-api-surface"));
    assert_eq!(filtered.summary.total, 2);
    assert_eq!(filtered.diagnostics.len(), 1);
    assert_eq!(filtered.diagnostics[0].diagnostic_type, "patch-filter");
    assert!(!filtered.diagnostics[0].is_failure());
    assert!(filtered.diagnostics[0]
        .message
        .contains("Patch filter kept 2 of 4 findings; suppressed 2"));
    assert!(filtered.diagnostics[0]
        .message
        .contains("Patch files not analysed: missing.rs"));
}

#[test]
fn diff_patch_analysis_filters_after_baseline_without_failing_on_summary_diagnostic() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let patch_path = dir.path().join("fixture.patch");
    fs::write(
        &patch_path,
        [
            "\
diff --git a/fixtures/sample.rs b/fixtures/sample.rs\n\
--- a/fixtures/sample.rs\n\
+++ b/fixtures/sample.rs\n\
@@ -11,1 +11,1 @@\n\
+        ",
            PROCESS_COMMAND_NEW,
            "(command).arg(url).spawn().unwrap();\n",
        ]
        .concat(),
    )
    .expect("patch write");
    let options = AnalysisOptions {
        paths: vec![PathBuf::from("fixtures/sample.rs")],
        no_config: true,
        diff: Some(DiffSelection::Patch(patch_path)),
        no_baseline: true,
        ..default_test_options()
    };

    let report = run_project_analysis(Path::new("."), options).expect("analysis succeeds");

    assert!(report.findings.len() < 12);
    assert!(!report.findings.is_empty());
    assert!(report
        .findings
        .iter()
        .all(|finding| finding.file_path == "fixtures/sample.rs" && finding.line == Some(11)));
    assert_eq!(
        report
            .diagnostics
            .last()
            .map(|diagnostic| diagnostic.diagnostic_type.as_str()),
        Some("patch-filter")
    );
    assert_eq!(
        RunOutcome::classify(&report, FailThreshold::None),
        RunOutcome::Success
    );
}

#[test]
fn diff_patch_diagnostics_are_sarif_notifications_without_failed_execution() {
    let report = sample_report_with(
            Vec::new(),
            vec![RunDiagnostic {
                diagnostic_type: "patch-filter".to_string(),
                message: "Patch filter kept 0 of 0 findings; suppressed 0 outside changed new-side lines. All patch files were analysed.".to_string(),
                file_path: None,
                line: None,
            }],
        );

    let sarif = sample_sarif(&report);

    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
    let notification = &sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0];
    assert_eq!(notification["descriptor"]["id"], "patch-filter");
    assert_eq!(notification["level"], "note");
}

#[test]
fn diff_requires_explicit_unsafe_git_flag() {
    let without_flag = Cli::try_parse_from(["gruff-rs", "analyse", "--diff", "working-tree"]);
    assert!(without_flag.is_err());

    let with_flag = Cli::try_parse_from([
        "gruff-rs",
        "analyse",
        "--diff",
        "working-tree",
        "--diff-git-unsafe",
    ]);
    assert!(with_flag.is_ok());
}

#[test]
fn exclusion_filter_counts_rule_path_message_and_unmatched_entries() {
    let registry = rules::builtin_registry();
    let findings = vec![
        test_finding(
            "docs.missing-public-doc",
            "src/lib.rs",
            1,
            Severity::Advisory,
            Pillar::Documentation,
        ),
        test_finding(
            "security.process-command",
            "tests/fixture.rs",
            4,
            Severity::Warning,
            Pillar::Security,
        ),
        test_finding(
            "waste.unwrap-expect",
            "src/lib.rs",
            5,
            Severity::Advisory,
            Pillar::Waste,
        ),
        Finding::new(
            "size.parameter-count",
            "too many params",
            "src/lib.rs",
            Some(9),
            Severity::Warning,
            Pillar::Size,
            Confidence::High,
            Some("process".to_string()),
            None,
            json!({}),
        ),
        test_finding(
            "security.process-command",
            "src/lib.rs",
            6,
            Severity::Warning,
            Pillar::Security,
        ),
    ];
    let exclusions = vec![
        ExclusionRule {
            selector: "docs.missing-public-doc".to_string(),
            rule_ids: expand_rule_selector("docs.missing-public-doc", &registry, "test.rule")
                .expect("exact selector"),
            paths: Vec::new(),
            message_contains: None,
            reason: "legacy docs debt".to_string(),
        },
        ExclusionRule {
            selector: "security.process-command".to_string(),
            rule_ids: expand_rule_selector("security.process-command", &registry, "test.rule")
                .expect("exact selector"),
            paths: vec!["tests/**".to_string()],
            message_contains: None,
            reason: "test fixture command".to_string(),
        },
        ExclusionRule {
            selector: "waste.unwrap-expect".to_string(),
            rule_ids: expand_rule_selector("waste.unwrap-expect", &registry, "test.rule")
                .expect("exact selector"),
            paths: Vec::new(),
            message_contains: Some("unwrap".to_string()),
            reason: "accepted unwrap".to_string(),
        },
        ExclusionRule {
            selector: "size.parameter-count".to_string(),
            rule_ids: expand_rule_selector("size.parameter-count", &registry, "test.rule")
                .expect("exact selector"),
            paths: vec!["src/**".to_string()],
            message_contains: Some("params".to_string()),
            reason: "generated adapter".to_string(),
        },
        ExclusionRule {
            selector: "sensitive-data.aws-access-key".to_string(),
            rule_ids: expand_rule_selector("sensitive-data.aws-access-key", &registry, "test.rule")
                .expect("exact selector"),
            paths: Vec::new(),
            message_contains: None,
            reason: "unused exclusion stays auditable".to_string(),
        },
    ];

    let (kept, summaries, suppressed) = apply_report_exclusions(findings, &exclusions);
    eprintln!(
        "exclusion kept rule ids: {:?}; suppression counts: {:?}",
        kept.iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>(),
        summaries
            .iter()
            .map(|summary| summary.suppressed)
            .collect::<Vec<_>>()
    );

    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].file_path, "src/lib.rs");
    assert_eq!(kept[0].rule_id, "security.process-command");
    assert_eq!(
        summaries
            .iter()
            .map(|summary| summary.suppressed)
            .collect::<Vec<_>>(),
        vec![1, 1, 1, 1, 0]
    );
    assert_eq!(suppressed.len(), 4);
}

#[test]
fn exclusion_config_rejects_missing_reason_unknown_rule_and_bad_shapes() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(
        dir.path(),
        r#"
exclude:
  - rule: security.process-command
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("missing reason rejected");
    assert!(error.contains("missing required config key `exclude[0].reason`"));

    write_config(
        dir.path(),
        r#"
exclude:
  - rule: unknown.rule
    reason: "unknown rule"
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("unknown rule rejected");
    assert!(error.contains("unknown selector `unknown.rule`"), "{error}");
    assert!(error.contains("exclude[0].rule"), "{error}");

    write_config(
        dir.path(),
        r#"
exclude:
  - rule: security.process-command
    paths: "tests/**"
    reason: "bad paths"
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("bad paths rejected");
    assert!(error.contains("config key `exclude[0].paths` must be an array"));
}

#[test]
fn exclusion_config_reuses_rule_selector_parsing() {
    let dir = tempdir().expect("tempdir");
    write_config(
        dir.path(),
        r#"
exclude:
  - rule: security.*
    reason: "all security findings are reviewed separately"
"#,
    );

    let config =
        load_config(dir.path(), &default_test_options()).expect("exclusion selector config loads");

    assert_eq!(config.exclusions.len(), 1);
    assert!(config.exclusions[0]
        .rule_ids
        .contains("security.process-command"));
    assert!(config.exclusions[0]
        .rule_ids
        .contains("security.unsafe-block"));
}

#[test]
fn report_level_exclusions_hide_findings_without_skipping_discovery() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::create_dir_all(dir.path().join("tests")).expect("tests dir");
    fs::write(
        dir.path().join("src/lib.rs"),
        concat!(
            "pub fn run_src() {\n",
            "    std::process::Command::new(\"sh\").spawn().unwrap();\n",
            "}\n"
        ),
    )
    .expect("src write");
    fs::write(
        dir.path().join("tests/process.rs"),
        concat!(
            "pub fn run_test() {\n",
            "    std::process::Command::new(\"sh\").spawn().unwrap();\n",
            "}\n"
        ),
    )
    .expect("tests write");
    write_config(
        dir.path(),
        r#"
exclude:
  - rule: security.process-command
    paths: ["tests/**"]
    reason: "test-only synthetic command"
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![
                PathBuf::from("src/lib.rs"),
                PathBuf::from("tests/process.rs"),
            ],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert_eq!(report.paths.analysed_files, 2);
    assert!(report.findings.iter().any(|finding| {
        finding.rule_id == "security.process-command" && finding.file_path == "src/lib.rs"
    }));
    assert!(!report.findings.iter().any(|finding| {
        finding.rule_id == "security.process-command" && finding.file_path == "tests/process.rs"
    }));
    assert_eq!(total_suppressed_findings(&report.suppressions), 1);
    assert_eq!(report.suppressions[0].reason, "test-only synthetic command");

    let json_output = render_report(&report, OutputFormat::Json);
    let json: Value = serde_json::from_str(&json_output).expect("json report");
    assert_eq!(json["suppressions"][0]["suppressed"], 1);
    assert_eq!(
        json["suppressions"][0]["reason"],
        "test-only synthetic command"
    );
    assert!(json["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .all(|finding| {
            finding["ruleId"] != "security.process-command"
                || finding["filePath"] != "tests/process.rs"
        }));
}

#[test]
fn sarif_suppression_results_carry_in_source_justification() {
    let registry = rules::builtin_registry();
    let finding = test_finding(
        "security.process-command",
        "tests/fixture.rs",
        4,
        Severity::Warning,
        Pillar::Security,
    );
    let exclusions = vec![ExclusionRule {
        selector: "security.process-command".to_string(),
        rule_ids: expand_rule_selector("security.process-command", &registry, "test.rule")
            .expect("exact selector"),
        paths: vec!["tests/**".to_string()],
        message_contains: None,
        reason: "test-only synthetic command".to_string(),
    }];
    let (findings, suppressions, suppressed_findings) =
        apply_report_exclusions(vec![finding], &exclusions);
    let mut report = sample_report_with(findings, Vec::new());
    report.summary = summarize(&report.findings);
    report.score = score_report(&report.findings);
    report.suppressions = suppressions;
    report.suppressed_findings = suppressed_findings;

    assert!(report.findings.is_empty());
    let sarif = sample_sarif(&report);
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "security.process-command");
    assert_eq!(result["suppressions"][0]["kind"], "inSource");
    assert_eq!(
        result["suppressions"][0]["justification"],
        "test-only synthetic command"
    );
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

#[test]
fn fixture_scan_contract_preserves_existing_sample_findings() {
    let _guard = analysis_lock();
    let report = analyse_test_paths(vec![PathBuf::from("fixtures/sample.rs")]);

    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert_eq!(report.summary.total, report.findings.len());
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.file_path == "fixtures/sample.rs")
            .count(),
        18
    );

    let expected = [
        (
            "docs.missing-public-doc",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(1),
            Some("SampleAnalyzer"),
            "33f9dd5201230832",
        ),
        (
            "modernisation.public-field",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(2),
            None,
            "bc7bce7d0361e8e7",
        ),
        (
            "docs.missing-public-doc",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("process"),
            "44dc31cc3f2fddf6",
        ),
        (
            "error-handling.public-unwrap",
            Severity::Warning,
            "fixtures/sample.rs",
            Some(7),
            Some("process"),
            "826987132b0ba61b",
        ),
        (
            "naming.generic-function",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("process"),
            "c3694de68d5ae921",
        ),
        (
            "size.parameter-count",
            Severity::Warning,
            "fixtures/sample.rs",
            Some(7),
            Some("process"),
            "ec04a7b3fcf15f6d",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("a"),
            "774487e8965bb4e2",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("b"),
            "450fd3ea76dd5ea3",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("c"),
            "5ac981000ba83401",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("d"),
            "e52f3842e9612076",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("e"),
            "8f6d56dc5dbd2e25",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("f"),
            "2febe2864706223f",
        ),
        (
            "security.process-command",
            Severity::Warning,
            "fixtures/sample.rs",
            Some(11),
            None,
            "c83527501efb5e12",
        ),
        (
            "waste.unwrap-expect",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(11),
            None,
            "80bf1a6b54a67ccf",
        ),
        (
            "sensitive-data.aws-access-key",
            Severity::Error,
            "fixtures/sample.rs",
            Some(16),
            None,
            "1aae444024c630df",
        ),
        (
            "sensitive-data.database-url-password",
            Severity::Error,
            "fixtures/sample.rs",
            Some(17),
            None,
            "79a7540d1b61cf02",
        ),
        (
            "test-quality.no-assertions",
            Severity::Warning,
            "fixtures/sample.rs",
            Some(23),
            Some("test_sleeps_without_assertion"),
            "7d01e1f8fa08edc9",
        ),
        (
            "test-quality.sleep-in-test",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(23),
            Some("test_sleeps_without_assertion"),
            "8e9591ae5cdf9beb",
        ),
    ];

    for (rule_id, severity, path, line, symbol, fingerprint) in expected {
        assert!(
            report.findings.iter().any(|finding| {
                finding.rule_id == rule_id
                    && finding.severity == severity
                    && finding.file_path == path
                    && finding.line == line
                    && finding.symbol.as_deref() == symbol
                    && finding.fingerprint == fingerprint
            }),
            "missing expected fixture finding `{rule_id}` at {path}:{line:?}"
        );
    }
}

#[test]
fn analysis_finds_core_rust_smells() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let rust_file = dir.path().join("bad.rs");
    fs::write(
        &rust_file,
        [
            r#"pub struct Bad {
    pub name: String,
}

impl Bad {
    pub fn process(a: bool, b: Vec<String>, c: String, d: String, e: String, f: String) {
        if a {
            "#,
            PROCESS_COMMAND_NEW,
            r#"("sh").arg("-c").arg(c).spawn().unwrap();
        }
        println!("{}{}{}", d, e, f);
    }
}

#[test]
fn test_no_assert() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}
"#,
        ]
        .concat(),
    )
    .expect("fixture write");
    let report = analyse_project_paths(dir.path(), vec![PathBuf::from(".")]);

    let rule_ids: BTreeSet<&str> = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(rule_ids.contains("security.process-command"));
    assert!(rule_ids.contains("size.parameter-count"));
    assert!(rule_ids.contains("test-quality.no-assertions"));
    assert!(rule_ids.contains("modernisation.public-field"));
}

#[test]
fn registry_rejects_duplicate_rule_ids_and_sorts_definitions() {
    let registry = rules::builtin_registry();
    assert!(registry
        .definitions()
        .windows(2)
        .all(|window| window[0].id < window[1].id));
    assert!(registry.contains("security.process-command"));

    let duplicate = registry.definitions()[0];
    assert!(rules::RuleRegistry::new(vec![duplicate, duplicate]).is_err());
}

#[test]
fn config_rejects_unknown_root_keys_and_rule_ids() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(dir.path(), r#"{ "unknown": true }"#);
    let error = load_config(dir.path(), &options).expect_err("unknown root key rejected");
    assert!(error.contains("unknown key `unknown`"), "{error}");

    write_config(
        dir.path(),
        r#"{ "rules": { "unknown.rule": { "enabled": false } } }"#,
    );
    let error = load_config(dir.path(), &options).expect_err("unknown rule rejected");
    assert!(error.contains("unknown rule id `unknown.rule`"), "{error}");
}

#[test]
fn config_rejects_threshold_maps_and_unknown_options() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(
        dir.path(),
        r#"{ "rules": { "size.parameter-count": { "thresholds": { "bogus": 1 } } } }"#,
    );
    let error = load_config(dir.path(), &options).expect_err("threshold map rejected");
    assert!(
        error.contains("unknown key `thresholds` in config for rule `size.parameter-count`"),
        "{error}"
    );

    write_config(
        dir.path(),
        r#"{ "rules": { "size.parameter-count": { "options": { "bogus": true } } } }"#,
    );
    let error = load_config(dir.path(), &options).expect_err("unknown option rejected");
    assert!(error.contains("unknown option `bogus`"), "{error}");
}

#[test]
fn rust_yaml_config_is_the_only_default_config_name() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("sample.rs"),
        r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String) {
    println!("{}{}{}{}{}", b, c, d, e, f);
    if a {
        println!("active");
    }
}
"#,
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"
rules:
  size.parameter-count:
    threshold: 10
    severity: warning
"#,
    );

    let yaml_default = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("gruff-rs yaml config is the preferred default");
    assert_missing_rule(&yaml_default, "size.parameter-count");
}

#[test]
fn unsupported_config_extensions_are_rejected() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("config.json"), "{}").expect("unsupported config write");
    let error = load_config(
        dir.path(),
        &AnalysisOptions {
            config: Some(PathBuf::from("config.json")),
            ..default_test_options()
        },
    )
    .expect_err("unsupported config extension rejected");
    assert!(
        error.contains("unsupported config extension `json`"),
        "{error}"
    );
}

#[test]
fn threshold_overrides_require_one_value_and_one_severity() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(
        dir.path(),
        r#"
rules:
  complexity.cognitive:
    threshold: 20
    severity: error
"#,
    );
    let config = load_config(dir.path(), &options).expect("threshold and severity accepted");
    assert_eq!(config.threshold("complexity.cognitive", 15.0), 20.0);
    assert_eq!(
        config.severity("complexity.cognitive", Severity::Warning),
        Severity::Error
    );

    write_config(
        dir.path(),
        r#"
rules:
  complexity.cognitive:
    threshold: 20
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("severity required");
    assert!(
            error.contains(
                "config key `rules.complexity.cognitive.severity` is required when `threshold` is configured"
            ),
            "{error}"
        );

    write_config(
        dir.path(),
        r#"
rules:
  complexity.cognitive:
    severity: warning
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("threshold required");
    assert!(
        error.contains("config key `rules.complexity.cognitive.severity` requires `threshold`"),
        "{error}"
    );
}

#[test]
fn config_disables_rules_and_overrides_threshold() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("sample.rs"),
        [
            r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String) {
    if a {
        "#,
            PROCESS_COMMAND_NEW,
            r#"("sh").arg("-c").arg(b).spawn().unwrap();
    }
    println!("{}{}{}{}", c, d, e, f);
}
"#,
        ]
        .concat(),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"{
  "rules": {
    "security.process-command": { "enabled": false },
    "size.parameter-count": { "threshold": 10, "severity": "warning" }
  }
}"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    let rule_ids: BTreeSet<&str> = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(!rule_ids.contains("security.process-command"));
    assert!(!rule_ids.contains("size.parameter-count"));
}

#[test]
fn selector_set_matches_registry_with_negative_precedence() {
    let registry = rules::builtin_registry();
    let mut config = Config::default();
    config.selectors.positive =
        expand_rule_selector("Security", &registry, "test").expect("pillar selector");
    config.selectors.has_positive = true;
    config.selectors.negative = expand_rule_selector("security.process-command", &registry, "test")
        .expect("exact selector");

    let enabled: Vec<&str> = registry
        .definitions()
        .iter()
        .map(|definition| definition.id)
        .filter(|rule_id| config.rule_enabled(rule_id))
        .collect();
    eprintln!("selector enabled ids: {enabled:?}");

    assert!(config.rule_enabled("security.unsafe-block"));
    assert!(!config.rule_enabled("security.process-command"));
    assert!(!config.rule_enabled("docs.missing-readme"));
}

#[test]
fn selector_config_supports_empty_pillar_prefix_exact_negative_and_custom_blocks() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(
        dir.path(),
        r#"
rules:
  select: []
"#,
    );
    let config = load_config(dir.path(), &options).expect("empty selector accepted");
    assert!(config.rule_enabled("security.process-command"));
    assert!(config.rule_enabled("docs.missing-readme"));

    write_config(
        dir.path(),
        r#"
rules:
  select: ["Security"]
"#,
    );
    let config = load_config(dir.path(), &options).expect("pillar selector accepted");
    assert!(config.rule_enabled("security.process-command"));
    assert!(config.rule_enabled("security.unsafe-block"));
    assert!(!config.rule_enabled("docs.missing-readme"));

    write_config(
        dir.path(),
        r#"
rules:
  select: ["security"]
  ignore: ["security.process-command"]
"#,
    );
    let config = load_config(dir.path(), &options).expect("prefix and exact selectors accepted");
    assert!(!config.rule_enabled("security.process-command"));
    assert!(config.rule_enabled("security.unsafe-block"));
    assert!(!config.rule_enabled("docs.missing-readme"));

    write_config(
        dir.path(),
        r#"
rules:
  select: ["security.unsafe-block"]
  custom:
    security.unsafe-block:
      enabled: false
"#,
    );
    let config = load_config(dir.path(), &options).expect("custom exact block accepted");
    assert!(!config.rule_enabled("security.unsafe-block"));
    assert!(!config.rule_enabled("security.process-command"));
}

#[test]
fn selector_config_rejects_unknown_pillar_prefix_exact_and_shapes() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(
        dir.path(),
        r#"
rules:
  select: ["Securtiy"]
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("unknown pillar rejected");
    assert!(error.contains("unknown selector `Securtiy`"), "{error}");
    assert!(error.contains("rules.select[0]"), "{error}");

    write_config(
        dir.path(),
        r#"
rules:
  select: ["does-not-exist.*"]
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("unknown prefix rejected");
    assert!(
        error.contains("unknown selector `does-not-exist.*`"),
        "{error}"
    );

    write_config(
        dir.path(),
        r#"
rules:
  select: ["security*"]
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("unsupported glob rejected");
    assert!(
        error.contains("unsupported selector `security*`"),
        "{error}"
    );

    write_config(
        dir.path(),
        r#"
rules:
  custom:
    unknown.rule:
      enabled: false
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("unknown exact id rejected");
    assert!(error.contains("unknown rule id `unknown.rule`"), "{error}");
}

#[test]
fn list_rules_selector_preview_is_deterministic() {
    let text = render_rule_list(
        Path::new("."),
        &ListRulesArgs {
            format: RuleListFormat::Text,
            selector: Some("Security".to_string()),
            config: None,
            no_config: true,
        },
    )
    .expect("selector preview");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        vec![
            "dependency.duplicate-locked-version",
            "dependency.git-source",
            "dependency.path-source",
            "dependency.wildcard-version",
            "security.process-command",
            "security.unsafe-block"
        ]
    );

    let json_output = render_rule_list(
        Path::new("."),
        &ListRulesArgs {
            format: RuleListFormat::Json,
            selector: Some("performance.*".to_string()),
            config: None,
            no_config: true,
        },
    )
    .expect("selector json preview");
    let ids: Vec<String> = serde_json::from_str(&json_output).expect("selector json");
    assert_eq!(
        ids,
        vec![
            "performance.clone-in-loop",
            "performance.format-in-loop",
            "performance.regex-in-loop"
        ]
    );
}

#[test]
fn custom_rule_text_scope_emits_deterministic_findings_with_builtins() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        concat!(
            "pub fn undocumented() {\n",
            "    let marker = \"ALPHA\";\n",
            "}\n",
            "// BETA\n"
        ),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.beta
    pillar: Documentation
    severity: advisory
    message: Beta marker
    scope: text
    pattern: BETA
  - id: custom.alpha
    pillar: Documentation
    severity: advisory
    message: Alpha marker
    scope: text
    pattern: ALPHA
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let ids: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    eprintln!("custom rule deterministic ids: {ids:?}");

    assert_eq!(
        ids,
        vec!["docs.missing-public-doc", "custom.alpha", "custom.beta"]
    );
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![Some(1), Some(2), Some(4)]
    );
}

#[test]
fn custom_rule_rust_code_scope_masks_string_literals_and_text_scope_does_not() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        "fn string_only() {\n    let marker = \"HACK\";\n}\n",
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.hack-code
    pillar: Documentation
    severity: warning
    message: Code marker
    scope: rust-code
    pattern: HACK
  - id: custom.hack-text
    pillar: Documentation
    severity: warning
    message: Text marker
    scope: text
    pattern: HACK
rules:
  select: ["custom.*"]
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert_has_rule(&report, "custom.hack-text");
    assert_missing_rule(&report, "custom.hack-code");
}

#[test]
fn custom_rule_comments_scope_matches_comments_not_strings() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        concat!(
            "fn comments() {\n",
            "    let marker = \"// HACK\";\n",
            "}\n",
            "// HACK\n"
        ),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.comment-hack
    pillar: Documentation
    severity: warning
    message: Comment marker
    scope: comments
    pattern: '(?m)^\s*//\s*HACK\b'
rules:
  select: ["custom.*"]
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let comment_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "custom.comment-hack")
        .collect();

    assert_eq!(comment_findings.len(), 1);
    assert_eq!(comment_findings[0].line, Some(4));
}

#[test]
fn custom_rule_include_exclude_paths_are_honored() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src/generated")).expect("generated dir");
    fs::create_dir_all(dir.path().join("tests")).expect("tests dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("src/lib.rs"), "ALLOW_MARKER\n").expect("src write");
    fs::write(dir.path().join("src/generated/lib.rs"), "ALLOW_MARKER\n").expect("generated write");
    fs::write(dir.path().join("tests/fixture.rs"), "ALLOW_MARKER\n").expect("tests write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.path-marker
    pillar: Documentation
    severity: advisory
    message: Path marker
    scope: text
    pattern: ALLOW_MARKER
    include_paths: ["src/**"]
    exclude_paths: ["src/generated/**"]
rules:
  select: ["custom.*"]
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src"), PathBuf::from("tests")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let paths: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "custom.path-marker")
        .map(|finding| finding.file_path.as_str())
        .collect();

    assert_eq!(paths, vec!["src/lib.rs"]);
}

#[test]
fn custom_rule_config_rejects_duplicate_id_missing_prefix_bad_regex_and_bad_settings() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.dup
    pillar: Documentation
    severity: advisory
    message: First
    scope: text
    pattern: FIRST
  - id: custom.dup
    pillar: Documentation
    severity: advisory
    message: Second
    scope: text
    pattern: SECOND
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("duplicate rejected");
    assert!(
        error.contains("duplicate custom rule id `custom.dup`"),
        "{error}"
    );

    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: no-prefix
    pillar: Documentation
    severity: advisory
    message: Missing prefix
    scope: text
    pattern: MARKER
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("prefix rejected");
    assert!(
        error.contains("must start with the reserved `custom.` namespace"),
        "{error}"
    );
    assert!(error.contains("custom_rules[0].id"), "{error}");

    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.bad-regex
    pillar: Documentation
    severity: advisory
    message: Bad regex
    scope: text
    pattern: '['
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("bad regex rejected");
    assert!(
        error.contains("config key `custom_rules[0].pattern` failed to compile regex"),
        "{error}"
    );

    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.threshold
    pillar: Documentation
    severity: advisory
    message: Threshold
    scope: text
    pattern: MARKER
rules:
  custom.threshold:
    threshold: 1
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("bad setting rejected");
    assert!(
        error.contains("custom rule `custom.threshold` only supports `enabled`"),
        "{error}"
    );
}

#[test]
fn custom_rule_no_match_is_ok() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("src/lib.rs"), "fn clean() {}\n").expect("fixture write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.no-match
    pillar: Documentation
    severity: advisory
    message: No match
    scope: text
    pattern: ABSENT_MARKER
rules:
  select: ["custom.*"]
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn custom_rule_findings_pass_selection_exclusion_baseline_and_diff() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        "fn selected() {}\nCUSTOM_MARKER\n",
    )
    .expect("selected write");
    fs::write(dir.path().join("src/excluded.rs"), "CUSTOM_MARKER\n").expect("excluded write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.marker
    pillar: Documentation
    severity: warning
    message: Custom marker
    scope: text
    pattern: CUSTOM_MARKER
rules:
  select: ["custom.marker"]
exclude:
  - rule: custom.marker
    paths: ["src/excluded.rs"]
    reason: generated custom marker
"#,
    );

    let selected = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("selection and exclusion analysis succeeds");
    assert_eq!(selected.findings.len(), 1);
    assert_eq!(selected.findings[0].rule_id, "custom.marker");
    assert_eq!(selected.findings[0].file_path, "src/lib.rs");
    assert_missing_rule(&selected, "docs.missing-public-doc");
    assert_eq!(total_suppressed_findings(&selected.suppressions), 1);

    let baseline_path = dir.path().join("baseline.json");
    write_baseline(&baseline_path, std::slice::from_ref(&selected.findings[0]))
        .expect("baseline write");
    let baseline_filtered = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("baseline analysis succeeds");
    assert!(baseline_filtered.findings.is_empty());
    assert_eq!(
        baseline_filtered
            .baseline
            .as_ref()
            .map(|baseline| baseline.suppressed),
        Some(1)
    );

    fs::write(
        dir.path().join("src/lib.rs"),
        "CUSTOM_MARKER\nfn gap() {}\nCUSTOM_MARKER\n",
    )
    .expect("diff fixture rewrite");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.marker
    pillar: Documentation
    severity: warning
    message: Custom marker
    scope: text
    pattern: CUSTOM_MARKER
rules:
  select: ["custom.marker"]
"#,
    );
    fs::write(
        dir.path().join("custom.patch"),
        concat!(
            "diff --git a/src/lib.rs b/src/lib.rs\n",
            "--- a/src/lib.rs\n",
            "+++ b/src/lib.rs\n",
            "@@ -3,1 +3,1 @@\n",
            "+CUSTOM_MARKER\n"
        ),
    )
    .expect("patch write");
    let diff_filtered = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            diff: Some(DiffSelection::Patch(PathBuf::from("custom.patch"))),
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("diff analysis succeeds");
    assert_eq!(diff_filtered.findings.len(), 1);
    assert_eq!(diff_filtered.findings[0].line, Some(3));
    assert!(diff_filtered
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.diagnostic_type == "patch-filter"));
}

#[test]
fn custom_rule_list_rules_includes_configured_rules_and_selectors() {
    let dir = tempdir().expect("tempdir");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.second
    pillar: Documentation
    severity: advisory
    message: Second custom rule
    scope: text
    pattern: SECOND
  - id: custom.first
    pillar: Security
    severity: warning
    message: First custom rule
    scope: text
    pattern: FIRST
"#,
    );

    let json_output = render_rule_list(
        dir.path(),
        &ListRulesArgs {
            format: RuleListFormat::Json,
            selector: None,
            config: None,
            no_config: false,
        },
    )
    .expect("rule list json");
    let rules: Vec<Value> = serde_json::from_str(&json_output).expect("rule list json");
    let ids: Vec<&str> = rules
        .iter()
        .map(|rule| rule["id"].as_str().expect("id"))
        .collect();
    let first_custom = ids
        .iter()
        .position(|id| id.starts_with("custom."))
        .expect("custom rule listed");
    assert!(ids[..first_custom]
        .iter()
        .all(|id| !id.starts_with("custom.")));
    assert_eq!(&ids[first_custom..], ["custom.first", "custom.second"]);
    assert!(rules.iter().any(|rule| {
        rule["id"] == "custom.first"
            && rule["kind"] == "custom"
            && rule["customScope"] == "text"
            && rule["pattern"] == "FIRST"
    }));

    let selector_output = render_rule_list(
        dir.path(),
        &ListRulesArgs {
            format: RuleListFormat::Json,
            selector: Some("custom.*".to_string()),
            config: None,
            no_config: false,
        },
    )
    .expect("custom selector");
    let selected: Vec<String> = serde_json::from_str(&selector_output).expect("selector json");
    assert_eq!(selected, vec!["custom.first", "custom.second"]);
}

#[test]
fn registry_reserves_custom_namespace() {
    assert!(rules::builtin_registry()
        .definitions()
        .iter()
        .all(|definition| !definition.id.starts_with("custom.")));

    let definition = rules::RuleDefinition {
        id: "custom.builtin",
        name: "Reserved",
        pillar: Pillar::Documentation,
        tier: "v0.1",
        kind: rules::RuleKind::Text,
        default_severity: Severity::Advisory,
        confidence: Confidence::High,
        threshold: None,
        options: &[],
        default_enabled: true,
        description: "Reserved namespace probe.",
    };
    let error = rules::RuleRegistry::new(vec![definition])
        .expect_err("custom namespace reserved for config rules");
    assert!(
        error.contains("built-in rule id `custom.builtin` uses reserved custom namespace"),
        "{error}"
    );
}

#[test]
fn fingerprint_stable_for_custom_rule() {
    let finding = Finding::new(
        "custom.no-hack",
        "HACK marker",
        "src/lib.rs",
        Some(2),
        Severity::Warning,
        Pillar::Documentation,
        Confidence::Medium,
        Some("byte:12".to_string()),
        None,
        json!({ "scope": "comments" }),
    );

    assert_eq!(finding.fingerprint, "223b4b2c56b0f0e1");
}

#[test]
fn legacy_config_byte_identical_rule_blocks_remain_selector_neutral() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("sample.rs"),
        [
            r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String) {
    if a {
        "#,
            PROCESS_COMMAND_NEW,
            r#"("sh").arg("-c").arg(b).spawn().unwrap();
    }
    println!("{}{}{}{}", c, d, e, f);
}
"#,
        ]
        .concat(),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"{
  "rules": {
    "security.process-command": { "enabled": false }
  }
}"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert_missing_rule(&report, "security.process-command");
    assert_has_rule(&report, "size.parameter-count");
}

#[test]
fn config_secret_previews_allowlist_only_matching_synthetic_values() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    let accepted_fixture = concat!("ghp_", "aaaaaaaaaaaaaaaaaaaaaa");
    let unlisted_secret = concat!("ghp_", "bbbbbbbbbbbbbbbbbbbbbb");
    let sample = format!(
        r#"pub fn entry() {{
    let accepted_fixture = "{accepted_fixture}";
    let unlisted_secret = "{unlisted_secret}";
    println!("{{accepted_fixture}}{{unlisted_secret}}");
}}
"#
    );
    fs::write(dir.path().join("sample.rs"), sample).expect("fixture write");
    write_config(
        dir.path(),
        r#"
allowlists:
  secretPreviews:
    - "ghp_...aaaa (redacted, 26 chars)"
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let api_key_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.api-key-pattern")
        .collect();

    assert_eq!(
        api_key_findings.len(),
        1,
        "expected only the unlisted API key preview to remain; findings={api_key_findings:?}"
    );
    assert_eq!(
        api_key_findings[0].metadata["preview"],
        "ghp_...bbbb (redacted, 26 chars)"
    );
}

#[test]
fn rule_fixtures_prove_complexity_and_naming_rules() {
    let _guard = analysis_lock();
    let positive = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/complexity_naming_positive.rs",
    )]);
    let negative = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/complexity_naming_negative.rs",
    )]);

    assert_has_rule(&positive, "complexity.nesting-depth");
    assert_has_rule(&positive, "complexity.npath");
    assert_has_rule(&positive, "naming.boolean-prefix");
    assert_has_rule(&positive, "naming.placeholder-identifier");

    assert_missing_rule(&negative, "complexity.nesting-depth");
    assert_missing_rule(&negative, "complexity.npath");
    assert_missing_rule(&negative, "naming.boolean-prefix");
    assert_missing_rule(&negative, "naming.placeholder-identifier");
}

#[test]
fn rule_fixtures_prove_security_sensitive_and_test_quality_rules() {
    let _guard = analysis_lock();
    let security_positive = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/security_sensitive_positive.rs",
    )]);
    let security_negative = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/security_sensitive_negative.rs",
    )]);
    let test_positive = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/test_quality_positive.rs",
    )]);
    let test_negative = analyse_test_paths(vec![PathBuf::from(
        "tests/fixtures/rules/test_quality_negative.rs",
    )]);

    assert_has_rule(&security_positive, "security.unsafe-block");
    assert_has_rule(&security_positive, "sensitive-data.hardcoded-env-value");
    assert_has_rule(&security_positive, "sensitive-data.high-entropy-string");

    assert_missing_rule(&security_negative, "security.unsafe-block");
    assert_missing_rule(&security_negative, "sensitive-data.hardcoded-env-value");
    assert_missing_rule(&security_negative, "sensitive-data.high-entropy-string");

    assert_has_rule(&test_positive, "test-quality.ignored-without-reason");
    assert_has_rule(&test_positive, "test-quality.long-test");
    assert_has_rule(&test_positive, "test-quality.trivial-assertion");

    assert_missing_rule(&test_negative, "test-quality.ignored-without-reason");
    assert_missing_rule(&test_negative, "test-quality.long-test");
    assert_missing_rule(&test_negative, "test-quality.trivial-assertion");
    assert_missing_rule(&test_negative, "test-quality.sleep-in-test");
    assert_missing_rule(&test_negative, "test-quality.no-assertions");
}

#[test]
fn project_model_indexes_manifest_modules_items_and_calls_deterministically() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("Cargo.toml"),
        r#"[package]
name = "project-model-fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1"
regex = { version = "1", default-features = false }

[dev-dependencies]
tempfile = "3"
"#,
    )
    .expect("manifest write");
    fs::write(
        dir.path().join("Cargo.lock"),
        r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "project-model-fixture"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .expect("lockfile write");
    fs::write(
        dir.path().join("src/lib.rs"),
        r#"pub mod api {
    pub struct Public;

    fn helper() {}

    pub fn call_helper() {
        helper();
    }

    impl Public {
        pub fn new() -> Self {
            Public
        }
    }
}

mod external;
"#,
    )
    .expect("lib write");
    fs::write(
        dir.path().join("src/external.rs"),
        "pub fn visible_external() {}\n",
    )
    .expect("external write");

    let first = project_context_for_test(dir.path());
    let second = project_context_for_test(dir.path());

    assert_eq!(first.manifest, second.manifest);
    assert_eq!(first.lockfile, second.lockfile);
    assert_eq!(first.modules, second.modules);
    assert_eq!(first.items, second.items);
    assert_eq!(first.call_names, second.call_names);
    assert!(first.diagnostics.is_empty(), "{:?}", first.diagnostics);

    let manifest = first.manifest.as_ref().expect("manifest summary");
    assert_eq!(manifest.file_path, "Cargo.toml");
    assert_eq!(
        manifest.package_name.as_deref(),
        Some("project-model-fixture")
    );
    assert!(manifest.dependencies.iter().any(|dependency| {
        dependency.section == "dependencies"
            && dependency.name == "serde"
            && dependency.requirement.as_deref() == Some("1")
    }));
    assert!(manifest.dependencies.iter().any(|dependency| {
        dependency.section == "dev-dependencies"
            && dependency.name == "tempfile"
            && dependency.requirement.as_deref() == Some("3")
    }));

    let lockfile = first.lockfile.as_ref().expect("lockfile summary");
    assert_eq!(lockfile.file_path, "Cargo.lock");
    assert!(lockfile
        .packages
        .iter()
        .any(|package| package.name == "serde" && package.version == "1.0.0"));

    assert!(first.modules.iter().any(|module| {
        module.file_path == "src/lib.rs"
            && module.module_path == "api"
            && module.public
            && module.inline
    }));
    assert!(first.modules.iter().any(|module| {
        module.file_path == "src/lib.rs"
            && module.module_path == "external"
            && !module.public
            && !module.inline
    }));
    assert!(first.items.iter().any(|item| {
        item.file_path == "src/lib.rs"
            && item.module_path == "api"
            && item.name == "Public"
            && item.kind == "struct"
            && item.public
    }));
    assert!(first.items.iter().any(|item| {
        item.file_path == "src/lib.rs"
            && item.module_path == "api"
            && item.name == "helper"
            && item.kind == "function"
            && !item.public
    }));
    assert!(first
        .call_names
        .iter()
        .any(|call| { call.file_path == "src/lib.rs" && call.name == "helper" && call.line == 7 }));
}

#[test]
fn project_model_handles_missing_and_invalid_cargo_metadata() {
    let _guard = analysis_lock();
    let missing_dir = tempdir().expect("tempdir");
    fs::create_dir_all(missing_dir.path().join("src")).expect("src dir");
    fs::write(missing_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(missing_dir.path().join("src/lib.rs"), "pub fn ready() {}\n").expect("lib write");
    let missing = project_context_for_test(missing_dir.path());
    assert!(missing.manifest.is_none());
    assert!(missing.lockfile.is_none());
    assert!(missing.diagnostics.is_empty(), "{:?}", missing.diagnostics);

    let invalid_manifest_dir = tempdir().expect("tempdir");
    fs::write(invalid_manifest_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(invalid_manifest_dir.path().join("Cargo.toml"), "[package\n")
        .expect("manifest write");
    let invalid_manifest = project_context_for_test(invalid_manifest_dir.path());
    assert!(invalid_manifest.manifest.is_none());
    assert_eq!(invalid_manifest.diagnostics.len(), 1);
    assert_eq!(
        invalid_manifest.diagnostics[0].diagnostic_type,
        "manifest-parse-error"
    );
    assert_eq!(
        invalid_manifest.diagnostics[0].file_path.as_deref(),
        Some("Cargo.toml")
    );
    assert!(!invalid_manifest.diagnostics[0]
        .message
        .to_ascii_lowercase()
        .contains("parser"));

    let invalid_lock_dir = tempdir().expect("tempdir");
    fs::write(invalid_lock_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        invalid_lock_dir.path().join("Cargo.toml"),
        r#"[package]
name = "invalid-lock-fixture"
version = "0.1.0"
"#,
    )
    .expect("manifest write");
    fs::write(invalid_lock_dir.path().join("Cargo.lock"), "[package\n").expect("lockfile write");
    let invalid_lock = project_context_for_test(invalid_lock_dir.path());
    assert!(invalid_lock.manifest.is_some());
    assert_eq!(invalid_lock.diagnostics.len(), 1);
    assert_eq!(
        invalid_lock.diagnostics[0].diagnostic_type,
        "lockfile-parse-error"
    );
    assert_eq!(
        invalid_lock.diagnostics[0].file_path.as_deref(),
        Some("Cargo.lock")
    );
}

#[test]
fn dependency_rules_flag_local_manifest_and_lockfile_posture() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "dependency-positive-fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
wildcard = "*"
gitdep = { git = "https://example.invalid/repo.git", rev = "1111111111111111111111111111111111111111" }
pathdep = { path = "../local-path" }
"#,
        )
        .expect("manifest write");
    fs::write(
        dir.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "duplicate"
version = "1.0.0"

[[package]]
name = "duplicate"
version = "2.0.0"

[[package]]
name = "duplicate"
version = "3.0.0"
"#,
    )
    .expect("lockfile write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert_has_rule(&report, "dependency.git-source");
    assert_has_rule(&report, "dependency.path-source");
    assert_has_rule(&report, "dependency.wildcard-version");
    assert_has_rule(&report, "dependency.duplicate-locked-version");
    assert_has_rule(&report, "dependency.missing-package-metadata");

    let git = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "dependency.git-source")
        .expect("git source finding");
    assert_eq!(git.file_path, "Cargo.toml");
    assert_eq!(git.line, Some(8));
    assert_eq!(git.symbol.as_deref(), Some("gitdep"));
    assert_eq!(git.pillar, Pillar::Security);

    let metadata = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "dependency.missing-package-metadata")
        .expect("metadata finding");
    assert_eq!(metadata.file_path, "Cargo.toml");
    assert_eq!(metadata.line, Some(1));
    assert_eq!(metadata.pillar, Pillar::Documentation);

    let duplicate = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "dependency.duplicate-locked-version")
        .expect("duplicate lockfile finding");
    assert_eq!(duplicate.file_path, "Cargo.lock");
    assert_eq!(duplicate.line, Some(4));
    assert_eq!(duplicate.symbol.as_deref(), Some("duplicate"));

    let security = report
        .score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == Pillar::Security)
        .expect("security score");
    assert!(
        security.findings >= 4,
        "expected dependency findings to affect security: {security:?}"
    );
}

#[test]
fn dependency_rules_accept_clean_manifest_and_config_threshold() {
    let _guard = analysis_lock();
    let clean_dir = tempdir().expect("tempdir");
    fs::write(clean_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        clean_dir.path().join("Cargo.toml"),
        r#"[package]
name = "dependency-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dependency rule tests."
license = "MIT"

[dependencies]
serde = "1"
"#,
    )
    .expect("manifest write");
    fs::write(
        clean_dir.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "serde"
version = "1.0.0"
"#,
    )
    .expect("lockfile write");
    let clean = run_project_analysis(
        clean_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("clean analysis succeeds");
    assert_missing_rule(&clean, "dependency.git-source");
    assert_missing_rule(&clean, "dependency.path-source");
    assert_missing_rule(&clean, "dependency.wildcard-version");
    assert_missing_rule(&clean, "dependency.duplicate-locked-version");
    assert_missing_rule(&clean, "dependency.missing-package-metadata");

    let threshold_dir = tempdir().expect("tempdir");
    fs::write(threshold_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        threshold_dir.path().join("Cargo.toml"),
        r#"[package]
name = "dependency-threshold-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dependency threshold tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        threshold_dir.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "duplicate"
version = "1.0.0"

[[package]]
name = "duplicate"
version = "2.0.0"

[[package]]
name = "duplicate"
version = "3.0.0"
"#,
    )
    .expect("lockfile write");
    write_config(
        threshold_dir.path(),
        r#"
rules:
  dependency.duplicate-locked-version:
    threshold: 3
    severity: advisory
"#,
    );
    let thresholded = run_project_analysis(
        threshold_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("thresholded analysis succeeds");
    assert_missing_rule(&thresholded, "dependency.duplicate-locked-version");

    write_config(
        threshold_dir.path(),
        r#"
rules:
  dependency.duplicate-locked-version:
    threshold: 2
    severity: severe
"#,
    );
    let error =
        load_config(threshold_dir.path(), &default_test_options()).expect_err("bad threshold");
    assert!(
            error.contains(
                "config key `rules.dependency.duplicate-locked-version.severity` must be advisory, warning, or error"
            ),
            "{error}"
        );
}

#[test]
fn architecture_rules_flag_module_shape_and_public_surface() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("Cargo.toml"),
        r#"[package]
name = "architecture-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for architecture rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        dir.path().join("src/lib.rs"),
        r#"pub mod api {
    pub struct One;
    pub struct Two;
    pub enum Three {
        Ready,
    }
    pub trait Four {}
}
mod alpha;
mod beta;
mod gamma;
"#,
    )
    .expect("lib write");
    write_config(
        dir.path(),
        r#"
rules:
  architecture.module-fan-out:
    threshold: 2
    severity: advisory
  architecture.public-api-surface:
    threshold: 2
    severity: advisory
  architecture.large-module:
    threshold: 3
    severity: advisory
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("architecture analysis succeeds");

    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert_has_rule(&report, "architecture.module-fan-out");
    assert_has_rule(&report, "architecture.public-api-surface");
    assert_has_rule(&report, "architecture.large-module");

    let fan_out = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "architecture.module-fan-out")
        .expect("module fan-out finding");
    assert_eq!(fan_out.file_path, "src/lib.rs");
    assert_eq!(fan_out.line, Some(1));
    assert_eq!(fan_out.symbol.as_deref(), Some("src/lib.rs"));
    assert_eq!(fan_out.metadata["modules"], json!(4));
    assert!(fan_out.message.contains("4 child modules"));

    let public_surface = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "architecture.public-api-surface")
        .expect("public API finding");
    assert_eq!(public_surface.symbol.as_deref(), Some("api"));
    assert_eq!(public_surface.metadata["publicItems"], json!(4));

    let large_module = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "architecture.large-module")
        .expect("large module finding");
    assert_eq!(large_module.symbol.as_deref(), Some("api"));
    assert_eq!(large_module.metadata["items"], json!(4));
}

#[test]
fn architecture_rules_accept_small_modules_and_validate_threshold() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("Cargo.toml"),
        r#"[package]
name = "architecture-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for architecture rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        dir.path().join("src/lib.rs"),
        r#"pub mod api {
    pub struct One;
}
mod alpha;
"#,
    )
    .expect("lib write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("small architecture analysis succeeds");
    assert_missing_rule(&report, "architecture.module-fan-out");
    assert_missing_rule(&report, "architecture.public-api-surface");
    assert_missing_rule(&report, "architecture.large-module");

    write_config(
        dir.path(),
        r#"
rules:
  architecture.large-module:
    threshold: 2
    severity: severe
"#,
    );
    let error =
        load_config(dir.path(), &default_test_options()).expect_err("bad threshold rejected");
    assert!(
            error.contains(
                "config key `rules.architecture.large-module.severity` must be advisory, warning, or error"
            ),
            "{error}"
        );
}

#[test]
fn dead_code_project_candidates_use_conservative_cross_file_evidence() {
    let _guard = analysis_lock();
    let positive_dir = tempdir().expect("tempdir");
    fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
    fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        positive_dir.path().join("Cargo.toml"),
        r#"[package]
name = "dead-code-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dead-code rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        positive_dir.path().join("src/lib.rs"),
        r#"fn isolated_helper() {}

struct HiddenType;

enum HiddenEnum {
    Ready,
}

trait HiddenTrait {}

fn referenced_helper() {}

pub fn entry() {
    referenced_helper();
}
"#,
    )
    .expect("positive lib write");

    let positive = run_project_analysis(
        positive_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("dead-code positive analysis succeeds");
    assert_has_rule(&positive, "dead-code.unused-private-item-candidate");
    let candidate = positive
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == "dead-code.unused-private-item-candidate"
                && finding.symbol.as_deref() == Some("isolated_helper")
        })
        .expect("isolated helper candidate");
    assert!(candidate.message.contains("candidate"));
    assert!(matches!(candidate.confidence, Confidence::Medium));
    assert_eq!(candidate.metadata["candidate"], json!(true));

    let negative_dir = tempdir().expect("tempdir");
    fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
    fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        negative_dir.path().join("Cargo.toml"),
        r#"[package]
name = "dead-code-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dead-code rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        negative_dir.path().join("src/lib.rs"),
        r#"macro_rules! register {
    ($item:ident) => {};
}

fn macro_registered() {}
register!(macro_registered);

#[cfg(feature = "optional")]
fn cfg_only() {}

#[test]
fn test_only_helper() {}

mod tests {
    fn module_test_helper() {}
}

fn referenced_helper() {}

pub fn entry() {
    referenced_helper();
}
"#,
    )
    .expect("negative lib write");

    let negative = run_project_analysis(
        negative_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("dead-code negative analysis succeeds");
    assert_missing_rule(&negative, "dead-code.unused-private-item-candidate");
}

#[test]
fn error_handling_rules_flag_production_hazards_and_skip_tests() {
    let _guard = analysis_lock();
    let positive_dir = tempdir().expect("tempdir");
    fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
    fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        positive_dir.path().join("Cargo.toml"),
        r#"[package]
name = "error-handling-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for error-handling rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        positive_dir.path().join("src/lib.rs"),
        r#"pub fn parse_public(input: &str) -> usize {
    input.parse::<usize>().unwrap()
}

pub fn production_panic(flag: bool) {
    if flag {
        panic!("broken invariant");
    }
}

fn unfinished() {
    todo!("finish this branch");
}

fn private_unwrap(input: &str) -> usize {
    input.parse::<usize>().unwrap()
}
"#,
    )
    .expect("positive lib write");

    let positive = run_project_analysis(
        positive_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("error-handling positive analysis succeeds");
    assert_has_rule(&positive, "error-handling.production-panic");
    assert_has_rule(&positive, "error-handling.unimplemented-placeholder");
    assert_has_rule(&positive, "error-handling.public-unwrap");
    assert_has_rule(&positive, "waste.unwrap-expect");

    let public_unwrap = positive
        .findings
        .iter()
        .find(|finding| finding.rule_id == "error-handling.public-unwrap")
        .expect("public unwrap finding");
    assert_eq!(public_unwrap.symbol.as_deref(), Some("parse_public"));
    assert_eq!(public_unwrap.severity, Severity::Warning);
    assert!(matches!(public_unwrap.confidence, Confidence::High));
    assert!(public_unwrap
        .remediation
        .as_deref()
        .is_some_and(|message| message.contains("Result")));

    let panic = positive
        .findings
        .iter()
        .find(|finding| finding.rule_id == "error-handling.production-panic")
        .expect("production panic finding");
    assert_eq!(panic.symbol.as_deref(), Some("production_panic"));
    assert!(panic.message.contains("panic!"));

    let negative_dir = tempdir().expect("tempdir");
    fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
    fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        negative_dir.path().join("Cargo.toml"),
        r#"[package]
name = "error-handling-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for error-handling rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        negative_dir.path().join("src/lib.rs"),
        r#"pub fn parse_public(input: &str) -> Result<usize, std::num::ParseIntError> {
    input.parse::<usize>()
}

pub fn documented_invariant(flag: bool) {
    // PANIC: this branch represents an impossible state checked by the caller.
    if flag {
        panic!("documented invariant");
    }
}

#[test]
fn panic_in_test() {
    panic!("expected failure");
}

mod tests {
    pub fn helper_placeholder() {
        todo!("test helper");
    }
}
"#,
    )
    .expect("negative lib write");

    let negative = run_project_analysis(
        negative_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("error-handling negative analysis succeeds");
    assert_missing_rule(&negative, "error-handling.production-panic");
    assert_missing_rule(&negative, "error-handling.unimplemented-placeholder");
    assert_missing_rule(&negative, "error-handling.public-unwrap");
}

#[test]
fn concurrency_rules_flag_narrow_async_and_channel_patterns() {
    let _guard = analysis_lock();
    let positive_dir = tempdir().expect("tempdir");
    fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
    fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        positive_dir.path().join("Cargo.toml"),
        r#"[package]
name = "concurrency-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for concurrency rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        positive_dir.path().join("src/lib.rs"),
        r#"pub async fn blocks_runtime() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}

pub async fn holds_lock(lock: &std::sync::Mutex<String>) {
    let guard = lock.lock().unwrap();
    async_step().await;
    println!("{}", *guard);
}

pub fn creates_unbounded_channel() {
    let (_tx, _rx) = std::sync::mpsc::channel::<String>();
}

async fn async_step() {}
"#,
    )
    .expect("positive lib write");

    let positive = run_project_analysis(
        positive_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("concurrency positive analysis succeeds");
    assert_has_rule(&positive, "concurrency.blocking-call-in-async");
    assert_has_rule(&positive, "concurrency.lock-across-await");
    assert_has_rule(&positive, "concurrency.unbounded-channel");

    let blocking = positive
        .findings
        .iter()
        .find(|finding| finding.rule_id == "concurrency.blocking-call-in-async")
        .expect("blocking async finding");
    assert_eq!(blocking.symbol.as_deref(), Some("blocks_runtime"));
    assert!(blocking.message.contains("std::thread::sleep"));
    assert!(matches!(blocking.confidence, Confidence::Medium));

    let lock = positive
        .findings
        .iter()
        .find(|finding| finding.rule_id == "concurrency.lock-across-await")
        .expect("lock across await finding");
    assert_eq!(lock.symbol.as_deref(), Some("holds_lock"));
    assert_eq!(lock.metadata["guard"], json!("guard"));

    let negative_dir = tempdir().expect("tempdir");
    fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
    fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        negative_dir.path().join("Cargo.toml"),
        r#"[package]
name = "concurrency-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for concurrency rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        negative_dir.path().join("src/lib.rs"),
        r#"pub async fn async_timer() {
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
}

pub async fn drops_before_await(lock: &std::sync::Mutex<String>) {
    let guard = lock.lock().unwrap();
    drop(guard);
    async_step().await;
}

pub fn bounded_channel() {
    let (_tx, _rx) = tokio::sync::mpsc::channel::<String>(16);
}

mod tests {
    pub async fn blocking_test_helper() {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    pub fn test_channel_helper() {
        let (_tx, _rx) = std::sync::mpsc::channel::<String>();
    }
}

async fn async_step() {}
"#,
    )
    .expect("negative lib write");

    let negative = run_project_analysis(
        negative_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("concurrency negative analysis succeeds");
    assert_missing_rule(&negative, "concurrency.blocking-call-in-async");
    assert_missing_rule(&negative, "concurrency.lock-across-await");
    assert_missing_rule(&negative, "concurrency.unbounded-channel");
}

#[test]
fn performance_rules_flag_loop_scoped_hotspots() {
    let _guard = analysis_lock();
    let positive_dir = tempdir().expect("tempdir");
    fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
    fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        positive_dir.path().join("Cargo.toml"),
        r#"[package]
name = "performance-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for performance rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        positive_dir.path().join("src/lib.rs"),
        r#"pub fn loop_hotspots(values: &[String]) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        let regex = Regex::new("ready").unwrap();
        if regex.is_match(value) {
            output.push(format!("{}", value.clone()));
        }
    }
    output
}
"#,
    )
    .expect("positive lib write");

    let positive = run_project_analysis(
        positive_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("performance positive analysis succeeds");
    assert_has_rule(&positive, "performance.regex-in-loop");
    assert_has_rule(&positive, "performance.format-in-loop");
    assert_has_rule(&positive, "performance.clone-in-loop");

    let regex = positive
        .findings
        .iter()
        .find(|finding| finding.rule_id == "performance.regex-in-loop")
        .expect("regex-in-loop finding");
    assert_eq!(regex.symbol.as_deref(), Some("loop_hotspots"));
    assert_eq!(regex.metadata["pattern"], json!("Regex::new"));
    assert_eq!(regex.metadata["occurrences"], json!(1));
    assert!(regex.message.contains("Regex::new"));

    let waste = positive
        .score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == Pillar::Waste)
        .expect("waste score");
    assert!(
        waste.findings >= 3,
        "expected performance findings in waste: {waste:?}"
    );

    let negative_dir = tempdir().expect("tempdir");
    fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
    fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        negative_dir.path().join("Cargo.toml"),
        r#"[package]
name = "performance-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for performance rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        negative_dir.path().join("src/lib.rs"),
        r#"pub fn setup_outside_loop(values: &[String]) -> Vec<String> {
    let regex = Regex::new("ready").unwrap();
    let label = format!("{}", values.len());
    let cloned = label.clone();
    let mut output = Vec::new();
    for value in values {
        if regex.is_match(value) {
            output.push(cloned.to_string());
        }
    }
    output
}
"#,
    )
    .expect("negative lib write");

    let negative = run_project_analysis(
        negative_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("performance negative analysis succeeds");
    assert_missing_rule(&negative, "performance.regex-in-loop");
    assert_missing_rule(&negative, "performance.format-in-loop");
    assert_missing_rule(&negative, "performance.clone-in-loop");
}

#[test]
fn metrics_rules_calibrate_threshold_and_formatting_stability() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("Cargo.toml"),
        r#"[package]
name = "metrics-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for metrics rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        dir.path().join("src/lib.rs"),
        r#"pub fn compact(input: i32) -> i32 { if input > 0 { input + 1 } else { input - 1 } }

pub fn spaced(input: i32) -> i32 {
    if input > 0 {
        input + 1
    } else {
        input - 1
    }
}

pub fn complex_metric(values: &[i32]) -> i32 {
    let mut total = 0;
    for value in values {
        if *value > 10 {
            total += *value;
        } else if *value < -10 {
            total -= *value;
        } else {
            total += 1;
        }
        match *value {
            0 => total += 3,
            1 | 2 => total += 5,
            _ => total += 8,
        }
        while total < 100 {
            total += *value;
            if total % 2 == 0 {
                total += 1;
            }
            break;
        }
    }
    total
}
"#,
    )
    .expect("metrics lib write");
    write_config(
        dir.path(),
        r#"
rules:
  metrics.halstead-volume:
    threshold: 1
    severity: advisory
  metrics.maintainability-pressure:
    threshold: 100
    severity: advisory
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("metrics analysis succeeds");
    assert_has_rule(&report, "metrics.halstead-volume");
    assert_has_rule(&report, "metrics.maintainability-pressure");

    let compact_volume = metric_metadata_number(
        &report,
        "metrics.halstead-volume",
        "compact",
        "halsteadVolume",
    );
    let spaced_volume = metric_metadata_number(
        &report,
        "metrics.halstead-volume",
        "spaced",
        "halsteadVolume",
    );
    assert_eq!(compact_volume, spaced_volume);

    let compact_score = metric_metadata_number(
        &report,
        "metrics.maintainability-pressure",
        "compact",
        "score",
    );
    let spaced_score = metric_metadata_number(
        &report,
        "metrics.maintainability-pressure",
        "spaced",
        "score",
    );
    assert_eq!(compact_score, spaced_score);

    let complex = report
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == "metrics.halstead-volume"
                && finding.symbol.as_deref() == Some("complex_metric")
        })
        .expect("complex metric volume finding");
    assert!(complex.metadata["totalTokens"].as_u64().unwrap_or_default() > 50);
    assert!(complex
        .metadata
        .get("halsteadVolume")
        .and_then(Value::as_f64)
        .is_some_and(|volume| volume > 100.0));

    let complexity = report
        .score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == Pillar::Complexity)
        .expect("complexity score");
    assert!(
        complexity.findings >= 2,
        "expected metric findings in complexity: {complexity:?}"
    );

    write_config(
        dir.path(),
        r#"
rules:
  metrics.halstead-volume:
    threshold: 1
    severity: severe
"#,
    );
    let error = load_config(dir.path(), &default_test_options()).expect_err("bad metric threshold");
    assert!(
            error.contains(
                "config key `rules.metrics.halstead-volume.severity` must be advisory, warning, or error"
            ),
            "{error}"
        );
}

#[test]
fn missing_readme_is_project_scoped() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("lib.rs"), "pub fn documented() {}\n").expect("fixture write");

    let missing = analyse_project_paths(dir.path(), vec![PathBuf::from("lib.rs")]);
    fs::write(dir.path().join("README.md"), "# Temporary fixture\n").expect("readme write");
    let present = analyse_project_paths(dir.path(), vec![PathBuf::from("lib.rs")]);

    assert_has_rule(&missing, "docs.missing-readme");
    assert_missing_rule(&present, "docs.missing-readme");
}

#[test]
fn baseline_generation_and_exact_suppression_are_stable() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("sample.rs"),
        [
            r#"pub fn process(command: String) {
    "#,
            PROCESS_COMMAND_NEW,
            r#"("sh").arg(command).spawn().unwrap();
}
"#,
        ]
        .concat(),
    )
    .expect("fixture write");

    let before = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert!(!before.findings.is_empty());

    let baseline_path = dir.path().join("baseline.json");
    write_baseline(&baseline_path, std::slice::from_ref(&before.findings[0]))
        .expect("baseline write");

    let suppressed = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert_eq!(suppressed.findings.len(), before.findings.len() - 1);
    assert_eq!(
        suppressed
            .baseline
            .as_ref()
            .map(|baseline| baseline.suppressed),
        Some(1)
    );

    let mut baseline_json: Value =
        serde_json::from_str(&fs::read_to_string(&baseline_path).expect("baseline read"))
            .expect("baseline json");
    baseline_json["entries"][0]["message"] = json!("changed message stays suppressible");
    fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_json).expect("baseline serialize"),
    )
    .expect("baseline rewrite");
    let message_changed = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert_eq!(
        message_changed
            .baseline
            .as_ref()
            .map(|baseline| baseline.suppressed),
        Some(1)
    );

    baseline_json["entries"][0]["filePath"] = json!("other.rs");
    fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_json).expect("baseline serialize"),
    )
    .expect("baseline rewrite");
    let file_changed = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert_eq!(file_changed.findings.len(), before.findings.len());
    assert_eq!(
        file_changed
            .baseline
            .as_ref()
            .map(|baseline| baseline.suppressed),
        Some(0)
    );
}

#[test]
fn baseline_generation_and_failure_modes_are_reported_cleanly() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("fixture write");

    let generated_path = dir.path().join("baseline.json");
    let generated = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            generate_baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            ..default_test_options()
        },
    )
    .expect("baseline generation succeeds");
    assert!(generated
        .baseline
        .as_ref()
        .is_some_and(|baseline| baseline.generated));
    let baseline_json: Value =
        serde_json::from_str(&fs::read_to_string(&generated_path).expect("baseline read"))
            .expect("baseline json");
    assert_eq!(baseline_json["schemaVersion"], "gruff.baseline.v1");
    assert!(baseline_json["entries"].as_array().is_some());

    fs::write(
        dir.path().join("bad-baseline.json"),
        r#"{ "schemaVersion": "wrong", "entries": [] }"#,
    )
    .expect("bad baseline write");
    let invalid_schema = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("bad-baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect_err("invalid baseline schema rejected");
    assert!(invalid_schema.contains("unsupported baseline schema"));

    let missing = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("missing-baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect_err("missing baseline rejected");
    assert!(missing.contains("unable to read baseline"));
}

#[test]
fn scoring_includes_all_static_pillars_and_weights_findings() {
    let clean = score_report(&[]);
    assert_eq!(clean.composite, 100.0);
    assert_eq!(clean.grade, "A");
    assert_eq!(clean.pillars.len(), SCORE_PILLARS.len());
    assert!(clean.pillars.iter().all(|pillar| pillar.findings == 0));

    let findings = vec![
        test_finding(
            "security.process-command",
            "src/a.rs",
            1,
            Severity::Error,
            Pillar::Security,
        ),
        test_finding_with_confidence(
            "dead-code.unused-private-function",
            "src/b.rs",
            1,
            Severity::Warning,
            Pillar::DeadCode,
            Confidence::Low,
        ),
        test_finding(
            "docs.todo-density",
            "src/b.rs",
            2,
            Severity::Advisory,
            Pillar::Documentation,
        ),
    ];
    let score = score_report(&findings);
    assert_eq!(score.grade, "A");
    assert_eq!(score.top_offenders[0].file_path, "src/a.rs");
    let security = score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == Pillar::Security)
        .expect("security pillar");
    let dead_code = score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == Pillar::DeadCode)
        .expect("dead-code pillar");
    assert_eq!(security.score, 92.0);
    assert_eq!(dead_code.score, 98.0);

    assert_eq!(grade(90.0), "A");
    assert_eq!(grade(80.0), "B");
    assert_eq!(grade(70.0), "C");
    assert_eq!(grade(60.0), "D");
    assert_eq!(grade(59.9), "F");
}

#[test]
fn source_discovery_covers_ignores_text_files_and_missing_paths() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join(".git/hooks")).expect("git hooks dir");
    fs::create_dir_all(dir.path().join(".git/info")).expect("git info dir");
    fs::create_dir_all(dir.path().join(".agents/skills")).expect("agents dir");
    fs::create_dir_all(dir.path().join(".claude")).expect("claude dir");
    fs::create_dir_all(dir.path().join(".codex/hooks")).expect("codex dir");
    fs::create_dir_all(dir.path().join(".github/workflows")).expect("github dir");
    fs::create_dir_all(dir.path().join(".goat-flow")).expect("goat dir");
    fs::create_dir_all(dir.path().join("local")).expect("local dir");
    fs::create_dir_all(dir.path().join("nested")).expect("nested dir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::create_dir_all(dir.path().join("target")).expect("target dir");
    fs::create_dir_all(dir.path().join("ignored")).expect("ignored dir");
    fs::write(
        dir.path().join(".gitignore"),
        "local/**\n.goat-flow/audit-cache.json\n",
    )
    .expect("gitignore write");
    fs::write(dir.path().join(".git/info/exclude"), "info-excluded.env\n")
        .expect("git exclude write");
    fs::write(
        dir.path().join(".git/hooks/pre-commit.sh"),
        "DATABASE_PASSWORD=git-hook-secret-123\n",
    )
    .expect("git hook write");
    fs::write(dir.path().join("nested/.gitignore"), "secret.env\n")
        .expect("nested gitignore write");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("info-excluded.env"),
        concat!("DATABASE_", "PASSWORD=info-excluded-secret-123\n"),
    )
    .expect("info excluded write");
    fs::write(
        dir.path().join(".agents/skills/demo.md"),
        "# Demo\nDATABASE_PASSWORD=agents-secret-123\n",
    )
    .expect("agents write");
    fs::write(
        dir.path().join(".claude/settings.json"),
        r#"{"DATABASE_PASSWORD":"claude-secret-123"}"#,
    )
    .expect("claude write");
    fs::write(
        dir.path().join(".codex/hooks/deny-dangerous.sh"),
        "DATABASE_PASSWORD=codex-secret-123\n",
    )
    .expect("codex write");
    fs::write(
        dir.path().join(".github/workflows/ci.yml"),
        "env:\n  DATABASE_PASSWORD=github-secret-123\n",
    )
    .expect("github write");
    fs::write(
        dir.path().join(".goat-flow/architecture.md"),
        "# Architecture\nDATABASE_PASSWORD=goat-secret-123\n",
    )
    .expect("goat write");
    fs::write(
        dir.path().join(".goat-flow/audit-cache.json"),
        r#"{"DATABASE_PASSWORD":"ignored-goat-secret-123"}"#,
    )
    .expect("goat cache write");
    fs::write(
        dir.path().join("src/lib.rs"),
        "/// Ready.\npub fn is_ready() -> bool { true }\n",
    )
    .expect("rust write");
    fs::write(
        dir.path().join("local/secret.env"),
        concat!("DATABASE_", "PASSWORD=local-secret-123\n"),
    )
    .expect("local secret write");
    fs::write(
        dir.path().join("nested/secret.env"),
        concat!("DATABASE_", "PASSWORD=nested-secret-123\n"),
    )
    .expect("nested secret write");
    fs::write(
        dir.path().join("nested/visible.env"),
        concat!("DATABASE_", "PASSWORD=visible-secret-123\n"),
    )
    .expect("nested visible write");
    fs::write(
        dir.path().join("target/secret.env"),
        concat!("DATABASE_", "PASSWORD=target-secret-123\n"),
    )
    .expect("target secret write");
    fs::write(
        dir.path().join("ignored/secret.env"),
        concat!("DATABASE_", "PASSWORD=ignored-secret-123\n"),
    )
    .expect("ignored secret write");
    write_config(dir.path(), r#"{ "paths": { "ignore": ["ignored/**"] } }"#);

    let discovery = discover_sources(
        dir.path(),
        &AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
        &load_config(
            dir.path(),
            &AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("config loads"),
    );
    let discovered_paths: BTreeSet<&str> = discovery
        .files
        .iter()
        .map(|file| file.display_path.as_str())
        .collect();
    assert!(discovered_paths.contains(".agents/skills/demo.md"));
    assert!(discovered_paths.contains(".claude/settings.json"));
    assert!(discovered_paths.contains(".codex/hooks/deny-dangerous.sh"));
    assert!(discovered_paths.contains(".github/workflows/ci.yml"));
    assert!(discovered_paths.contains(".goat-flow/architecture.md"));
    assert!(discovered_paths.contains("nested/visible.env"));
    assert!(discovered_paths.contains("src/lib.rs"));
    assert!(!discovered_paths.contains(".git/hooks/pre-commit.sh"));
    assert!(!discovered_paths.contains(".goat-flow/audit-cache.json"));
    assert!(!discovered_paths.contains("info-excluded.env"));
    assert!(!discovered_paths.contains("local/secret.env"));
    assert!(!discovered_paths.contains("nested/secret.env"));
    assert!(!discovered_paths.contains("target/secret.env"));
    assert!(!discovered_paths.contains("ignored/secret.env"));

    let default_scan = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert!(default_scan
        .paths
        .ignored_paths
        .contains(&"target".to_string()));
    assert!(default_scan
        .paths
        .ignored_paths
        .contains(&"ignored".to_string()));
    assert!(default_scan.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == ".github/workflows/ci.yml"
    }));
    assert!(!default_scan.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "local/secret.env"
    }));
    assert!(!default_scan.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "info-excluded.env"
    }));
    assert!(!default_scan.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == ".git/hooks/pre-commit.sh"
    }));

    let include_ignored = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            include_ignored: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert!(include_ignored.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "local/secret.env"
    }));
    assert!(include_ignored.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "ignored/secret.env"
    }));
    assert!(include_ignored.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "info-excluded.env"
    }));
    assert!(include_ignored.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "target/secret.env"
    }));
    assert!(!include_ignored.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == ".git/hooks/pre-commit.sh"
    }));

    let text_scan = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("local/secret.env")],
            no_config: true,
            include_ignored: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("text scan succeeds");
    assert_has_rule(&text_scan, "sensitive-data.hardcoded-env-value");

    let missing = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("missing.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("missing path is diagnostic, not hard error");
    assert_eq!(missing.diagnostics.len(), 1);
    assert_eq!(missing.diagnostics[0].diagnostic_type, "missing-path");
}

#[test]
fn report_renderers_escape_and_preserve_contracts() {
    let report = sample_report();

    let json_output = render_report(&report, OutputFormat::Json);
    let decoded: Value = serde_json::from_str(&json_output).expect("json report");
    assert_eq!(decoded["schemaVersion"], "gruff.analysis.v1");
    assert_eq!(decoded["findings"][0]["ruleId"], "security.process-command");

    let sarif: Value =
        serde_json::from_str(&render_report(&report, OutputFormat::Sarif)).expect("sarif report");
    assert_eq!(OutputFormat::Sarif.as_str(), "sarif");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "gruff-rs");
    assert_eq!(
        sarif["runs"][0]["properties"]["gruffSchemaVersion"],
        "gruff.analysis.v1"
    );
    let sarif_rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("sarif rules");
    let sarif_rule_ids: Vec<&str> = sarif_rules
        .iter()
        .map(|rule| rule["id"].as_str().expect("sarif rule id"))
        .collect();
    let mut sorted_rule_ids = sarif_rule_ids.clone();
    sorted_rule_ids.sort_unstable();
    assert_eq!(sarif_rule_ids, sorted_rule_ids);
    let rule_index = sarif_rule_ids
        .iter()
        .position(|rule_id| *rule_id == "security.process-command")
        .expect("security rule in sarif driver");
    let sarif_result = &sarif["runs"][0]["results"][0];
    assert_eq!(sarif_result["ruleId"], "security.process-command");
    assert_eq!(sarif_result["ruleIndex"].as_u64(), Some(rule_index as u64));
    assert_eq!(sarif_result["level"], "warning");
    assert_eq!(
        sarif_result["message"]["text"],
        "Use <escaped> command & args"
    );
    assert_eq!(
        sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/lib.rs"
    );
    assert_eq!(
        sarif_result["locations"][0]["physicalLocation"]["region"]["startLine"],
        7
    );
    assert_eq!(
        sarif_result["partialFingerprints"]["gruffFingerprint"].as_str(),
        Some(report.findings[0].fingerprint.as_str())
    );

    let text = render_report(&report, OutputFormat::Text);
    assert!(text.contains("gruff-rs"));
    assert!(text.contains("security.process-command"));

    let markdown = render_report(&report, OutputFormat::Markdown);
    assert!(markdown.starts_with("# gruff-rs report"));
    assert!(markdown.contains("`security.process-command`"));

    let github = render_report(&report, OutputFormat::Github);
    assert!(github.starts_with("::warning file=src/lib.rs,line=7"));

    let html = render_report(&report, OutputFormat::Html);
    assert!(html.contains("Use &lt;escaped&gt; command &amp; args"));
    assert!(!html.contains("Use <escaped> command & args"));

    let hotspot: Value =
        serde_json::from_str(&render_report(&report, OutputFormat::Hotspot)).expect("hotspot json");
    assert_eq!(hotspot["schemaVersion"], "gruff.hotspot.v1");
    assert_eq!(hotspot["files"][0]["filePath"], "src/lib.rs");
}

#[test]
fn sarif_contract_covers_rules_locations_levels_and_metadata() {
    let mut error = Finding::new(
        "complexity.cyclomatic",
        "Complex function",
        r".\src\space name.rs",
        Some(10),
        Severity::Error,
        Pillar::Complexity,
        Confidence::Medium,
        Some("complex".to_string()),
        Some("Split branches.".to_string()),
        json!({}),
    );
    error.column = Some(5);
    error.end_line = Some(12);
    error.secondary_pillars = vec![Pillar::Size];

    let advisory = Finding::new(
        "docs.todo-density",
        "Too many TODOs",
        "src/hash#name.rs",
        None,
        Severity::Advisory,
        Pillar::Documentation,
        Confidence::Low,
        None,
        None,
        Value::Null,
    );
    let unknown = Finding::new(
        "custom.example",
        "Custom warning",
        "src/q?percent%.rs",
        Some(3),
        Severity::Warning,
        Pillar::Naming,
        Confidence::High,
        Some("custom".to_string()),
        None,
        json!({ "detail": "kept" }),
    );
    let report = sample_report_with(vec![error, advisory, unknown], Vec::new());
    let sarif = sample_sarif(&report);

    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules");
    let cyclomatic_rule = rules
        .iter()
        .find(|rule| rule["id"] == "complexity.cyclomatic")
        .expect("cyclomatic rule");
    assert_eq!(cyclomatic_rule["defaultConfiguration"]["level"], "warning");
    assert_eq!(cyclomatic_rule["properties"]["threshold"], json!(10.0));
    assert!(cyclomatic_rule["properties"]["options"].is_null());

    let results = sarif["runs"][0]["results"].as_array().expect("results");
    assert_eq!(results[0]["level"], "error");
    assert_eq!(results[0]["ruleId"], "complexity.cyclomatic");
    assert!(results[0]["ruleIndex"].is_number());
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/space%20name.rs"
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        10
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["startColumn"],
        5
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["endLine"],
        12
    );
    assert!(results[0]["locations"][0]["physicalLocation"]["region"]["endColumn"].is_null());
    assert_eq!(results[0]["properties"]["secondaryPillars"][0], "size");
    assert_eq!(results[0]["properties"]["metadata"], json!({}));
    assert_eq!(results[0]["properties"]["remediation"], "Split branches.");

    assert_eq!(results[1]["level"], "note");
    assert_eq!(
        results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/hash%23name.rs"
    );
    assert!(results[1]["locations"][0]["physicalLocation"]["region"].is_null());
    assert!(results[1]["properties"]["metadata"].is_null());

    assert_eq!(results[2]["level"], "warning");
    assert_eq!(results[2]["ruleId"], "custom.example");
    assert!(results[2]["ruleIndex"].is_null());
    assert_eq!(
        results[2]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/q%3Fpercent%25.rs"
    );
    assert_eq!(results[2]["properties"]["metadata"]["detail"], "kept");
}

#[test]
fn sarif_uri_encodes_reserved_path_characters() {
    assert_eq!(sarif_uri("./src/lib.rs"), "src/lib.rs");
    assert_eq!(sarif_uri(r"src\lib.rs"), "src/lib.rs");
    assert_eq!(sarif_uri("src/space name.rs"), "src/space%20name.rs");
    assert_eq!(sarif_uri("src/hash#name.rs"), "src/hash%23name.rs");
    assert_eq!(sarif_uri("src/q?name.rs"), "src/q%3Fname.rs");
    assert_eq!(sarif_uri("src/percent%name.rs"), "src/percent%25name.rs");
    assert_eq!(sarif_uri(""), ".");
}

#[test]
fn sarif_location_ignores_column_without_start_line() {
    let location = sarif_physical_location_from_parts("src/lib.rs", None, Some(5), Some(7));
    assert_eq!(location["artifactLocation"]["uri"], "src/lib.rs");
    assert!(location["region"].is_null());
}

#[test]
fn sarif_maps_diagnostics_to_invocation_notifications() {
    let report = sample_report_with(
        Vec::new(),
        vec![RunDiagnostic {
            diagnostic_type: "missing-path".to_string(),
            message: "Input path does not exist: missing.rs".to_string(),
            file_path: Some("missing.rs".to_string()),
            line: None,
        }],
    );
    let sarif = sample_sarif(&report);

    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        false
    );
    assert!(sarif["runs"][0]["invocations"][0]["commandLine"].is_null());
    assert!(sarif["runs"][0]["invocations"][0]["arguments"].is_null());
    assert!(sarif["runs"][0]["invocations"][0]["workingDirectory"].is_null());
    let notification = &sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0];
    assert_eq!(notification["descriptor"]["id"], "missing-path");
    assert_eq!(notification["level"], "error");
    assert!(notification["message"]["text"]
        .as_str()
        .expect("message")
        .contains("missing.rs"));
    assert_eq!(
        notification["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "missing.rs"
    );
    assert_eq!(
        sarif["runs"][0]["results"]
            .as_array()
            .expect("results")
            .len(),
        0
    );
}

#[test]
fn sarif_marks_clean_invocation_successful() {
    let sarif = sample_sarif(&sample_report());
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .expect("notifications")
            .len(),
        0
    );
}

#[test]
fn sarif_parse_error_keeps_text_rule_results() {
    let report = analyse_test_paths(vec![PathBuf::from("tests/fixtures/parser/invalid.rs")]);
    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(report.diagnostics[0].diagnostic_type, "parse-error");
    assert_has_rule(&report, "sensitive-data.aws-access-key");

    let sarif = sample_sarif(&report);
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        false
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["descriptor"]["id"],
        "parse-error"
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["locations"][0]
            ["physicalLocation"]["artifactLocation"]["uri"],
        "tests/fixtures/parser/invalid.rs"
    );
    let result_rule_ids: Vec<&str> = sarif["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|result| result["ruleId"].as_str().expect("rule id"))
        .collect();
    assert!(
        result_rule_ids.contains(&"sensitive-data.aws-access-key"),
        "{result_rule_ids:?}"
    );
}

#[test]
fn report_json_keeps_deterministic_finding_order() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("b.rs"), "pub fn process() {}\n").expect("b write");
    fs::write(dir.path().join("a.rs"), "pub fn process() {}\n").expect("a write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("b.rs"), PathBuf::from("a.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    let ordered_paths: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.file_path.as_str())
        .collect();
    assert_eq!(ordered_paths, vec!["a.rs", "a.rs", "b.rs", "b.rs"]);
}

#[test]
fn dashboard_scan_preserves_cwd_and_report_paths() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("sample write");
    let cwd_before = std::env::current_dir().expect("cwd");
    let query = format!(
        "projectRoot={}&path=sample.rs",
        dir.path().to_string_lossy()
    );

    let response = dashboard_response("/scan", &query, Path::new("."));

    assert_eq!(response.status, "200 OK");
    assert_eq!(std::env::current_dir().expect("cwd"), cwd_before);
    assert!(response.body.contains("Dashboard scan"));
    assert!(response.body.contains("sample.rs"));
    assert!(!response
        .body
        .contains(&dir.path().join("sample.rs").display().to_string()));
}

#[test]
fn parser_handles_raw_strings_macros_impls_and_test_attributes() {
    let _guard = analysis_lock();
    let report = analyse_test_paths(vec![
        PathBuf::from("tests/fixtures/parser/raw_strings.rs"),
        PathBuf::from("tests/fixtures/parser/macros_impls.rs"),
    ]);

    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);

    let parameter_count = report
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == "size.parameter-count"
                && finding.file_path == "tests/fixtures/parser/macros_impls.rs"
                && finding.symbol.as_deref() == Some("process")
        })
        .expect("impl method parameter-count finding");
    assert_eq!(parameter_count.line, Some(12));

    let no_assertions = report
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == "test-quality.no-assertions"
                && finding.file_path == "tests/fixtures/parser/macros_impls.rs"
                && finding.symbol.as_deref() == Some("test_macro_fixture")
        })
        .expect("test attribute no-assertions finding");
    assert_eq!(no_assertions.line, Some(20));
}

#[test]
fn invalid_rust_reports_parse_error_and_keeps_text_rules() {
    let _guard = analysis_lock();
    let report = analyse_test_paths(vec![PathBuf::from("tests/fixtures/parser/invalid.rs")]);

    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(report.diagnostics[0].diagnostic_type, "parse-error");
    assert_eq!(
        report.diagnostics[0].file_path.as_deref(),
        Some("tests/fixtures/parser/invalid.rs")
    );

    let rule_ids: BTreeSet<&str> = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(rule_ids.contains("sensitive-data.aws-access-key"));
    assert!(!rule_ids.contains("size.function-length"));
}

#[test]
fn json_report_uses_schema_version() {
    let report = AnalysisReport {
        schema_version: "gruff.analysis.v1".to_string(),
        tool: ToolInfo {
            name: "gruff-rs".to_string(),
            version: VERSION.to_string(),
        },
        run: RunInfo {
            project_root: ".".to_string(),
            format: "json".to_string(),
            fail_on: "none".to_string(),
            generated_at: Utc::now().to_rfc3339(),
        },
        summary: Summary {
            advisory: 0,
            warning: 0,
            error: 0,
            total: 0,
        },
        paths: PathSummary {
            analysed_files: 0,
            ignored_paths: Vec::new(),
            missing_paths: Vec::new(),
        },
        diagnostics: Vec::new(),
        suppressions: Vec::new(),
        findings: Vec::new(),
        score: ScoreReport {
            composite: 100.0,
            grade: "A".to_string(),
            pillars: Vec::new(),
            top_offenders: Vec::new(),
        },
        baseline: None,
        suppressed_findings: Vec::new(),
    };

    let rendered = render_report(&report, OutputFormat::Json);
    assert!(rendered.contains("\"schemaVersion\": \"gruff.analysis.v1\""));
}

const CALIBRATION_BASELINE_MANIFEST: &str = r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "Calibration baseline."
license = "MIT"

[dependencies]
serde = "1"
"#;

const CALIBRATION_BASELINE_LOCKFILE: &str = r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "calibration-fixture"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

fn calibration_baseline(root: &Path) {
    fs::create_dir_all(root.join("src")).expect("calibration src dir");
    fs::write(root.join("README.md"), "# Calibration\n").expect("calibration readme");
    fs::write(root.join("Cargo.toml"), CALIBRATION_BASELINE_MANIFEST)
        .expect("calibration manifest");
    fs::write(root.join("Cargo.lock"), CALIBRATION_BASELINE_LOCKFILE)
        .expect("calibration lockfile");
}

fn write_lib(root: &Path, content: &str) {
    fs::write(root.join("src/lib.rs"), content).expect("calibration lib");
}

fn baseline_with_lib(root: &Path, lib_content: &str) {
    calibration_baseline(root);
    write_lib(root, lib_content);
}

fn module_with_n_items(count: usize) -> String {
    let mut body = String::from("/// Probe.\n");
    for index in 0..count {
        body.push_str(&format!("/// Item {index}.\npub fn item_{index}() {{}}\n"));
    }
    body
}

fn module_with_n_mod_decls(count: usize) -> String {
    let mut body = String::from("/// Root.\n");
    for index in 0..count {
        body.push_str(&format!("mod child_{index} {{ pub fn unused() {{}} }}\n"));
    }
    body
}

type Setup = Box<dyn Fn(&Path)>;

struct CalibrationCase {
    rule_id: &'static str,
    positive: Setup,
    negative: Setup,
}

fn case(rule_id: &'static str, positive: Setup, negative: Setup) -> CalibrationCase {
    CalibrationCase {
        rule_id,
        positive,
        negative,
    }
}

fn run_calibration_case(case: &CalibrationCase) -> (bool, bool) {
    let positive_dir = tempdir().expect("calibration positive tempdir");
    (case.positive)(positive_dir.path());
    let positive_report = run_project_analysis(
        positive_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("calibration positive analysis succeeds");
    let positive_fired = positive_report
        .findings
        .iter()
        .any(|finding| finding.rule_id == case.rule_id);

    let negative_dir = tempdir().expect("calibration negative tempdir");
    (case.negative)(negative_dir.path());
    let negative_report = run_project_analysis(
        negative_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("calibration negative analysis succeeds");
    let negative_fired = negative_report
        .findings
        .iter()
        .any(|finding| finding.rule_id == case.rule_id);

    (positive_fired, negative_fired)
}

fn calibration_cases() -> Vec<CalibrationCase> {
    vec![
        // ----- architecture -----
        case(
            "architecture.large-module",
            Box::new(|root| baseline_with_lib(root, &module_with_n_items(28))),
            Box::new(|root| baseline_with_lib(root, &module_with_n_items(3))),
        ),
        case(
            "architecture.module-fan-out",
            Box::new(|root| baseline_with_lib(root, &module_with_n_mod_decls(10))),
            Box::new(|root| baseline_with_lib(root, &module_with_n_mod_decls(2))),
        ),
        case(
            "architecture.public-api-surface",
            Box::new(|root| baseline_with_lib(root, &module_with_n_items(15))),
            Box::new(|root| baseline_with_lib(root, &module_with_n_items(3))),
        ),
        // ----- complexity -----
        case(
            "complexity.cognitive",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn complex(items: &[i32], flag_a: bool, flag_b: bool, flag_c: bool) -> i32 {
    let mut total = 0;
    for value in items {
        if flag_a {
            if flag_b {
                if flag_c {
                    if *value > 0 {
                        total += value;
                    } else if *value < 0 {
                        total -= value;
                    }
                }
            }
        }
        if flag_a && flag_b {
            total += 1;
        } else if flag_b || flag_c {
            total -= 1;
        }
    }
    total
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn simple(value: i32) -> i32 {
    value + 1
}
"#,
                )
            }),
        ),
        case(
            "complexity.cyclomatic",
            Box::new(|root| {
                let mut body = String::from("/// Probe.\npub fn many_branches(value: i32) -> i32 {\n    let mut total = 0;\n");
                for index in 0..15 {
                    body.push_str(&format!(
                        "    if value == {index} {{ total += {index}; }}\n"
                    ));
                }
                body.push_str("    total\n}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn straight_line(value: i32) -> i32 { value + 1 }\n",
                )
            }),
        ),
        case(
            "complexity.nesting-depth",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn deeply_nested(flag_a: bool, flag_b: bool, flag_c: bool, flag_d: bool, flag_e: bool) -> i32 {
    if flag_a {
        if flag_b {
            if flag_c {
                if flag_d {
                    if flag_e {
                        return 1;
                    }
                }
            }
        }
    }
    0
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn shallow(flag_a: bool, flag_b: bool) -> i32 {
    if flag_a && flag_b {
        return 1;
    }
    0
}
"#,
                )
            }),
        ),
        case(
            "complexity.npath",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn many_paths(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool, g: bool, h: bool) -> i32 {
    if a { 1 } else { 0 };
    if b { 1 } else { 0 };
    if c { 1 } else { 0 };
    if d { 1 } else { 0 };
    if e { 1 } else { 0 };
    if f { 1 } else { 0 };
    if g { 1 } else { 0 };
    if h { 1 } else { 0 };
    0
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn linear(a: bool) -> i32 { if a { 1 } else { 0 } }\n",
                )
            }),
        ),
        // ----- concurrency -----
        case(
            "concurrency.blocking-call-in-async",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub async fn blocks() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn synchronous() { std::thread::sleep(std::time::Duration::from_millis(1)); }\n",
                    )
            }),
        ),
        case(
            "concurrency.lock-across-await",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub async fn holds(lock: &std::sync::Mutex<i32>) {
    let guard = lock.lock().unwrap();
    other().await;
    println!("{}", *guard);
}

async fn other() {}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub async fn drops_first(lock: &std::sync::Mutex<i32>) {
    let guard = lock.lock().unwrap();
    drop(guard);
    other().await;
}

async fn other() {}
"#,
                )
            }),
        ),
        case(
            "concurrency.unbounded-channel",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn make_channel() { let (_tx, _rx) = std::sync::mpsc::channel::<i32>(); }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn make_channel() { let (_tx, _rx) = std::sync::mpsc::sync_channel::<i32>(16); }\n",
                    )
            }),
        ),
        // ----- dead code -----
        case(
            "dead-code.unused-private-function",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\nfn never_called() {}\npub fn entry() {}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\nfn helper() {}\npub fn entry() { helper(); }\n",
                )
            }),
        ),
        case(
            "dead-code.unused-private-item-candidate",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\nfn unused_isolated_widget() {}\npub fn entry() {}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\nfn helper_widget() {}\npub fn entry() { helper_widget(); }\n",
                )
            }),
        ),
        // ----- dependency -----
        case(
            "dependency.duplicate-locked-version",
            Box::new(|root| {
                calibration_baseline(root);
                fs::write(
                    root.join("Cargo.lock"),
                    r#"# generated
version = 3

[[package]]
name = "calibration-fixture"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "serde"
version = "1.0.1"
"#,
                )
                .expect("dup lock");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "dependency.git-source",
            Box::new(|root| {
                calibration_baseline(root);
                fs::write(
                    root.join("Cargo.toml"),
                    r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "git source fixture"
license = "MIT"

[dependencies]
serde = { git = "https://example.test/serde" }
"#,
                )
                .expect("git manifest");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "dependency.missing-package-metadata",
            Box::new(|root| {
                fs::create_dir_all(root.join("src")).expect("src dir");
                fs::write(root.join("README.md"), "# Calibration\n").expect("readme");
                fs::write(
                    root.join("Cargo.toml"),
                    r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
"#,
                )
                .expect("bare manifest");
                fs::write(root.join("Cargo.lock"), CALIBRATION_BASELINE_LOCKFILE)
                    .expect("lockfile");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "dependency.path-source",
            Box::new(|root| {
                calibration_baseline(root);
                fs::write(
                    root.join("Cargo.toml"),
                    r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "path source fixture"
license = "MIT"

[dependencies]
helper = { path = "../helper" }
"#,
                )
                .expect("path manifest");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "dependency.wildcard-version",
            Box::new(|root| {
                calibration_baseline(root);
                fs::write(
                    root.join("Cargo.toml"),
                    r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "wildcard fixture"
license = "MIT"

[dependencies]
serde = "*"
"#,
                )
                .expect("wildcard manifest");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        // ----- design -----
        case(
            "design.god-function",
            Box::new(|root| {
                let mut body = String::from(
                        "/// Probe.\npub fn god(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> i32 {\n    let mut total = 0;\n",
                    );
                for index in 0..60 {
                    body.push_str(&format!(
                        "    if a && b {{\n        total += {index};\n    }}\n"
                    ));
                }
                body.push_str("    total\n}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn small(a: i32) -> i32 { a + 1 }\n")
            }),
        ),
        // ----- docs -----
        case(
            "docs.missing-public-doc",
            Box::new(|root| baseline_with_lib(root, "pub fn undocumented_entry() {}\n")),
            Box::new(|root| baseline_with_lib(root, "/// Documented entry.\npub fn entry() {}\n")),
        ),
        case(
            "docs.missing-readme",
            Box::new(|root| {
                fs::create_dir_all(root.join("src")).expect("src dir");
                fs::write(root.join("Cargo.toml"), CALIBRATION_BASELINE_MANIFEST)
                    .expect("manifest");
                fs::write(root.join("Cargo.lock"), CALIBRATION_BASELINE_LOCKFILE)
                    .expect("lockfile");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "docs.todo-density",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\n// TODO: one\n// TODO: two\n// FIXME: three\n// TODO: four\npub fn entry() {}\n",
                    )
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "docs.stale-todo",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\n// TODO fix this later\npub fn entry() {}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\n// TODO(#123): remove after parser migration\npub fn entry() {}\n",
                )
            }),
        ),
        case(
            "docs.commented-out-code",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\n// let value = compute();\npub fn entry() {}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\n// reminder: the next refactor should remove the cache\npub fn entry() {}\n",
                    )
            }),
        ),
        case(
            "docs.weak-safety-rationale",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {\n    // SAFETY: safe\n    unsafe { std::ptr::null::<i32>(); }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {\n    // SAFETY: caller guarantees pointer is non-null and aligned for u8.\n    unsafe { std::ptr::null::<i32>(); }\n}\n",
                    )
            }),
        ),
        case(
            "docs.missing-errors-section",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Loads the value.\npub fn load() -> Result<i32, String> { Ok(0) }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Loads the value.\n///\n/// # Errors\n///\n/// Returns Err when input is missing.\npub fn load() -> Result<i32, String> { Ok(0) }\n",
                    )
            }),
        ),
        // ----- error handling -----
        case(
            "error-handling.production-panic",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn always_panics() { panic!(\"boom\"); }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn returns_value() -> i32 { 1 }\n")
            }),
        ),
        case(
            "error-handling.public-unwrap",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let value: Option<i32> = Some(1); value.unwrap(); }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() -> Option<i32> { Some(1) }\n",
                )
            }),
        ),
        case(
            "error-handling.unimplemented-placeholder",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() -> i32 { todo!(\"unfinished\") }\n",
                )
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() -> i32 { 0 }\n")),
        ),
        // ----- metrics -----
        case(
            "metrics.halstead-volume",
            Box::new(|root| {
                let mut body = String::from(
                        "/// Probe.\npub fn dense(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {\n    let mut acc = 0;\n",
                    );
                for index in 0..60 {
                    body.push_str(&format!(
                            "    acc = acc + (a * {index}) - (b ^ {index}) | (c & {index}) + (d % ({index} + 1)) * (e + {index});\n"
                        ));
                }
                body.push_str("    acc\n}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn small(a: i32) -> i32 { a + 1 }\n")
            }),
        ),
        case(
            "metrics.maintainability-pressure",
            Box::new(|root| {
                let mut body = String::from(
                        "/// Probe.\npub fn dense(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {\n    let mut acc = 0;\n",
                    );
                for index in 0..60 {
                    body.push_str(&format!(
                            "    if a == {index} {{ acc += b * {index} - c + d / ({index} + 1) - e; }}\n"
                        ));
                }
                body.push_str("    acc\n}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn small(a: i32) -> i32 { a + 1 }\n")
            }),
        ),
        // ----- modernisation -----
        case(
            "modernisation.public-field",
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub struct Wide { pub value: i32 }\n")
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub struct Narrow { value: i32 }\nimpl Narrow { /// Read.\npub fn value(&self) -> i32 { self.value } }\n",
                    )
            }),
        ),
        // ----- naming -----
        case(
            "naming.boolean-prefix",
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn ready() -> bool { true }\n")
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn is_ready() -> bool { true }\n")
            }),
        ),
        case(
            "naming.generic-function",
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn process() {}\n")),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn ingest_payload() {}\n")),
        ),
        case(
            "naming.placeholder-identifier",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let foo = 1; let _ = foo; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let count = 1; let _ = count; }\n",
                )
            }),
        ),
        case(
            "naming.short-variable",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() -> i32 { let xy = 1; xy + 1 }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() -> i32 { let count = 1; count + 1 }\n",
                )
            }),
        ),
        case(
            "naming.identifier-shadow",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\nfn payload(input: &str) -> String { input.to_string() }\n/// Probe.\npub fn entry(input: &str) -> String { let payload = payload(input); payload }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\nfn payload(input: &str) -> String { input.to_string() }\n/// Probe.\npub fn entry(input: &str) -> String { let body = payload(input); body }\n",
                    )
            }),
        ),
        // ----- performance -----
        case(
            "performance.clone-in-loop",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn entry(values: Vec<String>) {
    for value in values {
        let _owned = value.clone();
    }
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry(value: &String) { let _owned = value.clone(); }\n",
                )
            }),
        ),
        case(
            "performance.format-in-loop",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn entry(values: Vec<i32>) {
    for value in values {
        let _formatted = format!("{value}");
    }
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(value: i32) { let _formatted = format!(\"{value}\"); }\n",
                    )
            }),
        ),
        case(
            "performance.regex-in-loop",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn entry(values: Vec<i32>) {
    for value in values {
        let _compiled = regex::Regex::new("^a$");
        let _consume = value;
    }
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _compiled = regex::Regex::new(\"^a$\"); }\n",
                )
            }),
        ),
        // ----- security -----
        case(
            "security.process-command",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = std::process::Command::new(\"ls\"); }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() -> &'static str { \"ls\" }\n",
                )
            }),
        ),
        case(
            "security.unsafe-block",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry(p: *const u8) -> u8 { unsafe { *p } }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(p: *const u8) -> u8 {\n    // SAFETY: caller validated pointer.\n    unsafe { *p }\n}\n",
                    )
            }),
        ),
        // ----- sensitive data -----
        case(
            "sensitive-data.api-key-pattern",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"ghp_aaaaaaaaaaaaaaaaaaaaaa\"; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"safe-string\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.aws-access-key",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"AKIAABCDEFGHIJKLMNOP\"; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"safe-string\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.database-url-password",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"postgres://user:secret@db/app\"; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"postgres://db/app\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.hardcoded-env-value",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"DATABASE_PASSWORD=correct-horse-battery-123\"; }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"DATABASE_PASSWORD\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.high-entropy-string",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"Q7m2P9x8R4s6T1v3W5y7Z0a2B4c6D8e0\"; }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"hello world\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.jwt-token",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"; }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"plain-string\"; }\n",
                )
            }),
        ),
        case(
            "sensitive-data.private-key",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"-----BEGIN RSA PRIVATE KEY-----\"; }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry() { let _ = \"plain-string\"; }\n",
                )
            }),
        ),
        // ----- size -----
        case(
            "size.file-length",
            Box::new(|root| {
                let mut body = String::from("/// Probe.\npub fn entry() {}\n");
                for index in 0..620 {
                    body.push_str(&format!("// filler line {index}\n"));
                }
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "size.function-length",
            Box::new(|root| {
                let mut body = String::from("/// Probe.\npub fn long_entry() {\n");
                for index in 0..60 {
                    body.push_str(&format!("    let _ = {index};\n"));
                }
                body.push_str("}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "size.parameter-count",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 { a + b + c + d + e + f }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(root, "/// Probe.\npub fn entry(a: i32) -> i32 { a }\n")
            }),
        ),
        // ----- test quality -----
        case(
            "test-quality.conditional-logic",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        let value = 1;\n        if value > 0 { assert_eq!(value, 1); } else { assert_eq!(value, 0); }\n    }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(2 + 2, 4); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.ignored-without-reason",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    #[ignore]\n    fn skipped() { assert_eq!(1, 1); }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    #[ignore = \"flaky on CI\"]\n    fn skipped() { assert_eq!(1, 1); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.long-test",
            Box::new(|root| {
                let mut body = String::from(
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn long() {\n        let value = 0;\n",
                    );
                for index in 0..90 {
                    body.push_str(&format!("        let value = value + {index};\n"));
                }
                body.push_str("        assert_eq!(value, 4005);\n    }\n}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn quick() { assert_eq!(2 + 2, 4); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.loop-in-test",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        let mut sum = 0;\n        for index in 0..3 { sum += index; }\n        assert_eq!(sum, 3);\n    }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(1 + 2, 3); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.no-assertions",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { let _ = 1; }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(1, 1); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.sleep-in-test",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        std::thread::sleep(std::time::Duration::from_millis(1));\n        assert_eq!(1, 1);\n    }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(2, 2); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.trivial-assertion",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert!(true); }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { let actual = 2 + 2; assert_eq!(actual, 4); }\n}\n",
                    )
            }),
        ),
        case(
            "test-quality.unwrap-in-test",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        let value: Option<i32> = Some(1);\n        let v = value.unwrap();\n        assert_eq!(v, 1);\n    }\n}\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(1, 1); }\n}\n",
                    )
            }),
        ),
        // ----- waste -----
        case(
            "waste.unnecessary-clone-candidate",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry(value: &String) -> String { value.clone() }\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn entry(value: String) -> String { value }\n",
                )
            }),
        ),
        case(
            "waste.unreachable-code",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() -> i32 {\n    return 1;\n    let _ignored = 2;\n    3\n}\n",
                    )
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() -> i32 { 1 }\n")),
        ),
        case(
            "waste.unwrap-expect",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\nfn entry() { let value: Option<i32> = Some(1); value.unwrap(); }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\nfn entry(value: Option<i32>) -> Option<i32> { value }\n",
                )
            }),
        ),
    ]
}

#[test]
fn rule_calibration_matrix_covers_every_rule() {
    let _guard = analysis_lock();
    let cases = calibration_cases();
    let registry = crate::rules::builtin_registry();

    let cases_by_rule: BTreeSet<&str> = cases.iter().map(|case| case.rule_id).collect();
    let registry_ids: BTreeSet<&str> = registry
        .definitions()
        .iter()
        .map(|definition| definition.id)
        .collect();

    let missing_cases: Vec<&str> = registry_ids.difference(&cases_by_rule).copied().collect();
    let stale_cases: Vec<&str> = cases_by_rule.difference(&registry_ids).copied().collect();

    let mut report_lines: Vec<String> = Vec::new();
    let mut missing_positive: Vec<&str> = Vec::new();
    let mut leaked_negative: Vec<&str> = Vec::new();

    for case in &cases {
        let (positive_fired, negative_fired) = run_calibration_case(case);
        report_lines.push(format!(
            "{rule}: positive={positive} negative={negative}",
            rule = case.rule_id,
            positive = if positive_fired { "FIRES" } else { "MISS" },
            negative = if negative_fired { "FIRES" } else { "silent" },
        ));
        if !positive_fired {
            missing_positive.push(case.rule_id);
        }
        if negative_fired {
            leaked_negative.push(case.rule_id);
        }
    }

    eprintln!("\n=== Calibration matrix ===");
    for line in &report_lines {
        eprintln!("{line}");
    }
    eprintln!(
            "Coverage: {}/{} rules have calibration cases. Missing: {missing_cases:?}. Stale: {stale_cases:?}",
            cases_by_rule.len(),
            registry_ids.len(),
        );
    eprintln!(
            "Under-strict (positive missed): {missing_positive:?}\nOver-strict (negative fired): {leaked_negative:?}\n"
        );

    assert!(
        missing_cases.is_empty(),
        "calibration matrix missing cases for rules: {missing_cases:?}"
    );
    assert!(
        stale_cases.is_empty(),
        "calibration matrix references unknown rules: {stale_cases:?}"
    );
    assert!(
            missing_positive.is_empty() && leaked_negative.is_empty(),
            "calibration mismatches: under-strict={missing_positive:?}, over-strict={leaked_negative:?}"
        );
}

/// Proves that `naming.short-variable` ignores idiomatic throwaway bindings.
#[test]
fn calibration_naming_short_variable_ignores_underscore_binding() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        "/// Probe.\npub fn entry() { let value = 1; let _ = value; }\n",
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let underscore_finding = report.findings.iter().find(|finding| {
        finding.rule_id == "naming.short-variable" && finding.symbol.as_deref() == Some("_")
    });
    assert!(
        underscore_finding.is_none(),
        "calibration expected `naming.short-variable` to ignore `let _`; \
             findings={:?}",
        rule_ids(&report)
    );
}

/// Proves that `performance.clone-in-loop` catches single-line loop bodies.
#[test]
fn calibration_performance_loop_rules_catch_single_line_loops() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
            dir.path(),
            "/// Probe.\npub fn entry(values: Vec<String>) { for value in values { let _ = value.clone(); } }\n",
        );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert_has_rule(&report, "performance.clone-in-loop");
}

/// Proves that `dead-code.unused-private-function` skips harness entry points.
#[test]
fn calibration_dead_code_skips_test_attr_and_main() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn library_entry() {}

#[cfg(test)]
mod inner {
    #[test]
    fn private_test_only_called_by_runner() {
        assert_eq!(1, 1);
    }
}

fn main() {}
"#,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let main_dead = report.findings.iter().any(|finding| {
        finding.rule_id == "dead-code.unused-private-function"
            && finding.symbol.as_deref() == Some("main")
    });
    let test_dead = report.findings.iter().any(|finding| {
        finding.rule_id == "dead-code.unused-private-function"
            && finding.symbol.as_deref() == Some("private_test_only_called_by_runner")
    });
    assert!(
        !main_dead,
        "calibration expected `dead-code.unused-private-function` to skip `fn main`; \
             findings={:?}",
        rule_ids(&report)
    );
    assert!(
        !test_dead,
        "calibration expected `dead-code.unused-private-function` to skip `#[test]` fn; \
             findings={:?}",
        rule_ids(&report)
    );
}

/// Proves that `security.process-command` catches live process construction
/// while ignoring command snippets embedded in fixture strings.
#[test]
fn calibration_security_process_command_detects_code_not_fixture_text() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn live_command() {
    let mut command = std::process::Command::new("git");
    command.arg("status");
}

/// Probe.
pub fn fixture_text() {
    let snippet = r#"std::process::Command::new("sh");"#;
    println!("{snippet}");
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let command_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.process-command")
        .collect();
    assert_eq!(
            command_findings.len(),
            1,
            "calibration expected exactly one live process-command finding; findings={command_findings:?}"
        );
    assert_eq!(command_findings[0].symbol.as_deref(), None);
    assert_eq!(command_findings[0].line, Some(3));
}

/// M37 calibration: the three new naming options
/// (`predicatePrefixes`, `extraPlaceholders`, `extraGenericNames`) plumb
/// through the typed-option config and influence rule dispatch. Wrong
/// shapes (a non-array value) are rejected with the expected error
/// format.
#[test]
fn m37_naming_options_round_trip_through_config() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        "/// Probe.\npub fn requires_init() -> bool { true }\n\
             /// Probe.\npub fn entry() { let tmp = 1; let _ = tmp; }\n\
             /// Probe.\npub fn do_stuff() {}\n",
    );
    write_config(
        dir.path(),
        r##"
rules:
  naming.boolean-prefix:
    enabled: true
    options:
      predicatePrefixes: ["requires_"]
  naming.placeholder-identifier:
    enabled: true
    options:
      extraPlaceholders: ["tmp"]
  naming.generic-function:
    enabled: true
    options:
      extraGenericNames: ["do_stuff"]
"##,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    // predicatePrefixes accepts `requires_init` → no boolean-prefix finding for that fn
    assert!(
        !report.findings.iter().any(|finding| {
            finding.rule_id == "naming.boolean-prefix"
                && finding.symbol.as_deref() == Some("requires_init")
        }),
        "predicatePrefixes must silence requires_init; findings={:?}",
        report
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.symbol))
            .collect::<Vec<_>>()
    );

    // extraPlaceholders catches `tmp`
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "naming.placeholder-identifier"
                && finding.symbol.as_deref() == Some("tmp")
        }),
        "extraPlaceholders must flag `tmp`; findings={:?}",
        report
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.symbol))
            .collect::<Vec<_>>()
    );

    // extraGenericNames catches `do_stuff`
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "naming.generic-function"
                && finding.symbol.as_deref() == Some("do_stuff")
        }),
        "extraGenericNames must flag `do_stuff`; findings={:?}",
        report
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.symbol))
            .collect::<Vec<_>>()
    );

    // Wrong shape: predicatePrefixes is a number, not an array
    write_config(
        dir.path(),
        r##"
rules:
  naming.boolean-prefix:
    options:
      predicatePrefixes: 7
"##,
    );
    let error = load_config(dir.path(), &default_test_options())
        .expect_err("non-array option value must be rejected");
    assert!(
        error.contains("`rules.naming.boolean-prefix.options.predicatePrefixes`")
            && error.to_lowercase().contains("array"),
        "unexpected error: {error}"
    );

    // Wrong rule: predicatePrefixes on naming.placeholder-identifier
    write_config(
        dir.path(),
        r##"
rules:
  naming.placeholder-identifier:
    options:
      predicatePrefixes: ["foo"]
"##,
    );
    let error = load_config(dir.path(), &default_test_options())
        .expect_err("unknown option must be rejected");
    assert!(
        error.contains("predicatePrefixes") && error.contains("naming.placeholder-identifier"),
        "unexpected error: {error}"
    );
}

/// M35 calibration: `naming.boolean-prefix` accepts idiomatic Rust
/// predicate names (subject-predicate form, common predicate verbs) while
/// keeping passive shapes like `triggered_by` flagged.
#[test]
fn m35_boolean_prefix_accepts_idioms_and_flags_passive() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn visibility_is_public() -> bool { true }
/// Probe.
pub fn path_is_project_ignored() -> bool { true }
/// Probe.
pub fn line_in_ranges() -> bool { true }
/// Probe.
pub fn path_matches() -> bool { true }
/// Probe.
pub fn starts_with_prefix() -> bool { true }
/// Probe.
pub fn ends_with_suffix() -> bool { true }
/// Probe.
pub fn matches() -> bool { true }
/// Probe.
pub fn contains() -> bool { true }
/// Probe.
pub fn triggered_by() -> bool { true }
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let predicate_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "naming.boolean-prefix")
        .collect();
    let triggered_by_count = predicate_findings
        .iter()
        .filter(|f| f.symbol.as_deref() == Some("triggered_by"))
        .count();
    assert_eq!(
        triggered_by_count, 1,
        "triggered_by must still be flagged; findings={predicate_findings:?}"
    );
    for accepted in [
        "visibility_is_public",
        "path_is_project_ignored",
        "line_in_ranges",
        "path_matches",
        "starts_with_prefix",
        "ends_with_suffix",
        "matches",
        "contains",
    ] {
        let still_flagged = predicate_findings
            .iter()
            .any(|f| f.symbol.as_deref() == Some(accepted));
        assert!(
                !still_flagged,
                "{accepted} must be accepted by the idiom-aware predicate rule; findings={predicate_findings:?}"
            );
    }
}

/// M35 negative: prose inside Rust comments must not trigger code-pattern
/// line rules. `naming.short-variable`, `naming.placeholder-identifier`,
/// `waste.unwrap-expect`, and `waste.unnecessary-clone-candidate` all run
/// off the code-only line view that masks comments to spaces. The
/// `security.unsafe-block` rule remains comment-aware so it can still
/// find nearby `SAFETY:` rationale comments.
#[test]
fn m35_line_rules_skip_prose_in_comments() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"//! Probe.
//
// Documentation prose with code-shaped fragments that must stay silent:
//   - "for a built-in rule" (naming.short-variable false-positive bait)
//   - `let foo = ...` (naming.placeholder-identifier bait)
//   - `.unwrap()` mentioned in prose (waste.unwrap-expect bait)
//   - `.clone()` mentioned in prose (waste.unnecessary-clone-candidate bait)

/// for a, this is a documentation paragraph that mentions `.unwrap()` and `.clone()`
/// and even shows `let foo = bar;` as an example. None of these should fire.
pub fn well_documented(name: String) -> String {
    /* a block comment also mentioning .unwrap() and .clone() and let foo = ... */
    name
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    for rule in [
        "naming.short-variable",
        "naming.placeholder-identifier",
        "waste.unwrap-expect",
        "waste.unnecessary-clone-candidate",
    ] {
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule),
            "{rule} must not fire on prose in comments; findings={:?}",
            report
                .findings
                .iter()
                .filter(|f| f.rule_id == rule)
                .map(|f| f.line)
                .collect::<Vec<_>>()
        );
    }
}

/// M35 negative: `security.unsafe-block` must STILL find nearby `SAFETY:`
/// rationale comments after the M35 raw/code-only split. The unsafe-block
/// rule uses the raw (comment-preserved) line view so it can read the
/// `SAFETY:` marker.
#[test]
fn m35_unsafe_block_still_sees_safety_rationale_comment() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn explained() {
    // SAFETY: this is a synthetic fixture, no actual unsafety.
    unsafe {
        std::ptr::null::<i32>();
    }
}

/// Probe.
pub fn unexplained() {
    unsafe {
        std::ptr::null::<i32>();
    }
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let unsafe_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.unsafe-block")
        .collect();
    assert_eq!(
            unsafe_findings.len(),
            1,
            "expected exactly one unsafe-block finding (the unexplained one); findings={unsafe_findings:?}"
        );
}

/// M35 negative: external-public-API rules must not fire on `pub(crate)`,
/// `pub(super)`, or `pub(in path)` items. Those are crate-visible (so
/// dead-code / reachability rules still see them as reachable) but they
/// are NOT part of the external API surface, so reportable rules stay
/// silent. The corresponding `pub` bare positives are covered by the
/// existing fixture-based proofs.
#[test]
fn m35_external_public_rules_skip_crate_visible_items() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"//! Probe.
pub(crate) struct Buckets {
    pub(crate) primary: Vec<u32>,
    pub(super) seen: u32,
}

pub(crate) fn maybe_one(value: Option<u32>) -> u32 {
    value.unwrap()
}

pub(crate) fn entry_a() {}
pub(crate) fn entry_b() {}
pub(crate) fn entry_c() {}
pub(crate) fn entry_d() {}
pub(crate) fn entry_e() {}
pub(crate) fn entry_f() {}
pub(crate) fn entry_g() {}
pub(crate) fn entry_h() {}
pub(crate) fn entry_i() {}
pub(crate) fn entry_j() {}
pub(crate) fn entry_k() {}
pub(crate) fn entry_l() {}
pub(crate) fn entry_m() {}
pub(crate) fn entry_n() {}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    for rule in [
        "modernisation.public-field",
        "docs.missing-public-doc",
        "error-handling.public-unwrap",
        "architecture.public-api-surface",
    ] {
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule),
            "{rule} must not fire on crate-visible items; findings={:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.rule_id, f.line))
                .collect::<Vec<_>>()
        );
    }
    // The broader (non-public-API) unwrap rule SHOULD still fire on the
    // production unwrap inside `maybe_one`, even though the public-API
    // rule does not.
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "waste.unwrap-expect"),
        "waste.unwrap-expect must still fire on production unwraps regardless of visibility"
    );
}

/// M33 negative: `waste.unnecessary-clone-candidate` must skip clones
/// whose result is immediately consumed by ownership-taking calls
/// (`unwrap_or_else`, `unwrap_or`, `unwrap_or_default`, `into`, `into_iter`,
/// `collect`, `?` propagation), struct-field initialisation, or
/// `HashMap::entry/insert` keys. These are not avoidable clones.
#[test]
fn m33_unnecessary_clone_candidate_skips_consumed_or_owned_uses() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
use std::collections::HashMap;

pub struct Row {
    pub name: String,
    pub tags: Vec<String>,
}

pub fn build(input: &Row, fallback: Option<String>) -> Row {
    let _consumed_unwrap = fallback.clone().unwrap_or_else(String::new);
    let _consumed_into: Vec<String> = input.tags.clone().into_iter().collect();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    by_name.entry(input.name.clone()).or_insert(0);
    Row {
        name: input.name.clone(),
        tags: input.tags.clone(),
    }
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let clones: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "waste.unnecessary-clone-candidate")
        .collect();
    assert!(
        clones.is_empty(),
        "consumed/owned clones must stay silent; findings={clones:?}"
    );
}

/// M38 negative: `waste.unnecessary-clone-candidate` must skip clones
/// inside `#[test]` fns and any fn inside a `#[cfg(test)]` module, so the
/// rule stays symmetric with `waste.unwrap-expect`, whose
/// `analyse_waste_line` branch already applies
/// `!line.contains("#[test]") && !self.line_is_in_test_context(...)`.
/// A production clone outside any test context must still fire so the
/// guard does not silence real waste.
#[test]
fn m38_unnecessary_clone_candidate_skips_test_context() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn entry(value: &String) -> String {
    value.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_setup(seed: &String) -> String {
        seed.clone()
    }

    #[test]
    fn check() {
        let original = String::from("x");
        let _copy = original.clone();
        let _via = shared_setup(&original);
    }
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let clones: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "waste.unnecessary-clone-candidate")
        .collect();
    assert_eq!(
            clones.len(),
            1,
            "expected exactly one clone finding (the production one in `pub fn entry`); findings={clones:?}"
        );
}

/// M33 negative: `metrics.halstead-volume` must not count string-literal
/// content as tokens. A long `format!(concat!(...))` HTML template with
/// dense string fragments inside should still stay below the threshold —
/// only the wrapping `format`, `concat`, punctuation, and `{}` placeholder
/// tokens count.
#[test]
fn m33_halstead_volume_skips_string_literal_tokens() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let mut body =
        String::from("/// Probe.\npub fn render(name: &str) -> String {\n    format!(concat!(\n");
    for _ in 0..120 {
        body.push_str(
                "        \"<div class=\\\"row\\\"><span>some literal text inside that should not count toward tokens at all</span></div>\\n\",\n",
            );
    }
    body.push_str("        \"{}\"\n    ), name)\n}\n");
    baseline_with_lib(dir.path(), &body);
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let hv: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "metrics.halstead-volume")
        .collect();
    assert!(
        hv.is_empty(),
        "long format!(concat!(...)) template must stay below halstead threshold; findings={hv:?}"
    );
}

/// M33 negative: `size.function-length` must skip a function whose body is
/// a single declarative literal (here, a 70-entry `vec![...]`). Function
/// length is intended to flag logic, not table-data registries.
#[test]
fn m33_function_length_skips_declarative_vec_body() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let mut body = String::from("/// Probe.\npub fn registry() -> Vec<i32> {\n    vec![\n");
    for index in 0..70 {
        body.push_str(&format!("        {index},\n"));
    }
    body.push_str("    ]\n}\n");
    baseline_with_lib(dir.path(), &body);
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let size_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "size.function-length")
        .collect();
    assert!(
        size_findings.is_empty(),
        "70-entry vec![...] body must not trigger size.function-length; findings={size_findings:?}"
    );
}

/// M33 negative: `waste.unwrap-expect` must skip test code (functions
/// annotated with `#[test]` and any function inside a `#[cfg(test)]`
/// module). The dedicated `test-quality.unwrap-in-test` rule covers the
/// test-side concern.
#[test]
fn m33_unwrap_expect_skips_cfg_test_module() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn entry() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_setup() -> i32 {
        let value: Option<i32> = Some(1);
        value.unwrap()
    }

    #[test]
    fn check() {
        let v: Option<i32> = Some(2);
        assert_eq!(v.unwrap(), 2);
        let _ = shared_setup();
    }
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let waste: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "waste.unwrap-expect")
        .collect();
    assert!(
        waste.is_empty(),
        "unwrap-expect must skip #[cfg(test)] module functions; findings={waste:?}"
    );
    let in_test: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "test-quality.unwrap-in-test")
        .collect();
    assert!(
        !in_test.is_empty(),
        "test-quality.unwrap-in-test must still fire on test-mode unwraps; findings={:?}",
        report
            .findings
            .iter()
            .map(|f| &f.rule_id)
            .collect::<Vec<_>>()
    );
}

/// M33 negative: prove the literal mask handles Rust character literals
/// such as `trim_matches('"')`. Without char-literal awareness, the `"`
/// inside `'"'` flips the masker into string mode and every later string
/// in the file is masked one off, leaking later `Command::new` text inside
/// `concat!()` fixtures into the regex search. This test embeds the exact
/// shape (a char-literal `'"'` followed by a `concat!(...)` fixture
/// containing a fake `Command::new`) and expects zero findings.
#[test]
fn m33_process_command_silent_after_char_literal_quote() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn fixture(name: &str) -> String {
    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    let body = concat!(
        "pub fn run_src() {\n",
        "    std::process::Command::new(\"sh\").spawn().unwrap();\n",
        "}\n"
    );
    format!("{trimmed} {body}")
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let command_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.process-command")
        .collect();
    assert!(
        command_findings.is_empty(),
        "char-literal `'\"'` must not flip the string mask; findings={command_findings:?}"
    );
}

/// Proves that test-context functions keep dedicated test-quality checks
/// without also receiving production complexity, metric, and size findings.
#[test]
fn calibration_complexity_metrics_size_skip_test_context() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let mut body = String::from(
            "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod fixtures {\n    #[test]\n    fn long_setup() {\n        let mut total = 0;\n",
        );
    for index in 0..90 {
        body.push_str(&format!("        if {index} > 0 {{ total += {index}; }}\n"));
    }
    body.push_str("        assert_eq!(total, 4005);\n    }\n}\n");
    baseline_with_lib(dir.path(), &body);
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert_has_rule(&report, "test-quality.long-test");
    for rule_id in [
        "size.function-length",
        "complexity.cyclomatic",
        "complexity.nesting-depth",
        "complexity.npath",
        "complexity.cognitive",
        "metrics.halstead-volume",
        "metrics.maintainability-pressure",
    ] {
        assert!(
            !report.findings.iter().any(|finding| {
                finding.rule_id == rule_id && finding.symbol.as_deref() == Some("long_setup")
            }),
            "calibration expected `{rule_id}` to skip test function `long_setup`; findings={:?}",
            rule_ids(&report)
        );
    }
}

/// Proves that `sensitive-data.api-key-pattern` recognises common synthetic
/// provider-shaped tokens beyond the original narrow prefix set.
#[test]
fn calibration_api_key_pattern_detects_common_formats() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn entry() {
    let _stripe_test = "sk_test_aaaaaaaaaaaaaaaaaaaaaaaa";
    let _stripe_pub = "pk_live_aaaaaaaaaaaaaaaaaaaaaaaa";
    let _github_oauth = "gho_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _openai_legacy = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _google_api = "AIzaSyAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _azure_bus = "Endpoint=sb://example.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
}
"#,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let api_key_findings = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.api-key-pattern")
        .count();
    assert_eq!(
        api_key_findings,
        6,
        "calibration expected all common synthetic API-key formats to fire; findings={:?}",
        rule_ids(&report)
    );
}

/// Proves that `sensitive-data.hardcoded-env-value` still catches
/// production Rust literals but ignores fixture strings in test context.
#[test]
fn calibration_hardcoded_env_value_skips_test_fixture_strings() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn entry() {
    let production = "DATABASE_PASSWORD=production-secret-123";
    assert!(production.contains("DATABASE_PASSWORD"));
}

#[cfg(test)]
mod fixtures {
    #[test]
    fn fixture_text_contains_secret_pattern() {
        let fixture = "DATABASE_PASSWORD=correct-horse-battery-123";
        assert!(fixture.contains("PASSWORD"));
    }
}
"#,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let hardcoded_env_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.hardcoded-env-value")
        .collect();
    assert_eq!(
        hardcoded_env_findings.len(),
        1,
        "calibration expected only the production env-style assignment to fire; findings={:?}",
        rule_ids(&report)
    );
    assert_eq!(hardcoded_env_findings[0].line, Some(3));
}
