//! Diff-filter regressions verify line, hunk, and symbol selection over reports.
//! Users reach these paths through changed-region CLI flags, where function blocks
//! must keep stable anchors while filtering findings to the requested patch scope.

use super::*;

#[test]
pub(crate) fn diff_patch_filter_keeps_only_changed_lines_and_line_less_findings() {
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
                Pillar::Maintainability,
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

    let filtered = apply_diff_patch_filter(report, &patch, &analysed, &Config::default());

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
pub(crate) fn diff_patch_filter_excludes_context_lines() {
    let report = sample_report_with(
        vec![
            test_finding(
                "dead-code.unused-private-function",
                "src/lib.rs",
                1,
                Severity::Advisory,
                Pillar::DeadCode,
            ),
            test_finding(
                "dead-code.unused-private-item-candidate",
                "src/lib.rs",
                2,
                Severity::Advisory,
                Pillar::DeadCode,
            ),
        ],
        Vec::new(),
    );
    let patch = parse_unified_diff(concat!(
        "diff --git a/src/lib.rs b/src/lib.rs\n",
        "--- a/src/lib.rs\n",
        "+++ b/src/lib.rs\n",
        "@@ -1,2 +1,2 @@\n",
        " fn context() {}\n",
        "-fn old() {}\n",
        "+fn changed() {}\n",
    ));
    let analysed = BTreeSet::from(["src/lib.rs".to_string()]);

    let filtered = apply_diff_patch_filter(report, &patch, &analysed, &Config::default());

    assert_eq!(filtered.findings.len(), 1);
    assert_eq!(filtered.findings[0].line, Some(2));
}

#[test]
pub(crate) fn changed_region_symbol_scope_keeps_signature_finding_for_changed_body() {
    let report = sample_report_with(
        vec![
            test_finding(
                "docs.missing-function-doc",
                "src/lib.rs",
                1,
                Severity::Warning,
                Pillar::Documentation,
            ),
            test_finding(
                "docs.missing-function-doc",
                "src/lib.rs",
                10,
                Severity::Warning,
                Pillar::Documentation,
            ),
        ],
        Vec::new(),
    );
    let mut patch = DiffPatchLineMap::default();
    patch
        .lines_by_file
        .insert("src/lib.rs".to_string(), BTreeSet::from([3]));
    let analysed = BTreeSet::from(["src/lib.rs".to_string()]);
    let mut blocks = BTreeMap::new();
    blocks.insert(
        "src/lib.rs".to_string(),
        vec![
            function_block("changed", 1, 4),
            function_block("old", 10, 2),
        ],
    );

    let filtered = apply_changed_region_filter(
        report,
        &patch,
        &analysed,
        &Config::default(),
        &blocks,
        ChangedScope::Symbol,
    );

    assert_eq!(filtered.findings.len(), 1);
    assert_eq!(filtered.findings[0].line, Some(1));
    assert_eq!(filtered.suppressed_count, Some(1));
}

#[test]
pub(crate) fn changed_region_hunk_scope_excludes_signature_only_finding() {
    let report = sample_report_with(
        vec![test_finding(
            "docs.missing-function-doc",
            "src/lib.rs",
            1,
            Severity::Warning,
            Pillar::Documentation,
        )],
        Vec::new(),
    );
    let mut patch = DiffPatchLineMap::default();
    patch
        .lines_by_file
        .insert("src/lib.rs".to_string(), BTreeSet::from([3]));
    let analysed = BTreeSet::from(["src/lib.rs".to_string()]);
    let mut blocks = BTreeMap::new();
    blocks.insert(
        "src/lib.rs".to_string(),
        vec![function_block("changed", 1, 4)],
    );

    let filtered = apply_changed_region_filter(
        report,
        &patch,
        &analysed,
        &Config::default(),
        &blocks,
        ChangedScope::Hunk,
    );

    assert!(filtered.findings.is_empty());
    assert_eq!(filtered.suppressed_count, Some(1));
}

#[test]
pub(crate) fn diff_patch_rejects_non_unified_input_before_suppressing_findings() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("src/lib.rs"), "fn unused() {}\n").expect("lib write");
    fs::write(dir.path().join("names.patch"), "src/lib.rs\n").expect("patch write");

    let error = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            diff: Some(DiffSelection::Patch {
                path: PathBuf::from("names.patch"),
                scope: ChangedScope::Symbol,
            }),
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect_err("non-unified diff rejected");

    assert!(
        error.contains("not a parseable unified diff"),
        "unexpected error: {error}"
    );
}

#[test]
pub(crate) fn diff_patch_analysis_filters_after_baseline_without_failing_on_summary_diagnostic() {
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
        diff: Some(DiffSelection::Patch {
            path: patch_path,
            scope: ChangedScope::Symbol,
        }),
        no_baseline: true,
        ..default_test_options()
    };

    let report = run_project_analysis(Path::new("."), options).expect("analysis succeeds");

    assert!(report.findings.len() < 12);
    assert!(!report.findings.is_empty());
    assert!(report
        .findings
        .iter()
        .all(|finding| finding.file_path == "fixtures/sample.rs"));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.line == Some(11)));
    assert!(report.suppressed_count.is_some());
    assert_eq!(
        report
            .diagnostics
            .last()
            .map(|diagnostic| diagnostic.diagnostic_type.as_str()),
        Some("patch-filter")
    );
    assert_eq!(
        RunOutcome::classify(&report, FailThreshold::None, None),
        RunOutcome::Success
    );
}

#[test]
pub(crate) fn diff_patch_scope_all_gate_counts_baselined_findings_in_changed_region() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(
        dir.path().join("src/lib.rs"),
        "pub fn run(cmd: &str) { let _ = std::process::Command::new(cmd).spawn(); }\n",
    )
    .expect("source write");
    run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            generate_baseline: Some(PathBuf::from("gruff-baseline.json")),
            ..default_test_options()
        },
    )
    .expect("baseline generation succeeds");
    write_config(
        dir.path(),
        "gate:\n  scope: all\n  severity:\n    warning: 0\n",
    );
    let patch_path = dir.path().join("change.patch");
    fs::write(
        &patch_path,
        concat!(
            "diff --git a/src/lib.rs b/src/lib.rs\n",
            "--- a/src/lib.rs\n",
            "+++ b/src/lib.rs\n",
            "@@ -1,1 +1,1 @@\n",
            "+pub fn run(cmd: &str) { let _ = std::process::Command::new(cmd).spawn(); }\n",
        ),
    )
    .expect("patch write");
    let options = AnalysisOptions {
        paths: vec![PathBuf::from(".")],
        no_config: false,
        baseline: Some(PathBuf::from("gruff-baseline.json")),
        no_baseline: false,
        diff: Some(DiffSelection::Patch {
            path: patch_path,
            scope: ChangedScope::Symbol,
        }),
        ..default_test_options()
    };
    let config = load_config(dir.path(), &options).expect("config loads");
    let mut report =
        run_analysis_in_project(dir.path(), &options, &config).expect("analysis succeeds");

    assert_eq!(report.summary.warning, 0, "baselined warnings stay hidden");
    assert_eq!(
        report
            .baseline
            .as_ref()
            .map(|baseline| baseline.unchanged_count),
        Some(4),
        "baseline should classify the current findings as unchanged"
    );
    assert!(
        config
            .gate
            .as_ref()
            .expect("gate configured")
            .evaluate_report(&report)
            .fails,
        "scope: all must count the baselined warning in the changed region"
    );
    apply_gate_diagnostic(&mut report, config.gate.as_ref());
    assert_eq!(
        RunOutcome::classify(&report, FailThreshold::None, config.gate.as_ref()),
        RunOutcome::ThresholdHit
    );
}

#[test]
pub(crate) fn diff_patch_diagnostics_are_sarif_notifications_without_failed_execution() {
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
pub(crate) fn diff_patch_filter_emits_per_rule_deltas_for_inside_and_outside_findings() {
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
                11,
                Severity::Advisory,
                Pillar::Maintainability,
            ),
            test_finding(
                "docs.missing-public-doc",
                "src/other.rs",
                7,
                Severity::Advisory,
                Pillar::Documentation,
            ),
        ],
        Vec::new(),
    );
    let patch = parse_unified_diff(
        "\
diff --git a/src/lib.rs b/src/lib.rs\n\
--- a/src/lib.rs\n\
+++ b/src/lib.rs\n\
@@ -10,1 +11,1 @@\n\
+changed\n",
    );
    let analysed = BTreeSet::from(["src/lib.rs".to_string(), "src/other.rs".to_string()]);

    let filtered = apply_diff_patch_filter(report, &patch, &analysed, &Config::default());

    let deltas = filtered
        .per_rule_deltas
        .as_ref()
        .expect("diff filter populates per_rule_deltas");
    let process_command = deltas
        .iter()
        .find(|delta| delta.rule_id == "security.process-command")
        .expect("process-command finding inside patch");
    assert_eq!(process_command.introduced, 1);
    assert_eq!(process_command.removed, 0);
    assert_eq!(process_command.net, 1);
    let docs = deltas
        .iter()
        .find(|delta| delta.rule_id == "docs.missing-public-doc")
        .expect("docs finding outside patch");
    assert_eq!(docs.introduced, 0);
    assert_eq!(docs.removed, 1);
    assert_eq!(docs.net, -1);
}

/// Build a minimal function block for changed-region identity and scope tests.
fn function_block(
    name: &str,
    start_line: usize,
    line_count: usize,
) -> crate::built_in_rules::FunctionBlock {
    crate::built_in_rules::FunctionBlock {
        name: name.to_string(),
        param_count: 0,
        start_line,
        line_count,
        executable_line_count: line_count,
        body: String::new(),
        rustdoc: None,
        is_externally_public: true,
        is_test: false,
        test_context: false,
        is_async: false,
        returns_bool: false,
        returns_result: false,
        ignore_without_reason: false,
        body_is_declarative_literal: false,
    }
}
