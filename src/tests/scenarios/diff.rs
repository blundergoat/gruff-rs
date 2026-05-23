use super::*;

#[test]
pub(crate) fn diff_patch_parser_maps_new_side_lines_for_renames_crlf_and_deletions() {
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
        Some(&BTreeSet::from([11, 13]))
    );
    assert!(parsed.saw_hunk);
    assert_eq!(
        parsed.lines_by_file.get("src/delete.rs"),
        Some(&BTreeSet::new())
    );
    assert!(!parsed.lines_by_file.contains_key("bin.dat"));
    assert!(parse_unified_diff("").lines_by_file.is_empty());
    assert!(!parse_unified_diff("").saw_hunk);
}

#[test]
pub(crate) fn diff_patch_parser_handles_quoted_paths_and_plus_content_lines() {
    let patch = concat!(
        "diff --git \"a/src/\\303\\251.rs\" \"b/src/\\303\\251.rs\"\n",
        "--- \"a/src/\\303\\251.rs\"\n",
        "+++ \"b/src/\\303\\251.rs\"\n",
        "@@ -1,2 +1,3 @@\n",
        " context\n",
        "+++ not a file header\n",
        "+added\n",
    );

    let parsed = parse_unified_diff(patch);

    assert_eq!(
        parsed.lines_by_file.get("src/é.rs"),
        Some(&BTreeSet::from([2, 3]))
    );
}

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

    let filtered = apply_diff_patch_filter(report, &patch, &analysed);

    assert_eq!(filtered.findings.len(), 1);
    assert_eq!(filtered.findings[0].line, Some(2));
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
            diff: Some(DiffSelection::Patch(PathBuf::from("names.patch"))),
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
pub(crate) fn diff_requires_explicit_unsafe_git_flag() {
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
