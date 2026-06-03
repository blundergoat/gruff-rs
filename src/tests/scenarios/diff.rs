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

fn function_block(name: &str, start_line: usize, line_count: usize) -> FunctionBlock {
    FunctionBlock {
        name: name.to_string(),
        param_count: 0,
        start_line,
        line_count,
        body: String::new(),
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
pub(crate) fn diff_flags_accept_changed_region_forms() {
    // Git-executing modes require the --diff-git-unsafe opt-in (ADR-009 trust boundary).
    // The opt-in goes first: `--diff` allows hyphen values, so it would otherwise
    // swallow a trailing `--diff-git-unsafe` as its MODE.
    assert!(Cli::try_parse_from(["gruff-rs", "analyse", "--diff-git-unsafe", "--diff"]).is_ok());
    assert!(
        Cli::try_parse_from(["gruff-rs", "analyse", "--diff-git-unsafe", "--diff", "-"]).is_ok()
    );
    assert!(Cli::try_parse_from([
        "gruff-rs",
        "analyse",
        "--diff-git-unsafe",
        "--since",
        "HEAD"
    ])
    .is_ok());
    // ...and are rejected without it.
    assert!(Cli::try_parse_from(["gruff-rs", "analyse", "--diff"]).is_err());
    assert!(Cli::try_parse_from(["gruff-rs", "analyse", "--since", "HEAD"]).is_err());
    // Git-free modes need no opt-in.
    assert!(Cli::try_parse_from(["gruff-rs", "analyse", "--changed-ranges", "3-3,8-10"]).is_ok());
    assert!(Cli::try_parse_from(["gruff-rs", "analyse", "--changed-scope", "hunk"]).is_ok());

    let mut command = Cli::command();
    let help = command
        .find_subcommand_mut("analyse")
        .expect("analyse subcommand exists")
        .render_long_help()
        .to_string();
    assert!(help.contains("--since"));
    assert!(help.contains("--changed-ranges"));
    assert!(help.contains("--changed-scope"));
    assert!(!help.contains("--diff-git-unsafe"));
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

/// Two undocumented public functions for the changed-region trio tests below.
/// `alpha` occupies lines 1-7; a blank line 8 precedes `beta` on lines 9-15.
/// Each draws one `docs.missing-public-doc` finding anchored at its
/// function-block start (line 1 for `alpha`, line 8 for `beta`, since the block
/// start absorbs the leading blank line). Exercising these through
/// `--changed-ranges` drives the real range parse and AST block extraction, not
/// hand-built blocks.
const UNDOCUMENTED_FUNCTIONS_FIXTURE: &str = "\
pub fn alpha(seed: u32) -> u32 {
    let mut total = 0;
    for value in 0..seed {
        total += value;
    }
    total
}

pub fn beta(seed: u32) -> u32 {
    let mut total = 1;
    for value in 1..seed {
        total *= value;
    }
    total
}
";

fn undocumented_functions_project() -> tempfile::TempDir {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), UNDOCUMENTED_FUNCTIONS_FIXTURE).expect("fixture write");
    dir
}

fn full_file_options() -> AnalysisOptions {
    AnalysisOptions {
        paths: vec![PathBuf::from("sample.rs")],
        no_config: true,
        no_baseline: true,
        ..default_test_options()
    }
}

fn changed_region_options(ranges: &str, scope: ChangedScope) -> AnalysisOptions {
    AnalysisOptions {
        diff: Some(DiffSelection::ExplicitRanges {
            ranges: ranges.to_string(),
            scope,
        }),
        ..full_file_options()
    }
}

// End-to-end symbol-scope widening through the live `--changed-ranges` path: a
// line strictly inside `alpha`'s body (line 4) must keep `alpha`'s
// signature-anchored finding and suppress everything outside the symbol, while
// the same line under hunk scope keeps nothing (no finding sits on line 4). The
// suppressed count must account for every finding outside the kept set, pinning
// `in_region + suppressedCount == full_file_count`.
#[test]
pub(crate) fn changed_ranges_symbol_scope_widens_to_enclosing_function() {
    let _guard = analysis_lock();
    let project = undocumented_functions_project();

    let full = run_project_analysis(project.path(), full_file_options())
        .expect("full-file analysis succeeds");
    let total = full.findings.len();
    assert!(
        ["alpha", "beta"]
            .iter()
            .all(|name| full.findings.iter().any(|finding| {
                finding.rule_id == "docs.missing-public-doc"
                    && finding.symbol.as_deref() == Some(name)
            })),
        "fixture must yield a missing-public-doc finding for both functions; got {:?}",
        full.findings
            .iter()
            .map(|finding| (&finding.rule_id, &finding.symbol))
            .collect::<Vec<_>>()
    );

    let symbol = run_project_analysis(
        project.path(),
        changed_region_options("4-4", ChangedScope::Symbol),
    )
    .expect("symbol-scope analysis succeeds");
    assert!(
        symbol
            .findings
            .iter()
            .any(|finding| finding.symbol.as_deref() == Some("alpha")),
        "symbol scope must keep alpha's signature finding for a body-only change"
    );
    assert!(
        !symbol
            .findings
            .iter()
            .any(|finding| finding.symbol.as_deref() == Some("beta")),
        "beta is outside the changed symbol and must be suppressed"
    );
    assert!(
        symbol.findings.len() < total,
        "something outside alpha must be suppressed"
    );
    assert_eq!(
        symbol.suppressed_count,
        Some(total - symbol.findings.len()),
        "suppressed_count must account for every finding outside the changed symbol"
    );

    let hunk = run_project_analysis(
        project.path(),
        changed_region_options("4-4", ChangedScope::Hunk),
    )
    .expect("hunk-scope analysis succeeds");
    assert!(
        hunk.findings.is_empty(),
        "hunk scope must not keep findings off the changed line; got {:?}",
        hunk.findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.line))
            .collect::<Vec<_>>()
    );
    assert_eq!(hunk.suppressed_count, Some(total));
}

// `--no-baseline` must override an applied baseline in changed-region mode. The
// agent hook always passes `--no-baseline`, so a stray baseline (explicit or the
// default `gruff-baseline.json`) can never silently hide findings from the
// agent. With the baseline applied, the in-region finding is matched and removed
// before the region filter; with `--no-baseline` it re-surfaces.
#[test]
pub(crate) fn no_baseline_resurfaces_baselined_findings_in_changed_region() {
    let _guard = analysis_lock();
    let project = undocumented_functions_project();

    run_project_analysis(
        project.path(),
        AnalysisOptions {
            generate_baseline: Some(PathBuf::from("baseline.json")),
            ..full_file_options()
        },
    )
    .expect("baseline generation succeeds");

    let with_baseline = run_project_analysis(
        project.path(),
        AnalysisOptions {
            baseline: Some(PathBuf::from("baseline.json")),
            no_baseline: false,
            ..changed_region_options("4-4", ChangedScope::Symbol)
        },
    )
    .expect("baseline-applied analysis succeeds");
    assert!(
        !with_baseline
            .findings
            .iter()
            .any(|finding| finding.symbol.as_deref() == Some("alpha")),
        "an applied baseline must suppress alpha even inside the changed region"
    );
    assert!(
        with_baseline
            .baseline
            .as_ref()
            .is_some_and(|baseline| baseline.suppressed >= 1),
        "baseline report must record the suppression"
    );

    let no_baseline = run_project_analysis(
        project.path(),
        AnalysisOptions {
            baseline: Some(PathBuf::from("baseline.json")),
            no_baseline: true,
            ..changed_region_options("4-4", ChangedScope::Symbol)
        },
    )
    .expect("no-baseline analysis succeeds");
    assert!(
        no_baseline.baseline.is_none(),
        "--no-baseline must leave report.baseline None even with --baseline set"
    );
    assert!(
        no_baseline.findings.iter().any(|finding| {
            finding.rule_id == "docs.missing-public-doc"
                && finding.symbol.as_deref() == Some("alpha")
        }),
        "--no-baseline must re-surface the baselined finding inside the changed region"
    );
}

// The agent hook reads the scoped report as JSON: it trusts gruff's scoping and
// reads the out-of-region total from the top-level `suppressedCount`. Pin both
// the serialized field name and the scoping so a refactor cannot silently drop
// the count or leak an out-of-region finding. A full-tree run must omit the
// field entirely, keeping the JSON schema unchanged for non-diff consumers.
#[test]
pub(crate) fn changed_region_json_carries_top_level_suppressed_count_and_scopes_findings() {
    let _guard = analysis_lock();
    let project = undocumented_functions_project();

    let full = run_project_analysis(project.path(), full_file_options())
        .expect("full-file analysis succeeds");
    let full_json = render_report(&full, OutputFormat::Json);
    assert!(
        !full_json.contains("suppressedCount"),
        "full-tree JSON must omit suppressedCount entirely:\n{full_json}"
    );

    let scoped = run_project_analysis(
        project.path(),
        changed_region_options("4-4", ChangedScope::Symbol),
    )
    .expect("changed-region analysis succeeds");
    let expected_suppressed = scoped
        .suppressed_count
        .expect("a diff run must set suppressed_count");
    assert!(
        expected_suppressed >= 1,
        "at least beta must be suppressed outside the changed symbol"
    );

    let rendered = render_report(&scoped, OutputFormat::Json);
    assert!(
        rendered.contains("\"suppressedCount\""),
        "scoped JSON must carry the top-level suppressedCount key:\n{rendered}"
    );
    let value: serde_json::Value = serde_json::from_str(&rendered).expect("scoped JSON parses");
    assert_eq!(
        value["suppressedCount"].as_u64(),
        Some(expected_suppressed as u64),
        "top-level suppressedCount must equal the out-of-region total"
    );
    let findings = value["findings"].as_array().expect("findings array");
    assert!(
        findings.iter().any(|finding| finding["symbol"] == "alpha"),
        "scoped JSON must keep the in-region (alpha) finding"
    );
    assert!(
        findings.iter().all(|finding| finding["symbol"] != "beta"),
        "scoped JSON must exclude the out-of-region (beta) finding"
    );
}
