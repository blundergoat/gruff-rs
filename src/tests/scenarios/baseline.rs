use super::*;

#[test]
pub(crate) fn baseline_generation_and_exact_suppression_are_stable() {
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
pub(crate) fn baseline_generation_and_failure_modes_are_reported_cleanly() {
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
pub(crate) fn baseline_deltas_do_not_over_count_duplicate_findings() {
    // PR #3 review: `run_analysis_in_project` used to call
    // `resolve_baseline` BEFORE `sort_and_dedupe_findings`, so a
    // duplicated raw finding (same fingerprint emitted twice) would be
    // counted twice toward `introduced` even though the final report
    // collapses it to one entry. Pin the dedupe-then-baseline order
    // here by constructing a fixture that produces duplicates and
    // asserting introduced == 1 (not 2).
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn one() {}\n").expect("fixture write");

    // Write a baseline that has NO entries — every finding from the
    // current scan is "introduced". With duplicates in the raw stream,
    // a buggy pipeline would over-count introduced.
    let baseline_path = dir.path().join("baseline.json");
    fs::write(
        &baseline_path,
        json!({
            "schemaVersion": "gruff.baseline.v1",
            "generatedAt": "2026-01-01T00:00:00Z",
            "entries": [],
        })
        .to_string(),
    )
    .expect("empty baseline write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("baseline analysis succeeds");

    // Whatever the final per-rule finding count is, introduced must
    // equal that count exactly (the empty baseline matches nothing).
    // Over-counted duplicates would push introduced above the final
    // per-rule finding count, which the loop below would catch.
    let deltas = report
        .per_rule_deltas
        .as_ref()
        .expect("baseline run populates per_rule_deltas");
    for delta in deltas {
        let final_count = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == delta.rule_id)
            .count();
        assert_eq!(
            delta.introduced, final_count,
            "introduced count for `{}` must equal final finding count, not pre-dedupe duplicates",
            delta.rule_id,
        );
    }
}

#[test]
pub(crate) fn full_tree_run_produces_no_per_rule_deltas() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("fixture write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert!(
        report.per_rule_deltas.is_none(),
        "full-tree runs must not populate per_rule_deltas; got {:?}",
        report.per_rule_deltas
    );

    let rendered_json = render_report(&report, OutputFormat::Json);
    assert!(
        !rendered_json.contains("perRuleDeltas"),
        "JSON output on a full-tree run must omit the perRuleDeltas key entirely:\n{rendered_json}"
    );
}

#[test]
pub(crate) fn baseline_run_emits_per_rule_deltas_with_introduced_and_removed_counts() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("sample.rs"),
        "pub fn one() {}\npub fn two() {}\npub fn three() {}\n",
    )
    .expect("fixture write");

    // Generate a baseline against the same fixture so every current
    // finding is suppressed. Then mutate the baseline file to drop one
    // entry (simulates a newly introduced finding on the next scan) and
    // append a synthetic entry under a rule id that the next scan
    // cannot reproduce (simulates a resolved finding).
    let baseline_path = dir.path().join("baseline.json");
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
    assert!(!generated.findings.is_empty());

    let mut baseline_json: Value =
        serde_json::from_str(&fs::read_to_string(&baseline_path).expect("baseline read"))
            .expect("baseline json");
    let entries = baseline_json["entries"]
        .as_array_mut()
        .expect("entries array");
    let dropped = entries.remove(0);
    let dropped_rule = dropped["ruleId"].as_str().expect("rule id").to_string();
    entries.push(json!({
        "fingerprint": "deadbeefdeadbeef",
        "ruleId": "ghost.removed-rule",
        "filePath": "sample.rs",
        "line": 1,
        "symbol": null,
        "message": "phantom",
    }));
    fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_json).expect("baseline serialize"),
    )
    .expect("baseline rewrite");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("baseline analysis succeeds");

    let deltas = report
        .per_rule_deltas
        .as_ref()
        .expect("baseline run must populate per_rule_deltas");
    let dropped_delta = deltas
        .iter()
        .find(|delta| delta.rule_id == dropped_rule)
        .expect("dropped rule appears as introduced");
    assert_eq!(dropped_delta.introduced, 1);
    assert_eq!(dropped_delta.removed, 0);
    let ghost_delta = deltas
        .iter()
        .find(|delta| delta.rule_id == "ghost.removed-rule")
        .expect("phantom rule appears as removed");
    assert_eq!(ghost_delta.removed, 1);
    assert_eq!(ghost_delta.introduced, 0);
    assert_eq!(ghost_delta.net, -1);
}

// M01 (ADR-002 addendum): baseline matching classifies each finding as new,
// unchanged, or absent, and surfaces the counts on `BaselineReport` additively.
#[test]
pub(crate) fn baseline_tri_state_counts_classify_new_unchanged_absent() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("sample.rs"),
        "pub fn one() {}\npub fn two() {}\npub fn three() {}\n",
    )
    .expect("fixture write");

    // Generate a baseline that matches every current finding (all unchanged).
    let baseline_path = dir.path().join("baseline.json");
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
    let total = generated.findings.len();
    assert!(total >= 2, "fixture must produce >=2 findings, got {total}");
    // A generate run has no comparison context: counts are zero.
    let generated_baseline = generated.baseline.as_ref().expect("generated baseline");
    assert!(generated_baseline.generated);
    assert_eq!(generated_baseline.new_count, 0);
    assert_eq!(generated_baseline.unchanged_count, 0);
    assert_eq!(generated_baseline.absent_count, 0);

    // Re-scan against the unmodified baseline: every finding is unchanged.
    let all_unchanged = run_project_analysis(
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
    let unchanged_baseline = all_unchanged.baseline.as_ref().expect("baseline present");
    assert_eq!(unchanged_baseline.new_count, 0);
    assert_eq!(unchanged_baseline.unchanged_count, total);
    assert_eq!(unchanged_baseline.absent_count, 0);
    assert_eq!(
        unchanged_baseline.suppressed,
        unchanged_baseline.unchanged_count
    );
    assert!(
        all_unchanged.findings.is_empty(),
        "default list drops unchanged findings"
    );

    // Drop one baseline entry (its finding becomes new) and append a ghost entry
    // that matches no current finding (absent).
    let mut baseline_json: Value =
        serde_json::from_str(&fs::read_to_string(&baseline_path).expect("baseline read"))
            .expect("baseline json");
    baseline_json["entries"]
        .as_array_mut()
        .expect("entries array")
        .remove(0);
    baseline_json["entries"]
        .as_array_mut()
        .expect("entries array")
        .push(json!({
            "fingerprint": "deadbeefdeadbeef",
            "ruleId": "ghost.removed-rule",
            "filePath": "sample.rs",
            "line": 1,
            "symbol": null,
            "message": "phantom",
        }));
    fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_json).expect("baseline serialize"),
    )
    .expect("baseline rewrite");

    let mixed = run_project_analysis(
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
    let mixed_baseline = mixed.baseline.as_ref().expect("baseline present");
    assert_eq!(
        mixed_baseline.new_count, 1,
        "dropped entry's finding is new"
    );
    assert_eq!(mixed_baseline.unchanged_count, total - 1);
    assert_eq!(mixed_baseline.absent_count, 1, "ghost entry is absent");
    assert_eq!(mixed_baseline.suppressed, mixed_baseline.unchanged_count);
    // Default findings list = the new set only (unchanged dropped, absent not rendered).
    assert_eq!(mixed.findings.len(), mixed_baseline.new_count);
}

// M01: an empty baseline classifies every current finding as new; `--no-baseline`
// leaves the tri-state off entirely.
#[test]
pub(crate) fn baseline_tri_state_all_new_and_no_baseline_short_circuit() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn one() {}\n").expect("fixture write");

    let baseline_path = dir.path().join("baseline.json");
    fs::write(
        &baseline_path,
        json!({
            "schemaVersion": "gruff.baseline.v1",
            "generatedAt": "2026-01-01T00:00:00Z",
            "entries": [],
        })
        .to_string(),
    )
    .expect("empty baseline write");

    let all_new = run_project_analysis(
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
    let baseline = all_new.baseline.as_ref().expect("baseline present");
    assert_eq!(baseline.new_count, all_new.findings.len());
    assert_eq!(baseline.unchanged_count, 0);
    assert_eq!(baseline.absent_count, 0);
    assert!(baseline.new_count > 0);

    let no_baseline = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert!(
        no_baseline.baseline.is_none(),
        "--no-baseline must leave report.baseline None"
    );
}
