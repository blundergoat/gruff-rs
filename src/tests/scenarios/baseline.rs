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
