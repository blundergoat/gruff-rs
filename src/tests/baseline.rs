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

