use super::*;

#[test]
pub(crate) fn report_renderers_escape_and_preserve_contracts() {
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
pub(crate) fn report_json_keeps_deterministic_finding_order() {
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
pub(crate) fn dashboard_scan_preserves_cwd_and_report_paths() {
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

