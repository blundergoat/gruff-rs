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
pub(crate) fn github_renderer_escapes_annotation_properties() {
    let report = sample_report_with(
        vec![Finding::new(FindingDescriptor {
            rule_id: "custom.rule:id".to_string(),
            message: "Message with 100% and\nnewline".to_string(),
            file_path: "src/weird,path:100%.rs".to_string(),
            line: Some(3),
            severity: Severity::Warning,
            pillar: Pillar::Documentation,
            confidence: Confidence::High,
            symbol: None,
            remediation: None,
            metadata: json!({}),
        })],
        Vec::new(),
    );

    let github = render_report(&report, OutputFormat::Github);

    assert!(github.starts_with(
        "::warning file=src/weird%2Cpath%3A100%25.rs,line=3,title=custom.rule%3Aid::"
    ));
    assert!(github.ends_with("Message with 100%25 and%0Anewline"));
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
pub(crate) fn summary_top_file_limit_is_not_capped_by_score_report() {
    let findings: Vec<Finding> = (0..12)
        .map(|index| {
            test_finding(
                "docs.todo-density",
                &format!("src/file_{index}.rs"),
                1,
                Severity::Advisory,
                Pillar::Documentation,
            )
        })
        .collect();
    let report = sample_report_with(findings, Vec::new());

    let json_output = crate::summary::render(&report, 12, SummaryFormat::Json, 1);
    let decoded: Value = serde_json::from_str(&json_output).expect("summary json");

    assert_eq!(decoded["topFiles"].as_array().expect("top files").len(), 12);
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

    let response = dashboard_response("/scan", &query, dir.path());

    assert_eq!(response.status, "200 OK");
    assert_eq!(std::env::current_dir().expect("cwd"), cwd_before);
    assert!(response.body.contains("Dashboard scan"));
    assert!(response.body.contains("sample.rs"));
    assert!(!response
        .body
        .contains(&dir.path().join("sample.rs").display().to_string()));
}

#[test]
pub(crate) fn dashboard_scan_rejects_absolute_or_escaping_paths() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("sample write");

    let outside_root = dashboard_response("/scan", "projectRoot=/&path=.", dir.path());
    assert_eq!(outside_root.status, "400 Bad Request");
    assert!(outside_root.body.contains("projectRoot must stay inside"));

    let absolute_path = dashboard_response("/scan", "path=/etc", dir.path());
    assert_eq!(absolute_path.status, "400 Bad Request");
    assert!(absolute_path.body.contains("path must be relative"));

    let parent_escape = dashboard_response("/scan", "path=../", dir.path());
    assert_eq!(parent_escape.status, "400 Bad Request");
    assert!(parent_escape.body.contains("path must stay inside"));

    let malformed_percent = dashboard_response("/scan", "path=%E2%82%AC&bad=%€", dir.path());
    assert_eq!(malformed_percent.status, "200 OK");
}
