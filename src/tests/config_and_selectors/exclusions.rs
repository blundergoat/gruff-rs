use super::*;

#[test]
pub(crate) fn exclusion_filter_counts_rule_path_message_and_unmatched_entries() {
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
        Finding::new(FindingDescriptor {
            rule_id: "size.parameter-count".to_string(),
            message: "too many params".to_string(),
            file_path: "src/lib.rs".to_string(),
            line: Some(9),
            severity: Severity::Warning,
            pillar: Pillar::Size,
            confidence: Confidence::High,
            symbol: Some("process".to_string()),
            remediation: None,
            metadata: json!({}),
        }),
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
pub(crate) fn exclusion_config_rejects_missing_reason_unknown_rule_and_bad_shapes() {
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
pub(crate) fn exclusion_config_reuses_rule_selector_parsing() {
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
pub(crate) fn report_level_exclusions_hide_findings_without_skipping_discovery() {
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
