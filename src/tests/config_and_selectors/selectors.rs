use super::*;

#[test]
pub(crate) fn selector_set_matches_registry_with_negative_precedence() {
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
        .filter(|rule_id| config.is_rule_enabled(rule_id))
        .collect();
    eprintln!("selector enabled ids: {enabled:?}");

    assert!(config.is_rule_enabled("security.unsafe-block"));
    assert!(!config.is_rule_enabled("security.process-command"));
    assert!(!config.is_rule_enabled("docs.missing-readme"));
}

#[test]
pub(crate) fn selector_config_supports_empty_pillar_prefix_exact_negative_and_custom_blocks() {
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
    assert!(config.is_rule_enabled("security.process-command"));
    assert!(config.is_rule_enabled("docs.missing-readme"));

    write_config(
        dir.path(),
        r#"
rules:
  select: ["Security"]
"#,
    );
    let config = load_config(dir.path(), &options).expect("pillar selector accepted");
    assert!(config.is_rule_enabled("security.process-command"));
    assert!(config.is_rule_enabled("security.unsafe-block"));
    assert!(!config.is_rule_enabled("docs.missing-readme"));

    write_config(
        dir.path(),
        r#"
rules:
  select: ["security"]
  ignore: ["security.process-command"]
"#,
    );
    let config = load_config(dir.path(), &options).expect("prefix and exact selectors accepted");
    assert!(!config.is_rule_enabled("security.process-command"));
    assert!(config.is_rule_enabled("security.unsafe-block"));
    assert!(!config.is_rule_enabled("docs.missing-readme"));

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
    assert!(!config.is_rule_enabled("security.unsafe-block"));
    assert!(!config.is_rule_enabled("security.process-command"));
}

#[test]
pub(crate) fn selector_config_rejects_unknown_pillar_prefix_exact_and_shapes() {
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
pub(crate) fn list_rules_selector_preview_is_deterministic() {
    let text = render_rule_list(
        Path::new("."),
        &ListRulesArgs {
            rule_id: None,
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
            "ci.github-event-shell-interpolation",
            "dependency.duplicate-locked-version",
            "dependency.git-source",
            "dependency.git-unpinned-revision",
            "dependency.path-source",
            "dependency.wildcard-version",
            "security.hardcoded-bind-all-interfaces",
            "security.insecure-rng-for-secrets",
            "security.path-traversal-candidate",
            "security.process-command",
            "security.sql-dynamic-query",
            "security.tls-verification-disabled",
            "security.unsafe-block",
            "security.weak-crypto"
        ]
    );

    let sensitive_text = render_rule_list(
        Path::new("."),
        &ListRulesArgs {
            rule_id: None,
            format: RuleListFormat::Text,
            selector: Some("sensitive-data".to_string()),
            config: None,
            no_config: true,
        },
    )
    .expect("sensitive-data selector preview");
    let sensitive_lines: Vec<&str> = sensitive_text.lines().collect();
    assert_eq!(
        sensitive_lines,
        vec![
            "sensitive-data.api-key-pattern",
            "sensitive-data.aws-access-key",
            "sensitive-data.database-url-password",
            "sensitive-data.hardcoded-env-value",
            "sensitive-data.high-entropy-string",
            "sensitive-data.jwt-token",
            "sensitive-data.pii-test-fixture",
            "sensitive-data.private-key",
            "sensitive-data.url-embedded-credentials"
        ]
    );

    let json_output = render_rule_list(
        Path::new("."),
        &ListRulesArgs {
            rule_id: None,
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
pub(crate) fn selected_text_only_rules_skip_rust_parse_work() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(
        dir.path().join("src/lib.rs"),
        "pub fn broken( {\nlet value = 1;\n",
    )
    .expect("lib write");
    write_config(
        dir.path(),
        r#"
rules:
  select: ["size.file-length"]
"#,
    );

    let report = run_project_analysis(dir.path(), default_test_options())
        .expect("selected size analysis succeeds");

    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert_missing_rule(&report, "docs.missing-readme");
}

#[test]
pub(crate) fn selected_rules_keep_rust_parse_when_rule_needs_ast() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(
        dir.path().join("src/lib.rs"),
        "pub fn broken( {\nlet value = 1;\n",
    )
    .expect("lib write");

    write_config(
        dir.path(),
        r#"
rules:
  select: ["complexity.cyclomatic"]
"#,
    );
    let rust_report = run_project_analysis(dir.path(), default_test_options())
        .expect("selected rust analysis succeeds");
    assert!(rust_report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.diagnostic_type == "parse-error"));

    write_config(
        dir.path(),
        r#"
rules:
  select: ["SensitiveData"]
"#,
    );
    let sensitive_report = run_project_analysis(dir.path(), default_test_options())
        .expect("selected sensitive-data analysis succeeds");
    assert!(sensitive_report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.diagnostic_type == "parse-error"));
}
