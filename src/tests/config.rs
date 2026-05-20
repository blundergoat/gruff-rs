use super::*;

#[test]
pub(crate) fn registry_rejects_duplicate_rule_ids_and_sorts_definitions() {
    let registry = rules::builtin_registry();
    assert!(registry
        .definitions()
        .windows(2)
        .all(|window| window[0].id < window[1].id));
    assert!(registry.contains("security.process-command"));

    let duplicate = registry.definitions()[0];
    assert!(rules::RuleRegistry::new(vec![duplicate, duplicate]).is_err());
}

#[test]
pub(crate) fn registry_reserves_custom_namespace() {
    assert!(rules::builtin_registry()
        .definitions()
        .iter()
        .all(|definition| !definition.id.starts_with("custom.")));

    let definition = rules::RuleDefinition {
        id: "custom.builtin",
        name: "Reserved",
        pillar: Pillar::Documentation,
        tier: "v0.1",
        kind: rules::RuleKind::Text,
        default_severity: Severity::Advisory,
        confidence: Confidence::High,
        threshold: None,
        options: &[],
        default_enabled: true,
        description: "Reserved namespace probe.",
    };
    let error = rules::RuleRegistry::new(vec![definition])
        .expect_err("custom namespace reserved for config rules");
    assert!(
        error.contains("built-in rule id `custom.builtin` uses reserved custom namespace"),
        "{error}"
    );
}

#[test]
pub(crate) fn config_rejects_unknown_root_keys_and_rule_ids() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(dir.path(), r#"{ "unknown": true }"#);
    let error = load_config(dir.path(), &options).expect_err("unknown root key rejected");
    assert!(error.contains("unknown key `unknown`"), "{error}");

    write_config(
        dir.path(),
        r#"{ "rules": { "unknown.rule": { "enabled": false } } }"#,
    );
    let error = load_config(dir.path(), &options).expect_err("unknown rule rejected");
    assert!(error.contains("unknown rule id `unknown.rule`"), "{error}");
}

#[test]
pub(crate) fn config_rejects_threshold_maps_and_unknown_options() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(
        dir.path(),
        r#"{ "rules": { "size.parameter-count": { "thresholds": { "bogus": 1 } } } }"#,
    );
    let error = load_config(dir.path(), &options).expect_err("threshold map rejected");
    assert!(
        error.contains("unknown key `thresholds` in config for rule `size.parameter-count`"),
        "{error}"
    );

    write_config(
        dir.path(),
        r#"{ "rules": { "size.parameter-count": { "options": { "bogus": true } } } }"#,
    );
    let error = load_config(dir.path(), &options).expect_err("unknown option rejected");
    assert!(error.contains("unknown option `bogus`"), "{error}");
}

#[test]
pub(crate) fn rust_yaml_config_is_the_only_default_config_name() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("sample.rs"),
        r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String) {
    println!("{}{}{}{}{}", b, c, d, e, f);
    if a {
        println!("active");
    }
}
"#,
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"
rules:
  size.parameter-count:
    threshold: 10
    severity: warning
"#,
    );

    let yaml_default = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("gruff-rs yaml config is the preferred default");
    assert_missing_rule(&yaml_default, "size.parameter-count");
}

#[test]
pub(crate) fn unsupported_config_extensions_are_rejected() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("config.json"), "{}").expect("unsupported config write");
    let error = load_config(
        dir.path(),
        &AnalysisOptions {
            config: Some(PathBuf::from("config.json")),
            ..default_test_options()
        },
    )
    .expect_err("unsupported config extension rejected");
    assert!(
        error.contains("unsupported config extension `json`"),
        "{error}"
    );
}

#[test]
pub(crate) fn threshold_overrides_require_one_value_and_one_severity() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(
        dir.path(),
        r#"
rules:
  complexity.cognitive:
    threshold: 20
    severity: error
"#,
    );
    let config = load_config(dir.path(), &options).expect("threshold and severity accepted");
    assert_eq!(config.threshold("complexity.cognitive", 15.0), 20.0);
    assert_eq!(
        config.severity("complexity.cognitive", Severity::Warning),
        Severity::Error
    );

    write_config(
        dir.path(),
        r#"
rules:
  complexity.cognitive:
    threshold: 20
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("severity required");
    assert!(
            error.contains(
                "config key `rules.complexity.cognitive.severity` is required when `threshold` is configured"
            ),
            "{error}"
        );

    write_config(
        dir.path(),
        r#"
rules:
  complexity.cognitive:
    severity: warning
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("threshold required");
    assert!(
        error.contains("config key `rules.complexity.cognitive.severity` requires `threshold`"),
        "{error}"
    );
}

#[test]
pub(crate) fn config_disables_rules_and_overrides_threshold() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("sample.rs"),
        [
            r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String) {
    if a {
        "#,
            PROCESS_COMMAND_NEW,
            r#"("sh").arg("-c").arg(b).spawn().unwrap();
    }
    println!("{}{}{}{}", c, d, e, f);
}
"#,
        ]
        .concat(),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"{
  "rules": {
    "security.process-command": { "enabled": false },
    "size.parameter-count": { "threshold": 10, "severity": "warning" }
  }
}"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    let rule_ids: BTreeSet<&str> = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(!rule_ids.contains("security.process-command"));
    assert!(!rule_ids.contains("size.parameter-count"));
}

#[test]
pub(crate) fn legacy_config_byte_identical_rule_blocks_remain_selector_neutral() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("sample.rs"),
        [
            r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String) {
    if a {
        "#,
            PROCESS_COMMAND_NEW,
            r#"("sh").arg("-c").arg(b).spawn().unwrap();
    }
    println!("{}{}{}{}", c, d, e, f);
}
"#,
        ]
        .concat(),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"{
  "rules": {
    "security.process-command": { "enabled": false }
  }
}"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert_missing_rule(&report, "security.process-command");
    assert_has_rule(&report, "size.parameter-count");
}

#[test]
pub(crate) fn config_secret_previews_allowlist_only_matching_synthetic_values() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    let accepted_fixture = concat!("ghp_", "aaaaaaaaaaaaaaaaaaaaaa");
    let unlisted_secret = concat!("ghp_", "bbbbbbbbbbbbbbbbbbbbbb");
    let sample = format!(
        r#"pub fn entry() {{
    let accepted_fixture = "{accepted_fixture}";
    let unlisted_secret = "{unlisted_secret}";
    println!("{{accepted_fixture}}{{unlisted_secret}}");
}}
"#
    );
    fs::write(dir.path().join("sample.rs"), sample).expect("fixture write");
    write_config(
        dir.path(),
        r#"
allowlists:
  secretPreviews:
    - "ghp_...aaaa (redacted, 26 chars)"
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let api_key_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.api-key-pattern")
        .collect();

    assert_eq!(
        api_key_findings.len(),
        1,
        "expected only the unlisted API key preview to remain; findings={api_key_findings:?}"
    );
    assert_eq!(
        api_key_findings[0].metadata["preview"],
        "ghp_...bbbb (redacted, 26 chars)"
    );
}

