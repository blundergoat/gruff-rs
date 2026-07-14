//! Configuration loading and behavior contracts for user-authored project settings.
//! These tests keep strict schema validation, documented selectors, allowlists,
//! and command defaults aligned with the analysis path that consumes them.

use super::*;

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
pub(crate) fn accepted_abbreviations_replace_builtins() {
    let dir = tempdir().expect("tempdir");
    write_config(
        dir.path(),
        r#"
allowlists:
  acceptedAbbreviations:
    - ZZ
    - zz
    - Domain
"#,
    );

    let config = load_config(dir.path(), &default_test_options()).expect("allowlist loads");
    let loaded: Vec<&str> = config
        .accepted_abbreviations
        .iter()
        .map(String::as_str)
        .collect();

    assert_eq!(loaded, vec!["domain", "zz"]);
    assert!(!config.accepted_abbreviations.contains("id"));
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
pub(crate) fn plain_path_patterns_match_segment_boundaries() {
    let matcher = PathMatcher::new("src/gen");

    assert!(matcher.matches("src/gen"));
    assert!(matcher.matches("src/gen/lib.rs"));
    assert!(!matcher.matches("src/generated/lib.rs"));
    assert!(!matcher.matches("src/generated2/lib.rs"));
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
  security.process-command:
    severity: error
"#,
    );
    let config = load_config(dir.path(), &options).expect("standalone severity accepted");
    assert_eq!(
        config.severity("security.process-command", Severity::Warning),
        Severity::Error
    );
}

#[test]
pub(crate) fn config_disables_rules_and_overrides_threshold() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("sample.rs"),
        [
            r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String, g: String, h: String) {
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
pub(crate) fn standalone_severity_override_changes_security_finding() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("sample.rs"),
        [
            "/// Probe.\npub fn entry(argument: &str) {\n    ",
            PROCESS_COMMAND_NEW,
            "(\"sh\").arg(\"-c\").arg(argument).spawn().unwrap();\n}\n",
        ]
        .concat(),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"
rules:
  security.process-command:
    severity: error
"#,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "security.process-command")
        .expect("process command finding");
    assert_eq!(finding.severity, Severity::Error);
}

#[test]
pub(crate) fn standalone_severity_override_changes_dependency_finding() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("Cargo.toml"),
        r#"[package]
name = "dependency-severity-fixture"
version = "0.1.0"
edition = "2021"
description = "Dependency severity fixture."
license = "MIT"

[dependencies]
gitdep = { git = "https://example.invalid/repo.git" }
"#,
    )
    .expect("manifest write");
    write_config(
        dir.path(),
        r#"
rules:
  dependency.git-source:
    severity: error
"#,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "dependency.git-source")
        .expect("git source finding");
    assert_eq!(finding.severity, Severity::Error);
}

#[test]
pub(crate) fn legacy_config_byte_identical_rule_blocks_remain_selector_neutral() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("sample.rs"),
        [
            r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String, g: String, h: String) {
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
pub(crate) fn config_rejects_missing_schema_version() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join(".gruff-rs.yaml"),
        "paths:\n  ignore:\n    - foo\n",
    )
    .expect("yaml config write");
    let error = load_config(dir.path(), &default_test_options())
        .expect_err("missing schemaVersion rejected");
    assert!(
        error.contains("missing the required `schemaVersion` field"),
        "{error}"
    );
    assert!(error.contains("gruff-rs.config.v1"), "{error}");
}

#[test]
pub(crate) fn config_rejects_wrong_schema_version() {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join(".gruff-rs.yaml"),
        "schemaVersion: gruff-rs.config.v0\n",
    )
    .expect("yaml config write");
    let error =
        load_config(dir.path(), &default_test_options()).expect_err("wrong schemaVersion rejected");
    assert!(
        error.contains("unsupported schemaVersion `gruff-rs.config.v0`"),
        "{error}"
    );
    assert!(error.contains("gruff-rs.config.v1"), "{error}");
}

#[test]
pub(crate) fn config_accepts_schema_version_and_records_it() {
    let dir = tempdir().expect("tempdir");
    write_config(dir.path(), "");
    let config = load_config(dir.path(), &default_test_options()).expect("schemaVersion accepted");
    assert_eq!(config.schema_version, "gruff-rs.config.v1");
}

#[test]
pub(crate) fn minimum_severity_accepts_valid_keys_and_values() {
    let dir = tempdir().expect("tempdir");
    write_config(
        dir.path(),
        "minimumSeverity:\n  analyse: warning\n  report: none\n",
    );
    let config = load_config(dir.path(), &default_test_options())
        .expect("valid minimumSeverity block accepted");
    assert_eq!(
        config.minimum_severity.get("analyse"),
        Some(&FailThreshold::Warning)
    );
    assert_eq!(
        config.minimum_severity.get("report"),
        Some(&FailThreshold::None)
    );
}

#[test]
pub(crate) fn minimum_severity_rejects_non_gating_subcommands() {
    let dir = tempdir().expect("tempdir");
    write_config(dir.path(), "minimumSeverity:\n  summary: advisory\n");
    let error = load_config(dir.path(), &default_test_options())
        .expect_err("non-gating subcommand rejected");
    assert!(
        error.contains("unknown command `summary` in `minimumSeverity`"),
        "{error}"
    );
    assert!(error.contains("Valid keys: analyse, report"), "{error}");
}

#[test]
pub(crate) fn minimum_severity_rejects_unknown_threshold_values() {
    let dir = tempdir().expect("tempdir");
    write_config(dir.path(), "minimumSeverity:\n  analyse: never\n");
    let error = load_config(dir.path(), &default_test_options())
        .expect_err("never is not a valid threshold");
    assert!(error.contains("minimumSeverity.analyse"), "{error}");
    assert!(error.contains("advisory, warning, error, none"), "{error}");
}

#[test]
pub(crate) fn minimum_severity_empty_block_is_accepted() {
    let dir = tempdir().expect("tempdir");
    write_config(dir.path(), "minimumSeverity: {}\n");
    let config =
        load_config(dir.path(), &default_test_options()).expect("empty minimumSeverity accepted");
    assert!(config.minimum_severity.is_empty());
}

#[test]
pub(crate) fn minimum_severity_rejects_non_mapping_shape() {
    let dir = tempdir().expect("tempdir");
    write_config(dir.path(), "minimumSeverity: advisory\n");
    let error = load_config(dir.path(), &default_test_options())
        .expect_err("scalar minimumSeverity rejected");
    assert!(error.contains("must be an object"), "{error}");
}
