//! Legacy secret-preview configuration and finding-containment contracts.
//!
//! Users may keep the generated empty list, but every other shape fails before analysis.
//! No legacy preview can hide a finding, and guidance must not expose its value.

use super::*;
use crate::config_loader::LEGACY_SECRET_PREVIEWS_ERROR;

/// Keep high-entropy guidance clear that preview text cannot suppress user findings.
#[test]
pub(crate) fn secret_preview_mitigations_do_not_offer_retired_suppression() {
    let registry = rules::builtin_registry();
    let definition = registry
        .get("sensitive-data.high-entropy-string")
        .expect("high-entropy rule remains registered");

    // No false-positive shapes would leave list-rules users without practical review guidance.
    assert!(
        !definition.false_positive_shapes.is_empty(),
        "high-entropy guidance must retain its reviewed false-positive shapes"
    );

    // Each mitigation must explain the retired behavior without recommending an invalid value.
    for false_positive in definition.false_positive_shapes {
        assert!(
            !false_positive
                .mitigation
                .contains("allowlists.secretPreviews"),
            "mitigation must not recommend retired preview config for `{}`",
            false_positive.shape
        );
        assert!(
            !false_positive.mitigation.contains("secret_previews"),
            "mitigation must not name the rejected snake_case key for `{}`",
            false_positive.shape
        );
        assert!(
            false_positive
                .mitigation
                .contains("secret preview values cannot suppress it"),
            "mitigation must explain that the user's finding remains visible for `{}`",
            false_positive.shape
        );
    }
}

/// Accept the retained camelCase key only when the user leaves its list empty.
#[test]
pub(crate) fn config_secret_previews_accepts_empty_legacy_list() {
    let dir = tempdir().expect("tempdir");
    write_config(
        dir.path(),
        r#"
allowlists:
  secretPreviews: []
"#,
    );

    let config = load_config(dir.path(), &default_test_options())
        .expect("empty legacy secret preview list loads");
    assert_eq!(config.schema_version, SCHEMA_VERSION);
}

/// Reject the undocumented snake_case spelling so config typos fail closed.
#[test]
pub(crate) fn config_secret_preview_rejects_undocumented_snake_case_key() {
    let dir = tempdir().expect("tempdir");
    write_config(
        dir.path(),
        r#"
allowlists:
  secret_previews:
    - "ghp_...aaaa (redacted, 26 chars)"
"#,
    );

    let error = load_config(dir.path(), &default_test_options())
        .expect_err("undocumented secret preview key remains rejected");
    assert!(
        error.contains("unknown key `secret_previews` in config key `allowlists`"),
        "{error}"
    );
}

/// Reject every legacy preview value with the same safe diagnostic before analysis.
#[test]
pub(crate) fn config_secret_previews_rejects_every_value_except_empty_list() {
    let dir = tempdir().expect("tempdir");
    let invalid_preview_values = [
        ("non-empty-list", "[known-fixture]"),
        ("scalar", "known-fixture"),
        ("empty-object", "{}"),
        ("null", "null"),
        ("blank-entry", "['']"),
        ("mixed-list", "[known, 42]"),
    ];

    // Every unsupported shape must give users one deterministic, value-independent correction.
    for (case_name, configured_value) in invalid_preview_values {
        write_config(
            dir.path(),
            &format!("allowlists:\n  secretPreviews: {configured_value}\n"),
        );
        let error = load_config(dir.path(), &default_test_options())
            .expect_err("configured secret preview must fail");

        assert_eq!(error, LEGACY_SECRET_PREVIEWS_ERROR, "case={case_name}");
        assert!(
            !error.contains("known-fixture"),
            "diagnostic echoed user preview for case={case_name}: {error}"
        );
    }
}

/// Keep all sensitive findings when the legacy preview key is missing or empty.
#[test]
pub(crate) fn config_secret_previews_missing_and_empty_preserve_sensitive_findings() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    let first_secret = concat!("ghp_", "aaaaaaaaaaaaaaaaaaaaaa");
    let second_secret = concat!("ghp_", "bbbbbbbbbbbbbbbbbbbbbb");
    let sample = format!(
        r#"pub fn entry() {{
    let first_secret = "{first_secret}";
    let second_secret = "{second_secret}";
    println!("{{first_secret}}{{second_secret}}");
}}
"#
    );
    fs::write(dir.path().join("sample.rs"), sample).expect("fixture write");
    write_config(dir.path(), "");

    let missing_key_report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis without legacy key succeeds");

    write_config(dir.path(), "allowlists:\n  secretPreviews: []\n");
    let empty_list_report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis with empty legacy list succeeds");

    // API-key findings expose whether either supported config shape changed the user's results.
    let missing_key_findings: Vec<&Finding> = missing_key_report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.api-key-pattern")
        .collect();
    let empty_list_findings: Vec<&Finding> = empty_list_report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.api-key-pattern")
        .collect();

    assert_eq!(missing_key_findings.len(), 2, "{missing_key_findings:?}");
    assert_eq!(empty_list_findings.len(), 2, "{empty_list_findings:?}");
    assert!(missing_key_findings
        .iter()
        .all(|finding| finding.metadata["preview"] == "[redacted]"));
    assert!(empty_list_findings
        .iter()
        .all(|finding| finding.metadata["preview"] == "[redacted]"));
}
