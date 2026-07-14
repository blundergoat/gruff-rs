//! Secret-preview configuration and metadata contracts for project scans.
//! These tests keep user-facing mitigation text aligned with strict config
//! loading and prove reviewed legacy aliases suppress findings without
//! becoming report metadata or authorizing a displayed preview.

use super::*;

/// Keep high-entropy guidance aligned with the strict config key and its
/// legacy finding-suppression behavior.
#[test]
pub(crate) fn secret_preview_mitigations_name_the_accepted_suppression_key() {
    let registry = rules::builtin_registry();
    let definition = registry
        .get("sensitive-data.high-entropy-string")
        .expect("high-entropy rule remains registered");

    // No false-positive shapes would leave list-rules users without the config-key guidance.
    assert!(
        !definition.false_positive_shapes.is_empty(),
        "high-entropy guidance must retain its reviewed false-positive shapes"
    );

    // Each displayed mitigation must give users one loadable key and describe its real effect.
    for false_positive in definition.false_positive_shapes {
        assert!(
            false_positive
                .mitigation
                .contains("allowlists.secretPreviews"),
            "mitigation must name the accepted nested key for `{}`",
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
                .contains("suppress only their exact legacy alias"),
            "mitigation must describe finding suppression, not preview authorization for `{}`",
            false_positive.shape
        );
    }
}

/// Accept the documented nested camelCase key when a user loads project config.
#[test]
pub(crate) fn config_secret_preview_accepts_documented_camel_case_key() {
    let dir = tempdir().expect("tempdir");
    write_config(
        dir.path(),
        r#"
allowlists:
  secretPreviews:
    - "ghp_...aaaa (redacted, 26 chars)"
"#,
    );

    let config = load_config(dir.path(), &default_test_options())
        .expect("documented secret preview suppression key loads");
    assert!(
        config
            .secret_previews
            .contains("ghp_...aaaa (redacted, 26 chars)"),
        "the reviewed legacy alias must reach the detector suppression set"
    );
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

/// Legacy `secretPreviews` aliases suppress exact matches without becoming report metadata.
#[test]
pub(crate) fn config_secret_previews_preserve_legacy_suppression_without_serializing_alias() {
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

    // API-key findings alone show whether the reviewed alias suppressed its exact match.
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
    assert_eq!(api_key_findings[0].metadata["preview"], "[redacted]");
}
