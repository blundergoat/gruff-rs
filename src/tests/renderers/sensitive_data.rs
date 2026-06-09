use super::*;

#[test]
pub(crate) fn sensitive_data_renderers_do_not_leak_new_secret_values() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn entry() {
    let _phi = "MRN: AB1234567";
    let _gcp = r#"{
        "type": "service_account",
        "project_id": "demo",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEAwvR2b2d1c2ZpeHR1cmV2YWx1ZQ==\n-----END PRIVATE KEY-----\n"
    }"#;
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert_has_rule(&report, "sensitive-data.phi-pattern");
    assert_has_rule(&report, "sensitive-data.gcp-service-account-key");

    for format in [
        OutputFormat::Json,
        OutputFormat::Text,
        OutputFormat::Markdown,
        OutputFormat::Github,
        OutputFormat::Sarif,
        OutputFormat::Html,
        OutputFormat::Hotspot,
    ] {
        let rendered = render_report(&report, format);
        assert!(
            !rendered.contains("AB1234567"),
            "{format:?} renderer leaked raw PHI: {rendered}"
        );
        assert!(
            !rendered.contains("MIIEowIBAAKCAQEAwvR2b2d1c2ZpeHR1cmV2YWx1ZQ"),
            "{format:?} renderer leaked raw GCP key body: {rendered}"
        );
    }
}

#[test]
pub(crate) fn private_key_scan_survives_multibyte_context_window() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    // Place a 3-byte `€` run so the private-key context window's lower bound
    // (key_start - 1500) lands one byte into a `€`. Slicing the source at that
    // raw byte offset is a non-char-boundary that used to panic; the scan must
    // complete and still report the key.
    let header = "pub fn k() -> &'static str {\n    \"";
    let filler = "€".repeat(500);
    assert_eq!(filler.len(), 1500, "filler must be exactly 1500 bytes");
    let key = "\n-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEAwvR2b2QxdW51c2Zpe0E=\n-----END PRIVATE KEY-----\"\n}\n";
    let source = format!("{header}{filler}{key}");
    baseline_with_lib(dir.path(), &source);
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("scan must not panic on a multibyte context window");
    assert_has_rule(&report, "sensitive-data.private-key");
}

#[test]
pub(crate) fn reordered_service_account_key_is_still_reported() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    // `private_key` appears before `type`: the order-sensitive GCP rule cannot
    // match, so suppression must not fire and the generic private-key rule must
    // still report the key (no silently-dropped secret).
    baseline_with_lib(
        dir.path(),
        r##"pub fn k() {
    let _gcp = r#"{
        "private_key": "-----BEGIN PRIVATE KEY-----
MIIEowIBAAKCAQEAwvR2b2QxdW51c2Zpe0E=
-----END PRIVATE KEY-----",
        "type": "service_account"
    }"#;
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert_missing_rule(&report, "sensitive-data.gcp-service-account-key");
    assert_has_rule(&report, "sensitive-data.private-key");
}

#[test]
pub(crate) fn disabling_gcp_rule_keeps_generic_private_key_coverage() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    // With the GCP-specific rule disabled, the generic private-key suppression
    // must not fire, otherwise a committed service-account key produces no
    // finding at all.
    write_config(
        dir.path(),
        "rules:\n  sensitive-data.gcp-service-account-key:\n    enabled: false\n",
    );
    baseline_with_lib(
        dir.path(),
        r##"pub fn k() {
    let _gcp = r#"{
        "type": "service_account",
        "private_key": "-----BEGIN PRIVATE KEY-----
MIIEowIBAAKCAQEAwvR2b2QxdW51c2Zpe0E=
-----END PRIVATE KEY-----"
    }"#;
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert_missing_rule(&report, "sensitive-data.gcp-service-account-key");
    assert_has_rule(&report, "sensitive-data.private-key");
}
