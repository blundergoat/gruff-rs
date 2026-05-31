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
