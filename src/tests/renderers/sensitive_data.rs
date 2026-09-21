//! Sensitive-data output contracts across native, CI, and human renderers.
//! These tests prove secret-like source values never reach reports while the
//! metadata marker and legacy suppression paths remain separate.

use super::*;

const FIXTURE_API_KEY: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaa";
const FIXTURE_AWS_KEY: &str = "AKIAABCDEFGHIJKLMNOP";
const FIXTURE_JWT: &str =
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const FIXTURE_DATABASE_URL: &str = "postgres://analyst:realSecret123@db.internal/app";
const FIXTURE_HTTP_URL: &str = "https://agent:realSecret123@service.internal/path";
const FIXTURE_PRIVATE_KEY_BODY: &str = "MIIEowIBAAKCAQEAwvR2b2d1c2ZpeHR1cmV2YWx1ZQ==";
const FIXTURE_MRN: &str = "AB1234567";
const FIXTURE_ENV_SECRET: &str = "correct-horse-battery-123";
const FIXTURE_ENTROPY_SECRET: &str = "Q7m2P9x8R4s6T1v3W5y7Z0a2B4c6D8e0";

/// Analyse one source containing each identity-independent sensitive-data shape.
/// Renderer tests use it to compare category markers without touching fixture PII.
fn identity_independent_sensitive_report() -> AnalysisReport {
    let dir = tempdir().expect("tempdir");
    let source = format!(
        r####"/// Probe.
pub fn entry() {{
    let _api = "{FIXTURE_API_KEY}";
    let _aws = "{FIXTURE_AWS_KEY}";
    let _jwt = "{FIXTURE_JWT}";
    let _database = "{FIXTURE_DATABASE_URL}";
    let _http = "{FIXTURE_HTTP_URL}";
    let _private = r#"-----BEGIN RSA PRIVATE KEY-----
{FIXTURE_PRIVATE_KEY_BODY}
-----END RSA PRIVATE KEY-----"#;
    let _phi = "MRN: {FIXTURE_MRN}";
    let _gcp = r#"{{
        "type": "service_account",
        "private_key": "-----BEGIN PRIVATE KEY-----\n{FIXTURE_PRIVATE_KEY_BODY}\n-----END PRIVATE KEY-----\n"
    }}"#;
    let _env = "DATABASE_PASSWORD={FIXTURE_ENV_SECRET}";
    let _entropy = "{FIXTURE_ENTROPY_SECRET}";
}}
"####,
    );
    baseline_with_lib(dir.path(), &source);
    run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds")
}

/// Return the one expected finding for a sensitive-data rule in the focused report.
fn sensitive_finding<'a>(report: &'a AnalysisReport, rule_id: &str) -> &'a Finding {
    report
        .findings
        .iter()
        .find(|finding| finding.rule_id == rule_id)
        .unwrap_or_else(|| panic!("missing {rule_id} in {:#?}", report.findings))
}

/// AWS issues temporary session credentials under the `ASIA` prefix over the same fixed body, so a rule naming
/// only `AKIA` left a live credential unreported. gruff-php and gruff-py already named both shapes.
#[test]
pub(crate) fn aws_session_token_reports_as_an_access_key() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let session_token = format!("{}{}", "ASIA", "IOSFODNN7EXAMPLE");
    let source = format!(
        r####"/// Probe.
pub fn entry() {{
    let _session = "{session_token}";
}}
"####
    );
    baseline_with_lib(dir.path(), &source);

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let aws: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.aws-access-key")
        .collect();

    assert_eq!(
        aws.len(),
        1,
        "expected the session token reported: {:#?}",
        report.findings
    );
}

/// FAMILY-CONTRACT.md section 5 reads a key whose body is entirely `X` as naming no credential, while a real key that
/// merely contains a run of `X` still reports, because hiding it would hide a live credential.
#[test]
pub(crate) fn aws_key_whose_whole_body_is_x_is_read_as_masked() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let masked = "X".repeat(16);
    let partly_masked = format!("{}{}", "IOSFODNN", "X".repeat(8));
    let source = format!(
        r####"/// Probe.
pub fn entry() {{
    let _long = "AKIA{masked}";
    let _session = "ASIA{masked}";
    let _partly = "AKIA{partly_masked}";
}}
"####
    );
    baseline_with_lib(dir.path(), &source);

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let lines: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.aws-access-key")
        .map(|finding| finding.line)
        .collect();

    assert_eq!(
        lines,
        vec![Some(5)],
        "expected only the partly masked key reported: {:#?}",
        report.findings
    );
}

/// Identity-independent findings expose only detector-owned zero-payload markers.
#[test]
pub(crate) fn identity_independent_sensitive_metadata_uses_zero_payload_markers() {
    let _guard = analysis_lock();
    let report = identity_independent_sensitive_report();
    let expected_markers = [
        ("sensitive-data.api-key-pattern", "[redacted]"),
        ("sensitive-data.aws-access-key", "[redacted:aws-access-key]"),
        ("sensitive-data.jwt-token", "[redacted:jwt]"),
        (
            "sensitive-data.database-url-password",
            "[redacted:connection-string:postgres]",
        ),
        (
            "sensitive-data.url-embedded-credentials",
            "[redacted:connection-string:https]",
        ),
        ("sensitive-data.private-key", "[redacted:private-key]"),
        ("sensitive-data.phi-pattern", "[redacted:mrn]"),
        (
            "sensitive-data.gcp-service-account-key",
            "[redacted:gcp-service-account]",
        ),
        ("sensitive-data.hardcoded-env-value", "[redacted]"),
        ("sensitive-data.high-entropy-string", "[redacted]"),
    ];
    let expected_identity_contract = [
        (
            "sensitive-data.api-key-pattern",
            "API key pattern detected.",
            "78eebb79c9159c3d",
            "e5aa86cac3c8125c",
        ),
        (
            "sensitive-data.aws-access-key",
            "AWS access key pattern detected.",
            "7c41f39e962ab9b9",
            "1cb652c4bb17e262",
        ),
        (
            "sensitive-data.jwt-token",
            "JWT-looking token detected.",
            "75601609bf186847",
            "f3d5dd1b8dcddb8e",
        ),
        (
            "sensitive-data.database-url-password",
            "Database URL appears to include a password.",
            "ae3130b926e39ca6",
            "00a673087ed0dfa9",
        ),
        (
            "sensitive-data.url-embedded-credentials",
            "HTTP(S) URL appears to include embedded credentials.",
            "1ed7196bda8e91cc",
            "4957bb552cad2c43",
        ),
        (
            "sensitive-data.private-key",
            "Private key block detected.",
            "4be31610f2bded48",
            "33459a0c2ef9d42d",
        ),
        (
            "sensitive-data.phi-pattern",
            "Protected health identifier pattern detected for mrn.",
            "ea3541710aec140c",
            "c65ab74689fd263c",
        ),
        (
            "sensitive-data.gcp-service-account-key",
            "GCP service account private key material detected.",
            "56cb1be790e202cd",
            "1fad36f5db62371a",
        ),
        (
            "sensitive-data.hardcoded-env-value",
            "Hardcoded environment-style secret assignment detected.",
            "3ae99b4c961a64d3",
            "9330614a150e5fa7",
        ),
        (
            "sensitive-data.high-entropy-string",
            "High-entropy string literal detected.",
            "90dcbd0f187c9e57",
            "d2fc362707d14de3",
        ),
    ];

    for (rule_id, marker) in expected_markers {
        assert_eq!(
            sensitive_finding(&report, rule_id).metadata["preview"],
            marker
        );
    }
    for (rule_id, message, fingerprint, stable_identity) in expected_identity_contract {
        let finding = sensitive_finding(&report, rule_id);
        assert_eq!(finding.message, message, "{rule_id}");
        assert_eq!(finding.fingerprint, fingerprint, "{rule_id}");
        assert_eq!(finding.stable_identity, stable_identity, "{rule_id}");
    }

    let json = render_report(&report, OutputFormat::Json);
    let sarif = render_report(&report, OutputFormat::Sarif);
    for marker in expected_markers.map(|(_, marker)| marker) {
        assert!(json.contains(marker), "JSON omitted {marker}: {json}");
        assert!(sarif.contains(marker), "SARIF omitted {marker}: {sarif}");
    }

    let raw_values = [
        FIXTURE_API_KEY,
        FIXTURE_AWS_KEY,
        FIXTURE_JWT,
        FIXTURE_DATABASE_URL,
        FIXTURE_HTTP_URL,
        FIXTURE_PRIVATE_KEY_BODY,
        FIXTURE_MRN,
        FIXTURE_ENV_SECRET,
        FIXTURE_ENTROPY_SECRET,
    ];
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
        for raw_value in raw_values {
            assert!(
                !rendered.contains(raw_value),
                "{format:?} renderer leaked a raw value: {rendered}"
            );
        }
        assert!(
            !rendered.contains("(redacted,"),
            "{format:?} renderer serialized a partial legacy alias: {rendered}"
        );
        assert!(
            !rendered.contains("service_account private key (redacted)"),
            "{format:?} renderer serialized the GCP legacy alias: {rendered}"
        );
    }

    let hook = crate::hook::render_hook_report(report, false, false);
    for marker in expected_markers.map(|(_, marker)| marker) {
        assert!(hook.contains(marker), "hook omitted {marker}: {hook}");
    }
    assert!(!hook.contains("(redacted,"), "{hook}");
    assert!(
        !hook.contains("service_account private key (redacted)"),
        "{hook}"
    );
}

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

/// Pin the ratified high-entropy contract (FAMILY-CONTRACT sections 5, 6, 12 and 13a): warning severity,
/// medium confidence, on by default, and `minLength` and `entropy` read from configuration with defaults
/// 32 and 4.2. A 24-character literal is silent at the default floor and reported once at a lowered one;
/// a lowered floor reads each `concat!` literal on its own line, and the literal that directly follows
/// another's closing quote. One finding per rule and line is reported, so each case keeps its own line.
#[test]
pub(crate) fn high_entropy_contract_reads_both_named_thresholds() {
    let rule = "sensitive-data.high-entropy-string";
    let definition = rules::builtin_registry()
        .get(rule)
        .copied()
        .expect("catalogued");
    assert_eq!(
        (
            definition.default_severity,
            definition.confidence,
            definition.default_enabled
        ),
        (Severity::Warning, Confidence::Medium, true)
    );
    assert_eq!(rules::builtin_detector_parameter(rule, "minLength"), 32.0);
    assert_eq!(rules::builtin_detector_parameter(rule, "entropy"), 4.2);

    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    // Assembled at run time, so no file in this repository holds a secret-shaped literal.
    let first = ["Gt5Hy9Ju", "3Ki7Lo1P", "z4Xa8Sd2"].concat();
    let second = ["Qw8Er2Ty", "6Ui0Op4A", "s1Df5Gh9"].concat();
    fs::write(
        dir.path().join("src/token.rs"),
        format!("/// Probe.\npub const TOKEN: &str = \"{first}\";\n"),
    )
    .expect("token write");
    fs::write(
        dir.path().join("src/pair.rs"),
        format!(
            "/// Probe.\npub const PAIR: &str = concat!(\n    \"{first}\",\n    \"{second}\"\n);\n"
        ),
    )
    .expect("pair write");
    // A low-entropy literal first: the secret after its closing quote must still be read.
    let filler = "abcdabcdabcdabcdabcd";
    fs::write(
        dir.path().join("src/adjacent.rs"),
        format!("/// Probe.\n// \"{filler}\"\"{second}\"\npub fn adjacent() {{}}\n"),
    )
    .expect("adjacent write");

    let entropy_findings = |report: &AnalysisReport| {
        let mut found: Vec<(String, Option<usize>, Severity)> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == rule)
            .map(|finding| (finding.file_path.clone(), finding.line, finding.severity))
            .collect();
        found.sort();
        found
    };
    let default_scan = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("default scan");
    assert!(
        entropy_findings(&default_scan).is_empty(),
        "24 characters sit below the default floor of 32"
    );

    write_config(
        dir.path(),
        r#"{ "rules": { "sensitive-data.high-entropy-string": { "thresholds": { "minLength": 16 } } } }"#,
    );
    let lowered_scan = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("lowered scan");
    let expected: Vec<(String, Option<usize>, Severity)> = [
        ("src/adjacent.rs", 2),
        ("src/pair.rs", 3),
        ("src/pair.rs", 4),
        ("src/token.rs", 2),
    ]
    .into_iter()
    .map(|(path, line)| (path.to_string(), Some(line), Severity::Warning))
    .collect();
    assert_eq!(entropy_findings(&lowered_scan), expected);
}
