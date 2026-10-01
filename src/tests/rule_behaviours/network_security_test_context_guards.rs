//! Test-context policy guards for executable network and security behavior.
//!
//! Temporary production, test, and fixture sources model paths a CLI user scans.
//! Real CI risks remain visible while semantic negatives stay quiet.

use super::*;

const NETWORK_SECURITY_RULES: [&str; 5] = [
    "security.hardcoded-bind-all-interfaces",
    "security.ssrf-candidate",
    "security.unsafe-deserialization",
    "security.xxe-candidate",
    "security.template-injection-xss",
];

const EXECUTABLE_RISK_SOURCE: &str = concat!(
    "/// Return the listener address used by this executable probe.\n",
    "pub fn bind_listener() -> &'static str { \"0.0.0.",
    "0:8080\" }\n",
    "/// Fetch a caller-provided URL.\n",
    "pub fn fetch_url(url: String) { let _ = reqwest::get(&url); }\n",
    "/// Decode caller-provided bytes.\n",
    "pub fn decode_payload(body: &[u8]) { let _ = bincode::deserialize(body); }\n",
    "/// Enable external XML entity resolution.\n",
    "pub fn parse_xml() { let _ = libxml::parser::ParserOption::NOENT; }\n",
    "/// Render caller-provided text into HTML.\n",
    "pub fn render_page(name: String) { let _ = Html(format!(\"<p>{name}</p>\")); }\n",
);

const SEMANTIC_NEGATIVE_SOURCE: &str = concat!(
    "/// Return a loopback-only listener address.\n",
    "pub fn bind_listener() -> &'static str { \"127.0.0.1:8080\" }\n",
    "/// Fetch a URL only after parsing and validating it.\n",
    "pub fn fetch_url(url: String) {\n",
    "    let validated_url = Url::parse(&url).unwrap();\n",
    "    let _ = reqwest::get(validated_url.as_str());\n",
    "}\n",
    "/// Decode an intentional YAML configuration document.\n",
    "pub fn load_yaml_config(body: &str) { let _ = serde_yaml::from_str(body); }\n",
    "/// Keep external XML entity resolution disabled.\n",
    "pub fn parse_xml() { let _ = libxml::parser::ParserOption::RECOVER; }\n",
    "/// Escape caller-provided text before rendering HTML.\n",
    "pub fn render_page(name: String) {\n",
    "    let escaped = html_escape::encode_text(&name);\n",
    "    let _ = Html(format!(\"<p>{escaped}</p>\"));\n",
    "}\n",
);

/// Write one analyzer input at the production, test, or fixture path under review.
fn write_policy_source(root: &Path, relative_path: &str, source: &str) {
    let source_path = root.join(relative_path);
    let parent = source_path
        .parent()
        .expect("policy source path has a parent directory");
    fs::create_dir_all(parent).expect("policy source directory");
    fs::write(source_path, source).expect("policy source write");
}

/// Return sorted finding paths for one rule so path-policy failures are explicit.
fn finding_paths_for_rule<'a>(report: &'a AnalysisReport, rule_id: &str) -> Vec<&'a str> {
    // Only the selected detector contributes paths to the policy assertion the user reviews.
    let mut finding_paths: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == rule_id)
        .map(|finding| finding.file_path.as_str())
        .collect();
    finding_paths.sort_unstable();
    finding_paths
}

/// Regression guard: these sinks often cannot infer their type parameter, so the turbofish spelling
/// is the common one. Matching only the bare call left `serde_yaml::from_str::<Config>(body)` and
/// its siblings unreported, which is the dominant form of the pattern the rule exists to find.
#[test]
pub(crate) fn unsafe_deserialization_reports_turbofish_sinks() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        concat!(
            "/// Decode caller-provided bytes with an annotated type.\n",
            "pub fn decode_payload(body: &[u8]) { let _ = bincode::deserialize::<String>(body); }\n",
            // Deliberately not named `*config*` or `*yaml*`: `yaml_config_parse_is_intentional`
            // exempts those, and this guard is about the turbofish, not that exemption.
            "/// Parse caller-provided YAML with an annotated type.\n",
            "pub fn parse_manifest(body: &str) { let _ = serde_yaml::from_str::<Vec<String>>(body); }\n",
        ),
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
    let sinks: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.unsafe-deserialization")
        .collect();
    assert_eq!(
        sinks.len(),
        2,
        "both turbofish deserialization sinks must be reported; findings={sinks:?}"
    );
}

/// Prove executable risks stay visible across source contexts while semantic negatives stay quiet.
#[test]
pub(crate) fn network_security_test_context_policy_matrix() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), EXECUTABLE_RISK_SOURCE);
    write_policy_source(
        dir.path(),
        "tests/network_security_matrix.rs",
        EXECUTABLE_RISK_SOURCE,
    );
    write_policy_source(
        dir.path(),
        "fixtures/network_security_matrix.rs",
        EXECUTABLE_RISK_SOURCE,
    );
    write_policy_source(
        dir.path(),
        "tests/network_security_safe.rs",
        SEMANTIC_NEGATIVE_SOURCE,
    );
    write_policy_source(
        dir.path(),
        "fixtures/network_security_data.txt",
        EXECUTABLE_RISK_SOURCE,
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
    let expected_paths = vec![
        "fixtures/network_security_matrix.rs",
        "src/lib.rs",
        "tests/network_security_matrix.rs",
    ];
    let registry = crate::rules::builtin_registry();

    // Every detector must expose the same executable risk in production, tests, and Rust fixtures.
    for rule_id in NETWORK_SECURITY_RULES {
        let rule_findings: Vec<(&str, Option<usize>, Option<&str>)> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == rule_id)
            .map(|finding| {
                (
                    finding.file_path.as_str(),
                    finding.line,
                    finding.symbol.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            finding_paths_for_rule(&report, rule_id),
            expected_paths,
            "{rule_id} must retain executable findings without treating data-only fixtures as Rust; findings={rule_findings:?}"
        );
        assert!(
            rule_findings
                .iter()
                .all(|(_, _, symbol)| *symbol != Some("_")),
            "{rule_id} must report the risky input rather than Rust's discard target"
        );
        let definition = registry
            .get(rule_id)
            .expect("network security rule metadata");
        assert!(
            definition.description.contains("test"),
            "{rule_id} must state that executable test source remains in scope"
        );
        assert!(
            !definition.false_positive_shapes.is_empty(),
            "{rule_id} must provide a specific mitigation for intentional test behavior"
        );
    }
}

/// A scanned handler may print a finite enum in HTML without printing request text.
/// Keep warnings when the same handler shape can carry a payload or another dynamic value.
#[test]
pub(crate) fn template_html_distinguishes_derived_unit_enum_from_dynamic_output() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let source = r##"
use axum::response::Html;
#[derive(Debug)]
enum Version { V1, V2 }
#[derive(Debug)]
enum PayloadVersion { V1(String), V2 }
#[derive(Debug)]
enum RecordVersion { V1 { text: String }, V2 }
#[derive(Debug)]
enum CustomVersion { V1, V2 }
impl std::fmt::Display for CustomVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&std::env::var("CUSTOM_VERSION").unwrap_or_default())
    }
}

#[derive(Debug)]
enum CustomDebugVersion { V1, V2 }
#[cfg(feature = "custom-debug")]
impl std::fmt::Debug for CustomDebugVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("custom")
    }
}
#[derive(Debug)]
struct UnknownVersion(String);

fn render_version(version: Version) -> Html<String> { Html(format!("version {version:?}")) }
fn render_raw_version(version: Version) -> Html<String> { Html(format!(r#"version {version:?}"#)) }
fn render_payload(payload: PayloadVersion) -> Html<String> { Html(format!("payload {payload:?}")) }
fn render_record(record: RecordVersion) -> Html<String> { Html(format!("record {record:?}")) }
fn render_custom(custom: CustomVersion) -> Html<String> { Html(format!("custom {custom}")) }
fn render_custom_debug(custom_debug: CustomDebugVersion) -> Html<String> { Html(format!("custom debug {custom_debug:?}")) }
fn render_unknown(unknown: UnknownVersion) -> Html<String> { Html(format!("unknown {unknown:?}")) }
fn render_mixed(version: Version, user: String) -> Html<String> { Html(format!("mixed {version:?} {user}")) }
fn render_explicit(version: Version) -> Html<String> { Html(format!("explicit {:?}", version)) }
fn render_indexed(version: Version) -> Html<String> { Html(format!("indexed {0:?}", version)) }
"##;
    baseline_with_lib(dir.path(), source);
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
    let reported_lines: Vec<usize> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.template-injection-xss")
        .filter_map(|finding| finding.line)
        .collect();
    let expected_reported_functions = [
        "render_payload",
        "render_record",
        "render_custom",
        "render_custom_debug",
        "render_unknown",
        "render_mixed",
    ];
    // Each unsafe neighbor has a separate line, so a missing warning points to its user-visible handler.
    for function_name in expected_reported_functions {
        let function_line = source
            .lines()
            .position(|line| line.contains(&format!("fn {function_name}(")))
            .expect("handler in source")
            + 1;
        assert!(
            reported_lines.contains(&function_line),
            "{function_name} must remain reportable; lines={reported_lines:?}"
        );
    }
    // The unit-only handlers are the precise false-positive cases a user sees in the report.
    for function_name in [
        "render_version",
        "render_raw_version",
        "render_explicit",
        "render_indexed",
    ] {
        let function_line = source
            .lines()
            .position(|line| line.contains(&format!("fn {function_name}(")))
            .expect("handler in source")
            + 1;
        assert!(
            !reported_lines.contains(&function_line),
            "{function_name} prints only a finite enum; lines={reported_lines:?}"
        );
    }
}

/// A scanned project can declare another module that changes how its enum is printed.
/// Keep the HTML warning until the formatter's behavior is proven from that source.
#[test]
pub(crate) fn template_html_keeps_external_formatter_module_reportable() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        concat!(
            "use axum::response::Html;\n",
            "mod formatter;\n",
            "#[derive(Debug)] enum Version { V1 }\n",
            "fn render_version(version: Version) -> Html<String> { Html(format!(\"{version:?}\")) }\n",
        ),
    );
    write_policy_source(
        dir.path(),
        "src/formatter.rs",
        "#[cfg(feature = \"custom-debug\")] impl std::fmt::Debug for super::Version { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(\"dynamic\") } }\n",
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
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "security.template-injection-xss"
                && finding.file_path == "src/lib.rs"
                && finding.line == Some(4)
        }),
        "an uninspected external formatter must keep the HTML warning"
    );
}
