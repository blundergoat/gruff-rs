use super::*;

/// Proves that `naming.short-variable` ignores idiomatic throwaway bindings.
#[test]
pub(crate) fn calibration_naming_short_variable_ignores_underscore_binding() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        "/// Probe.\npub fn entry() { let value = 1; let _ = value; }\n",
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
    let underscore_finding = report.findings.iter().find(|finding| {
        finding.rule_id == "naming.short-variable" && finding.symbol.as_deref() == Some("_")
    });
    assert!(
        underscore_finding.is_none(),
        "calibration expected `naming.short-variable` to ignore `let _`; \
             findings={:?}",
        rule_ids(&report)
    );
}

/// Proves that `performance.clone-in-loop` catches single-line loop bodies.
#[test]
pub(crate) fn calibration_performance_loop_rules_catch_single_line_loops() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
            dir.path(),
            "/// Probe.\npub fn entry(values: Vec<String>) { for value in values { let _ = value.clone(); } }\n",
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
    assert_has_rule(&report, "performance.clone-in-loop");
}

/// Proves that `dead-code.unused-private-function` skips harness entry points.
#[test]
pub(crate) fn calibration_dead_code_skips_test_attr_and_main() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn library_entry() {}

#[cfg(test)]
mod inner {
    #[test]
    fn private_test_only_called_by_runner() {
        assert_eq!(1, 1);
    }
}

fn main() {}
"#,
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
    let main_dead = report.findings.iter().any(|finding| {
        finding.rule_id == "dead-code.unused-private-function"
            && finding.symbol.as_deref() == Some("main")
    });
    let test_dead = report.findings.iter().any(|finding| {
        finding.rule_id == "dead-code.unused-private-function"
            && finding.symbol.as_deref() == Some("private_test_only_called_by_runner")
    });
    assert!(
        !main_dead,
        "calibration expected `dead-code.unused-private-function` to skip `fn main`; \
             findings={:?}",
        rule_ids(&report)
    );
    assert!(
        !test_dead,
        "calibration expected `dead-code.unused-private-function` to skip `#[test]` fn; \
             findings={:?}",
        rule_ids(&report)
    );
}

/// Proves that `security.process-command` catches live process construction
/// while ignoring command snippets embedded in fixture strings.
#[test]
pub(crate) fn calibration_security_process_command_detects_code_not_fixture_text() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn live_command() {
    let mut command = std::process::Command::new("git");
    command.arg("status");
}

/// Probe.
pub fn fixture_text() {
    let snippet = r#"std::process::Command::new("sh");"#;
    println!("{snippet}");
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
    let command_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.process-command")
        .collect();
    assert_eq!(
            command_findings.len(),
            1,
            "calibration expected exactly one live process-command finding; findings={command_findings:?}"
        );
    assert_eq!(command_findings[0].symbol.as_deref(), None);
    assert_eq!(command_findings[0].line, Some(3));
}

/// Proves that test-context functions keep dedicated test-quality checks
/// without also receiving production complexity, metric, and size findings.
#[test]
pub(crate) fn calibration_complexity_metrics_size_skip_test_context() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let mut body = String::from(
            "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod fixtures {\n    #[test]\n    fn long_setup() {\n        let mut total = 0;\n",
        );
    for index in 0..90 {
        body.push_str(&format!("        if {index} > 0 {{ total += {index}; }}\n"));
    }
    body.push_str("        assert_eq!(total, 4005);\n    }\n}\n");
    baseline_with_lib(dir.path(), &body);
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
    assert_has_rule(&report, "test-quality.long-test");
    for rule_id in [
        "size.function-length",
        "complexity.cyclomatic",
        "complexity.nesting-depth",
        "complexity.npath",
        "complexity.cognitive",
        "metrics.halstead-volume",
        "metrics.maintainability-pressure",
    ] {
        assert!(
            !report.findings.iter().any(|finding| {
                finding.rule_id == rule_id && finding.symbol.as_deref() == Some("long_setup")
            }),
            "calibration expected `{rule_id}` to skip test function `long_setup`; findings={:?}",
            rule_ids(&report)
        );
    }
}

/// Proves that `sensitive-data.api-key-pattern` recognises common synthetic
/// provider-shaped tokens beyond the original narrow prefix set.
#[test]
pub(crate) fn calibration_api_key_pattern_detects_common_formats() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let github_fine_grained = concat!("github_", "pat_", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let gitlab_token = concat!("gl", "pat-", "aaaaaaaaaaaaaaaaaaaaaaaa");
    let npm_token = concat!("npm_", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let azure_storage = concat!(
        "DefaultEndpointsProtocol=https;AccountName=acct;",
        "AccountKey=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;",
        "EndpointSuffix=core.windows.net"
    );
    let body = format!(
        r#"/// Probe.
pub fn entry() {{
    let _stripe_test = "sk_test_aaaaaaaaaaaaaaaaaaaaaaaa";
    let _stripe_pub = "pk_live_aaaaaaaaaaaaaaaaaaaaaaaa";
    let _stripe_restricted = "rk_live_aaaaaaaaaaaaaaaaaaaaaaaa";
    let _github_oauth = "gho_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _github_fine_grained = "{github_fine_grained}";
    let _gitlab_token = "{gitlab_token}";
    let _npm_token = "{npm_token}";
    let _openai_legacy = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _google_api = "AIzaSyAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _azure_bus = "Endpoint=sb://example.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _azure_storage = "{azure_storage}";
}}
"#
    );
    baseline_with_lib(dir.path(), &body);
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
    let api_key_findings = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.api-key-pattern")
        .count();
    assert_eq!(
        api_key_findings,
        11,
        "calibration expected all common synthetic API-key formats to fire; findings={:?}",
        rule_ids(&report)
    );
}

#[test]
pub(crate) fn calibration_hardcoded_env_value_detects_structured_config_keys() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("secrets.yaml"),
        "database_password: yaml-secret-123\napi_token: yaml-token-456\n",
    )
    .expect("yaml write");
    fs::write(
        dir.path().join("settings.json"),
        "{\n  \"database_url\":\"postgres://user:secret@db/app\",\n  \"service-token\":\"json-secret-123\"\n}\n",
    )
    .expect("json write");

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
    let hardcoded_env_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.hardcoded-env-value")
        .collect();
    assert_eq!(
        hardcoded_env_findings.len(),
        4,
        "expected YAML/JSON secret-like assignments to fire; findings={hardcoded_env_findings:?}"
    );
}

#[test]
pub(crate) fn calibration_process_command_records_risk_signals() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn run(command: &str, path: &str, dir: &std::path::Path) {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("PATH", path)
        .current_dir(dir);
}
"#,
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
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "security.process-command")
        .expect("process-command finding");
    let signals: BTreeSet<&str> = finding
        .metadata
        .get("riskSignals")
        .and_then(Value::as_array)
        .expect("riskSignals array")
        .iter()
        .map(|signal| signal.as_str().expect("signal string"))
        .collect();
    for expected in [
        "shell-interpreter",
        "shell-command-argument",
        "custom-environment",
        "custom-working-directory",
    ] {
        assert!(
            signals.contains(expected),
            "missing `{expected}` from risk signals: {signals:?}"
        );
    }
}

#[test]
pub(crate) fn calibration_security_rubric_improvements_have_false_positive_guards() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn tls() {
    let _dangerous = reqwest::Client::builder()
        .danger_accept_invalid_certs(true);
    let _safe = reqwest::Client::builder()
        .danger_accept_invalid_certs(false);
}
"#,
    );
    write_config(
        dir.path(),
        r#"
paths:
  ignore:
    - .github/**
    - target/**
"#,
    );
    fs::create_dir_all(dir.path().join(".github/workflows")).expect("workflow dir");
    fs::write(
        dir.path().join(".github/workflows/ci.yml"),
        "name: ci\njobs:\n  test:\n    steps:\n      - run: echo '${{ github.event.pull_request.title }}'\n      - run: echo '${{ github.ref }}'\n",
    )
    .expect("workflow write");

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

    let tls_count = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.tls-verification-disabled")
        .count();
    let config_count = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "config.security-blind-ignore")
        .count();
    let ci_count = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "ci.github-event-shell-interpolation")
        .count();

    assert_eq!(
        tls_count,
        1,
        "TLS guard count drifted: {:?}",
        rule_ids(&report)
    );
    assert_eq!(
        config_count,
        1,
        "config ignore guard count drifted: {:?}",
        rule_ids(&report)
    );
    assert_eq!(
        ci_count,
        1,
        "CI interpolation guard count drifted: {:?}",
        rule_ids(&report)
    );
}

#[test]
pub(crate) fn calibration_narrow_security_rules_have_false_positive_guards() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"use md5::Md5;
use sha2::Sha256;

/// Probe.
pub fn entry(tenant: &str) {
    let _dynamic = sqlx::query(format!("select * from users_{tenant}"));
    let _static = sqlx::query("select * from users");
    let _weak = Md5::new();
    let _strong = Sha256::new();
    let _http_credential = "https://user:secret@example.invalid/path";
    let _plain_http = "https://example.invalid/path";
    let _db_credential = "postgres://user:secret@db/app";
}
"#,
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

    let sql_count = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.sql-dynamic-query")
        .count();
    let weak_crypto_count = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.weak-crypto")
        .count();
    let url_credential_count = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.url-embedded-credentials")
        .count();
    let database_url_count = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.database-url-password")
        .count();

    assert_eq!(
        sql_count,
        1,
        "SQL dynamic-query guard count drifted: {:?}",
        rule_ids(&report)
    );
    assert_eq!(
        weak_crypto_count,
        1,
        "weak-crypto guard count drifted: {:?}",
        rule_ids(&report)
    );
    assert_eq!(
        url_credential_count,
        1,
        "URL credential guard count drifted: {:?}",
        rule_ids(&report)
    );
    assert_eq!(
        database_url_count,
        1,
        "database URL guard count drifted: {:?}",
        rule_ids(&report)
    );
}

/// Proves that `sensitive-data.hardcoded-env-value` still catches
/// production Rust literals but ignores fixture strings in test context.
#[test]
pub(crate) fn calibration_hardcoded_env_value_skips_test_fixture_strings() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn entry() {
    let production = "DATABASE_PASSWORD=production-secret-123";
    assert!(production.contains("DATABASE_PASSWORD"));
}

#[cfg(test)]
mod fixtures {
    #[test]
    fn fixture_text_contains_secret_pattern() {
        let fixture = "DATABASE_PASSWORD=correct-horse-battery-123";
        assert!(fixture.contains("PASSWORD"));
    }
}
"#,
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
    let hardcoded_env_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.hardcoded-env-value")
        .collect();
    assert_eq!(
        hardcoded_env_findings.len(),
        1,
        "calibration expected only the production env-style assignment to fire; findings={:?}",
        rule_ids(&report)
    );
    assert_eq!(hardcoded_env_findings[0].line, Some(3));
}
