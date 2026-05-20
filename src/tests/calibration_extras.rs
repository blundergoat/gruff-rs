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
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn entry() {
    let _stripe_test = "sk_test_aaaaaaaaaaaaaaaaaaaaaaaa";
    let _stripe_pub = "pk_live_aaaaaaaaaaaaaaaaaaaaaaaa";
    let _github_oauth = "gho_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _openai_legacy = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _google_api = "AIzaSyAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _azure_bus = "Endpoint=sb://example.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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
    let api_key_findings = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.api-key-pattern")
        .count();
    assert_eq!(
        api_key_findings,
        6,
        "calibration expected all common synthetic API-key formats to fire; findings={:?}",
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

