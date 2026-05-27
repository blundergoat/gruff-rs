use super::*;

fn make_finding(rule_id: &str, file: &str, line: usize, symbol: Option<&str>) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!("Synthetic finding for {rule_id} at line {line}"),
        file_path: file.to_string(),
        line: Some(line),
        severity: Severity::Advisory,
        pillar: Pillar::Naming,
        confidence: Confidence::High,
        symbol: symbol.map(str::to_string),
        remediation: None,
        metadata: serde_json::json!({}),
    })
}

#[test]
pub(crate) fn stable_identity_is_invariant_under_line_shifts() {
    let same_symbol_line_1 = make_finding("naming.short", "src/foo.rs", 1, Some("x"));
    let same_symbol_line_42 = make_finding("naming.short", "src/foo.rs", 42, Some("x"));

    assert_eq!(
        same_symbol_line_1.stable_identity, same_symbol_line_42.stable_identity,
        "stable identity must be invariant under line shifts for the same rule + symbol",
    );
    assert_ne!(
        same_symbol_line_1.fingerprint, same_symbol_line_42.fingerprint,
        "fingerprint MUST shift with line - that's the baseline contract this milestone preserves",
    );
}

#[test]
pub(crate) fn stable_identity_distinguishes_rule_ids() {
    let one_rule = make_finding("naming.short", "src/foo.rs", 10, Some("x"));
    let other_rule = make_finding("naming.generic", "src/foo.rs", 10, Some("x"));

    assert_ne!(
        one_rule.stable_identity, other_rule.stable_identity,
        "two findings differing only by rule_id must have different stable identities",
    );
}

#[test]
pub(crate) fn stable_identity_distinguishes_files() {
    let in_first_file = make_finding("naming.short", "src/auth.rs", 10, Some("x"));
    let in_second_file = make_finding("naming.short", "src/api.rs", 10, Some("x"));

    assert_ne!(
        in_first_file.stable_identity,
        in_second_file.stable_identity
    );
}

#[test]
pub(crate) fn stable_identity_falls_back_to_message_when_symbol_is_none() {
    fn finding_with(message: &str, file: &str, line: usize) -> Finding {
        Finding::new(FindingDescriptor {
            rule_id: "sensitive-data.api-key".to_string(),
            message: message.to_string(),
            file_path: file.to_string(),
            line: Some(line),
            severity: Severity::Advisory,
            pillar: Pillar::SensitiveData,
            confidence: Confidence::High,
            symbol: None,
            remediation: None,
            metadata: serde_json::json!({}),
        })
    }

    let same_message_line_10 = finding_with("API key pattern detected.", "src/foo.rs", 10);
    let same_message_line_20 = finding_with("API key pattern detected.", "src/foo.rs", 20);
    assert_eq!(
        same_message_line_10.stable_identity, same_message_line_20.stable_identity,
        "same message + same file + no symbol must produce a line-invariant identity",
    );

    let different_message = finding_with("Different message.", "src/foo.rs", 10);
    assert_ne!(
        same_message_line_10.stable_identity, different_message.stable_identity,
        "different message text must produce a different identity when symbol is absent",
    );
}

#[test]
pub(crate) fn stable_identity_is_sixteen_hex_chars() {
    let finding = make_finding("naming.short", "src/foo.rs", 1, Some("x"));
    assert_eq!(
        finding.stable_identity.len(),
        16,
        "stable identity must be a 16-character SHA-256 prefix (got {:?})",
        finding.stable_identity
    );
    assert!(
        finding
            .stable_identity
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "stable identity must be lowercase hex",
    );
}

#[test]
pub(crate) fn fingerprint_byte_identical_to_pre_m02_formula() {
    // The fingerprint formula hashes rule_id, file_path, line (or 0), and
    // symbol (or empty) with `\0` separators. This test pins the
    // byte-for-byte output so any accidental change to the formula breaks
    // here before consumer baselines break.
    let finding = make_finding("naming.short", "src/foo.rs", 42, Some("x"));
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, b"naming.short");
    sha2::Digest::update(&mut hasher, b"\0");
    sha2::Digest::update(&mut hasher, b"src/foo.rs");
    sha2::Digest::update(&mut hasher, b"\0");
    sha2::Digest::update(&mut hasher, b"42");
    sha2::Digest::update(&mut hasher, b"\0");
    sha2::Digest::update(&mut hasher, b"x");
    let expected = format!("{:x}", hasher.finalize())[..16].to_string();
    assert_eq!(finding.fingerprint, expected);
}

#[test]
pub(crate) fn analyse_resolution_falls_through_cli_then_config_then_default() {
    let mut config = Config::default();
    config
        .minimum_severity
        .insert("analyse".to_string(), FailThreshold::Error);

    // No CLI override -> config wins.
    assert_eq!(
        resolve_fail_on(None, &config, "analyse", FailThreshold::Advisory),
        FailThreshold::Error
    );
    // CLI override beats config.
    assert_eq!(
        resolve_fail_on(
            Some(FailThreshold::Warning),
            &config,
            "analyse",
            FailThreshold::Advisory
        ),
        FailThreshold::Warning
    );
    // No config entry, no CLI -> binary default.
    let empty = Config::default();
    assert_eq!(
        resolve_fail_on(None, &empty, "analyse", FailThreshold::Error),
        FailThreshold::Error
    );
}

#[test]
pub(crate) fn report_resolution_returns_none_default_when_unset() {
    let empty = Config::default();
    assert_eq!(
        resolve_fail_on(None, &empty, "report", FailThreshold::None),
        FailThreshold::None
    );

    let mut config = Config::default();
    config
        .minimum_severity
        .insert("report".to_string(), FailThreshold::Warning);
    assert_eq!(
        resolve_fail_on(None, &config, "report", FailThreshold::None),
        FailThreshold::Warning
    );
    assert_eq!(
        resolve_fail_on(
            Some(FailThreshold::Error),
            &config,
            "report",
            FailThreshold::None
        ),
        FailThreshold::Error
    );
}

#[test]
pub(crate) fn config_entry_for_one_command_does_not_leak_to_another() {
    let mut config = Config::default();
    config
        .minimum_severity
        .insert("analyse".to_string(), FailThreshold::Error);

    // analyse picks up its own override.
    assert_eq!(
        resolve_fail_on(None, &config, "analyse", FailThreshold::Advisory),
        FailThreshold::Error
    );
    // report does not see analyse's override.
    assert_eq!(
        resolve_fail_on(None, &config, "report", FailThreshold::None),
        FailThreshold::None
    );
}
fn synth_finding(rule_id: &str, severity: Severity, pillar: Pillar) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!("Synthetic finding for {rule_id}."),
        file_path: "src/auth.rs".to_string(),
        line: Some(10),
        severity,
        pillar,
        confidence: Confidence::High,
        symbol: None,
        remediation: None,
        metadata: serde_json::json!({}),
    })
}

#[test]
pub(crate) fn excluded_rule_findings_do_not_affect_composite_penalty() {
    let findings = vec![
        synth_finding(
            "docs.missing-public-doc",
            Severity::Advisory,
            Pillar::Documentation,
        ),
        synth_finding(
            "docs.missing-public-doc",
            Severity::Advisory,
            Pillar::Documentation,
        ),
    ];

    let baseline_config = Config::default();
    let baseline_score = score_report(&findings, &baseline_config);
    assert!(
        baseline_score.composite < 100.0,
        "advisory findings should depress the score under default config",
    );

    let mut exclusion_config = Config::default();
    exclusion_config.rule_settings.insert(
        "docs.missing-public-doc".to_string(),
        RuleSetting {
            exclude_from_score: Some(true),
            ..RuleSetting::default()
        },
    );
    let excluded_score = score_report(&findings, &exclusion_config);
    assert_eq!(
        excluded_score.composite, 100.0,
        "exclusion must zero out the rule's penalty contribution",
    );

    let doc_pillar = excluded_score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == Pillar::Documentation)
        .expect("documentation pillar present");
    assert_eq!(
        doc_pillar.findings, 2,
        "exclusion preserves the per-pillar finding count - only the penalty bucket is empty",
    );
    assert_eq!(
        doc_pillar.penalty, 0.0,
        "exclusion zeroes the penalty bucket",
    );
}

#[test]
pub(crate) fn non_excluded_rule_scores_normally() {
    let findings = vec![synth_finding(
        "naming.short-variable",
        Severity::Advisory,
        Pillar::Naming,
    )];
    let baseline = score_report(&findings, &Config::default());
    assert!(baseline.composite < 100.0);

    let mut other_excluded = Config::default();
    other_excluded.rule_settings.insert(
        "docs.missing-public-doc".to_string(),
        RuleSetting {
            exclude_from_score: Some(true),
            ..RuleSetting::default()
        },
    );
    let still_penalised = score_report(&findings, &other_excluded);
    assert_eq!(
        still_penalised.composite, baseline.composite,
        "excluding one rule does not affect penalty contributions from others",
    );
}

#[test]
pub(crate) fn excluding_security_rule_emits_warning_diagnostic() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(
        dir.path(),
        "rules:\n  security.process-command:\n    excludeFromScore: true\n",
    );
    let options = AnalysisOptions {
        paths: vec![std::path::PathBuf::from(".")],
        no_baseline: true,
        ..default_test_options()
    };
    let config = load_config(dir.path(), &options).expect("config loads");
    let report = run_analysis_in_project(dir.path(), &options, &config).expect("analysis runs");

    let diagnostic = report
        .diagnostics
        .iter()
        .find(|d| d.diagnostic_type == "excluded-security-rule-from-score")
        .expect("diagnostic must surface for excluded Security rule");
    assert!(
        diagnostic.message.contains("security.process-command"),
        "diagnostic names the affected rule: {}",
        diagnostic.message
    );
    assert!(
        !diagnostic.is_failure(),
        "warning is non-fatal; strict-mode escalation deferred",
    );
}

#[test]
pub(crate) fn excluding_non_security_rule_emits_no_diagnostic() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(
        dir.path(),
        "rules:\n  docs.missing-public-doc:\n    excludeFromScore: true\n",
    );
    let options = AnalysisOptions {
        paths: vec![std::path::PathBuf::from(".")],
        no_baseline: true,
        ..default_test_options()
    };
    let config = load_config(dir.path(), &options).expect("config loads");
    let report = run_analysis_in_project(dir.path(), &options, &config).expect("analysis runs");

    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.diagnostic_type == "excluded-security-rule-from-score"),
        "non-Security/SensitiveData exclusions are silent: {:?}",
        report.diagnostics,
    );
}

#[test]
pub(crate) fn exclude_from_score_rejects_non_boolean_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(
        dir.path(),
        "rules:\n  docs.missing-public-doc:\n    excludeFromScore: \"yes\"\n",
    );
    let error =
        load_config(dir.path(), &default_test_options()).expect_err("non-boolean must reject");
    assert!(
        error.contains("excludeFromScore"),
        "error names the config key: {error}",
    );
    assert!(
        error.contains("boolean"),
        "error explains the required shape: {error}",
    );
}

#[test]
pub(crate) fn excluded_security_rule_diagnostics_are_sorted_by_rule_id() {
    // Two Security/SensitiveData built-ins excluded at the same time.
    // `rule_settings` is a HashMap, so the iteration order of the source
    // is non-deterministic; the diagnostics list must still come out in
    // a stable sorted order so JSON/HTML output stays reproducible.
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(
        dir.path(),
        "rules:\n  \
         security.process-command:\n    excludeFromScore: true\n  \
         sensitive-data.api-key-pattern:\n    excludeFromScore: true\n",
    );
    let options = AnalysisOptions {
        paths: vec![std::path::PathBuf::from(".")],
        no_baseline: true,
        ..default_test_options()
    };
    let config = load_config(dir.path(), &options).expect("config loads");
    let report = run_analysis_in_project(dir.path(), &options, &config).expect("analysis runs");

    let security_diagnostics: Vec<&str> = report
        .diagnostics
        .iter()
        .filter(|d| d.diagnostic_type == "excluded-security-rule-from-score")
        .map(|d| d.message.as_str())
        .collect();
    assert_eq!(
        security_diagnostics.len(),
        2,
        "both excluded rules surface: {security_diagnostics:?}"
    );
    let mut sorted = security_diagnostics.clone();
    sorted.sort();
    assert_eq!(
        security_diagnostics, sorted,
        "diagnostics must already be sorted by rule id; got {security_diagnostics:?}"
    );
}

#[test]
pub(crate) fn custom_rules_cannot_set_exclude_from_score() {
    // ADR-014 + the M04a config-loader restriction together mean custom
    // rules can only carry `enabled` under `rules.<id>:`. PR #3 review
    // worried about a "silent scoring blind spot" when a custom
    // Security/SensitiveData rule sets `excludeFromScore: true`, but the
    // loader rejects that combination outright. Pin the loader behaviour
    // so the assumption stays explicit; future lifts must update this
    // test alongside the analysis-side diagnostic coverage.
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(
        dir.path(),
        r#"
rules:
  custom.fake-secret:
    excludeFromScore: true
custom_rules:
  - id: custom.fake-secret
    pillar: Security
    severity: warning
    message: Fake secret pattern
    scope: text
    pattern: 'SECRET_TOKEN'
"#,
    );
    let error = load_config(dir.path(), &default_test_options())
        .expect_err("custom rule + excludeFromScore must reject at load time");
    assert!(
        error.contains("custom rule `custom.fake-secret`")
            && error.contains("only supports `enabled`"),
        "error names the rule + the loader restriction: {error}",
    );
}
