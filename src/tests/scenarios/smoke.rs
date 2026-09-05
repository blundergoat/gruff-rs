use super::*;

#[test]
pub(crate) fn analysis_finds_core_rust_smells() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let rust_file = dir.path().join("bad.rs");
    fs::write(
        &rust_file,
        [
            r#"pub struct Bad {
    pub name: String,
}

impl Bad {
    pub fn process(a: bool, b: Vec<String>, c: String, d: String, e: String, f: String, g: String, h: String) {
        if a {
            "#,
            PROCESS_COMMAND_NEW,
            r#"("sh").arg("-c").arg(c).spawn().unwrap();
        }
        println!("{}{}{}", d, e, f);
    }
}

#[test]
fn test_no_assert() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}
"#,
        ]
        .concat(),
    )
    .expect("fixture write");
    let report = analyse_project_paths(dir.path(), vec![PathBuf::from(".")]);

    let rule_ids: BTreeSet<&str> = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(rule_ids.contains("security.process-command"));
    assert!(rule_ids.contains("size.parameter-count"));
    assert!(rule_ids.contains("test-quality.sleep-in-test"));
}

#[test]
pub(crate) fn fixture_scan_contract_preserves_existing_sample_findings() {
    let _guard = analysis_lock();
    let report = analyse_test_paths(vec![PathBuf::from("fixtures/sample.rs")]);

    assert_only_partial_context_diagnostic(&report);
    assert_eq!(report.summary.total, report.findings.len());
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.file_path == "fixtures/sample.rs")
            .count(),
        10
    );

    let expected = [
        (
            "docs.missing-public-doc",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(1),
            Some("SampleAnalyzer"),
            "33f9dd5201230832",
        ),
        (
            "docs.missing-public-doc",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("process"),
            "44dc31cc3f2fddf6",
        ),
        (
            "error-handling.public-unwrap",
            Severity::Warning,
            "fixtures/sample.rs",
            Some(7),
            Some("process"),
            "826987132b0ba61b",
        ),
        (
            "naming.generic-function",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("process"),
            "c3694de68d5ae921",
        ),
        (
            "size.parameter-count",
            Severity::Warning,
            "fixtures/sample.rs",
            Some(7),
            Some("process"),
            "ec04a7b3fcf15f6d",
        ),
        (
            "security.process-command",
            Severity::Warning,
            "fixtures/sample.rs",
            Some(11),
            None,
            "c83527501efb5e12",
        ),
        (
            "waste.unwrap-expect",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(11),
            None,
            "80bf1a6b54a67ccf",
        ),
        (
            "sensitive-data.aws-access-key",
            Severity::Error,
            "fixtures/sample.rs",
            Some(16),
            None,
            "1aae444024c630df",
        ),
        (
            "sensitive-data.database-url-password",
            Severity::Error,
            "fixtures/sample.rs",
            Some(17),
            None,
            "79a7540d1b61cf02",
        ),
        (
            // Line 24 is the `#[test]` attribute, the item's own first line. Before M07's anchor repair this
            // pinned line 23, the blank separator belonging to the function above it.
            "test-quality.sleep-in-test",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(24),
            Some("test_sleeps_without_assertion"),
            "3da3d9f1b4bfed50",
        ),
    ];

    for (rule_id, severity, path, line, symbol, fingerprint) in expected {
        assert!(
            report.findings.iter().any(|finding| {
                finding.rule_id == rule_id
                    && finding.severity == severity
                    && finding.file_path == path
                    && finding.line == line
                    && finding.symbol.as_deref() == symbol
                    && finding.fingerprint == fingerprint
            }),
            "missing expected fixture finding `{rule_id}` at {path}:{line:?}"
        );
    }
}

#[test]
pub(crate) fn block_findings_anchor_on_the_item_not_the_blank_line_above_it() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let rust_file = dir.path().join("anchors.rs");

    // Two items separated by a blank line, the layout every Rust file uses. Before M07's repair the prefix
    // walk crossed that separator and reported the blank line, which belongs to the function above.
    let source = r#"pub fn first() -> usize {
    1
}

/// Doc line for second.
pub fn second(alpha: usize, beta: usize) -> usize {
    alpha + beta
}

#[test]
fn third() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}
"#;
    fs::write(&rust_file, source).expect("fixture write");

    let report = analyse_project_paths(dir.path(), vec![PathBuf::from(".")]);
    let lines: Vec<&str> = source.lines().collect();

    assert!(
        !report.findings.is_empty(),
        "the anchor fixture produced no findings, so it could not prove where one lands"
    );

    // The claim is about the source text at the reported line, not about which rules happened to fire.
    for finding in &report.findings {
        let Some(line) = finding.line else {
            continue;
        };
        let text = lines.get(line - 1).copied().unwrap_or_default();
        assert!(
            !text.trim().is_empty(),
            "`{}` anchors on blank line {line}; block anchors must land on the item's own first line",
            finding.rule_id
        );
    }

    // `second` carries a doc comment, so its block starts at the doc line, never at the blank line above it.
    let second = report
        .findings
        .iter()
        .find(|finding| finding.symbol.as_deref() == Some("second"))
        .expect("a finding on `second`");

    assert_eq!(
        second.line,
        Some(5),
        "`second` must anchor on its doc line, not the blank line 4 above it"
    );
}

#[test]
pub(crate) fn parser_handles_raw_strings_macros_impls_and_test_attributes() {
    let _guard = analysis_lock();
    let report = analyse_test_paths(vec![
        PathBuf::from("tests/fixtures/parser/raw_strings.rs"),
        PathBuf::from("tests/fixtures/parser/macros_impls.rs"),
    ]);

    assert_only_partial_context_diagnostic(&report);

    let parameter_count = report
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == "size.parameter-count"
                && finding.file_path == "tests/fixtures/parser/macros_impls.rs"
                && finding.symbol.as_deref() == Some("process")
        })
        .expect("impl method parameter-count finding");
    assert_eq!(parameter_count.line, Some(12));
}

#[test]
pub(crate) fn parameter_count_threshold_allows_seven_and_flags_eight() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn six(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 {
    a + b + c + d + e + f
}

/// Probe.
pub fn seven(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32) -> i32 {
    a + b + c + d + e + f + g
}

/// Probe.
pub fn eight(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32) -> i32 {
    a + b + c + d + e + f + g + h
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
    let parameter_symbols: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "size.parameter-count")
        .filter_map(|finding| finding.symbol.as_deref())
        .collect();
    assert_eq!(
        parameter_symbols,
        vec!["eight"],
        "parameter-count should allow 6 and 7 params, then flag 8; findings={:?}",
        report.findings
    );
}

#[test]
pub(crate) fn invalid_rust_reports_parse_error_and_keeps_text_rules() {
    let _guard = analysis_lock();
    let report = analyse_test_paths(vec![PathBuf::from("tests/fixtures/parser/invalid.rs")]);

    assert_eq!(
        diagnostic_types(&report),
        vec!["partial-context-rule-suppressed", "parse-error"]
    );
    let parse_error = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.diagnostic_type == "parse-error")
        .expect("parse-error diagnostic");
    assert_eq!(
        parse_error.file_path.as_deref(),
        Some("tests/fixtures/parser/invalid.rs")
    );

    let rule_ids: BTreeSet<&str> = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(rule_ids.contains("sensitive-data.aws-access-key"));
    assert!(!rule_ids.contains("size.function-length"));
}

#[test]
pub(crate) fn source_discovery_covers_ignores_text_files_and_missing_paths() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join(".git/hooks")).expect("git hooks dir");
    fs::create_dir_all(dir.path().join(".git/info")).expect("git info dir");
    fs::create_dir_all(dir.path().join(".agents/skills")).expect("agents dir");
    fs::create_dir_all(dir.path().join(".claude")).expect("claude dir");
    fs::create_dir_all(dir.path().join(".codex/hooks")).expect("codex dir");
    fs::create_dir_all(dir.path().join(".github/workflows")).expect("github dir");
    fs::create_dir_all(dir.path().join(".goat-flow")).expect("goat dir");
    fs::create_dir_all(dir.path().join("local")).expect("local dir");
    fs::create_dir_all(dir.path().join("nested")).expect("nested dir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::create_dir_all(dir.path().join("target")).expect("target dir");
    fs::create_dir_all(dir.path().join("ignored")).expect("ignored dir");
    fs::write(
        dir.path().join(".gitignore"),
        "local/**\n.goat-flow/audit-cache.json\n",
    )
    .expect("gitignore write");
    fs::write(dir.path().join(".git/info/exclude"), "info-excluded.env\n")
        .expect("git exclude write");
    fs::write(
        dir.path().join(".git/hooks/pre-commit.sh"),
        "DATABASE_PASSWORD=git-hook-secret-123\n",
    )
    .expect("git hook write");
    fs::write(dir.path().join("nested/.gitignore"), "secret.env\n")
        .expect("nested gitignore write");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("info-excluded.env"),
        concat!("DATABASE_", "PASSWORD=info-excluded-secret-123\n"),
    )
    .expect("info excluded write");
    fs::write(
        dir.path().join(".agents/skills/demo.md"),
        "# Demo\nDATABASE_PASSWORD=agents-secret-123\n",
    )
    .expect("agents write");
    fs::write(
        dir.path().join(".claude/settings.json"),
        r#"{"DATABASE_PASSWORD":"claude-secret-123"}"#,
    )
    .expect("claude write");
    fs::write(
        dir.path().join(".codex/hooks/deny-dangerous.sh"),
        "DATABASE_PASSWORD=codex-secret-123\n",
    )
    .expect("codex write");
    fs::write(
        dir.path().join(".github/workflows/ci.yml"),
        "env:\n  DATABASE_PASSWORD=github-secret-123\n",
    )
    .expect("github write");
    fs::write(
        dir.path().join(".goat-flow/architecture.md"),
        "# Architecture\nDATABASE_PASSWORD=goat-secret-123\n",
    )
    .expect("goat write");
    fs::write(
        dir.path().join(".goat-flow/audit-cache.json"),
        r#"{"DATABASE_PASSWORD":"ignored-goat-secret-123"}"#,
    )
    .expect("goat cache write");
    fs::write(
        dir.path().join("src/lib.rs"),
        "/// Ready.\npub fn is_ready() -> bool { true }\n",
    )
    .expect("rust write");
    fs::write(
        dir.path().join("local/secret.env"),
        concat!("DATABASE_", "PASSWORD=local-secret-123\n"),
    )
    .expect("local secret write");
    fs::write(
        dir.path().join("nested/secret.env"),
        concat!("DATABASE_", "PASSWORD=nested-secret-123\n"),
    )
    .expect("nested secret write");
    fs::write(
        dir.path().join("nested/visible.env"),
        concat!("DATABASE_", "PASSWORD=visible-secret-123\n"),
    )
    .expect("nested visible write");
    fs::write(
        dir.path().join("target/secret.env"),
        concat!("DATABASE_", "PASSWORD=target-secret-123\n"),
    )
    .expect("target secret write");
    fs::write(
        dir.path().join("ignored/secret.env"),
        concat!("DATABASE_", "PASSWORD=ignored-secret-123\n"),
    )
    .expect("ignored secret write");
    write_config(dir.path(), r#"{ "paths": { "ignore": ["ignored/**"] } }"#);

    let discovery = discover_sources(
        dir.path(),
        &AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
        &load_config(
            dir.path(),
            &AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("config loads"),
    );
    let discovered_paths: BTreeSet<&str> = discovery
        .files
        .iter()
        .map(|file| file.display_path.as_str())
        .collect();
    assert!(discovered_paths.contains(".agents/skills/demo.md"));
    assert!(discovered_paths.contains(".claude/settings.json"));
    assert!(discovered_paths.contains(".codex/hooks/deny-dangerous.sh"));
    assert!(discovered_paths.contains(".github/workflows/ci.yml"));
    assert!(discovered_paths.contains(".goat-flow/architecture.md"));
    assert!(discovered_paths.contains("nested/visible.env"));
    assert!(discovered_paths.contains("src/lib.rs"));
    assert!(!discovered_paths.contains(".git/hooks/pre-commit.sh"));
    assert!(!discovered_paths.contains(".goat-flow/audit-cache.json"));
    assert!(!discovered_paths.contains("info-excluded.env"));
    assert!(!discovered_paths.contains("local/secret.env"));
    assert!(!discovered_paths.contains("nested/secret.env"));
    assert!(discovered_paths.contains("target/secret.env"));
    assert!(!discovered_paths.contains("ignored/secret.env"));

    let default_scan = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert!(!default_scan
        .paths
        .ignored_paths
        .contains(&"target".to_string()));
    assert!(default_scan
        .paths
        .ignored_paths
        .contains(&"ignored".to_string()));
    assert!(default_scan.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == ".github/workflows/ci.yml"
    }));
    assert!(default_scan.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "target/secret.env"
    }));
    assert!(!default_scan.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "local/secret.env"
    }));
    assert!(!default_scan.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "info-excluded.env"
    }));
    assert!(!default_scan.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == ".git/hooks/pre-commit.sh"
    }));

    let include_ignored = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            include_ignored: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert!(include_ignored.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "local/secret.env"
    }));
    // ADR-018: config `paths.ignore` is authoritative. `--include-ignored` opts
    // into git/default ignores only and must NOT reveal config-ignored files,
    // so `ignored/**` stays excluded here even with include_ignored.
    assert!(!include_ignored.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "ignored/secret.env"
    }));
    assert!(include_ignored.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "info-excluded.env"
    }));
    assert!(include_ignored.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == "target/secret.env"
    }));
    assert!(!include_ignored.findings.iter().any(|finding| {
        finding.rule_id == "sensitive-data.hardcoded-env-value"
            && finding.file_path == ".git/hooks/pre-commit.sh"
    }));

    let text_scan = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("local/secret.env")],
            no_config: true,
            include_ignored: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("text scan succeeds");
    assert_has_rule(&text_scan, "sensitive-data.hardcoded-env-value");

    let missing = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("missing.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("missing path is diagnostic, not hard error");
    assert_eq!(missing.diagnostics.len(), 1);
    assert_eq!(missing.diagnostics[0].diagnostic_type, "missing-path");
}

#[test]
pub(crate) fn scoring_includes_all_static_pillars_and_weights_findings() {
    let clean = score_report(&[], &Config::default(), 10);
    assert_eq!(clean.composite, Some(100.0));
    assert_eq!(clean.grade.as_deref(), Some("A"));
    assert_eq!(clean.pillars.len(), SCORE_PILLARS.len());
    assert!(clean.pillars.iter().all(|pillar| pillar.findings == 0));

    let findings = vec![
        test_finding(
            "security.process-command",
            "src/a.rs",
            1,
            Severity::Error,
            Pillar::Security,
        ),
        test_finding_with_confidence(
            "dead-code.unused-private-function",
            "src/b.rs",
            1,
            TestFindingClassification {
                severity: Severity::Warning,
                pillar: Pillar::DeadCode,
                confidence: Confidence::Low,
            },
        ),
        test_finding(
            "docs.stale-todo",
            "src/b.rs",
            2,
            Severity::Advisory,
            Pillar::Documentation,
        ),
    ];
    let score = score_report(&findings, &Config::default(), 10);
    assert_eq!(score.grade.as_deref(), Some("A"));
    assert_eq!(score.top_offenders[0].file_path, "src/a.rs");
    let security = score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == Pillar::Security)
        .expect("security pillar");
    let dead_code = score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == Pillar::DeadCode)
        .expect("dead-code pillar");
    // Over ten evaluated files: security carries one high-confidence error (weight 12.0, density
    // 1.20) and dead-code one low-confidence warning (weight 2.0, density 0.20).
    assert_eq!(security.score, Some(53.85));
    assert_eq!(dead_code.score, Some(66.67));

    assert_eq!(grade(90.0), "A");
    assert_eq!(grade(80.0), "B");
    assert_eq!(grade(70.0), "C");
    assert_eq!(grade(60.0), "D");
    assert_eq!(grade(59.9), "F");
}

#[test]
pub(crate) fn bounded_rust_source_keeps_text_safety_and_drops_deep_analysis() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let source = concat!(
        "pub fn run() {\n",
        "    let key = \"AKIA1234567890ABCDEF\";\n",
        "    std::process::Command::new(\"sh\").spawn().unwrap();\n",
        "}\n",
    );
    fs::write(dir.path().join("large.rs"), source).expect("Rust fixture write");
    let options = AnalysisOptions {
        paths: vec![PathBuf::from("large.rs")],
        no_config: true,
        no_baseline: true,
        ..default_test_options()
    };
    let mut config = Config::default();
    config.deep_scan_budget = DeepScanBudget {
        enabled: true,
        max_lines: 1,
        max_bytes: usize::MAX,
        override_state: "cli",
    };
    config.rule_settings.insert(
        "size.file-length".to_string(),
        RuleSetting {
            threshold: Some(1.0),
            ..RuleSetting::default()
        },
    );

    let report = run_analysis_in_project(dir.path(), &options, &config)
        .expect("bounded Rust analysis succeeds");
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.diagnostic_type == "bounded-deep-scan")
        .expect("bounded deep scan is visible");

    assert_eq!(report.paths.analysed_files, 1);
    assert_eq!(diagnostic.invalidates_run, Some(false));
    assert!(!diagnostic.is_failure());
    assert!(diagnostic.message.contains("path=large.rs"));
    assert!(diagnostic.message.contains("lines=5"));
    assert!(diagnostic
        .message
        .contains(&format!("bytes={}", source.len())));
    assert!(diagnostic.message.contains("maxLines=1"));
    assert!(diagnostic
        .message
        .contains(&format!("maxBytes={}", usize::MAX)));
    assert!(diagnostic.message.contains("override=cli"));
    assert_has_rule(&report, "size.file-length");
    assert_has_rule(&report, "sensitive-data.aws-access-key");
    assert_missing_rule(&report, "security.process-command");
}

#[test]
pub(crate) fn deep_scan_budget_honours_both_boundaries_disable_and_source_classification() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let rust_source = concat!(
        "pub fn run() {\n",
        "    std::process::Command::new(\"sh\").spawn().unwrap();\n",
        "}\n",
    );
    fs::write(dir.path().join("boundary.rs"), rust_source).expect("Rust fixture write");
    fs::write(
        dir.path().join("oversized.env"),
        "LEAKED=AKIA1234567890ABCDEF\nSECOND=value\n",
    )
    .expect("text fixture write");
    let rust_options = AnalysisOptions {
        paths: vec![PathBuf::from("boundary.rs")],
        no_config: true,
        no_baseline: true,
        ..default_test_options()
    };

    let mut equal = Config::default();
    equal.deep_scan_budget = DeepScanBudget {
        enabled: true,
        max_lines: rust_source.bytes().filter(|byte| *byte == b'\n').count() + 1,
        max_bytes: rust_source.len(),
        override_state: "config",
    };
    let equal_report = run_analysis_in_project(dir.path(), &rust_options, &equal)
        .expect("equal bounds remain deep-scanned");
    assert!(!diagnostic_types(&equal_report).contains(&"bounded-deep-scan"));
    assert_has_rule(&equal_report, "security.process-command");

    let mut byte_only = equal.clone();
    byte_only.deep_scan_budget.max_lines = usize::MAX;
    byte_only.deep_scan_budget.max_bytes = rust_source.len() - 1;
    let byte_report = run_analysis_in_project(dir.path(), &rust_options, &byte_only)
        .expect("byte-only overflow degrades");
    assert!(diagnostic_types(&byte_report).contains(&"bounded-deep-scan"));

    let mut disabled = byte_only.clone();
    disabled.deep_scan_budget.enabled = false;
    disabled.deep_scan_budget.override_state = "cli";
    let disabled_report = run_analysis_in_project(dir.path(), &rust_options, &disabled)
        .expect("disabled budget restores deep scan");
    assert!(!diagnostic_types(&disabled_report).contains(&"bounded-deep-scan"));
    assert_has_rule(&disabled_report, "security.process-command");

    let text_options = AnalysisOptions {
        paths: vec![PathBuf::from("oversized.env")],
        ..rust_options
    };
    let mut tiny = Config::default();
    tiny.deep_scan_budget = DeepScanBudget {
        enabled: true,
        max_lines: 1,
        max_bytes: 1,
        override_state: "cli",
    };
    let text_report = run_analysis_in_project(dir.path(), &text_options, &tiny)
        .expect("oversized non-code text remains fully scanned");
    assert_eq!(text_report.paths.analysed_files, 1);
    assert!(!diagnostic_types(&text_report).contains(&"bounded-deep-scan"));
    assert_has_rule(&text_report, "sensitive-data.aws-access-key");
}
