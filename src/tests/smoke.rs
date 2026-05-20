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
    pub fn process(a: bool, b: Vec<String>, c: String, d: String, e: String, f: String) {
        if a {
            "#,
            PROCESS_COMMAND_NEW,
            r#"("sh").arg("-c").arg(c).spawn().unwrap();
        }
        println!("{}{}{}", d, e, f);
    }
}

#[test]
pub(crate) fn fixture_scan_contract_preserves_existing_sample_findings() {
    let _guard = analysis_lock();
    let report = analyse_test_paths(vec![PathBuf::from("fixtures/sample.rs")]);

    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert_eq!(report.summary.total, report.findings.len());
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.file_path == "fixtures/sample.rs")
            .count(),
        18
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
            "modernisation.public-field",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(2),
            None,
            "bc7bce7d0361e8e7",
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
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("a"),
            "774487e8965bb4e2",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("b"),
            "450fd3ea76dd5ea3",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("c"),
            "5ac981000ba83401",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("d"),
            "e52f3842e9612076",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("e"),
            "8f6d56dc5dbd2e25",
        ),
        (
            "naming.short-variable",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(7),
            Some("f"),
            "2febe2864706223f",
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
            "test-quality.no-assertions",
            Severity::Warning,
            "fixtures/sample.rs",
            Some(23),
            Some("test_sleeps_without_assertion"),
            "7d01e1f8fa08edc9",
        ),
        (
            "test-quality.sleep-in-test",
            Severity::Advisory,
            "fixtures/sample.rs",
            Some(23),
            Some("test_sleeps_without_assertion"),
            "8e9591ae5cdf9beb",
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
pub(crate) fn parser_handles_raw_strings_macros_impls_and_test_attributes() {
    let _guard = analysis_lock();
    let report = analyse_test_paths(vec![
        PathBuf::from("tests/fixtures/parser/raw_strings.rs"),
        PathBuf::from("tests/fixtures/parser/macros_impls.rs"),
    ]);

    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);

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

    let no_assertions = report
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == "test-quality.no-assertions"
                && finding.file_path == "tests/fixtures/parser/macros_impls.rs"
                && finding.symbol.as_deref() == Some("test_macro_fixture")
        })
        .expect("test attribute no-assertions finding");
    assert_eq!(no_assertions.line, Some(20));
}

#[test]
pub(crate) fn invalid_rust_reports_parse_error_and_keeps_text_rules() {
    let _guard = analysis_lock();
    let report = analyse_test_paths(vec![PathBuf::from("tests/fixtures/parser/invalid.rs")]);

    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(report.diagnostics[0].diagnostic_type, "parse-error");
    assert_eq!(
        report.diagnostics[0].file_path.as_deref(),
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
    assert!(!discovered_paths.contains("target/secret.env"));
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
    assert!(default_scan
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
    assert!(include_ignored.findings.iter().any(|finding| {
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
    let clean = score_report(&[]);
    assert_eq!(clean.composite, 100.0);
    assert_eq!(clean.grade, "A");
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
            Severity::Warning,
            Pillar::DeadCode,
            Confidence::Low,
        ),
        test_finding(
            "docs.todo-density",
            "src/b.rs",
            2,
            Severity::Advisory,
            Pillar::Documentation,
        ),
    ];
    let score = score_report(&findings);
    assert_eq!(score.grade, "A");
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
    assert_eq!(security.score, 92.0);
    assert_eq!(dead_code.score, 98.0);

    assert_eq!(grade(90.0), "A");
    assert_eq!(grade(80.0), "B");
    assert_eq!(grade(70.0), "C");
    assert_eq!(grade(60.0), "D");
    assert_eq!(grade(59.9), "F");
}

