use super::*;

#[test]
pub(crate) fn custom_rule_text_scope_emits_deterministic_findings_with_builtins() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        concat!(
            "pub fn undocumented() {\n",
            "    let marker = \"ALPHA\";\n",
            "}\n",
            "// BETA\n"
        ),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.beta
    pillar: Documentation
    severity: advisory
    message: Beta marker
    scope: text
    pattern: BETA
  - id: custom.alpha
    pillar: Documentation
    severity: advisory
    message: Alpha marker
    scope: text
    pattern: ALPHA
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let ids: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    eprintln!("custom rule deterministic ids: {ids:?}");

    assert_eq!(
        ids,
        vec!["docs.missing-public-doc", "custom.alpha", "custom.beta"]
    );
    assert_eq!(
        report
            .findings
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![Some(1), Some(2), Some(4)]
    );
}

#[test]
pub(crate) fn custom_rule_rust_code_scope_masks_strings_and_comments() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        concat!(
            "fn string_only() {\n",
            "    // unsafe should stay comment-only\n",
            "    let marker = \"HACK\";\n",
            "    unsafe { std::ptr::read(&marker); }\n",
            "}\n",
        ),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.hack-code
    pillar: Documentation
    severity: warning
    message: Code marker
    scope: rust-code
    pattern: HACK
  - id: custom.hack-text
    pillar: Documentation
    severity: warning
    message: Text marker
    scope: text
    pattern: HACK
  - id: custom.unsafe-code
    pillar: Security
    severity: warning
    message: Unsafe code marker
    scope: rust-code
    pattern: '\bunsafe\b'
rules:
  select: ["custom.*"]
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert_has_rule(&report, "custom.hack-text");
    assert_missing_rule(&report, "custom.hack-code");
    let findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "custom.unsafe-code")
        .collect();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, Some(4));
}

#[test]
pub(crate) fn custom_rule_comments_scope_matches_comments_not_strings() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        concat!(
            "fn comments() {\n",
            "    let marker = \"// HACK\";\n",
            "}\n",
            "// HACK\n"
        ),
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.comment-hack
    pillar: Documentation
    severity: warning
    message: Comment marker
    scope: comments
    pattern: '(?m)^\s*//\s*HACK\b'
rules:
  select: ["custom.*"]
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let comment_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "custom.comment-hack")
        .collect();

    assert_eq!(comment_findings.len(), 1);
    assert_eq!(comment_findings[0].line, Some(4));
}

#[test]
pub(crate) fn custom_rule_comments_scope_handles_nested_block_comments() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        "fn comments() {}\n/* outer /* inner */ HACK still outer */\n",
    )
    .expect("fixture write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.nested-comment
    pillar: Documentation
    severity: warning
    message: Nested comment marker
    scope: comments
    pattern: 'HACK still outer'
rules:
  select: ["custom.*"]
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert_has_rule(&report, "custom.nested-comment");
}

#[test]
pub(crate) fn custom_rule_include_exclude_paths_are_honored() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src/generated")).expect("generated dir");
    fs::create_dir_all(dir.path().join("tests")).expect("tests dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("src/lib.rs"), "ALLOW_MARKER\n").expect("src write");
    fs::write(dir.path().join("src/generated/lib.rs"), "ALLOW_MARKER\n").expect("generated write");
    fs::write(dir.path().join("tests/fixture.rs"), "ALLOW_MARKER\n").expect("tests write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.path-marker
    pillar: Documentation
    severity: advisory
    message: Path marker
    scope: text
    pattern: ALLOW_MARKER
    include_paths: ["src/**"]
    exclude_paths: ["src/generated/**"]
rules:
  select: ["custom.*"]
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src"), PathBuf::from("tests")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let paths: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "custom.path-marker")
        .map(|finding| finding.file_path.as_str())
        .collect();

    assert_eq!(paths, vec!["src/lib.rs"]);
}

#[test]
pub(crate) fn custom_rule_config_rejects_duplicate_id_missing_prefix_bad_regex_and_bad_settings() {
    let dir = tempdir().expect("tempdir");
    let options = default_test_options();

    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.dup
    pillar: Documentation
    severity: advisory
    message: First
    scope: text
    pattern: FIRST
  - id: custom.dup
    pillar: Documentation
    severity: advisory
    message: Second
    scope: text
    pattern: SECOND
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("duplicate rejected");
    assert!(
        error.contains("duplicate custom rule id `custom.dup`"),
        "{error}"
    );

    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: no-prefix
    pillar: Documentation
    severity: advisory
    message: Missing prefix
    scope: text
    pattern: MARKER
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("prefix rejected");
    assert!(
        error.contains("must start with the reserved `custom.` namespace"),
        "{error}"
    );
    assert!(error.contains("custom_rules[0].id"), "{error}");

    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.bad-regex
    pillar: Documentation
    severity: advisory
    message: Bad regex
    scope: text
    pattern: '['
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("bad regex rejected");
    assert!(
        error.contains("config key `custom_rules[0].pattern` failed to compile regex"),
        "{error}"
    );

    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.threshold
    pillar: Documentation
    severity: advisory
    message: Threshold
    scope: text
    pattern: MARKER
rules:
  custom.threshold:
    threshold: 1
"#,
    );
    let error = load_config(dir.path(), &options).expect_err("bad setting rejected");
    assert!(
        error.contains("custom rule `custom.threshold` only supports `enabled`"),
        "{error}"
    );
}

#[test]
pub(crate) fn custom_rule_no_match_is_ok() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("src/lib.rs"), "fn clean() {}\n").expect("fixture write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.no-match
    pillar: Documentation
    severity: advisory
    message: No match
    scope: text
    pattern: ABSENT_MARKER
rules:
  select: ["custom.*"]
"#,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
pub(crate) fn custom_rule_findings_pass_selection_exclusion_baseline_and_diff() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        "fn selected() {}\nCUSTOM_MARKER\n",
    )
    .expect("selected write");
    fs::write(dir.path().join("src/excluded.rs"), "CUSTOM_MARKER\n").expect("excluded write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.marker
    pillar: Documentation
    severity: warning
    message: Custom marker
    scope: text
    pattern: CUSTOM_MARKER
rules:
  select: ["custom.marker"]
exclude:
  - rule: custom.marker
    paths: ["src/excluded.rs"]
    reason: generated custom marker
"#,
    );

    let selected = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("selection and exclusion analysis succeeds");
    assert_eq!(selected.findings.len(), 1);
    assert_eq!(selected.findings[0].rule_id, "custom.marker");
    assert_eq!(selected.findings[0].file_path, "src/lib.rs");
    assert_missing_rule(&selected, "docs.missing-public-doc");
    assert_eq!(total_suppressed_findings(&selected.suppressions), 1);

    let baseline_path = dir.path().join("baseline.json");
    write_baseline(&baseline_path, std::slice::from_ref(&selected.findings[0]))
        .expect("baseline write");
    let baseline_filtered = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("baseline analysis succeeds");
    assert!(baseline_filtered.findings.is_empty());
    assert_eq!(
        baseline_filtered
            .baseline
            .as_ref()
            .map(|baseline| baseline.suppressed),
        Some(1)
    );

    fs::write(
        dir.path().join("src/lib.rs"),
        "CUSTOM_MARKER\nfn gap() {}\nCUSTOM_MARKER\n",
    )
    .expect("diff fixture rewrite");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.marker
    pillar: Documentation
    severity: warning
    message: Custom marker
    scope: text
    pattern: CUSTOM_MARKER
rules:
  select: ["custom.marker"]
"#,
    );
    fs::write(
        dir.path().join("custom.patch"),
        concat!(
            "diff --git a/src/lib.rs b/src/lib.rs\n",
            "--- a/src/lib.rs\n",
            "+++ b/src/lib.rs\n",
            "@@ -3,1 +3,1 @@\n",
            "+CUSTOM_MARKER\n"
        ),
    )
    .expect("patch write");
    let diff_filtered = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            diff: Some(DiffSelection::Patch {
                path: PathBuf::from("custom.patch"),
                scope: ChangedScope::Symbol,
            }),
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("diff analysis succeeds");
    assert_eq!(diff_filtered.findings.len(), 1);
    assert_eq!(diff_filtered.findings[0].line, Some(3));
    assert!(diff_filtered
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.diagnostic_type == "patch-filter"));
}

#[test]
pub(crate) fn custom_rule_list_rules_includes_configured_rules_and_selectors() {
    let dir = tempdir().expect("tempdir");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.second
    pillar: Documentation
    severity: advisory
    message: Second custom rule
    scope: text
    pattern: SECOND
  - id: custom.first
    pillar: Security
    severity: warning
    message: First custom rule
    scope: text
    pattern: FIRST
"#,
    );

    let json_output = render_rule_list(
        dir.path(),
        &ListRulesArgs {
            rule_id: None,
            format: RuleListFormat::Json,
            selector: None,
            config: None,
            no_config: false,
        },
    )
    .expect("rule list json");
    let rules: Vec<Value> = serde_json::from_str(&json_output).expect("rule list json");
    let ids: Vec<&str> = rules
        .iter()
        .map(|rule| rule["id"].as_str().expect("id"))
        .collect();
    let first_custom = ids
        .iter()
        .position(|id| id.starts_with("custom."))
        .expect("custom rule listed");
    assert!(ids[..first_custom]
        .iter()
        .all(|id| !id.starts_with("custom.")));
    assert_eq!(&ids[first_custom..], ["custom.first", "custom.second"]);
    assert!(rules.iter().any(|rule| {
        rule["id"] == "custom.first"
            && rule["kind"] == "custom"
            && rule["customScope"] == "text"
            && rule["pattern"] == "FIRST"
    }));

    let selector_output = render_rule_list(
        dir.path(),
        &ListRulesArgs {
            rule_id: None,
            format: RuleListFormat::Json,
            selector: Some("custom.*".to_string()),
            config: None,
            no_config: false,
        },
    )
    .expect("custom selector");
    let selected: Vec<String> = serde_json::from_str(&selector_output).expect("selector json");
    assert_eq!(selected, vec!["custom.first", "custom.second"]);
}

#[test]
pub(crate) fn fingerprint_stable_for_custom_rule() {
    let finding = Finding::new(FindingDescriptor {
        rule_id: "custom.no-hack".to_string(),
        message: "HACK marker".to_string(),
        file_path: "src/lib.rs".to_string(),
        line: Some(2),
        severity: Severity::Warning,
        pillar: Pillar::Documentation,
        confidence: Confidence::Medium,
        symbol: Some("byte:12".to_string()),
        remediation: None,
        metadata: json!({ "scope": "comments" }),
    });

    assert_eq!(finding.fingerprint, "223b4b2c56b0f0e1");
}
