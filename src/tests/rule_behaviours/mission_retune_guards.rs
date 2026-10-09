use super::*;

#[test]
pub(crate) fn complexity_rules_ignore_comment_keywords_and_question_marks() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Validate a script path for command execution.
///
/// This prose says if, for, match, while, loop, and for again, but it is
/// reviewer-facing contract text rather than executable control flow.
pub fn validate_script_path(value: Option<&str>) -> Result<(), String> {
    let candidate = value.ok_or_else(|| "missing".to_string())?;
    if candidate.is_empty() {
        return Err("empty".to_string());
    }
    if candidate.contains("..") {
        return Err("parent traversal".to_string());
    }
    if candidate.starts_with('/') {
        return Err("absolute path".to_string());
    }
    Ok(())
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
    for rule_id in [
        "complexity.cyclomatic",
        "complexity.cognitive",
        "complexity.nesting-depth",
    ] {
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule_id),
            "{rule_id} must ignore comment keywords and linear error propagation; findings={:?}",
            report.findings
        );
    }
}

#[test]
pub(crate) fn long_test_ignores_setup_before_first_assertion() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let mut body = String::from(
        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn builds_large_fixture() {\n        let mut value = 0;\n",
    );
    for index in 0..130 {
        body.push_str(&format!("        value += {index};\n"));
    }
    body.push_str("        assert!(value > 0);\n    }\n}\n");
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
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "test-quality.long-test"),
        "long-test must ignore fixture setup before the first assertion; findings={:?}",
        report.findings
    );
}

/// Long-test counts code lines on both paths (FAMILY-CONTRACT section 12, search `Code lines in every line count`):
/// from the first assertion when the test asserts, across the whole test when it does not. Comment, doc-comment,
/// attribute and blank lines are free; a test long in code lines still reports.
#[test]
pub(crate) fn long_test_counts_code_lines_on_both_paths() {
    let _guard = analysis_lock();
    // `steps` statements give 2 + steps code lines on either path; padding sits between them.
    let test_module = |steps: usize| {
        let mut source = String::from(
            "/// Probe.\npub fn entry() -> u32 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn asserted() {\n        let mut value = entry();\n        assert!(value > 0);\n",
        );
        for index in 0..steps {
            source.push_str("        // Each step adds one.\n\n");
            source.push_str(&format!("        value += {index};\n"));
        }
        source.push_str("    }\n\n    /// Runs the chain without asserting.\n    #[test]\n    #[allow(unused_must_use)]\n    fn unasserted() {\n");
        for _ in 0..steps {
            source.push_str("        /// One more call.\n        #[allow(unused_must_use)]\n");
            source.push_str("        std::hint::black_box(entry());\n");
        }
        source.push_str("    }\n}\n");
        source
    };
    let long_tests = |steps: usize| {
        let dir = tempdir().expect("tempdir");
        baseline_with_lib(dir.path(), &test_module(steps));
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
        let mut rows: Vec<(String, Value)> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "test-quality.long-test")
            .map(|finding| {
                (
                    finding.symbol.clone().unwrap_or_default(),
                    finding.metadata["measured"].clone(),
                )
            })
            .collect();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        rows
    };
    assert_eq!(
        long_tests(118),
        vec![],
        "120 code lines on either path stay at the limit"
    );
    assert_eq!(
        long_tests(119),
        vec![
            ("asserted".to_string(), json!(121)),
            ("unasserted".to_string(), json!(121)),
        ],
        "121 code lines report on both paths"
    );
}

#[test]
pub(crate) fn tls_true_binding_flags_within_one_function() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Build a client.
pub fn make_client() {
    let insecure = true;
    let _ = reqwest::Client::builder().danger_accept_invalid_certs(insecure);
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
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "security.tls-verification-disabled"),
        "a `let x = true;` bypass inside the same function must still flag; findings={:?}",
        report.findings
    );
}

#[test]
pub(crate) fn tls_true_binding_does_not_leak_across_functions() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// A truthy flag used elsewhere.
pub fn defaults() {
    let insecure = true;
    let _ = insecure;
}

/// Build a client from a caller-supplied flag.
pub fn make_client(insecure: bool) {
    let _ = reqwest::Client::builder().danger_accept_invalid_certs(insecure);
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
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "security.tls-verification-disabled"),
        "a `true` binding in another function must not flag a same-named parameter; findings={:?}",
        report.findings
    );
}
