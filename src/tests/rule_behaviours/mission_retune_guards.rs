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
