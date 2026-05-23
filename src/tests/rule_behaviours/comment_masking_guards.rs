use super::*;

#[test]
pub(crate) fn unreachable_code_ignores_terminator_mentions_in_comments() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn entry() -> i32 {
    let _value = 1; // explained that `return 1;` would short-circuit
    2
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

    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "waste.unreachable-code"),
        "waste.unreachable-code must not fire on terminators inside comments; findings={:?}",
        report
            .findings
            .iter()
            .map(|f| (&f.rule_id, f.line))
            .collect::<Vec<_>>()
    );
}

#[test]
pub(crate) fn dead_private_function_ignores_comment_and_string_mentions() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// docs that mention `unused_private` should not count as a use.
// unused_private is also named in this comment.
pub fn keepalive() {
    let _ = "unused_private is also a string literal here";
}

fn unused_private() {}
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

    assert!(
        report.findings.iter().any(|finding| {
            finding.symbol.as_deref() == Some("unused_private")
                && finding.rule_id == "dead-code.unused-private-function"
        }),
        "dead-code scan must ignore comment/string mentions; findings={:?}",
        report
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.symbol))
            .collect::<Vec<_>>()
    );
}
