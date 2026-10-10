//! Comment-boundary regressions keep prose from masquerading as executable Rust.
//! These behavior tests exercise complete temporary projects so users receive
//! findings only from code and from the exact rustdoc attached to an item.

use super::*;

#[path = "rustdoc_function_guards.rs"]
mod rustdoc_function_guards;

/// A scan accepts an assigned removal condition and still reports markers that a developer cannot act on.
#[test]
pub(crate) fn stale_todo_requires_a_complete_owner_and_removal_condition() {
    let _guard = analysis_lock();
    let project = tempdir().expect("tempdir");
    baseline_with_lib(
        project.path(),
        r##"//FIXME(chenyukang), remove this after type ascription is removed from AST
//FIXME(chenyukang)
//FIXME(chenyukang), remove this after
//FIXME(??), remove this after type ascription is removed from AST
//FIXME(chenyukang), revisit later
//FIXME
pub fn entry() {}
"##,
    );

    let report = run_project_analysis(
        project.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let reported_lines: Vec<Option<usize>> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "docs.stale-todo")
        .map(|finding| finding.line)
        .collect();
    assert_eq!(
        reported_lines,
        [Some(2), Some(3), Some(4), Some(5), Some(6)]
    );
}

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

/// A Rust file with `production` statements in one function (`production + 2` code lines) and, when `test_calls` is
/// set, an inline `#[cfg(test)]` module whose test makes that many calls (`test_calls + 5` code lines).
fn production_and_test_module(production: usize, test_calls: Option<usize>) -> String {
    let mut source = String::from("/// Probe.\npub fn entry() {\n");
    for index in 0..production {
        source.push_str(&format!("    let _ = {index};\n"));
    }
    source.push_str("}\n");
    if let Some(calls) = test_calls {
        source.push_str(
            "\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn runs() {\n",
        );
        for _ in 0..calls {
            source.push_str("        entry();\n");
        }
        source.push_str("    }\n}\n");
    }
    source
}

/// The `size.file-length` findings of one analysed source, as (line, severity, measured, test-module lines).
fn file_length_rows(source: &str) -> Vec<(Option<usize>, Severity, Value, Value)> {
    let dir = tempdir().expect("tempdir");
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
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "size.file-length")
        .map(|finding| {
            (
                finding.line,
                finding.severity,
                finding.metadata["measured"].clone(),
                finding.metadata["testModuleLines"].clone(),
            )
        })
        .collect()
}

/// FAMILY-CONTRACT section 12 (search `A Rust inline test module counts apart`): only production code lines meet the
/// limit, the test module's lines ride in the metadata, and a test module over the limit reports on its own line.
#[test]
pub(crate) fn file_length_counts_the_inline_test_module_apart() {
    let _guard = analysis_lock();
    assert_eq!(
        file_length_rows(&production_and_test_module(900, Some(400))),
        vec![],
        "902 production lines stay under the limit whatever the test module adds"
    );
    assert_eq!(
        file_length_rows(&production_and_test_module(1000, Some(400))),
        vec![(Some(1), Severity::Advisory, json!(1002), json!(405))],
        "1002 production lines report at line 1, as a lower-band notice, with the test module's 405 lines in the metadata"
    );
    assert_eq!(
        file_length_rows(&production_and_test_module(1600, Some(400))),
        vec![(Some(1), Severity::Error, json!(1602), json!(405))],
        "1602 production lines are past one and a half times the limit, so they report at the rule's severity"
    );
    assert_eq!(
        file_length_rows(&production_and_test_module(10, Some(996))),
        vec![(Some(16), Severity::Advisory, json!(1001), Value::Null)],
        "a 1001-line test module reports as advisory on its own `mod` line"
    );
}

/// Attribute lines are not code lines, so they never push a file over the limit; code lines still do.
#[test]
pub(crate) fn file_length_leaves_attribute_lines_out() {
    let _guard = analysis_lock();
    let with_attributes = |statements: usize| {
        let mut source = String::from("/// Probe.\n");
        for _ in 0..60 {
            source.push_str("#[allow(unused_variables)]\n");
        }
        source.push_str(&production_and_test_module(statements, None)["/// Probe.\n".len()..]);
        source
    };
    assert_eq!(
        file_length_rows(&with_attributes(990)),
        vec![],
        "992 code lines and 60 attribute lines stay under the limit"
    );
    assert_eq!(
        file_length_rows(&with_attributes(999)),
        vec![(Some(1), Severity::Advisory, json!(1001), Value::Null)],
        "1001 code lines report, as a lower-band notice, whatever attributes sit above them"
    );
}

/// The bounded deep-scan path counts code lines like the full path (FAMILY-CONTRACT section 12, search `What stays
/// physical`): comment padding that pushes a file past the line budget does not count toward the limit.
#[test]
pub(crate) fn file_length_bounded_path_counts_code_lines() {
    let _guard = analysis_lock();
    let bounded_rows = |statements: usize| {
        let dir = tempdir().expect("tempdir");
        let mut source = production_and_test_module(statements, None);
        for index in 0..1500 {
            source.push_str(&format!("// documentation filler {index}\n"));
        }
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
        let report = run_analysis_in_project(dir.path(), &options, &config)
            .expect("bounded Rust analysis succeeds");
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.diagnostic_type == "bounded-deep-scan"),
            "the probe must take the bounded path"
        );
        report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "size.file-length")
            .map(|finding| finding.metadata["measured"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        bounded_rows(990),
        Vec::<Value>::new(),
        "992 code lines and 1500 comment lines stay under the limit"
    );
    assert_eq!(
        bounded_rows(999),
        vec![json!(1001)],
        "1001 code lines report on the bounded path"
    );
}
