//! Exercise group cardinality and retained syntax through the configured project analyser.

use super::*;

const RULE: &str = "test-quality.duplicate-test-body";

/// Build real source functions rather than testing the detector's internal shape representation.
fn test_source(bodies: &[&str]) -> String {
    let mut source = String::from("mod probe {\n");
    for (index, body) in bodies.iter().enumerate() {
        source.push_str(&format!("#[test]\nfn case_{index}() {{ {body} }}\n"));
    }
    source.push_str("}\n");
    source
}

/// The same scan proves defaults, grouping, literal kinds and meaningful negative boundaries.
#[test]
fn duplicate_groups_preserve_executable_differences() {
    let _guard = analysis_lock();
    let variants = [
        "assert_eq!(parse(1), 2);",
        "assert_eq!(parse(3), 4);",
        "assert_eq!(parse(5), 6);",
    ];
    let cases = [
        ("default off", variants.to_vec(), false, false, 0),
        ("three", variants.to_vec(), true, false, 1),
        (
            "four",
            vec![
                variants[0],
                variants[1],
                variants[2],
                "assert_eq!(parse(7), 8);",
            ],
            true,
            false,
            1,
        ),
        ("pair off", variants[..2].to_vec(), true, false, 0),
        ("pair on", variants[..2].to_vec(), true, true, 1),
        ("three with pairs", variants.to_vec(), true, true, 1),
        (
            "callee",
            vec![variants[0], variants[1], "assert_eq!(decode(5), 6);"],
            true,
            false,
            0,
        ),
        (
            "assertion",
            vec![variants[0], variants[1], "assert_ne!(parse(5), 6);"],
            true,
            false,
            0,
        ),
        (
            "binding",
            vec![
                "let value = parse(1); check(value);",
                "let value = parse(2); check(value);",
                "let actual = parse(3); check(actual);",
            ],
            true,
            false,
            0,
        ),
        (
            "operator",
            vec!["check(1 + 2);", "check(3 + 4);", "check(5 - 6);"],
            true,
            false,
            0,
        ),
        (
            "order",
            vec![
                "setup(1); check(2);",
                "setup(3); check(4);",
                "check(5); setup(6);",
            ],
            true,
            false,
            0,
        ),
        (
            "delimiter",
            vec!["check!(1);", "check!(2);", "check![3];"],
            true,
            false,
            0,
        ),
        (
            "kind",
            vec!["check(1);", "check(2);", "check(\"3\");"],
            true,
            false,
            0,
        ),
        (
            "byte and char",
            vec!["check('a');", "check('b');", "check(b'c');"],
            true,
            false,
            0,
        ),
        (
            "numeric suffix",
            vec!["check(1u8);", "check(2u8);", "check(3u16);"],
            true,
            false,
            0,
        ),
        (
            "comments",
            vec![
                "/* first */ check(1);",
                "// second\n check(2);",
                "check(3); // third\n",
            ],
            true,
            false,
            1,
        ),
        (
            "rustdoc",
            vec![
                "/// First\n let value = 1; check(value);",
                "/// Second\n let value = 2; check(value);",
                "let value = 3; check(value);",
            ],
            true,
            false,
            1,
        ),
        (
            "booleans",
            vec!["check(true);", "check(false);", "check(true);"],
            true,
            false,
            1,
        ),
        (
            "table loop",
            vec![
                "for value in [1, 2] { check(value); }",
                "for value in [3, 4] { check(value); }",
                "for value in [5, 6] { check(value); }",
            ],
            true,
            false,
            0,
        ),
    ];
    for (label, bodies, enabled, pairs, expected) in cases {
        let project = tempdir().expect("project");
        baseline_with_lib(project.path(), &test_source(&bodies));
        fs::write(
            project.path().join(".gruff-rs.yaml"),
            format!(
            "schemaVersion: gruff-rs.config.v1\nrules:\n  {RULE}:\n    enabled: {enabled}\n    options:\n      includePairs: {pairs}\n"
        ),
        )
        .expect("configuration");
        let report = run_project_analysis(
            project.path(),
            AnalysisOptions {
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect(label);
        let groups: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == RULE)
            .collect();
        assert_eq!(groups.len(), expected, "{label}: {groups:?}");
        if let Some(group) = groups.first() {
            assert_eq!(group.line, Some(3), "{label}");
            assert_eq!(group.symbol.as_deref(), Some("case_0"));
            assert_eq!(group.confidence, Confidence::Medium);
            let members = group.metadata["members"].as_array().expect("members");
            assert_eq!(members.len(), bodies.len());
            for (index, member) in members.iter().enumerate() {
                assert_eq!(member["name"], format!("probe::case_{index}"));
                assert_eq!(member["file"], "src/lib.rs");
                assert!(group.message.contains(&format!("probe::case_{index}")));
            }
            assert!(group.message.contains("table-driven case loop"));
            assert!(group.message.contains("descriptive label"));
        }
    }
}

/// Compare across modules in one file, while production helpers, case attributes and other files stay out.
#[test]
fn duplicate_groups_use_file_boundaries_and_test_members() {
    let _guard = analysis_lock();
    let project = tempdir().expect("project");
    baseline_with_lib(
        project.path(),
        concat!(
            "mod first { #[test] fn one() { check(1); } }\n",
            "mod second { #[test] fn two() { check(2); } }\n",
            "mod third { #[test] fn three() { check(3); } }\n",
            "fn production() { check(4); }\n",
            "#[test] #[case(5)] fn parameterized() { check(5); }\n",
            "mod other;\n"
        ),
    );
    fs::write(
        project.path().join("src/other.rs"),
        "#[test] fn separate() { check(6); }\n",
    )
    .expect("other source file");
    enable_builtin_rule(project.path(), RULE);
    let report = run_project_analysis(
        project.path(),
        AnalysisOptions {
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis");
    let groups: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == RULE)
        .collect();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].symbol.as_deref(), Some("one"));
    let members = groups[0].metadata["members"].as_array().expect("members");
    let names: Vec<_> = members
        .iter()
        .map(|member| member["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["first::one", "second::two", "third::three"]);
}

/// The field report's f18 yields the three positive assertions; negated assertions stay a separate pair.
#[test]
fn field_report_sorting_group_disappears_when_folded() {
    let _guard = analysis_lock();
    let cases = [
        (
            r#"
#[test] fn sorts_after_basic_greater() { assert!(sorts_after("b", "a")); }
#[test] fn sorts_after_basic_less() { assert!(!sorts_after("a", "b")); }
#[test] fn sorts_after_equal() { assert!(!sorts_after("a", "a")); }
#[test] fn sorts_after_longer() { assert!(sorts_after("ab", "a")); }
#[test] fn sorts_after_numeric_suffix() { assert!(sorts_after("b2", "b1")); }
"#,
            1,
        ),
        (
            r#"
#[test] fn sorting_cases() {
    for (label, left, right, expected) in [
        ("greater", "b", "a", true), ("less", "a", "b", false),
        ("equal", "a", "a", false), ("longer", "ab", "a", true),
        ("numeric suffix", "b2", "b1", true),
    ] { assert_eq!(sorts_after(left, right), expected, "{label}"); }
}
"#,
            0,
        ),
    ];
    for (source, expected) in cases {
        let project = tempdir().expect("project");
        baseline_with_lib(project.path(), source);
        enable_builtin_rule(project.path(), RULE);
        let report = run_project_analysis(
            project.path(),
            AnalysisOptions {
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis");
        let groups: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == RULE)
            .collect();
        assert_eq!(groups.len(), expected);
        if let Some(group) = groups.first() {
            assert_eq!(group.metadata["groupSize"], 3);
            assert_eq!(group.symbol.as_deref(), Some("sorts_after_basic_greater"));
        }
    }
}
