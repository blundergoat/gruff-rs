//! Exercise FAMILY-CONTRACT.md section 16 group membership through the configured project analyser.

use super::*;

const RULE: &str = "test-quality.duplicate-test-body";
/// The plain test declaration most controls use; attribute controls pass their own.
const PLAIN: &str = "#[test]\nfn";

/// Build real source functions inside one module; each member is a declaration prefix and a body.
fn test_source(members: &[(&str, &str)]) -> String {
    let mut source = String::from("mod probe {\n");
    for (index, (prefix, body)) in members.iter().enumerate() {
        source.push_str(&format!("{prefix} case_{index}() {{ {body} }}\n"));
    }
    source.push_str("}\n");
    source
}

/// Scan one project and return only this rule's group findings.
fn group_findings(root: &Path, enabled: bool) -> Vec<Finding> {
    if enabled {
        enable_builtin_rule(root, RULE);
    }
    let report = run_project_analysis(
        root,
        AnalysisOptions {
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis");
    report
        .findings
        .into_iter()
        .filter(|finding| finding.rule_id == RULE)
        .collect()
}

/// Scan members declared with a plain `#[test]` and check the one group they form, if any.
fn assert_plain_groups(label: &str, bodies: &[&str], enabled: bool, expected: usize) {
    let members: Vec<_> = bodies.iter().map(|body| (PLAIN, *body)).collect();
    let project = tempdir().expect("project");
    baseline_with_lib(project.path(), &test_source(&members));
    let groups = group_findings(project.path(), enabled);
    assert_eq!(groups.len(), expected, "{label}: {groups:?}");
    if let Some(group) = groups.first() {
        assert_eq!(group.line, Some(3), "{label}");
        assert_eq!(group.symbol.as_deref(), Some("case_0"));
        assert_eq!(group.confidence, Confidence::Medium);
        assert_eq!(group.metadata["groupSize"], bodies.len());
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

/// Copies that change only eligible literals form one group; every other difference keeps tests apart.
#[test]
fn duplicate_groups_preserve_executable_differences() {
    let _guard = analysis_lock();
    let variants = [
        "let value = parse(1); assert_eq!(value, 2);",
        "let value = parse(3); assert_eq!(value, 4);",
        "let value = parse(5); assert_eq!(value, 6);",
    ];
    let cases: &[(&str, &[&str], bool, usize)] = &[
        ("default off", &variants, false, 0),
        ("three", &variants, true, 1),
        (
            "four",
            &[
                variants[0],
                variants[1],
                variants[2],
                "let value = parse(7); assert_eq!(value, 8);",
            ],
            true,
            1,
        ),
        ("pair", &variants[..2], true, 0),
        (
            "callee",
            &[
                variants[0],
                variants[1],
                "let value = decode(5); assert_eq!(value, 6);",
            ],
            true,
            0,
        ),
        (
            "assertion",
            &[
                variants[0],
                variants[1],
                "let value = parse(5); assert_ne!(value, 6);",
            ],
            true,
            0,
        ),
        (
            "binding",
            &[
                variants[0],
                variants[1],
                "let actual = parse(5); assert_eq!(actual, 6);",
            ],
            true,
            0,
        ),
        (
            "operator",
            &[
                "let value = 1 + 2; check(value);",
                "let value = 3 + 4; check(value);",
                "let value = 5 - 6; check(value);",
            ],
            true,
            0,
        ),
        (
            "order",
            &[
                "setup(1); check(2);",
                "setup(3); check(4);",
                "check(5); setup(6);",
            ],
            true,
            0,
        ),
        (
            "delimiter",
            &[
                "setup(); check!(1);",
                "setup(); check!(2);",
                "setup(); check![3];",
            ],
            true,
            0,
        ),
        (
            "kind",
            &[
                "setup(); check(1);",
                "setup(); check(2);",
                "setup(); check(\"3\");",
            ],
            true,
            0,
        ),
        (
            "byte and char",
            &[
                "setup(); check('a');",
                "setup(); check('b');",
                "setup(); check(b'c');",
            ],
            true,
            0,
        ),
        (
            "numeric suffix",
            &[
                "setup(); check(1u8);",
                "setup(); check(2u8);",
                "setup(); check(3u16);",
            ],
            true,
            0,
        ),
        (
            "comments",
            &[
                "/* first */ setup(); check(1);",
                "// second\n setup(); check(2);",
                "setup(); check(3); // third\n",
            ],
            true,
            1,
        ),
        (
            "rustdoc",
            &[
                "/// First\n let value = 1; check(value);",
                "/// Second\n let value = 2; check(value);",
                "let value = 3; check(value);",
            ],
            true,
            1,
        ),
        (
            "booleans",
            &[
                "setup(); check(true);",
                "setup(); check(false);",
                "setup(); check(true);",
            ],
            true,
            1,
        ),
        (
            "table loop",
            &[
                "setup(); for value in [1, 2] { check(value); }",
                "setup(); for value in [3, 4] { check(value); }",
                "setup(); for value in [5, 6] { check(value); }",
            ],
            true,
            0,
        ),
        (
            "one statement",
            &[
                "assert_eq!(parse(1), 2);",
                "assert_eq!(parse(3), 4);",
                "assert_eq!(parse(5), 6);",
            ],
            true,
            0,
        ),
        ("empty", &["", "", ""], true, 0),
        (
            "text without whitespace",
            &[
                "let value = parse(\"alpha\"); check(value);",
                "let value = parse(\"beta\"); check(value);",
                "let value = parse(\"gamma\"); check(value);",
            ],
            true,
            1,
        ),
        (
            "text with whitespace",
            &[
                "let value = parse(\"a b\"); check(value);",
                "let value = parse(\"a c\"); check(value);",
                "let value = parse(\"a d\"); check(value);",
            ],
            true,
            0,
        ),
        (
            "decoded whitespace",
            &[
                "let value = parse(\"a\\tb\", 1); check(value);",
                "let value = parse(r\"a\tb\", 2); check(value);",
                "let value = parse(\"a\\u{9}b\", 3); check(value);",
            ],
            true,
            1,
        ),
        (
            "format text",
            &[
                "let value = format!(\"{} a\", 1); check(value);",
                "let value = format!(\"{} b\", 2); check(value);",
                "let value = format!(\"{} c\", 3); check(value);",
            ],
            true,
            0,
        ),
        (
            "index",
            &[
                "let value = parse(1); check(value[0]);",
                "let value = parse(2); check(value[1]);",
                "let value = parse(3); check(value[2]);",
            ],
            true,
            0,
        ),
        (
            "index in macro",
            &[
                "let value = parse(1); assert_eq!(value[0], 1);",
                "let value = parse(2); assert_eq!(value[1], 2);",
                "let value = parse(3); assert_eq!(value[2], 3);",
            ],
            true,
            0,
        ),
        (
            "slice",
            &[
                "let value = parse(1); check(&value[1..]);",
                "let value = parse(2); check(&value[2..]);",
                "let value = parse(3); check(&value[3..]);",
            ],
            true,
            0,
        ),
        (
            "array literal",
            &[
                "let value = [1, 2]; check(value);",
                "let value = [3, 4]; check(value);",
                "let value = [5, 6]; check(value);",
            ],
            true,
            1,
        ),
        (
            "object key",
            &[
                "let value = json!({\"a\": 1}); check(value);",
                "let value = json!({\"b\": 1}); check(value);",
                "let value = json!({\"c\": 1}); check(value);",
            ],
            true,
            0,
        ),
        (
            "map key",
            &[
                "let value = hashmap! {\"a\" => 1}; check(value);",
                "let value = hashmap! {\"b\" => 1}; check(value);",
                "let value = hashmap! {\"c\" => 1}; check(value);",
            ],
            true,
            0,
        ),
        (
            "tuple field",
            &[
                "let value = parse(1); check(value.0);",
                "let value = parse(1); check(value.1);",
                "let value = parse(1); check(value.2);",
            ],
            true,
            0,
        ),
        (
            "range",
            &[
                "let value = (0..1).len(); check(value);",
                "let value = (0..2).len(); check(value);",
                "let value = (0..3).len(); check(value);",
            ],
            true,
            1,
        ),
        (
            "nested item attribute literal",
            &[
                "#[derive(Debug)] #[repr(align(4))] struct Opt; let value = parse(1); check(value);",
                "#[derive(Debug)] #[repr(align(8))] struct Opt; let value = parse(2); check(value);",
                "#[derive(Debug)] #[repr(align(16))] struct Opt; let value = parse(3); check(value);",
            ],
            true,
            0,
        ),
        (
            "nested item rustdoc",
            &[
                "/// one\n struct Opt; let value = parse(1); check(value);",
                "/// two\n struct Opt; let value = parse(2); check(value);",
                "/// three\n struct Opt; let value = parse(3); check(value);",
            ],
            true,
            0,
        ),
        (
            "nested fn literal",
            &[
                "fn helper() -> u8 { 1 } let value = helper(); check(value);",
                "fn helper() -> u8 { 2 } let value = helper(); check(value);",
                "fn helper() -> u8 { 3 } let value = helper(); check(value);",
            ],
            true,
            0,
        ),
        (
            "nested const value",
            &[
                "const DATA: u8 = 1; let value = parse(DATA); check(value);",
                "const DATA: u8 = 2; let value = parse(DATA); check(value);",
                "const DATA: u8 = 3; let value = parse(DATA); check(value);",
            ],
            true,
            1,
        ),
        (
            "identical nested item",
            &[
                "struct Opt; let value = parse(1); check(value);",
                "struct Opt; let value = parse(2); check(value);",
                "struct Opt; let value = parse(3); check(value);",
            ],
            true,
            1,
        ),
        (
            "statement attribute literal",
            &[
                "#[cfg(feature = \"a\")] let value = parse(1); check(value);",
                "#[cfg(feature = \"b\")] let value = parse(2); check(value);",
                "#[cfg(feature = \"c\")] let value = parse(3); check(value);",
            ],
            true,
            0,
        ),
        (
            "identical statement attribute",
            &[
                "#[allow(unused_variables)] let value = parse(1); check(value);",
                "#[allow(unused_variables)] let value = parse(2); check(value);",
                "#[allow(unused_variables)] let value = parse(3); check(value);",
            ],
            true,
            1,
        ),
    ];
    for (label, bodies, enabled, expected) in cases {
        assert_plain_groups(label, bodies, *enabled, *expected);
    }
}

/// Members must share every attribute and the signature apart from the name; rustdoc does not count.
#[test]
fn duplicate_groups_require_identical_attributes() {
    let _guard = analysis_lock();
    let body = "let value = parse(1); check(value);";
    let cases: &[(&str, [&str; 3], usize)] = &[
        (
            "same attributes",
            ["#[test]\n#[should_panic(expected = \"boom\")]\nfn"; 3],
            1,
        ),
        (
            "rustdoc differs",
            ["/// First.\n#[test]\nfn", "/// Second.\n#[test]\nfn", PLAIN],
            1,
        ),
        (
            "panic message",
            [
                "#[test]\n#[should_panic(expected = \"first\")]\nfn",
                "#[test]\n#[should_panic(expected = \"second\")]\nfn",
                "#[test]\n#[should_panic(expected = \"third\")]\nfn",
            ],
            0,
        ),
        ("ignore", [PLAIN, PLAIN, "#[test]\n#[ignore]\nfn"], 0),
        (
            "feature gate",
            [
                "#[test]\n#[cfg(feature = \"a\")]\nfn",
                "#[test]\n#[cfg(feature = \"b\")]\nfn",
                "#[test]\n#[cfg(feature = \"c\")]\nfn",
            ],
            0,
        ),
        (
            "order",
            [
                "#[test]\n#[ignore]\nfn",
                "#[test]\n#[ignore]\nfn",
                "#[ignore]\n#[test]\nfn",
            ],
            0,
        ),
        (
            "runtime flavor",
            [
                "#[tokio::test(flavor = \"multi_thread\")]\nasync fn",
                "#[tokio::test(flavor = \"multi_thread\")]\nasync fn",
                "#[tokio::test(flavor = \"current_thread\")]\nasync fn",
            ],
            0,
        ),
        (
            "signature",
            [
                "#[tokio::test]\nasync fn",
                "#[tokio::test]\nasync fn",
                "#[tokio::test]\nfn",
            ],
            0,
        ),
    ];
    for (label, prefixes, expected) in cases {
        let members: Vec<_> = prefixes.iter().map(|prefix| (*prefix, body)).collect();
        let project = tempdir().expect("project");
        baseline_with_lib(project.path(), &test_source(&members));
        let groups = group_findings(project.path(), true);
        assert_eq!(groups.len(), *expected, "{label}: {groups:?}");
    }
}

/// The whole signature after the name is compared: a return type on one member keeps it out,
/// while three members sharing that return type still group.
#[test]
fn duplicate_groups_compare_the_return_type() {
    let _guard = analysis_lock();
    let project = tempdir().expect("project");
    baseline_with_lib(
        project.path(),
        concat!(
            "mod same {\n",
            "    #[test] fn one() -> () { setup(); check(1); }\n",
            "    #[test] fn two() -> () { setup(); check(2); }\n",
            "    #[test] fn three() -> () { setup(); check(3); }\n",
            "}\n",
            "mod different {\n",
            "    #[test] fn four() { setup(); check(4); }\n",
            "    #[test] fn five() { setup(); check(5); }\n",
            "    #[test] fn six() -> () { setup(); check(6); }\n",
            "}\n"
        ),
    );
    let groups = group_findings(project.path(), true);
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].symbol.as_deref(), Some("one"));
}

/// Only tests in one module declaration group, while production helpers, case attributes and other files stay out.
#[test]
fn duplicate_groups_stay_within_one_module() {
    let _guard = analysis_lock();
    let project = tempdir().expect("project");
    baseline_with_lib(
        project.path(),
        concat!(
            "mod first {\n",
            "    #[test] fn one() { setup(); check(1); }\n",
            "    #[test] fn two() { setup(); check(2); }\n",
            "    #[test] fn three() { setup(); check(3); }\n",
            "}\n",
            "mod second { #[test] fn four() { setup(); check(4); } }\n",
            "mod third { #[test] fn five() { setup(); check(5); } }\n",
            "mod outer_a { mod shared {\n",
            "    #[test] fn six() { setup(); check(6); }\n",
            "    #[test] fn seven() { setup(); check(7); }\n",
            "} }\n",
            "mod outer_b { mod shared { #[test] fn eight() { setup(); check(8); } } }\n",
            "fn production() { setup(); check(9); }\n",
            "#[test] #[case(10)] fn parameterized() { setup(); check(10); }\n",
            "mod other;\n"
        ),
    );
    fs::write(
        project.path().join("src/other.rs"),
        "#[test] fn separate() { setup(); check(11); }\n",
    )
    .expect("other source file");
    let groups = group_findings(project.path(), true);
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].symbol.as_deref(), Some("one"));
    let members = groups[0].metadata["members"].as_array().expect("members");
    let names: Vec<_> = members
        .iter()
        .map(|member| member["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["first::one", "first::two", "first::three"]);
}

/// The field report's one-line f18 tests stay silent; with two statements each, the three positive
/// assertions form one group, the negated pair stays silent, and folding the cases removes the finding.
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
            0,
        ),
        (
            r#"
#[test] fn sorts_after_basic_greater() { let ordered = sorts_after("b", "a"); assert!(ordered); }
#[test] fn sorts_after_basic_less() { let ordered = sorts_after("a", "b"); assert!(!ordered); }
#[test] fn sorts_after_equal() { let ordered = sorts_after("a", "a"); assert!(!ordered); }
#[test] fn sorts_after_longer() { let ordered = sorts_after("ab", "a"); assert!(ordered); }
#[test] fn sorts_after_numeric_suffix() { let ordered = sorts_after("b2", "b1"); assert!(ordered); }
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
        let groups = group_findings(project.path(), true);
        assert_eq!(groups.len(), expected, "{groups:?}");
        if let Some(group) = groups.first() {
            assert_eq!(group.metadata["groupSize"], 3);
            assert_eq!(group.symbol.as_deref(), Some("sorts_after_basic_greater"));
        }
    }
}
