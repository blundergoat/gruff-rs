//! Precision-floor M14: size and complexity findings report in two bands (FAMILY-CONTRACT section 12, search `Size
//! and complexity findings in two bands`), complexity is counted on the syntax tree, trait default methods and
//! closures assigned to `const` items are measured, and file length reads Rust source only.

use super::*;
use crate::built_in_rules::{
    limit_band, syntax_complexity, SyntaxComplexity, GROUP_PARAMETERS, LIMIT_BAND_KEY,
    LOWER_BAND_FILE, LOWER_BAND_FUNCTION, LOWER_BAND_PARAMETER, SIMPLIFY_PATH, SPLIT_FILE,
    SPLIT_FUNCTION,
};

/// Analyse one library source with default settings, plus complexity.cyclomatic, which is off by default, turned on, and
/// return its findings for one rule.
fn rule_findings(lib: &str, rule_id: &str) -> Vec<Finding> {
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), lib);
    write_config(
        dir.path(),
        "rules:\n  complexity.cyclomatic:\n    enabled: true\n",
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    report
        .findings
        .into_iter()
        .filter(|finding| finding.rule_id == rule_id)
        .collect()
}

/// A documented function with the given number of straight-line statements in its body.
fn function_of_lines(statements: usize) -> String {
    let mut source = String::from("/// Probe.\npub fn probe() {\n");
    for index in 0..statements {
        source.push_str(&format!("    let _value{index} = {index};\n"));
    }
    source.push_str("}\n");
    source
}

/// A documented function taking the given number of parameters.
fn function_with_parameters(count: usize) -> String {
    let params: Vec<String> = (0..count).map(|index| format!("p{index}: u8")).collect();
    format!("/// Probe.\npub fn probe({}) {{}}\n", params.join(", "))
}

/// A documented function of flat `if` statements that do work, so each adds one decision and one cognitive point.
fn function_with_branches(count: usize) -> String {
    let mut source =
        String::from("/// Probe.\npub fn probe(flag: u32) -> u32 {\n    let mut total = 0;\n");
    for index in 0..count {
        source.push_str(&format!(
            "    if flag == {index} {{\n        total += {index};\n    }}\n"
        ));
    }
    source.push_str("    total\n}\n");
    source
}

/// A documented function whose `if` statements nest the given number of levels.
fn function_nested_to(depth: usize) -> String {
    let mut source = String::from("/// Probe.\npub fn probe(flag: bool) -> u32 {\n");
    for _ in 0..depth {
        source.push_str("if flag {\n");
    }
    source.push_str("return 1;\n");
    for _ in 0..depth {
        source.push_str("}\n");
    }
    source.push_str("0\n}\n");
    source
}

/// A file of the given number of one-line functions under a module doc comment.
fn file_of_lines(count: usize) -> String {
    let mut source = String::from("//! Probe.\n");
    for index in 0..count {
        source.push_str(&format!("pub fn item_{index}() {{}}\n"));
    }
    source
}

/// Assert one finding's band, severity and advice.
fn assert_band(finding: &Finding, band: &str, severity: Severity, advice: &str) {
    assert_eq!(finding.metadata[LIMIT_BAND_KEY], json!(band), "{finding:?}");
    assert_eq!(finding.severity, severity, "{finding:?}");
    assert_eq!(finding.remediation.as_deref(), Some(advice), "{finding:?}");
}

#[test]
pub(crate) fn each_size_and_complexity_rule_reports_in_two_bands() {
    let _guard = analysis_lock();
    type Builder = fn(usize) -> String;
    let cases: [(&str, Builder, usize, usize, &str, &str); 6] = [
        (
            "size.function-length",
            function_of_lines,
            52,
            120,
            LOWER_BAND_FUNCTION,
            SPLIT_FUNCTION,
        ),
        (
            "size.parameter-count",
            function_with_parameters,
            8,
            14,
            LOWER_BAND_PARAMETER,
            GROUP_PARAMETERS,
        ),
        (
            "complexity.cyclomatic",
            function_with_branches,
            11,
            20,
            LOWER_BAND_FUNCTION,
            SIMPLIFY_PATH,
        ),
        (
            "complexity.cognitive",
            function_with_branches,
            16,
            30,
            LOWER_BAND_FUNCTION,
            SIMPLIFY_PATH,
        ),
        (
            "complexity.nesting-depth",
            function_nested_to,
            5,
            8,
            LOWER_BAND_FUNCTION,
            SIMPLIFY_PATH,
        ),
        (
            "size.file-length",
            file_of_lines,
            1100,
            2000,
            LOWER_BAND_FILE,
            SPLIT_FILE,
        ),
    ];
    for (rule_id, build, lower, upper, lower_advice, upper_advice) in cases {
        let near = rule_findings(&build(lower), rule_id);
        assert_eq!(near.len(), 1, "{rule_id} just over its limit: {near:?}");
        assert_band(&near[0], "lower", Severity::Advisory, lower_advice);
        let far = rule_findings(&build(upper), rule_id);
        assert_eq!(far.len(), 1, "{rule_id} at twice its limit: {far:?}");
        assert_band(
            &far[0],
            "upper",
            rules::builtin_severity(rule_id),
            upper_advice,
        );
    }
}

#[test]
pub(crate) fn band_boundary_compares_in_floating_point() {
    // Cognitive's limit of 15 puts the boundary at 22.5, and parameter count's 7 puts it at 10.5.
    assert_eq!(limit_band(22, 15.0), "lower");
    assert_eq!(limit_band(23, 15.0), "upper");
    assert_eq!(limit_band(10, 7.0), "lower");
    assert_eq!(limit_band(11, 7.0), "upper");
}

#[test]
pub(crate) fn complexity_is_counted_on_the_syntax_tree() {
    let measure =
        |body: &str| syntax_complexity(&syn::parse_str::<syn::Block>(body).expect("block parses"));
    assert_eq!(
        measure("{ let a = || 1; let b = || 2; a() + b() }"),
        SyntaxComplexity {
            cyclomatic: 1,
            nesting: 0,
            cognitive: 0
        },
        "a closure's bars are not a logical operator"
    );
    assert_eq!(
        measure("{ Outer { inner: Inner { value: Leaf { x: 1 } } } }"),
        SyntaxComplexity {
            cyclomatic: 1,
            nesting: 0,
            cognitive: 0
        },
        "struct literal braces are not nesting"
    );
    assert_eq!(
        measure("{ match kind { 0 => { a() } 1 => { b() } 2 => { c() } _ => { d() } } }"),
        SyntaxComplexity {
            cyclomatic: 2,
            nesting: 1,
            cognitive: 1
        },
        "a match is one decision, and its arm braces are not a further level"
    );
    assert_eq!(
        measure("{ let value = parse()?; if value > 0 && value < 9 { 1 } else if value == 0 { 0 } else { 2 } }"),
        SyntaxComplexity { cyclomatic: 4, nesting: 1, cognitive: 3 },
        "the question mark adds nothing; the if, its else if and the && each count once"
    );
}

#[test]
pub(crate) fn trait_default_methods_are_measured() {
    let _guard = analysis_lock();
    let mut lib = String::from("/// Probe.\npub trait Scorer {\n    /// Score.\n    fn score(&self, flag: u32) -> u32 {\n        let mut total = 0;\n");
    for index in 0..30 {
        lib.push_str(&format!(
            "        if flag == {index} {{\n            total += {index};\n        }}\n"
        ));
    }
    lib.push_str("        total\n    }\n}\n");
    let findings = rule_findings(&lib, "complexity.cyclomatic");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].symbol.as_deref(), Some("score"));
}

#[test]
pub(crate) fn inline_test_module_finding_names_its_module_and_carries_no_band() {
    let _guard = analysis_lock();
    let mut lib = String::from("//! Probe.\npub fn item() {}\n\n#[cfg(test)]\nmod tests {\n");
    for index in 0..2100 {
        lib.push_str(&format!("    fn case_{index}() {{}}\n"));
    }
    lib.push_str("}\n");
    let findings = rule_findings(&lib, "size.file-length");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].metadata["testModule"], json!("tests"));
    assert_eq!(findings[0].metadata.get(LIMIT_BAND_KEY), None);
    assert_eq!(findings[0].severity, Severity::Advisory);
}

#[test]
pub(crate) fn file_length_reads_rust_source_only() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), &file_of_lines(1100));
    let mut data = String::from("[\n");
    for index in 0..1600 {
        data.push_str(&format!("  {{\"key\": {index}}},\n"));
    }
    data.push_str("  {}\n]\n");
    fs::write(dir.path().join("data.json"), data).expect("data write");
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
    let files: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "size.file-length")
        .map(|finding| finding.file_path.as_str())
        .collect();
    assert_eq!(
        files,
        vec!["src/lib.rs"],
        "a long JSON file reports nothing; a long Rust file still does"
    );
}

#[test]
pub(crate) fn configured_severity_does_not_lift_a_lower_band_finding() {
    let _guard = analysis_lock();
    for (statements, band, severity) in [
        (52, "lower", Severity::Advisory),
        (120, "upper", Severity::Error),
    ] {
        let dir = tempdir().expect("tempdir");
        baseline_with_lib(dir.path(), &function_of_lines(statements));
        write_config(
            dir.path(),
            "rules:\n  size.function-length:\n    threshold: 50\n    severity: error\n",
        );
        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        let rows: Vec<(Value, Severity)> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "size.function-length")
            .map(|finding| (finding.metadata[LIMIT_BAND_KEY].clone(), finding.severity))
            .collect();
        assert_eq!(
            rows,
            vec![(json!(band), severity)],
            "{statements} statements"
        );
    }
}

#[test]
pub(crate) fn const_item_closures_are_measured_by_size_and_complexity_only() {
    let _guard = analysis_lock();
    let mut lib = String::from(
        "//! Probe.\n\n/// Adds the probe values.\n///\n/// # Returns\n///\n/// The total of the probe values.\npub const TOTAL: fn() -> u32 = || {\n    let mut total = 0;\n",
    );
    for index in 0..60 {
        lib.push_str(&format!("    total += {index};\n"));
    }
    lib.push_str("    total\n};\n");
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), &lib);
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
    let on_closure: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.symbol.as_deref() == Some("TOTAL"))
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert_eq!(on_closure, vec!["size.function-length"], "{on_closure:?}");
}

#[test]
pub(crate) fn cognitive_complexity_spares_guards_and_match_arms_like_gruff_go() {
    let measure =
        |body: &str| syntax_complexity(&syn::parse_str::<syn::Block>(body).expect("block parses"));
    assert_eq!(
        measure("{ for x in items { if x { continue; } } }").cognitive,
        2,
        "the loop adds one and the continue guard one, with no nesting penalty"
    );
    assert_eq!(
        measure("{ for x in items { if x { a(); b(); } } }").cognitive,
        3,
        "an if that does work is no guard, so it still pays the loop's level"
    );
    let arm = measure("{ match k { 0 => { if a { b(); } } _ => {} } }");
    assert_eq!(
        (arm.cognitive, arm.nesting),
        (2, 2),
        "an if inside an arm keeps the match's cognitive level, while the match still counts as nesting"
    );
}
