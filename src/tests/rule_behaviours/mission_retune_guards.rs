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

/// A local literal argument array, and a lone working directory on a bare program name, run fixed commands;
/// caller-chosen, rebound, out-of-scope or extra arguments and a relative program path still report.
#[test]
pub(crate) fn process_command_skips_literal_argument_arrays_and_bare_program_working_directory() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"use std::path::Path;
use std::process::Command;

/// Read the current revision with fixed arguments.
pub fn revision() -> bool {
    let args = &["rev-parse", "--short=10", "HEAD"];
    let output = Command::new("git").args(args).output();
    output.is_ok()
}

/// Check spelling from the workspace root.
pub fn spelling(root: &Path) {
    let mut command = Command::new("typos");
    command.current_dir(root);
    let _ = command.status();
}

/// Forward caller-chosen arguments.
pub fn forward(extra: &[String]) {
    let args = extra;
    let _ = Command::new("git").args(args).status();
}

/// Rebind the literal array before use.
pub fn rebound(extra: &[&str]) {
    let args = &["status"];
    let args = extra;
    let _ = Command::new("git").args(args).status();
}

/// Run a fixed program on a caller-chosen file in a chosen directory.
pub fn in_directory(root: &Path, file: &str) {
    let _ = Command::new("rustfmt").arg(file).current_dir(root).status();
}

/// Rebind the literal array through `if let` before one command.
pub fn sync(custom: Option<Vec<String>>) {
    let args = ["pull", "--ff-only"];
    if let Some(args) = custom {
        let _ = Command::new("git").args(args).status();
    }
}

/// Use the caller's arguments after an inner literal binding's block has closed.
pub fn scoped(extra: &[String], quick: bool) {
    let args = extra;
    if quick {
        let args = &["status"];
        let _ = args;
    }
    let _ = Command::new("git").args(args).status();
}

/// Rebind on the same line as the literal array.
pub fn same_line(extra: &[&str]) {
    let args = ["status"]; let args = extra;
    let _ = Command::new("git").args(args).status();
}

/// Run a relative program in a chosen directory.
pub fn configure(checkout: &Path) {
    let _ = Command::new("./configure").current_dir(checkout).status();
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
    let lines: Vec<Option<usize>> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.process-command")
        .map(|finding| finding.line)
        .collect();
    assert_eq!(
        lines,
        vec![Some(21), Some(28), Some(33), Some(40), Some(51), Some(57), Some(62)],
        "the forwarded, rebound, out-of-scope, file-argument and relative-program commands should report"
    );
}

/// Unwraps whose outcome the source fixes stay quiet: a Cargo-set variable read in a build script, and a constructor
/// given one literal. A variable Cargo does not set, a library read of `OUT_DIR`, a constructor given
/// a variable, and any other unwrap on the same line keep reporting.
#[test]
pub(crate) fn unwrap_expect_skips_cargo_build_variables_and_literal_constructors() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"use std::ffi::CString;
use std::net::IpAddr;
use std::str::FromStr;

/// Build fixed values and one from input.
pub fn values(input: &str) -> usize {
    let empty = CString::new("").unwrap();
    let address = IpAddr::from_str("198.51.100.1").expect("fixed address");
    let parsed = IpAddr::from_str(input).unwrap();
    let out = std::env::var("OUT_DIR").unwrap();
    let both = CString::new("x").unwrap().into_string().unwrap();
    empty.as_bytes().len() + usize::from(address.is_ipv4()) + usize::from(parsed.is_ipv4()) + out.len() + both.len()
}
"#,
    );
    std::fs::write(
        dir.path().join("build.rs"),
        "fn main() {\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n    let arch = std::env::var_os(\"CARGO_CFG_TARGET_ARCH\").unwrap();\n    let flag = std::env::var(\"MY_FEATURE_FLAG\").unwrap();\n    println!(\"{out} {arch:?} {flag}\");\n}\n",
    )
    .expect("write build script");

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
    let mut lines: Vec<(&str, usize)> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "waste.unwrap-expect")
        .map(|finding| (finding.file_path.as_str(), finding.line.unwrap_or(0)))
        .collect();
    lines.sort_unstable();
    assert_eq!(
        lines,
        [
            ("build.rs", 4),
            ("src/lib.rs", 9),
            ("src/lib.rs", 10),
            ("src/lib.rs", 11)
        ],
        "the flag Cargo does not set, the input address, the library OUT_DIR and the second unwrap report"
    );
}

/// FAMILY-CONTRACT.md section 13c: an `allow` or `expect` attribute naming a lint that makes a rule's claim suppresses
/// that rule's finding on the item, or on the members of an attributed impl, and counts it in one inline row; a lint
/// group the table does not name, and an unattributed sibling, keep reporting.
#[test]
pub(crate) fn allow_and_expect_attributes_suppress_only_the_lints_they_name() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Allowed long function.
#[allow(clippy::too_many_lines)]
pub fn allowed() -> usize {
    let first = 1;
    let second = 2;
    first + second
}

/// Expected long function, with a reason.
#[expect(clippy::too_many_lines, reason = "the fixture keeps its steps linear")]
pub fn expected() -> usize {
    let first = 1;
    let second = 2;
    first + second
}

/// A clippy group section 13c does not name.
#[allow(clippy::pedantic)]
pub fn grouped() -> usize {
    let first = 1;
    let second = 2;
    first + second
}

/// The unattributed sibling.
pub fn reported() -> usize {
    let first = 1;
    let second = 2;
    first + second
}

/// Holds a method covered by its impl's attribute.
pub struct Holder;

#[allow(clippy::too_many_lines)]
impl Holder {
    /// Covered by the impl's attribute.
    pub fn method() -> usize {
        let first = 1;
        let second = 2;
        first + second
    }
}
"#,
    );
    write_config(
        dir.path(),
        "rules:\n  size.function-length:\n    threshold: 3\n    severity: warning\n",
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

    let reported: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "size.function-length")
        .filter_map(|finding| finding.symbol.as_deref())
        .collect();
    assert_eq!(
        reported,
        ["grouped", "reported"],
        "only the unnamed group and the sibling report"
    );
    let inline: Vec<(&str, &str, usize)> = report
        .suppressions
        .iter()
        .filter(|row| row.source == Some("inline"))
        .map(|row| (row.rule.as_str(), row.paths[0].as_str(), row.suppressed))
        .collect();
    assert_eq!(inline, [("size.function-length", "src/lib.rs", 3)]);
    assert!(report
        .suppressions
        .iter()
        .filter(|row| row.source == Some("inline"))
        .all(|row| row.reason == crate::inline_suppressions::INLINE_SUPPRESSION_REASON));

    let sarif: serde_json::Value =
        serde_json::from_str(&crate::render::render_report(&report, OutputFormat::Sarif))
            .expect("sarif json");
    let kinds: Vec<&str> = sarif["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|result| result["suppressions"][0]["kind"].as_str())
        .collect();
    assert_eq!(
        kinds,
        ["inSource", "inSource", "inSource"],
        "each suppressed finding stays a SARIF result"
    );
}

/// A file's own `#![allow(dead_code)]` suppresses both dead-code rules' findings there and counts each in an inline
/// row, so allowed dead code is never hidden silently.
#[test]
pub(crate) fn file_level_allow_dead_code_is_counted_not_silent() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        "//! Fixture crate.\n\nmod helpers;\n\n/// Entry point.\npub fn run() {}\n",
    );
    std::fs::write(
        dir.path().join("src/helpers.rs"),
        "#![allow(dead_code)]\n//! Helpers kept for later.\n\nfn unused_helper() {}\n\nstruct UnusedHolder;\n",
    )
    .expect("write helpers");

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
            .any(|finding| finding.rule_id.starts_with("dead-code.")),
        "allowed dead code must not report: {:?}",
        report.findings
    );
    let inline: Vec<(&str, usize)> = report
        .suppressions
        .iter()
        .filter(|row| row.source == Some("inline") && row.paths[0] == "src/helpers.rs")
        .map(|row| (row.rule.as_str(), row.suppressed))
        .collect();
    // The item-candidate rule covers the function too, so it counts both items.
    assert_eq!(
        inline,
        [
            ("dead-code.unused-private-function", 1),
            ("dead-code.unused-private-item-candidate", 2)
        ]
    );
}
