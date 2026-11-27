//! End-to-end analyzer, parser, rule, and inline-suppression regression tests.
//!
//! Each test invokes the compiled `gruff-rs` binary against an isolated temporary project
//! so rule-boundary, UTF-8 span, budget, and parser guards stay enforced end to end.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;

/// Run the compiled `gruff-rs` binary from `cwd` with non-interactive output and `arguments`.
/// Returns the captured process exit status, stdout, and stderr.
fn run(cwd: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gruff-rs"))
        .current_dir(cwd)
        .arg("--no-interaction")
        .args(arguments)
        .output()
        .expect("run gruff-rs")
}

/// Decode JSON stdout from `output`, returning the parsed JSON value or panicking with stderr context.
fn json_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Write minimal `Cargo.toml` and `README.md` markers inside `root` so temporary projects anchor their project root cleanly.
fn write_project_markers(root: &Path) {
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\ndescription = \"d\"\nlicense = \"MIT\"\n",
    )
    .expect("manifest");
    fs::write(root.join("README.md"), "# demo\n").expect("readme");
}

/// Deeply nested `=` or `let` chains inside comments must not overflow the `syn` parser stack.
#[test]
fn deep_assignment_and_let_comments_do_not_overflow_parser() {
    let project = tempdir().expect("project");
    let root = project.path();
    write_project_markers(root);
    fs::create_dir(root.join("src")).expect("src");
    let assign_chain = "a=".repeat(2500);
    let let_chain = "let a = ".repeat(1200);
    fs::write(
        root.join("src/lib.rs"),
        format!("// {assign_chain}1;\n// {let_chain}1;\n/// Clean function.\npub fn ok() {{}}\n"),
    )
    .expect("source");

    let output = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--no-config",
            "--no-baseline",
            "--include-rule",
            "docs.commented-out-code",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let report = json_output(&output);
    assert_eq!(report["findings"].as_array().expect("findings").len(), 0);
}

/// Multi-byte UTF-8 before a PEM pattern const does not shift byte spans, and a long unquoted gap before a secret does not swallow its opening quote.
#[test]
fn multibyte_pem_pattern_const_skipped_and_long_gap_secret_reported() {
    let project = tempdir().expect("project");
    let root = project.path();
    write_project_markers(root);
    fs::create_dir(root.join("src")).expect("src");
    let header_marker = concat!("-----BEGIN RSA ", "PRIVATE KEY-----");
    let synthetic_secret = concat!("k9xP2mQ8vR4nL7wZ3jH", "6tB5cF1yD0aE8sG");
    let source = format!(
        "/* café résumé naïve */ const PRIVATE_KEY_PATTERN: &str = \"{header_marker}\";\n\
         pub fn token() -> &'static str {{\n\
             let _re = ::regex::Regex::new(self::PRIVATE_KEY_PATTERN);\n\
             let _gap = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";\n\
             //////////////////////////////////////// \"{synthetic_secret}\"\n\
             \"{synthetic_secret}\"\n\
         }}\n"
    );
    fs::write(root.join("src/lib.rs"), source).expect("source");

    let output = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--no-config",
            "--no-baseline",
            "--include-rule",
            "sensitive-data.private-key",
            "--include-rule",
            "sensitive-data.high-entropy-string",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let report = json_output(&output);
    let findings = report["findings"].as_array().expect("findings");
    assert!(
        !findings
            .iter()
            .any(|item| item["ruleId"] == "sensitive-data.private-key"),
        "PEM pattern const after multi-byte UTF-8 should be skipped: {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|item| item["ruleId"] == "sensitive-data.high-entropy-string"),
        "High-entropy literal after long gap should still report: {findings:?}"
    );
}

/// Verify zizmor comment boundary parsing and Rust inline-suppression `deepScanBudget` gating.
///
/// Ignores quoted YAML scalars and unclosed brackets, checks all `zizmor:` markers per comment, and skips parsing over-budget Rust files.
#[test]
fn zizmor_comment_boundaries_and_rust_deep_scan_budget() {
    let project = tempdir().expect("project");
    let root = project.path();
    write_project_markers(root);
    fs::create_dir_all(root.join(".github/workflows")).expect("workflows");
    fs::write(
        root.join(".github/workflows/ci.yml"),
        concat!(
            "name: ci\n",
            "on: [push]\n",
            "jobs:\n",
            "  build:\n",
            "    runs-on: ubuntu-latest\n",
            "    steps:\n",
            "      - name: \"# zizmor: ignore[unpinned-uses]\"\n",
            "        uses: vendor/unclosed@v1 # zizmor: ignore[unpinned-uses\n",
            "      - uses: vendor/second@v1 # zizmor: ignore[other] zizmor: ignore[unpinned-uses]\n",
        ),
    )
    .expect("workflow");

    let wf_output = run(
        root,
        &[
            "analyse",
            ".github/workflows/ci.yml",
            "--no-config",
            "--no-baseline",
            "--include-rule",
            "security.github-actions-unpinned-action",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(wf_output.status.code(), Some(0));
    let wf_report = json_output(&wf_output);
    assert_eq!(wf_report["findings"].as_array().expect("findings").len(), 1);
    assert_eq!(
        wf_report["suppressions"].as_array().expect("suppressions")[0]["suppressed"],
        1
    );

    fs::create_dir(root.join("src")).expect("src");
    fs::write(
        root.join("src/over_budget.rs"),
        "#[allow(dead_code)]\nfn a() {}\nfn b() {}\nfn c() {}\nfn d() {}\nfn e() {}\nfn f() {}\n",
    )
    .expect("rust file");
    let budget_output = run(
        root,
        &[
            "analyse",
            "src/over_budget.rs",
            "--no-config",
            "--no-baseline",
            "--deep-scan-budget",
            "3:100",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(budget_output.status.code(), Some(0));
    let budget_report = json_output(&budget_output);
    assert_eq!(budget_report["summary"]["parsedFiles"], 0);
    assert!(budget_report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .any(|diag| diag["type"] == "bounded-deep-scan"));
}

/// Verify `#[cfg(test)]` `pub const` closures, `Fn(...) -> Result<A, B>` params, and oversized test identifiers.
///
/// Confirms test-module const closures stay silent, arrow parameter types parse cleanly, and 300-char test bindings never panic.
#[test]
fn test_const_closures_fn_arrow_params_and_oversized_test_identifiers() {
    let project = tempdir().expect("project");
    let root = project.path();
    write_project_markers(root);
    fs::create_dir(root.join("src")).expect("src");
    let huge_ident = "x".repeat(300);
    fs::write(
        root.join("src/lib.rs"),
        format!(
            "/// Apply `callback` to `input`.\n\
             /// Returns the computed number or an error message.\n\
             pub fn apply(callback: impl Fn(u32) -> Result<u32, String>, input: u32) -> Result<u32, String> {{\n\
                 callback(input)\n\
             }}\n\
             #[cfg(test)]\n\
             mod tests {{\n\
                 pub const HELPER: fn() = || {{}};\n\
                 #[test]\n\
                 fn huge_binding() {{\n\
                     let {huge_ident} = 1;\n\
                     assert_eq!({huge_ident}, 2);\n\
                 }}\n\
             }}\n"
        ),
    )
    .expect("source");

    let output = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--no-config",
            "--no-baseline",
            "--include-rule",
            "docs.missing-public-doc",
            "--include-rule",
            "docs.missing-param-doc",
            "--include-rule",
            "test-quality.trivial-assertion",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let findings = json_output(&output)["findings"]
        .as_array()
        .expect("findings")
        .clone();
    assert!(
        findings.is_empty(),
        "expected no findings, got: {findings:?}"
    );
}

/// Verify rule and parser boundary guards across unwraps, Axum handlers, `Command::new`, and Rust comments.
///
/// Covers raw-string unwraps, `\u{0_0}` and `\u{0_}` NUL escapes, doc-commented handlers, and multi-line attributes above `#[should_panic]`.
/// Also covers UTF-8 char literals, empty `/**/` block comments, and multi-line or spoofed `Command::new` bindings.
#[test]
fn rule_and_parser_boundary_guards_for_unwraps_axum_commands_and_comments() {
    let project = tempdir().expect("project");
    let root = project.path();
    write_project_markers(root);
    fs::create_dir(root.join("src")).expect("src");
    fs::write(
        root.join("src/lib.rs"),
        concat!(
            "use axum::response::Html;\n",
            "use std::ffi::CString;\n",
            "use std::process::Command;\n",
            "/// Enum doc.\n",
            "#[derive(Debug)]\n",
            "enum Kind { Ready }\n",
            "/// Handler doc.\n",
            "async fn show(kind: Kind) -> Html<String> { Html(format!(\"{kind:?}\")) }\n",
            "/// Raw regex and UTF-8 char.\n",
            "pub fn helpers(input: Option<i32>) -> char {\n",
            "    let _re = Regex::new(r\"[a-z]+\").unwrap();\n",
            "    let _nul = CString::new(\"a\\u{0_0}b\").unwrap();\n",
            "    let _bad = input.expect(\"ok\"); // trailing comment must not satisfy rationale length\n",
            "    let _nul_tail = CString::new(\"a\\u{0_}b\").unwrap();\n",
            "    let args = &[\"status\"];\n",
            "    let _ = Command::new(\"git\")\n",
            "        .args(args)\n",
            "        .status();\n",
            "    'é'\n",
            "}\n",
            "/**/ pub fn undocumented_after_empty_block_comment() {}\n",
            "/// Spoofed raw string binding.\n",
            "pub fn spoof(args: &[&str]) {\n",
            "    let _s = r#\"\nlet args = &[\"status\"];\n\"#;\n",
            "    let _ = Command::new(\"git\").args(args).status();\n",
            "}\n",
            "#[cfg(test)]\n",
            "mod t {\n",
            "    #[test]\n",
            "    #[cfg(\n",
            "        test\n",
            "    )]\n",
            "    #[should_panic]\n",
            "    fn unpinned() {}\n",
            "}\n",
        ),
    )
    .expect("source");

    let output = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--no-config",
            "--no-baseline",
            "--include-rule",
            "waste.unwrap-expect",
            "--include-rule",
            "security.template-injection-xss",
            "--include-rule",
            "security.process-command",
            "--include-rule",
            "docs.missing-public-doc",
            "--include-rule",
            "test-quality.should-panic-without-expected",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let findings = json_output(&output)["findings"]
        .as_array()
        .expect("findings")
        .clone();

    let unwrap_lines: Vec<u64> = findings
        .iter()
        .filter(|f| f["ruleId"] == "waste.unwrap-expect")
        .filter_map(|f| f["line"].as_u64())
        .collect();
    assert_eq!(
        unwrap_lines,
        vec![12, 13, 14],
        "raw regex quiet; NUL (with or without a trailing underscore) + trailing-comment expect flagged: {findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|f| f["ruleId"] == "security.template-injection-xss"),
        "doc-commented Axum unit-enum handler stays quiet: {findings:?}"
    );
    let cmd_lines: Vec<u64> = findings
        .iter()
        .filter(|f| f["ruleId"] == "security.process-command")
        .filter_map(|f| f["line"].as_u64())
        .collect();
    assert_eq!(
        cmd_lines,
        vec![27],
        "multi-line literal args quiet; raw-string spoof flagged: {findings:?}"
    );
    assert!(
        findings.iter().any(|f| {
            f["ruleId"] == "docs.missing-public-doc"
                && f["symbol"] == "undocumented_after_empty_block_comment"
        }),
        "empty /**/ block comment is not rustdoc: {findings:?}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f["ruleId"] == "test-quality.should-panic-without-expected"),
        "multi-line attr above #[should_panic] still flags: {findings:?}"
    );
}
