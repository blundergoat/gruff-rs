use super::*;

#[test]
pub(crate) fn sensitive_data_rules_skip_common_placeholder_and_detector_contexts() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn runtime_secret_values(secret_access_key: String, output: Vec<u8>) {
    let secret_access_key = secret_access_key.trim().to_string();
    let secret_json = String::from_utf8_lossy(&output);
    println!("{secret_access_key} {secret_json}");
}
"#,
    );
    fs::create_dir_all(dir.path().join(".github/workflows")).expect("workflow dir");
    fs::create_dir_all(dir.path().join("scripts")).expect("scripts dir");
    fs::create_dir_all(dir.path().join("src-tauri")).expect("src-tauri dir");
    fs::write(
        dir.path().join(".env.example"),
        r#"GITHUB_PAT=your_github_pat_here
AWS_DEV_SECRET_ACCESS_KEY=your_dev_secret_access_key_here
NPM_AUTH_TOKEN=your_npm_auth_token_here
"#,
    )
    .expect("env example write");
    fs::write(
        dir.path().join(".github/workflows/release.yml"),
        r#"env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"#,
    )
    .expect("workflow write");
    fs::write(
        dir.path().join("package-lock.json"),
        r#"{"packages":{"node_modules/demo":{"dependencies":{"js-tokens":"^4.0.0"}}}}"#,
    )
    .expect("package lock write");
    fs::write(
        dir.path().join("src-tauri/Cargo.toml"),
        r#"[dependencies]
aws-sdk-secretsmanager = "1"
"#,
    )
    .expect("tauri manifest write");
    fs::write(
        dir.path().join("scripts/oss-gate-check.sh"),
        r#"SECRET_PATTERNS=(
  '-----BEGIN PRIVATE KEY-----'
  '-----BEGIN RSA PRIVATE KEY-----'
  '-----BEGIN EC PRIVATE KEY-----'
)
"#,
    )
    .expect("detector script write");

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
    for rule in [
        "sensitive-data.hardcoded-env-value",
        "sensitive-data.private-key",
    ] {
        let findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == rule)
            .collect();
        assert!(
            findings.is_empty(),
            "{rule} must skip placeholders, runtime values, dependency names, and detector patterns; findings={findings:?}"
        );
    }
}

#[test]
pub(crate) fn dead_code_unused_private_function_recognises_indirect_references() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"use serde::Deserialize;

fn check_ai_tool(value: &i32) -> bool {
    *value > 0
}

fn default_branch() -> String {
    "main".to_string()
}

#[derive(Deserialize)]
pub struct ForgeConfig {
    #[serde(default = "default_branch")]
    pub branch: String,
}

impl std::fmt::Debug for ForgeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ForgeConfig").finish()
    }
}

pub fn entry(values: &[i32]) -> Vec<bool> {
    values.iter().map(check_ai_tool).collect()
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
    for symbol in ["check_ai_tool", "default_branch", "fmt"] {
        assert!(
            !report.findings.iter().any(|finding| {
                finding.rule_id == "dead-code.unused-private-function"
                    && finding.symbol.as_deref() == Some(symbol)
            }),
            "dead-code.unused-private-function must recognise indirect reference `{symbol}`; findings={:?}",
            report
                .findings
                .iter()
                .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
pub(crate) fn file_length_skips_dependency_lockfiles() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    let mut cargo_lock = String::from("# This is intentionally large lockfile metadata.\n");
    let mut package_lock = String::from("{\n");
    for index in 0..620 {
        cargo_lock.push_str(&format!("# package row {index}\n"));
        package_lock.push_str(&format!("  \"package-{index}\": \"1.0.0\",\n"));
    }
    package_lock.push_str("  \"tail\": \"1.0.0\"\n}\n");
    fs::write(dir.path().join("Cargo.lock"), cargo_lock).expect("cargo lock write");
    fs::write(dir.path().join("package-lock.json"), package_lock).expect("package lock write");

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
    let lockfile_size_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| {
            finding.rule_id == "size.file-length"
                && matches!(
                    finding.file_path.as_str(),
                    "Cargo.lock" | "package-lock.json"
                )
        })
        .collect();
    assert!(
        lockfile_size_findings.is_empty(),
        "dependency lockfiles must not produce file-length findings; findings={lockfile_size_findings:?}"
    );
}

#[test]
/// Short-lived loop and closure bindings stay idiomatic; a named local remains in scope.
pub(crate) fn short_variable_skips_short_lived_bindings() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn poll_once(cx: &mut std::task::Context<'_>) {
    let _ = cx.waker();
}

/// An unrelated two-letter parameter still needs a clearer name.
pub fn retain_plain_parameter(cx: usize) -> usize {
    cx
}

/// Normalize input strings.
pub fn entry(values: &[String]) -> Vec<String> {
    for aa in values {
        println!("{aa}");
    }
    let zz = values.len();
    values
        .iter()
        .map(|bb| bb.trim())
        .filter_map(|v| v.parse::<u32>().map_err(|e| e.to_string()).ok())
        .map(|n| n.to_string())
        .take(zz)
        .collect()
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
    let short_names: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "naming.short-variable")
        .filter_map(|finding| finding.symbol.as_deref())
        .collect();
    assert_eq!(
        short_names,
        vec!["cx", "zz"],
        "only the unrelated parameter and longer-lived local should report; names={short_names:?}"
    );
}

#[test]
/// Placeholder detection remains active when short-variable checks exempt a narrow binding.
pub(crate) fn placeholder_identifier_checks_loop_and_closure_bindings() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Normalize input strings.
pub fn entry(values: &[String]) -> Vec<String> {
    for foo in values {
        println!("{foo}");
    }
    values.iter().map(|bar| bar.trim().to_string()).collect()
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
    let placeholder_names: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "naming.placeholder-identifier")
        .filter_map(|finding| finding.symbol.as_deref())
        .collect();

    assert_eq!(
        placeholder_names,
        vec!["foo", "bar"],
        "short-lived placeholders must remain visible; names={placeholder_names:?}"
    );
    assert_missing_rule(&report, "naming.short-variable");
}

#[test]
/// The configured abbreviation list directly controls short-variable findings.
pub(crate) fn short_variable_uses_configured_abbreviations() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Combine two counters.
pub fn combine(ok: usize, id: usize) -> usize {
    ok + id
}
"#,
    );
    write_config(dir.path(), "allowlists:\n  acceptedAbbreviations: [ok]\n");
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let short_names: Vec<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "naming.short-variable")
        .filter_map(|finding| finding.symbol.as_deref())
        .collect();

    assert_eq!(
        short_names,
        vec!["id"],
        "configured `ok` should be accepted while replaced built-in `id` reports; names={short_names:?}"
    );
}

#[test]
pub(crate) fn performance_loop_rules_ignore_loop_words_in_comments() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Load favorites for a workspace.
pub fn load_favorites(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("Failed to read favorites: {}", e))
}

/// Resize while preserving the terminal state.
pub fn ai_resize_chat(session_id: String) -> Result<(), String> {
    Err(format!("No active chat session '{}'", session_id))
}

/// Cancel for reset mode only.
pub fn forge_cancel(current_distro: Option<String>) -> Option<String> {
    let distro = current_distro.clone();
    distro
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
    for rule in ["performance.format-in-loop", "performance.clone-in-loop"] {
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule),
            "{rule} must ignore loop keywords that appear only in comments; findings={:?}",
            report
                .findings
                .iter()
                .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
pub(crate) fn format_in_loop_skips_static_probe_and_report_message_construction() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"const AI_TOOL_SPECS: &[&str] = &["claude", "codex"];

/// Build a bounded probe script from known tool specs.
pub fn build_wsl_batch_probe_script() -> String {
    let mut lines = vec!["set -e".to_string()];
    for spec in AI_TOOL_SPECS {
        lines.push(format!("check_tool {}", spec));
    }
    lines.join("\n")
}

/// Build user-facing security group findings.
pub fn scan_security_groups(rules: &[(i32, i32)]) -> Vec<String> {
    let mut findings = Vec::new();
    for (from_port, to_port) in rules {
        let port_desc = if from_port == to_port {
            from_port.to_string()
        } else {
            format!("{from_port}-{to_port}")
        };
        let port_label = match *from_port {
            22 => format!("{port_desc} (SSH)"),
            3389 => format!("{port_desc} (RDP)"),
            _ => port_desc,
        };
        findings.push(
            format!("Port {port_label} open to 0.0.0.0/0"),
        );
    }
    findings
}

/// Build dynamic per-item output.
pub fn dynamic_format_loop(values: &[String]) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        output.push(format!("{}", value));
    }
    output
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

    for symbol in ["build_wsl_batch_probe_script", "scan_security_groups"] {
        assert!(
            !report.findings.iter().any(|finding| {
                finding.rule_id == "performance.format-in-loop"
                    && finding.symbol.as_deref() == Some(symbol)
            }),
            "bounded static probes and report message construction must stay silent for `{symbol}`; findings={:?}",
            report
                .findings
                .iter()
                .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
                .collect::<Vec<_>>()
        );
    }
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "performance.format-in-loop"
                && finding.symbol.as_deref() == Some("dynamic_format_loop")
        }),
        "dynamic same-line push(format!(...)) loops must still be reported; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
            .collect::<Vec<_>>()
    );
}

#[test]
pub(crate) fn external_public_module_declaration_uses_module_file_docs() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"//! Root docs.

pub mod commands;
"#,
    );
    fs::write(
        dir.path().join("src/commands.rs"),
        r#"//! Command module docs.

/// Entry command.
pub fn entry() {}
"#,
    )
    .expect("commands module write");
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
        !report.findings.iter().any(|finding| {
            finding.rule_id == "docs.missing-public-doc"
                && finding.symbol.as_deref() == Some("commands")
        }),
        "external module declarations should not require duplicate outer docs; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
            .collect::<Vec<_>>()
    );
}

#[test]
pub(crate) fn unnecessary_clone_candidate_skips_standalone_call_argument() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"use std::collections::HashMap;

/// Start a chat session.
pub fn start_chat(session_id: String) -> String {
    let mut sessions = HashMap::new();
    sessions.insert(
        session_id.clone(),
        1,
    );
    session_id
}
"#,
    );
    enable_builtin_rule(dir.path(), "waste.unnecessary-clone-candidate");
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "waste.unnecessary-clone-candidate"),
        "standalone clone arguments in multi-line calls require ownership context; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
            .collect::<Vec<_>>()
    );
}

#[test]
/// The opt-in unwrap rule preserves its narrow assertion-subject exemption.
pub(crate) fn opt_in_unwrap_rule_skips_assertion_subject_but_reports_setup_unwrap() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Normalize a shell profile id.
pub fn normalize_shell_profile_id(value: Option<String>) -> Result<Option<String>, String> {
    Ok(value.map(|id| if id == "windows" { "powershell".to_string() } else { id }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_subject_unwrap() {
        assert_eq!(
            normalize_shell_profile_id(Some("windows".to_string())).unwrap(),
            Some("powershell".to_string())
        );
    }

    #[test]
    fn setup_unwrap_still_reports() {
        let value = normalize_shell_profile_id(Some("windows".to_string())).unwrap();
        assert_eq!(value, Some("powershell".to_string()));
    }
}
"#,
    );
    write_config(
        dir.path(),
        "rules:\n  test-quality.unwrap-in-test:\n    enabled: true\n",
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert!(
        !report.findings.iter().any(|finding| {
            finding.rule_id == "test-quality.unwrap-in-test"
                && finding.symbol.as_deref() == Some("assertion_subject_unwrap")
        }),
        "unwrap used as the asserted subject should stay silent; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
            .collect::<Vec<_>>()
    );
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "test-quality.unwrap-in-test"
                && finding.symbol.as_deref() == Some("setup_unwrap_still_reports")
        }),
        "the explicitly enabled rule must still report setup unwraps; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
            .collect::<Vec<_>>()
    );
}

/// `should-panic-without-expected` skips a test item whose own attributes exclude test builds, since it is
/// never compiled as a test, while a bare `#[should_panic]` beside it still fires.
#[test]
pub(crate) fn should_panic_skips_items_excluded_from_test_builds() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn entry() {}
#[cfg(test)]
mod tests {
    #[test]
    #[should_panic]
    fn bare() { panic!("boom"); }

    #[cfg(not(test))]
    #[test]
    #[should_panic]
    fn excluded() { panic!("boom"); }

    #[cfg(all(unix, not(test)))]
    #[test]
    #[should_panic]
    fn excluded_by_all() { panic!("boom"); }

    #[cfg(any(not(test), feature = "x"))]
    #[test]
    #[should_panic]
    fn any_branch() { panic!("boom"); }

    #[test]
    #[should_panic]
    fn nested_item() {
        #[cfg(not(test))]
        fn helper() {}
        panic!("boom");
    }

    #[test]
    #[should_panic]
    fn body_string() {
        let _attribute = "#[cfg(not(test))]";
        panic!("boom");
    }

    #[test]
    #[should_panic = ""]
    fn empty_message() { panic!("boom"); }
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
    .expect("should-panic analysis succeeds");
    let mut flagged: Vec<String> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "test-quality.should-panic-without-expected")
        .filter_map(|finding| finding.symbol.clone())
        .map(|symbol| symbol.rsplit("::").next().unwrap_or(&symbol).to_string())
        .collect();
    flagged.sort();
    assert_eq!(
        flagged,
        vec![
            "any_branch",
            "bare",
            "body_string",
            "empty_message",
            "nested_item"
        ]
    );
}

/// `commented-out-code` keeps reporting a disabled fn, one finding per line, and stays silent on a fenced
/// example, placeholder pseudocode and the specimens of a clippy UI test file. The specimen line is
/// byte-identical to the true positive; only its file's `//~` annotation differs. Disabled code still reports
/// beside `// ~/` prose or a `//~~~~` banner, with rest patterns, a spaced range or an ellipsis inside a string,
/// and between a prose lead-in line and a trailing prose line (one ending in `)` included), after a non-ASCII
/// identifier before a spaced range, with prose between
/// two snippets, a closing line that carries its own comment, a `...` in a nested comment, and a `//~ ERROR`
/// mentioned in ordinary prose.
#[test]
pub(crate) fn commented_out_code_skips_fences_placeholders_and_ui_specimens() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        "/// Probe.\npub fn entry() {}\n\n// fn old_code() {}\n\n// fn older() {\n//     entry();\n// }\n",
    );
    fs::write(
        dir.path().join("src/fenced.rs"),
        "/// Probe.\npub fn fenced() {}\n\n// Usage:\n// ```\n// let value = compute();\n// ```\n",
    )
    .expect("fenced write");
    fs::write(
        dir.path().join("src/prose.rs"),
        "/// Probe.\npub fn prose() {}\n\n// if .. { insert } else { .. }\n",
    )
    .expect("prose write");
    fs::write(
        dir.path().join("src/specimen.rs"),
        "//~v empty_line_after_doc_comments\n/// Probe.\npub fn specimen() {}\n\n// fn old_code() {}\n",
    )
    .expect("specimen write");
    for (name, body) in [
        (
            "tilde",
            "// ~/.cargo/config.toml overrides the values below.\n\n// let disabled = old_call();\n",
        ),
        (
            "rest",
            "// let Point { x, .. } = point;\n\n// let (first, ..) = pair;\n",
        ),
        ("ellipsis", "// let message = \"loading...\";\n"),
        ("unicode", "// let x = café .. y;\n"),
        (
            "fenceonly",
            "// ```\n// let total = compute(1, 2);\n// ```\n",
        ),
        (
            "banner",
            "//~~~~~~~~~~~~\n\n// let total = compute_total(1, 2);\n",
        ),
        (
            "range",
            "// for i in 0 .. count { total += i; }\n\n// let window = &buffer[start .. end];\n",
        ),
        (
            "paren",
            "// match state {\n//     0 => go(),\n//     _ => stop(),\n// }\n// Disabled for now (see issue 42)\n",
        ),
        ("closing", "// if ready {\n//     go();\n// } // end if\n"),
        (
            "nested",
            "// match state {\n//     0 => go(), // and so on...\n//     _ => stop(),\n// }\n",
        ),
        (
            "mention",
            "// annotations look like //~^ ERROR on the next line\n\n// let x = compute(state);\n",
        ),
        (
            "between",
            "// let a = compute(state);\n// then the match:\n// match state {\n//     0 => go(),\n// }\n",
        ),
        (
            "trailing",
            "// match state {\n//     State::Idle => start(),\n//     State::Busy => wait(),\n// }\n// Restore it after the state machine lands\n",
        ),
        (
            "leadin",
            "// The old version was:\n// fn old_version(x: u32) -> u32 {\n//     x + 1\n// }\n",
        ),
    ] {
        fs::write(
            dir.path().join(format!("src/{name}.rs")),
            format!("/// Probe.\npub fn {name}() {{}}\n\n{body}"),
        )
        .expect("probe write");
    }
    // Comment text is untrusted: nesting this deep would overflow the parser's stack if it were parsed.
    let deep = format!(
        "/// Probe.\npub fn deep() {{}}\n\n// let x = {}1{};\n// let y = {}1;\n",
        "(".repeat(3000),
        ")".repeat(3000),
        "return ".repeat(3000)
    );
    fs::write(dir.path().join("src/deep.rs"), deep).expect("deep write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("commented-out-code analysis succeeds");
    let mut flagged: Vec<(&str, Option<usize>)> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "docs.commented-out-code")
        .map(|finding| (finding.file_path.as_str(), finding.line))
        .collect();
    flagged.sort();
    assert_eq!(
        flagged,
        vec![
            ("src/banner.rs", Some(6)),
            ("src/between.rs", Some(4)),
            ("src/between.rs", Some(6)),
            ("src/closing.rs", Some(4)),
            ("src/ellipsis.rs", Some(4)),
            ("src/leadin.rs", Some(5)),
            ("src/lib.rs", Some(4)),
            ("src/lib.rs", Some(6)),
            ("src/mention.rs", Some(6)),
            ("src/nested.rs", Some(4)),
            ("src/paren.rs", Some(4)),
            ("src/range.rs", Some(4)),
            ("src/range.rs", Some(6)),
            ("src/rest.rs", Some(4)),
            ("src/rest.rs", Some(6)),
            ("src/tilde.rs", Some(6)),
            ("src/trailing.rs", Some(4)),
            ("src/unicode.rs", Some(4)),
        ]
    );
}
