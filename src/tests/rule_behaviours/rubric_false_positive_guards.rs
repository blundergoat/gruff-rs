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
pub(crate) fn public_field_skips_serde_transport_structs() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"use serde::{Deserialize, Serialize};

/// API response DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse {
    pub id: String,
    pub status: String,
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
    let public_field_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "modernisation.public-field")
        .collect();
    assert!(
        public_field_findings.is_empty(),
        "serde DTO public fields must stay silent; findings={public_field_findings:?}"
    );
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
pub(crate) fn short_variable_skips_single_letter_bindings() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"/// Probe.
pub fn entry(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|s| s.trim())
        .filter_map(|v| v.parse::<u32>().map_err(|e| e.to_string()).ok())
        .map(|n| n.to_string())
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
    let short_names: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "naming.short-variable")
        .collect();
    assert!(
        short_names.is_empty(),
        "single-letter closure/error bindings must stay silent; findings={short_names:?}"
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
            .any(|finding| finding.rule_id == "waste.unnecessary-clone-candidate"),
        "standalone clone arguments in multi-line calls require ownership context; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
            .collect::<Vec<_>>()
    );
}
