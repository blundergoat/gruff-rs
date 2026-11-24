//! Exercise release-sensitive behavior through the built `gruff-rs` binary.
//!
//! Temporary projects reproduce ordinary shell workflows such as scanning from `src` or migrating a config.
//! Check process status, report output, and files that must remain safe even when the command fails.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;

/// Run the built binary from `cwd` with `arguments`.
/// Returns the exit status and captured stdout and stderr.
fn run(cwd: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gruff-rs"))
        .current_dir(cwd)
        .arg("--no-interaction")
        .args(arguments)
        .output()
        .expect("run gruff-rs")
}

/// Returns the JSON report from `output`, or panics with stderr if JSON decoding fails.
fn json_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Starting `analyse` inside `src` must not report unrelated findings from the parent project.
#[test]
fn no_arguments_keep_the_launch_directory_as_scan_scope() {
    let project = tempdir().expect("project");
    let root = project.path();
    let nested = root.join("src");
    fs::create_dir(&nested).expect("source directory");
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .expect("manifest");
    fs::write(root.join("outside.rs"), "pub fn outside() {}\n").expect("sibling");
    fs::write(nested.join("inside.rs"), "pub fn inside() {}\n").expect("source");

    let output = run(
        &nested,
        &[
            "analyse",
            "--no-config",
            "--no-baseline",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--include-rule",
            "docs.missing-public-doc",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let report = json_output(&output);
    assert_eq!(report["run"]["inputs"], serde_json::json!(["src"]));
    let findings = report["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["file"], "src/inside.rs");
}

/// A name beginning with dots can still be a real project directory covered by `.gitignore`.
#[test]
fn check_ignore_recognizes_dot_prefixed_directory_names() {
    let project = tempdir().expect("project");
    let project_root = project.path();
    fs::create_dir(project_root.join("..cache")).expect("cache directory");
    fs::write(
        project_root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .expect("project marker");
    fs::write(project_root.join(".gitignore"), "..cache/\n").expect("ignore rule");

    let output = run(
        project_root,
        &["check-ignore", "..cache", "--no-config", "--format", "json"],
    );
    assert_eq!(output.status.code(), Some(0));
    let verdicts = json_output(&output);
    assert_eq!(verdicts[0]["path"], "..cache");
    assert_eq!(verdicts[0]["pattern"], "..cache/");
}

/// JSON and SARIF consumers can tell a missing config from a clean run.
#[test]
fn machine_failures_keep_the_error_category_and_exit_status() {
    let project = tempdir().expect("project");
    for command in ["analyse", "report", "summary"] {
        let output = run(
            project.path(),
            &[
                command,
                ".",
                "--config",
                "diff-settings.yaml",
                "--format",
                "json",
            ],
        );
        assert_eq!(output.status.code(), Some(2), "{command}");
        let report = json_output(&output);
        assert_eq!(report["summary"]["exitCode"], 2, "{command}");
        assert_eq!(
            report["diagnostics"][0]["type"], "config-error",
            "{command}"
        );
        assert_eq!(
            report["diagnostics"][0]["invalidatesRun"], true,
            "{command}"
        );
    }
    let output = run(
        project.path(),
        &[
            "analyse",
            ".",
            "--config",
            "diff-settings.yaml",
            "--format",
            "sarif",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    let sarif = json_output(&output);
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        false
    );
}

/// Reject invalid gate requests that could otherwise make an empty run look successful.
#[test]
fn stale_selectors_and_missing_hook_comparison_are_errors() {
    let project = tempdir().expect("project");
    let output = run(
        project.path(),
        &[
            "analyse",
            "--no-config",
            "--format",
            "json",
            "--include-rule",
            "docs.unknown",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        json_output(&output)["diagnostics"][0]["type"],
        "config-error"
    );

    let output = run(project.path(), &["hook", "--no-config", "--fail-on-new"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(json_output(&output)["diagnostics"][0]["type"], "baseline");
}

/// Upgrade valid legacy YAML while preserving an original that is also named by the destination.
#[test]
fn migration_handles_flow_mappings_and_refuses_existing_outputs() {
    let project = tempdir().expect("project");
    let root = project.path();
    let original = "# legacy\n\"minimumSeverity\": { analyse: warning } # keep gate\nallowlists: { secretPreviews: [] }\n";
    fs::write(root.join("legacy.yaml"), original).expect("legacy config");
    fs::hard_link(root.join("legacy.yaml"), root.join("alias.yaml")).expect("hard link");

    let rejected = run(
        root,
        &[
            "migrate-config",
            "--config",
            "legacy.yaml",
            "--output",
            "alias.yaml",
        ],
    );
    assert_eq!(rejected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("unable to create migration output"));
    assert_eq!(
        fs::read_to_string(root.join("legacy.yaml")).expect("preserved input"),
        original
    );

    let migrated = run(
        root,
        &[
            "migrate-config",
            "--config",
            "legacy.yaml",
            "--output",
            "current.yaml",
        ],
    );
    assert_eq!(
        migrated.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&migrated.stderr)
    );
    let checked = run(
        root,
        &[
            "analyse",
            ".",
            "--config",
            "current.yaml",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        checked.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert_eq!(json_output(&checked)["run"]["failOn"], "warning");
}

/// Keep an audited exclusion out of the scope-all gate even when reviewed baseline debt is included.
#[test]
fn scope_all_respects_reviewed_exclusions() {
    let project = tempdir().expect("project");
    let root = project.path();
    fs::write(root.join("lib.rs"), "pub fn sample() {}\n").expect("source");
    fs::write(
        root.join(".gruff-rs.yaml"),
        concat!(
            "schemaVersion: gruff-rs.config.v1\n",
            "gate: { scope: all, total: 0 }\n",
            "exclude:\n",
            "  - rule: docs.missing-public-doc\n",
            "    paths: [lib.rs]\n",
            "    reason: Reviewed sample\n",
        ),
    )
    .expect("config");

    let output = run(
        root,
        &[
            "analyse",
            "lib.rs",
            "--format",
            "json",
            "--no-baseline",
            "--include-rule",
            "docs.missing-public-doc",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json_output(&output);
    assert_eq!(report["summary"]["findings"]["total"], 0);
    assert_eq!(report["suppressions"][0]["suppressed"], 1);
}

/// A file that fails parsing adds no denominator that could improve the run's grade.
#[test]
fn parse_failure_does_not_publish_a_score_for_unevaluated_rust() {
    let project = tempdir().expect("project");
    fs::write(project.path().join("lib.rs"), "pub fn unfinished(\n").expect("source");
    let output = run(
        project.path(),
        &["analyse", "lib.rs", "--no-config", "--format", "json"],
    );
    assert_eq!(output.status.code(), Some(2));
    let report = json_output(&output);
    assert_eq!(report["summary"]["discoveredFiles"], 1);
    assert_eq!(report["summary"]["parsedFiles"], 0);
    assert_eq!(report["score"]["evaluatedFiles"], 0);
    assert!(report["score"]["composite"]["score"].is_null());
}

/// Migrate a 0.5-style config with retired rules and empty `minimumSeverity:`, confirm unmigrated runs hint `migrate-config`, and keep CLI `--selector` errors free of config hints.
#[test]
fn migrate_config_upgrades_legacy_05_config_and_unmigrated_shows_hint() {
    let project = tempdir().expect("project");
    let root = project.path();
    fs::write(root.join("README.md"), "# Sample\n").expect("readme");
    fs::write(
        root.join("lib.rs"),
        "/// Sample function.\npub fn sample() {}\n",
    )
    .expect("source");
    let legacy = concat!(
        "schemaVersion: gruff-rs.config.v1\n",
        "minimumSeverity:\n",
        "  # analyse: advisory\n",
        "allowlists:\n",
        "  secretPreviews: []\n",
        "rules:\n",
        "  docs.stale-todo:\n",
        "    enabled: true\n",
        "  naming.short-variable:\n",
        "    enabled: true\n",
    );
    fs::write(root.join(".gruff-rs.yaml"), legacy).expect("legacy config");

    let unmigrated = run(root, &["summary", "--no-ansi", "."]);
    assert_eq!(unmigrated.status.code(), Some(2));
    let unmigrated_stderr = String::from_utf8_lossy(&unmigrated.stderr);
    assert!(
        unmigrated_stderr.contains("gruff-rs migrate-config"),
        "{unmigrated_stderr}"
    );

    let migrated = run(
        root,
        &[
            "migrate-config",
            "--no-ansi",
            "--config",
            ".gruff-rs.yaml",
            "--output",
            "migrated.yaml",
        ],
    );
    assert_eq!(
        migrated.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&migrated.stderr)
    );
    let stdout = String::from_utf8_lossy(&migrated.stdout);
    assert!(stdout.contains("docs.stale-todo"), "{stdout}");
    assert!(stdout.contains("minimumSeverity:"), "{stdout}");
    assert_eq!(
        fs::read_to_string(root.join(".gruff-rs.yaml")).expect("source preserved"),
        legacy
    );

    let summary = run(
        root,
        &["summary", "--no-ansi", "--config", "migrated.yaml", "."],
    );
    assert_eq!(
        summary.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&summary.stderr)
    );

    let cli_selector = run(
        root,
        &["rules", "--no-config", "--selector", "docs.stale-todo"],
    );
    assert_eq!(cli_selector.status.code(), Some(2));
    let cli_stderr = String::from_utf8_lossy(&cli_selector.stderr);
    assert!(!cli_stderr.contains("migrate-config"), "{cli_stderr}");
}

/// Scanning a nested Git repository inside a gitignored subdirectory of a parent Rust repo evaluates the child repo rather than zero files.
#[test]
fn nested_git_repo_under_ignored_parent_dir_scans_its_own_sources() {
    let project = tempdir().expect("project");
    let parent = project.path();
    fs::write(parent.join("Cargo.toml"), "[package]\nname = \"parent\"\n").expect("parent cargo");
    fs::write(parent.join(".gitignore"), "scratch/\n").expect("parent gitignore");

    let child = parent.join("scratch/nested-app");
    fs::create_dir_all(child.join(".git")).expect("child git");
    fs::create_dir_all(child.join("src-tauri/src")).expect("child crate");
    fs::write(child.join("README.md"), "# Child\n").expect("child readme");
    fs::write(
        child.join("src-tauri/Cargo.toml"),
        "[package]\nname = \"child\"\n",
    )
    .expect("child cargo");
    fs::write(
        child.join("src-tauri/src/lib.rs"),
        "/// Entry point.\npub fn entry() {}\n",
    )
    .expect("child source");

    let output = run(
        parent,
        &[
            "summary",
            "--no-ansi",
            "--no-config",
            "--format",
            "json",
            "scratch/nested-app",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json_output(&output);
    assert_eq!(report["score"]["evaluatedFiles"], 1, "{report}");
    assert_eq!(report["summary"]["discoveredFiles"], 3, "{report}");
}
