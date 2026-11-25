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

/// Migrate a 0.5-style config with retired rules and empty `minimumSeverity:`.
///
/// Also verifies unmigrated runs suggest `migrate-config` while CLI `--selector` typos stay free of config migration hints.
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

/// Keep an inline YAML comment on an already-matching `schemaVersion:` line during comment-preserving config migration.
#[test]
fn migrate_config_preserves_inline_comment_on_schema_version() {
    let project = tempdir().expect("project");
    let root = project.path();
    fs::write(
        root.join(".gruff-rs.yaml"),
        "schemaVersion: gruff-rs.config.v1  # pinned\nminimumSeverity:\n  # analyse: advisory\n",
    )
    .expect("legacy config");

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
    let output_text = fs::read_to_string(root.join("migrated.yaml")).expect("migrated");
    assert!(
        output_text.contains("schemaVersion: gruff-rs.config.v1  # pinned"),
        "{output_text}"
    );
    assert!(!String::from_utf8_lossy(&migrated.stdout).contains("schemaVersion pinned"));
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

/// Execute `git` inside `dir` with `arguments` and assert a zero exit status.
fn run_git(dir: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .current_dir(dir)
        .args(arguments)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
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

/// Configured `exclude` and `sensitiveExclusions` precede baseline generation and application without marking excluded findings resolved.
#[test]
fn exclusions_precede_baseline_generation_and_application() {
    let project = tempdir().expect("project");
    let root = project.path();
    write_project_markers(root);
    fs::create_dir(root.join("src")).expect("src");
    let secret = concat!("k9xP2mQ8vR4nL7wZ3jH", "6tB5cF1yD0aE8sG");
    fs::write(
        root.join("src/lib.rs"),
        format!(
            "/// Unwrap `x` and return its inner integer.\n\
             pub fn demo(x: Option<i32>) -> i32 {{\n\
                 let _s = \"{secret}\";\n\
                 x.unwrap()\n\
             }}\n"
        ),
    )
    .expect("source");
    fs::write(
        root.join("exclude.yaml"),
        concat!(
            "schemaVersion: gruff-rs.config.v1\n",
            "exclude:\n",
            "  - rule: waste.unwrap-expect\n",
            "    reason: accepted unwrap\n",
            "sensitiveExclusions:\n",
            "  - rule: sensitive-data.high-entropy-string\n",
            "    path: src/lib.rs\n",
            "    reason: synthetic secret\n",
        ),
    )
    .expect("config");

    let gen_excluded = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--config",
            "exclude.yaml",
            "--include-rule",
            "waste.unwrap-expect",
            "--include-rule",
            "sensitive-data.high-entropy-string",
            "--generate-baseline",
            "excluded-base.json",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(gen_excluded.status.code(), Some(0));
    let generated: Value =
        serde_json::from_str(&fs::read_to_string(root.join("excluded-base.json")).expect("read"))
            .expect("json");
    assert_eq!(generated["occurrences"].as_array().expect("occ").len(), 0);
    assert_eq!(generated["sensitive"]["counts"]["total"], 0);

    let gen_full = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--no-config",
            "--include-rule",
            "waste.unwrap-expect",
            "--include-rule",
            "sensitive-data.high-entropy-string",
            "--generate-baseline",
            "full-base.json",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(gen_full.status.code(), Some(0));

    let applied = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--config",
            "exclude.yaml",
            "--include-rule",
            "waste.unwrap-expect",
            "--include-rule",
            "sensitive-data.high-entropy-string",
            "--baseline",
            "full-base.json",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(applied.status.code(), Some(0));
    let applied_report = json_output(&applied);
    assert_eq!(applied_report["baseline"]["resolvedFindings"], 0);
    assert_eq!(applied_report["summary"]["findings"]["total"], 0);
}

/// Running `--diff` and `hook --diff` from a nested workspace member crate maps changed lines relative to the crate root.
#[test]
fn nested_member_crate_git_diff_and_hook_map_relative_paths() {
    let project = tempdir().expect("project");
    let root = project.path();
    let member = root.join("crates/sub");
    fs::create_dir_all(member.join("src")).expect("member src");
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/sub\"]\n",
    )
    .expect("workspace");
    fs::write(
        member.join("Cargo.toml"),
        "[package]\nname = \"sub\"\nversion = \"0.1.0\"\ndescription = \"sub\"\nlicense = \"MIT\"\n",
    )
    .expect("member manifest");
    fs::write(member.join("README.md"), "# sub\n").expect("readme");
    fs::write(
        member.join("src/lib.rs"),
        "/// Stable.\npub fn clean() {}\n",
    )
    .expect("lib");

    run_git(root, &["init", "-q"]);
    run_git(root, &["config", "user.email", "dev@example.com"]);
    run_git(root, &["config", "user.name", "Dev"]);
    run_git(root, &["add", "."]);
    run_git(root, &["commit", "-q", "-m", "initial"]);

    fs::write(
        member.join("src/lib.rs"),
        "/// Stable.\npub fn clean() {}\npub fn added(v: Option<i32>) -> i32 { v.unwrap() }\n",
    )
    .expect("modified lib");

    let analyse_out = run(
        &member,
        &[
            "analyse",
            ".",
            "--diff",
            "working-tree",
            "--diff-git-unsafe",
            "--no-config",
            "--no-baseline",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(analyse_out.status.code(), Some(0));
    let report = json_output(&analyse_out);
    assert!(report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .any(|item| item["file"] == "src/lib.rs" && item["ruleId"] == "waste.unwrap-expect"));

    let hook_out = run(
        &member,
        &[
            "hook",
            ".",
            "--diff",
            "working-tree",
            "--diff-git-unsafe",
            "--no-config",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(hook_out.status.code(), Some(0));
    let hook_json = json_output(&hook_out);
    assert_eq!(hook_json["contractVersion"], "gruff.hook.v2");
    assert!(hook_json["findings"]
        .as_array()
        .expect("hook findings")
        .iter()
        .any(|item| item["ruleId"] == "waste.unwrap-expect"));
}

/// Verify CLI execution selectors override config ignores and display flags validate rules and pillars.
///
/// Verifies `--include-rule` beats `rules.ignore` and `--exclude-rule` beats `--include-pillar`.
/// Also checks unknown `--show-rule` exits 2 and `--show-pillar` matches case-insensitively.
#[test]
fn cli_selectors_override_config_ignore_and_validate_display_flags() {
    let project = tempdir().expect("project");
    let root = project.path();
    write_project_markers(root);
    fs::create_dir(root.join("src")).expect("src");
    fs::write(
        root.join("src/lib.rs"),
        "/// Demo.\npub fn demo(v: Option<i32>) -> i32 { v.unwrap() }\n",
    )
    .expect("source");
    fs::write(
        root.join(".gruff-rs.yaml"),
        "schemaVersion: gruff-rs.config.v1\nrules:\n  ignore: [\"waste.unwrap-expect\"]\n",
    )
    .expect("config");

    let included = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--include-rule",
            "waste.unwrap-expect",
            "--no-baseline",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(included.status.code(), Some(0));
    let included_report = json_output(&included);
    assert!(included_report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .any(|item| item["ruleId"] == "waste.unwrap-expect"));

    let excluded = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--include-pillar",
            "Maintainability",
            "--exclude-rule",
            "waste.unwrap-expect",
            "--no-baseline",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(excluded.status.code(), Some(0));
    assert!(!json_output(&excluded)["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .any(|item| item["ruleId"] == "waste.unwrap-expect"));

    let bad_show = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--no-config",
            "--show-rule",
            "bogus.nonexistent",
            "--format",
            "json",
        ],
    );
    assert_eq!(bad_show.status.code(), Some(2));

    let lower_pillar = run(
        root,
        &[
            "analyse",
            "src/lib.rs",
            "--no-config",
            "--no-baseline",
            "--show-pillar",
            "maintainability",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(lower_pillar.status.code(), Some(0));
    assert!(json_output(&lower_pillar)["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .any(|item| item["ruleId"] == "waste.unwrap-expect"));
}

/// Verify hook external baselines, hook diff failures, Markdown findings headings, and HTML cognitive fallback.
///
/// Checks external baselines report `applied: true` with `path: null`, diff errors emit `changed-region`, and Markdown emits `## Findings`.
#[test]
fn hook_external_baseline_diff_error_and_markdown_html_reports() {
    let parent = tempdir().expect("parent");
    let root = parent.path().join("proj");
    fs::create_dir_all(root.join("src")).expect("src");
    write_project_markers(&root);
    fs::write(
        root.join("src/lib.rs"),
        concat!(
            "/// Complex demo.\n",
            "pub fn complex(a: bool, b: bool, c: bool, d: bool, e: bool) -> i32 {\n",
            "    if a { if b { if c { if d { if e { return 1; } } } } }\n",
            "    if a && b || c && d || e { return 2; }\n",
            "    0\n",
            "}\n",
        ),
    )
    .expect("source");

    let ext_base = parent.path().join("external-baseline.json");
    let generated_baseline = run(
        &root,
        &[
            "analyse",
            "src/lib.rs",
            "--no-config",
            "--generate-baseline",
            ext_base.to_str().expect("path"),
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(generated_baseline.status.code(), Some(0));

    let hook = run(
        &root,
        &[
            "hook",
            "src/lib.rs",
            "--no-config",
            "--baseline",
            ext_base.to_str().expect("path"),
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(hook.status.code(), Some(0));
    let hook_json = json_output(&hook);
    assert_eq!(hook_json["run"]["baseline"]["applied"], true);
    assert!(hook_json["run"]["baseline"]["path"].is_null());
    assert_eq!(hook_json["run"]["scope"], "file");

    let hook_diff_err = run(
        &root,
        &[
            "hook",
            "src/lib.rs",
            "--no-config",
            "--diff",
            "working-tree",
            "--diff-git-unsafe",
        ],
    );
    assert_eq!(hook_diff_err.status.code(), Some(2));
    assert_eq!(
        json_output(&hook_diff_err)["diagnostics"][0]["type"],
        "changed-region"
    );

    let markdown_out = run(
        &root,
        &[
            "analyse",
            "src/lib.rs",
            "--no-config",
            "--no-baseline",
            "--format",
            "markdown",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(markdown_out.status.code(), Some(0));
    let markdown_text = String::from_utf8_lossy(&markdown_out.stdout);
    assert!(markdown_text.contains("## Findings"), "{markdown_text}");

    let html = run(
        &root,
        &[
            "analyse",
            "src/lib.rs",
            "--no-config",
            "--no-baseline",
            "--format",
            "html",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(html.status.code(), Some(0));
    let html_text = String::from_utf8_lossy(&html.stdout);
    assert!(html_text.contains("cognitive complexity"), "{html_text}");
}

/// Multi-file `diff -ru` patches do not swallow subsequent file headers into hunk context.
#[test]
fn multifile_diff_ru_patch_retains_second_file() {
    let project = tempdir().expect("project");
    let root = project.path();
    write_project_markers(root);
    fs::create_dir(root.join("src")).expect("src");
    fs::write(
        root.join("src/a.rs"),
        "/// A.\npub fn a(x: Option<i32>) -> i32 { x.unwrap() }\n",
    )
    .expect("a");
    fs::write(
        root.join("src/b.rs"),
        "/// B.\npub fn b(x: Option<i32>) -> i32 { x.unwrap() }\n",
    )
    .expect("b");
    fs::write(
        root.join("changes.patch"),
        concat!(
            "--- src/a.rs\n",
            "+++ src/a.rs\n",
            "@@ -1,1 +1,1 @@\n",
            "-/// old\n",
            "+/// A.\n",
            "--- src/b.rs\n",
            "+++ src/b.rs\n",
            "@@ -1,1 +1,1 @@\n",
            "-/// old\n",
            "+pub fn b(x: Option<i32>) -> i32 { x.unwrap() }\n",
        ),
    )
    .expect("patch");

    let output = run(
        root,
        &[
            "analyse",
            "src",
            "--no-config",
            "--no-baseline",
            "--diff-patch",
            "changes.patch",
            "--include-rule",
            "waste.unwrap-expect",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(json_output(&output)["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .any(|f| f["file"] == "src/b.rs"));
}

/// Every subcommand that accepts `--config` and `--no-config` rejects passing both flags together.
#[test]
fn subcommands_reject_conflicting_config_and_no_config_flags() {
    let project = tempdir().expect("project");
    for subcommand in ["summary", "report", "hook", "list-rules", "check-ignore"] {
        let conflict = run(
            project.path(),
            &[subcommand, "--config", "a.yaml", "--no-config"],
        );
        assert_eq!(
            conflict.status.code(),
            Some(2),
            "{subcommand} must reject --config + --no-config"
        );
    }
}

/// Explicit symlink targets matching `paths.ignore` remain ignored instead of resolving to an unignored path.
#[cfg(unix)]
#[test]
fn explicit_symlink_matching_config_ignore_stays_ignored() {
    use std::os::unix::fs::symlink;

    let project = tempdir().expect("project");
    let root = project.path();
    write_project_markers(root);
    fs::create_dir_all(root.join("src")).expect("src");
    fs::create_dir_all(root.join("vendor")).expect("vendor");
    fs::write(
        root.join("src/real.rs"),
        "/// Real.\npub fn real(x: Option<i32>) -> i32 { x.unwrap() }\n",
    )
    .expect("real");
    symlink(root.join("src/real.rs"), root.join("vendor/link.rs")).expect("symlink");
    fs::write(
        root.join(".gruff-rs.yaml"),
        "schemaVersion: gruff-rs.config.v1\npaths:\n  ignore:\n    - \"vendor/**\"\n",
    )
    .expect("config");

    let output = run(
        root,
        &[
            "analyse",
            "vendor/link.rs",
            "--no-baseline",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let report = json_output(&output);
    assert_eq!(report["summary"]["analysedFiles"], 0);
    assert_eq!(report["findings"].as_array().expect("findings").len(), 0);
}
