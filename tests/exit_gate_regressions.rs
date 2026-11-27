//! Exercise the exit gates that decide whether an agent or CI run may continue, through the built `gruff-rs` binary.
//!
//! A gate that fails open lets an agent ship what the caller asked to block; one that blocks wrongly orders a change to
//! correct code. Covered: `hook --fail-on-new` against a Git base and against a baseline, the diagnostic severities the
//! bundled quality hook reads, and the `analyse --min-confidence` floor.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::{tempdir, TempDir};

/// One documented function whose `unwrap` reports medium-confidence `waste.unwrap-expect`; every test starts from it.
const UNWRAP_SOURCE: &str = "/// Old.\npub fn old(v: Option<i32>) -> i32 { v.unwrap() }\n";

/// Run the built binary from `cwd` with `command` split on single spaces, so no operand may contain a space.
/// Returns the exit status and captured stdout and stderr.
fn run(cwd: &Path, command: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gruff-rs"))
        .current_dir(cwd)
        .arg("--no-interaction")
        .args(command.split(' '))
        .output()
        .expect("run gruff-rs")
}

/// Returns the `key` array of the JSON report on `output`'s stdout, or panics with stdout and stderr when there is none.
fn rows(output: &Output, key: &str) -> Vec<Value> {
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_default();
    report[key].as_array().cloned().unwrap_or_else(|| {
        panic!(
            "`{key}` is not an array in: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Create a temporary project with package metadata, a README, and `src/lib.rs` holding `UNWRAP_SOURCE`.
/// Returns the directory, which deletes the project when dropped.
fn unwrap_project() -> TempDir {
    let project = tempdir().expect("project");
    let root = project.path();
    fs::create_dir_all(root.join("src")).expect("src");
    let manifest =
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\ndescription = \"d\"\nlicense = \"MIT\"\n";
    fs::write(root.join("Cargo.toml"), manifest).expect("manifest");
    fs::write(root.join("README.md"), "# demo\n").expect("readme");
    fs::write(root.join("src/lib.rs"), UNWRAP_SOURCE).expect("lib");
    project
}

/// Record everything in `root` as the first commit of a new Git repository, panicking with Git's stderr on failure.
fn commit_all(root: &Path) {
    let steps = [
        "init -q",
        "config user.email dev@example.com",
        "config user.name Dev",
        "add .",
        "commit -q -m initial",
    ];
    for step in steps {
        let output = Command::new("git")
            .current_dir(root)
            .args(step.split(' '))
            .output()
            .expect("run git");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "git {step} failed: {stderr}");
    }
}

/// `hook --diff <ref> --fail-on-new` blocks only what the edit introduced, under the default `--fail-on none`.
///
/// A finding already in the Git base is dropped, so an untouched tree exits 0.
/// A finding added since the base is published as `baselineStatus: "new"` and exits 1.
#[test]
fn hook_diff_fail_on_new_blocks_only_findings_absent_from_the_git_base() {
    let project = unwrap_project();
    let root = project.path();
    commit_all(root);
    let gate = "hook . --diff working-tree --diff-git-unsafe --no-config --fail-on-new";

    let unchanged = run(root, gate);
    assert_eq!(unchanged.status.code(), Some(0));
    assert!(rows(&unchanged, "findings").is_empty());

    let added = "/// Added.\npub fn added(v: Option<i32>) -> i32 { v.unwrap() }\n";
    fs::write(root.join("src/lib.rs"), format!("{UNWRAP_SOURCE}{added}")).expect("edit");
    let edited = run(root, gate);
    assert_eq!(edited.status.code(), Some(1));
    let findings = rows(&edited, "findings");
    let rules: Vec<&Value> = findings.iter().map(|row| &row["ruleId"]).collect();
    assert!(
        rules.contains(&&Value::from("waste.unwrap-expect")),
        "{rules:?}"
    );
    let statuses: Vec<&Value> = findings.iter().map(|row| &row["baselineStatus"]).collect();
    assert!(
        statuses.iter().all(|status| *status == "new"),
        "{statuses:?}"
    );
}

/// An applied baseline cannot exempt a secret from `hook --fail-on-new`, because no baseline can review one.
///
/// The baseline reviews every ordinary finding, so only the `notEligible` sensitive-data finding is left to block.
#[test]
fn hook_baseline_fail_on_new_blocks_a_sensitive_finding_no_baseline_can_review() {
    let project = unwrap_project();
    let root = project.path();
    // The sample key is assembled at run time so this file holds no contiguous key literal.
    let key = ["AKIA", "QQZZRSTVZZZZWWWW"].concat();
    let keys = format!("/// Sample.\npub const AWS_ACCESS_KEY_ID: &str = \"{key}\";\n");
    fs::write(root.join("src/keys.rs"), keys).expect("keys");
    let generate = "analyse --no-config --generate-baseline base.json --format json --fail-on none";
    assert_eq!(run(root, generate).status.code(), Some(0));

    // Without the new-only gate, the default `--fail-on none` lets the same run pass.
    let ungated = run(root, "hook --no-config --baseline base.json");
    assert_eq!(ungated.status.code(), Some(0));

    let gated = run(root, "hook --no-config --baseline base.json --fail-on-new");
    assert_eq!(gated.status.code(), Some(1));
    let findings = rows(&gated, "findings");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["ruleId"], "sensitive-data.aws-access-key");
    assert_eq!(findings[0]["baselineStatus"], "notEligible");
}

/// A hook run publishes informational diagnostics as warnings, never as fatal, and still exits 0.
///
/// `.goat-flow/hooks/gruff/feedback.mjs` runs `hook --format json <file>` after each edit and reports any fatal row as
/// `analyzer-failed`, dropping the findings. A one-file scan of a larger project always emits `partial-context-rule-suppressed`,
/// and a `--changed-ranges` run always emits `patch-filter`; neither sets `invalidatesRun`.
#[test]
fn hook_publishes_informational_diagnostics_as_warnings() {
    let project = unwrap_project();
    let root = project.path();
    fs::write(root.join("src/other.rs"), "/// Other.\npub fn other() {}\n").expect("other");
    let cases = [
        (
            "hook --format json src/lib.rs --no-config",
            "partial-context-rule-suppressed",
        ),
        (
            "hook src/lib.rs --no-config --changed-ranges 2-2 --changed-scope hunk",
            "patch-filter",
        ),
    ];
    for (command, informational) in cases {
        let output = run(root, command);
        assert_eq!(output.status.code(), Some(0), "{command}");
        assert!(!rows(&output, "findings").is_empty(), "{command}");
        let diagnostics = rows(&output, "diagnostics");
        let severities: Vec<(&Value, &Value)> = diagnostics
            .iter()
            .map(|row| (&row["type"], &row["severity"]))
            .collect();
        let expected = (&Value::from(informational), &Value::from("warning"));
        assert!(severities.contains(&expected), "{command}: {severities:?}");
        let fatal = severities.iter().any(|(_, severity)| *severity == "fatal");
        assert!(!fatal, "{command}: {severities:?}");
    }
}

/// `analyse --min-confidence` keeps lower-confidence findings in the report but out of the exit gate.
///
/// `waste.unwrap-expect` publishes medium confidence, so `--fail-on advisory` alone exits 1 and adding `--min-confidence high` exits 0.
#[test]
fn analyse_min_confidence_keeps_lower_confidence_findings_out_of_the_exit_gate() {
    let project = unwrap_project();
    let root = project.path();
    let gate =
        "analyse --no-config --include-rule waste.unwrap-expect --format json --fail-on advisory";

    let without_floor = run(root, gate);
    assert_eq!(without_floor.status.code(), Some(1));
    let findings = rows(&without_floor, "findings");
    assert_eq!(findings[0]["ruleId"], "waste.unwrap-expect");
    // The floor below only proves the gate while this rule stays under high confidence.
    assert_eq!(findings[0]["confidence"], "medium", "{findings:?}");

    let with_floor = run(root, &format!("{gate} --min-confidence high"));
    assert_eq!(with_floor.status.code(), Some(0));
    let kept = rows(&with_floor, "findings");
    assert_eq!(kept.len(), 1, "the floor gates without hiding: {kept:?}");
}
