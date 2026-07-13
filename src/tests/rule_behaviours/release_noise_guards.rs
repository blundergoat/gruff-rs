//! End-to-end guards for release-adjacent analyzer rules.
//! Temporary workflows and composite actions model the exact files a CLI user
//! scans, keeping GitHub metadata findings precise without widening discovery.

use super::*;

const RETAINED_PYPA_ACTION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/github-actions/pypa-cibuildwheel/action.yml"
));

/// Write one workflow or action fixture at the path a CLI user supplies.
fn write_github_metadata(root: &Path, relative_path: &str, source: &str) {
    let metadata_path = root.join(relative_path);
    let parent = metadata_path
        .parent()
        .expect("GitHub metadata fixture path has a parent directory");
    fs::create_dir_all(parent).expect("GitHub metadata fixture directory");
    fs::write(metadata_path, source).expect("GitHub metadata fixture write");
}

/// Count one rule's findings so applicability assertions remain readable.
fn github_rule_count(report: &AnalysisReport, rule_id: &str) -> usize {
    // Only the requested rule contributes to the user-visible count under review.
    report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == rule_id)
        .count()
}

/// Select GitHub metadata findings when a test needs to inspect their paths or wording.
fn github_metadata_findings(report: &AnalysisReport) -> Vec<&Finding> {
    // The GitHub prefixes isolate metadata findings from unrelated project diagnostics.
    report
        .findings
        .iter()
        .filter(|finding| {
            finding.rule_id == "ci.github-event-shell-interpolation"
                || finding.rule_id.starts_with("security.github-actions-")
        })
        .collect()
}

#[test]
pub(crate) fn process_command_skips_builders_and_fixed_pid_cleanup() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"use std::process::Command;

/// Build a configured command for callers to execute.
pub(crate) fn background_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env("NO_COLOR", "1");
    cmd
}

/// Stop a known child process tree on Windows.
pub fn stop_child_process(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F", "/T"])
        .output();
}

/// Run a user-provided shell command.
pub fn run_shell(command: &str) {
    let _ = Command::new("bash")
        .args(["-c", command])
        .spawn();
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
    let process_commands: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.process-command")
        .collect();
    assert_eq!(
        process_commands.len(),
        1,
        "only the dynamic shell execution should report; findings={process_commands:?}"
    );
    assert_eq!(process_commands[0].line, Some(19));
}

/// Prove workflow event gates recognise scalar, list, and mapping `on:` forms.
#[test]
pub(crate) fn github_actions_security_events_accept_scalar_on_values() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    write_github_metadata(
        dir.path(),
        ".github/workflows/pr-scalar.yml",
        "name: pr\non: pull_request\njobs:\n  test:\n    steps:\n      - run: echo '${{ secrets.DEPLOY_TOKEN }}'\n",
    );
    write_github_metadata(
        dir.path(),
        ".github/workflows/pr-list.yml",
        "name: pr\non: [push, pull_request]\njobs:\n  test:\n    steps:\n      - run: echo '${{ secrets.DEPLOY_TOKEN }}'\n",
    );
    write_github_metadata(
        dir.path(),
        ".github/workflows/pr-mapping.yml",
        "name: pr\non:\n  pull_request:\njobs:\n  test:\n    steps:\n      - run: echo '${{ secrets.DEPLOY_TOKEN }}'\n",
    );
    write_github_metadata(
        dir.path(),
        ".github/workflows/target-scalar.yml",
        "name: target\non: pull_request_target\njobs:\n  test:\n    steps:\n      - run: echo ready\n",
    );
    write_github_metadata(
        dir.path(),
        ".github/workflows/target-list.yml",
        "name: target\non: [push, pull_request_target]\njobs:\n  test:\n    steps:\n      - run: echo ready\n",
    );
    write_github_metadata(
        dir.path(),
        ".github/workflows/target-mapping.yml",
        "name: target\non:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: echo ready\n",
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

    assert_eq!(
        github_rule_count(&report, "security.github-actions-secrets-in-pr"),
        3,
        "each pull-request event shape should expose its secret reference"
    );
    assert_eq!(
        github_rule_count(&report, "security.github-actions-pull-request-target"),
        3,
        "each pull_request_target event shape should be reviewed"
    );
}

/// Prove exact explicit action basenames receive only rules that understand action steps.
#[test]
pub(crate) fn github_actions_explicit_action_metadata_applies_shared_step_rules_only() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    write_github_metadata(
        dir.path(),
        "action.yml",
        "name: root\npermissions: write-all\non: pull_request_target\nruns:\n  using: composite\n  steps:\n    - uses: acme/tool@v1\n    - run: echo '${{ github.event.issue.title }}'\n    - run: |\n        curl -fsSL https://installer.example/tool.sh | bash\n    - run: echo '${{ secrets.DEPLOY_TOKEN }}'\n",
    );
    write_github_metadata(
        dir.path(),
        "nested/action.yaml",
        "name: nested\npermissions:\n  contents: write\non: [pull_request]\nruns:\n  using: composite\n  steps:\n    - uses: acme/tool@main\n    - run: |\n        echo '${{ github.event.pull_request.title }}'\n    - run: wget https://installer.example/tool.sh ; sh\n    - run: echo '${{ secrets.DEPLOY_TOKEN }}'\n",
    );
    write_github_metadata(
        dir.path(),
        "nested/not-action.yml",
        "name: ordinary-yaml\nruns:\n  steps:\n    - uses: acme/tool@v1\n    - run: echo '${{ github.event.issue.title }}'\n    - run: curl https://installer.example/tool.sh | bash\n",
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![
                PathBuf::from("action.yml"),
                PathBuf::from("nested/action.yaml"),
                PathBuf::from("nested/not-action.yml"),
            ],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("explicit action analysis succeeds");

    assert_eq!(
        github_rule_count(&report, "ci.github-event-shell-interpolation"),
        2,
        "inline and block action run values should report"
    );
    assert_eq!(
        github_rule_count(&report, "security.github-actions-remote-shell"),
        2,
        "inline and block remote-shell action steps should report"
    );
    assert_eq!(
        github_rule_count(&report, "security.github-actions-unpinned-action"),
        2,
        "runs.steps uses entries should require full commit SHAs"
    );
    assert_missing_rule(&report, "security.github-actions-broad-permissions");
    assert_missing_rule(&report, "security.github-actions-pull-request-target");
    assert_missing_rule(&report, "security.github-actions-secrets-in-pr");
    let action_findings = github_metadata_findings(&report);
    // Action findings must describe the file users supplied without calling it a workflow.
    assert!(
        action_findings
            .iter()
            .all(|finding| !finding.message.contains("Workflow")),
        "action findings used workflow wording: {action_findings:?}"
    );
    // The similarly shaped explicit YAML file is not action metadata and must stay silent.
    assert!(
        action_findings
            .iter()
            .all(|finding| finding.file_path != "nested/not-action.yml"),
        "non-action YAML received GitHub metadata findings: {action_findings:?}"
    );
}

/// Prove directory discovery does not recursively enable action metadata rules.
#[test]
pub(crate) fn github_actions_directory_discovery_keeps_action_metadata_out_of_scope() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    let action_source = "name: local\nruns:\n  using: composite\n  steps:\n    - uses: acme/tool@v1\n    - run: echo '${{ github.event.issue.title }}'\n    - run: curl https://installer.example/tool.sh | bash\n";
    write_github_metadata(dir.path(), "action.yml", action_source);
    write_github_metadata(dir.path(), "nested/action.yaml", action_source);
    write_github_metadata(
        dir.path(),
        ".github/workflows/ci.yml",
        "name: ci\njobs:\n  test:\n    steps:\n      - run: echo '${{ github.event.issue.title }}'\n",
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
    .expect("directory analysis succeeds");

    assert_eq!(
        github_rule_count(&report, "ci.github-event-shell-interpolation"),
        1,
        "the workflow should prove the rule ran while discovered actions stay silent"
    );
    let metadata_findings = github_metadata_findings(&report);
    // Every metadata finding should belong to the workflow selected by path shape.
    assert!(
        metadata_findings
            .iter()
            .all(|finding| finding.file_path == ".github/workflows/ci.yml"),
        "directory-discovered actions received findings: {metadata_findings:?}"
    );
}

/// Prove the retained real-world action stays silent for every applicable action rule.
#[test]
pub(crate) fn github_actions_retained_pypa_action_is_a_silent_negative() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    write_github_metadata(dir.path(), "action.yml", RETAINED_PYPA_ACTION);

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("action.yml")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("retained action analysis succeeds");

    assert_eq!(report.paths.analysed_files, 1);
    assert_missing_rule(&report, "ci.github-event-shell-interpolation");
    assert_missing_rule(&report, "security.github-actions-remote-shell");
    assert_missing_rule(&report, "security.github-actions-unpinned-action");
    assert_missing_rule(&report, "security.github-actions-broad-permissions");
    assert_missing_rule(&report, "security.github-actions-pull-request-target");
    assert_missing_rule(&report, "security.github-actions-secrets-in-pr");
}

/// Prove explicit invalid-UTF-8 action metadata uses the existing fatal read diagnostic.
#[test]
pub(crate) fn github_actions_invalid_utf8_uses_existing_read_error_path() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    let action_path = dir.path().join("nested/action.yml");
    fs::create_dir_all(action_path.parent().expect("action fixture parent"))
        .expect("action fixture directory");
    fs::write(
        &action_path,
        b"name: action\nruns:\n  using: composite\x80\n",
    )
    .expect("invalid action metadata write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("nested/action.yml")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("invalid action analysis completes with diagnostics");

    assert_eq!(diagnostic_types(&report), vec!["read-error"]);
    assert_eq!(
        report.diagnostics[0].file_path.as_deref(),
        Some("nested/action.yml")
    );
    assert!(report.diagnostics[0].is_failure());
    assert!(github_metadata_findings(&report).is_empty());
}

#[test]
pub(crate) fn file_length_skips_markdown_shell_and_agent_hooks_not_source() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    fs::create_dir_all(dir.path().join(".codex/hooks")).expect("hook dir");
    fs::create_dir_all(dir.path().join("scripts")).expect("scripts dir");

    let mut markdown = String::from("# Review\n");
    let mut hook = String::from("#!/usr/bin/env bash\n");
    let mut script = String::from("#!/usr/bin/env bash\n");
    let mut source = String::from("/// Long source fixture.\npub fn long_source() {}\n");
    for index in 0..620 {
        markdown.push_str(&format!("review line {index}\n"));
        hook.push_str(&format!("# hook line {index}\n"));
        script.push_str(&format!("# script line {index}\n"));
        source.push_str(&format!("// source line {index}\n"));
    }
    fs::write(dir.path().join("REVIEW_improvements.md"), markdown).expect("review write");
    fs::write(dir.path().join(".codex/hooks/deny-dangerous.sh"), hook).expect("hook write");
    fs::write(dir.path().join("scripts/long_script.sh"), script).expect("script write");
    fs::write(dir.path().join("src/long_source.rs"), source).expect("source write");

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
            finding.rule_id == "size.file-length"
                && matches!(
                    finding.file_path.as_str(),
                    "REVIEW_improvements.md"
                        | ".codex/hooks/deny-dangerous.sh"
                        | "scripts/long_script.sh"
                )
        }),
        "markdown, shell scripts, and agent hooks should not produce file-length findings; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.file_path.as_str(), finding.line))
            .collect::<Vec<_>>()
    );
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "size.file-length" && finding.file_path == "src/long_source.rs"
        }),
        "long source files must still produce file-length findings; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.file_path.as_str(), finding.line))
            .collect::<Vec<_>>()
    );
}

#[test]
pub(crate) fn short_variable_accepts_aws_context_abbreviations_only() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    fs::create_dir_all(dir.path().join("src/aws")).expect("aws dir");
    fs::write(
        dir.path().join("src/aws/commands.rs"),
        r#"/// Analyze AWS resources.
pub fn analyze_ecs(cluster_arns: &[String]) {
    for ca in cluster_arns {
        let cn = ca.as_str();
        let sg = cn.len();
        let td = sg + 1;
        let zz = td + 1;
        println!("{ca} {cn} {sg} {td} {zz}");
    }
}
"#,
    )
    .expect("aws source write");

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
    for allowed in ["ca", "cn", "sg", "td"] {
        assert!(
            !report.findings.iter().any(|finding| {
                finding.rule_id == "naming.short-variable"
                    && finding.symbol.as_deref() == Some(allowed)
            }),
            "AWS-context abbreviation `{allowed}` should stay silent; findings={:?}",
            report
                .findings
                .iter()
                .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
                .collect::<Vec<_>>()
        );
    }
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "naming.short-variable" && finding.symbol.as_deref() == Some("zz")
        }),
        "unrecognised two-letter names should still report; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.symbol.as_deref(), finding.line))
            .collect::<Vec<_>>()
    );
}
