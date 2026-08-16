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

#[test]
/// Resolve process constructors from lexical imports before applying command-risk heuristics.
pub(crate) fn process_command_requires_std_import_provenance() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    let provenance_cases = [
        (
            "std_bare.rs",
            "use rayon::prelude::*;\nuse std::process::Command;\n\npub fn run(input: &str) {\n    let _ = Command::new(\"sh\").arg(\"-c\").arg(input);\n}\n",
        ),
        (
            "std_module.rs",
            "use std::process;\n\npub fn run(input: &str) {\n    let _ = process::Command::new(\"sh\").arg(\"-c\").arg(input);\n}\n",
        ),
        (
            "std_qualified.rs",
            "pub fn run(input: &str) {\n    let _ = std::process::Command::new(\"sh\").arg(\"-c\").arg(input);\n}\n",
        ),
        (
            "function_std_bare.rs",
            "pub fn run(input: &str) {\n    use std::process::Command;\n    let _ = Command::new(\"sh\").arg(\"-c\").arg(input);\n}\n",
        ),
        (
            "block_std_module.rs",
            "pub fn run(input: &str) {\n    if !input.is_empty() {\n        use std::process;\n        let _ = process::Command::new(\"sh\").arg(\"-c\").arg(input);\n    }\n}\n",
        ),
        (
            "root_clap_shadowed.rs",
            "use clap::Command;\n\npub fn run(input: &str) {\n    use std::process::Command;\n    let _ = Command::new(\"sh\").arg(\"-c\").arg(input);\n}\n",
        ),
        (
            "clap_bare.rs",
            "use clap::Command;\n\npub fn app(input: &str) {\n    let _ = Command::new(\"app\").arg(input);\n}\n",
        ),
        (
            "function_clap_bare.rs",
            "pub fn app(input: &str) {\n    use clap::Command;\n    let _ = Command::new(\"app\").arg(input);\n}\n",
        ),
        (
            "root_std_shadowed.rs",
            "use std::process::Command;\n\npub fn app(input: &str) {\n    use clap::Command;\n    let _ = Command::new(\"app\").arg(input);\n}\n",
        ),
        (
            "unimported_bare.rs",
            "pub fn run(input: &str) {\n    let _ = Command::new(\"sh\").arg(\"-c\").arg(input);\n}\n",
        ),
        (
            "root_qualified.rs",
            "pub fn run(input: &str) {\n    let _ = ::std::process::Command::new(\"sh\").arg(\"-c\").arg(input);\n}\n",
        ),
        (
            "outer_path.rs",
            "pub fn run(input: &str) {\n    let _ = vendor::std::process::Command::new(\"sh\").arg(\"-c\").arg(input);\n}\n",
        ),
        (
            "comment_only.rs",
            "/// `std::process::Command::new(\"sh\").arg(input)` is example text.\npub fn documented() {}\n",
        ),
    ];
    for (fixture_name, fixture_source) in provenance_cases {
        fs::write(dir.path().join("src").join(fixture_name), fixture_source)
            .expect("write Rust case");
    }

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
    let process_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.process-command")
        .collect();
    assert_eq!(
        process_findings.len(),
        7,
        "only standard-library process constructors should report; findings={process_findings:?}"
    );
    for expected_file_name in [
        "std_bare.rs",
        "std_module.rs",
        "std_qualified.rs",
        "function_std_bare.rs",
        "block_std_module.rs",
        "root_clap_shadowed.rs",
        // A `::` root qualifier names the same standard-library type.
        "root_qualified.rs",
    ] {
        assert!(
            process_findings
                .iter()
                .any(|finding| finding.file_path.ends_with(expected_file_name)),
            "expected {expected_file_name} to report; findings={process_findings:?}"
        );
    }
}

/// Prove constructor matching and risk evidence come only from executable process code.
#[test]
pub(crate) fn process_command_ignores_name_suffixes_and_comment_risk() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"use std::process::Command;

struct AppCommand;

impl AppCommand {
    fn new(_name: &str) -> Self {
        Self
    }

    fn arg(self, _value: &str) -> Self {
        self
    }
}

mod other {
    pub(super) struct Command;

    impl Command {
        pub(super) fn new(_name: &str) -> AppCommand {
            AppCommand
        }
    }

    use super::AppCommand;
}

pub fn configure_app(input: &str) {
    let _ = AppCommand::new("sh").arg("-c").arg(input);
    let _ = other::Command::new("sh").arg("-c").arg(input);
}

pub fn print_message() {
    let _ = Command::new("echo").arg("hello").status();
    // Command::new("bash").arg("-c").arg(input);
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
    let process_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.process-command")
        .collect();

    assert!(
        process_findings.is_empty(),
        "same-suffix builders and comment-only risk must stay silent; findings={process_findings:?}"
    );
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

/// Prove `uses:` reports a dependency attached directly to a GitHub step or job,
/// and stays silent for `env:`, `with:`, and lookalike keys that only spell `uses`.
#[test]
pub(crate) fn github_actions_uses_requires_step_placement() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    write_github_metadata(
        dir.path(),
        "action.yml",
        "name: placement\ninputs:\n  uses:\n    description: Not an action dependency.\nruns:\n  using: composite\n  steps:\n    - name: Configure\n      with:\n        uses: acme/config-value@v1\n    - name: Run dependency\n      uses: acme/tool@v1\n    - uses: acme/pinned@1111111111111111111111111111111111111111\nmetadata:\n  runs:\n    steps:\n      - uses: acme/nested-action-value@v1\n",
    );
    write_github_metadata(
        dir.path(),
        ".github/workflows/placement.yml",
        "name: placement\nenv:\n  uses: acme/env-value@v1\njobs:\n  reusable:\n    uses: acme/reusable/.github/workflows/check.yml@v1\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Configure\n        with:\n          uses: acme/config-value@v1\n      - uses: acme/workflow-tool@v1\nmetadata:\n  jobs:\n    fake:\n      steps:\n        - uses: acme/nested-workflow-value@v1\n",
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![
                PathBuf::from("action.yml"),
                PathBuf::from(".github/workflows/placement.yml"),
            ],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("explicit action analysis succeeds");
    let unpinned_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.github-actions-unpinned-action")
        .collect();

    assert_eq!(
        unpinned_findings.len(),
        3,
        "only direct step and job dependencies should report; findings={unpinned_findings:?}"
    );
    assert!(unpinned_findings
        .iter()
        .any(|finding| { finding.file_path == "action.yml" && finding.line == Some(12) }));
    assert!(unpinned_findings.iter().any(|finding| {
        finding.file_path == ".github/workflows/placement.yml" && finding.line == Some(13)
    }));
    // A job calling a reusable workflow depends on third-party code exactly as a step does.
    assert!(unpinned_findings.iter().any(|finding| {
        finding.file_path == ".github/workflows/placement.yml" && finding.line == Some(6)
    }));
}

/// Prove pull-request gating reads the top-level `on` mapping: a step input named
/// `pull_request` is not a trigger, and a quoted key or event name still is.
#[test]
pub(crate) fn github_actions_events_require_top_level_on_placement() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    write_github_metadata(
        dir.path(),
        ".github/workflows/step-input.yml",
        "name: push only\non: push\njobs:\n  build:\n    steps:\n      - uses: acme/tool@1111111111111111111111111111111111111111\n        with:\n          pull_request: false\n      - run: echo '${{ secrets.DEPLOY_TOKEN }}'\n",
    );
    write_github_metadata(
        dir.path(),
        ".github/workflows/quoted-scalar.yml",
        "name: quoted trigger\n\"on\": pull_request_target\njobs:\n  build:\n    steps:\n      - run: echo '${{ secrets.DEPLOY_TOKEN }}'\n",
    );
    write_github_metadata(
        dir.path(),
        ".github/workflows/quoted-event.yml",
        "name: quoted event\non:\n  \"pull_request\":\n    branches: [main]\njobs:\n  build:\n    steps:\n      - run: echo '${{secrets.DEPLOY_TOKEN}}'\n",
    );
    write_github_metadata(
        dir.path(),
        ".github/workflows/flow-mapping.yml",
        "name: flow mapping\non: {push: null, pull_request: null}\njobs:\n  build:\n    steps:\n      - run: echo '${{ secrets.DEPLOY_TOKEN }}'\n",
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

    // Only the two real pull-request workflows expose their secret reference, and the
    // second proves interior expression whitespace is optional.
    assert_eq!(
        github_rule_count(&report, "security.github-actions-secrets-in-pr"),
        3,
        "quoted and flow-mapping triggers report; a `with:` input named pull_request does not"
    );
    assert_eq!(
        github_rule_count(&report, "security.github-actions-pull-request-target"),
        1,
        "only the quoted target trigger is a pull_request_target workflow"
    );
    let event_findings = github_metadata_findings(&report);
    assert!(
        event_findings
            .iter()
            .all(|finding| finding.file_path != ".github/workflows/step-input.yml"),
        "push-only workflow received pull-request findings: {event_findings:?}"
    );
}

/// Prove step keys and block headers accept every spelling GitHub honours, so a
/// quoted key or an explicit indentation indicator cannot hide a step's content.
#[test]
pub(crate) fn github_actions_step_keys_accept_quoted_and_indented_block_forms() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    write_github_metadata(
        dir.path(),
        ".github/workflows/quoted-step.yml",
        "name: quoted step\non: push\njobs:\n  build:\n    steps:\n      - \"uses\": acme/quoted@main\n      - \"run\": |2\n         curl -fsSL https://installer.example/tool.sh | bash\n      - run: | # install the toolchain\n          curl -fsSL https://installer.example/other.sh | bash\n",
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
        github_rule_count(&report, "security.github-actions-unpinned-action"),
        1,
        "a quoted `uses` key still names a moving dependency"
    );
    assert_eq!(
        github_rule_count(&report, "security.github-actions-remote-shell"),
        2,
        "a block header keeps its shell content in scope through an indentation indicator and a trailing comment"
    );
}

/// Prove a container image is exempt only when it names an immutable digest.
#[test]
pub(crate) fn github_actions_container_images_require_digest_pins() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    write_github_metadata(
        dir.path(),
        ".github/workflows/images.yml",
        "name: images\non: push\njobs:\n  build:\n    steps:\n      - uses: docker://alpine:latest\n      - uses: docker://alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n      - uses: ./.github/actions/local\n",
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

    let image_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.github-actions-unpinned-action")
        .collect();
    assert_eq!(
        image_findings.len(),
        1,
        "only the moving tag is unpinned; findings={image_findings:?}"
    );
    assert_eq!(image_findings[0].line, Some(6));
    // Guidance for an image must not tell users to supply a commit SHA.
    assert!(
        image_findings[0].message.contains("digest"),
        "container guidance should name a digest: {:?}",
        image_findings[0].message
    );
}

/// Prove the remote-shell rule requires the downloaded payload to reach the shell,
/// so running a checked-in script after an unrelated request stays silent.
#[test]
pub(crate) fn github_actions_remote_shell_requires_payload_reaching_shell() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    write_github_metadata(
        dir.path(),
        ".github/workflows/sequential.yml",
        "name: sequential\non: push\njobs:\n  build:\n    steps:\n      - run: curl -fsS https://example.invalid/health; bash ./scripts/verify.sh\n      - run: curl -fsS https://example.invalid/health || bash ./scripts/fallback.sh\n      - run: curl -fsSL -o /tmp/install.sh https://installer.example/tool.sh; bash /tmp/install.sh\n      - run: curl -fsSL https://installer.example/tool.sh | bash\n",
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

    let shell_lines: Vec<Option<usize>> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.github-actions-remote-shell")
        .map(|finding| finding.line)
        .collect();
    assert_eq!(
        shell_lines,
        vec![Some(8), Some(9)],
        "only the downloaded payload and the pipeline reach a shell"
    );
}

/// Prove a `permissions:` key inside a step is an action input, not a workflow grant.
#[test]
pub(crate) fn github_actions_broad_permissions_ignores_step_inputs() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    write_github_metadata(
        dir.path(),
        ".github/workflows/step-permissions.yml",
        "name: step input\non: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: acme/tool@1111111111111111111111111111111111111111\n        with:\n          permissions: write-all\n",
    );
    write_github_metadata(
        dir.path(),
        ".github/workflows/workflow-permissions.yml",
        "name: workflow grant\non: push\npermissions: write-all\njobs:\n  build:\n    steps:\n      - run: echo ready\n",
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

    let permission_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.github-actions-broad-permissions")
        .collect();
    assert_eq!(
        permission_findings.len(),
        1,
        "only the workflow-level grant is a permission; findings={permission_findings:?}"
    );
    assert_eq!(
        permission_findings[0].file_path,
        ".github/workflows/workflow-permissions.yml"
    );
}

/// Prove a download-to-shell pipeline still reports when the author splits it
/// across block-scalar lines, while fallbacks and non-shell pipe targets stay quiet.
#[test]
pub(crate) fn github_actions_remote_shell_tracks_split_block_pipelines() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    write_github_metadata(
        dir.path(),
        "action.yml",
        "name: split\nruns:\n  using: composite\n  steps:\n    - run: |\n        curl -fsSL https://installer.example/tool.sh |\n        bash\n",
    );
    write_github_metadata(
        dir.path(),
        "quiet/action.yml",
        "name: quiet\nruns:\n  using: composite\n  steps:\n    - run: |\n        curl -fsSL https://installer.example/tool.sh ||\n        bash ./fallback.sh\n    - run: |\n        curl -fsSL https://installer.example/tool.sh |\n        sha256sum -c expected.txt\n    - run: |\n        curl -fsSL https://installer.example/tool.sh -o installer\n        bash ./verify.sh\n",
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![
                PathBuf::from("action.yml"),
                PathBuf::from("quiet/action.yml"),
            ],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("explicit action analysis succeeds");

    assert_eq!(
        github_rule_count(&report, "security.github-actions-remote-shell"),
        1,
        "only the split download-to-shell pipeline should report; findings={:?}",
        github_metadata_findings(&report)
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
pub(crate) fn file_length_counts_comment_markers_inside_strings_as_code() {
    // A `/*` inside a string literal must not start comment state: every generated line below is
    // code, so the file crosses the 1000 substantive bar even though each line embeds a marker.
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let mut source = String::from("/// Probe.\npub fn entry() {\n");
    for index in 0..1005 {
        source.push_str(&format!("    let _ = \"/* marker {index} */\";\n"));
    }
    source.push_str("}\n");
    baseline_with_lib(dir.path(), &source);

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
            .any(|finding| finding.rule_id == "size.file-length"),
        "string-embedded comment markers must not hide substantive lines; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.file_path.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
pub(crate) fn file_length_ignores_comments_after_a_quote_char_literal() {
    // A `'"'` char literal must not open string state in the comment projection: the comment
    // padding after it stays free, so this tiny file never reaches the substantive bar.
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let mut source =
        String::from("/// Probe.\npub fn entry() -> char {\n    let quote = '\"';\n    quote\n}\n");
    for index in 0..1500 {
        source.push_str(&format!("// documentation filler {index}\n"));
    }
    baseline_with_lib(dir.path(), &source);

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
            .any(|finding| finding.rule_id == "size.file-length"),
        "comments after a quote char literal must stay free; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.file_path.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
pub(crate) fn file_length_leaves_block_comment_padding_free() {
    // The same file shape padded with a nested block comment stays under the bar: documentation
    // is free, so only the handful of code lines count.
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let mut source = String::from("/// Probe.\npub fn entry() {}\n/*\n");
    for index in 0..1500 {
        source.push_str(&format!("documentation line {index}\n"));
    }
    source.push_str("*/\n");
    baseline_with_lib(dir.path(), &source);

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
            .any(|finding| finding.rule_id == "size.file-length"),
        "block-comment padding must stay free under substantive counting; findings={:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.file_path.as_str()))
            .collect::<Vec<_>>()
    );
}

/// Pin the no-config file-length gate end to end. The rule reads its bar from the
/// catalogue, so this fails if a call site ever hardcodes a threshold or severity
/// again and a `--no-config` scan stops matching what `list-rules` advertises.
#[test]
pub(crate) fn file_length_no_config_gate_matches_ratified_bar() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");

    let mut under = String::from("/// Under the bar.\npub fn under() {\n");
    for index in 0..900 {
        under.push_str(&format!("    let _ = {index};\n"));
    }
    under.push_str("}\n");
    let mut over = String::from("/// Over the bar.\npub fn over() {\n");
    for index in 0..1005 {
        over.push_str(&format!("    let _ = {index};\n"));
    }
    over.push_str("}\n");
    fs::write(dir.path().join("src/under_bar.rs"), under).expect("under write");
    fs::write(dir.path().join("src/over_bar.rs"), over).expect("over write");

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

    let file_length: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "size.file-length")
        .map(|finding| (finding.file_path.as_str(), finding.severity))
        .collect();
    assert_eq!(
        file_length,
        vec![("src/over_bar.rs", Severity::Error)],
        "only the file past the ratified bar should flag, at error severity",
    );
}

#[test]
pub(crate) fn file_length_skips_markdown_shell_and_agent_hooks_not_source() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "/// Probe.\npub fn entry() {}\n");
    fs::create_dir_all(dir.path().join(".codex/hooks")).expect("hook dir");
    fs::create_dir_all(dir.path().join("scripts")).expect("scripts dir");

    // The source fixture needs substantive statements: file-length counts non-blank,
    // non-comment lines only, and the exempt shapes stay oversized on raw length.
    let mut markdown = String::from("# Review\n");
    let mut hook = String::from("#!/usr/bin/env bash\n");
    let mut script = String::from("#!/usr/bin/env bash\n");
    let mut source = String::from("/// Long source fixture.\npub fn long_source() {\n");
    for index in 0..1005 {
        markdown.push_str(&format!("review line {index}\n"));
        hook.push_str(&format!("echo hook line {index}\n"));
        script.push_str(&format!("echo script line {index}\n"));
        source.push_str(&format!("    let _ = {index};\n"));
    }
    source.push_str("}\n");
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
