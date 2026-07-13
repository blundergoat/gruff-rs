//! Supply-chain contract tests for workflows maintainers and contributors run.
//! They reject moving action references, unexpected GitHub write authority,
//! floating Rust/Cargo tools, and incomplete platform pins before hosted CI can
//! execute them. A negative mutation proves the action-ref guard really fires.

use serde_yaml::{Mapping, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

const EXPECTED_ACTION_PINS: &[(&str, &str, &str)] = &[
    (
        "actions/checkout",
        "34e114876b0b11c390a56381ad16ebd13914f8d5",
        "v4.3.1",
    ),
    (
        "actions/upload-artifact",
        "ea165f8d65b6e75b540449e92b4886f43607fa02",
        "v4.6.2",
    ),
    (
        "actions/download-artifact",
        "d3f86a106a0bac45b974a628896c90dbdf5c8093",
        "v4.3.0",
    ),
    (
        "Swatinem/rust-cache",
        "c19371144df3bb44fab255c43d04cbc2ab54d1c4",
        "v2.9.1",
    ),
    (
        "dtolnay/rust-toolchain",
        "4be7066ada62dd38de10e7b70166bc74ed198c30",
        "stable snapshot for Rust 1.97.0",
    ),
];

const EXPECTED_RELEASE_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

const EXPECTED_ACTIONLINT_CHECKSUMS: &[&str] = &[
    "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
    "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6",
    "5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644",
    "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f",
];

/// Locate one checked-in contract relative to the workspace users run from.
fn workspace_path(relative_path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_path)
}

/// Read one workflow or script exactly as a contributor and hosted runner receive it.
fn read_workspace_text(relative_path: &str) -> String {
    let contract_path = workspace_path(relative_path);
    fs::read_to_string(&contract_path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", contract_path.display()))
}

/// Parse workflow YAML so permission checks follow the structure GitHub consumes.
fn read_workflow_yaml(relative_path: &str) -> Value {
    let workflow_text = read_workspace_text(relative_path);
    serde_yaml::from_str(&workflow_text)
        .unwrap_or_else(|error| panic!("{relative_path} must be valid YAML: {error}"))
}

/// Read a required mapping whose absence would remove a visible workflow section.
fn required_mapping<'a>(value: &'a Value, context: &str) -> Result<&'a Mapping, String> {
    // A non-mapping value means GitHub cannot apply the expected workflow contract.
    value
        .as_mapping()
        .ok_or_else(|| format!("{context} must be a mapping"))
}

/// Read a required YAML field so missing workflow authority has actionable feedback.
fn required_field<'a>(
    mapping: &'a Mapping,
    field_name: &str,
    context: &str,
) -> Result<&'a Value, String> {
    // A missing field means users cannot rely on that workflow permission or job.
    mapping
        .get(Value::String(field_name.to_string()))
        .ok_or_else(|| format!("{context} is missing `{field_name}`"))
}

/// Read one named workflow job that users see in a hosted run.
fn required_job<'a>(workflow: &'a Value, job_name: &str) -> Result<&'a Mapping, String> {
    let workflow_mapping = required_mapping(workflow, "workflow")?;
    let jobs = required_mapping(
        required_field(workflow_mapping, "jobs", "workflow")?,
        "workflow jobs",
    )?;
    required_mapping(
        required_field(jobs, job_name, "workflow jobs")?,
        &format!("job `{job_name}`"),
    )
}

/// Require exactly one contents permission so a job cannot silently gain authority.
fn require_contents_permission(
    permissions_owner: &Mapping,
    owner_name: &str,
    expected_access: &str,
) -> Result<(), String> {
    let permissions = required_mapping(
        required_field(permissions_owner, "permissions", owner_name)?,
        &format!("{owner_name} permissions"),
    )?;
    // One contents entry is the complete reviewed authority visible to maintainers.
    (permissions.len() == 1
        && permissions
            .get(Value::String("contents".to_string()))
            .and_then(Value::as_str)
            .is_some_and(|actual_access| actual_access == expected_access))
    .then_some(())
    .ok_or_else(|| format!("{owner_name} must grant only `contents: {expected_access}`"))
}

/// Keep contributor CI on its single read-only workflow permission.
fn validate_ci_workflow_permissions() -> Result<(), String> {
    let ci_workflow = read_workflow_yaml(".github/workflows/ci.yml");
    let ci_mapping = required_mapping(&ci_workflow, "CI workflow")?;
    require_contents_permission(ci_mapping, "CI workflow", "read")?;
    let ci_verify_job = required_job(&ci_workflow, "verify")?;
    // Job-level permission overrides would escape the reviewed read-only CI default.
    if ci_verify_job.contains_key(Value::String("permissions".to_string())) {
        return Err("CI verify job must inherit the read-only workflow permission".to_string());
    }
    Ok(())
}

/// Keep every release job on its reviewed read or write contents scope.
fn validate_release_job_permissions(release_workflow: &Value) -> Result<(), String> {
    let release_mapping = required_mapping(release_workflow, "release workflow")?;
    require_contents_permission(release_mapping, "release workflow", "read")?;
    let release_jobs = [
        "source_verify",
        "build",
        "asset_verify",
        "publish_crate",
        "publish_github",
    ];
    // Every visible release job gets an explicit least-authority contract.
    for release_job_name in release_jobs {
        let release_job = required_job(release_workflow, release_job_name)?;
        let expected_access = match release_job_name {
            "publish_github" => "write",
            _ => "read",
        };
        require_contents_permission(
            release_job,
            &format!("release job `{release_job_name}`"),
            expected_access,
        )?;
    }
    Ok(())
}

/// Keep the crates.io credential on its tag-only publish step and reject broad shorthand.
fn validate_release_secret_scope(
    release_workflow: &Value,
    release_text: &str,
) -> Result<(), String> {
    // One token reference keeps crate credentials on the user-visible publish step only.
    if release_text.matches("secrets.CARGO_REGISTRY_TOKEN").count() != 1 {
        return Err(
            "release workflow must reference CARGO_REGISTRY_TOKEN exactly once".to_string(),
        );
    }
    let publish_crate_yaml =
        serde_yaml::to_string(required_job(release_workflow, "publish_crate")?)
            .map_err(|error| error.to_string())?;
    // The single crate credential reference must remain inside the tag-only crate job.
    if !publish_crate_yaml.contains("secrets.CARGO_REGISTRY_TOKEN") {
        return Err("publish_crate must own the only crate credential reference".to_string());
    }
    // Broad shorthand would grant future jobs authority not visible in this review.
    if release_text.contains("write-all") || release_text.contains("read-all") {
        return Err("release workflow must use explicit least permissions".to_string());
    }

    Ok(())
}

/// Validate workflow defaults, job scopes, and the one secret-bearing publish step.
fn validate_workflow_permissions() -> Result<(), String> {
    validate_ci_workflow_permissions()?;
    let release_workflow = read_workflow_yaml(".github/workflows/release.yml");
    validate_release_job_permissions(&release_workflow)?;
    let release_text = read_workspace_text(".github/workflows/release.yml");
    validate_release_secret_scope(&release_workflow, &release_text)
}

/// Report whether an action ref is the immutable 40-hex identity maintainers reviewed.
fn is_full_commit_sha(action_ref: &str) -> bool {
    action_ref.len() == 40
        && action_ref
            .bytes()
            .all(|character| character.is_ascii_hexdigit())
}

/// Parse one external action identity, or return None for a commit-bound local action.
fn parsed_external_action<'a>(
    workflow_name: &str,
    line_number: usize,
    reference_with_comment: &'a str,
) -> Result<Option<(&'a str, &'a str, &'a str)>, String> {
    // Local actions are bound to the checked-out commit rather than an external ref.
    if reference_with_comment.starts_with("./") {
        return Ok(None);
    }
    // A missing comment would hide which reviewed release the SHA represents.
    let Some((action_identity, version_comment)) = reference_with_comment.split_once('#') else {
        return Err(format!(
            "{workflow_name}:{line_number} action pin needs a version comment"
        ));
    };
    let version_comment = version_comment.trim();
    // An empty comment gives maintainers no safe update trail.
    if version_comment.is_empty() {
        return Err(format!(
            "{workflow_name}:{line_number} action pin has an empty version comment"
        ));
    }
    // A missing @ separator cannot bind the action name to an immutable identity.
    let Some((action_name, action_ref)) = action_identity.trim().rsplit_once('@') else {
        return Err(format!(
            "{workflow_name}:{line_number} action reference must contain `@`"
        ));
    };
    // Moving tags, branch names, and short SHAs can change what users execute.
    if !is_full_commit_sha(action_ref) {
        return Err(format!(
            "{workflow_name}:{line_number} `{action_name}@{action_ref}` must use a full 40-character commit SHA"
        ));
    }
    Ok(Some((action_name, action_ref, version_comment)))
}

/// Match one immutable action identity to the reviewed release inventory.
fn require_reviewed_action_pin(
    workflow_name: &str,
    line_number: usize,
    action_name: &str,
    action_ref: &str,
    version_comment: &str,
) -> Result<(), String> {
    // Unknown external actions require a deliberate reviewed identity before use.
    let Some((_, expected_ref, expected_comment)) = EXPECTED_ACTION_PINS
        .iter()
        .find(|(expected_name, _, _)| *expected_name == action_name)
    else {
        return Err(format!(
            "{workflow_name}:{line_number} `{action_name}` is not in the reviewed action pin set"
        ));
    };
    // A changed SHA or comment must go through the documented update review.
    if action_ref != *expected_ref || version_comment != *expected_comment {
        return Err(format!(
            "{workflow_name}:{line_number} `{action_name}` must use `{expected_ref} # {expected_comment}`"
        ));
    }
    Ok(())
}

/// Validate every third-party action ref and its human-readable update comment.
fn validate_action_references(workflow_files: &[(&str, &str)]) -> Result<(), String> {
    let mut seen_action_names = BTreeSet::new();

    // Every workflow and composite path is scanned so users never execute a moving ref.
    for (workflow_name, workflow_text) in workflow_files {
        // Every line is considered because action steps may appear in any workflow job.
        for (line_index, workflow_line) in workflow_text.lines().enumerate() {
            let trimmed_line = workflow_line.trim_start();
            // Lines without `uses:` cannot execute a third-party action.
            let Some(reference_with_comment) = trimmed_line.strip_prefix("uses:") else {
                continue;
            };
            let line_number = line_index + 1;
            // None means this is a checked-in local action with no external identity.
            let Some((action_name, action_ref, version_comment)) =
                parsed_external_action(workflow_name, line_number, reference_with_comment.trim())?
            else {
                continue;
            };
            require_reviewed_action_pin(
                workflow_name,
                line_number,
                action_name,
                action_ref,
                version_comment,
            )?;
            seen_action_names.insert(action_name.to_string());
        }
    }

    // Every reviewed dependency must remain exercised by at least one visible workflow.
    for (expected_action_name, _, _) in EXPECTED_ACTION_PINS {
        // A missing action can signal an accidental workflow deletion or stale pin inventory.
        if !seen_action_names.contains(*expected_action_name) {
            return Err(format!(
                "reviewed action `{expected_action_name}` is missing from workflow execution paths"
            ));
        }
    }

    Ok(())
}

/// Join shell continuation lines so version checks inspect the command users execute.
fn logical_shell_commands(script_text: &str) -> Vec<String> {
    let mut logical_commands = Vec::new();
    let mut pending_command = String::new();

    // Each physical line contributes to one complete shell command or YAML run line.
    for physical_line in script_text.lines() {
        let trimmed_line = physical_line.trim();
        // Empty and comment-only lines cannot install a tool for the user.
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }
        let continues = trimmed_line.ends_with('\\');
        let command_fragment = trimmed_line.trim_end_matches('\\').trim_end();
        // A continued command needs one separator before its next visible argument.
        if !pending_command.is_empty() {
            pending_command.push(' ');
        }
        pending_command.push_str(command_fragment);
        // Continuation means the user-visible install command is not complete yet.
        if continues {
            continue;
        }
        // Non-empty commands are ready for version and lock enforcement.
        if !pending_command.is_empty() {
            logical_commands.push(std::mem::take(&mut pending_command));
        }
    }

    // A final command without a newline must still be checked for users.
    if !pending_command.is_empty() {
        logical_commands.push(pending_command);
    }
    logical_commands
}

/// Reject direct Cargo installs that float a version or ignore the crate lockfile.
fn validate_direct_cargo_installs(executable_files: &[(&str, &str)]) -> Result<(), String> {
    // Every executable workflow/script is checked because either can install release tools.
    for (file_name, file_text) in executable_files {
        // Logical commands keep split preflight arguments in the same reviewable unit.
        for shell_command in logical_shell_commands(file_text) {
            // Commands without a direct Cargo install do not affect installed tool identity.
            if !shell_command.contains("cargo install ") {
                continue;
            }
            // Both fields are required for the exact dependency users and CI execute.
            if !shell_command.contains("--version") || !shell_command.contains("--locked") {
                return Err(format!(
                    "{file_name} has an unpinned Cargo install: {shell_command}"
                ));
            }
        }
    }
    Ok(())
}

/// Require a reviewed literal that binds one tool or target to its expected identity.
fn require_contract_text(
    file_name: &str,
    file_text: &str,
    required_text: &str,
) -> Result<(), String> {
    file_text
        .contains(required_text)
        .then_some(())
        .ok_or_else(|| format!("{file_name} is missing reviewed pin `{required_text}`"))
}

/// Validate the exact Rust and cross versions users receive from hosted workflows.
fn validate_workflow_tool_versions(
    ci_workflow: &str,
    release_workflow: &str,
) -> Result<(), String> {
    require_contract_text(
        ".github/workflows/ci.yml",
        ci_workflow,
        "CI_RUST_TOOLCHAIN: 1.97.0",
    )?;
    require_contract_text(
        ".github/workflows/release.yml",
        release_workflow,
        "RELEASE_RUST_TOOLCHAIN: 1.97.0",
    )?;
    require_contract_text(
        ".github/workflows/release.yml",
        release_workflow,
        "cargo install cross --version 0.2.5 --locked",
    )
}

/// Validate exact Cargo and Go checker versions shared by local and hosted preflight.
fn validate_local_checker_versions(
    dependency_installer: &str,
    preflight: &str,
) -> Result<(), String> {
    require_contract_text(
        "scripts/dependency-install.sh",
        dependency_installer,
        "CARGO_AUDIT_VERSION=0.22.2",
    )?;
    require_contract_text(
        "scripts/preflight-checks.sh",
        preflight,
        "CARGO_AUDIT_VERSION=0.22.2",
    )?;
    require_contract_text(
        "scripts/dependency-install.sh",
        dependency_installer,
        "ACTION_VALIDATOR_VERSION=0.9.0",
    )?;
    require_contract_text(
        "scripts/dependency-install.sh",
        dependency_installer,
        "ACTIONLINT_VERSION=1.7.12",
    )?;
    require_contract_text(
        "scripts/preflight-checks.sh",
        preflight,
        "ACTIONLINT_VERSION=1.7.12",
    )
}

/// Validate every platform digest used before actionlint executes for a contributor.
fn validate_actionlint_checksums(dependency_installer: &str) -> Result<(), String> {
    // Each platform checksum prevents a downloaded actionlint binary changing unnoticed.
    for expected_checksum in EXPECTED_ACTIONLINT_CHECKSUMS {
        require_contract_text(
            "scripts/dependency-install.sh",
            dependency_installer,
            expected_checksum,
        )?;
    }
    Ok(())
}

/// Validate every target that becomes a downloadable release archive for users.
fn validate_release_target_pins(release_targets: &str) -> Result<(), String> {
    // Each target binds one downloadable archive row to a user-visible platform.
    for expected_target in EXPECTED_RELEASE_TARGETS {
        require_contract_text(
            "scripts/release-targets.sh",
            release_targets,
            expected_target,
        )?;
    }
    Ok(())
}

/// Validate exact Rust, Cargo-tool, actionlint, and release-target identities.
fn validate_tool_and_target_pins() -> Result<(), String> {
    let ci_workflow = read_workspace_text(".github/workflows/ci.yml");
    let release_workflow = read_workspace_text(".github/workflows/release.yml");
    let dependency_installer = read_workspace_text("scripts/dependency-install.sh");
    let preflight = read_workspace_text("scripts/preflight-checks.sh");
    let release_targets = read_workspace_text("scripts/release-targets.sh");

    validate_workflow_tool_versions(&ci_workflow, &release_workflow)?;
    validate_local_checker_versions(&dependency_installer, &preflight)?;
    validate_actionlint_checksums(&dependency_installer)?;
    validate_release_target_pins(&release_targets)?;

    validate_direct_cargo_installs(&[
        (".github/workflows/ci.yml", &ci_workflow),
        (".github/workflows/release.yml", &release_workflow),
        ("scripts/dependency-install.sh", &dependency_installer),
        ("scripts/preflight-checks.sh", &preflight),
    ])
}

/// Prove the live repository exposes only reviewed release supply-chain identities.
#[test]
fn live_release_paths_are_pinned_and_least_privilege() {
    let ci_workflow = read_workspace_text(".github/workflows/ci.yml");
    let release_workflow = read_workspace_text(".github/workflows/release.yml");
    let composite_action = read_workspace_text("action.yml");
    validate_action_references(&[
        (".github/workflows/ci.yml", &ci_workflow),
        (".github/workflows/release.yml", &release_workflow),
        ("action.yml", &composite_action),
    ])
    .expect("third-party action identities must stay immutable");
    validate_workflow_permissions().expect("workflow permissions must stay least privilege");
    validate_tool_and_target_pins().expect("release tools and targets must stay exact");
}

/// Prove a familiar moving checkout tag fails with an actionable repair message.
#[test]
fn mutable_action_tag_is_rejected_by_contract() {
    let ci_workflow = read_workspace_text(".github/workflows/ci.yml");
    let pinned_checkout = format!(
        "actions/checkout@{} # {}",
        EXPECTED_ACTION_PINS[0].1, EXPECTED_ACTION_PINS[0].2
    );
    let mutable_ci_workflow =
        ci_workflow.replacen(&pinned_checkout, "actions/checkout@v4 # v4.3.1", 1);
    let contract_error =
        validate_action_references(&[(".github/workflows/ci.yml", &mutable_ci_workflow)])
            .expect_err("a moving checkout tag must fail the supply-chain contract");
    assert!(
        contract_error.contains("must use a full 40-character commit SHA"),
        "unexpected contract feedback: {contract_error}"
    );
}
