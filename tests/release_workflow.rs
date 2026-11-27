//! Contract tests for the release workflow graph consumed by maintainers.
//! They parse the checked-in YAML so candidate runs must traverse source,
//! package, matrix, archive, and checksum gates before tag-only publication.
//! Negative mutations prove each load-bearing edge and draft stage is enforced.

use serde_yaml::{Mapping, Value};
use std::fs;
use std::path::PathBuf;

/// Locate the workflow a maintainer dispatches or triggers with a release tag.
///
/// Returns `.github/workflows/release.yml` joined onto the crate's `CARGO_MANIFEST_DIR`, without checking that the file exists.
fn release_workflow_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml")
}

/// Parse the live workflow exactly as GitHub receives it from the selected ref.
///
/// Returns the parsed YAML document from `release_workflow_path`, and panics when the file cannot be read or is not valid YAML.
fn read_release_workflow() -> Value {
    let workflow_path = release_workflow_path();
    // A missing file means the selected ref offers maintainers no release workflow.
    let workflow_text = fs::read_to_string(&workflow_path).expect("release workflow is readable");
    // Invalid YAML means GitHub cannot present the release workflow to a maintainer.
    serde_yaml::from_str(&workflow_text).expect("release workflow is valid YAML")
}

/// Build a YAML mapping key without scattering representation details through tests.
///
/// Returns `key` copied into a `Value::String` for mapping lookups and inserts.
fn yaml_key(key: &str) -> Value {
    Value::String(key.to_string())
}

/// Read a required mapping whose absence means the workflow graph is incomplete.
///
/// `value` is the YAML node to view as a mapping, and `context` names that node in the error message.
/// Returns the borrowed mapping, or an Err saying `context` must be a mapping when `value` is any other YAML shape.
fn required_mapping<'a>(value: &'a Value, context: &str) -> Result<&'a Mapping, String> {
    // A non-mapping value means the maintainer-facing workflow section is missing.
    value
        .as_mapping()
        .ok_or_else(|| format!("{context} must be a mapping"))
}

/// Read one required field so missing YAML becomes actionable contract feedback.
///
/// Looks up the `field` key in `mapping`, and `context` names the owner of that key in the error message.
/// Returns the field's value, or an Err saying `context` is missing `field` when the key is absent.
fn required_field<'a>(
    mapping: &'a Mapping,
    field: &str,
    context: &str,
) -> Result<&'a Value, String> {
    // A missing field means GitHub cannot enforce that part of the release journey.
    mapping
        .get(yaml_key(field))
        .ok_or_else(|| format!("{context} is missing `{field}`"))
}

/// Read one named job from the graph a candidate or tag run will traverse.
///
/// `workflow` is the parsed workflow document, and `job_name` is the key looked up under its top-level `jobs` mapping.
/// Returns that job's mapping, or an Err when the root or `jobs` is not a mapping, `jobs` is absent, or the job is absent or not a mapping.
fn required_job<'a>(workflow: &'a Value, job_name: &str) -> Result<&'a Mapping, String> {
    let workflow_mapping = required_mapping(workflow, "workflow")?;
    let jobs = required_mapping(
        required_field(workflow_mapping, "jobs", "workflow")?,
        "jobs",
    )?;
    required_mapping(
        required_field(jobs, job_name, "jobs")?,
        &format!("job `{job_name}`"),
    )
}

/// Read mutable job YAML for a deliberate negative graph mutation.
///
/// `workflow` is the parsed workflow document to edit, and `job_name` is the key looked up under its top-level `jobs` mapping.
/// Returns a mutable borrow of that job's mapping.
/// Returns an Err when the root is not a mapping, or when `jobs` or the named job is absent or not a mapping.
fn required_job_mut<'a>(
    workflow: &'a mut Value,
    job_name: &str,
) -> Result<&'a mut Mapping, String> {
    // A non-mapping root means the negative test cannot model a real workflow edit.
    let workflow_mapping = workflow
        .as_mapping_mut()
        .ok_or_else(|| "workflow must be a mapping".to_string())?;
    // Missing jobs mean there is no graph edge for the negative test to remove.
    let jobs = workflow_mapping
        .get_mut(yaml_key("jobs"))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| "workflow jobs must be a mapping".to_string())?;
    // Missing named jobs already violate the intended graph contract.
    jobs.get_mut(yaml_key(job_name))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| format!("job `{job_name}` must be a mapping"))
}

/// Normalize scalar or list-shaped `needs` into the prerequisite jobs users rely on.
///
/// `job` is the job mapping whose `needs` field is read, and `job_name` names that job in error messages.
/// Returns one name for a scalar `needs`, or every name in list order for a sequence.
/// Returns an Err when `needs` is absent, is another YAML shape, or lists a non-string item.
fn job_needs(job: &Mapping, job_name: &str) -> Result<Vec<String>, String> {
    let needs = required_field(job, "needs", &format!("job `{job_name}`"))?;
    match needs {
        Value::String(name) => Ok(vec![name.clone()]),
        Value::Sequence(names) => names
            .iter()
            .map(|name| {
                // A non-string prerequisite cannot identify a visible workflow job.
                name.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("job `{job_name}` has a non-string prerequisite"))
            })
            .collect(),
        _ => Err(format!("job `{job_name}` has invalid `needs`")),
    }
}

/// Join every run step so the graph test can inspect user-visible release stages.
///
/// `job` is the job mapping whose `steps` sequence is read; steps that are not mappings or lack a text `run` value are skipped.
/// Returns the `run` texts joined with newlines in step order, or an empty string when no step has one.
/// Returns an Err when `steps` is absent or is not a sequence.
fn job_run_script(job: &Mapping) -> Result<String, String> {
    // Missing or non-list steps mean the job cannot run its visible release gates.
    let steps = required_field(job, "steps", "job")?
        .as_sequence()
        .ok_or_else(|| "job steps must be a sequence".to_string())?;
    Ok(steps
        .iter()
        .filter_map(Value::as_mapping)
        .filter_map(|step| step.get(yaml_key("run")))
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Require a dependency edge that prevents a job from bypassing verification.
///
/// Reads the `needs` of `job`, which `job_name` names in errors, and passes when `prerequisite` is one of its job names.
/// Returns an Err when `needs` cannot be read or does not include `prerequisite`.
fn require_job_need(job: &Mapping, job_name: &str, prerequisite: &str) -> Result<(), String> {
    let prerequisites = job_needs(job, job_name)?;
    prerequisites
        .iter()
        .any(|name| name == prerequisite)
        .then_some(())
        .ok_or_else(|| format!("job `{job_name}` must need `{prerequisite}`"))
}

/// Require one command fragment that represents a user-visible release gate.
///
/// Passes when `stage` occurs anywhere in the joined `run` text of `job`, and `job_name` names the job in the missing-stage error.
/// Returns an Err when the steps cannot be read or `stage` is absent.
fn require_run_stage(job: &Mapping, job_name: &str, stage: &str) -> Result<(), String> {
    job_run_script(job)?
        .contains(stage)
        .then_some(())
        .ok_or_else(|| format!("job `{job_name}` is missing release stage `{stage}`"))
}

/// Require one complete shell line so a related command cannot mask its removal.
///
/// Passes when one line of the joined `run` text of `job`, trimmed of surrounding whitespace, equals `command` exactly.
/// `job_name` names the job in the missing-command error. Returns an Err when the steps cannot be read or no line matches.
fn require_run_command(job: &Mapping, job_name: &str, command: &str) -> Result<(), String> {
    job_run_script(job)?
        .lines()
        .any(|run_line| run_line.trim() == command)
        .then_some(())
        .ok_or_else(|| format!("job `{job_name}` is missing release command `{command}`"))
}

/// Require both reviewed tag-push fragments in a publication job's condition.
///
/// Passes when the `if` condition of `job` contains the `github.event_name == 'push'` and `startsWith(github.ref, 'refs/tags/v')` fragments.
/// Other clauses, such as an added `|| true`, are not checked.
/// `job_name` names the job in errors. Returns an Err when `if` is absent, is not text, or lacks either fragment.
fn require_tag_only_publication(job: &Mapping, job_name: &str) -> Result<(), String> {
    // Missing or non-text conditions could let a candidate reach publication.
    let condition = required_field(job, "if", &format!("job `{job_name}`"))?
        .as_str()
        .ok_or_else(|| format!("job `{job_name}` condition must be text"))?;
    let checks_push = condition.contains("github.event_name == 'push'");
    let checks_tag = condition.contains("startsWith(github.ref, 'refs/tags/v')");
    (checks_push && checks_tag)
        .then_some(())
        .ok_or_else(|| format!("job `{job_name}` must require a matching tag-push event"))
}

/// Require the reviewed GitHub glob that reaches exact SemVer validation.
///
/// `triggers` is the workflow's `on` mapping, whose `push.tags` list must hold only the reviewed `v`-prefixed three-part version glob.
/// Returns an Err when `push` is absent or not a mapping, `tags` is absent or not a sequence, or the list is not that single glob.
fn require_release_tag_trigger(triggers: &Mapping) -> Result<(), String> {
    let push = required_mapping(
        required_field(triggers, "push", "workflow triggers")?,
        "push trigger",
    )?;
    // Missing, empty, or non-list tags mean a maintainer's vX.Y.Z push may never start.
    let tag_filters = required_field(push, "tags", "push trigger")?
        .as_sequence()
        .ok_or_else(|| "push trigger tags must be a sequence".to_string())?;
    // The source script applies exact SemVer after this valid GitHub glob matches.
    (tag_filters.len() == 1
        && tag_filters
            .first()
            .and_then(Value::as_str)
            .is_some_and(|tag_filter| tag_filter == "v[0-9]*.[0-9]*.[0-9]*"))
    .then_some(())
    .ok_or_else(|| "push trigger must use the reviewed release tag glob".to_string())
}

/// Require a candidate job to stay read-only and outside publication environments.
///
/// Passes when `job` has a `permissions` mapping whose only entry is `contents: read` and has no `environment` key.
/// Returns an Err naming `job_name` for a missing or non-mapping `permissions`, any other scope or access, or an `environment` key.
fn require_candidate_job_is_read_only(job: &Mapping, job_name: &str) -> Result<(), String> {
    let permissions = required_mapping(
        required_field(job, "permissions", &format!("job `{job_name}`"))?,
        &format!("job `{job_name}` permissions"),
    )?;
    // Missing contents access or any extra scope means candidate authority expanded.
    (permissions.len() == 1
        && permissions
            .get(yaml_key("contents"))
            .and_then(Value::as_str)
            .is_some_and(|access| access == "read"))
    .then_some(())
    .ok_or_else(|| format!("job `{job_name}` must have only read contents permission"))?;
    (!job.contains_key(yaml_key("environment")))
        .then_some(())
        .ok_or_else(|| format!("job `{job_name}` must not enter a publication environment"))
}

/// Require shared candidate jobs to remain free of publication secret references.
///
/// `candidate_jobs` holds the three candidate job mappings, which are serialized back to YAML and must not mention `secrets.` anywhere.
/// Returns an Err when serialization fails or any job's YAML contains `secrets.`.
fn require_candidate_jobs_have_no_secrets(candidate_jobs: [&Mapping; 3]) -> Result<(), String> {
    let shared_job_yaml = candidate_jobs
        .into_iter()
        .map(serde_yaml::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
        .join("\n");
    (!shared_job_yaml.contains("secrets."))
        .then_some(())
        .ok_or_else(|| {
            "candidate verification jobs must not receive publication secrets".to_string()
        })
}

/// Validate the read-only source, build, and asset path a candidate traverses.
///
/// `source_verify`, `build` and `asset_verify` are the named job mappings; each must grant only `contents: read` and have no `environment` key.
/// None of their serialized YAML may contain `secrets.`.
///
/// `source_verify` must contain `resolve-source`, `scripts/preflight-checks.sh` and `write-source-manifest` in its joined run text,
/// plus a trimmed run line equal to `cargo package --locked`.
///
/// `build` must need `source_verify` and contain `stage-archive` in its joined run text.
/// Its serialized YAML must contain `fromJSON(needs.source_verify.outputs.build_matrix)` and `if-no-files-found: error` anywhere.
/// `asset_verify` must need `source_verify` and `build` and contain `verify-assets` in its joined run text.
///
/// Returns the first failing check's Err.
fn validate_candidate_verification_jobs(
    source_verify: &Mapping,
    build: &Mapping,
    asset_verify: &Mapping,
) -> Result<(), String> {
    require_candidate_job_is_read_only(source_verify, "source_verify")?;
    require_candidate_job_is_read_only(build, "build")?;
    require_candidate_job_is_read_only(asset_verify, "asset_verify")?;

    require_run_stage(source_verify, "source_verify", "resolve-source")?;
    require_run_stage(
        source_verify,
        "source_verify",
        "scripts/preflight-checks.sh",
    )?;
    require_run_command(source_verify, "source_verify", "cargo package --locked")?;
    require_run_stage(source_verify, "source_verify", "write-source-manifest")?;

    require_job_need(build, "build", "source_verify")?;
    require_run_stage(build, "build", "stage-archive")?;
    let build_yaml = serde_yaml::to_string(build).map_err(|error| error.to_string())?;
    build_yaml
        .contains("fromJSON(needs.source_verify.outputs.build_matrix)")
        .then_some(())
        .ok_or_else(|| "build matrix must come from verified source outputs".to_string())?;
    build_yaml
        .contains("if-no-files-found: error")
        .then_some(())
        .ok_or_else(|| "build artifacts must fail when target files are missing".to_string())?;

    require_job_need(asset_verify, "asset_verify", "source_verify")?;
    require_job_need(asset_verify, "asset_verify", "build")?;
    require_run_stage(asset_verify, "asset_verify", "verify-assets")?;

    require_candidate_jobs_have_no_secrets([source_verify, build, asset_verify])
}

/// Validate the crate gate that runs after source and all assets are proven.
///
/// `publish_crate` is the crate publication job mapping, which must need `source_verify` and `asset_verify`.
/// Its `if` condition must contain both tag-push fragments, and its joined run text must contain `verify-package` and `cargo publish --locked`.
/// Returns the first failing check's Err.
fn validate_crate_publication_job(publish_crate: &Mapping) -> Result<(), String> {
    require_job_need(publish_crate, "publish_crate", "source_verify")?;
    require_job_need(publish_crate, "publish_crate", "asset_verify")?;
    require_tag_only_publication(publish_crate, "publish_crate")?;
    require_run_stage(publish_crate, "publish_crate", "verify-package")?;
    require_run_stage(publish_crate, "publish_crate", "cargo publish --locked")
}

/// Validate publication prerequisites, tag-push condition fragments, and the order of draft, upload, verify and publish markers.
///
/// `publish_github` is the GitHub release job mapping, which must need `source_verify`, `asset_verify` and `publish_crate`.
/// Its `if` condition must contain both tag-push fragments, and it must pass `require_fail_stop_draft_recovery`.
/// Its joined run text must contain `--draft` and `--verify-tag`.
///
/// The first occurrences of `gh release create`, `gh release upload`, `verify-draft` and `gh release edit` must all exist and appear in that order.
/// Returns the first failing check's Err.
fn validate_github_publication_job(publish_github: &Mapping) -> Result<(), String> {
    require_job_need(publish_github, "publish_github", "source_verify")?;
    require_job_need(publish_github, "publish_github", "asset_verify")?;
    require_job_need(publish_github, "publish_github", "publish_crate")?;
    require_tag_only_publication(publish_github, "publish_github")?;
    require_fail_stop_draft_recovery(publish_github)?;
    let github_release_script = job_run_script(publish_github)?;
    // Without draft creation, the first public state could be an incomplete release.
    let draft_position = github_release_script
        .find("gh release create")
        .ok_or_else(|| "GitHub publication must create a draft".to_string())?;
    // Without upload, users would see a release with none of its platform files.
    let upload_position = github_release_script
        .find("gh release upload")
        .ok_or_else(|| "GitHub publication must upload verified assets".to_string())?;
    // Without draft verification, a missing platform could reach release users.
    let verify_position = github_release_script
        .find("verify-draft")
        .ok_or_else(|| "GitHub publication must verify the complete draft".to_string())?;
    // Without the final edit, a verified draft would never become downloadable.
    let publish_position = github_release_script
        .find("gh release edit")
        .ok_or_else(|| "GitHub publication must publish the verified draft".to_string())?;
    github_release_script
        .contains("--draft")
        .then_some(())
        .ok_or_else(|| "GitHub release must be staged as a draft".to_string())?;
    github_release_script
        .contains("--verify-tag")
        .then_some(())
        .ok_or_else(|| "GitHub release must refuse to create a missing tag".to_string())?;
    (draft_position < upload_position
        && upload_position < verify_position
        && verify_position < publish_position)
        .then_some(())
        .ok_or_else(|| {
            "GitHub draft, upload, verify, and publish stages are out of order".to_string()
        })
}

/// Pin the fail-stop recovery policy for a rerun that meets an existing draft.
///
/// 0.5.0 deliberately has no reconciliation path. `gh release create` fails when a release already exists for the tag, and
/// `gh release upload` fails on an asset that is already attached, so a rerun stops rather than adopting remote state this run never verified.
///
/// That is the whole policy, and each assertion here blocks one way of quietly dissolving it: adding `--clobber` would overwrite assets
/// belonging to a draft built from a different commit; deleting an existing release would discard evidence an operator needs to investigate;
/// and probing for a release before creating one would let a rerun skip creation and upload into whatever draft happened to be there.
///
/// Real resumability is deferred, and building it means verifying an existing draft against the release manifest first,
/// not relaxing one of these guards.
///
/// `publish_github` is the GitHub release job mapping whose joined run text must contain neither `--clobber` nor `gh release delete`.
/// It must contain `gh release create`, and the first `gh release view`, if any, must come after the first `gh release create`.
/// Returns an Err for the first broken guard, or when the job's steps cannot be read.
fn require_fail_stop_draft_recovery(publish_github: &Mapping) -> Result<(), String> {
    let github_release_script = job_run_script(publish_github)?;
    (!github_release_script.contains("--clobber"))
        .then_some(())
        .ok_or_else(|| "GitHub publication must not clobber existing draft assets".to_string())?;
    (!github_release_script.contains("gh release delete"))
        .then_some(())
        .ok_or_else(|| "GitHub publication must not delete an existing release".to_string())?;
    let create_position = github_release_script
        .find("gh release create")
        .ok_or_else(|| "GitHub publication must create a draft".to_string())?;
    // Verification reads the draft back, so `gh release view` is expected. It must come after creation: seeing it first
    // would mean creation is gated on whether a release already exists.
    match github_release_script.find("gh release view") {
        Some(view_position) if view_position < create_position => {
            Err("GitHub draft creation must not be gated on an existing-release probe".to_string())
        }
        _ => Ok(()),
    }
}

/// Validate the candidate path and serialized crate-then-release publication path.
///
/// `workflow` is the parsed release workflow, whose `on` mapping must hold the reviewed push tag trigger and a `workflow_dispatch` key.
/// The `source_verify`, `build`, `asset_verify`, `publish_crate` and `publish_github` jobs must exist and pass their job validators.
/// Returns the first failing check's Err.
fn validate_release_workflow(workflow: &Value) -> Result<(), String> {
    let workflow_mapping = required_mapping(workflow, "workflow")?;
    let triggers = required_mapping(
        required_field(workflow_mapping, "on", "workflow")?,
        "workflow triggers",
    )?;
    require_release_tag_trigger(triggers)?;
    required_field(triggers, "workflow_dispatch", "workflow triggers")?;

    let source_verify = required_job(workflow, "source_verify")?;
    let build = required_job(workflow, "build")?;
    let asset_verify = required_job(workflow, "asset_verify")?;
    let publish_crate = required_job(workflow, "publish_crate")?;
    let publish_github = required_job(workflow, "publish_github")?;

    validate_candidate_verification_jobs(source_verify, build, asset_verify)?;
    validate_crate_publication_job(publish_crate)?;
    validate_github_publication_job(publish_github)
}

/// Replace one job's prerequisite list to model a bypass a future edit might introduce.
///
/// Overwrites the whole `needs` value of the `job_name` job in `workflow` with `prerequisites` as a YAML list of names.
/// An empty slice models a job users could run without any verification gate.
/// Panics when `workflow` has no `job_name` job mapping.
fn set_job_needs(workflow: &mut Value, job_name: &str, prerequisites: &[&str]) {
    let job = required_job_mut(workflow, job_name).expect("negative-test job exists");
    job.insert(
        yaml_key("needs"),
        Value::Sequence(
            prerequisites
                .iter()
                .map(|name| Value::String((*name).to_string()))
                .collect(),
        ),
    );
}

/// Set one text job field to model an unsafe maintainer-facing workflow edit.
///
/// Inserts `value` as a YAML string under the `field` key of the `job_name` job in `workflow`, overwriting any existing value.
/// Panics when `workflow` has no `job_name` job mapping.
fn set_job_text_field(workflow: &mut Value, job_name: &str, field: &str, value: &str) {
    let job = required_job_mut(workflow, job_name).expect("negative-test job exists");
    job.insert(yaml_key(field), Value::String(value.to_string()));
}

/// Rewrite controlled workflow YAML to prove the validator notices a removed or weakened gate.
///
/// Serializes `workflow` to YAML text and replaces the first occurrence of `original_text` with `replacement_text`; `workflow` is not changed.
/// Returns the edited text parsed as a new workflow value.
/// Panics when serialization fails, `original_text` is absent from the serialized text, or the edited text is not valid YAML.
fn replace_workflow_yaml_text(
    workflow: &Value,
    original_text: &str,
    replacement_text: &str,
) -> Value {
    let workflow_text = serde_yaml::to_string(workflow).expect("workflow serializes");
    assert!(
        workflow_text.contains(original_text),
        "negative mutation source `{original_text}` is present"
    );
    serde_yaml::from_str(&workflow_text.replacen(original_text, replacement_text, 1))
        .expect("negative workflow mutation parses")
}

/// Rewrite controlled job YAML so a negative test changes the intended graph edge.
///
/// Serializes the `job_name` job of `workflow` and replaces the first occurrence of `original_text` with `replacement_text`.
/// The reparsed mapping then replaces that job in `workflow`.
/// Panics when the job is missing or does not serialize, `original_text` is absent from its YAML, or the edited text is not a YAML mapping.
fn replace_job_yaml_text(
    workflow: &mut Value,
    job_name: &str,
    original_text: &str,
    replacement_text: &str,
) {
    let job = required_job_mut(workflow, job_name).expect("negative-test job exists");
    let job_text = serde_yaml::to_string(job).expect("negative-test job serializes");
    assert!(
        job_text.contains(original_text),
        "negative mutation source `{original_text}` is present in `{job_name}`"
    );
    let replacement_job: Value =
        serde_yaml::from_str(&job_text.replacen(original_text, replacement_text, 1))
            .expect("negative job parses");
    // A non-mapping replacement would no longer represent a runnable GitHub job.
    *job = replacement_job
        .as_mapping()
        .expect("negative job remains a mapping")
        .clone();
}

/// Prove one YAML text replacement makes validation fail with the expected operator-facing error.
///
/// Reads the live release workflow, replaces the first occurrence of `original_text` with `replacement_text`, and validates the result.
/// Panics when `validate_release_workflow` accepts the edit or returns an error that does not contain `expected_error`.
/// Also panics when the workflow cannot be read, `original_text` is absent, or the edited text does not parse.
fn assert_workflow_yaml_mutation_rejected(
    original_text: &str,
    replacement_text: &str,
    expected_error: &str,
) {
    let workflow =
        replace_workflow_yaml_text(&read_release_workflow(), original_text, replacement_text);
    let rejection_context = format!("removed release gate `{original_text}` is rejected");
    let error = validate_release_workflow(&workflow).expect_err(&rejection_context);
    assert!(
        error.contains(expected_error),
        "expected error containing `{expected_error}`, got `{error}`"
    );
}

/// Prove the checked-in candidate and publication graph carries every required gate.
#[test]
fn release_workflow_graph_is_closed_before_publication() {
    validate_release_workflow(&read_release_workflow()).expect("release workflow contract passes");
}

/// Prove a platform build cannot silently stop depending on source verification.
#[test]
fn release_workflow_rejects_build_source_bypass() {
    let mut workflow = read_release_workflow();
    // An empty prerequisite list models a build starting before source proof.
    set_job_needs(&mut workflow, "build", &[]);
    let error = validate_release_workflow(&workflow).expect_err("source bypass is rejected");
    assert!(error.contains("must need `source_verify`"));
}

/// Prove crate publication cannot run before all platform assets pass verification.
#[test]
fn release_workflow_rejects_crate_asset_bypass() {
    let mut workflow = read_release_workflow();
    set_job_needs(&mut workflow, "publish_crate", &["source_verify"]);
    let error = validate_release_workflow(&workflow).expect_err("asset bypass is rejected");
    assert!(error.contains("must need `asset_verify`"));
}

/// Prove candidate mode cannot reach a publication job through a weakened condition.
#[test]
fn release_workflow_rejects_candidate_publication() {
    let mut workflow = read_release_workflow();
    set_job_text_field(&mut workflow, "publish_github", "if", "${{ always() }}");
    let error =
        validate_release_workflow(&workflow).expect_err("candidate publication is rejected");
    assert!(error.contains("matching tag-push event"));
}

/// Prove candidate verification cannot gain write access to repository contents.
#[test]
fn release_workflow_rejects_candidate_write_permission() {
    let mut workflow = read_release_workflow();
    replace_job_yaml_text(
        &mut workflow,
        "source_verify",
        "contents: read",
        "contents: write",
    );
    let error =
        validate_release_workflow(&workflow).expect_err("candidate write access is rejected");
    assert!(error.contains("only read contents permission"));
}

/// Prove candidate verification cannot enter a protected publication environment.
#[test]
fn release_workflow_rejects_candidate_environment() {
    let mut workflow = read_release_workflow();
    set_job_text_field(&mut workflow, "asset_verify", "environment", "production");
    let error =
        validate_release_workflow(&workflow).expect_err("candidate environment is rejected");
    assert!(error.contains("must not enter a publication environment"));
}

/// Prove regex-style repetition cannot silently disable normal release tags.
#[test]
fn release_workflow_rejects_regex_style_tag_glob() {
    let workflow = replace_workflow_yaml_text(
        &read_release_workflow(),
        "v[0-9]*.[0-9]*.[0-9]*",
        "v[0-9]+.[0-9]+.[0-9]+",
    );
    let error = validate_release_workflow(&workflow).expect_err("invalid tag glob is rejected");
    assert!(error.contains("reviewed release tag glob"));
}

/// Prove every shared candidate gate remains load-bearing in the parsed graph.
#[test]
fn release_workflow_rejects_omitted_candidate_gates() {
    assert_workflow_yaml_mutation_rejected(
        "resolve-source",
        "source-resolution-disabled",
        "resolve-source",
    );
    assert_workflow_yaml_mutation_rejected(
        "scripts/preflight-checks.sh",
        "preflight-disabled",
        "scripts/preflight-checks.sh",
    );
    assert_workflow_yaml_mutation_rejected(
        "cargo package --locked",
        "cargo package --unlocked",
        "cargo package --locked",
    );
    assert_workflow_yaml_mutation_rejected(
        "write-source-manifest",
        "source-manifest-disabled",
        "write-source-manifest",
    );
    assert_workflow_yaml_mutation_rejected(
        "fromJSON(needs.source_verify.outputs.build_matrix)",
        "fromJSON('{}')",
        "build matrix must come from verified source outputs",
    );
    assert_workflow_yaml_mutation_rejected(
        "stage-archive",
        "archive-stage-disabled",
        "stage-archive",
    );
    assert_workflow_yaml_mutation_rejected(
        "verify-assets",
        "asset-verification-disabled",
        "verify-assets",
    );
}

/// Prove a release cannot become visible before its complete draft is verified.
#[test]
fn release_workflow_rejects_missing_draft_verification() {
    let workflow = replace_workflow_yaml_text(
        &read_release_workflow(),
        "verify-draft",
        "draft-verification-disabled",
    );
    let error =
        validate_release_workflow(&workflow).expect_err("missing draft verification is rejected");
    assert!(error.contains("verify the complete draft"));
}

/// Prove a rerun cannot overwrite assets on a draft this run never verified.
#[test]
fn release_workflow_rejects_clobbering_existing_draft_assets() {
    assert_workflow_yaml_mutation_rejected(
        "gh release upload",
        "gh release upload --clobber",
        "must not clobber existing draft assets",
    );
}

/// Prove recovery cannot discard the evidence an operator needs to investigate.
#[test]
fn release_workflow_rejects_deleting_an_existing_release() {
    assert_workflow_yaml_mutation_rejected(
        "gh release create",
        "gh release delete --yes \"v$RELEASE_VERSION\" || true\n          gh release create",
        "must not delete an existing release",
    );
}

/// Prove creation cannot be skipped by probing for a release that already exists.
#[test]
fn release_workflow_rejects_gating_draft_creation_on_an_existence_probe() {
    assert_workflow_yaml_mutation_rejected(
        "gh release create",
        "gh release view \"v$RELEASE_VERSION\" >/dev/null 2>&1 || gh release create",
        "must not be gated on an existing-release probe",
    );
}

/// Prove tag publication cannot skip creating the private draft staging area.
#[test]
fn release_workflow_rejects_missing_draft_staging() {
    let workflow = replace_workflow_yaml_text(
        &read_release_workflow(),
        "gh release create",
        "draft-creation-disabled",
    );
    let error =
        validate_release_workflow(&workflow).expect_err("missing draft staging is rejected");
    assert!(error.contains("create a draft"));
}

/// Prove the release cannot become visible before its assets are uploaded.
#[test]
fn release_workflow_rejects_publish_before_asset_upload() {
    let workflow_with_upload_placeholder = replace_workflow_yaml_text(
        &read_release_workflow(),
        "gh release upload",
        "release-upload-order-placeholder",
    );
    let workflow_with_early_publish = replace_workflow_yaml_text(
        &workflow_with_upload_placeholder,
        "gh release edit",
        "gh release upload",
    );
    let reordered_workflow = replace_workflow_yaml_text(
        &workflow_with_early_publish,
        "release-upload-order-placeholder",
        "gh release edit",
    );
    let error = validate_release_workflow(&reordered_workflow)
        .expect_err("publication before upload is rejected");
    assert!(error.contains("out of order"));
}

/// Prove a partial matrix cannot pass by silently ignoring a missing archive.
#[test]
fn release_workflow_rejects_ignored_missing_artifacts() {
    let mut workflow = read_release_workflow();
    replace_job_yaml_text(
        &mut workflow,
        "build",
        "if-no-files-found: error",
        "if-no-files-found: ignore",
    );
    let error = validate_release_workflow(&workflow).expect_err("ignored artifacts are rejected");
    assert!(error.contains("must fail when target files are missing"));
}
