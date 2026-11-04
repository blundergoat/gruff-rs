//! Deterministic rules for GitHub workflows and explicit composite actions.
//! Path shape plus source origin selects the understood metadata contract,
//! then structurally placed step rules and workflow-only rules feed the normal report.

use super::super::*;

#[path = "github_metadata_rules/event_guards.rs"]
mod event_guards;

/// Find direct event-context interpolation in understood GitHub shell steps.
///
/// `unit` supplies the file and its text; only a workflow path or an explicit composite-action file is scanned.
/// Each line of a step's `run` value that contains `github.event.` appends one high-confidence warning to `findings`.
pub(super) fn analyse_ci_github_event_shell_interpolation(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
) {
    // Other YAML and directory-discovered actions stay outside the GitHub metadata contract.
    let Some(metadata_kind) = github_metadata_kind(unit.file) else {
        return;
    };

    let mut state = RunBlockState::default();
    // Step tracking runs alongside the shell state so an input named `run` cannot open a step.
    let mut steps = GithubStepState::default();
    // Each source line can open, continue, or close the shell step a user configured.
    for (line_index, line) in unit.source.lines().enumerate() {
        let line_has_event_shell = state.line_has_event_shell_interpolation(line);
        steps.track_line(line, metadata_kind);
        // A match becomes one line-scoped finding in the normal report.
        if line_has_event_shell && steps.is_inside_step_item() {
            push_github_event_shell_finding(unit, findings, metadata_kind, line_index + 1);
        }
    }
}

/// Continuation state for event interpolation inside YAML `run` blocks.
/// Inline values are checked immediately; block scalars keep their indentation
/// until the next peer key closes the shell step the user supplied.
#[derive(Default)]
struct RunBlockState {
    in_run_block: bool,
    run_indent: usize,
}

impl RunBlockState {
    /// Check one line while preserving whether a block `run` value remains open.
    ///
    /// `line` is the raw source line; its indentation decides when an open block `run` value ends.
    /// Returns true when this line's `run:` value contains `github.event.`, or when an open block line contains it.
    fn line_has_event_shell_interpolation(&mut self, line: &str) -> bool {
        let trimmed = line.trim();
        self.close_completed_block(line_indent(line), trimmed);
        // A new `run:` key replaces any prior step state before its value is checked.
        if let Some(after_run) = workflow_run_value(trimmed) {
            return self.run_value_contains_event_shell_interpolation(line_indent(line), after_run);
        }

        self.in_run_block && trimmed.contains("github.event.")
    }

    /// Close a block when the next non-empty YAML key returns to its indentation.
    ///
    /// `indent` is the line's leading-space width and `trimmed` its trimmed text; a blank `trimmed` never closes the block.
    fn close_completed_block(&mut self, indent: usize, trimmed: &str) {
        // Blank lines remain part of a block; a peer key ends it for the CLI scan.
        if self.in_run_block && indent <= self.run_indent && !trimmed.is_empty() {
            self.in_run_block = false;
        }
    }

    /// Open the new run value and check its inline event expression, if present.
    ///
    /// `indent` is the `run:` line's indentation, kept as the block boundary, and `after_run` is the raw text after the key.
    /// An empty value or a block-scalar header leaves the block open for the following lines.
    /// Returns true when `after_run` contains `github.event.`.
    fn run_value_contains_event_shell_interpolation(
        &mut self,
        indent: usize,
        after_run: &str,
    ) -> bool {
        self.run_indent = indent;
        let value = after_run.trim();
        self.in_run_block = value.is_empty() || is_yaml_block_scalar(value);
        after_run.contains("github.event.")
    }
}

/// Emit event-interpolation guidance for the workflow or action the user scanned.
///
/// Appends one high-confidence `ci.github-event-shell-interpolation` warning to `findings` for the file in `unit` at 1-based `line`.
/// `metadata_kind` selects workflow or composite-action wording for the message.
fn push_github_event_shell_finding(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    metadata_kind: GithubMetadataKind,
    line: usize,
) {
    // Preserve established workflow wording while naming a composite action accurately.
    let message = if metadata_kind == GithubMetadataKind::Workflow {
        "GitHub event data is interpolated directly into a workflow shell step."
    } else {
        "GitHub event data is interpolated directly into a composite-action shell step."
    };
    findings.push(Finding::new(FindingDescriptor {
        rule_id: "ci.github-event-shell-interpolation".to_string(),
        message: message.to_string(),
        file_path: unit.file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: None,
        remediation: Some(
            "Pass event data through environment variables or validated script inputs before shell use."
                .to_string(),
        ),
        metadata: json!({}),
    }));
}

/// GitHub metadata kinds supported by the lightweight text-rule model.
/// Workflows are recognised by their repository path; composite actions are
/// recognised only when a user supplies an exact action metadata file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GithubMetadataKind {
    Workflow,
    Action,
}

/// Classify the GitHub metadata contract a supplied source file can satisfy.
///
/// `file` supplies the display path and whether the user named the file directly.
/// Returns `Workflow` for a `.github/workflows/` YAML path, `Action` for an explicit `action.yml` or `action.yaml`, else None.
/// None means the file gets ordinary text rules but no GitHub metadata rules.
fn github_metadata_kind(file: &SourceFile) -> Option<GithubMetadataKind> {
    // Workflow paths keep their existing rules whether reached by a walk or explicit input.
    if is_github_workflow(&file.display_path) {
        return Some(GithubMetadataKind::Workflow);
    }
    // Only an exact file argument opts a composite action into shared step rules.
    if file.origin == SourceOrigin::ExplicitFile && is_action_metadata_path(&file.display_path) {
        return Some(GithubMetadataKind::Action);
    }
    // No kind means this source file receives ordinary text rules but no GitHub metadata rules.
    None
}

/// Recognise the two exact composite-action basenames accepted by GitHub.
///
/// `path` is the display path; only its final component after either path separator is compared, and the file is never opened.
/// Returns true when that basename is exactly `action.yml` or `action.yaml`.
fn is_action_metadata_path(path: &str) -> bool {
    // Both platform separators are lexical here; classification never opens the user path.
    let basename = path.rsplit(['/', '\\']).next().unwrap_or(path);
    matches!(basename, "action.yml" | "action.yaml")
}

/// Recognise root `.github/workflows/` YAML paths without recursively widening discovery.
///
/// `path` is the display path, with backslashes read as forward slashes before the checks.
/// Returns true when it starts with `.github/workflows/` and ends in `.yml` or `.yaml`; a file in a subdirectory below it also matches.
fn is_github_workflow(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.starts_with(".github/workflows/")
        && (normalized.ends_with(".yml") || normalized.ends_with(".yaml"))
}

/// Return the leading-space width used to bound a YAML block.
///
/// Returns the byte length of the leading whitespace in `line`, so tabs count as well as spaces.
fn line_indent(line: &str) -> usize {
    line.len().saturating_sub(line.trim_start().len())
}

/// Return a `run:` value from plain or list-item step syntax, or no value for other keys.
///
/// `trimmed` is one trimmed source line, optionally a `- ` list item.
/// Returns the raw text after the first colon, or None when the line has no colon or its key is not `run`.
fn workflow_run_value(trimmed: &str) -> Option<&str> {
    step_property_value(trimmed, "run")
}

/// Return the value of one step property written in plain or list-item syntax. GitHub accepts
/// quoted keys (`- "run": ...`), so the key is normalised before it is compared. The remainder is
/// returned unchanged because block-scalar headers and shell text are inspected as written.
///
/// `trimmed` is one trimmed source line and `key` the unquoted property name to match.
/// Returns None when the line has no colon or its normalised key differs from `key`.
fn step_property_value<'a>(trimmed: &'a str, key: &str) -> Option<&'a str> {
    let property = trimmed.strip_prefix("- ").unwrap_or(trimmed);
    let (property_key, value) = property.split_once(':')?;
    (normalize_yaml_key(property_key) == key).then_some(value)
}

/// Recognise YAML block-scalar markers whose following lines belong to `run`.
/// A header may carry an explicit indentation digit and a chomping indicator in either
/// order (`|2`, `>-`, `|2-`, `|-2`), and YAML also allows a trailing comment after it.
/// All of those keep the following lines in the block.
///
/// `value` is the trimmed text after a `run:` key.
/// Returns true when `value`, minus any comment, is `|` or `>` followed by at most one digit 1-9 and one `-` or `+`, else false.
fn is_yaml_block_scalar(value: &str) -> bool {
    // A comment after the header describes the step; it does not end the block.
    let header = strip_inline_comment(value).trim_end();
    // Only the literal and folded markers open a block whose later lines are shell text.
    let Some(indicators) = header.strip_prefix(['|', '>']) else {
        return false;
    };
    let mut seen_indentation = false;
    let mut seen_chomping = false;
    for indicator in indicators.chars() {
        match indicator {
            // YAML forbids a zero indentation indicator, so digits start at one.
            '1'..='9' if !seen_indentation => seen_indentation = true,
            '-' | '+' if !seen_chomping => seen_chomping = true,
            // Any other trailing text means the value is a command, not a block header.
            _ => return false,
        }
    }
    true
}

/// Run the GitHub rules applicable to this workflow or explicit action file.
///
/// `unit` supplies the file and its text; files that are neither a workflow nor an explicit composite action are skipped.
/// Step findings are appended to `findings` line by line, and a workflow then gets its trigger and secret findings.
pub(super) fn analyse_github_actions_rules(unit: &SourceUnit<'_>, findings: &mut Vec<Finding>) {
    // Ordinary YAML and directory-discovered actions receive no GitHub metadata rules.
    let Some(metadata_kind) = github_metadata_kind(unit.file) else {
        return;
    };
    let mut scan_state = GithubMetadataScanState {
        workflow_permissions: WorkflowPermissionsState {
            single_concrete_job: metadata_kind == GithubMetadataKind::Workflow
                && workflow_has_one_concrete_job(unit.source),
            ..Default::default()
        },
        ..Default::default()
    };

    // Shared step syntax is inspected line by line while workflow state stays separately gated.
    for (line_index, line) in unit.source.lines().enumerate() {
        analyse_github_actions_line(
            unit,
            findings,
            metadata_kind,
            &mut scan_state,
            line_index + 1,
            line,
        );
    }

    // Composite actions have no trigger or pull-request secret contract to summarize.
    if metadata_kind == GithubMetadataKind::Workflow {
        push_github_actions_summary_findings(unit, findings, scan_state.workflow_summary);
    }
}

/// A scoped workflow grant reaches no wider than one concrete, non-matrix job.
/// Reusable workflows, unknown YAML and expanded jobs retain the conservative warning.
///
/// `source` is the whole workflow text, parsed as YAML.
/// Returns true only when `jobs` holds exactly one job whose name is a non-empty string other than the `<<` merge key.
/// That job needs a `steps` sequence and no `uses` or `strategy` key; unparsable YAML or a missing `jobs` mapping gives false.
fn workflow_has_one_concrete_job(source: &str) -> bool {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(source) else {
        return false;
    };
    let Some(jobs) = value.get("jobs").and_then(serde_yaml::Value::as_mapping) else {
        return false;
    };
    jobs.len() == 1
        && jobs.iter().all(|(name, job)| {
            name.as_str()
                .is_some_and(|name| !name.is_empty() && name != "<<")
                && job.get("steps").is_some_and(serde_yaml::Value::is_sequence)
                && job.get("uses").is_none()
                && job.get("strategy").is_none()
        })
}

/// Mutable state shared while one GitHub metadata file is scanned.
/// Step tracking applies to workflows and actions; permission and event state
/// is populated only for workflows before findings enter the user report.
#[derive(Default)]
struct GithubMetadataScanState {
    run: WorkflowRunState,
    steps: GithubStepState,
    workflow_permissions: WorkflowPermissionsState,
    workflow_summary: WorkflowSecuritySummary,
}

/// Workflow trigger and secret evidence accumulated across one YAML file.
/// Optional lines mean the corresponding event was absent; secret lines matter
/// only after a pull-request event makes that context reachable to user code.
#[derive(Default)]
struct WorkflowSecuritySummary {
    triggers: WorkflowTriggerState,
    pull_request_target_line: Option<usize>,
    secret_lines: Vec<usize>,
}

impl WorkflowSecuritySummary {
    /// Observe workflow events and secret references on one line.
    ///
    /// `line` is the raw line, whose indentation places entries in the `on:` mapping, and `trimmed` is its trimmed text.
    /// `line_number` becomes the first `pull_request_target` line and joins the secret lines when a repository secret is referenced.
    fn observe_line(&mut self, line: &str, trimmed: &str, line_number: usize) {
        // Target events take precedence because they also satisfy pull-request gating.
        match self.triggers.event_on_line(line, trimmed) {
            Some(WorkflowEvent::PullRequestTarget) => {
                self.pull_request_target_line.get_or_insert(line_number);
            }
            // A plain pull_request run gets no secrets from a fork, so it exposes none to untrusted code.
            Some(WorkflowEvent::PullRequest) | None => {}
        }
        // Secret lines are retained until the completed workflow trigger is known.
        if line_has_secret_expression(trimmed) {
            self.secret_lines.push(line_number);
        }
    }
}

/// Inspect one metadata line and route shared or workflow-only security checks.
///
/// `line` is the raw source line at 1-based `line_number`, and `metadata_kind` gates the workflow-only permission and trigger checks.
/// `scan_state` carries step, run-block, permission and trigger state between lines and is updated for this line.
/// Unpinned-action, broad-permission and remote-shell findings for the file in `unit` are appended to `findings`.
fn analyse_github_actions_line(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    metadata_kind: GithubMetadataKind,
    scan_state: &mut GithubMetadataScanState,
    line_number: usize,
    line: &str,
) {
    let trimmed = line.trim();
    // Only a `uses:` property attached directly to a real step names an action dependency.
    if let Some(action) = scan_state.steps.action_dependency(line, metadata_kind) {
        maybe_push_unpinned_action(unit, findings, metadata_kind, line_number, action);
    }
    // Composite action metadata has no workflow-level permissions contract. A `permissions:`
    // key inside a step is an action input, not a grant, so step placement disqualifies it.
    let line_grants_broad_permission = scan_state
        .workflow_permissions
        .line_allows_broad_permission(line);
    if metadata_kind == GithubMetadataKind::Workflow
        && line_grants_broad_permission
        && !scan_state.steps.is_inside_step_item()
    {
        push_workflow_finding(
            unit,
            findings,
            "security.github-actions-broad-permissions",
            "Workflow grants broad write permissions.",
            line_number,
            json!({}),
        );
    }
    // Both metadata kinds can place remote-download commands in shell steps. The state machine
    // still sees every line so block scalars stay tracked, but only a real step can report.
    let line_has_remote_shell = scan_state.run.line_has_remote_shell(line);
    if line_has_remote_shell && scan_state.steps.is_inside_step_item() {
        push_remote_shell_finding(unit, findings, metadata_kind, line_number);
    }
    // Event and secret summary state exists only for workflow triggers.
    if metadata_kind == GithubMetadataKind::Workflow {
        scan_state
            .workflow_summary
            .observe_line(line, trimmed, line_number);
    }
}

/// Emit the shared remote-download finding for the metadata file under review.
///
/// Appends one `security.github-actions-remote-shell` warning to `findings` for the file in `unit` at 1-based `line`.
/// `metadata_kind` selects workflow or composite-action wording.
fn push_remote_shell_finding(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    metadata_kind: GithubMetadataKind,
    line: usize,
) {
    push_shared_github_metadata_finding(
        unit,
        findings,
        metadata_kind,
        GithubStepFinding {
            rule_id: "security.github-actions-remote-shell",
            workflow_message: "Workflow downloads remote content directly into a shell.",
            action_message: "Composite action downloads remote content directly into a shell.",
            line,
            metadata: json!({}),
        },
    );
}

/// Emit trigger and secret findings that require a completed workflow view.
///
/// `summary` holds the trigger and secret evidence from every line of the workflow in `unit`; findings are appended to `findings`.
/// A `pull_request_target` trigger adds one finding at its line, plus one secrets-in-PR finding per secret line.
/// Secret lines that `event_guards::unreachable_secret_lines` reports as unreachable are skipped.
fn push_github_actions_summary_findings(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    summary: WorkflowSecuritySummary,
) {
    // A target trigger always requires a manual checkout and secret review.
    if let Some(line) = summary.pull_request_target_line {
        push_workflow_finding(
            unit,
            findings,
            "security.github-actions-pull-request-target",
            "Workflow uses pull_request_target; review checked-out code and secret exposure.",
            line,
            json!({ "event": "pull_request_target" }),
        );
    }
    // Secrets are exposed only when pull_request_target runs pull-request code with the repository's secrets.
    if summary.pull_request_target_line.is_some() {
        let unreachable = event_guards::unreachable_secret_lines(unit.source);
        // Each referenced secret keeps its own source line for human review.
        for line in summary.secret_lines {
            if unreachable.contains(&line) {
                continue;
            }
            push_workflow_finding(
                unit,
                findings,
                "security.github-actions-secrets-in-pr",
                "pull_request_target workflow references a repository secret.",
                line,
                json!({}),
            );
        }
    }
}

/// Continuation state for remote-download patterns inside YAML `run` blocks.
/// Inline values are checked immediately; block scalars remain active until a
/// peer key closes the command supplied by the workflow or action author.
#[derive(Default)]
struct WorkflowRunState {
    in_run_block: bool,
    run_indent: usize,
    /// Shell text carried forward when a block line leaves a pipeline unfinished.
    pending_pipeline: Option<String>,
}

impl WorkflowRunState {
    /// Check one shell line while preserving whether a block command remains open.
    ///
    /// `line` is the raw source line; its indentation decides when an open block ends.
    /// A block line ending in an unfinished pipe or a backslash is joined with the next block line before matching.
    /// Returns true when the `run:` value or joined block text matches the download-to-shell patterns of `is_remote_download_piped_to_shell`.
    fn line_has_remote_shell(&mut self, line: &str) -> bool {
        let trimmed = line.trim();
        self.close_completed_block(line_indent(line), trimmed);
        // A new `run:` key resets continuation state before its command is checked.
        if let Some(after_run) = workflow_run_value(trimmed) {
            self.run_indent = line_indent(line);
            let value = after_run.trim();
            self.in_run_block = value.is_empty() || is_yaml_block_scalar(value);
            self.pending_pipeline = None;
            return is_remote_download_piped_to_shell(after_run);
        }
        if !self.in_run_block {
            return false;
        }
        // A downloader and its shell can sit on separate block lines, so an
        // unfinished pipeline carries forward and is matched against the join.
        let joined = match self.pending_pipeline.take() {
            Some(previous) => format!("{previous} {trimmed}"),
            None => trimmed.to_string(),
        };
        if is_unfinished_shell_pipeline(trimmed) {
            self.pending_pipeline = Some(joined.clone());
        }
        is_remote_download_piped_to_shell(&joined)
    }

    /// Close a block when the next non-empty YAML key returns to its indentation.
    ///
    /// `indent` is the line's leading-space width and `trimmed` its trimmed text; closing also drops any pending pipeline text.
    fn close_completed_block(&mut self, indent: usize, trimmed: &str) {
        // Blank lines do not end a shell block visible to the metadata scan.
        if self.in_run_block && indent <= self.run_indent && !trimmed.is_empty() {
            self.in_run_block = false;
            self.pending_pipeline = None;
        }
    }
}

/// Reports whether a shell line leaves a pipeline open for the following line.
/// A trailing `||` is a logical fallback rather than a pipe, so it ends the join.
///
/// `trimmed` is the trimmed block line; text from its first `#` on is ignored, even inside quotes.
/// Returns true when the remaining text ends in `|` but not `||`, or ends in a backslash continuation.
fn is_unfinished_shell_pipeline(trimmed: &str) -> bool {
    let command_text = trimmed.split('#').next().unwrap_or(trimmed).trim_end();
    command_text.ends_with('\\') || (command_text.ends_with('|') && !command_text.ends_with("||"))
}

/// Return a normalized `uses:` value from plain or list-item property syntax.
///
/// `trimmed` is one trimmed source line; quotes, outer whitespace and a trailing comment are removed from the value.
/// Returns None when the line has no colon or its key is not `uses`.
fn github_step_uses_value(trimmed: &str) -> Option<&str> {
    Some(normalize_yaml_scalar(step_property_value(trimmed, "uses")?))
}

/// One open `steps:` sequence and the indentation of its direct list items.
#[derive(Clone, Copy, Debug)]
struct OpenGithubSteps {
    steps_indent: usize,
    item_indent: Option<usize>,
}

/// One YAML mapping key that can establish a supported GitHub metadata path.
#[derive(Debug)]
struct GithubMappingScope {
    indent: usize,
    key: String,
}

/// Locate action dependencies without treating arbitrary YAML keys named `uses` as steps.
#[derive(Default)]
struct GithubStepState {
    mapping_scopes: Vec<GithubMappingScope>,
    open_steps: Option<OpenGithubSteps>,
}

impl GithubStepState {
    /// Return the action dependency attached directly to a step on this line.
    ///
    /// `line` is the raw source line; its indentation updates the tracked mappings and `steps:` sequence for later lines.
    /// `metadata_kind` decides which `steps:` parents count and whether a workflow job's own `uses:` names a reusable workflow.
    /// Returns the normalised `uses:` value, or None for blank, comment and other non-dependency lines.
    fn action_dependency<'a>(
        &mut self,
        line: &'a str,
        metadata_kind: GithubMetadataKind,
    ) -> Option<&'a str> {
        let trimmed = line.trim();
        // Empty and comment-only lines preserve the surrounding YAML path.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }
        let indent = line_indent(line);
        let step_dependency = self.dependency_in_open_steps(indent, trimmed);
        self.close_mapping_scopes(indent);
        // A job can call a reusable workflow instead of running steps, and that reference
        // moves exactly like an action reference, so it needs the same pinning review.
        let dependency =
            step_dependency.or_else(|| self.reusable_workflow_dependency(trimmed, metadata_kind));
        self.open_mapping_scope(indent, trimmed, metadata_kind);
        dependency
    }

    /// Advance the YAML path for one line when only the position, not a dependency, is needed.
    /// The event-interpolation scan uses this to reach the same step awareness as `uses:`.
    ///
    /// `line` and `metadata_kind` are passed to `action_dependency`, and its result is discarded.
    fn track_line(&mut self, line: &str, metadata_kind: GithubMetadataKind) {
        let _ = self.action_dependency(line, metadata_kind);
    }

    /// Whether the line just tracked sits inside a real step list item.
    /// Shell keys carry step semantics only here: a top-level input named `run` is metadata, so its
    /// `description` and `default` text must not be parsed as a command the user would execute.
    fn is_inside_step_item(&self) -> bool {
        self.open_steps
            .is_some_and(|open_steps| open_steps.item_indent.is_some())
    }

    /// Check direct list-item and continuation properties inside the current `steps:` sequence.
    ///
    /// `indent` is the line's indentation and `trimmed` its text; a non-item line at or left of `steps:` closes the sequence.
    /// The first list item at or right of the `steps:` column fixes the item indentation for later steps.
    /// Returns the `uses:` value of a list item at that indentation or of a property two columns deeper, else None.
    fn dependency_in_open_steps<'a>(&mut self, indent: usize, trimmed: &'a str) -> Option<&'a str> {
        let mut open_steps = self.open_steps?;
        let is_list_item = trimmed.starts_with("- ");
        // A peer mapping closes `steps`; an indentationless list item at the same level remains valid.
        if indent <= open_steps.steps_indent && !is_list_item {
            self.open_steps = None;
            return None;
        }
        // The first list item fixes the direct sequence indentation for all following steps.
        if open_steps.item_indent.is_none() && is_list_item && indent >= open_steps.steps_indent {
            open_steps.item_indent = Some(indent);
            self.open_steps = Some(open_steps);
        }
        let item_indent = open_steps.item_indent?;
        if is_list_item {
            return (indent == item_indent)
                .then(|| github_step_uses_value(trimmed))
                .flatten();
        }
        // A continuation property begins two columns after `- `; deeper keys belong to `with`,
        // `env`, or another nested mapping and cannot name the step dependency.
        (indent == item_indent + 2)
            .then(|| github_step_uses_value(trimmed))
            .flatten()
    }

    /// Close every mapping whose key ended before this line's indentation.
    ///
    /// `indent` is the current line's indentation; scopes opened at that column or deeper are popped.
    fn close_mapping_scopes(&mut self, indent: usize) {
        // Returning to a peer key closes that key's mapping before the new line is classified.
        while self
            .mapping_scopes
            .last()
            .is_some_and(|scope| scope.indent >= indent)
        {
            self.mapping_scopes.pop();
        }
    }

    /// Return a reusable workflow this job calls directly, which pins like an action reference.
    ///
    /// `trimmed` is the current trimmed line, and `metadata_kind` must be `Workflow` for any reference to count.
    /// Returns the normalised `uses:` value only when the line is a direct property of one job, else None.
    fn reusable_workflow_dependency<'a>(
        &self,
        trimmed: &'a str,
        metadata_kind: GithubMetadataKind,
    ) -> Option<&'a str> {
        // Only a workflow job calls another workflow, and only as its own direct property.
        if metadata_kind != GithubMetadataKind::Workflow || !self.is_inside_job_mapping() {
            return None;
        }
        github_step_uses_value(trimmed)
    }

    /// Whether the current YAML path is a direct property of one workflow job.
    ///
    /// Returns true when exactly two mapping scopes are open and the outer one is `jobs`.
    fn is_inside_job_mapping(&self) -> bool {
        self.mapping_scopes.len() == 2 && self.mapping_scopes[0].key == "jobs"
    }

    /// Maintain the mapping ancestors needed to recognise workflow and action `steps:` blocks.
    ///
    /// `trimmed` is pushed as a scope at `indent` only when it is a plain mapping key with an empty value.
    /// An empty `steps:` key under the parent that `metadata_kind` requires also opens a steps sequence at `indent`.
    fn open_mapping_scope(
        &mut self,
        indent: usize,
        trimmed: &str,
        metadata_kind: GithubMetadataKind,
    ) {
        let Some((key, value)) = yaml_mapping_entry(trimmed) else {
            return;
        };
        let normalized_value = normalize_yaml_scalar(value);
        if key == "steps"
            && normalized_value.is_empty()
            && self.has_supported_steps_parent(metadata_kind)
        {
            self.open_steps = Some(OpenGithubSteps {
                steps_indent: indent,
                item_indent: None,
            });
        }
        // Only an empty mapping value can contain later indented child keys.
        if normalized_value.is_empty() {
            self.mapping_scopes.push(GithubMappingScope {
                indent,
                key: key.to_string(),
            });
        }
    }

    /// Check the exact metadata path GitHub assigns step semantics.
    ///
    /// `metadata_kind` selects the path: `runs` alone for a composite action, or a direct property of one job for a workflow.
    /// Returns true when the open mapping scopes match that path.
    fn has_supported_steps_parent(&self, metadata_kind: GithubMetadataKind) -> bool {
        match metadata_kind {
            GithubMetadataKind::Action => {
                self.mapping_scopes.len() == 1 && self.mapping_scopes[0].key == "runs"
            }
            GithubMetadataKind::Workflow => self.is_inside_job_mapping(),
        }
    }
}

/// Split one plain YAML mapping entry; sequence items are handled by step state instead.
///
/// `trimmed` is one trimmed source line, split at its first colon.
/// Returns the normalised key and the raw value text, or None for a `- ` list item, a line without a colon, or an empty key.
fn yaml_mapping_entry(trimmed: &str) -> Option<(&str, &str)> {
    if trimmed.starts_with("- ") {
        return None;
    }
    let (key, value) = trimmed.split_once(':')?;
    let normalized_key = normalize_yaml_key(key);
    (!normalized_key.is_empty()).then_some((normalized_key, value))
}

/// Strip a YAML key's surrounding whitespace and matching quotes so `on`, `"on"`, and `'on'` —
/// all valid spellings of the same key, and commonly quoted because YAML 1.1 reads bare `on`
/// as a boolean — normalise to one token.
///
/// Returns `key` trimmed, then with any leading or trailing double and single quote characters removed, paired or not.
fn normalize_yaml_key(key: &str) -> &str {
    key.trim().trim_matches('"').trim_matches('\'')
}

/// Strip a trailing YAML inline comment (` #...`). YAML requires whitespace before
/// `#` to start a comment, so a `#` embedded in the value itself is preserved.
///
/// Returns `value` cut before the first `#` that follows a space, or all of `value` when there is none.
fn strip_inline_comment(value: &str) -> &str {
    match value.find(" #") {
        // YAML whitespace starts a comment that is not part of the action reference.
        Some(index) => &value[..index],
        // Without that delimiter, the complete value belongs to the user's reference.
        None => value,
    }
}

/// Report a third-party step dependency unless its ref is an immutable full SHA.
///
/// `action` is the normalised `uses:` value at 1-based `line`; local `./` paths and `actions/` or `github/` owners are skipped.
/// A `docker://` image is reported unless it names a sha256 digest, and any finding for the file in `unit` goes to `findings`.
/// Refs on names containing `/` need a 40-hex commit SHA, and `metadata_kind` selects workflow or composite-action wording.
fn maybe_push_unpinned_action(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    metadata_kind: GithubMetadataKind,
    line: usize,
    action: &str,
) {
    // A local action ships in the repository users already review.
    if action.starts_with("./") {
        return;
    }
    // A container image is immutable only when it names a digest: a tag such as
    // `docker://alpine:latest` still executes whatever the registry serves next.
    if let Some(image) = action.strip_prefix("docker://") {
        if !is_digest_pinned_image(image) {
            push_unpinned_image(unit, findings, metadata_kind, line, action);
        }
        return;
    }
    // GitHub's own `actions/*` and `github/*` actions are first-party, not the third-party dependency this rule
    // reports; gruff-ts exempts the same two owners.
    let owner = action.split(['/', '@']).next().unwrap_or_default();
    if owner == "actions" || owner == "github" {
        return;
    }
    // A third-party action without any ref is unpinned for either metadata kind.
    let Some((name, reference)) = action.rsplit_once('@') else {
        push_unpinned_action(unit, findings, metadata_kind, line, action, None);
        return;
    };
    // Third-party repository refs must use the complete commit identity users reviewed.
    if name.contains('/') && !is_full_sha_reference(reference) {
        push_unpinned_action(unit, findings, metadata_kind, line, name, Some(reference));
    }
}

/// Whether a dependency ref is exactly one immutable 40-hex commit identity.
///
/// Returns true when `reference` is exactly 40 ASCII hex digits in either case.
fn is_full_sha_reference(reference: &str) -> bool {
    // Every character must be hexadecimal after the exact-length check succeeds.
    reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether a container reference names an immutable digest rather than a moving tag.
///
/// `image` is the reference with its `docker://` prefix removed.
/// Returns true when the text after its last `@sha256:` is exactly 64 ASCII hex digits, and false when that marker is absent.
fn is_digest_pinned_image(image: &str) -> bool {
    let Some((_, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    // A sha256 digest is exactly 64 hexadecimal characters.
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Report a container image whose tag can change under the workflow that runs it.
///
/// Appends one `security.github-actions-unpinned-action` warning to `findings` for the file in `unit` at 1-based `line`.
/// `action` is the full `docker://` reference stored in the metadata with a null reference, and `metadata_kind` selects the wording.
fn push_unpinned_image(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    metadata_kind: GithubMetadataKind,
    line: usize,
    action: &str,
) {
    push_shared_github_metadata_finding(
        unit,
        findings,
        metadata_kind,
        GithubStepFinding {
            rule_id: "security.github-actions-unpinned-action",
            workflow_message: "Workflow container image is not pinned to a digest.",
            action_message: "Composite action container image is not pinned to a digest.",
            line,
            metadata: json!({ "action": action, "reference": null }),
        },
    );
}

/// Emit pinning guidance with wording accurate for the supplied metadata kind.
///
/// Appends one `security.github-actions-unpinned-action` warning to `findings` for the file in `unit` at 1-based `line`.
/// `action` is the dependency name and `reference` its ref after `@`, or None when there is none; both are stored in the metadata.
/// `metadata_kind` selects workflow or composite-action wording.
fn push_unpinned_action(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    metadata_kind: GithubMetadataKind,
    line: usize,
    action: &str,
    reference: Option<&str>,
) {
    push_shared_github_metadata_finding(
        unit,
        findings,
        metadata_kind,
        GithubStepFinding {
            rule_id: "security.github-actions-unpinned-action",
            workflow_message: "Workflow action is not pinned to a full commit SHA.",
            action_message: "Composite action dependency is not pinned to a full commit SHA.",
            line,
            metadata: json!({ "action": action, "reference": reference }),
        },
    );
}

/// State for one workflow `permissions:` mapping while lines are streamed.
/// Workflow-level scoped writes are broad unless confined to one concrete job.
/// Job mappings stay bounded; `write-all` remains broad at any indentation.
#[derive(Default)]
struct WorkflowPermissionsState {
    single_concrete_job: bool,
    in_permissions_block: bool,
    permissions_indent: usize,
}

impl WorkflowPermissionsState {
    /// Whether `line` allows a broad write permission. Inline `permissions: write-all`
    /// always counts; scoped writes count only in a workflow-level mapping so a
    /// required job grant and similarly named step input stay silent.
    ///
    /// Returns true for an inline `write-all` value, or for a known scope set to `write` inside an indent-0 `permissions:` mapping.
    /// The scoped case stays false when the workflow has exactly one concrete job.
    /// A `permissions:` line, or a non-empty line at or left of the open mapping's indentation, updates the tracked mapping.
    fn line_allows_broad_permission(&mut self, line: &str) -> bool {
        let trimmed = line.trim();
        let indent = line_indent(line);
        // A peer non-empty key closes the prior permissions mapping.
        if self.in_permissions_block && !trimmed.is_empty() && indent <= self.permissions_indent {
            self.in_permissions_block = false;
        }
        // A permissions key either opens a mapping or carries an inline scalar.
        if let Some(value) = permissions_mapping_value(trimmed) {
            // An absent scalar opens the following indented mapping for later lines.
            if value.is_empty() {
                self.in_permissions_block = true;
                self.permissions_indent = indent;
                return false;
            }
            // Inline scalar such as `permissions: write-all`.
            self.in_permissions_block = false;
            return value == "write-all";
        }
        self.in_permissions_block
            && !self.single_concrete_job
            && self.permissions_indent == 0
            && line_is_write_permission(trimmed)
    }
}

/// The scalar after a `permissions:` key (quotes and inline comment
/// stripped), or `None` when the line is not a `permissions:` key.
///
/// `trimmed` must start with `permissions:` exactly, so list-item or quoted keys do not match.
/// Returns the normalised scalar, which is empty when the key opens a nested mapping.
fn permissions_mapping_value(trimmed: &str) -> Option<&str> {
    Some(normalize_yaml_scalar(trimmed.strip_prefix("permissions:")?))
}

/// Strip a YAML scalar's trailing inline comment, surrounding whitespace, and
/// matching quotes, so `write`, `"write"`, `'write'`, and `write  # note` all
/// normalise to the same token.
///
/// Returns `value` cut at its first space-then-`#` comment, trimmed, then stripped of leading and trailing double and single quotes.
fn normalize_yaml_scalar(value: &str) -> &str {
    strip_inline_comment(value)
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
}

/// Whether a line inside a `permissions:` mapping grants write to a known scope,
/// e.g. `contents: write`. The value is normalised first, so quoted
/// (`contents: "write"`) and commented (`contents: write  # release`) forms —
/// all valid YAML granting the same access — are detected too.
///
/// `trimmed` is one trimmed line from the mapping, split at its first colon.
/// Returns true when the key is a known permission scope and the normalised value is `write`, and false for a line without a colon.
fn line_is_write_permission(trimmed: &str) -> bool {
    // A line without a YAML key/value separator cannot grant a named scope.
    let Some((scope, value)) = trimmed.split_once(':') else {
        return false;
    };
    is_known_permission_scope(scope.trim()) && normalize_yaml_scalar(value) == "write"
}

/// Recognise GitHub permission scopes whose workflow-level write access is broad.
///
/// `scope` is the trimmed key from a `permissions:` mapping line.
/// Returns true for a recognised broad-write permission scope, such as `contents` or `pull-requests`, and false for any other name.
fn is_known_permission_scope(scope: &str) -> bool {
    matches!(
        scope,
        "actions"
            | "checks"
            | "contents"
            | "deployments"
            | "discussions"
            | "issues"
            | "packages"
            | "pages"
            | "pull-requests"
            | "repository-projects"
            | "security-events"
            | "statuses"
    )
}

/// Detect a downloaded payload reaching a shell interpreter. A shell joined by a pipe counts without any check of its arguments
/// or of the downloader's output options.
///
/// A sequential `;` or `||` counts only when the interpreter gets no non-option argument or its first non-option argument appears
/// as text in the download segment, so running a checked-in script after an unrelated request stays silent instead of instructing
/// users to rewrite a safe step.
///
/// `value` is one shell command line, or several block lines joined by spaces.
/// Returns true when `sh`, `bash`, `dash` or `zsh`, directly or via `sudo`, follows a segment naming `curl` or `wget` under those rules.
/// An unrelated sequential command in between ends the download's reach.
fn is_remote_download_piped_to_shell(value: &str) -> bool {
    // The downloader's own segment names the file any later command could execute.
    let mut download_segment: Option<&str> = None;
    for (connector, segment) in shell_command_segments(value) {
        match (
            connector,
            download_segment,
            shell_invocation_arguments(segment),
        ) {
            // A pipeline stage hands the payload straight to the interpreter that reads it.
            (ShellConnector::Pipe, Some(_), Some(_)) => return true,
            // A sequential command receives the payload only by naming the downloaded path.
            (ShellConnector::Sequential, Some(download), Some(arguments))
                if shell_input_is_downloaded_payload(arguments, download) =>
            {
                return true;
            }
            _ => {}
        }
        if segment_has_remote_download(segment) {
            download_segment = Some(segment);
        } else if connector == ShellConnector::Sequential {
            // An unrelated sequential command ends the previous payload's reach.
            download_segment = None;
        }
    }
    false
}

/// How one shell segment received control from the segment before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShellConnector {
    /// The first segment of the command line.
    Start,
    /// `|`, which streams the previous command's output into this one.
    Pipe,
    /// `;` or `||`, which run this command without the previous command's output.
    Sequential,
}

/// Split one shell command line into segments and the connector that introduced each.
/// Only `|`, `||`, and `;` are recognised, because those are the connectors this rule reports.
///
/// `value` is split at every `|`, `||` and `;` byte, including ones inside quotes.
/// Returns the segments in order with their untrimmed text; the first carries `Start`, and the list always has at least one entry.
fn shell_command_segments(value: &str) -> Vec<(ShellConnector, &str)> {
    let mut segments = Vec::new();
    let mut connector = ShellConnector::Start;
    let mut segment_start = 0usize;
    let mut index = 0usize;
    let bytes = value.as_bytes();
    // Connector bytes are ASCII, so a byte scan never splits a multi-byte character.
    while index < bytes.len() {
        let found = match bytes[index] {
            b'|' if bytes.get(index + 1) == Some(&b'|') => (ShellConnector::Sequential, 2),
            b'|' => (ShellConnector::Pipe, 1),
            b';' => (ShellConnector::Sequential, 1),
            _ => {
                index += 1;
                continue;
            }
        };
        segments.push((connector, &value[segment_start..index]));
        connector = found.0;
        index += found.1;
        segment_start = index;
    }
    segments.push((connector, &value[segment_start..]));
    segments
}

/// Whether a segment fetches remote content that a later command could execute.
///
/// Returns true when `segment` contains `curl` or `wget` as a whole word in any case, anywhere in its text.
fn segment_has_remote_download(segment: &str) -> bool {
    static REMOTE_DOWNLOAD_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(&REMOTE_DOWNLOAD_REGEX, r"(?i)\b(?:curl|wget)\b").is_match(segment)
}

/// Return the arguments after a shell interpreter invoked as this segment's command.
/// The interpreter must be the command itself: a script path such as `./deploy.sh` ends in
/// `sh` without being one, and an interpreter named in a message is not an invocation.
fn shell_invocation_arguments(segment: &str) -> Option<&str> {
    let command = segment.trim_start();
    let (first_token, arguments) = split_leading_token(command);
    // A privilege wrapper keeps the interpreter as the command it runs.
    let (interpreter, arguments) = match first_token {
        "sudo" => split_leading_token(arguments.trim_start()),
        _ => (first_token, arguments),
    };
    is_shell_interpreter(interpreter).then_some(arguments)
}

/// Split the first whitespace-delimited token from the rest of a command.
///
/// Returns the text of `command` before its first whitespace and the rest, which still starts with that whitespace.
/// A command without whitespace comes back whole with an empty rest.
fn split_leading_token(command: &str) -> (&str, &str) {
    match command.find(char::is_whitespace) {
        Some(end) => command.split_at(end),
        // A command without whitespace is a single token with no arguments.
        None => (command, ""),
    }
}

/// Recognise a POSIX shell interpreter named directly or through an absolute path.
///
/// `token` is a command's first word; only the part after its last `/` is compared, so any path prefix is accepted.
/// Returns true when that name is exactly `sh`, `bash`, `dash` or `zsh`.
fn is_shell_interpreter(token: &str) -> bool {
    let name = token.rsplit('/').next().unwrap_or(token);
    matches!(name, "sh" | "bash" | "dash" | "zsh")
}

/// Whether an interpreter invoked after a download reads that download's payload.
/// An interpreter given no path reads the stream or terminal it was handed.
///
/// `arguments` is the text after the interpreter, whose first word not starting with `-` is taken as the script path.
/// Returns true when there is no such word, or when `download_segment`, the downloader's text, contains that path as a substring.
fn shell_input_is_downloaded_payload(arguments: &str, download_segment: &str) -> bool {
    let Some(script_path) = arguments
        .split_whitespace()
        .find(|token| !token.starts_with('-'))
    else {
        return true;
    };
    download_segment.contains(script_path)
}

/// Pull-request triggers whose presence changes how workflow secrets are reviewed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkflowEvent {
    PullRequest,
    PullRequestTarget,
}

/// Tracks the top-level `on:` mapping so only a real trigger declaration counts as an event.
/// A step input, matrix entry, or `with:` value named `pull_request` lives outside that mapping
/// and must not make an unrelated push-only workflow look like it runs on pull requests.
#[derive(Default)]
struct WorkflowTriggerState {
    in_on_mapping: bool,
    event_indent: Option<usize>,
}

impl WorkflowTriggerState {
    /// Return the pull-request event this line declares under the top-level `on` key.
    ///
    /// `line` is the raw line, whose indentation finds top-level keys and event entries, and `trimmed` is its trimmed text.
    /// The first indented entry under `on:` fixes the event depth, and a top-level key resets the tracked state.
    /// Returns None for blank and comment lines, deeper filter keys, lines outside `on:`, and other event names.
    fn event_on_line(&mut self, line: &str, trimmed: &str) -> Option<WorkflowEvent> {
        // Blank and comment lines keep the surrounding trigger scope intact.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }
        let indent = line_indent(line);
        if indent == 0 {
            return self.top_level_key_event(trimmed);
        }
        if !self.in_on_mapping {
            return None;
        }
        // The first nested entry fixes the depth at which events are named; deeper keys such as
        // `branches:` and `types:` filter the event above them rather than naming a new one.
        let event_indent = *self.event_indent.get_or_insert(indent);
        (indent == event_indent)
            .then(|| workflow_event_in_entry(trimmed))
            .flatten()
    }

    /// Classify a top-level key, which either opens the trigger mapping or closes it.
    ///
    /// `trimmed` is an indent-0 line; an `on:` key with an empty value opens the mapping for later lines.
    /// Returns the event in an inline `on:` value, or None for other keys, an empty value, or no pull-request event.
    fn top_level_key_event(&mut self, trimmed: &str) -> Option<WorkflowEvent> {
        self.in_on_mapping = false;
        self.event_indent = None;
        let (key, value) = yaml_mapping_entry(trimmed)?;
        if key != "on" {
            return None;
        }
        let events = normalize_yaml_scalar(value);
        // An empty value defers the events to the indented lines that follow.
        if events.is_empty() {
            self.in_on_mapping = true;
            return None;
        }
        workflow_event_in_scalar(events)
    }
}

/// Recognise a pull-request event in an inline `on:` scalar, flow sequence, or flow mapping.
/// Only a top-level `on:` value reaches this, so matching a flow entry cannot pick up an
/// unrelated key elsewhere in the workflow that happens to share an event name.
///
/// `value` is the normalised inline text after `on:`; a bracketed or braced value is split at commas, using each flow-mapping key.
/// Returns `PullRequestTarget` if any entry names it, else `PullRequest` if one names it, else None.
fn workflow_event_in_scalar(value: &str) -> Option<WorkflowEvent> {
    let flow_entries = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| {
            value
                .strip_prefix('{')
                .and_then(|rest| rest.strip_suffix('}'))
        });
    let Some(items) = flow_entries else {
        return workflow_event_from_name(value);
    };
    let mut listed_event = None;
    for item in items.split(',') {
        // A flow mapping carries its event as the entry key; a flow sequence has no key.
        let name = item.split_once(':').map_or(item, |(key, _)| key);
        match workflow_event_from_name(normalize_yaml_key(name)) {
            // A target trigger ends the search because it outranks a plain pull request.
            Some(WorkflowEvent::PullRequestTarget) => {
                return Some(WorkflowEvent::PullRequestTarget);
            }
            Some(event) => listed_event = Some(event),
            None => {}
        }
    }
    listed_event
}

/// Recognise a pull-request event named by one entry inside the `on:` mapping.
///
/// `trimmed` is one entry line; an optional `- ` prefix, a trailing comment and any text after the first colon are ignored.
/// Returns the pull-request event the normalised name maps to, or None for any other event.
fn workflow_event_in_entry(trimmed: &str) -> Option<WorkflowEvent> {
    // A list item names its event directly; a mapping key carries that event's filters. A trailing
    // comment, such as `- pull_request_target  # label bot`, is not part of the event name.
    let entry = strip_inline_comment(trimmed.strip_prefix("- ").unwrap_or(trimmed));
    let name = match entry.split_once(':') {
        Some((key, _)) => key,
        None => entry,
    };
    workflow_event_from_name(normalize_yaml_key(name))
}

/// Map one normalised event name to the trigger this rule reviews.
///
/// Returns `PullRequestTarget` or `PullRequest` when `name` is exactly `pull_request_target` or `pull_request`, else None.
fn workflow_event_from_name(name: &str) -> Option<WorkflowEvent> {
    match name {
        "pull_request_target" => Some(WorkflowEvent::PullRequestTarget),
        "pull_request" => Some(WorkflowEvent::PullRequest),
        _ => None,
    }
}

/// Recognise a repository secret expression, including the optional interior
/// whitespace GitHub accepts, so `${{secrets.X}}` reads the same as `${{ secrets.X }}`.
/// `secrets.GITHUB_TOKEN` is the token GitHub mints for each run, scoped by the job's
/// `permissions:`, so it is not a repository secret.
///
/// `trimmed` is one trimmed workflow line; every expression on it that opens with `secrets.` is checked.
/// Returns true when at least one referenced secret name is not `GITHUB_TOKEN`, so a line naming only that token gives false.
fn line_has_secret_expression(trimmed: &str) -> bool {
    static SECRET_EXPRESSION_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &SECRET_EXPRESSION_REGEX,
        r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)",
    )
    .captures_iter(trimmed)
    .any(|captures| {
        captures
            .get(1)
            .is_some_and(|name| name.as_str() != "GITHUB_TOKEN")
    })
}

/// Emit one workflow-only security finding through the normal report contract.
///
/// Appends a medium-confidence security warning to `findings` for the file in `unit` at 1-based `line`.
/// `rule_id`, `message` and `metadata` are copied into the finding, which always carries the shared workflow remediation text.
fn push_workflow_finding(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    rule_id: &str,
    message: &str,
    line: usize,
    metadata: Value,
) {
    findings.push(Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: message.to_string(),
        file_path: unit.file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::Medium,
        symbol: None,
        remediation: Some(
            "Pin third-party actions, minimise workflow permissions, and avoid exposing secrets to untrusted pull request code."
                .to_string(),
        ),
        metadata,
    }));
}

/// User-visible copy and metadata for one shared GitHub step finding.
/// Call sites keep established workflow wording beside action-specific wording,
/// then the emitter selects the copy that matches the file the user supplied.
struct GithubStepFinding<'a> {
    rule_id: &'a str,
    workflow_message: &'a str,
    action_message: &'a str,
    line: usize,
    metadata: Value,
}

/// Emit a step finding with wording and remediation accurate for its metadata file.
///
/// `finding` supplies the rule, both message variants, the 1-based line and metadata; `metadata_kind` picks the variant.
/// A medium-confidence warning for the file in `unit` is appended to `findings`; remote-shell findings get download-verification advice.
fn push_shared_github_metadata_finding(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    metadata_kind: GithubMetadataKind,
    finding: GithubStepFinding<'_>,
) {
    // Metadata kind selects the message; remote-shell findings have script-specific advice.
    let (message, remediation) = if metadata_kind == GithubMetadataKind::Workflow {
        (
            finding.workflow_message,
            "Pin third-party actions, minimise workflow permissions, and avoid exposing secrets to untrusted pull request code.",
        )
    } else {
        (
            finding.action_message,
            "Pin third-party actions, verify downloaded installers, and pass untrusted context through validated inputs.",
        )
    };
    let remediation = if finding.rule_id == "security.github-actions-remote-shell" {
        "Download the remote script to a file, verify it against a pinned checksum or signature, then run that file instead of piping a download into a shell."
    } else {
        remediation
    };
    findings.push(Finding::new(FindingDescriptor {
        rule_id: finding.rule_id.to_string(),
        message: message.to_string(),
        file_path: unit.file.display_path.clone(),
        line: Some(finding.line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::Medium,
        symbol: None,
        remediation: Some(remediation.to_string()),
        metadata: finding.metadata,
    }));
}

#[cfg(test)]
#[path = "github_metadata_rules/tests.rs"]
mod tests;
