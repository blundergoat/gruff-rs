//! Deterministic rules for GitHub workflows and explicit composite actions.
//! Path shape plus source origin selects the understood metadata contract,
//! then structurally placed step rules and workflow-only rules feed the normal report.

use super::super::*;

/// Find direct event-context interpolation in understood GitHub shell steps.
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
    fn close_completed_block(&mut self, indent: usize, trimmed: &str) {
        // Blank lines remain part of a block; a peer key ends it for the CLI scan.
        if self.in_run_block && indent <= self.run_indent && !trimmed.is_empty() {
            self.in_run_block = false;
        }
    }

    /// Open the new run value and check its inline event expression, if present.
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
fn is_action_metadata_path(path: &str) -> bool {
    // Both platform separators are lexical here; classification never opens the user path.
    let basename = path.rsplit(['/', '\\']).next().unwrap_or(path);
    matches!(basename, "action.yml" | "action.yaml")
}

/// Recognise root `.github/workflows/` YAML paths without recursively widening discovery.
fn is_github_workflow(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.starts_with(".github/workflows/")
        && (normalized.ends_with(".yml") || normalized.ends_with(".yaml"))
}

/// Return the leading-space width used to bound a YAML block.
fn line_indent(line: &str) -> usize {
    line.len().saturating_sub(line.trim_start().len())
}

/// Return a `run:` value from plain or list-item step syntax, or no value for other keys.
fn workflow_run_value(trimmed: &str) -> Option<&str> {
    step_property_value(trimmed, "run")
}

/// Return the value of one step property written in plain or list-item syntax. GitHub accepts
/// quoted keys (`- "run": ...`), so the key is normalised before it is compared. The remainder is
/// returned unchanged because block-scalar headers and shell text are inspected as written.
fn step_property_value<'a>(trimmed: &'a str, key: &str) -> Option<&'a str> {
    let property = trimmed.strip_prefix("- ").unwrap_or(trimmed);
    let (property_key, value) = property.split_once(':')?;
    (normalize_yaml_key(property_key) == key).then_some(value)
}

/// Recognise YAML block-scalar markers whose following lines belong to `run`.
/// A header may carry an explicit indentation digit and a chomping indicator in either
/// order (`|2`, `>-`, `|2-`, `|-2`), and YAML also allows a trailing comment after it.
/// All of those keep the following lines in the block.
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
pub(super) fn analyse_github_actions_rules(unit: &SourceUnit<'_>, findings: &mut Vec<Finding>) {
    // Ordinary YAML and directory-discovered actions receive no GitHub metadata rules.
    let Some(metadata_kind) = github_metadata_kind(unit.file) else {
        return;
    };
    let mut scan_state = GithubMetadataScanState::default();

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
    pull_request_line: Option<usize>,
    pull_request_target_line: Option<usize>,
    secret_lines: Vec<usize>,
}

impl WorkflowSecuritySummary {
    /// Observe workflow events and secret references on one line.
    fn observe_line(&mut self, line: &str, trimmed: &str, line_number: usize) {
        // Target events take precedence because they also satisfy pull-request gating.
        match self.triggers.event_on_line(line, trimmed) {
            Some(WorkflowEvent::PullRequestTarget) => {
                self.pull_request_target_line.get_or_insert(line_number);
            }
            Some(WorkflowEvent::PullRequest) => {
                self.pull_request_line.get_or_insert(line_number);
            }
            None => {}
        }
        // Secret lines are retained until the completed workflow trigger is known.
        if line_has_secret_expression(trimmed) {
            self.secret_lines.push(line_number);
        }
    }

    /// Whether either supported pull-request event was present in the workflow.
    fn has_pull_request_event(&self) -> bool {
        self.pull_request_line.is_some() || self.pull_request_target_line.is_some()
    }
}

/// Inspect one metadata line and route shared or workflow-only security checks.
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
    // Secrets are actionable only when a pull-request trigger can reach them.
    if summary.has_pull_request_event() {
        // Each referenced secret keeps its own source line for human review.
        for line in summary.secret_lines {
            push_workflow_finding(
                unit,
                findings,
                "security.github-actions-secrets-in-pr",
                "Workflow exposes repository secrets during a pull request event.",
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
fn is_unfinished_shell_pipeline(trimmed: &str) -> bool {
    let command_text = trimmed.split('#').next().unwrap_or(trimmed).trim_end();
    command_text.ends_with('\\') || (command_text.ends_with('|') && !command_text.ends_with("||"))
}

/// Return a normalized `uses:` value from plain or list-item property syntax.
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
    fn is_inside_job_mapping(&self) -> bool {
        self.mapping_scopes.len() == 2 && self.mapping_scopes[0].key == "jobs"
    }

    /// Maintain the mapping ancestors needed to recognise workflow and action `steps:` blocks.
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
fn normalize_yaml_key(key: &str) -> &str {
    key.trim().trim_matches('"').trim_matches('\'')
}

/// Strip a trailing YAML inline comment (` #...`). YAML requires whitespace before
/// `#` to start a comment, so a `#` embedded in the value itself is preserved.
fn strip_inline_comment(value: &str) -> &str {
    match value.find(" #") {
        // YAML whitespace starts a comment that is not part of the action reference.
        Some(index) => &value[..index],
        // Without that delimiter, the complete value belongs to the user's reference.
        None => value,
    }
}

/// Report a third-party step dependency unless its ref is an immutable full SHA.
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
fn is_full_sha_reference(reference: &str) -> bool {
    // Every character must be hexadecimal after the exact-length check succeeds.
    reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether a container reference names an immutable digest rather than a moving tag.
fn is_digest_pinned_image(image: &str) -> bool {
    let Some((_, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    // A sha256 digest is exactly 64 hexadecimal characters.
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Report a container image whose tag can change under the workflow that runs it.
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
/// Workflow-level scoped writes affect every job and are broad; job-scoped
/// mappings are bounded, while `write-all` remains broad at any indentation.
#[derive(Default)]
struct WorkflowPermissionsState {
    in_permissions_block: bool,
    permissions_indent: usize,
}

impl WorkflowPermissionsState {
    /// Whether `line` allows a broad write permission. Inline `permissions: write-all`
    /// always counts; scoped writes count only in a workflow-level mapping so a
    /// required job grant and similarly named step input stay silent.
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
            && self.permissions_indent == 0
            && line_is_write_permission(trimmed)
    }
}

/// The scalar after a `permissions:` key (quotes and inline comment
/// stripped), or `None` when the line is not a `permissions:` key.
fn permissions_mapping_value(trimmed: &str) -> Option<&str> {
    Some(normalize_yaml_scalar(trimmed.strip_prefix("permissions:")?))
}

/// Strip a YAML scalar's trailing inline comment, surrounding whitespace, and
/// matching quotes, so `write`, `"write"`, `'write'`, and `write  # note` all
/// normalise to the same token.
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
fn line_is_write_permission(trimmed: &str) -> bool {
    // A line without a YAML key/value separator cannot grant a named scope.
    let Some((scope, value)) = trimmed.split_once(':') else {
        return false;
    };
    is_known_permission_scope(scope.trim()) && normalize_yaml_scalar(value) == "write"
}

/// Recognise GitHub permission scopes whose workflow-level write access is broad.
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

/// Detect a downloaded payload reaching a shell interpreter. A pipe always delivers the
/// downloaded bytes. A sequential `;` or `||` delivers them only when the interpreter reads a
/// path the downloader wrote, so running a checked-in script after an unrelated request stays
/// silent instead of instructing users to rewrite a safe step.
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
fn split_leading_token(command: &str) -> (&str, &str) {
    match command.find(char::is_whitespace) {
        Some(end) => command.split_at(end),
        // A command without whitespace is a single token with no arguments.
        None => (command, ""),
    }
}

/// Recognise a POSIX shell interpreter named directly or through an absolute path.
fn is_shell_interpreter(token: &str) -> bool {
    let name = token.rsplit('/').next().unwrap_or(token);
    matches!(name, "sh" | "bash" | "dash" | "zsh")
}

/// Whether an interpreter invoked after a download reads that download's payload.
/// An interpreter given no path reads the stream or terminal it was handed.
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
fn workflow_event_in_entry(trimmed: &str) -> Option<WorkflowEvent> {
    // A list item names its event directly; a mapping key carries that event's filters.
    let entry = trimmed.strip_prefix("- ").unwrap_or(trimmed);
    let name = match entry.split_once(':') {
        Some((key, _)) => key,
        None => entry,
    };
    workflow_event_from_name(normalize_yaml_key(name))
}

/// Map one normalised event name to the trigger this rule reviews.
fn workflow_event_from_name(name: &str) -> Option<WorkflowEvent> {
    match name {
        "pull_request_target" => Some(WorkflowEvent::PullRequestTarget),
        "pull_request" => Some(WorkflowEvent::PullRequest),
        _ => None,
    }
}

/// Recognise a repository secret expression, including the optional interior
/// whitespace GitHub accepts, so `${{secrets.X}}` reads the same as `${{ secrets.X }}`.
fn line_has_secret_expression(trimmed: &str) -> bool {
    static SECRET_EXPRESSION_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(&SECRET_EXPRESSION_REGEX, r"\$\{\{\s*secrets\.").is_match(trimmed)
}

/// Emit one workflow-only security finding through the normal report contract.
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
fn push_shared_github_metadata_finding(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    metadata_kind: GithubMetadataKind,
    finding: GithubStepFinding<'_>,
) {
    // Existing workflow findings keep their public wording and remediation unchanged.
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
