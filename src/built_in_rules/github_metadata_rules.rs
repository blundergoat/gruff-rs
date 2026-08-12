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
    trimmed
        .strip_prefix("- ")
        .unwrap_or(trimmed)
        .strip_prefix("run:")
}

/// Recognise YAML block-scalar markers whose following lines belong to `run`.
fn is_yaml_block_scalar(value: &str) -> bool {
    matches!(value, "|" | "|-" | "|+" | ">" | ">-" | ">+")
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
    pull_request_line: Option<usize>,
    pull_request_target_line: Option<usize>,
    secret_lines: Vec<usize>,
}

impl WorkflowSecuritySummary {
    /// Observe workflow events and secret references on one normalized line.
    fn observe_line(&mut self, trimmed: &str, line_number: usize) {
        // Target events take precedence because they also satisfy pull-request gating.
        if workflow_line_contains_event(trimmed, "pull_request_target") {
            self.pull_request_target_line.get_or_insert(line_number);
        } else if workflow_line_contains_event(trimmed, "pull_request") {
            self.pull_request_line.get_or_insert(line_number);
        }
        // Secret lines are retained until the completed workflow trigger is known.
        if trimmed.contains("${{ secrets.") {
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
    // Composite action metadata has no workflow-level permissions contract.
    if metadata_kind == GithubMetadataKind::Workflow
        && scan_state
            .workflow_permissions
            .line_allows_broad_permission(line)
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
            .observe_line(trimmed, line_number);
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
    let value = trimmed
        .strip_prefix("- ")
        .unwrap_or(trimmed)
        .strip_prefix("uses:")?;
    Some(normalize_yaml_scalar(value))
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
        let dependency = self.dependency_in_open_steps(indent, trimmed);
        self.update_mapping_path(indent, trimmed, metadata_kind);
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

    /// Maintain the mapping ancestors needed to recognise workflow and action `steps:` blocks.
    fn update_mapping_path(
        &mut self,
        indent: usize,
        trimmed: &str,
        metadata_kind: GithubMetadataKind,
    ) {
        // Returning to a peer key closes that key's mapping before the new line is classified.
        while self
            .mapping_scopes
            .last()
            .is_some_and(|scope| scope.indent >= indent)
        {
            self.mapping_scopes.pop();
        }
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
            GithubMetadataKind::Workflow => {
                self.mapping_scopes.len() == 2 && self.mapping_scopes[0].key == "jobs"
            }
        }
    }
}

/// Split one plain YAML mapping entry; sequence items are handled by step state instead.
fn yaml_mapping_entry(trimmed: &str) -> Option<(&str, &str)> {
    if trimmed.starts_with("- ") {
        return None;
    }
    let (key, value) = trimmed.split_once(':')?;
    let normalized_key = key.trim().trim_matches('"').trim_matches('\'');
    (!normalized_key.is_empty()).then_some((normalized_key, value))
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
    // Local actions and pinned container images do not depend on a moving repository ref.
    if action.starts_with("./") || action.starts_with("docker://") {
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

/// Detect a downloaded payload piped or chained directly into a shell interpreter.
fn is_remote_download_piped_to_shell(value: &str) -> bool {
    static REMOTE_SHELL_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &REMOTE_SHELL_REGEX,
        r"(?i)\b(curl|wget)\b[^\n|;]*(\||;)[^\n]*(sh|bash|dash|zsh)\b",
    )
    .is_match(value)
}

/// Recognise scalar, list, mapping, or list-item syntax for one workflow event.
fn workflow_line_contains_event(trimmed: &str, event: &str) -> bool {
    let event_pattern = regex::escape(event);
    let pattern = format!(
        r#"(^on:\s*(?:\[[^\]]*\b{event_pattern}\b|["']?{event_pattern}["']?\s*(?:#.*)?$)|^-?\s*{event_pattern}\s*:|^-?\s*{event_pattern}\s*$)"#
    );
    Regex::new(&pattern)
        .map(|compiled| compiled.is_match(trimmed))
        .unwrap_or(false)
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
