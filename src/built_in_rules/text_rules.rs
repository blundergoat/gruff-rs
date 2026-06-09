use super::*;

pub(crate) fn analyse_text_rules(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_file_length(unit.file, unit.source, config, findings);
    analyse_ci_github_event_shell_interpolation(unit, findings);
    analyse_github_actions_rules(unit, findings);
    analyse_sensitive_data(unit, config, findings);
    analyse_pii_test_fixture(unit, findings);
}

fn analyse_file_length(
    file: &SourceFile,
    source: &str,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if file_length_is_exempt(&file.display_path) {
        return;
    }
    let line_count = source.lines().count();
    let rule_id = "size.file-length";
    let threshold = config.threshold(rule_id, 600.0) as usize;
    if line_count > threshold {
        findings.push(finding_with_metadata(
            SimpleFindingDescriptor {
                rule_id,
                message: format!(
                    "File has {line_count} lines, above the threshold of {threshold}."
                ),
                file,
                line: Some(1),
                severity: config.severity(rule_id, Severity::Warning),
                pillar: Pillar::Size,
            },
            threshold_metadata(line_count, threshold, "lines"),
        ));
    }
}

fn file_length_is_exempt(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    let file_name = normalized
        .rsplit('/')
        .next()
        .unwrap_or(&normalized)
        .to_ascii_lowercase();
    file_name_is_lockfile(&file_name)
        || file_name_is_markdown(&file_name)
        || file_name.ends_with(".sh")
        || path_is_rule_definition_table(&normalized)
        || path_is_calibration_case_table(&normalized)
        || path_is_agent_hook(&normalized)
}

fn file_name_is_lockfile(file_name: &str) -> bool {
    matches!(
        file_name,
        "cargo.lock" | "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml"
    ) || file_name.ends_with(".lock")
}

fn file_name_is_markdown(file_name: &str) -> bool {
    file_name.ends_with(".md") || file_name.ends_with(".markdown")
}

fn path_is_rule_definition_table(normalized: &str) -> bool {
    normalized.starts_with("src/rules/") && normalized.ends_with("_definitions.rs")
}

fn path_is_calibration_case_table(normalized: &str) -> bool {
    normalized.starts_with("src/tests/calibration/") && normalized.ends_with("_cases.rs")
}

fn path_is_agent_hook(normalized: &str) -> bool {
    normalized.contains("/.codex/hooks/")
        || normalized.contains("/.claude/hooks/")
        || normalized.starts_with(".codex/hooks/")
        || normalized.starts_with(".claude/hooks/")
}

fn analyse_ci_github_event_shell_interpolation(unit: &SourceUnit<'_>, findings: &mut Vec<Finding>) {
    if !is_github_workflow(&unit.file.display_path) {
        return;
    }

    let mut state = RunBlockState::default();
    for (line_index, line) in unit.source.lines().enumerate() {
        if state.line_has_event_shell_interpolation(line) {
            push_github_event_shell_finding(unit, findings, line_index + 1);
        }
    }
}

#[derive(Default)]
struct RunBlockState {
    in_run_block: bool,
    run_indent: usize,
}

impl RunBlockState {
    fn line_has_event_shell_interpolation(&mut self, line: &str) -> bool {
        let trimmed = line.trim();
        self.close_completed_block(line_indent(line), trimmed);
        if let Some(after_run) = workflow_run_value(trimmed) {
            return self.run_value_contains_event_shell_interpolation(line_indent(line), after_run);
        }

        self.in_run_block && trimmed.contains("github.event.")
    }

    fn close_completed_block(&mut self, indent: usize, trimmed: &str) {
        if self.in_run_block && indent <= self.run_indent && !trimmed.is_empty() {
            self.in_run_block = false;
        }
    }

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

fn push_github_event_shell_finding(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    line: usize,
) {
    findings.push(Finding::new(FindingDescriptor {
        rule_id: "ci.github-event-shell-interpolation".to_string(),
        message:
            "GitHub event data is interpolated directly into a workflow shell step.".to_string(),
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

fn is_github_workflow(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.starts_with(".github/workflows/")
        && (normalized.ends_with(".yml") || normalized.ends_with(".yaml"))
}

fn line_indent(line: &str) -> usize {
    line.len().saturating_sub(line.trim_start().len())
}

fn workflow_run_value(trimmed: &str) -> Option<&str> {
    trimmed
        .strip_prefix("- ")
        .unwrap_or(trimmed)
        .strip_prefix("run:")
}

fn is_yaml_block_scalar(value: &str) -> bool {
    matches!(value, "|" | "|-" | "|+" | ">" | ">-" | ">+")
}

fn analyse_github_actions_rules(unit: &SourceUnit<'_>, findings: &mut Vec<Finding>) {
    if !is_github_workflow(&unit.file.display_path) {
        return;
    }
    let mut state = WorkflowRunState::default();
    let mut permissions = WorkflowPermissionsState::default();
    let mut summary = WorkflowSecuritySummary::default();

    for (line_index, line) in unit.source.lines().enumerate() {
        analyse_github_actions_line(
            unit,
            findings,
            &mut state,
            &mut permissions,
            &mut summary,
            line_index + 1,
            line,
        );
    }

    push_github_actions_summary_findings(unit, findings, summary);
}

#[derive(Default)]
struct WorkflowSecuritySummary {
    pull_request_line: Option<usize>,
    pull_request_target_line: Option<usize>,
    secret_lines: Vec<usize>,
}

impl WorkflowSecuritySummary {
    fn observe_line(&mut self, trimmed: &str, line_number: usize) {
        if workflow_line_contains_event(trimmed, "pull_request_target") {
            self.pull_request_target_line.get_or_insert(line_number);
        } else if workflow_line_contains_event(trimmed, "pull_request") {
            self.pull_request_line.get_or_insert(line_number);
        }
        if trimmed.contains("${{ secrets.") {
            self.secret_lines.push(line_number);
        }
    }

    fn has_pull_request_event(&self) -> bool {
        self.pull_request_line
            .or(self.pull_request_target_line)
            .is_some()
    }
}

fn analyse_github_actions_line(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    state: &mut WorkflowRunState,
    permissions: &mut WorkflowPermissionsState,
    summary: &mut WorkflowSecuritySummary,
    line_number: usize,
    line: &str,
) {
    let trimmed = line.trim();
    if let Some(action) = workflow_uses_value(trimmed) {
        maybe_push_unpinned_action(unit, findings, line_number, action);
    }
    if permissions.line_allows_broad_permission(line) {
        push_workflow_finding(
            unit,
            findings,
            "security.github-actions-broad-permissions",
            "Workflow grants broad write permissions.",
            line_number,
            json!({}),
        );
    }
    if state.line_has_remote_shell(line) {
        push_workflow_finding(
            unit,
            findings,
            "security.github-actions-remote-shell",
            "Workflow downloads remote content directly into a shell.",
            line_number,
            json!({}),
        );
    }
    summary.observe_line(trimmed, line_number);
}

fn push_github_actions_summary_findings(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    summary: WorkflowSecuritySummary,
) {
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
    if summary.has_pull_request_event() {
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

#[derive(Default)]
struct WorkflowRunState {
    in_run_block: bool,
    run_indent: usize,
}

impl WorkflowRunState {
    fn line_has_remote_shell(&mut self, line: &str) -> bool {
        let trimmed = line.trim();
        self.close_completed_block(line_indent(line), trimmed);
        if let Some(after_run) = workflow_run_value(trimmed) {
            self.run_indent = line_indent(line);
            let value = after_run.trim();
            self.in_run_block = value.is_empty() || is_yaml_block_scalar(value);
            return is_remote_download_piped_to_shell(after_run);
        }
        self.in_run_block && is_remote_download_piped_to_shell(trimmed)
    }

    fn close_completed_block(&mut self, indent: usize, trimmed: &str) {
        if self.in_run_block && indent <= self.run_indent && !trimmed.is_empty() {
            self.in_run_block = false;
        }
    }
}

fn workflow_uses_value(trimmed: &str) -> Option<&str> {
    let value = trimmed
        .strip_prefix("- ")
        .unwrap_or(trimmed)
        .strip_prefix("uses:")?;
    Some(
        strip_inline_comment(value)
            .trim()
            .trim_matches('"')
            .trim_matches('\''),
    )
}

/// Strip a trailing YAML inline comment (` #...`). YAML requires whitespace before
/// `#` to start a comment, so a `#` embedded in the value itself is preserved.
fn strip_inline_comment(value: &str) -> &str {
    match value.find(" #") {
        Some(index) => &value[..index],
        None => value,
    }
}

fn maybe_push_unpinned_action(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    line: usize,
    action: &str,
) {
    if action.starts_with("./") || action.starts_with("docker://") {
        return;
    }
    let Some((name, reference)) = action.rsplit_once('@') else {
        push_unpinned_action(unit, findings, line, action, None);
        return;
    };
    if name.contains('/') && !is_full_sha_reference(reference) {
        push_unpinned_action(unit, findings, line, name, Some(reference));
    }
}

fn is_full_sha_reference(reference: &str) -> bool {
    reference.len() == 40
        && reference
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn push_unpinned_action(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    line: usize,
    action: &str,
    reference: Option<&str>,
) {
    push_workflow_finding(
        unit,
        findings,
        "security.github-actions-unpinned-action",
        "Workflow action is not pinned to a full commit SHA.",
        line,
        json!({ "action": action, "reference": reference }),
    );
}

#[derive(Default)]
struct WorkflowPermissionsState {
    in_permissions_block: bool,
    permissions_indent: usize,
}

impl WorkflowPermissionsState {
    /// Whether `line` allows a broad write permission. Inline `permissions: write-all`
    /// (any quoting / trailing comment) always counts; a per-permission `<perm>: write`
    /// counts only inside a `permissions:` mapping block, so step `with:`/`env:` keys
    /// named like permissions don't false-positive.
    fn line_allows_broad_permission(&mut self, line: &str) -> bool {
        let trimmed = line.trim();
        let indent = line_indent(line);
        if self.in_permissions_block && !trimmed.is_empty() && indent <= self.permissions_indent {
            self.in_permissions_block = false;
        }
        if let Some(value) = permissions_mapping_value(trimmed) {
            if value.is_empty() {
                // `permissions:` with nothing after opens a mapping block.
                self.in_permissions_block = true;
                self.permissions_indent = indent;
                return false;
            }
            // Inline scalar such as `permissions: write-all`.
            self.in_permissions_block = false;
            return value == "write-all";
        }
        self.in_permissions_block && line_is_write_permission(trimmed)
    }
}

/// The scalar after a top-level `permissions:` key (quotes and inline comment
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
    let Some((scope, value)) = trimmed.split_once(':') else {
        return false;
    };
    is_known_permission_scope(scope.trim()) && normalize_yaml_scalar(value) == "write"
}

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

fn is_remote_download_piped_to_shell(value: &str) -> bool {
    static REMOTE_SHELL_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &REMOTE_SHELL_REGEX,
        r"(?i)\b(curl|wget)\b[^\n|;]*(\||;)[^\n]*(sh|bash|dash|zsh)\b",
    )
    .is_match(value)
}

fn workflow_line_contains_event(trimmed: &str, event: &str) -> bool {
    let event_pattern = regex::escape(event);
    let pattern = format!(
        r#"(^on:\s*(?:\[[^\]]*\b{event_pattern}\b|["']?{event_pattern}["']?\s*(?:#.*)?$)|^-?\s*{event_pattern}\s*:|^-?\s*{event_pattern}\s*$)"#
    );
    Regex::new(&pattern)
        .map(|compiled| compiled.is_match(trimmed))
        .unwrap_or(false)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Replay `lines` through one permissions state, reporting whether any line
    /// is judged to grant broad write access.
    fn grants_broad_permission(lines: &[&str]) -> bool {
        let mut state = WorkflowPermissionsState::default();
        lines
            .iter()
            .any(|line| state.line_allows_broad_permission(line))
    }

    #[test]
    fn per_permission_write_is_detected_regardless_of_quoting() {
        // Unquoted baseline plus the valid-YAML quoted and commented variants
        // that all grant the same write access.
        assert!(grants_broad_permission(&[
            "permissions:",
            "  contents: write"
        ]));
        assert!(grants_broad_permission(&[
            "permissions:",
            "  contents: \"write\"",
        ]));
        assert!(grants_broad_permission(&[
            "permissions:",
            "  contents: 'write'",
        ]));
        assert!(grants_broad_permission(&[
            "permissions:",
            "  contents: write  # needed for release",
        ]));
        assert!(grants_broad_permission(&[
            "permissions:",
            "  contents: \"write\"  # needed for release",
        ]));
        assert!(grants_broad_permission(&[
            "permissions:",
            "  packages: \"write\"",
        ]));
    }

    #[test]
    fn narrow_or_out_of_block_permissions_stay_silent() {
        assert!(!grants_broad_permission(&[
            "permissions:",
            "  contents: read"
        ]));
        assert!(!grants_broad_permission(&[
            "permissions:",
            "  contents: 'read'",
        ]));
        // `id-token: write` is a narrow, expected grant, not a broad one.
        assert!(!grants_broad_permission(&[
            "permissions:",
            "  id-token: write",
        ]));
        // A step input named like a permission, outside any permissions block.
        assert!(!grants_broad_permission(&["with:", "  contents: write"]));
    }

    #[test]
    fn inline_write_all_scalar_is_detected_regardless_of_quoting() {
        assert!(grants_broad_permission(&["permissions: write-all"]));
        assert!(grants_broad_permission(&["permissions: \"write-all\""]));
        assert!(grants_broad_permission(&[
            "permissions: write-all  # broad",
        ]));
        assert!(!grants_broad_permission(&["permissions: read-all"]));
    }
}
