use super::*;

pub(crate) fn analyse_text_rules(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_file_length(unit.file, unit.source, config, findings);
    analyse_ci_github_event_shell_interpolation(unit, findings);
    analyse_sensitive_data(unit, config, findings);
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
        findings.push(finding(SimpleFindingDescriptor {
            rule_id,
            message: format!("File has {line_count} lines, above the threshold of {threshold}."),
            file,
            line: Some(1),
            severity: config.severity(rule_id, Severity::Warning),
            pillar: Pillar::Size,
        }));
    }
}

fn file_length_is_exempt(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    let file_name = normalized
        .rsplit('/')
        .next()
        .unwrap_or(&normalized)
        .to_ascii_lowercase();
    let lockfile = matches!(
        file_name.as_str(),
        "cargo.lock" | "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml"
    ) || file_name.ends_with(".lock");
    let markdown = file_name.ends_with(".md") || file_name.ends_with(".markdown");
    let agent_hook = normalized.contains("/.codex/hooks/")
        || normalized.contains("/.claude/hooks/")
        || normalized.starts_with(".codex/hooks/")
        || normalized.starts_with(".claude/hooks/");
    lockfile || markdown || agent_hook
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
