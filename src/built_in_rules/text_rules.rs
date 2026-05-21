use super::*;

pub(crate) fn analyse_text_rules(
    file: &SourceFile,
    source: &str,
    rust_ast: Option<&syn::File>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_file_length(file, source, config, findings);
    analyse_todo_density(file, source, config, findings);
    analyse_sensitive_data(file, source, rust_ast, config, findings);
}

fn analyse_file_length(
    file: &SourceFile,
    source: &str,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
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

fn analyse_todo_density(
    file: &SourceFile,
    source: &str,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let string_masked = strip_rust_string_literals(source);
    let todo_count = string_masked.matches("TODO").count() + string_masked.matches("FIXME").count();
    let rule_id = "docs.todo-density";
    if todo_count >= config.threshold(rule_id, 4.0) as usize {
        findings.push(finding(SimpleFindingDescriptor {
            rule_id,
            message: format!("File contains {todo_count} TODO/FIXME markers."),
            file,
            line: Some(first_matching_line(&string_masked, "TODO").unwrap_or(1)),
            severity: config.severity(rule_id, Severity::Advisory),
            pillar: Pillar::Documentation,
        }));
    }
}
