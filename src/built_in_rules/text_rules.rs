use super::*;

pub(crate) fn analyse_text_rules(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_file_length(unit.file, unit.source, config, findings);
    analyse_sensitive_data(unit, config, findings);
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
