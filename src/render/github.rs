use super::*;

pub(super) fn render_github(report: &AnalysisReport) -> String {
    report
        .findings
        .iter()
        .map(|finding| {
            format!(
                "::{} file={},line={},title={}::{}",
                github_level(finding.severity),
                escape_command_property(&finding.file_path),
                finding.line.unwrap_or(1),
                escape_command_property(&finding.rule_id),
                escape_command(&finding.message)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
