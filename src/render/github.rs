use super::*;

pub(super) fn render_github(report: &AnalysisReport) -> String {
    report
        .diagnostics
        .iter()
        .map(github_diagnostic)
        .chain(report.findings.iter().map(|finding| {
            format!(
                "::{} file={},line={},title={}::{}",
                github_level(finding.severity),
                escape_command_property(&finding.file_path),
                finding.line.unwrap_or(1),
                escape_command_property(&finding.rule_id),
                escape_command(&finding.message)
            )
        }))
        .collect::<Vec<_>>()
        .join("\n")
}

fn github_diagnostic(diagnostic: &RunDiagnostic) -> String {
    let level = if diagnostic.is_failure() {
        "error"
    } else {
        "notice"
    };
    let location = diagnostic
        .file_path
        .as_deref()
        .map(|file| {
            format!(
                " file={},line={},",
                escape_command_property(file),
                diagnostic.line.unwrap_or(1)
            )
        })
        .unwrap_or_default();
    format!(
        "::{level}{location}title={}::{}",
        escape_command_property(&diagnostic.diagnostic_type),
        escape_command(&diagnostic.message)
    )
}
