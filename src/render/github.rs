use super::*;

/// Renders `report` as GitHub Actions workflow command lines, one per diagnostic and finding, with run diagnostics listed first.
///
/// Each finding is annotated at its file and line, falling back to line 1 when it has no line, and is titled with its rule id.
/// File paths, rule ids and messages are escaped for the workflow command syntax.
/// A diagnostic without a file path currently gets a malformed prefix that runs the level into `title=`, so it is not a valid annotation.
///
/// Returns the command lines joined by newlines, or an empty string when `report` has no diagnostics and no findings.
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

/// Formats `diagnostic` as one GitHub Actions workflow command line, at error level for a failure and notice level otherwise.
///
/// The annotation names a file and line only when the diagnostic has a file path (line defaulting to 1) and is titled with the diagnostic type.
/// Without a file path the level runs straight into `title=` with no separating space, so the line is currently not a valid annotation.
///
/// Returns the single workflow command line for `diagnostic`, without a trailing newline.
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
