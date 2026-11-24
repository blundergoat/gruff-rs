//! Format findings as GitHub Actions annotations for CI runs using `analyse --format github`.
//!
//! Diagnostics come first so a broken scan is visible before individual findings.
//! Findings with a position can link a reviewer straight to the affected file and line.

use super::*;

/// Render `report` as GitHub Actions workflow command lines for `analyse --format github`.
///
/// Run diagnostics appear first so CI logs surface setup or parse failures ahead of individual findings.
/// Each finding annotates its file and line (defaulting to line 1) with its rule ID as title; paths, rule IDs, and messages are escaped.
///
/// `report` supplies the diagnostics and findings to publish.
/// Returns the workflow command lines joined by newlines, or an empty string when `report` has neither diagnostics nor findings.
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

/// Format one `diagnostic` as a GitHub Actions workflow annotation at `error` level for failures and `notice` level otherwise.
///
/// Diagnostics tied to a file include `file=` and `line=` (defaulting to line 1).
/// Pathless diagnostics keep a single space before `title=` so GitHub Actions parses the command instead of dropping it as plain log text.
///
/// `diagnostic` supplies the type, severity classification, optional location, and message.
/// Returns the single workflow command line for `diagnostic` without a trailing newline.
fn github_diagnostic(diagnostic: &RunDiagnostic) -> String {
    // Failing diagnostics (such as parse or config errors) surface as red GitHub errors; informational notes stay notices.
    let level = if diagnostic.is_failure() {
        "error"
    } else {
        "notice"
    };
    // Keep a space before `title=` when no file path exists so GitHub parses `::notice title=...::...` as an annotation.
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
        .unwrap_or_else(|| " ".to_string());
    format!(
        "::{level}{location}title={}::{}",
        escape_command_property(&diagnostic.diagnostic_type),
        escape_command(&diagnostic.message)
    )
}
