use super::*;

mod github;
mod hotspot;
mod markdown;
mod sarif;
mod text;

#[cfg(test)]
pub(crate) use sarif::{sarif_physical_location_from_parts, sarif_uri};

// Shared with the `summary` text surface, which applies the same suppressions.
pub(crate) use text::render_text_suppressions;

#[cfg(test)]
pub(crate) fn render_report(report: &AnalysisReport, format: OutputFormat) -> String {
    render_report_with_scope(report, &RequestedScope::default(), format, None)
}

/// Render `report` in the requested output `format`, passing `scope` only to the HTML report and `duration_ms` only to the text renderer.
/// `duration_ms` is the scan time in milliseconds; the text renderer leaves out its `Duration:` line when it is None.
///
/// Returns the rendered report as one string, produced by the renderer that `format` selects.
/// GitHub output is an empty string when `report` has no diagnostics and no findings.
///
/// The JSON form panics when a report path it must publish has no project-relative form, when the ignored paths disagree with
/// their details, or when a default ignore has no canonical reason.
pub(crate) fn render_report_with_scope(
    report: &AnalysisReport,
    scope: &RequestedScope,
    format: OutputFormat,
    duration_ms: Option<u128>,
) -> String {
    match format {
        OutputFormat::Json => crate::machine_contract::render_analysis(report),
        OutputFormat::Sarif => sarif::render_sarif(report),
        OutputFormat::Html => html_report::render(report, scope),
        OutputFormat::Markdown => markdown::render_markdown(report),
        OutputFormat::Github => github::render_github(report),
        OutputFormat::Hotspot => hotspot::render_hotspot(report),
        OutputFormat::Text => text::render_text(report, duration_ms),
    }
}

/// Sum the `suppressed` count of every suppression summary in `suppressions` into one total.
///
/// Returns the total number of suppressed findings, or zero when `suppressions` is empty.
pub(crate) fn total_suppressed_findings(suppressions: &[SuppressionSummary]) -> usize {
    suppressions.iter().map(|summary| summary.suppressed).sum()
}

/// Map `severity` to its lowercase report label: advisory, warning or error.
///
/// Returns a static label string matching the variant name in lowercase.
pub(super) fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// Map `severity` to a GitHub Actions annotation level, keeping error and warning and turning advisory into notice.
///
/// Returns the static level string error, warning or notice.
pub(super) fn github_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advisory => "notice",
    }
}

/// Percent-encode `%` first, then newline and carriage return, so `value` stays on one GitHub Actions workflow-command line.
///
/// Returns a new string with each `%` written as %25, each newline as %0A and each carriage return as %0D.
pub(super) fn escape_command(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\n', "%0A")
        .replace('\r', "%0D")
}

/// Escape `value` for a GitHub Actions workflow-command property, percent-encoding `:` and `,` on top of `escape_command`.
///
/// Returns the `escape_command` result with each `:` written as %3A and each `,` written as %2C.
pub(super) fn escape_command_property(value: &str) -> String {
    escape_command(value)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

/// Encode `&`, `<`, `>` and double quotes in `value` as HTML entities for element content and double-quoted attribute values.
///
/// Returns a new string with those four characters replaced by `&amp;`, `&lt;`, `&gt;` and `&quot;`.
/// Single quotes pass through unchanged, so the result is not safe inside single-quoted attributes.
pub(crate) fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
