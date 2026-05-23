use super::*;

mod github;
mod hotspot;
mod markdown;
mod sarif;
mod text;

#[cfg(test)]
pub(crate) use sarif::{sarif_physical_location_from_parts, sarif_uri};

#[cfg(test)]
pub(crate) fn render_report(report: &AnalysisReport, format: OutputFormat) -> String {
    render_report_with_scope(report, &RequestedScope::default(), format, None)
}

pub(crate) fn render_report_with_scope(
    report: &AnalysisReport,
    scope: &RequestedScope,
    format: OutputFormat,
    duration_ms: Option<u128>,
) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).expect("report serializes"),
        OutputFormat::Sarif => sarif::render_sarif(report),
        OutputFormat::Html => html_report::render(report, scope),
        OutputFormat::Markdown => markdown::render_markdown(report),
        OutputFormat::Github => github::render_github(report),
        OutputFormat::Hotspot => hotspot::render_hotspot(report),
        OutputFormat::Text => text::render_text(report, duration_ms),
    }
}

pub(crate) fn total_suppressed_findings(suppressions: &[SuppressionSummary]) -> usize {
    suppressions.iter().map(|summary| summary.suppressed).sum()
}

pub(super) fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

pub(super) fn github_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advisory => "notice",
    }
}

pub(super) fn escape_command(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\n', "%0A")
        .replace('\r', "%0D")
}

pub(super) fn escape_command_property(value: &str) -> String {
    escape_command(value)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

pub(crate) fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
