use super::*;
use std::fmt::Write as _;

const OUTPUT_VOLUME_HINT_THRESHOLD: usize = 50;

pub(super) fn render_text(report: &AnalysisReport, duration_ms: Option<u128>) -> String {
    let mut output = String::with_capacity(256 + report.findings.len().saturating_mul(160));
    render_text_header(&mut output, report, duration_ms);
    render_text_diagnostics(&mut output, report);
    render_text_findings(&mut output, report);
    render_text_suppressions(&mut output, report);
    render_output_volume_hint(&mut output, report);
    output
}

fn render_output_volume_hint(output: &mut String, report: &AnalysisReport) {
    if report.findings.len() < OUTPUT_VOLUME_HINT_THRESHOLD {
        return;
    }
    let _ = write!(
        output,
        "\nHint: {} findings is a lot to read flat. Try:\n  gruff-rs summary --top 20 <paths>\n",
        report.findings.len()
    );
}

fn render_text_header(output: &mut String, report: &AnalysisReport, duration_ms: Option<u128>) {
    let mut header = format!(
        "gruff-rs {}  ·  project: {}  ·  files: {}{}",
        report.tool.version,
        display_project_root(&report.run.project_root),
        report.paths.analysed_files,
        ignored_count_label(report),
    );
    if let Some(ms) = duration_ms {
        header.push_str(&format!("  ·  duration: {}", format_duration(ms)));
    }
    header.push('\n');
    output.push_str(&header);

    output.push_str(&format!(
        "Score: {:.1} ({}) | Findings: {} advisory, {} warning, {} error\n",
        report.score.composite,
        report.score.grade,
        report.summary.advisory,
        report.summary.warning,
        report.summary.error
    ));
    render_ignored_guidance(output, report);
}

fn ignored_count_label(report: &AnalysisReport) -> String {
    if report.paths.ignored_paths.is_empty() {
        String::new()
    } else {
        format!("  ·  ignored: {}", report.paths.ignored_paths.len())
    }
}

fn render_ignored_guidance(output: &mut String, report: &AnalysisReport) {
    if report.paths.ignored_paths.is_empty() {
        return;
    }
    output.push_str(
        "Ignored paths skipped by Git/config ignores; pass --include-ignored to scan them.\n",
    );
}

fn format_duration(duration_ms: u128) -> String {
    if duration_ms < 1_000 {
        format!("{duration_ms}ms")
    } else if duration_ms < 60_000 {
        format!("{:.2}s", duration_ms as f64 / 1_000.0)
    } else {
        let secs = duration_ms / 1_000;
        let minutes = secs / 60;
        let remainder = secs % 60;
        format!("{minutes}m{remainder:02}s")
    }
}

fn display_project_root(project_root: &str) -> String {
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.to_string_lossy();
        if !home.is_empty() {
            if project_root == home.as_ref() {
                return "~".to_string();
            }
            if let Some(rest) = project_root.strip_prefix(home.as_ref()) {
                if rest.starts_with('/') {
                    return format!("~{rest}");
                }
            }
        }
    }
    project_root.to_string()
}

fn render_text_diagnostics(output: &mut String, report: &AnalysisReport) {
    if report.diagnostics.is_empty() {
        return;
    }
    output.push_str("\nDiagnostics:\n");
    for diagnostic in &report.diagnostics {
        output.push_str(&format_text_diagnostic_line(diagnostic));
    }
}

fn format_text_diagnostic_line(diagnostic: &RunDiagnostic) -> String {
    let file_suffix = diagnostic
        .file_path
        .as_deref()
        .map(|path| format!(" ({path})"))
        .unwrap_or_default();
    format!(
        "- {}: {}{file_suffix}\n",
        diagnostic.diagnostic_type, diagnostic.message
    )
}

fn render_text_findings(output: &mut String, report: &AnalysisReport) {
    if report.findings.is_empty() {
        return;
    }
    output.push_str("\nFindings:\n");
    for finding in &report.findings {
        output.push_str(&format!(
            "- [{}] {}:{} {} - {}\n",
            severity_label(finding.severity),
            finding.file_path,
            finding.line.unwrap_or(1),
            finding.rule_id,
            finding.message
        ));
    }
}

fn render_text_suppressions(output: &mut String, report: &AnalysisReport) {
    let suppressed = total_suppressed_findings(&report.suppressions);
    if suppressed == 0 {
        return;
    }
    let details = report
        .suppressions
        .iter()
        .filter(|summary| summary.suppressed > 0)
        .map(|summary| {
            format!(
                "exclude[{}] {}: {} ({})",
                summary.index, summary.rule, summary.suppressed, summary.reason
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    output.push_str(&format!(
        "\nSuppressed findings: {suppressed} via {details}\n"
    ));
}
