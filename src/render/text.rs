use super::*;

pub(super) fn render_text(report: &AnalysisReport) -> String {
    let mut output = String::new();
    render_text_header(&mut output, report);
    render_text_diagnostics(&mut output, report);
    render_text_findings(&mut output, report);
    render_text_suppressions(&mut output, report);
    output
}

fn render_text_header(output: &mut String, report: &AnalysisReport) {
    output.push_str(&format!("gruff-rs {}\n", report.tool.version));
    output.push_str(&format!(
        "Score: {:.1} ({}) | Findings: {} advisory, {} warning, {} error\n",
        report.score.composite,
        report.score.grade,
        report.summary.advisory,
        report.summary.warning,
        report.summary.error
    ));
    output.push_str(&format!(
        "Analysed files: {}\n",
        report.paths.analysed_files
    ));
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
