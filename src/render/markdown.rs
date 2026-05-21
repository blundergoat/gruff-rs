use super::*;

pub(super) fn render_markdown(report: &AnalysisReport) -> String {
    let mut output = format!(
        "# gruff-rs report\n\nScore: **{:.1} ({})**\n\nFindings: {} advisory, {} warning, {} error.\n",
        report.score.composite,
        report.score.grade,
        report.summary.advisory,
        report.summary.warning,
        report.summary.error
    );
    for finding in report.findings.iter().take(50) {
        output.push_str(&format!(
            "\n- `{}` `{}`:{} - {}",
            finding.rule_id,
            finding.file_path,
            finding.line.unwrap_or(1),
            finding.message
        ));
    }
    output
}
