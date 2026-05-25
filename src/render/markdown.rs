use super::*;
use crate::summary::pillar_digests;

pub(super) fn render_markdown(report: &AnalysisReport) -> String {
    let pillars = pillar_digests(report);
    let finding_count = report.findings.len().min(50);
    let mut output = String::with_capacity(
        256 + finding_count.saturating_mul(120) + pillars.len().saturating_mul(96),
    );
    output.push_str(&format!(
        "# gruff-rs report\n\nScore: **{:.1} ({})**\n\nFindings: {} advisory, {} warning, {} error.\n",
        report.score.composite,
        report.score.grade,
        report.summary.advisory,
        report.summary.warning,
        report.summary.error
    ));
    render_pillars_section(&mut output, &pillars);
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

// Canonical Pillars block (cross-port harmonised contract). Seven columns in fixed order:
// pillar, grade, score (2dp), findings, advisory, warning, error. Sort is `findings DESC,
// then pillar ASC` and is supplied by `summary::pillar_digests`; do not re-sort here.
fn render_pillars_section(output: &mut String, pillars: &[crate::summary::PillarDigest]) {
    output.push_str("\n## Pillars\n\n");
    if pillars.is_empty() {
        output.push_str("No pillars to report.\n");
        return;
    }
    output.push_str("| Pillar | Grade | Score | Findings | Advisory | Warning | Error |\n");
    output.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: |\n");
    for pillar in pillars {
        output.push_str(&format!(
            "| {} | {} | {:.2} | {} | {} | {} | {} |\n",
            pillar_label(pillar.pillar),
            pillar.grade,
            pillar.score,
            pillar.findings,
            pillar.advisory,
            pillar.warning,
            pillar.error,
        ));
    }
}

fn pillar_label(pillar: Pillar) -> &'static str {
    match pillar {
        Pillar::Size => "size",
        Pillar::Complexity => "complexity",
        Pillar::DeadCode => "dead-code",
        Pillar::Waste => "waste",
        Pillar::Maintainability => "maintainability",
        Pillar::Naming => "naming",
        Pillar::Documentation => "documentation",
        Pillar::Modernisation => "modernisation",
        Pillar::Security => "security",
        Pillar::SensitiveData => "sensitive-data",
        Pillar::TestQuality => "test-quality",
        Pillar::Design => "design",
    }
}
