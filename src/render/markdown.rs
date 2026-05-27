use super::*;
use crate::{pillar_label, summary::pillar_digests};

const RULE_DELTA_BLOCK_LIMIT: usize = 5;

pub(super) fn render_markdown(report: &AnalysisReport) -> String {
    let pillars = pillar_digests(report);
    let finding_count = report.findings.len().min(50);
    let mut output = String::with_capacity(
        256 + finding_count.saturating_mul(120) + pillars.len().saturating_mul(96),
    );
    output.push_str("# gruff-rs report\n");
    render_rule_delta_blocks(&mut output, report);
    output.push_str(&format!(
        "\nScore: **{:.1} ({})**\n\nFindings: {} advisory, {} warning, {} error.\n",
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

// ADR-014 per-rule delta blocks for markdown. Same shape as text reporter:
// rendered BEFORE the composite-score line, two ranked sub-lists capped at
// five entries each, zero-net rules omitted. Order: by absolute net DESC
// then rule_id ASC.
fn render_rule_delta_blocks(output: &mut String, report: &AnalysisReport) {
    let Some(deltas) = report.per_rule_deltas.as_ref() else {
        return;
    };
    let improved = rule_delta_entries(deltas, |delta| delta.net < 0);
    let regressed = rule_delta_entries(deltas, |delta| delta.net > 0);
    if improved.is_empty() && regressed.is_empty() {
        return;
    }
    if !improved.is_empty() {
        let _ = std::fmt::Write::write_fmt(
            output,
            format_args!("\nTop {RULE_DELTA_BLOCK_LIMIT} improved: {improved}\n"),
        );
    }
    if !regressed.is_empty() {
        let _ = std::fmt::Write::write_fmt(
            output,
            format_args!("\nTop {RULE_DELTA_BLOCK_LIMIT} regressed: {regressed}\n"),
        );
    }
}

fn rule_delta_entries(deltas: &[RuleDelta], predicate: impl Fn(&RuleDelta) -> bool) -> String {
    let mut filtered: Vec<&RuleDelta> = deltas.iter().filter(|delta| predicate(delta)).collect();
    filtered.sort_by(|left, right| {
        right
            .net
            .abs()
            .cmp(&left.net.abs())
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    filtered.truncate(RULE_DELTA_BLOCK_LIMIT);
    filtered
        .into_iter()
        .map(|delta| format!("{:+} `{}`", delta.net, delta.rule_id))
        .collect::<Vec<_>>()
        .join(", ")
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
