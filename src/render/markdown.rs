//! Render analysis reports as deterministic Markdown for review comments.
//! Finding-controlled identifiers and paths enter code spans, while messages
//! use plain-text escaping so an untrusted source tree cannot add structure.

use super::*;
use crate::{pillar_label, scoring::score_text, summary::pillar_digests};
use std::fmt::Write as _;

const RULE_DELTA_BLOCK_LIMIT: usize = 5;

/// Encode a finding identifier or path in a delimiter-safe Markdown code span.
/// Empty text becomes a blank inert span, and line endings remain visible.
fn markdown_code_span(value: &str) -> String {
    let mut visible_value = String::with_capacity(value.len());
    let mut current_backtick_run = 0usize;
    let mut longest_backtick_run = 0usize;

    // Each untrusted character becomes visible text while backtick runs size the safe delimiter.
    for character in value.chars() {
        match character {
            // A carriage return stays visible instead of returning to the start of a report line.
            '\r' => {
                visible_value.push_str("\\r");
                current_backtick_run = 0;
            }
            // A newline stays visible instead of opening a new Markdown block for the user.
            '\n' => {
                visible_value.push_str("\\n");
                current_backtick_run = 0;
            }
            // A backtick remains literal while contributing to the required delimiter length.
            '`' => {
                visible_value.push(character);
                current_backtick_run += 1;
                longest_backtick_run = longest_backtick_run.max(current_backtick_run);
            }
            // Ordinary path and identifier text passes through unchanged inside the code span.
            _ => {
                visible_value.push(character);
                current_backtick_run = 0;
            }
        }
    }

    let delimiter = "`".repeat(longest_backtick_run + 1);
    // Backtick-bearing, blank, or boundary-spaced values need padding to keep delimiters distinct.
    let needs_padding = longest_backtick_run > 0
        || visible_value.is_empty()
        || (visible_value.starts_with(' ') && visible_value.ends_with(' '));
    // Padding is parsed away for normal content and keeps hostile backticks inside one code span.
    if needs_padding {
        return format!("{delimiter} {visible_value} {delimiter}");
    }

    format!("{delimiter}{visible_value}{delimiter}")
}

/// Encode a finding message as inert Markdown plain text.
/// Line endings remain visible, HTML is encoded, and Markdown punctuation is escaped.
fn markdown_plain_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    // Each message character is encoded for plain text without reprocessing inserted entities.
    for character in value.chars() {
        match character {
            // A carriage return remains visible instead of rewriting the current report line.
            '\r' => output.push_str("\\r"),
            // A newline remains visible instead of starting a heading, list, table, or fence.
            '\n' => output.push_str("\\n"),
            // Ampersands are encoded first in one pass so source entities remain inert text.
            '&' => output.push_str("&amp;"),
            // Angle brackets cannot become raw HTML or an automatic link in the rendered report.
            '<' => output.push_str("&lt;"),
            // A closing angle bracket is encoded with its opening counterpart for literal display.
            '>' => output.push_str("&gt;"),
            // CommonMark punctuation is escaped so it cannot open an inline construct.
            punctuation if punctuation.is_ascii_punctuation() => {
                output.push('\\');
                output.push(punctuation);
            }
            // Letters, numbers, spaces, and Unicode text remain readable to the report user.
            _ => output.push(character),
        }
    }
    output
}

/// Render the full Markdown report shown in pull-request or release review text.
/// The report layout stays static while finding-controlled fields are encoded by context.
pub(super) fn render_markdown(report: &AnalysisReport) -> String {
    let pillars = pillar_digests(report);
    let finding_count = report.findings.len().min(50);
    let mut output = String::with_capacity(
        256 + finding_count.saturating_mul(120) + pillars.len().saturating_mul(96),
    );
    output.push_str("# gruff-rs report\n");
    render_rule_delta_blocks(&mut output, report);
    let composite_text = match (report.score.composite, report.score.grade.as_deref()) {
        (Some(composite), Some(grade)) => format!("{composite:.1} ({grade})"),
        // A run that evaluated nothing renders no number, matching the text and machine views.
        _ => "n/a (nothing evaluated)".to_string(),
    };
    output.push_str(&format!(
        "\nScore: **{}**\n\nFindings: {} advisory, {} warning, {} error.\n",
        composite_text, report.summary.advisory, report.summary.warning, report.summary.error
    ));
    render_pillars_section(&mut output, &pillars);
    render_diagnostics_section(&mut output, report);
    // The review shows at most fifty findings in deterministic report order.
    for finding in report.findings.iter().take(50) {
        let rule_id = markdown_code_span(&finding.rule_id);
        let file_path = markdown_code_span(&finding.file_path);
        let message = markdown_plain_text(&finding.message);
        // A finding without a source line retains the renderer's established line-one fallback.
        let line = finding.line.unwrap_or(1);
        output.push_str(&format!("\n- {rule_id} {file_path}:{line} - {message}"));
    }
    output
}

fn render_diagnostics_section(output: &mut String, report: &AnalysisReport) {
    if report.diagnostics.is_empty() {
        return;
    }
    output.push_str("\n## Diagnostics\n");
    for diagnostic in &report.diagnostics {
        let diagnostic_type = markdown_code_span(&diagnostic.diagnostic_type);
        let message = markdown_plain_text(&diagnostic.message);
        let _ = write!(output, "\n- {diagnostic_type}");
        if let Some(path) = diagnostic.file_path.as_deref() {
            let path = markdown_code_span(path);
            let _ = write!(output, " {path}:{}", diagnostic.line.unwrap_or(1));
        }
        let _ = write!(output, " - {message}");
    }
    output.push('\n');
}

/// Render ranked rule improvements and regressions before the composite score.
/// Full-tree reports have no comparison block, so users see the established layout.
fn render_rule_delta_blocks(output: &mut String, report: &AnalysisReport) {
    // A full-tree scan has no comparison context, so no delta block is shown.
    let Some(deltas) = report.per_rule_deltas.as_ref() else {
        return;
    };
    let improved = rule_delta_entries(deltas, |delta| delta.net < 0);
    let regressed = rule_delta_entries(deltas, |delta| delta.net > 0);
    // No changed rule counts means the score remains the first report detail.
    if improved.is_empty() && regressed.is_empty() {
        return;
    }
    // Improvements are shown first so resolved findings lead the comparison summary.
    if !improved.is_empty() {
        let _ = std::fmt::Write::write_fmt(
            output,
            format_args!("\nTop {RULE_DELTA_BLOCK_LIMIT} improved: {improved}\n"),
        );
    }
    // Regressions follow improvements so newly introduced findings remain easy to review.
    if !regressed.is_empty() {
        let _ = std::fmt::Write::write_fmt(
            output,
            format_args!("\nTop {RULE_DELTA_BLOCK_LIMIT} regressed: {regressed}\n"),
        );
    }
}

/// Select and format the five most significant rule deltas for one direction.
/// An empty result means that comparison category is omitted from the report.
fn rule_delta_entries(deltas: &[RuleDelta], predicate: impl Fn(&RuleDelta) -> bool) -> String {
    // Only deltas in the requested direction compete for the five visible positions.
    let mut filtered: Vec<&RuleDelta> = deltas.iter().filter(|delta| predicate(delta)).collect();
    // Larger changes lead; equal changes use the rule ID for deterministic ordering.
    filtered.sort_by(|left, right| {
        right
            .net
            .abs()
            .cmp(&left.net.abs())
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    filtered.truncate(RULE_DELTA_BLOCK_LIMIT);
    // Each selected rule becomes one signed, delimiter-safe comparison entry.
    filtered
        .into_iter()
        .map(|delta| format!("{:+} {}", delta.net, markdown_code_span(&delta.rule_id)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render the canonical seven-column pillar table in its pre-ranked order.
/// Empty reports show a plain empty state instead of a table with no rows.
fn render_pillars_section(output: &mut String, pillars: &[crate::summary::PillarDigest]) {
    output.push_str("\n## Pillars\n\n");
    // No applicable pillars gives the user an explicit empty state instead of a blank section.
    if pillars.is_empty() {
        output.push_str("No pillars to report.\n");
        return;
    }
    output.push_str("| Pillar | Grade | Score | Findings | Advisory | Warning | Error |\n");
    output.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: |\n");
    // Pillars retain the shared findings-descending, label-ascending report order.
    for pillar in pillars {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            pillar_label(pillar.pillar),
            pillar.grade.as_deref().unwrap_or("n/a"),
            score_text(pillar.score),
            pillar.findings,
            pillar.advisory,
            pillar.warning,
            pillar.error,
        ));
    }
}
