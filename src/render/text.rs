use super::*;
use std::fmt::Write as _;

const OUTPUT_VOLUME_HINT_THRESHOLD: usize = 50;

/// Renders an analysis report as plain text: header and score, diagnostics, findings, suppressions, the applied baseline and a volume hint.
///
/// `report` supplies every section, and `duration_ms` is the scan time in milliseconds; the `Duration:` line is left out when it is None.
/// Returns the full report text.
pub(super) fn render_text(report: &AnalysisReport, duration_ms: Option<u128>) -> String {
    let mut output = String::with_capacity(256 + report.findings.len().saturating_mul(160));
    render_text_header(&mut output, report, duration_ms);
    render_text_diagnostics(&mut output, report);
    render_text_findings(&mut output, report);
    render_text_suppressions(&mut output, report);
    render_text_applied_baseline(&mut output, report);
    render_output_volume_hint(&mut output, report);
    output
}

/// Appends the `Baseline:` line when the run applied a baseline that is not marked `generated`.
///
/// Name an applied baseline and how it was chosen, so a run that hid accepted findings never reads as a clean scan,
/// e.g. `Baseline: default gruff-baseline.json; suppressed 6 findings` (ADR-006).
///
/// `report` supplies the baseline's source, path and suppressed count, and the line is appended to `output`; nothing is written without a baseline.
fn render_text_applied_baseline(output: &mut String, report: &AnalysisReport) {
    let Some(baseline) = report
        .baseline
        .as_ref()
        .filter(|baseline| !baseline.generated)
    else {
        return;
    };
    let _ = write!(
        output,
        "\nBaseline: {} {}; suppressed {} findings\n",
        baseline.source, baseline.path, baseline.suppressed
    );
}

// ADR-014 per-rule delta blocks. Rendered BEFORE the composite-score line
// when `per_rule_deltas` is present. Two ranked blocks (improved, regressed)
// capped at five entries each, omitting zero-net rules. Order: by absolute
// net delta DESC then rule_id ASC for deterministic output.
const RULE_DELTA_BLOCK_LIMIT: usize = 5;

/// Writes the ADR-014 improved and regressed lines that rank rules by the size of their net delta.
///
/// `report` supplies `per_rule_deltas`; a negative net counts as improved, a positive net as regressed, and each line is appended to `output`.
/// A block with no entries is left out, and nothing is written when `per_rule_deltas` is absent.
fn render_rule_delta_blocks(output: &mut String, report: &AnalysisReport) {
    let Some(deltas) = report.per_rule_deltas.as_ref() else {
        return;
    };
    let improved = render_rule_delta_entries(deltas, |delta| delta.net < 0);
    let regressed = render_rule_delta_entries(deltas, |delta| delta.net > 0);
    if improved.is_empty() && regressed.is_empty() {
        return;
    }
    if !improved.is_empty() {
        let _ = writeln!(output, "Top {RULE_DELTA_BLOCK_LIMIT} improved: {improved}");
    }
    if !regressed.is_empty() {
        let _ = writeln!(
            output,
            "Top {RULE_DELTA_BLOCK_LIMIT} regressed: {regressed}"
        );
    }
}

/// Formats the entries of one delta block, largest absolute net first and ties ordered by rule id.
///
/// `deltas` are the per-rule deltas and `predicate` picks the ones that belong in this block; at most `RULE_DELTA_BLOCK_LIMIT` are kept.
/// Returns each entry as its signed net and rule id, joined by commas, or an empty string when no delta matches.
fn render_rule_delta_entries(
    deltas: &[RuleDelta],
    predicate: impl Fn(&RuleDelta) -> bool,
) -> String {
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
        .map(|delta| format!("{:+} {}", delta.net, delta.rule_id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Suggests `gruff-rs summary --top 20` when a report holds at least `OUTPUT_VOLUME_HINT_THRESHOLD` findings, since a long flat list is hard to read.
///
/// `report` supplies the finding count, and the hint is appended to `output`; nothing is written below the threshold.
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

/// Writes the report header: the masthead and composite block first, as FAMILY-CONTRACT section 1 requires, then the scan card.
///
/// `report` supplies the version, score, project root, file counts, rule deltas and ignored paths, and every line is appended to `output`.
/// `duration_ms` is the scan time in milliseconds; the `Duration:` line is left out when it is None.
fn render_text_header(output: &mut String, report: &AnalysisReport, duration_ms: Option<u128>) {
    // FAMILY-CONTRACT section 1: the masthead and the two-line composite block are the first three
    // lines of the view, in that order, and every port-local extension sits below them. The scan card
    // (project root, file count, duration) used to sit between the masthead and the composite, which
    // put a reader three lines further from the number they came for than the contract allows.
    let _ = writeln!(output, "gruff-rs {} analyse", report.tool.version);
    crate::render_composite_block(output, report);
    let _ = writeln!(
        output,
        "Path: {}",
        display_project_root(&report.run.project_root)
    );
    let _ = writeln!(
        output,
        "Files: {}{}",
        report.paths.analysed_files,
        ignored_count_label(report),
    );
    if let Some(ms) = duration_ms {
        let _ = writeln!(output, "Duration: {}", format_duration(ms));
    }
    // ADR-014: per-rule delta blocks sit below the canonical block with the rest of the scan card.
    render_rule_delta_blocks(output, report);
    render_ignored_guidance(output, report);
}

/// Builds the suffix of the `Files:` line that counts paths skipped by ignores.
///
/// `report` supplies the ignored paths.
/// Returns a suffix such as `(ignored: 3)` with a leading space, or an empty string when no path was ignored.
fn ignored_count_label(report: &AnalysisReport) -> String {
    if report.paths.ignored_paths.is_empty() {
        String::new()
    } else {
        format!(" (ignored: {})", report.paths.ignored_paths.len())
    }
}

/// Tells the reader that ignored paths were skipped and that `--include-ignored` scans them.
///
/// `report` supplies the ignored paths; the line is appended to `output` only when at least one path was ignored.
fn render_ignored_guidance(output: &mut String, report: &AnalysisReport) {
    if report.paths.ignored_paths.is_empty() {
        return;
    }
    output.push_str(
        "Ignored paths skipped by Git/config ignores; pass --include-ignored to scan them.\n",
    );
}

/// Formats a scan duration for the `Duration:` line in a unit that suits its size.
///
/// `duration_ms` is the elapsed time in milliseconds.
/// Returns whole milliseconds under one second, seconds with two decimals under a minute, and minutes with two-digit seconds after that.
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

/// Shortens the project root for the `Path:` line by writing the home directory as `~`.
///
/// `project_root` is the scanned root from the report; it is compared with the `HOME` environment variable, which is ignored when unset or empty.
/// Returns `~` when `project_root` equals `HOME`, and `~` followed by the rest when `HOME` is a prefix followed by `/`.
/// Any other `project_root`, including one under a `HOME` value that ends in `/`, is returned unchanged.
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

/// Writes the `Diagnostics:` section after a blank line, one line per run diagnostic.
///
/// `report` supplies the diagnostics and the section is appended to `output`; nothing is written when there are none.
fn render_text_diagnostics(output: &mut String, report: &AnalysisReport) {
    if report.diagnostics.is_empty() {
        return;
    }
    output.push_str("\nDiagnostics:\n");
    for diagnostic in &report.diagnostics {
        output.push_str(&format_text_diagnostic_line(diagnostic));
    }
}

/// Formats one run diagnostic as a dash-led line of its type and message.
///
/// `diagnostic` supplies the type, message and optional file path.
/// Returns the line with a trailing newline, adding the file path in parentheses when `diagnostic` has one.
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

/// Writes the `Findings:` section, one line per finding with its severity, file, line, rule id and message.
///
/// `report` supplies the findings and the section is appended to `output`; nothing is written when there are no findings.
/// A finding without a line number is shown at line 1.
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

// FAMILY-CONTRACT.md section 13a: a surface that applies a suppression must
// report its count on that same surface. `summary` filters too, so it renders
// this exact line through this function rather than restating the wording.
/// Writes the `Suppressed findings:` line that FAMILY-CONTRACT section 13a requires wherever a suppression was applied.
///
/// `report` supplies the suppression summaries, and the line is appended to `output`; nothing is written when no finding was suppressed.
/// Each summary that hid findings is listed with its `config_key` label, scope, rule, count and reason.
/// Its scope is the first covered path when the summary has a `source`, as built-in and inline rows do, and the configured entry index otherwise.
pub(crate) fn render_text_suppressions(output: &mut String, report: &AnalysisReport) {
    let suppressed = total_suppressed_findings(&report.suppressions);
    if suppressed == 0 {
        return;
    }
    let details = report
        .suppressions
        .iter()
        .filter(|summary| summary.suppressed > 0)
        .map(|summary| {
            // A built-in or inline row names the file it covers, because it has no configured entry to point at.
            let scope = match summary.source {
                Some(_) => summary.paths.first().cloned().unwrap_or_default(),
                None => summary.index.to_string(),
            };
            format!(
                "{}[{}] {}: {} ({})",
                summary.config_key, scope, summary.rule, summary.suppressed, summary.reason
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    output.push_str(&format!(
        "\nSuppressed findings: {suppressed} via {details}\n"
    ));
}
