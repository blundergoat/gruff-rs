use crate::{
    grade, pillar_label,
    rules::{builtin_registry, RuleRegistry},
    scoring::score_text,
    scoring::top_file_scores_with_limit,
    AnalysisReport, Confidence, Finding, Pillar, PillarScore, RuleDelta, Severity, SummaryFormat,
    SCORE_PILLARS,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;

const RULE_DELTA_BLOCK_LIMIT: usize = 5;

/// Render a compact summary view from a full analysis report.
///
/// `report` is the finished analysis and `format` picks the text card or the machine JSON summary.
/// `top` caps the text card's top-rule and top-file lists, and `duration_ms` is the run time it prints; JSON ignores both.
/// Returns the text card without trailing newlines, or the JSON summary that the machine contract renders.
///
/// The JSON form panics when the machine contract meets report paths or ignore details it cannot render.
pub(crate) fn render(
    report: &AnalysisReport,
    top: usize,
    format: SummaryFormat,
    duration_ms: u128,
) -> String {
    match format {
        SummaryFormat::Text => {
            let digest = SummaryDigest::build(report, top);
            render_text(report, &digest, duration_ms)
        }
        SummaryFormat::Json => crate::machine_contract::render_summary(report),
    }
}

struct SummaryDigest {
    pillars: Vec<PillarDigest>,
    top_rules: Vec<RuleDigest>,
    top_files: Vec<FileDigest>,
    per_rule_deltas: Option<Vec<RuleDelta>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PillarDigest {
    pub(crate) pillar: Pillar,
    pub(crate) grade: Option<String>,
    pub(crate) score: Option<f64>,
    pub(crate) applicable: bool,
    pub(crate) findings: usize,
    pub(crate) advisory: usize,
    pub(crate) warning: usize,
    pub(crate) error: usize,
    pub(crate) penalty: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuleDigest {
    rule_id: String,
    count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<Confidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileDigest {
    file_path: String,
    findings: usize,
    score: Option<f64>,
    grade: Option<String>,
}

impl SummaryDigest {
    /// Gather the pillar, top-rule and top-file digests and the per-rule deltas the text summary prints.
    ///
    /// `report` is the analysis to digest and `top` caps the rule and file lists.
    /// Returns the digest, with the deltas copied from the report and None when the report has none.
    fn build(report: &AnalysisReport, top: usize) -> Self {
        SummaryDigest {
            pillars: pillar_digests(report),
            top_rules: top_rule_digests(report, top),
            top_files: top_file_digests(report, top),
            per_rule_deltas: report.per_rule_deltas.clone(),
        }
    }
}

/// Build one digest row per scored pillar with its severity counts, the pillar with the most findings first.
///
/// `report` supplies the pillar scores and the findings to count.
/// Returns rows sorted by finding count descending, then by pillar label; a report with no pillar scores yields an empty list.
pub(crate) fn pillar_digests(report: &AnalysisReport) -> Vec<PillarDigest> {
    let severity_counts = tally_severity_by_pillar(&report.findings);
    let mut digests: Vec<PillarDigest> = report
        .score
        .pillars
        .iter()
        .map(|pillar_score| pillar_digest_row(pillar_score, &severity_counts))
        .collect();
    digests.sort_by(|left, right| {
        right
            .findings
            .cmp(&left.findings)
            .then_with(|| pillar_label(left.pillar).cmp(pillar_label(right.pillar)))
    });
    digests
}

/// Count how many advisory, warning and error findings each pillar holds.
///
/// `findings` holds the findings to count.
/// Returns a map from pillar to its advisory, warning and error counts in that order; a pillar with no findings is absent.
fn tally_severity_by_pillar(findings: &[Finding]) -> BTreeMap<Pillar, (usize, usize, usize)> {
    let mut counts: BTreeMap<Pillar, (usize, usize, usize)> = BTreeMap::new();
    for finding in findings {
        let entry = counts.entry(finding.pillar).or_insert((0, 0, 0));
        match finding.severity {
            Severity::Advisory => entry.0 += 1,
            Severity::Warning => entry.1 += 1,
            Severity::Error => entry.2 += 1,
        }
    }
    counts
}

/// Combine one pillar's score with its severity counts into a digest row.
///
/// `pillar_score` supplies the grade, score, findings, penalty and applicability, and `severity_counts` the per-pillar severity tallies.
/// Returns the row, with zero counts for a pillar missing from the tallies, applicable only when the pillar is also a score pillar.
fn pillar_digest_row(
    pillar_score: &PillarScore,
    severity_counts: &BTreeMap<Pillar, (usize, usize, usize)>,
) -> PillarDigest {
    let (advisory, warning, error) = severity_counts
        .get(&pillar_score.pillar)
        .copied()
        .unwrap_or((0, 0, 0));
    PillarDigest {
        pillar: pillar_score.pillar,
        grade: pillar_score.grade.clone(),
        score: pillar_score.score,
        applicable: pillar_score.applicable && SCORE_PILLARS.contains(&pillar_score.pillar),
        findings: pillar_score.findings,
        advisory,
        warning,
        error,
        penalty: pillar_score.penalty,
    }
}

/// List the rules with the most findings and their severity, adding confidence and a short description for built-in rules only.
///
/// `report` supplies the findings and `top` caps how many rules are kept.
/// Returns at most `top` rows sorted by count descending, then rule id; empty when there are no findings or `top` is 0.
fn top_rule_digests(report: &AnalysisReport, top: usize) -> Vec<RuleDigest> {
    let registry = builtin_registry();
    let by_rule = tally_findings_by_rule(report);
    let mut top_rules: Vec<RuleDigest> = by_rule
        .into_iter()
        .map(|(rule_id, (count, severity))| build_rule_digest(rule_id, count, severity, &registry))
        .collect();
    top_rules.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    top_rules.truncate(top);
    top_rules
}

// Source per-rule severity from the actual findings, not from
// `RuleDefinition.default_severity`, so `rules.<id>.severity:` overrides
// (applied via `config.severity` at rule-emission time) stay consistent
// between `summary.<severity>` counts and the topRules digest.
/// Count each rule's findings and take its severity from the findings themselves, so severity overrides match the summary counts.
///
/// `report` supplies the findings.
/// Returns a map from rule id to its finding count and the severity of its first finding; empty when the report has none.
fn tally_findings_by_rule(report: &AnalysisReport) -> BTreeMap<&str, (usize, Severity)> {
    let mut by_rule: BTreeMap<&str, (usize, Severity)> = BTreeMap::new();
    for finding in &report.findings {
        let entry = by_rule
            .entry(&finding.rule_id)
            .or_insert((0, finding.severity));
        entry.0 += 1;
    }
    by_rule
}

/// Make the top-rules row for one rule, adding the registry's confidence and the first sentence of its description.
///
/// `rule_id`, `count` and `severity` come from the findings tally, and `registry` is searched for the rule's definition.
/// Returns the row; confidence and description are None when the registry does not know the rule.
fn build_rule_digest(
    rule_id: &str,
    count: usize,
    severity: Severity,
    registry: &RuleRegistry,
) -> RuleDigest {
    let definition = registry.get(rule_id);
    RuleDigest {
        rule_id: rule_id.to_string(),
        count,
        severity: Some(severity),
        confidence: definition.map(|d| d.confidence),
        description: definition.map(|d| first_sentence(d.description)),
    }
}

/// Cut a rule description down to its first sentence for the summary table.
///
/// `description` is the full description; a sentence ends at the first period followed by a space.
/// Returns the text up to and including that period, or the whole description when it has none.
fn first_sentence(description: &'static str) -> &'static str {
    match description.find(". ") {
        Some(end) => &description[..=end],
        None => description,
    }
}

/// List the top file offenders as the scoring module ranks them, with each file's finding count, score and grade.
///
/// `report` supplies the findings and evaluated-file count, and `top` caps the list.
/// Returns the rows in the order the scoring module gives them; a file without a score has no grade.
fn top_file_digests(report: &AnalysisReport, top: usize) -> Vec<FileDigest> {
    top_file_scores_with_limit(&report.findings, top, report.score.evaluated_files)
        .iter()
        .map(|file| FileDigest {
            file_path: file.file_path.to_string(),
            findings: file.findings,
            score: file.score,
            grade: file.score.map(grade),
        })
        .collect()
}

/// Lay out the text summary: the scan card, diagnostics, pillars, top rules, top files and the suppression audit lines.
///
/// `report` supplies the card values, diagnostics and suppression audit, `digest` the table rows and deltas, and `duration_ms` the run time.
/// Returns the text with trailing newlines trimmed.
fn render_text(report: &AnalysisReport, digest: &SummaryDigest, duration_ms: u128) -> String {
    let mut out = String::new();
    render_scan_card(&mut out, report, duration_ms, |out| {
        rule_delta_blocks::render_text(out, digest.per_rule_deltas.as_deref());
    });
    render_diagnostics_text(&mut out, report);
    out.push('\n');
    render_pillars_text(&mut out, &digest.pillars);
    out.push('\n');
    render_rules_text(&mut out, &digest.top_rules);
    out.push('\n');
    render_files_text(&mut out, &digest.top_files);
    // `summary` applies sensitive exclusions, so it publishes the same audit line
    // `analyse` prints, from the same renderer (FAMILY-CONTRACT.md section 13a).
    // It is a port-local extension line below the canonical block, which section 1
    // permits; machine JSON is the exact findings-free analysis projection.
    crate::render_text_suppressions(&mut out, report);
    out.trim_end_matches('\n').to_string()
}

/// Write one line per report diagnostic giving its type and message, with its file in parentheses when it has one.
///
/// `out` receives the lines and `report` supplies the diagnostics; a report without diagnostics writes nothing.
fn render_diagnostics_text(out: &mut String, report: &AnalysisReport) {
    for diagnostic in &report.diagnostics {
        let _ = write!(
            out,
            "Diagnostic {}: {}",
            diagnostic.diagnostic_type, diagnostic.message
        );
        if let Some(path) = diagnostic.file_path.as_deref() {
            let _ = write!(out, " ({path})");
        }
        out.push('\n');
    }
}

// ADR-014 per-rule delta blocks in the compact summary view. Surfaced when
// a baseline or diff comparison context populated `per_rule_deltas`. Same
// shape and ordering as the analyse text reporter (absolute net DESC,
// rule_id ASC, capped at five entries, zero-net rules dropped).
mod rule_delta_blocks {
    use super::{RuleDelta, RULE_DELTA_BLOCK_LIMIT};
    use std::fmt::Write as _;

    /// Write the improved and regressed rule-delta lines, each listing up to five rules by largest net change.
    ///
    /// `out` receives the lines and `deltas` holds the per-rule movement; None, or no rule with a nonzero net, writes nothing.
    /// A negative net counts as improved and a positive one as regressed, and a side with no rules prints no line.
    pub(super) fn render_text(out: &mut String, deltas: Option<&[RuleDelta]>) {
        let Some(deltas) = deltas else {
            return;
        };
        let improved = entries(deltas, |delta| delta.net < 0);
        let regressed = entries(deltas, |delta| delta.net > 0);
        if improved.is_empty() && regressed.is_empty() {
            return;
        }
        // Sits between the header line and the Score line per ADR-014.
        // Caller arranges leading/trailing newlines; both flank lines
        // already terminate with `\n`.
        if !improved.is_empty() {
            let _ = writeln!(out, "Top {RULE_DELTA_BLOCK_LIMIT} improved: {improved}");
        }
        if !regressed.is_empty() {
            let _ = writeln!(out, "Top {RULE_DELTA_BLOCK_LIMIT} regressed: {regressed}");
        }
    }

    /// Format the deltas a predicate selects as one comma-separated list of signed net changes with their rule ids.
    ///
    /// `deltas` holds every rule's movement and `predicate` picks the ones to list.
    /// Returns up to five entries, each a signed net then the rule id, largest absolute net first and then by rule id; empty when none match.
    fn entries(deltas: &[RuleDelta], predicate: impl Fn(&RuleDelta) -> bool) -> String {
        let mut filtered: Vec<&RuleDelta> =
            deltas.iter().filter(|delta| predicate(delta)).collect();
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
}

// `mid` runs between the header detail and the canonical composite block so
// callers can inject content there (per-rule deltas per ADR-014 in the
// comparison case). When the caller has nothing to inject, pass a no-op closure.
/// Write the summary's header card: masthead, composite block, path, file count, duration, then the injected lines, annotations and guidance.
///
/// `out` receives the text, `report` supplies the values, and `duration_ms` is the run time shown on the card.
/// `mid` runs once after the duration line, so a caller can insert lines before the annotations.
fn render_scan_card(
    out: &mut String,
    report: &AnalysisReport,
    duration_ms: u128,
    mid: impl FnOnce(&mut String),
) {
    // FAMILY-CONTRACT section 1: masthead, then the two-line composite block, then everything this
    // port adds. `summary` and `analyse` lead with the same three lines for the same reason - a
    // reader moving between the two views should not have to hunt for the grade in a different place.
    let _ = writeln!(out, "{} {} summary", report.tool.name, report.tool.version);
    crate::render_composite_block(out, report);
    let _ = writeln!(
        out,
        "Path: {}",
        display_project_root(&report.run.project_root)
    );
    let _ = writeln!(
        out,
        "Files: {}{}",
        report.paths.analysed_files,
        ignored_count_label(report),
    );
    let _ = writeln!(out, "Duration: {}", format_duration(duration_ms));
    mid(out);
    render_scan_annotations(out, report);
    render_scan_guidance(out, report);
}

// Baseline / diagnostics / missing-path context that previously trailed the
// `Score:` line. Kept off the canonical composite block (which must stay
// byte-aligned across ports) by emitting a single annotation line after it.
/// Write one line joining the baseline, diagnostic-count and missing-path notes, when any of them applies.
///
/// `out` receives the line and `report` supplies the baseline result, diagnostics and missing paths; with none of them, nothing is written.
fn render_scan_annotations(out: &mut String, report: &AnalysisReport) {
    let mut annotations: Vec<String> = Vec::new();
    if let Some(baseline) = &report.baseline {
        if baseline.generated {
            annotations.push("baseline: generated".to_string());
        } else {
            annotations.push(format!(
                "baseline: {} new, {} unchanged, {} resolved",
                baseline.new_count, baseline.unchanged_count, baseline.absent_count
            ));
        }
    }
    if !report.diagnostics.is_empty() {
        annotations.push(format!("diagnostics: {}", report.diagnostics.len()));
    }
    if !report.paths.missing_paths.is_empty() {
        annotations.push(format!(
            "missing paths: {}",
            report.paths.missing_paths.len()
        ));
    }
    if !annotations.is_empty() {
        let _ = writeln!(out, "{}", annotations.join("  ·  "));
    }
}

/// Format the ignored-path count that follows the file count on the card.
///
/// `report` supplies the ignored paths.
/// Returns the count after `ignored:` in parentheses with a leading space, or an empty string when nothing was ignored.
fn ignored_count_label(report: &AnalysisReport) -> String {
    if report.paths.ignored_paths.is_empty() {
        String::new()
    } else {
        format!(" (ignored: {})", report.paths.ignored_paths.len())
    }
}

/// Write the hint lines that tell the user how to scan ignored paths, see baseline-suppressed findings, or start a baseline.
///
/// `out` receives the hints and `report` decides them; ignored paths add the `--include-ignored` hint.
/// A baseline that suppressed findings adds the `--no-baseline` hint, and no baseline with findings adds the `--generate-baseline` tip.
fn render_scan_guidance(out: &mut String, report: &AnalysisReport) {
    if !report.paths.ignored_paths.is_empty() {
        let _ = writeln!(
            out,
            "Ignored paths skipped by Git/config ignores; pass --include-ignored to scan them."
        );
    }
    match &report.baseline {
        Some(baseline) if baseline.suppressed > 0 => {
            let _ = writeln!(
                out,
                "Unsuppressed view: run `gruff-rs analyse --no-baseline`."
            );
        }
        None if report.summary.total > 0 => {
            let _ = writeln!(
                out,
                "Tip: run `gruff-rs analyse --generate-baseline` to accept today's findings as the starting point."
            );
        }
        _ => {}
    }
}

/// Format a run time for the card in the unit that suits its size.
///
/// `duration_ms` is the run time in milliseconds.
/// Returns whole milliseconds below one second, seconds to two decimals below a minute, and otherwise minutes with zero-padded seconds.
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

/// Shorten a project root under the home directory to a `~` path for display.
///
/// `project_root` is the root as the report records it.
/// Returns `~` for the home directory, `~` plus the remainder for a path below it, and the root unchanged otherwise or with `HOME` unset or empty.
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

/// Write the Pillars section with one aligned row per pillar giving its grade, score and severity counts.
///
/// `out` receives the section and `pillars` holds the digest rows in display order; an empty slice prints `(none)`.
fn render_pillars_text(out: &mut String, pillars: &[PillarDigest]) {
    out.push_str("Pillars\n");
    if pillars.is_empty() {
        out.push_str("  (none)\n");
        return;
    }

    let name_width = pillars
        .iter()
        .map(|pillar| pillar_label(pillar.pillar).len())
        .max()
        .unwrap_or(0);
    let count_width = pillars
        .iter()
        .flat_map(|pillar| [pillar.findings, pillar.advisory, pillar.warning])
        .map(digit_width)
        .max()
        .unwrap_or(1);

    for pillar in pillars {
        let _ = writeln!(
            out,
            "  {name:<name_width$} {grade} {score:>6} findings={findings:<count_width$}   advisory={advisory:<count_width$}   warning={warning:<count_width$}   error={error}",
            name = pillar_label(pillar.pillar),
            name_width = name_width,
            grade = pillar.grade.as_deref().unwrap_or("n/a"),
            score = score_text(pillar.score),
            findings = pillar.findings,
            count_width = count_width,
            advisory = pillar.advisory,
            warning = pillar.warning,
            error = pillar.error,
        );
    }
}

/// Count the decimal digits of a number so the summary columns line up.
///
/// `value` is the number to measure.
/// Returns its digit count, which is 1 for zero.
fn digit_width(value: usize) -> usize {
    value.checked_ilog10().map_or(1, |log| log as usize + 1)
}

/// Write the Top rules section with each rule's count, id, severity, confidence and description in aligned columns.
///
/// `out` receives the section and `rules` holds the digest rows in display order; an empty slice prints `(none)`.
fn render_rules_text(out: &mut String, rules: &[RuleDigest]) {
    out.push_str("Top rules\n");
    if rules.is_empty() {
        out.push_str("  (none)\n");
        return;
    }
    let id_width = rules
        .iter()
        .map(|rule| rule.rule_id.len())
        .max()
        .unwrap_or(0);
    let count_width = rules
        .iter()
        .map(|rule| digit_width(rule.count))
        .max()
        .unwrap_or(1);
    for rule in rules {
        let severity = match rule.severity {
            Some(Severity::Advisory) => "advisory",
            Some(Severity::Warning) => "warning",
            Some(Severity::Error) => "error",
            None => "",
        };
        let confidence = match rule.confidence {
            Some(Confidence::Low) => "low",
            Some(Confidence::Medium) => "medium",
            Some(Confidence::High) => "high",
            None => "",
        };
        let description = rule.description.unwrap_or("").trim_end_matches(' ');
        let _ = writeln!(
            out,
            "  {count:>count_width$}  {id:<id_width$}  {severity:<8}  {confidence:<6}  {description}",
            count = rule.count,
            count_width = count_width,
            id = rule.rule_id,
            id_width = id_width,
        );
    }
}

/// Write the Top file offenders section with each file's finding count, score and grade.
///
/// `out` receives the section and `files` holds the digest rows in display order; an empty slice prints `(none)`.
fn render_files_text(out: &mut String, files: &[FileDigest]) {
    out.push_str("Top file offenders\n");
    if files.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for file in files {
            let _ = writeln!(
                out,
                "  {:<48}  findings={:<4}  score={:>6}  grade={}",
                file.file_path,
                file.findings,
                score_text(file.score),
                file.grade.as_deref().unwrap_or("n/a"),
            );
        }
    }
}
