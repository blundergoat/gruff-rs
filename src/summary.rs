use crate::{
    grade, pillar_label,
    rules::{builtin_registry, RuleRegistry},
    scoring::top_file_scores_with_limit,
    AnalysisReport, Confidence, Finding, Pillar, PillarScore, RuleDelta, Severity, SummaryFormat,
    SCORE_PILLARS,
};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt::Write as _;

const SCHEMA_VERSION: &str = "gruff.summary.v2";
const RULE_DELTA_BLOCK_LIMIT: usize = 5;

/// Render a compact summary view from a full analysis report.
pub(crate) fn render(
    report: &AnalysisReport,
    top: usize,
    format: SummaryFormat,
    duration_ms: u128,
) -> String {
    let digest = SummaryDigest::build(report, top);
    match format {
        SummaryFormat::Text => render_text(report, &digest, duration_ms),
        SummaryFormat::Json => render_json(report, &digest),
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
    pub(crate) grade: String,
    pub(crate) score: f64,
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
    score: f64,
    grade: String,
}

impl SummaryDigest {
    fn build(report: &AnalysisReport, top: usize) -> Self {
        SummaryDigest {
            pillars: pillar_digests(report),
            top_rules: top_rule_digests(report, top),
            top_files: top_file_digests(report, top),
            per_rule_deltas: report.per_rule_deltas.clone(),
        }
    }
}

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
        grade: grade(pillar_score.score),
        score: pillar_score.score,
        applicable: SCORE_PILLARS.contains(&pillar_score.pillar),
        findings: pillar_score.findings,
        advisory,
        warning,
        error,
        penalty: pillar_score.penalty,
    }
}

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

fn first_sentence(description: &'static str) -> &'static str {
    match description.find(". ") {
        Some(end) => &description[..=end],
        None => description,
    }
}

fn top_file_digests(report: &AnalysisReport, top: usize) -> Vec<FileDigest> {
    top_file_scores_with_limit(&report.findings, top)
        .iter()
        .map(|file| FileDigest {
            file_path: file.file_path.to_string(),
            findings: file.findings,
            score: file.score,
            grade: grade(file.score),
        })
        .collect()
}

fn render_text(report: &AnalysisReport, digest: &SummaryDigest, duration_ms: u128) -> String {
    let mut out = String::new();
    render_scan_card(&mut out, report, duration_ms, |out| {
        rule_delta_blocks::render_text(out, digest.per_rule_deltas.as_deref());
    });
    out.push('\n');
    render_pillars_text(&mut out, &digest.pillars);
    out.push('\n');
    render_rules_text(&mut out, &digest.top_rules);
    out.push('\n');
    render_files_text(&mut out, &digest.top_files);
    out.trim_end_matches('\n').to_string()
}

// ADR-014 per-rule delta blocks in the compact summary view. Surfaced when
// a baseline or diff comparison context populated `per_rule_deltas`. Same
// shape and ordering as the analyse text reporter (absolute net DESC,
// rule_id ASC, capped at five entries, zero-net rules dropped).
mod rule_delta_blocks {
    use super::{RuleDelta, RULE_DELTA_BLOCK_LIMIT};
    use std::fmt::Write as _;

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

// `mid` runs between the header line and the Score line so callers can
// inject content there (per-rule deltas per ADR-014 in the comparison
// case). When the caller has nothing to inject, pass a no-op closure.
fn render_scan_card(
    out: &mut String,
    report: &AnalysisReport,
    duration_ms: u128,
    mid: impl FnOnce(&mut String),
) {
    let _ = writeln!(
        out,
        "{} {}  ·  project: {}  ·  files: {}{}  ·  duration: {}",
        report.tool.name,
        report.tool.version,
        display_project_root(&report.run.project_root),
        report.paths.analysed_files,
        ignored_count_label(report),
        format_duration(duration_ms),
    );
    mid(out);
    let mut score_line = format!(
        "Score: {:.1} ({})  ·  Findings: {} error · {} warning · {} advisory",
        report.score.composite,
        report.score.grade,
        report.summary.error,
        report.summary.warning,
        report.summary.advisory,
    );
    if let Some(baseline) = &report.baseline {
        if baseline.generated {
            let _ = write!(score_line, "  ·  baseline: generated");
        } else {
            let _ = write!(
                score_line,
                "  ·  baseline: {} new, {} unchanged, {} resolved",
                baseline.new_count, baseline.unchanged_count, baseline.absent_count
            );
        }
    }
    if !report.diagnostics.is_empty() {
        let _ = write!(score_line, "  ·  diagnostics: {}", report.diagnostics.len());
    }
    if !report.paths.missing_paths.is_empty() {
        let _ = write!(
            score_line,
            "  ·  missing paths: {}",
            report.paths.missing_paths.len()
        );
    }
    out.push_str(&score_line);
    out.push('\n');
    render_scan_guidance(out, report);
}

fn ignored_count_label(report: &AnalysisReport) -> String {
    if report.paths.ignored_paths.is_empty() {
        String::new()
    } else {
        format!("  ·  ignored: {}", report.paths.ignored_paths.len())
    }
}

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
            "  {name:<name_width$} {grade} {score:>6.2} findings={findings:<count_width$}   advisory={advisory:<count_width$}   warning={warning:<count_width$}   error={error}",
            name = pillar_label(pillar.pillar),
            name_width = name_width,
            grade = pillar.grade,
            score = pillar.score,
            findings = pillar.findings,
            count_width = count_width,
            advisory = pillar.advisory,
            warning = pillar.warning,
            error = pillar.error,
        );
    }
}

fn digit_width(value: usize) -> usize {
    value.checked_ilog10().map_or(1, |log| log as usize + 1)
}

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

fn render_files_text(out: &mut String, files: &[FileDigest]) {
    out.push_str("Top file offenders\n");
    if files.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for file in files {
            let _ = writeln!(
                out,
                "  {:<48}  findings={:<4}  score={:>6.2}  grade={}",
                file.file_path, file.findings, file.score, file.grade,
            );
        }
    }
}

fn render_json(report: &AnalysisReport, digest: &SummaryDigest) -> String {
    let mut value = json!({
        "schemaVersion": SCHEMA_VERSION,
        "tool": report.tool,
        "run": report.run,
        "summary": report.summary,
        "pillars": digest.pillars,
        "topRules": digest.top_rules,
        "topFiles": digest.top_files,
    });
    if let Some(deltas) = digest.per_rule_deltas.as_ref() {
        value
            .as_object_mut()
            .expect("summary root is an object")
            .insert(
                "perRuleDeltas".to_string(),
                serde_json::to_value(deltas).expect("rule deltas serialize"),
            );
    }
    serde_json::to_string_pretty(&value).expect("summary serializes")
}
