use crate::{grade, AnalysisReport, Pillar, Severity, SummaryFormat};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt::Write as _;

const SCHEMA_VERSION: &str = "gruff.summary.v1";

/// Render a compact summary view from a full analysis report.
pub(crate) fn render(report: &AnalysisReport, top: usize, format: SummaryFormat) -> String {
    let digest = SummaryDigest::build(report, top);
    match format {
        SummaryFormat::Text => render_text(&digest),
        SummaryFormat::Json => render_json(report, &digest),
    }
}

struct SummaryDigest {
    pillars: Vec<PillarDigest>,
    top_rules: Vec<RuleDigest>,
    top_files: Vec<FileDigest>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PillarDigest {
    pillar: Pillar,
    findings: usize,
    advisory: usize,
    warning: usize,
    error: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuleDigest {
    rule_id: String,
    count: usize,
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
        }
    }
}

fn pillar_digests(report: &AnalysisReport) -> Vec<PillarDigest> {
    let mut pillars: BTreeMap<Pillar, PillarDigest> = BTreeMap::new();
    for finding in &report.findings {
        let entry = pillars.entry(finding.pillar).or_insert(PillarDigest {
            pillar: finding.pillar,
            findings: 0,
            advisory: 0,
            warning: 0,
            error: 0,
        });
        entry.findings += 1;
        match finding.severity {
            Severity::Advisory => entry.advisory += 1,
            Severity::Warning => entry.warning += 1,
            Severity::Error => entry.error += 1,
        }
    }
    pillars.into_values().collect()
}

fn top_rule_digests(report: &AnalysisReport, top: usize) -> Vec<RuleDigest> {
    let mut rule_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in &report.findings {
        *rule_counts.entry(&finding.rule_id).or_insert(0) += 1;
    }
    let mut top_rules: Vec<RuleDigest> = rule_counts
        .into_iter()
        .map(|(rule_id, count)| RuleDigest {
            rule_id: rule_id.to_string(),
            count,
        })
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

fn top_file_digests(report: &AnalysisReport, top: usize) -> Vec<FileDigest> {
    report
        .score
        .top_offenders
        .iter()
        .take(top)
        .map(|file| FileDigest {
            file_path: file.file_path.to_string(),
            findings: file.findings,
            score: file.score,
            grade: grade(file.score),
        })
        .collect()
}

fn render_text(digest: &SummaryDigest) -> String {
    let mut out = String::new();
    render_pillars_text(&mut out, &digest.pillars);
    out.push('\n');
    render_rules_text(&mut out, &digest.top_rules);
    out.push('\n');
    render_files_text(&mut out, &digest.top_files);
    out.trim_end_matches('\n').to_string()
}

fn render_pillars_text(out: &mut String, pillars: &[PillarDigest]) {
    out.push_str("Pillars\n");
    if pillars.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for pillar in pillars {
            let _ = writeln!(
                out,
                "  {:<16}  findings={:<4}  err={:<3}  warn={:<3}  adv={:<3}",
                pillar_label(pillar.pillar),
                pillar.findings,
                pillar.error,
                pillar.warning,
                pillar.advisory,
            );
        }
    }
}

fn render_rules_text(out: &mut String, rules: &[RuleDigest]) {
    out.push_str("Top rules\n");
    if rules.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for rule in rules {
            let _ = writeln!(out, "  {:<48}  {}", rule.rule_id, rule.count);
        }
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
    let value = json!({
        "schemaVersion": SCHEMA_VERSION,
        "tool": report.tool,
        "run": report.run,
        "summary": report.summary,
        "pillars": digest.pillars,
        "topRules": digest.top_rules,
        "topFiles": digest.top_files,
    });
    serde_json::to_string_pretty(&value).expect("summary serializes")
}

fn pillar_label(pillar: Pillar) -> &'static str {
    match pillar {
        Pillar::Size => "size",
        Pillar::Complexity => "complexity",
        Pillar::DeadCode => "dead-code",
        Pillar::Waste => "waste",
        Pillar::Naming => "naming",
        Pillar::Documentation => "documentation",
        Pillar::Modernisation => "modernisation",
        Pillar::Security => "security",
        Pillar::SensitiveData => "sensitive-data",
        Pillar::TestQuality => "test-quality",
        Pillar::Design => "design",
    }
}
