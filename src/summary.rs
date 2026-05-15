use crate::{grade, AnalysisReport, Pillar, Severity, SummaryFormat};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;

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
        let pillars: Vec<PillarDigest> = pillars.into_values().collect();

        let mut rule_counts: BTreeMap<String, usize> = BTreeMap::new();
        for finding in &report.findings {
            *rule_counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
        }
        let mut top_rules: Vec<RuleDigest> = rule_counts
            .into_iter()
            .map(|(rule_id, count)| RuleDigest { rule_id, count })
            .collect();
        top_rules.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });
        top_rules.truncate(top);

        let top_files: Vec<FileDigest> = report
            .score
            .top_offenders
            .iter()
            .take(top)
            .map(|file| FileDigest {
                file_path: file.file_path.clone(),
                findings: file.findings,
                score: file.score,
                grade: grade(file.score),
            })
            .collect();

        SummaryDigest {
            pillars,
            top_rules,
            top_files,
        }
    }
}

fn render_text(digest: &SummaryDigest) -> String {
    let mut out = String::new();
    out.push_str("Pillars\n");
    if digest.pillars.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for pillar in &digest.pillars {
            out.push_str(&format!(
                "  {:<16}  findings={:<4}  err={:<3}  warn={:<3}  adv={:<3}\n",
                pillar_label(pillar.pillar),
                pillar.findings,
                pillar.error,
                pillar.warning,
                pillar.advisory,
            ));
        }
    }
    out.push('\n');

    out.push_str("Top rules\n");
    if digest.top_rules.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for rule in &digest.top_rules {
            out.push_str(&format!("  {:<48}  {}\n", rule.rule_id, rule.count));
        }
    }
    out.push('\n');

    out.push_str("Top file offenders\n");
    if digest.top_files.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for file in &digest.top_files {
            out.push_str(&format!(
                "  {:<48}  findings={:<4}  score={:>6.2}  grade={}\n",
                file.file_path, file.findings, file.score, file.grade,
            ));
        }
    }

    out.trim_end_matches('\n').to_string()
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
