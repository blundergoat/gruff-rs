use crate::{
    grade, AnalysisReport, FileScore, Finding, Pillar, PillarScore, RequestedScope, Severity,
};

mod sections;
mod styles;

pub(crate) const SCHEMA_VERSION: &str = "gruff.analysis.v1";
pub(crate) const DISTRIBUTION_BUCKETS: [DistributionBucket; 5] = [
    DistributionBucket::new("1-5", ""),
    DistributionBucket::new("6-10", ""),
    DistributionBucket::new("11-15", "warn"),
    DistributionBucket::new("16-20", "fail"),
    DistributionBucket::new("21+", "fail"),
];

/// Render the full HTML inspection report for the given analysis result.
pub(crate) fn render(report: &AnalysisReport, scope: &RequestedScope) -> String {
    let view = ReportView::build(report, scope);
    sections::document(&view)
}

pub(crate) struct ReportView<'a> {
    pub(crate) report: &'a AnalysisReport,
    pub(crate) scope: &'a RequestedScope,
    pub(crate) grade_letter: String,
    pub(crate) grade_class: char,
    pub(crate) composite_text: String,
    pub(crate) verdict_summary: String,
    pub(crate) pillar_rows: Vec<PillarRow>,
    pub(crate) offender_rows: Vec<OffenderRow<'a>>,
    pub(crate) distribution: Vec<DistributionBar>,
    pub(crate) distribution_summary: String,
    pub(crate) findings_total: usize,
    pub(crate) pillar_for_mutation_missing: bool,
}

pub(crate) struct PillarRow {
    pub(crate) pillar: Pillar,
    pub(crate) score: f64,
    pub(crate) grade_letter: String,
    pub(crate) grade_class: char,
    pub(crate) findings: usize,
    pub(crate) advisories: usize,
    pub(crate) warnings: usize,
    pub(crate) errors: usize,
}

pub(crate) struct OffenderRow<'a> {
    pub(crate) file: &'a FileScore,
    pub(crate) grade_letter: String,
    pub(crate) grade_class: char,
}

pub(crate) struct DistributionBar {
    pub(crate) label: &'static str,
    pub(crate) count: usize,
    pub(crate) class: &'static str,
}

pub(crate) struct DistributionBucket {
    pub(crate) label: &'static str,
    pub(crate) class: &'static str,
}

impl DistributionBucket {
    const fn new(label: &'static str, class: &'static str) -> Self {
        Self { label, class }
    }
}

impl<'a> ReportView<'a> {
    fn build(report: &'a AnalysisReport, scope: &'a RequestedScope) -> Self {
        let composite = report.score.composite;
        let grade_letter = grade(composite);
        let grade_class = grade_class_letter(&grade_letter);
        let composite_text = format!("{:.2} / 100", composite);
        let summary_line = verdict_summary(&report.findings, &report.summary);

        let pillar_rows = build_pillar_rows(&report.score.pillars, &report.findings);
        let offender_rows = build_offender_rows(&report.score.top_offenders);
        let (distribution, distribution_summary) = build_distribution(&report.findings);

        ReportView {
            report,
            scope,
            grade_letter,
            grade_class,
            composite_text,
            verdict_summary: summary_line,
            pillar_rows,
            offender_rows,
            distribution,
            distribution_summary,
            findings_total: report.findings.len(),
            pillar_for_mutation_missing: true,
        }
    }
}

fn build_pillar_rows(pillars: &[PillarScore], findings: &[Finding]) -> Vec<PillarRow> {
    pillars
        .iter()
        .map(|pillar| {
            let mut advisories = 0usize;
            let mut warnings = 0usize;
            let mut errors = 0usize;
            for finding in findings.iter().filter(|f| f.pillar == pillar.pillar) {
                match finding.severity {
                    Severity::Advisory => advisories += 1,
                    Severity::Warning => warnings += 1,
                    Severity::Error => errors += 1,
                }
            }
            let letter = grade(pillar.score);
            let class = grade_class_letter(&letter);
            PillarRow {
                pillar: pillar.pillar,
                score: pillar.score,
                grade_letter: letter,
                grade_class: class,
                findings: pillar.findings,
                advisories,
                warnings,
                errors,
            }
        })
        .collect()
}

fn build_offender_rows(offenders: &[FileScore]) -> Vec<OffenderRow<'_>> {
    offenders
        .iter()
        .map(|file| {
            let letter = grade(file.score);
            let class = grade_class_letter(&letter);
            OffenderRow {
                file,
                grade_letter: letter,
                grade_class: class,
            }
        })
        .collect()
}

fn build_distribution(findings: &[Finding]) -> (Vec<DistributionBar>, String) {
    let counts = cyclomatic_distribution_counts(findings);
    let bars = DISTRIBUTION_BUCKETS
        .iter()
        .zip(counts.iter())
        .map(|(bucket, count)| DistributionBar {
            label: bucket.label,
            count: *count,
            class: bucket.class,
        })
        .collect();

    (bars, distribution_summary(&counts))
}

fn cyclomatic_distribution_counts(findings: &[Finding]) -> [usize; 5] {
    let mut counts = [0usize; 5];
    for finding in findings {
        let Some(value) = cyclomatic_value(finding) else {
            continue;
        };
        counts[cyclomatic_bucket_index(value)] += 1;
    }
    counts
}

fn cyclomatic_value(finding: &Finding) -> Option<u64> {
    (finding.rule_id == "complexity.cyclomatic")
        .then(|| {
            finding
                .metadata
                .get("complexity")
                .and_then(|value| value.as_u64())
        })
        .flatten()
}

fn cyclomatic_bucket_index(value: u64) -> usize {
    match value {
        0..=5 => 0,
        6..=10 => 1,
        11..=15 => 2,
        16..=20 => 3,
        _ => 4,
    }
}

fn distribution_summary(counts: &[usize; 5]) -> String {
    let moderate = counts[2];
    let high = counts[3];
    let severe = counts[4];
    let exceeds = moderate + high + severe;
    if exceeds == 0 {
        "No methods exceed cyclomatic complexity 10 in this scan.".to_string()
    } else {
        format!(
            "{exceeds} {noun} {verb} cyclomatic complexity 10 ({moderate} in 11-15, {high} in 16-20, {severe} at 21+).",
            noun = if exceeds == 1 { "method" } else { "methods" },
            verb = if exceeds == 1 { "exceeds" } else { "exceed" },
        )
    }
}

fn verdict_summary(findings: &[Finding], summary: &crate::Summary) -> String {
    let threshold = summary.warning + summary.error;
    if threshold == 0 {
        return "No warning or error findings flagged.".to_string();
    }
    let mut pillars: std::collections::BTreeSet<Pillar> = std::collections::BTreeSet::new();
    for finding in findings {
        if matches!(finding.severity, Severity::Warning | Severity::Error) {
            pillars.insert(finding.pillar);
        }
    }
    format!(
        "{threshold} {finding_noun} at warning or error severity across {count} {pillar_noun}.",
        threshold = threshold,
        finding_noun = if threshold == 1 {
            "finding"
        } else {
            "findings"
        },
        count = pillars.len(),
        pillar_noun = if pillars.len() == 1 {
            "pillar"
        } else {
            "pillars"
        },
    )
}

pub(crate) fn severity_text(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

pub(crate) fn pillar_label(pillar: Pillar) -> &'static str {
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

pub(crate) fn grade_class_letter(grade_letter: &str) -> char {
    grade_letter
        .chars()
        .next()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| matches!(c, 'a' | 'b' | 'c' | 'd' | 'f'))
        .unwrap_or('n')
}
