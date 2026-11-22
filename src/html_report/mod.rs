//! Build the HTML report shown by `report --format html` and the browser dashboard.
//!
//! Use the scan's findings, score, and requested scope to show where a reviewer can start looking.
//! Render finding text and paths as page content so scanned source cannot supply HTML markup.

use crate::{
    grade, summary::pillar_digests, AnalysisReport, FileScore, Finding, Pillar, RequestedScope,
    Severity,
};

mod sections;
mod styles;

pub(crate) const SCHEMA_VERSION: &str = "gruff.analysis.v3";
pub(crate) const DISTRIBUTION_BUCKETS: [DistributionBucket; 5] = [
    DistributionBucket::new("1-5", ""),
    DistributionBucket::new("6-10", ""),
    DistributionBucket::new("11-15", "warn"),
    DistributionBucket::new("16-20", "fail"),
    DistributionBucket::new("21+", "fail"),
];

/// Render the full HTML inspection report for the given analysis result.
///
/// `report` is the analysis result and `scope` is the requested scope, both carried into the `ReportView` the page sections read.
/// Returns the complete HTML document as a string.
pub(crate) fn render(report: &AnalysisReport, scope: &RequestedScope) -> String {
    let view = ReportView::build(report, scope);
    sections::document(&view)
}

/// Gather what the reviewer sees in the HTML report or dashboard.
///
/// Page sections share one view of the scope, overall grade, and ranked findings.
/// The formatting fields let each section show the same result without calculating it again.
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
}

/// Show one quality area's grade and counts on the report page.
///
/// The score can be absent when the run cannot grade that area.
/// Severity counts tell a reviewer what each area contains before inspecting individual findings.
pub(crate) struct PillarRow {
    pub(crate) pillar: Pillar,
    pub(crate) score: Option<f64>,
    pub(crate) grade_letter: String,
    pub(crate) grade_class: char,
    pub(crate) findings: usize,
    pub(crate) advisories: usize,
    pub(crate) warnings: usize,
    pub(crate) errors: usize,
}

/// Show one ranked file in the report's top-offender section.
///
/// The file result provides the path and finding count a reviewer needs.
/// The display grade uses the same styling as the other score sections.
pub(crate) struct OffenderRow<'a> {
    pub(crate) file: &'a FileScore,
    pub(crate) grade_letter: String,
    pub(crate) grade_class: char,
}

/// One bar in the displayed complexity distribution.
///
/// The label is the complexity range a reviewer sees. The count determines the bar size.
/// The class controls the visual distinction between ranges.
pub(crate) struct DistributionBar {
    pub(crate) label: &'static str,
    pub(crate) count: usize,
    pub(crate) class: &'static str,
}

/// Define one complexity range before grouping the run's findings.
///
/// Its label becomes a bar label in the report.
/// Its class lets the report mark flagged ranges consistently.
pub(crate) struct DistributionBucket {
    pub(crate) label: &'static str,
    pub(crate) class: &'static str,
}

impl DistributionBucket {
    /// Pairs a cyclomatic-complexity bucket label with its class name, usable in a const such as `DISTRIBUTION_BUCKETS`.
    ///
    /// `label` is the range shown, such as `6-10`, and `class` is the class name copied onto the bucket's bar, empty for an unflagged bucket.
    /// Returns the bucket holding both.
    const fn new(label: &'static str, class: &'static str) -> Self {
        Self { label, class }
    }
}

impl<'a> ReportView<'a> {
    /// Precomputes the grade, verdict, table rows and distribution that the HTML report sections display.
    ///
    /// `report` supplies the score, findings and summary, and `scope` is stored unchanged.
    /// A run with no composite score gets the grade `n/a` and the text `not evaluated` rather than a number.
    /// Returns the view holding those values and the total finding count.
    fn build(report: &'a AnalysisReport, scope: &'a RequestedScope) -> Self {
        let composite = report.score.composite;
        // A run that evaluated nothing shows no number in the stamp, so an empty scan cannot read
        // as perfect; "n/a" is the same absence marker every other gruff-rs surface uses.
        let grade_letter = composite.map(grade).unwrap_or_else(|| "n/a".to_string());
        let grade_class = grade_class_letter(&grade_letter);
        let composite_text = match composite {
            Some(value) => format!("{value:.2} / 100"),
            None => "not evaluated".to_string(),
        };
        let summary_line = verdict_summary(&report.findings, &report.summary);

        let pillar_rows = build_pillar_rows(report);
        let offenders = &report.score.top_offenders;
        let offender_rows = build_offender_rows(
            &offenders[..offenders.len().min(crate::scoring::TOP_OFFENDER_LIMIT)],
        );
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
        }
    }
}

/// Builds the pillar table rows, one per digest in the order `pillar_digests` gives them.
///
/// `report` is the analysis result to digest; a pillar without a grade gets the letter `n/a` and the class `n`.
/// Returns the rows with each pillar's score, grade and finding counts by severity.
fn build_pillar_rows(report: &AnalysisReport) -> Vec<PillarRow> {
    pillar_digests(report)
        .into_iter()
        .map(|digest| {
            // A pillar that evaluated nothing has no letter, and 'n' is the class the helper
            // already returns for anything outside the A-F bands.
            let letter = digest.grade.unwrap_or_else(|| "n/a".to_string());
            let class = grade_class_letter(&letter);
            PillarRow {
                pillar: digest.pillar,
                score: digest.score,
                grade_letter: letter,
                grade_class: class,
                findings: digest.findings,
                advisories: digest.advisory,
                warnings: digest.warning,
                errors: digest.error,
            }
        })
        .collect()
}

/// Builds the top-offender table rows, pairing each file score with its grade letter and class.
///
/// `offenders` are the report's top-offender file scores, kept in their given order; a file with no score gets the letter `n/a`.
/// Returns one row per offender, borrowing its file score.
fn build_offender_rows(offenders: &[FileScore]) -> Vec<OffenderRow<'_>> {
    offenders
        .iter()
        .map(|file| {
            let letter = file.score.map(grade).unwrap_or_else(|| "n/a".to_string());
            let class = grade_class_letter(&letter);
            OffenderRow {
                file,
                grade_letter: letter,
                grade_class: class,
            }
        })
        .collect()
}

/// Builds the cyclomatic-complexity histogram bars and the sentence that summarises them.
///
/// `findings` are searched for `complexity.cyclomatic` findings, which are counted into the `DISTRIBUTION_BUCKETS` ranges.
/// Returns one bar per bucket with its label, count and class, together with the summary from `distribution_summary`.
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

/// Counts cyclomatic-complexity findings into the five histogram buckets by their recorded complexity.
///
/// `findings` may hold any rule; a finding without a cyclomatic value is skipped.
/// Returns the per-bucket counts in `DISTRIBUTION_BUCKETS` order.
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

/// Reads the complexity a cyclomatic-complexity finding recorded in its `complexity` metadata.
///
/// Returns the value when `finding` has the rule id `complexity.cyclomatic`, and None otherwise or when it is missing or not an unsigned integer.
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

/// Maps a cyclomatic complexity onto its histogram bucket.
///
/// `value` is the complexity recorded on the finding.
/// Returns 0 for up to 5, 1 for 6-10, 2 for 11-15, 3 for 16-20 and 4 for anything higher, matching `DISTRIBUTION_BUCKETS`.
fn cyclomatic_bucket_index(value: u64) -> usize {
    match value {
        0..=5 => 0,
        6..=10 => 1,
        11..=15 => 2,
        16..=20 => 3,
        _ => 4,
    }
}

/// Builds the histogram's summary sentence, which counts methods above cyclomatic complexity 10.
///
/// `counts` are the per-bucket counts in `DISTRIBUTION_BUCKETS` order; only the last three buckets, all above 10, are summed.
/// Returns a no-methods sentence when they are all zero, and otherwise the total with its split across the 11-15, 16-20 and 21+ ranges.
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

/// Builds the report's one-sentence verdict on how many warning and error findings there are and how many pillars they span.
///
/// `summary` supplies the warning and error totals, and `findings` supplies the distinct pillars of the warning and error findings.
/// Returns the verdict sentence, or a no-findings sentence when both totals are zero.
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

/// Names a severity in lowercase for the HTML report.
///
/// `severity` is the finding severity to name.
/// Returns `advisory`, `warning` or `error`.
pub(crate) fn severity_text(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// Turns a grade letter into the one-letter class code the HTML report uses for it.
///
/// `grade_letter` is a grade such as `B` or `n/a`; only its first character is read.
/// Returns that character in lowercase when it is a, b, c, d or f, and `n` for anything else, including `n/a` and an empty string.
pub(crate) fn grade_class_letter(grade_letter: &str) -> char {
    grade_letter
        .chars()
        .next()
        .map(|character| character.to_ascii_lowercase())
        .filter(|character| matches!(character, 'a' | 'b' | 'c' | 'd' | 'f'))
        .unwrap_or('n')
}
