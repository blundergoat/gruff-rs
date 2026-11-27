//! Turn evaluated files and their findings into a composite score, pillar scores, and ranked files.
//!
//! Use the same rule weights across those views so a caller can see what drove the grade.
//! If no Rust files qualify for scoring, the report shows that there is no grade to interpret.

use super::*;

/// Return the count of Rust `files` that could be evaluated, excluding failures in `diagnostics`.
pub(crate) fn evaluated_rust_files(files: &[SourceFile], diagnostics: &[RunDiagnostic]) -> usize {
    let failed: BTreeSet<_> = diagnostics
        .iter()
        .filter(|diagnostic| {
            matches!(
                diagnostic.diagnostic_type.as_str(),
                "read-error" | "parse-error"
            )
        })
        .filter_map(|diagnostic| diagnostic.file_path.as_deref())
        .collect();
    files
        .iter()
        .filter(|file| file.is_rust && !failed.contains(file.display_path.as_str()))
        .count()
}

/// Count findings by severity for the report summary.
///
/// `findings` is the full list to tally; nothing is filtered here.
///
/// Returns a `Summary` with the advisory, warning, and error counts and `total` set to the length of `findings`.
pub(crate) fn summarize(findings: &[Finding]) -> Summary {
    let advisory = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Advisory)
        .count();
    let warning = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Warning)
        .count();
    let error = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .count();
    Summary {
        advisory,
        warning,
        error,
        total: findings.len(),
    }
}

/// Give `analyse` and `summary` the same two-line score and finding block, with each line terminated by `\n`.
///
/// ```text
/// Composite: <GRADE> (<score> / 100)
/// Findings: <total> total · <e> error · <w> warning · <a> advisory
/// ```
///
/// The score carries two decimals, the findings tally is error-first, and the
/// separator is the literal middot `·` (U+00B7).
///
/// `out` receives the two lines, appended to its existing text, and `report` supplies the composite score, grade, and finding tallies.
/// When the report has no grade or no composite score, the first line reads `Composite: n/a (nothing evaluated)` instead.
pub(crate) fn render_composite_block(out: &mut String, report: &AnalysisReport) {
    use std::fmt::Write as _;
    // A run that evaluated nothing has no composite; printing 100.00 would call an empty scan perfect.
    match (report.score.grade.as_deref(), report.score.composite) {
        (Some(grade), Some(composite)) => {
            let _ = writeln!(out, "Composite: {grade} ({composite:.2} / 100)");
        }
        _ => {
            let _ = writeln!(out, "Composite: n/a (nothing evaluated)");
        }
    }
    let _ = writeln!(
        out,
        "Findings: {} total · {} error · {} warning · {} advisory",
        report.summary.total, report.summary.error, report.summary.warning, report.summary.advisory,
    );
}

/// Keep the scoring curve aligned across Gruff ports so a reviewer can interpret the grade consistently.
/// `SCORE_FLOOR` limits a saturated pillar's effect. `DENSITY_SCALE` is the density halfway from 100 to the floor.
pub(crate) const SCORE_FLOOR: f64 = 50.0;
pub(crate) const DENSITY_SCALE: f64 = 0.1;

/// Apply the ratified pillar curve to one summed weight.
///
/// The curve is `floor + (100 - floor) / (1 + density / densityScale)`, where density is the weight
/// divided by the evaluated-file count. Dividing before transforming is what makes a duplicated
/// project score the same as the original: twice the findings over twice the code is one ratio.
///
/// Returns `None` when nothing was evaluated, because an empty scan has no health to report and a
/// number here would present it as perfect.
///
/// `weight` is the summed penalty for one pillar or file, and `evaluated_files` is the file count it is divided by.
/// A returned score is rounded to two decimals.
pub(crate) fn curve_score(weight: f64, evaluated_files: usize) -> Option<f64> {
    if evaluated_files == 0 {
        return None;
    }
    let density = weight / evaluated_files as f64;
    Some(round_score(
        SCORE_FLOOR + (100.0 - SCORE_FLOOR) / (1.0 + density / DENSITY_SCALE),
    ))
}

/// Render one optional score for a human view, at the ratified two decimals.
///
/// A run that evaluated nothing has no score, and every score this helper formats shows the same `n/a`
/// marker for it rather than a number that would read as a grade. Kept here so the render loops
/// call one helper instead of formatting inline.
///
/// `score` is the optional score to show, `None` when the run evaluated nothing.
///
/// Returns the score with exactly two decimals, or `n/a` for `None`.
pub(crate) fn score_text(score: Option<f64>) -> String {
    match score {
        Some(value) => format!("{value:.2}"),
        None => "n/a".to_string(),
    }
}

/// Round one score to the ratified two decimals, normalizing negative zero away because JSON
/// projection keeps it in some ports and not others.
///
/// `value` is a score or summed weight to round to the nearest hundredth.
///
/// Returns the rounded value, with a zero result returned as positive `0.0`.
pub(crate) fn round_score(value: f64) -> f64 {
    let rounded = (value * 100.0).round() / 100.0;
    if rounded == 0.0 {
        0.0
    } else {
        rounded
    }
}

/// Build the score section of an analysis report from its findings.
///
/// `findings` are the findings to weigh, and `config` decides which rules are left out of pillar penalties.
/// `evaluated_files` normalizes pillar penalties; file penalties use a denominator of one, and zero leaves every score and grade as `None`.
///
/// Returns pillar scores, the composite, the full file ranking, correlated clusters, and rule weights for the selected renderer.
pub(crate) fn score_report(
    findings: &[Finding],
    config: &Config,
    evaluated_files: usize,
) -> ScoreReport {
    let penalties = clustered_penalties(findings, config);
    let pillars = pillar_scores(findings, &penalties, evaluated_files);
    let composite = composite_score(&pillars);
    let top_offenders = rank_file_scores(findings, &penalties, evaluated_files);

    ScoreReport {
        composite,
        grade: composite.map(grade),
        evaluated_files,
        scored_pillars: pillars
            .iter()
            .filter(|pillar| pillar.score.is_some())
            .map(|pillar| pillar.pillar)
            .collect(),
        clusters: correlated_clusters(findings, &penalties),
        rule_attribution: rule_attribution(findings, &penalties),
        pillars,
        top_offenders,
    }
}

/// List correlated findings that counted as one scoring penalty.
///
/// The file and symbol tell the caller which code the rules agreed on.
/// The shared weight shows how much they changed the grade together.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScoreCluster {
    pub(crate) file: String,
    /// The symbol the members share; the cluster key is (file, symbol) with no line identity.
    pub(crate) symbol: String,
    pub(crate) rule_ids: Vec<String>,
    pub(crate) findings: usize,
    /// Total weight the cluster billed, which is its single worst member.
    pub(crate) weight: f64,
}

/// Attribute the score's penalty to a rule ID the caller can look up.
///
/// A finding still contributes to the count when config excludes its rule from scoring and leaves its weight at zero.
/// Use this attribution to explain which rules changed the grade most.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuleWeight {
    pub(crate) rule_id: String,
    pub(crate) findings: usize,
    /// Summed post-clustering weight this rule removed from the score.
    pub(crate) weight: f64,
}

/// List every correlated concept that billed one shared weight, sorted by file then symbol so two
/// runs over unchanged input publish the same bytes.
///
/// `findings` is the full finding list; only findings with a symbol and a rule in `CORRELATED_COMPLEXITY_RULES` can join a cluster.
/// `penalties` contains the weight already assigned to each finding, in matching order.
///
/// Returns one `ScoreCluster` per file and symbol with two or more such findings, or an empty list when none qualify.
/// Each cluster lists its rule ids sorted and a `weight` equal to its worst member's penalty, rounded to two decimals.
fn correlated_clusters(findings: &[Finding], penalties: &[f64]) -> Vec<ScoreCluster> {
    let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();

    for (index, finding) in findings.iter().enumerate() {
        let Some(symbol) = finding.symbol.as_deref() else {
            continue;
        };
        // A finding omitted from scores cannot reduce or share another rule's penalty, even on the same function.
        if penalties[index] == 0.0
            || !CORRELATED_COMPLEXITY_RULES.contains(&finding.rule_id.as_str())
        {
            continue;
        }
        groups
            .entry((finding.file_path.clone(), symbol.to_string()))
            .or_default()
            .push(index);
    }

    groups
        .into_iter()
        // A lone correlated finding billed its own full weight, so it is not a cluster to report.
        .filter(|(_, members)| members.len() >= 2)
        .map(|((file, symbol), members)| {
            let mut rule_ids: Vec<String> = members
                .iter()
                .map(|index| findings[*index].rule_id.clone())
                .collect();
            rule_ids.sort();
            ScoreCluster {
                file,
                symbol,
                findings: members.len(),
                weight: round_score(members.iter().map(|index| penalties[*index]).sum()),
                rule_ids,
            }
        })
        .collect()
}

/// Report each rule's summed post-clustering finding weight, sorted by rule identifier, including rules excluded from pillar penalties.
///
/// `findings` is the full finding list. `penalties` holds the weight each finding contributes after clustering.
///
/// Returns one `RuleWeight` per rule id with its finding count and summed weight rounded to two decimals, or an empty list for no findings.
fn rule_attribution(findings: &[Finding], penalties: &[f64]) -> Vec<RuleWeight> {
    let mut totals: BTreeMap<String, (usize, f64)> = BTreeMap::new();

    // Keep counts even at zero weight so a reviewer can see why a visible rule did not affect the grade.
    for (index, finding) in findings.iter().enumerate() {
        let entry = totals.entry(finding.rule_id.clone()).or_insert((0, 0.0));
        entry.0 += 1;
        entry.1 += penalties[index];
    }

    totals
        .into_iter()
        .map(|(rule_id, (findings, weight))| RuleWeight {
            rule_id,
            findings,
            weight: round_score(weight),
        })
        .collect()
}

/// Score each standard pillar, plus any other pillar a finding belongs to, from the clustered finding weights.
///
/// `findings` are grouped by pillar, and `penalties` contains their assigned weights in matching order.
/// `evaluated_files` divides each pillar's penalty before the curve is applied; zero leaves every row's score and grade as `None`.
///
/// Returns a `PillarScore` for every `SCORE_PILLARS` entry in order, even without findings, then for any other pillar a finding uses.
fn pillar_scores(
    findings: &[Finding],
    penalties: &[f64],
    evaluated_files: usize,
) -> Vec<PillarScore> {
    let weighted: Vec<(&Finding, f64)> = findings.iter().zip(penalties.iter().copied()).collect();
    let mut by_pillar: BTreeMap<Pillar, Vec<&(&Finding, f64)>> = BTreeMap::new();
    for entry in &weighted {
        by_pillar.entry(entry.0.pillar).or_default().push(entry);
    }

    let mut pillar_order: Vec<Pillar> = SCORE_PILLARS.to_vec();
    for pillar in by_pillar.keys() {
        if !pillar_order.contains(pillar) {
            pillar_order.push(*pillar);
        }
    }

    pillar_order
        .into_iter()
        .map(|pillar| pillar_score_row(pillar, by_pillar.get(&pillar), evaluated_files))
        .collect()
}

/// Score one pillar from its findings and their clustered weights.
///
/// `pillar` is the pillar being scored, and `pillar_findings` holds its findings paired with clustered weights, `None` when it has none.
/// `evaluated_files` is the file count the penalty is divided by.
///
/// Returns an applicable `PillarScore` whose score and grade are `None` when no files were evaluated.
/// Its rounded penalty skips excluded rules, but its finding count still includes them.
fn pillar_score_row(
    pillar: Pillar,
    pillar_findings: Option<&Vec<&(&Finding, f64)>>,
    evaluated_files: usize,
) -> PillarScore {
    let empty: Vec<&(&Finding, f64)> = Vec::new();
    let findings = pillar_findings.unwrap_or(&empty);
    let penalty: f64 = findings.iter().map(|(_, weight)| *weight).sum();
    let applicable = SCORE_PILLARS.contains(&pillar);
    let score = if applicable {
        curve_score(penalty, evaluated_files)
    } else {
        None
    };
    PillarScore {
        pillar,
        applicable,
        score,
        grade: score.map(grade),
        penalty: round_score(penalty),
        findings: findings.len(),
    }
}

/// Average the scored standard pillars into the project's composite score.
///
/// `pillars` are the pillar rows; only rows in `SCORE_PILLARS` that have a score count toward the average.
///
/// Returns the mean rounded to two decimals, or `None` when no standard pillar has a score.
pub(crate) fn composite_score(pillars: &[PillarScore]) -> Option<f64> {
    let scored: Vec<f64> = pillars
        .iter()
        .filter(|pillar| SCORE_PILLARS.contains(&pillar.pillar))
        .filter_map(|pillar| pillar.score)
        .collect();
    // No pillar had an opinion, so there is no composite. Returning 100.0 here is what let an empty
    // directory grade A before the M06 break.
    if scored.is_empty() {
        None
    } else {
        Some(round_score(
            scored.iter().sum::<f64>() / scored.len() as f64,
        ))
    }
}

/// Number of ranked files published in standard reports.
pub(crate) const TOP_OFFENDER_LIMIT: usize = 10;

/// Rank files by their clustered scoring penalties. Keep counts for visible findings in ranked files.
/// `findings` and `penalties` pair each finding with its weight. `evaluated_files` normalizes the penalty.
/// Returns files with positive penalties, ordered by worst score, then most findings, then path.
fn rank_file_scores(
    findings: &[Finding],
    penalties: &[f64],
    evaluated_files: usize,
) -> Vec<FileScore> {
    let mut file_counts: BTreeMap<String, (usize, f64)> = BTreeMap::new();
    // Use the same clustered weights as the composite so the file ranking points to what drove the grade.
    for (finding, weight) in findings.iter().zip(penalties) {
        let entry = file_counts
            .entry(finding.file_path.clone())
            .or_insert((0, 0.0));
        entry.0 += 1;
        entry.1 += weight;
    }
    let mut top_offenders: Vec<FileScore> = file_counts
        .into_iter()
        .filter(|(_, (_, penalty))| *penalty > 0.0)
        .map(|(file_path, (findings, penalty))| FileScore {
            file_path,
            // A file's density is its own weighted findings, so file and project scores share one
            // curve and a top-offender list cannot rank code by a rule the project grade never used.
            score: if evaluated_files == 0 {
                None
            } else {
                curve_score(penalty, 1)
            },
            penalty: round_score(penalty),
            findings,
        })
        .collect();
    top_offenders.sort_by(|left, right| {
        // An ungraded file sorts as if perfect, so a run that evaluated nothing ranks by findings.
        left.score
            .unwrap_or(100.0)
            .total_cmp(&right.score.unwrap_or(100.0))
            .then_with(|| right.findings.cmp(&left.findings))
            .then_with(|| left.file_path.cmp(&right.file_path))
    });
    top_offenders
}

/// Size and complexity rules that can describe the same underlying problem in one function.
/// Their findings remain visible, while the score counts one shared weight for that symbol.
pub(crate) const CORRELATED_COMPLEXITY_RULES: [&str; 5] = [
    "complexity.cognitive",
    "complexity.cyclomatic",
    "complexity.nesting-depth",
    "size.function-length",
    "size.parameter-count",
];

/// Weigh every finding, then share one weight across each correlated cluster.
///
/// Group by project-relative file and symbol so rules pointing at different lines of the same function can share a penalty.
/// Rust's unqualified symbols can also group same-named functions in one file. Qualifying them would change finding identity.
///
/// Each member of a cluster of two or more contributes `max(member weight) / len`, so the cluster
/// bills the single worst member once. Every finding still renders and still counts toward its
/// pillar; only its scoring weight is shared.
///
/// `findings` is the full finding list; each starts from `finding_penalty` before clustering.
/// `config` specifies the rules to leave out of scoring.
///
/// Returns one penalty per finding in the same order as `findings`, so callers can zip or index the two lists together.
fn clustered_penalties(findings: &[Finding], config: &Config) -> Vec<f64> {
    let mut penalties: Vec<f64> = findings
        .iter()
        .map(|finding| {
            if SCORE_PILLARS.contains(&finding.pillar)
                && !config.is_rule_excluded_from_score(&finding.rule_id)
            {
                finding_penalty(finding)
            } else {
                0.0
            }
        })
        .collect();
    let mut clusters: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();

    for (index, finding) in findings.iter().enumerate() {
        // A file-level finding has no function to share its weight with.
        let Some(symbol) = finding.symbol.as_deref() else {
            continue;
        };
        // A rule excluded from scoring cannot change the weight of an included finding.
        if penalties[index] == 0.0
            || !CORRELATED_COMPLEXITY_RULES.contains(&finding.rule_id.as_str())
        {
            continue;
        }
        clusters
            .entry((finding.file_path.clone(), symbol.to_string()))
            .or_default()
            .push(index);
    }

    for members in clusters.values() {
        // A lone correlated finding is not a cluster, so it keeps its own full weight.
        if members.len() < 2 {
            continue;
        }
        let worst = members
            .iter()
            .map(|index| penalties[*index])
            .fold(0.0_f64, f64::max);
        let shared = worst / members.len() as f64;
        for index in members {
            penalties[*index] = shared;
        }
    }

    penalties
}

/// Weigh one finding's score penalty from its severity and confidence.
///
/// `finding` supplies the severity and confidence that are multiplied together.
///
/// Returns `severity_penalty` times `confidence_weight`, from 0.5 for a low-confidence advisory up to 12.0 for a high-confidence error.
pub(crate) fn finding_penalty(finding: &Finding) -> f64 {
    severity_penalty(finding.severity) * confidence_weight(finding.confidence)
}

/// Give the base score penalty for one severity level.
///
/// `severity` is the severity of a finding being weighed.
///
/// Returns 1.0 for advisory, 4.0 for warning, and 12.0 for error.
pub(crate) fn severity_penalty(severity: Severity) -> f64 {
    match severity {
        Severity::Advisory => 1.0,
        Severity::Warning => 4.0,
        Severity::Error => 12.0,
    }
}

/// Give the multiplier that scales a finding's penalty by how confident its rule is.
///
/// `confidence` is the confidence level of a finding being weighed.
///
/// Returns 0.5 for low, 0.75 for medium, and 1.0 for high confidence.
pub(crate) fn confidence_weight(confidence: Confidence) -> f64 {
    match confidence {
        Confidence::Low => 0.5,
        Confidence::Medium => 0.75,
        Confidence::High => 1.0,
    }
}

/// Convert a score to its letter grade.
///
/// `score` is a pillar or composite score on the 0 to 100 scale.
///
/// Returns `A` from 90, `B` from 80, `C` from 70, `D` from 60, and `F` for anything lower, including `NaN`.
pub(crate) fn grade(score: f64) -> String {
    match score {
        value if value >= 90.0 => "A",
        value if value >= 80.0 => "B",
        value if value >= 70.0 => "C",
        value if value >= 60.0 => "D",
        _ => "F",
    }
    .to_string()
}
