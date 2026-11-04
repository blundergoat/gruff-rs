use super::*;

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

/// Cross-port canonical composite-score block. Shared verbatim by the `analyse`
/// text header (`render::text`) and the `summary` text view (`summary`) so the two
/// surfaces render byte-identical score lines (they previously diverged on
/// separator, severity order, decimals, and the `/100` denominator). Emits exactly
/// two lines, each terminated with `\n`:
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

/// Ratified family scoring parameters. The shape `bounded-normalized-density-floored` was ratified
/// 2026-09-01 and these values 2026-09-03; all five ports carry the same numbers, so changing either
/// is a family decision rather than a gruff-rs one. `SCORE_FLOOR` bounds how far one saturated pillar
/// can drag the composite; `DENSITY_SCALE` is the per-file finding density at which a pillar sits half
/// way between the floor and 100.
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
/// Returns a `ScoreReport` holding pillar scores, the composite and grade, up to ten top offenders, correlated clusters, and rule weights.
pub(crate) fn score_report(
    findings: &[Finding],
    config: &Config,
    evaluated_files: usize,
) -> ScoreReport {
    let pillars = pillar_scores(findings, config, evaluated_files);
    let composite = composite_score(&pillars);
    let top_offenders = top_file_scores(findings, evaluated_files);

    ScoreReport {
        composite,
        grade: composite.map(grade),
        evaluated_files,
        scored_pillars: pillars.iter().map(|pillar| pillar.pillar).collect(),
        clusters: correlated_clusters(findings),
        rule_attribution: rule_attribution(findings),
        pillars,
        top_offenders,
    }
}

/// One correlated concept whose members share a single score weight.
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

/// One native rule's contribution to the score.
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
///
/// Returns one `ScoreCluster` per file and symbol with two or more such findings, or an empty list when none qualify.
/// Each cluster lists its rule ids sorted and a `weight` equal to its worst member's penalty, rounded to two decimals.
pub(crate) fn correlated_clusters(findings: &[Finding]) -> Vec<ScoreCluster> {
    let penalties = clustered_penalties(findings);
    let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();

    for (index, finding) in findings.iter().enumerate() {
        let Some(symbol) = finding.symbol.as_deref() else {
            continue;
        };
        if !CORRELATED_COMPLEXITY_RULES.contains(&finding.rule_id.as_str()) {
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
/// `findings` is the full finding list, weighed after correlated clusters share their penalty.
///
/// Returns one `RuleWeight` per rule id with its finding count and summed weight rounded to two decimals, or an empty list for no findings.
pub(crate) fn rule_attribution(findings: &[Finding]) -> Vec<RuleWeight> {
    let penalties = clustered_penalties(findings);
    let mut totals: BTreeMap<String, (usize, f64)> = BTreeMap::new();

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
/// `findings` are grouped by pillar, and `config` names rules whose weight is left out of a pillar's penalty.
/// `evaluated_files` divides each pillar's penalty before the curve is applied; zero leaves every row's score and grade as `None`.
///
/// Returns a `PillarScore` for every `SCORE_PILLARS` entry in order, even without findings, then for any other pillar a finding uses.
pub(crate) fn pillar_scores(
    findings: &[Finding],
    config: &Config,
    evaluated_files: usize,
) -> Vec<PillarScore> {
    let weighted: Vec<(&Finding, f64)> =
        findings.iter().zip(clustered_penalties(findings)).collect();
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
        .map(|pillar| pillar_score_row(pillar, by_pillar.get(&pillar), config, evaluated_files))
        .collect()
}

/// Score one pillar from its findings and their clustered weights.
///
/// `pillar` is the pillar being scored, and `pillar_findings` holds its findings paired with clustered weights, `None` when it has none.
/// `config` drops excluded rules from the penalty, and `evaluated_files` is the file count the penalty is divided by.
///
/// Returns an applicable `PillarScore` whose score and grade are `None` when no files were evaluated.
/// Its rounded penalty skips excluded rules, but its finding count still includes them.
fn pillar_score_row(
    pillar: Pillar,
    pillar_findings: Option<&Vec<&(&Finding, f64)>>,
    config: &Config,
    evaluated_files: usize,
) -> PillarScore {
    let empty: Vec<&(&Finding, f64)> = Vec::new();
    let findings = pillar_findings.unwrap_or(&empty);
    let penalty: f64 = findings
        .iter()
        .filter(|(finding, _)| !config.is_rule_excluded_from_score(&finding.rule_id))
        .map(|(_, weight)| *weight)
        .sum();
    PillarScore {
        pillar,
        // Every pillar in SCORE_PILLARS is reachable by this port's rule set; a pillar a finding
        // introduced from outside that set is reachable by definition, having just been reached.
        applicable: true,
        score: curve_score(penalty, evaluated_files),
        grade: curve_score(penalty, evaluated_files).map(grade),
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

/// List the worst-scoring files for the report's top-offender section, capped at ten.
///
/// `findings` supplies each file's weighted findings, and `evaluated_files` of zero leaves every file score `None`.
///
/// Returns at most ten `FileScore` rows from `top_file_scores_with_limit`, or an empty list when there are no findings.
pub(crate) fn top_file_scores(findings: &[Finding], evaluated_files: usize) -> Vec<FileScore> {
    top_file_scores_with_limit(findings, 10, evaluated_files)
}

/// Rank the files that have findings by their own score so the worst offenders come first.
///
/// `findings` are grouped by file with their clustered weights, and `limit` caps how many rows are kept.
/// `evaluated_files` of zero leaves every file score `None`; otherwise each file is scored as one file from its own penalty.
///
/// Returns up to `limit` `FileScore` rows sorted by lowest score, then most findings, then path, with ungraded files sorted as if they scored 100.
pub(crate) fn top_file_scores_with_limit(
    findings: &[Finding],
    limit: usize,
    evaluated_files: usize,
) -> Vec<FileScore> {
    let mut file_counts: BTreeMap<String, (usize, f64)> = BTreeMap::new();
    // File scores charge the clustered weight too, so a top-offender list ranks one over-large
    // function once rather than once per symptom.
    for (finding, weight) in findings.iter().zip(clustered_penalties(findings)) {
        let entry = file_counts
            .entry(finding.file_path.clone())
            .or_insert((0, 0.0));
        entry.0 += 1;
        entry.1 += weight;
    }
    let mut top_offenders: Vec<FileScore> = file_counts
        .into_iter()
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
    top_offenders.truncate(limit);
    top_offenders
}

/// Size and complexity rules that describe one over-large function from different angles: too long,
/// too nested, too branchy, too many parameters. The ratified contract bills one penalty per
/// correlated concept, so when two or more of these land on the same symbol they share a single
/// weight instead of charging the grade once per symptom.
pub(crate) const CORRELATED_COMPLEXITY_RULES: [&str; 5] = [
    "complexity.cognitive",
    "complexity.cyclomatic",
    "complexity.nesting-depth",
    "size.function-length",
    "size.parameter-count",
];

/// Weigh every finding, then share one weight across each correlated cluster.
///
/// The cluster key is project-relative file and symbol, without line identity: correlated rules do
/// not agree on which line to report, and a line in the key splits one root cause into two. The
/// contract's key is the *qualified* symbol; gruff-rs emits an unqualified one, so two same-named
/// functions in one file share a key and bill one penalty between them. That under-penalises rather
/// than over-penalises, and qualifying the symbol would change finding identity.
///
/// Each member of a cluster of two or more contributes `max(member weight) / len`, so the cluster
/// bills the single worst member once. Every finding still renders and still counts toward its
/// pillar; only its scoring weight is shared.
///
/// `findings` is the full finding list; each starts from `finding_penalty` before clustering.
///
/// Returns one penalty per finding in the same order as `findings`, so callers can zip or index the two lists together.
pub(crate) fn clustered_penalties(findings: &[Finding]) -> Vec<f64> {
    let mut penalties: Vec<f64> = findings.iter().map(finding_penalty).collect();
    let mut clusters: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();

    for (index, finding) in findings.iter().enumerate() {
        let Some(symbol) = finding.symbol.as_deref() else {
            continue;
        };
        if !CORRELATED_COMPLEXITY_RULES.contains(&finding.rule_id.as_str()) {
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
