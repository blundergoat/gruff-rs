use super::*;

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

pub(crate) fn score_report(findings: &[Finding]) -> ScoreReport {
    let pillars = pillar_scores(findings);
    let composite = composite_score(&pillars);
    let top_offenders = top_file_scores(findings);

    ScoreReport {
        composite,
        grade: grade(composite),
        pillars,
        top_offenders,
    }
}

pub(crate) fn pillar_scores(findings: &[Finding]) -> Vec<PillarScore> {
    let mut by_pillar: BTreeMap<Pillar, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        by_pillar.entry(finding.pillar).or_default().push(finding);
    }

    let mut pillar_order: Vec<Pillar> = SCORE_PILLARS.to_vec();
    for pillar in by_pillar.keys() {
        if !pillar_order.contains(pillar) {
            pillar_order.push(*pillar);
        }
    }

    let pillars: Vec<PillarScore> = pillar_order
        .into_iter()
        .map(|pillar| {
            let pillar_findings = by_pillar.get(&pillar).cloned().unwrap_or_default();
            let penalty: f64 = pillar_findings
                .iter()
                .map(|finding| finding_penalty(finding))
                .sum();
            PillarScore {
                pillar,
                score: (100.0 - penalty).max(0.0),
                findings: pillar_findings.len(),
            }
        })
        .collect();
    pillars
}

pub(crate) fn composite_score(pillars: &[PillarScore]) -> f64 {
    if pillars.is_empty() {
        100.0
    } else {
        pillars.iter().map(|pillar| pillar.score).sum::<f64>() / pillars.len() as f64
    }
}

pub(crate) fn top_file_scores(findings: &[Finding]) -> Vec<FileScore> {
    top_file_scores_with_limit(findings, 10)
}

pub(crate) fn top_file_scores_with_limit(findings: &[Finding], limit: usize) -> Vec<FileScore> {
    let mut file_counts: BTreeMap<String, (usize, f64)> = BTreeMap::new();
    for finding in findings {
        let entry = file_counts
            .entry(finding.file_path.clone())
            .or_insert((0, 0.0));
        entry.0 += 1;
        entry.1 += finding_penalty(finding);
    }
    let mut top_offenders: Vec<FileScore> = file_counts
        .into_iter()
        .map(|(file_path, (findings, penalty))| FileScore {
            file_path,
            score: (100.0 - penalty).max(0.0),
            findings,
        })
        .collect();
    top_offenders.sort_by(|left, right| {
        left.score
            .total_cmp(&right.score)
            .then_with(|| right.findings.cmp(&left.findings))
            .then_with(|| left.file_path.cmp(&right.file_path))
    });
    top_offenders.truncate(limit);
    top_offenders
}

pub(crate) fn finding_penalty(finding: &Finding) -> f64 {
    severity_penalty(finding.severity) * confidence_weight(finding.confidence)
}

pub(crate) fn severity_penalty(severity: Severity) -> f64 {
    match severity {
        Severity::Advisory => 1.5,
        Severity::Warning => 4.0,
        Severity::Error => 8.0,
    }
}

pub(crate) fn confidence_weight(confidence: Confidence) -> f64 {
    match confidence {
        Confidence::Low => 0.5,
        Confidence::Medium => 0.75,
        Confidence::High => 1.0,
    }
}

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
