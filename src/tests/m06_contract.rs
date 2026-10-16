//! Pins the behaviours the ratified family scoring contract fixes.
//!
//! The cross-port suite (`family-check --suite scoring`) proves the same properties for all five
//! ports at once, but it runs from the specification repository and needs every port built. These
//! tests fail here, in gruff-rs's own gate, the moment one of them breaks.

use super::*;

/// Evaluated-file denominator every fixture scores against; ten keeps the derived numbers legible.
const EVALUATED_FILES: usize = 10;

/// Build one finding with an explicit weight and symbol so a test can state what it expects.
fn contract_finding(
    rule_id: &str,
    file_path: &str,
    severity: Severity,
    pillar: Pillar,
    symbol: &str,
    line: usize,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!("{rule_id} message"),
        file_path: file_path.to_string(),
        line: Some(line),
        severity,
        pillar,
        confidence: Confidence::High,
        symbol: Some(symbol.to_string()),
        remediation: Some("Remediate the issue.".to_string()),
        metadata: json!({}),
    })
}

/// Find one published pillar row by name, panicking rather than returning a default.
fn pillar_row(score: &ScoreReport, name: Pillar) -> &PillarScore {
    score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == name)
        .expect("pillar present in the published set")
}

/// Duplicating a project must not move its grade.
///
/// This is the property the ratified shape exists to deliver: duplication doubles the findings and
/// the evaluated files together, so the density they make is unchanged. The retired absolute-sum
/// shape failed it - a 4x duplication of identical code cost gruff-rs three composite points.
#[test]
pub(crate) fn scale_is_not_an_automatic_penalty() {
    let config = Config::default();
    let single = vec![contract_finding(
        "naming.one",
        "src/a.rs",
        Severity::Warning,
        Pillar::Naming,
        "one",
        1,
    )];
    let mut doubled = single.clone();
    doubled.push(contract_finding(
        "naming.one",
        "src/b.rs",
        Severity::Warning,
        Pillar::Naming,
        "two",
        1,
    ));
    let mut quadrupled = doubled.clone();
    quadrupled.push(contract_finding(
        "naming.one",
        "src/c.rs",
        Severity::Warning,
        Pillar::Naming,
        "three",
        1,
    ));
    quadrupled.push(contract_finding(
        "naming.one",
        "src/d.rs",
        Severity::Warning,
        Pillar::Naming,
        "four",
        1,
    ));

    let base = score_report(&single, &config, EVALUATED_FILES).composite;
    assert!(base.is_some());
    assert_eq!(
        score_report(&doubled, &config, EVALUATED_FILES * 2).composite,
        base
    );
    assert_eq!(
        score_report(&quadrupled, &config, EVALUATED_FILES * 4).composite,
        base
    );
}

/// Adding a finding without adding a file can only worsen its own pillar.
#[test]
pub(crate) fn monotonicity_at_a_fixed_denominator() {
    let config = Config::default();
    let before = score_report(
        &[contract_finding(
            "security.one",
            "src/a.rs",
            Severity::Warning,
            Pillar::Security,
            "one",
            1,
        )],
        &config,
        EVALUATED_FILES,
    );
    let after = score_report(
        &[
            contract_finding(
                "security.one",
                "src/a.rs",
                Severity::Warning,
                Pillar::Security,
                "one",
                1,
            ),
            contract_finding(
                "security.two",
                "src/a.rs",
                Severity::Error,
                Pillar::Security,
                "two",
                9,
            ),
        ],
        &config,
        EVALUATED_FILES,
    );

    assert!(
        pillar_row(&after, Pillar::Security).score < pillar_row(&before, Pillar::Security).score
    );
    assert!(after.composite < before.composite);
    // A pillar that gained no finding must not move, or the composite couples unrelated areas.
    assert_eq!(
        pillar_row(&after, Pillar::Documentation).score,
        pillar_row(&before, Pillar::Documentation).score
    );
}

/// A reachable clean pillar scores 100; a run that evaluated nothing scores nothing at all.
#[test]
pub(crate) fn applicability_keeps_null_apart_from_perfect() {
    let config = Config::default();
    let clean = score_report(&[], &config, EVALUATED_FILES);

    for pillar in &clean.pillars {
        assert!(
            pillar.applicable,
            "pillar {:?} is not applicable",
            pillar.pillar
        );
        assert_eq!(pillar.score, Some(100.0), "pillar {:?}", pillar.pillar);
    }

    let nothing = score_report(&[], &config, 0);
    assert_eq!(nothing.composite, None);
    assert_eq!(nothing.grade, None);
    assert_eq!(nothing.evaluated_files, 0);
    assert!(nothing.pillars.iter().all(|pillar| pillar.score.is_none()));
}

/// Ties round away from zero, matching the four sibling ports.
#[test]
pub(crate) fn serialization_rounds_to_two_decimals_away_from_zero() {
    assert_eq!(crate::scoring::round_score(53.125), 53.13);
    assert_eq!(crate::scoring::round_score(97.681_818), 97.68);
    assert_eq!(crate::scoring::round_score(100.0), 100.0);
    // Negative zero is normalized away: JSON projection keeps it in some ports and not others.
    assert!(crate::scoring::round_score(-0.001).is_sign_positive());
}

/// Correlated findings on one symbol bill once, whatever lines they report.
///
/// Correlated rules disagree about which line to report, so a line in the cluster key would split
/// one root cause into two and bill it twice.
#[test]
pub(crate) fn clustering_keys_on_symbol_without_line_identity() {
    let config = Config::default();
    let shared = score_report(
        &[
            contract_finding(
                "size.function-length",
                "src/a.rs",
                Severity::Warning,
                Pillar::Size,
                "run",
                1,
            ),
            contract_finding(
                "complexity.cyclomatic",
                "src/a.rs",
                Severity::Warning,
                Pillar::Complexity,
                "run",
                9,
            ),
        ],
        &config,
        EVALUATED_FILES,
    );

    // One warning weighs 4, so the cluster bills 4 across two members: 2 each.
    assert_eq!(pillar_row(&shared, Pillar::Size).penalty, 2.0);
    assert_eq!(pillar_row(&shared, Pillar::Complexity).penalty, 2.0);
    assert_eq!(shared.clusters.len(), 1);
    assert_eq!(shared.clusters[0].findings, 2);
    assert_eq!(shared.clusters[0].weight, 4.0);
    assert_eq!(
        shared.clusters[0].rule_ids,
        vec![
            "complexity.cyclomatic".to_string(),
            "size.function-length".to_string()
        ]
    );

    let distinct = score_report(
        &[
            contract_finding(
                "size.function-length",
                "src/a.rs",
                Severity::Warning,
                Pillar::Size,
                "run",
                1,
            ),
            contract_finding(
                "complexity.cyclomatic",
                "src/a.rs",
                Severity::Warning,
                Pillar::Complexity,
                "walk",
                9,
            ),
        ],
        &config,
        EVALUATED_FILES,
    );
    assert!(distinct.clusters.is_empty());
}

/// Every rule that produced a finding owes exactly one row, sorted by its native identifier.
#[test]
pub(crate) fn rule_attribution_is_keyed_by_native_rule_id() {
    let config = Config::default();
    let score = score_report(
        &[
            contract_finding(
                "naming.b-rule",
                "src/a.rs",
                Severity::Advisory,
                Pillar::Naming,
                "one",
                1,
            ),
            contract_finding(
                "naming.a-rule",
                "src/a.rs",
                Severity::Warning,
                Pillar::Naming,
                "two",
                2,
            ),
            contract_finding(
                "naming.a-rule",
                "src/b.rs",
                Severity::Warning,
                Pillar::Naming,
                "three",
                3,
            ),
        ],
        &config,
        EVALUATED_FILES,
    );

    let rule_ids: Vec<&str> = score
        .rule_attribution
        .iter()
        .map(|row| row.rule_id.as_str())
        .collect();
    assert_eq!(rule_ids, vec!["naming.a-rule", "naming.b-rule"]);
    // Two high-confidence warnings weigh 4 each.
    assert_eq!(score.rule_attribution[0].findings, 2);
    assert_eq!(score.rule_attribution[0].weight, 8.0);
    assert_eq!(score.rule_attribution[1].findings, 1);
    assert_eq!(score.rule_attribution[1].weight, 1.0);
}

/// The composite a person reads and the one a script reads come from one calculation.
///
/// A renderer that formats the score itself, rather than printing what the scorer produced, can
/// drift from the machine view without any other test noticing.
#[test]
pub(crate) fn text_and_machine_views_agree_on_the_composite() {
    let mut report = sample_report_with(
        vec![contract_finding(
            "complexity.cyclomatic",
            "src/a.rs",
            Severity::Warning,
            Pillar::Complexity,
            "run",
            1,
        )],
        Vec::new(),
    );
    report.score = score_report(&report.findings, &Config::default(), EVALUATED_FILES);

    let composite = report.score.composite.expect("composite present");
    let grade_letter = report.score.grade.clone().expect("grade present");
    let expected = format!("Composite: {grade_letter} ({composite:.2} / 100)");

    let analyse_text = render_report(&report, OutputFormat::Text);
    let summary_text = crate::summary::render(&report, 5, SummaryFormat::Text, 0);

    assert!(
        analyse_text.contains(&expected),
        "analyse text missing {expected}:\n{analyse_text}"
    );
    assert!(
        summary_text.contains(&expected),
        "summary text missing {expected}:\n{summary_text}"
    );

    // FAMILY-CONTRACT section 1 puts the masthead and the composite block first in both views.
    for (name, rendered) in [("analyse", &analyse_text), ("summary", &summary_text)] {
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(
            lines[0].starts_with("gruff-rs "),
            "{name} masthead: {}",
            lines[0]
        );
        assert_eq!(lines[1], expected, "{name} line 2");
        assert!(
            lines[2].starts_with("Findings: "),
            "{name} line 3: {}",
            lines[2]
        );
    }
}
