use super::*;

/// Two undocumented public functions for the changed-region trio tests below.
/// `alpha` occupies lines 1-7; a blank line 8 precedes `beta` on lines 9-15.
/// Each draws one `docs.missing-public-doc` finding anchored at its
/// function-block start (line 1 for `alpha`, line 8 for `beta`, since the block
/// start absorbs the leading blank line). Exercising these through
/// `--changed-ranges` drives the real range parse and AST block extraction, not
/// hand-built blocks.
const UNDOCUMENTED_FUNCTIONS_FIXTURE: &str = "\
pub fn alpha(seed: u32) -> u32 {
    let mut total = 0;
    for value in 0..seed {
        total += value;
    }
    total
}

pub fn beta(seed: u32) -> u32 {
    let mut total = 1;
    for value in 1..seed {
        total *= value;
    }
    total
}
";

fn undocumented_functions_project() -> tempfile::TempDir {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), UNDOCUMENTED_FUNCTIONS_FIXTURE).expect("fixture write");
    dir
}

fn full_file_options() -> AnalysisOptions {
    AnalysisOptions {
        paths: vec![PathBuf::from("sample.rs")],
        no_config: true,
        no_baseline: true,
        ..default_test_options()
    }
}

fn changed_region_options(ranges: &str, scope: ChangedScope) -> AnalysisOptions {
    AnalysisOptions {
        diff: Some(DiffSelection::ExplicitRanges {
            ranges: ranges.to_string(),
            scope,
        }),
        ..full_file_options()
    }
}

// End-to-end symbol-scope widening through the live `--changed-ranges` path: a
// line strictly inside `alpha`'s body (line 4) must keep `alpha`'s
// signature-anchored finding and suppress everything outside the symbol, while
// the same line under hunk scope keeps nothing (no finding sits on line 4). The
// suppressed count must account for every finding outside the kept set, pinning
// `in_region + suppressedCount == full_file_count`.
#[test]
pub(crate) fn changed_ranges_symbol_scope_widens_to_enclosing_function() {
    let _guard = analysis_lock();
    let project = undocumented_functions_project();

    let full = run_project_analysis(project.path(), full_file_options())
        .expect("full-file analysis succeeds");
    let total = full.findings.len();
    assert!(
        ["alpha", "beta"].iter().all(|name| {
            full.findings.iter().any(|finding| {
                finding.rule_id == "docs.missing-public-doc"
                    && finding.symbol.as_deref() == Some(name)
            })
        }),
        "fixture must yield a missing-public-doc finding for both functions; got {:?}",
        full.findings
            .iter()
            .map(|finding| (&finding.rule_id, &finding.symbol))
            .collect::<Vec<_>>()
    );

    let symbol = run_project_analysis(
        project.path(),
        changed_region_options("4-4", ChangedScope::Symbol),
    )
    .expect("symbol-scope analysis succeeds");
    assert!(
        symbol
            .findings
            .iter()
            .any(|finding| finding.symbol.as_deref() == Some("alpha")),
        "symbol scope must keep alpha's signature finding for a body-only change"
    );
    assert!(
        !symbol
            .findings
            .iter()
            .any(|finding| finding.symbol.as_deref() == Some("beta")),
        "beta is outside the changed symbol and must be suppressed"
    );
    assert!(
        symbol.findings.len() < total,
        "something outside alpha must be suppressed"
    );
    assert_eq!(
        symbol.suppressed_count,
        Some(total - symbol.findings.len()),
        "suppressed_count must account for every finding outside the changed symbol"
    );

    let hunk = run_project_analysis(
        project.path(),
        changed_region_options("4-4", ChangedScope::Hunk),
    )
    .expect("hunk-scope analysis succeeds");
    assert!(
        hunk.findings.is_empty(),
        "hunk scope must not keep findings off the changed line; got {:?}",
        hunk.findings
            .iter()
            .map(|finding| (&finding.rule_id, finding.line))
            .collect::<Vec<_>>()
    );
    assert_eq!(hunk.suppressed_count, Some(total));
}

// `--no-baseline` must override an applied baseline in changed-region mode. The
// agent hook always passes `--no-baseline`, so a stray baseline (explicit or the
// default `gruff-baseline.json`) can never silently hide findings from the
// agent. With the baseline applied, the in-region finding is matched and removed
// before the region filter; with `--no-baseline` it re-surfaces.
#[test]
pub(crate) fn no_baseline_resurfaces_baselined_findings_in_changed_region() {
    let _guard = analysis_lock();
    let project = undocumented_functions_project();

    run_project_analysis(
        project.path(),
        AnalysisOptions {
            generate_baseline: Some(PathBuf::from("baseline.json")),
            ..full_file_options()
        },
    )
    .expect("baseline generation succeeds");

    let with_baseline = run_project_analysis(
        project.path(),
        AnalysisOptions {
            baseline: Some(PathBuf::from("baseline.json")),
            no_baseline: false,
            ..changed_region_options("4-4", ChangedScope::Symbol)
        },
    )
    .expect("baseline-applied analysis succeeds");
    assert!(
        !with_baseline
            .findings
            .iter()
            .any(|finding| finding.symbol.as_deref() == Some("alpha")),
        "an applied baseline must suppress alpha even inside the changed region"
    );
    assert!(
        with_baseline
            .baseline
            .as_ref()
            .is_some_and(|baseline| baseline.suppressed >= 1),
        "baseline report must record the suppression"
    );

    let no_baseline = run_project_analysis(
        project.path(),
        AnalysisOptions {
            baseline: Some(PathBuf::from("baseline.json")),
            no_baseline: true,
            ..changed_region_options("4-4", ChangedScope::Symbol)
        },
    )
    .expect("no-baseline analysis succeeds");
    assert!(
        no_baseline.baseline.is_none(),
        "--no-baseline must leave report.baseline None even with --baseline set"
    );
    assert!(
        no_baseline.findings.iter().any(|finding| {
            finding.rule_id == "docs.missing-public-doc"
                && finding.symbol.as_deref() == Some("alpha")
        }),
        "--no-baseline must re-surface the baselined finding inside the changed region"
    );
}

// A scoped v3 report publishes the out-of-region total as
// `summary.suppressedFindings`. Pin both the serialized field and the scoping so
// a refactor cannot silently drop the count or leak an out-of-region finding. A
// full-tree run must omit the optional field entirely.
#[test]
pub(crate) fn changed_region_json_carries_suppressed_finding_count_and_scopes_findings() {
    let _guard = analysis_lock();
    let project = undocumented_functions_project();

    let full = run_project_analysis(project.path(), full_file_options())
        .expect("full-file analysis succeeds");
    let full_json = render_report(&full, OutputFormat::Json);
    let full_value: serde_json::Value =
        serde_json::from_str(&full_json).expect("full-tree JSON parses");
    assert!(full_value["summary"].get("suppressedFindings").is_none());

    let scoped = run_project_analysis(
        project.path(),
        changed_region_options("4-4", ChangedScope::Symbol),
    )
    .expect("changed-region analysis succeeds");
    let expected_suppressed = scoped
        .suppressed_count
        .expect("a diff run must set suppressed_count");
    assert!(
        expected_suppressed >= 1,
        "at least beta must be suppressed outside the changed symbol"
    );

    let rendered = render_report(&scoped, OutputFormat::Json);
    let value: serde_json::Value = serde_json::from_str(&rendered).expect("scoped JSON parses");
    assert_eq!(
        value["summary"]["suppressedFindings"].as_u64(),
        Some(expected_suppressed as u64),
        "summary.suppressedFindings must equal the out-of-region total"
    );
    assert_eq!(
        value["diff"]["filteredFindings"].as_u64(),
        Some(expected_suppressed as u64)
    );
    let findings = value["findings"].as_array().expect("findings array");
    assert!(
        findings.iter().any(|finding| finding["symbol"] == "alpha"),
        "scoped JSON must keep the in-region (alpha) finding"
    );
    assert!(
        findings.iter().all(|finding| finding["symbol"] != "beta"),
        "scoped JSON must exclude the out-of-region (beta) finding"
    );
}
