use super::*;

/// M35 calibration: `naming.boolean-prefix` accepts idiomatic Rust
/// predicate names (subject-predicate form, common predicate verbs) while
/// keeping passive shapes like `triggered_by` flagged.
#[test]
pub(crate) fn boolean_prefix_accepts_idioms_and_flags_passive() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn visibility_is_public() -> bool { true }
/// Probe.
pub fn path_is_project_ignored() -> bool { true }
/// Probe.
pub fn line_in_ranges() -> bool { true }
/// Probe.
pub fn path_matches() -> bool { true }
/// Probe.
pub fn starts_with_prefix() -> bool { true }
/// Probe.
pub fn ends_with_suffix() -> bool { true }
/// Probe.
pub fn matches() -> bool { true }
/// Probe.
pub fn contains() -> bool { true }
/// Probe.
pub fn triggered_by() -> bool { true }
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let predicate_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "naming.boolean-prefix")
        .collect();
    let triggered_by_count = predicate_findings
        .iter()
        .filter(|finding| finding.symbol.as_deref() == Some("triggered_by"))
        .count();
    assert_eq!(
        triggered_by_count, 1,
        "triggered_by must still be flagged; findings={predicate_findings:?}"
    );
    for accepted in [
        "visibility_is_public",
        "path_is_project_ignored",
        "line_in_ranges",
        "path_matches",
        "starts_with_prefix",
        "ends_with_suffix",
        "matches",
        "contains",
    ] {
        let still_flagged = predicate_findings
            .iter()
            .any(|finding| finding.symbol.as_deref() == Some(accepted));
        assert!(
                !still_flagged,
                "{accepted} must be accepted by the idiom-aware predicate rule; findings={predicate_findings:?}"
            );
    }
}

/// M35 negative: `security.unsafe-block` must STILL find nearby `SAFETY:`
/// rationale comments after the M35 raw/code-only split. The unsafe-block
/// rule uses the raw (comment-preserved) line view so it can read the
/// `SAFETY:` marker.
#[test]
pub(crate) fn unsafe_block_still_sees_safety_rationale_comment() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn explained() {
    // SAFETY: this is a synthetic fixture, no actual unsafety.
    unsafe {
        std::ptr::null::<i32>();
    }
}

/// Probe.
pub fn unexplained() {
    unsafe {
        std::ptr::null::<i32>();
    }
}
"##,
    );
    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let unsafe_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.unsafe-block")
        .collect();
    assert_eq!(
            unsafe_findings.len(),
            1,
            "expected exactly one unsafe-block finding (the unexplained one); findings={unsafe_findings:?}"
        );
}

/// M37 calibration: the three new naming options
/// (`predicatePrefixes`, `extraPlaceholders`, `extraGenericNames`) plumb
/// through the typed-option config and influence rule dispatch. Wrong
/// shapes (a non-array value) are rejected with the expected error
/// format.
#[test]
pub(crate) fn naming_options_round_trip_through_config() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        "/// Probe.\npub fn requires_init() -> bool { true }\n\
             /// Probe.\npub fn entry() { let tmp = 1; let _ = tmp; }\n\
             /// Probe.\npub fn do_stuff() {}\n",
    );
    write_config(
        dir.path(),
        r##"
rules:
  naming.boolean-prefix:
    enabled: true
    options:
      predicatePrefixes: ["requires_"]
  naming.placeholder-identifier:
    enabled: true
    options:
      extraPlaceholders: ["tmp"]
  naming.generic-function:
    enabled: true
    options:
      extraGenericNames: ["do_stuff"]
"##,
    );

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    // predicatePrefixes accepts `requires_init` → no boolean-prefix finding for that fn
    assert!(
        !report.findings.iter().any(|finding| {
            finding.rule_id == "naming.boolean-prefix"
                && finding.symbol.as_deref() == Some("requires_init")
        }),
        "predicatePrefixes must silence requires_init; findings={:?}",
        report
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.symbol))
            .collect::<Vec<_>>()
    );

    // extraPlaceholders catches `tmp`
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "naming.placeholder-identifier"
                && finding.symbol.as_deref() == Some("tmp")
        }),
        "extraPlaceholders must flag `tmp`; findings={:?}",
        report
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.symbol))
            .collect::<Vec<_>>()
    );

    // extraGenericNames catches `do_stuff`
    assert!(
        report.findings.iter().any(|finding| {
            finding.rule_id == "naming.generic-function"
                && finding.symbol.as_deref() == Some("do_stuff")
        }),
        "extraGenericNames must flag `do_stuff`; findings={:?}",
        report
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.symbol))
            .collect::<Vec<_>>()
    );

    // Wrong shape: predicatePrefixes is a number, not an array
    write_config(
        dir.path(),
        r##"
rules:
  naming.boolean-prefix:
    options:
      predicatePrefixes: 7
"##,
    );
    let error = load_config(dir.path(), &default_test_options())
        .expect_err("non-array option value must be rejected");
    assert!(
        error.contains("`rules.naming.boolean-prefix.options.predicatePrefixes`")
            && error.to_lowercase().contains("array"),
        "unexpected error: {error}"
    );

    // Wrong rule: predicatePrefixes on naming.placeholder-identifier
    write_config(
        dir.path(),
        r##"
rules:
  naming.placeholder-identifier:
    options:
      predicatePrefixes: ["foo"]
"##,
    );
    let error = load_config(dir.path(), &default_test_options())
        .expect_err("unknown option must be rejected");
    assert!(
        error.contains("predicatePrefixes") && error.contains("naming.placeholder-identifier"),
        "unexpected error: {error}"
    );
}
