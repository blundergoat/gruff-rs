use super::*;

/// M35 calibration: `naming.boolean-prefix` accepts idiomatic Rust
/// predicate names (subject-predicate form, common predicate verbs) while
/// keeping passive shapes like `triggered_by` flagged.
#[test]
pub(crate) fn m35_boolean_prefix_accepts_idioms_and_flags_passive() {
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
        .filter(|f| f.symbol.as_deref() == Some("triggered_by"))
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
            .any(|f| f.symbol.as_deref() == Some(accepted));
        assert!(
                !still_flagged,
                "{accepted} must be accepted by the idiom-aware predicate rule; findings={predicate_findings:?}"
            );
    }
}

/// M35 negative: prose inside Rust comments must not trigger code-pattern
/// line rules. `naming.short-variable`, `naming.placeholder-identifier`,
/// `waste.unwrap-expect`, and `waste.unnecessary-clone-candidate` all run
/// off the code-only line view that masks comments to spaces. The
/// `security.unsafe-block` rule remains comment-aware so it can still
/// find nearby `SAFETY:` rationale comments.
#[test]
pub(crate) fn m35_line_rules_skip_prose_in_comments() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"//! Probe.
//
// Documentation prose with code-shaped fragments that must stay silent:
//   - "for a built-in rule" (naming.short-variable false-positive bait)
//   - `let foo = ...` (naming.placeholder-identifier bait)
//   - `.unwrap()` mentioned in prose (waste.unwrap-expect bait)
//   - `.clone()` mentioned in prose (waste.unnecessary-clone-candidate bait)

/// for a, this is a documentation paragraph that mentions `.unwrap()` and `.clone()`
/// and even shows `let foo = bar;` as an example. None of these should fire.
pub fn well_documented(name: String) -> String {
    /* a block comment also mentioning .unwrap() and .clone() and let foo = ... */
    name
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
    for rule in [
        "naming.short-variable",
        "naming.placeholder-identifier",
        "waste.unwrap-expect",
        "waste.unnecessary-clone-candidate",
    ] {
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule),
            "{rule} must not fire on prose in comments; findings={:?}",
            report
                .findings
                .iter()
                .filter(|f| f.rule_id == rule)
                .map(|f| f.line)
                .collect::<Vec<_>>()
        );
    }
}

/// M35 negative: `security.unsafe-block` must STILL find nearby `SAFETY:`
/// rationale comments after the M35 raw/code-only split. The unsafe-block
/// rule uses the raw (comment-preserved) line view so it can read the
/// `SAFETY:` marker.
#[test]
pub(crate) fn m35_unsafe_block_still_sees_safety_rationale_comment() {
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

/// M35 negative: external-public-API rules must not fire on `pub(crate)`,
/// `pub(super)`, or `pub(in path)` items. Those are crate-visible (so
/// dead-code / reachability rules still see them as reachable) but they
/// are NOT part of the external API surface, so reportable rules stay
/// silent. The corresponding `pub` bare positives are covered by the
/// existing fixture-based proofs.
#[test]
pub(crate) fn m35_external_public_rules_skip_crate_visible_items() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"//! Probe.
pub(crate) struct Buckets {
    pub(crate) primary: Vec<u32>,
    pub(super) seen: u32,
}

pub(crate) fn maybe_one(value: Option<u32>) -> u32 {
    value.unwrap()
}

pub(crate) fn entry_a() {}
pub(crate) fn entry_b() {}
pub(crate) fn entry_c() {}
pub(crate) fn entry_d() {}
pub(crate) fn entry_e() {}
pub(crate) fn entry_f() {}
pub(crate) fn entry_g() {}
pub(crate) fn entry_h() {}
pub(crate) fn entry_i() {}
pub(crate) fn entry_j() {}
pub(crate) fn entry_k() {}
pub(crate) fn entry_l() {}
pub(crate) fn entry_m() {}
pub(crate) fn entry_n() {}
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
    for rule in [
        "modernisation.public-field",
        "docs.missing-public-doc",
        "error-handling.public-unwrap",
        "architecture.public-api-surface",
    ] {
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule),
            "{rule} must not fire on crate-visible items; findings={:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.rule_id, f.line))
                .collect::<Vec<_>>()
        );
    }
    // The broader (non-public-API) unwrap rule SHOULD still fire on the
    // production unwrap inside `maybe_one`, even though the public-API
    // rule does not.
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "waste.unwrap-expect"),
        "waste.unwrap-expect must still fire on production unwraps regardless of visibility"
    );
}

/// M37 calibration: the three new naming options
/// (`predicatePrefixes`, `extraPlaceholders`, `extraGenericNames`) plumb
/// through the typed-option config and influence rule dispatch. Wrong
/// shapes (a non-array value) are rejected with the expected error
/// format.
#[test]
pub(crate) fn m37_naming_options_round_trip_through_config() {
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

/// M38 negative: `waste.unnecessary-clone-candidate` must skip clones
/// inside `#[test]` fns and any fn inside a `#[cfg(test)]` module, so the
/// rule stays symmetric with `waste.unwrap-expect`, whose
/// `analyse_waste_line` branch already applies
/// `!line.contains("#[test]") && !self.line_is_in_test_context(...)`.
/// A production clone outside any test context must still fire so the
/// guard does not silence real waste.
#[test]
pub(crate) fn m38_unnecessary_clone_candidate_skips_test_context() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn entry(value: &String) -> String {
    value.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_setup(seed: &String) -> String {
        seed.clone()
    }

    #[test]
    fn check() {
        let original = String::from("x");
        let _copy = original.clone();
        let _via = shared_setup(&original);
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
    let clones: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "waste.unnecessary-clone-candidate")
        .collect();
    assert_eq!(
            clones.len(),
            1,
            "expected exactly one clone finding (the production one in `pub fn entry`); findings={clones:?}"
        );
}
