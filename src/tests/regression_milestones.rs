use super::*;

/// M33 negative: `waste.unnecessary-clone-candidate` must skip clones
/// whose result is immediately consumed by ownership-taking calls
/// (`unwrap_or_else`, `unwrap_or`, `unwrap_or_default`, `into`, `into_iter`,
/// `collect`, `?` propagation), struct-field initialisation, or
/// `HashMap::entry/insert` keys. These are not avoidable clones.
#[test]
pub(crate) fn m33_unnecessary_clone_candidate_skips_consumed_or_owned_uses() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
use std::collections::HashMap;

pub struct Row {
    pub name: String,
    pub tags: Vec<String>,
}

pub fn build(input: &Row, fallback: Option<String>) -> Row {
    let _consumed_unwrap = fallback.clone().unwrap_or_else(String::new);
    let _consumed_into: Vec<String> = input.tags.clone().into_iter().collect();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    by_name.entry(input.name.clone()).or_insert(0);
    Row {
        name: input.name.clone(),
        tags: input.tags.clone(),
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
    assert!(
        clones.is_empty(),
        "consumed/owned clones must stay silent; findings={clones:?}"
    );
}

/// M33 negative: `metrics.halstead-volume` must not count string-literal
/// content as tokens. A long `format!(concat!(...))` HTML template with
/// dense string fragments inside should still stay below the threshold —
/// only the wrapping `format`, `concat`, punctuation, and `{}` placeholder
/// tokens count.
#[test]
pub(crate) fn m33_halstead_volume_skips_string_literal_tokens() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let mut body =
        String::from("/// Probe.\npub fn render(name: &str) -> String {\n    format!(concat!(\n");
    for _ in 0..120 {
        body.push_str(
                "        \"<div class=\\\"row\\\"><span>some literal text inside that should not count toward tokens at all</span></div>\\n\",\n",
            );
    }
    body.push_str("        \"{}\"\n    ), name)\n}\n");
    baseline_with_lib(dir.path(), &body);
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
    let hv: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "metrics.halstead-volume")
        .collect();
    assert!(
        hv.is_empty(),
        "long format!(concat!(...)) template must stay below halstead threshold; findings={hv:?}"
    );
}

/// M33 negative: `size.function-length` must skip a function whose body is
/// a single declarative literal (here, a 70-entry `vec![...]`). Function
/// length is intended to flag logic, not table-data registries.
#[test]
pub(crate) fn m33_function_length_skips_declarative_vec_body() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let mut body = String::from("/// Probe.\npub fn registry() -> Vec<i32> {\n    vec![\n");
    for index in 0..70 {
        body.push_str(&format!("        {index},\n"));
    }
    body.push_str("    ]\n}\n");
    baseline_with_lib(dir.path(), &body);
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
    let size_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "size.function-length")
        .collect();
    assert!(
        size_findings.is_empty(),
        "70-entry vec![...] body must not trigger size.function-length; findings={size_findings:?}"
    );
}

/// M33 negative: `waste.unwrap-expect` must skip test code (functions
/// annotated with `#[test]` and any function inside a `#[cfg(test)]`
/// module). The dedicated `test-quality.unwrap-in-test` rule covers the
/// test-side concern.
#[test]
pub(crate) fn m33_unwrap_expect_skips_cfg_test_module() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn entry() {}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_setup() -> i32 {
        let value: Option<i32> = Some(1);
        value.unwrap()
    }

    #[test]
    fn check() {
        let v: Option<i32> = Some(2);
        assert_eq!(v.unwrap(), 2);
        let _ = shared_setup();
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
    let waste: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "waste.unwrap-expect")
        .collect();
    assert!(
        waste.is_empty(),
        "unwrap-expect must skip #[cfg(test)] module functions; findings={waste:?}"
    );
    let in_test: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "test-quality.unwrap-in-test")
        .collect();
    assert!(
        !in_test.is_empty(),
        "test-quality.unwrap-in-test must still fire on test-mode unwraps; findings={:?}",
        report
            .findings
            .iter()
            .map(|f| &f.rule_id)
            .collect::<Vec<_>>()
    );
}

/// M33 negative: prove the literal mask handles Rust character literals
/// such as `trim_matches('"')`. Without char-literal awareness, the `"`
/// inside `'"'` flips the masker into string mode and every later string
/// in the file is masked one off, leaking later `Command::new` text inside
/// `concat!()` fixtures into the regex search. This test embeds the exact
/// shape (a char-literal `'"'` followed by a `concat!(...)` fixture
/// containing a fake `Command::new`) and expects zero findings.
#[test]
pub(crate) fn m33_process_command_silent_after_char_literal_quote() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn fixture(name: &str) -> String {
    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    let body = concat!(
        "pub fn run_src() {\n",
        "    std::process::Command::new(\"sh\").spawn().unwrap();\n",
        "}\n"
    );
    format!("{trimmed} {body}")
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
    let command_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "security.process-command")
        .collect();
    assert!(
        command_findings.is_empty(),
        "char-literal `'\"'` must not flip the string mask; findings={command_findings:?}"
    );
}

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

