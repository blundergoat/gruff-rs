use super::*;

/// Regression guard: `waste.unnecessary-clone-candidate` must skip clones
/// whose result is immediately consumed by ownership-taking calls
/// (`unwrap_or_else`, `unwrap_or`, `unwrap_or_default`, `into`, `into_iter`,
/// `collect`, `?` propagation), struct-field initialisation, or
/// `HashMap::entry/insert` keys. These are not avoidable clones.
#[test]
pub(crate) fn unnecessary_clone_candidate_skips_consumed_or_owned_uses() {
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

/// Regression guard: `size.function-length` must skip a function whose body is
/// a single declarative literal (here, a 70-entry `vec![...]`). Function
/// length is intended to flag logic, not table-data registries.
#[test]
pub(crate) fn function_length_skips_declarative_vec_body() {
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

/// Regression guard: `waste.unwrap-expect` must skip test code (functions
/// annotated with `#[test]` and any function inside a `#[cfg(test)]`
/// module). The dedicated `test-quality.unwrap-in-test` rule covers the
/// test-side concern.
#[test]
pub(crate) fn unwrap_expect_skips_cfg_test_module() {
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

#[test]
pub(crate) fn cfg_test_items_are_test_context_but_cfg_attr_is_not_a_gate() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
#[cfg(test)]
fn cfg_test_helper() {
    let value: Option<i32> = Some(1);
    value.unwrap();
}

#[cfg_attr(test, allow(dead_code))]
fn cfg_attr_still_production() {}
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

    assert!(!report.findings.iter().any(|finding| {
        finding.symbol.as_deref() == Some("cfg_test_helper")
            && finding.rule_id == "dead-code.unused-private-function"
    }));
    assert!(report.findings.iter().any(|finding| {
        finding.symbol.as_deref() == Some("cfg_attr_still_production")
            && finding.rule_id == "dead-code.unused-private-function"
    }));
}

#[test]
pub(crate) fn mixed_cfg_any_test_feature_stays_production_reachable() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
#[cfg(any(test, feature = "bench"))]
fn mixed_cfg_helper() {}
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

    assert!(report.findings.iter().any(|finding| {
        finding.symbol.as_deref() == Some("mixed_cfg_helper")
            && finding.rule_id == "dead-code.unused-private-function"
    }));
}

/// Regression guard: prove the literal mask handles Rust character literals
/// such as `trim_matches('"')`. Without char-literal awareness, the `"`
/// inside `'"'` flips the masker into string mode and every later string
/// in the file is masked one off, leaking later `Command::new` text inside
/// `concat!()` fixtures into the regex search. This test embeds the exact
/// shape (a char-literal `'"'` followed by a `concat!(...)` fixture
/// containing a fake `Command::new`) and expects zero findings.
#[test]
pub(crate) fn process_command_silent_after_char_literal_quote() {
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

#[test]
pub(crate) fn rust_masking_preserves_non_ascii_byte_offsets_and_nested_comments() {
    let source = "éé\nlet sql = format!(\"SELECT {}\", name);\n/* outer /* inner */ still outer */\nlet done = true;\n";
    let masked_strings = strip_rust_string_literals(source);
    assert_eq!(masked_strings.len(), source.len());
    let masked_comments = strip_rust_comments_after_string_mask(&masked_strings);
    assert_eq!(masked_comments.len(), source.len());
    assert!(!masked_comments.contains("still outer"));
    let format_offset = masked_comments.find("format!").expect("format offset");
    assert_eq!(byte_line_from_starts(&line_starts(source), format_offset), 2);
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

/// Regression guard: prose inside Rust comments must not trigger code-pattern
/// line rules. `naming.short-variable`, `naming.placeholder-identifier`,
/// `waste.unwrap-expect`, and `waste.unnecessary-clone-candidate` all run
/// off the code-only line view that masks comments to spaces. The
/// `security.unsafe-block` rule remains comment-aware so it can still
/// find nearby `SAFETY:` rationale comments.
#[test]
pub(crate) fn line_rules_skip_prose_in_comments() {
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

/// Regression guard: external-public-API rules must not fire on `pub(crate)`,
/// `pub(super)`, or `pub(in path)` items. Those are crate-visible (so
/// dead-code / reachability rules still see them as reachable) but they
/// are NOT part of the external API surface, so reportable rules stay
/// silent. The corresponding `pub` bare positives are covered by the
/// existing fixture-based proofs.
#[test]
pub(crate) fn external_public_rules_skip_crate_visible_items() {
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
    // Visibility only affects public-API rules; production unwrap checks
    // still apply inside crate-visible functions.
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "waste.unwrap-expect"),
        "waste.unwrap-expect must still fire on production unwraps regardless of visibility"
    );
}

/// Regression guard: `waste.unnecessary-clone-candidate` must skip clones
/// inside `#[test]` fns and any fn inside a `#[cfg(test)]` module, so the
/// rule stays symmetric with `waste.unwrap-expect`, whose
/// `analyse_waste_line` branch already applies
/// `!line.contains("#[test]") && !self.line_is_in_test_context(...)`.
/// A production clone outside any test context must still fire so the
/// guard does not silence real waste.
#[test]
pub(crate) fn unnecessary_clone_candidate_skips_test_context() {
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

/// Negative: `sensitive-data.high-entropy-string` must skip subresource
/// integrity hashes (`sha256-...`, `sha512-...`, etc.) committed in
/// lockfiles, integrity manifests, and HTML `integrity` attributes. The
/// rule must still fire on a real high-entropy string literal in the
/// same fixture so the skip is provably scoped to the prefix.
#[test]
pub(crate) fn high_entropy_string_skips_integrity_hashes() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r##"/// Probe.
pub fn entry() {
    let _sri_256 = "sha256-pDhVbGGHEIRHH5vpSIdcFkMAjiIIyqatK7tGw30sPmoGlSN7";
    let _sri_512 = "sha512-pDhVbGGHEIRHH5vpSIdcFkMAjiIIyqatK7tGw30sPmoGlSN7+/ls0rb2R/x42DYbwli3ZokMiTyJFhGQBdJCpg==";
    let _bare_secret = "Q7m2P9x8R4s6T1v3W5y7Z0a2B4c6D8e0";
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
    let entropy_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "sensitive-data.high-entropy-string")
        .collect();
    assert_eq!(
        entropy_findings.len(),
        1,
        "expected exactly one entropy finding (the bare secret); findings={entropy_findings:?}"
    );
}
