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
