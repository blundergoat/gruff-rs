use super::dead_code::has_dead_code_symbol;
use super::*;

#[test]
pub(crate) fn project_dead_code_honors_module_level_allow_dead_code() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        "pub mod generated;\nfn ordinary_unused() {}\npub fn entry() {}\n",
    )
    .expect("lib write");
    // A module file with an inner `#![allow(dead_code)]` keeps its items on purpose.
    fs::write(
        dir.path().join("src/generated.rs"),
        "#![allow(dead_code)]\nfn intentionally_kept() {}\n",
    )
    .expect("generated write");

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
    assert!(
        !has_dead_code_symbol(&report, "intentionally_kept"),
        "module-level #![allow(dead_code)] must suppress its private items"
    );
    assert!(
        has_dead_code_symbol(&report, "ordinary_unused"),
        "an unrelated unused private item must still flag"
    );
}

#[test]
pub(crate) fn project_dead_code_suppressed_when_a_sibling_fails_to_parse() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    // `helper_used_by_sibling` is referenced only by the sibling that fails to parse.
    fs::write(
        dir.path().join("src/lib.rs"),
        "mod broken;\nfn helper_used_by_sibling() {}\npub fn entry() {}\n",
    )
    .expect("lib write");
    fs::write(
        dir.path().join("src/broken.rs"),
        "pub fn call( { crate::helper_used_by_sibling() }\n",
    )
    .expect("broken write");

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
    assert!(
        !has_dead_code_symbol(&report, "helper_used_by_sibling"),
        "a parse-failed sibling makes coverage partial, suppressing cross-file dead-code"
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.diagnostic_type == "partial-context-rule-suppressed"),
        "partial coverage from the unparseable file must emit the suppression diagnostic"
    );
}

#[test]
pub(crate) fn dead_code_partial_context_suppresses_candidate_when_rust_read_fails() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("src/lib.rs"),
        "mod unreadable;\nfn helper_used_by_unreadable_sibling() {}\npub fn entry() {}\n",
    )
    .expect("lib write");
    fs::write(
        dir.path().join("src/unreadable.rs"),
        b"pub fn call() { crate::helper_used_by_unreadable_sibling(); }\n\x80",
    )
    .expect("invalid Rust write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            fail_on: FailThreshold::None,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert!(
        !has_dead_code_symbol(&report, "helper_used_by_unreadable_sibling"),
        "a read-failed Rust sibling makes cross-file dead-code unauthoritative"
    );
    let read_error = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.diagnostic_type == "read-error")
        .expect("read error remains visible");
    assert_eq!(read_error.file_path.as_deref(), Some("src/unreadable.rs"));
    assert!(
        read_error.is_failure(),
        "the existing read error stays fatal"
    );
    let suppression = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.diagnostic_type == "partial-context-rule-suppressed")
        .expect("partial-context suppression remains visible");
    assert!(suppression.message.contains("gruff-rs analyse ."));
    assert_eq!(
        RunOutcome::classify(&report, FailThreshold::None, None),
        RunOutcome::DiagnosticsFailed
    );
}
