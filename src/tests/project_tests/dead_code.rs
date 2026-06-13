use super::*;

#[test]
pub(crate) fn dead_code_project_candidates_use_conservative_cross_file_evidence() {
    let _guard = analysis_lock();
    let positive_dir = tempdir().expect("tempdir");
    fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
    fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        positive_dir.path().join("Cargo.toml"),
        r#"[package]
name = "dead-code-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dead-code rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        positive_dir.path().join("src/lib.rs"),
        r#"fn isolated_helper() {}

const UNUSED_LIMIT: usize = 1;

static UNUSED_STATE: &str = "off";

type HiddenAlias = usize;

struct HiddenType;

enum HiddenEnum {
    Ready,
}

trait HiddenTrait {}

fn referenced_helper() {}

pub fn entry() {
    referenced_helper();
}
"#,
    )
    .expect("positive lib write");

    let positive = run_project_analysis(
        positive_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("dead-code positive analysis succeeds");
    assert_has_rule(&positive, "dead-code.unused-private-item-candidate");
    let candidate = positive
        .findings
        .iter()
        .find(|finding| {
            finding.rule_id == "dead-code.unused-private-item-candidate"
                && finding.symbol.as_deref() == Some("isolated_helper")
        })
        .expect("isolated helper candidate");
    assert!(candidate.message.contains("candidate"));
    assert!(matches!(candidate.confidence, Confidence::Medium));
    assert_eq!(candidate.metadata["candidate"], json!(true));
    assert_eq!(candidate.fingerprint, "395572648fc5a9b0");
    for symbol in ["UNUSED_LIMIT", "UNUSED_STATE", "HiddenAlias"] {
        assert!(
            positive.findings.iter().any(|finding| {
                finding.rule_id == "dead-code.unused-private-item-candidate"
                    && finding.symbol.as_deref() == Some(symbol)
            }),
            "expected new private item candidate `{symbol}`; findings={:?}",
            positive
                .findings
                .iter()
                .map(|finding| (&finding.rule_id, finding.symbol.as_deref()))
                .collect::<Vec<_>>()
        );
    }

    let negative_dir = tempdir().expect("tempdir");
    fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
    fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        negative_dir.path().join("Cargo.toml"),
        r#"[package]
name = "dead-code-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dead-code rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        negative_dir.path().join("src/lib.rs"),
        r#"macro_rules! register {
    ($item:ident) => {};
}

fn macro_registered() {}
register!(macro_registered);

#[cfg(feature = "optional")]
fn cfg_only() {}

#[test]
fn test_only_helper() {}

mod tests {
    fn module_test_helper() {}
}

struct Worker;

impl Worker {
    fn new() -> Self {
        Worker
    }

    fn len(&self) -> usize {
        0
    }
}

trait Job {
    fn poll(&self);
}

impl Job for Worker {
    fn poll(&self) {}
}

fn referenced_helper() {}

pub fn entry() {
    referenced_helper();
}
"#,
    )
    .expect("negative lib write");

    let negative = run_project_analysis(
        negative_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("dead-code negative analysis succeeds");
    assert_missing_rule(&negative, "dead-code.unused-private-item-candidate");
}

#[test]
pub(crate) fn project_dead_code_ignores_comment_mentions_and_test_cfg_helpers() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"fn comment_only_reference() {}
// comment_only_reference is only mentioned in prose.

#[cfg(test)] fn cfg_test_helper() {}
#[cfg_attr(test, allow(dead_code))] struct CfgAttrStillProduction;
"#,
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

    let has_dead_item = |symbol| {
        report.findings.iter().any(|finding| {
            finding.rule_id == "dead-code.unused-private-item-candidate"
                && finding.symbol.as_deref() == Some(symbol)
        })
    };
    assert!(has_dead_item("comment_only_reference"));
    assert!(!has_dead_item("cfg_test_helper"));
    assert!(has_dead_item("CfgAttrStillProduction"));
}

#[test]
pub(crate) fn project_dead_code_skips_attribute_exported_and_allowed_items() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(
        dir.path(),
        r#"#[no_mangle]
unsafe extern "C" fn ffi_entry() -> i32 {
    0
}

#[export_name = "renamed_entry"]
fn renamed_entry() {}

#[unsafe(no_mangle)]
unsafe extern "C" fn ffi_entry_2024() -> i32 {
    0
}

#[unsafe(export_name = "renamed_entry_2024")]
fn renamed_entry_2024() {}

#[pymodule]
fn plugin_module() {}

#[pyfunction]
fn plugin_function() {}

#[allow(dead_code)]
fn intentionally_registered() {}

#[allow(dead_code)]
mod plugin_generated {
    fn module_registered() {}
}

fn ordinary_unused() {}

pub fn entry() {}
"#,
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

    let candidate_symbols: BTreeSet<&str> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "dead-code.unused-private-item-candidate")
        .filter_map(|finding| finding.symbol.as_deref())
        .collect();
    assert!(
        candidate_symbols.contains("ordinary_unused"),
        "ordinary unused private item must still flag; symbols={candidate_symbols:?}"
    );
    for exported in [
        "ffi_entry",
        "renamed_entry",
        "ffi_entry_2024",
        "renamed_entry_2024",
        "plugin_module",
        "plugin_function",
        "intentionally_registered",
        "module_registered",
    ] {
        assert!(
            !candidate_symbols.contains(exported),
            "attribute-exported or allow(dead_code) item `{exported}` must stay silent; symbols={candidate_symbols:?}"
        );
    }
}

#[test]
pub(crate) fn dead_code_single_file_crate_reports_unused_private_item_on_narrow_path() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("Cargo.toml"),
        r#"[package]
name = "dead-code-single-file-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dead-code partial-context tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        dir.path().join("src/lib.rs"),
        r#"fn genuinely_unused() {}

pub fn entry() {}
"#,
    )
    .expect("lib write");

    let whole = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("whole-crate analysis succeeds");
    assert!(
        has_dead_code_symbol(&whole, "genuinely_unused"),
        "whole-crate scan should report unused private item"
    );

    let narrow = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("single-file analysis succeeds");
    assert!(
        has_dead_code_symbol(&narrow, "genuinely_unused"),
        "single-file crate narrow scan should still report unused private item"
    );
}

#[test]
pub(crate) fn dead_code_partial_context_suppresses_cross_file_candidate() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_cross_file_dead_code_fixture(dir.path());

    let whole = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("whole-crate analysis succeeds");
    assert!(
        !has_dead_code_symbol(&whole, "helper_used_by_child"),
        "whole-crate scan sees sibling reference"
    );

    let narrow = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("narrow analysis succeeds");
    assert!(
        !has_dead_code_symbol(&narrow, "helper_used_by_child"),
        "partial-context scan must not claim sibling-referenced item is unused"
    );
    assert!(
        has_partial_context_diagnostic(&narrow),
        "partial-context suppression should be visible in analyse diagnostics"
    );
}

#[test]
pub(crate) fn dead_code_diff_patch_partial_context_suppresses_candidate() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_cross_file_dead_code_fixture(dir.path());
    fs::write(
        dir.path().join("lib.patch"),
        "diff --git a/src/lib.rs b/src/lib.rs\n\
--- a/src/lib.rs\n\
+++ b/src/lib.rs\n\
@@ -0,0 +1,3 @@\n\
+mod child;\n\
+fn helper_used_by_child() {}\n\
+pub fn entry() {}\n",
    )
    .expect("patch write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            diff: Some(DiffSelection::Patch {
                path: PathBuf::from("lib.patch"),
                scope: ChangedScope::Symbol,
            }),
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("diff-patch analysis succeeds");
    assert!(
        !has_dead_code_symbol(&report, "helper_used_by_child"),
        "diff-patch partial-context scan must not claim sibling-referenced item is unused"
    );
    assert!(
        has_partial_context_diagnostic(&report),
        "diff-patch suppression should be visible in analyse diagnostics"
    );
}

#[test]
pub(crate) fn dead_code_partial_context_coverage_tracks_actual_rust_file_universe() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_cross_file_dead_code_fixture(dir.path());

    let whole = project_coverage_for_test(
        dir.path(),
        &AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
        &load_config(
            dir.path(),
            &AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("config loads"),
    )
    .expect("coverage resolves");
    assert!(
        !whole.is_partial(),
        "whole-project analysis covers every discoverable Rust source"
    );

    let narrow_options = AnalysisOptions {
        paths: vec![PathBuf::from("src/lib.rs")],
        no_config: true,
        no_baseline: true,
        ..default_test_options()
    };
    let narrow_config = load_config(dir.path(), &narrow_options).expect("config loads");
    let narrow =
        project_coverage_for_test(dir.path(), &narrow_options, &narrow_config).expect("coverage");
    assert!(
        narrow.is_partial(),
        "multi-file crate with only src/lib.rs analysed is partial"
    );

    let single = tempdir().expect("tempdir");
    fs::create_dir_all(single.path().join("src")).expect("single src dir");
    fs::write(single.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        single.path().join("Cargo.toml"),
        r#"[package]
name = "single-file-coverage-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for coverage tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(single.path().join("src/lib.rs"), "fn unused() {}\n").expect("lib write");
    let single_options = AnalysisOptions {
        paths: vec![PathBuf::from("src/lib.rs")],
        no_config: true,
        no_baseline: true,
        ..default_test_options()
    };
    let single_config = load_config(single.path(), &single_options).expect("config loads");
    let single_coverage = project_coverage_for_test(single.path(), &single_options, &single_config)
        .expect("coverage resolves");
    assert!(
        !single_coverage.is_partial(),
        "single-file crate remains complete even when that file is named directly"
    );

    let ignored = tempdir().expect("tempdir");
    write_cross_file_dead_code_fixture(ignored.path());
    write_config(ignored.path(), "paths:\n  ignore:\n    - src/child.rs\n");
    let ignored_options = AnalysisOptions {
        paths: vec![PathBuf::from("src/lib.rs")],
        no_config: false,
        no_baseline: true,
        ..default_test_options()
    };
    let ignored_config = load_config(ignored.path(), &ignored_options).expect("config loads");
    let ignored_coverage =
        project_coverage_for_test(ignored.path(), &ignored_options, &ignored_config)
            .expect("coverage resolves");
    assert!(
        !ignored_coverage.is_partial(),
        "config-ignored Rust siblings are outside the discoverable universe"
    );

    fs::write(
        dir.path().join("lib.patch"),
        "diff --git a/src/lib.rs b/src/lib.rs\n\
--- a/src/lib.rs\n\
+++ b/src/lib.rs\n\
@@ -0,0 +1,3 @@\n\
+mod child;\n\
+fn helper_used_by_child() {}\n\
+pub fn entry() {}\n",
    )
    .expect("patch write");
    let patch_options = AnalysisOptions {
        paths: vec![PathBuf::from(".")],
        diff: Some(DiffSelection::Patch {
            path: PathBuf::from("lib.patch"),
            scope: ChangedScope::Symbol,
        }),
        no_config: true,
        no_baseline: true,
        ..default_test_options()
    };
    let patch_config = load_config(dir.path(), &patch_options).expect("config loads");
    let patch_coverage = project_coverage_for_test(dir.path(), &patch_options, &patch_config)
        .expect("coverage resolves");
    assert!(
        patch_coverage.is_partial(),
        "patch file selection is partial when it removes discoverable Rust sources"
    );
}

pub(super) fn has_dead_code_symbol(report: &AnalysisReport, symbol: &str) -> bool {
    report.findings.iter().any(|finding| {
        finding.rule_id == "dead-code.unused-private-item-candidate"
            && finding.symbol.as_deref() == Some(symbol)
    })
}

fn has_partial_context_diagnostic(report: &AnalysisReport) -> bool {
    report.diagnostics.iter().any(|diagnostic| {
        diagnostic.diagnostic_type == "partial-context-rule-suppressed"
            && diagnostic
                .message
                .contains("dead-code.unused-private-item-candidate")
    })
}

fn write_cross_file_dead_code_fixture(root: &Path) {
    fs::create_dir_all(root.join("src")).expect("src dir");
    fs::write(root.join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        root.join("Cargo.toml"),
        r#"[package]
name = "dead-code-partial-context-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dead-code partial-context tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        root.join("src/lib.rs"),
        r#"mod child;
fn helper_used_by_child() {}
pub fn entry() {}
"#,
    )
    .expect("lib write");
    fs::write(
        root.join("src/child.rs"),
        r#"pub fn call() {
    crate::helper_used_by_child();
}
"#,
    )
    .expect("child write");
}
