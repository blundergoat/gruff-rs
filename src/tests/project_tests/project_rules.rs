use super::*;

#[test]
pub(crate) fn dependency_rules_flag_local_manifest_and_lockfile_posture() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "dependency-positive-fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
wildcard = "*"
gitdep = { git = "https://example.invalid/repo.git", rev = "1111111111111111111111111111111111111111" }
gitunpinned = { git = "https://example.invalid/unpinned.git" }
pathdep = { path = "../local-path" }
"#,
        )
        .expect("manifest write");
    fs::write(
        dir.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "duplicate"
version = "1.0.0"

[[package]]
name = "duplicate"
version = "2.0.0"

[[package]]
name = "duplicate"
version = "3.0.0"
"#,
    )
    .expect("lockfile write");

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

    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert_has_rule(&report, "dependency.git-source");
    assert_has_rule(&report, "dependency.git-unpinned-revision");
    assert_has_rule(&report, "dependency.path-source");
    assert_has_rule(&report, "dependency.wildcard-version");
    assert_has_rule(&report, "dependency.duplicate-locked-version");
    assert_has_rule(&report, "dependency.missing-package-metadata");

    let git = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "dependency.git-source")
        .expect("git source finding");
    assert_eq!(git.file_path, "Cargo.toml");
    assert_eq!(git.line, Some(8));
    assert_eq!(git.symbol.as_deref(), Some("gitdep"));
    assert_eq!(git.pillar, Pillar::Security);

    let unpinned = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "dependency.git-unpinned-revision")
        .expect("unpinned git source finding");
    assert_eq!(unpinned.file_path, "Cargo.toml");
    assert_eq!(unpinned.line, Some(9));
    assert_eq!(unpinned.symbol.as_deref(), Some("gitunpinned"));
    assert_eq!(unpinned.pillar, Pillar::Security);

    let metadata = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "dependency.missing-package-metadata")
        .expect("metadata finding");
    assert_eq!(metadata.file_path, "Cargo.toml");
    assert_eq!(metadata.line, Some(1));
    assert_eq!(metadata.pillar, Pillar::Documentation);

    let duplicate = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "dependency.duplicate-locked-version")
        .expect("duplicate lockfile finding");
    assert_eq!(duplicate.file_path, "Cargo.lock");
    assert_eq!(duplicate.line, Some(4));
    assert_eq!(duplicate.symbol.as_deref(), Some("duplicate"));

    let security = report
        .score
        .pillars
        .iter()
        .find(|pillar| pillar.pillar == Pillar::Security)
        .expect("security score");
    assert!(
        security.findings >= 5,
        "expected dependency findings to affect security: {security:?}"
    );
}

#[test]
pub(crate) fn dependency_rules_scan_target_specific_manifest_tables() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("Cargo.toml"),
        r#"[package]
name = "target-dependency-fixture"
version = "0.1.0"
edition = "2021"

[target.'cfg(unix)'.dependencies]
targetwild = "*"
targetgit = { git = "https://example.invalid/target.git" }
"#,
    )
    .expect("manifest write");

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

    let wildcard = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "dependency.wildcard-version")
        .expect("target wildcard finding");
    assert_eq!(wildcard.symbol.as_deref(), Some("targetwild"));
    assert_eq!(wildcard.line, Some(7));
    let unpinned = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "dependency.git-unpinned-revision")
        .expect("target git finding");
    assert_eq!(unpinned.symbol.as_deref(), Some("targetgit"));
    assert_eq!(unpinned.line, Some(8));
}

#[test]
pub(crate) fn dependency_rules_accept_clean_manifest_and_config_threshold() {
    let _guard = analysis_lock();
    let clean_dir = tempdir().expect("tempdir");
    fs::write(clean_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        clean_dir.path().join("Cargo.toml"),
        r#"[package]
name = "dependency-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dependency rule tests."
license = "MIT"

[dependencies]
serde = "1"
"#,
    )
    .expect("manifest write");
    fs::write(
        clean_dir.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "serde"
version = "1.0.0"
"#,
    )
    .expect("lockfile write");
    let clean = run_project_analysis(
        clean_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("clean analysis succeeds");
    assert_missing_rule(&clean, "dependency.git-source");
    assert_missing_rule(&clean, "dependency.git-unpinned-revision");
    assert_missing_rule(&clean, "dependency.path-source");
    assert_missing_rule(&clean, "dependency.wildcard-version");
    assert_missing_rule(&clean, "dependency.duplicate-locked-version");
    assert_missing_rule(&clean, "dependency.missing-package-metadata");

    let threshold_dir = tempdir().expect("tempdir");
    fs::write(threshold_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        threshold_dir.path().join("Cargo.toml"),
        r#"[package]
name = "dependency-threshold-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dependency threshold tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        threshold_dir.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "duplicate"
version = "1.0.0"

[[package]]
name = "duplicate"
version = "2.0.0"

[[package]]
name = "duplicate"
version = "3.0.0"
"#,
    )
    .expect("lockfile write");
    write_config(
        threshold_dir.path(),
        r#"
rules:
  dependency.duplicate-locked-version:
    threshold: 3
    severity: advisory
"#,
    );
    let thresholded = run_project_analysis(
        threshold_dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("thresholded analysis succeeds");
    assert_missing_rule(&thresholded, "dependency.duplicate-locked-version");

    write_config(
        threshold_dir.path(),
        r#"
rules:
  dependency.duplicate-locked-version:
    threshold: 2
    severity: severe
"#,
    );
    let error =
        load_config(threshold_dir.path(), &default_test_options()).expect_err("bad threshold");
    assert!(
            error.contains(
                "config key `rules.dependency.duplicate-locked-version.severity` must be advisory, warning, or error"
            ),
            "{error}"
        );
}

#[test]
pub(crate) fn architecture_rules_flag_module_shape_and_public_surface() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("Cargo.toml"),
        r#"[package]
name = "architecture-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for architecture rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        dir.path().join("src/lib.rs"),
        r#"pub mod api {
    pub struct One;
    pub struct Two;
    pub enum Three {
        Ready,
    }
    pub trait Four {}
}
mod alpha;
mod beta;
mod gamma;
"#,
    )
    .expect("lib write");
    write_config(
        dir.path(),
        r#"
rules:
  architecture.module-fan-out:
    threshold: 2
    severity: advisory
  architecture.public-api-surface:
    threshold: 2
    severity: advisory
  architecture.large-module:
    threshold: 3
    severity: advisory
"#,
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
    .expect("architecture analysis succeeds");

    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert_has_rule(&report, "architecture.module-fan-out");
    assert_has_rule(&report, "architecture.public-api-surface");
    assert_has_rule(&report, "architecture.large-module");

    let fan_out = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "architecture.module-fan-out")
        .expect("module fan-out finding");
    assert_eq!(fan_out.file_path, "src/lib.rs");
    assert_eq!(fan_out.line, Some(1));
    assert_eq!(fan_out.symbol.as_deref(), Some("src/lib.rs"));
    assert_eq!(fan_out.metadata["modules"], json!(4));
    assert!(fan_out.message.contains("4 child modules"));

    let public_surface = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "architecture.public-api-surface")
        .expect("public API finding");
    assert_eq!(public_surface.symbol.as_deref(), Some("api"));
    assert_eq!(public_surface.metadata["publicItems"], json!(4));

    let large_module = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "architecture.large-module")
        .expect("large module finding");
    assert_eq!(large_module.symbol.as_deref(), Some("api"));
    assert_eq!(large_module.metadata["items"], json!(4));
}

#[test]
pub(crate) fn architecture_rules_accept_small_modules_and_validate_threshold() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("Cargo.toml"),
        r#"[package]
name = "architecture-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for architecture rule tests."
license = "MIT"
"#,
    )
    .expect("manifest write");
    fs::write(
        dir.path().join("src/lib.rs"),
        r#"pub mod api {
    pub struct One;
}
mod alpha;
"#,
    )
    .expect("lib write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("small architecture analysis succeeds");
    assert_missing_rule(&report, "architecture.module-fan-out");
    assert_missing_rule(&report, "architecture.public-api-surface");
    assert_missing_rule(&report, "architecture.large-module");

    write_config(
        dir.path(),
        r#"
rules:
  architecture.large-module:
    threshold: 2
    severity: severe
"#,
    );
    let error =
        load_config(dir.path(), &default_test_options()).expect_err("bad threshold rejected");
    assert!(
            error.contains(
                "config key `rules.architecture.large-module.severity` must be advisory, warning, or error"
            ),
            "{error}"
        );
}

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
pub(crate) fn missing_readme_accepts_common_case_variants() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    baseline_with_lib(dir.path(), "pub fn entry() {}\n");
    fs::remove_file(dir.path().join("README.md")).expect("remove readme");
    fs::write(dir.path().join("readme.md"), "# Fixture\n").expect("readme write");

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

    assert_missing_rule(&report, "docs.missing-readme");
}
