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
