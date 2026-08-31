//! Sensitive-data suppression contracts for the `sensitiveExclusions` config section.
//!
//! Acceptance cases prove a declared scope suppresses exactly the findings inside it, publishes
//! an audit row, and leaves every sibling finding reporting. Rejection cases prove each ratified
//! configuration error stops the command before analysis. Cases and fixtures follow
//! `gruff-spec/fixtures/sensitive-exclusions/cases.v1.json` and the synthetic renderings in
//! `gruff-spec/fixtures/redaction/corpus.v1.json`; every value here is synthetic.

use super::*;

/// Rendered corpus case `aws`, kept byte-identical to the family fixture.
const CORPUS_AWS_PATH: &str = "src/aws_config.rs";
/// Rendered corpus case `aws-sibling`: the same rule in a second file.
const CORPUS_AWS_SIBLING_PATH: &str = "src/aws_sibling.rs";
/// Rendered corpus case `jwt`: a second sensitive rule in a second file.
const CORPUS_JWT_PATH: &str = "src/session_token.rs";
/// Rendered corpus case `clean`: a file the sensitive-data pillar never reports.
const CORPUS_CLEAN_PATH: &str = "src/app_config.rs";

const AWS_RULE_ID: &str = "sensitive-data.aws-access-key";

/// Materialise the four corpus cases this suite needs into one temporary project.
/// The values are the spec's synthetic sentinels, so no real credential is ever written.
fn write_redaction_corpus(project_root: &Path) {
    let aws_source = concat!(
        "//! Synthetic redaction fixture.\n\n",
        "/// Synthetic value used only by the family redaction suite.\n",
        "pub const AWS_ACCESS_KEY_ID: &str = \"AKIAQQZZRSTVZZZZWWWW\";\n"
    );
    let jwt_source = concat!(
        "//! Synthetic redaction fixture.\n\n",
        "/// Synthetic value used only by the family redaction suite.\n",
        "pub const SESSION_TOKEN: &str = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.",
        "c3ludGhldGljLXNpZ25hdHVyZS12YWx1ZS16ZXJvLXBheWxvYWQ\";\n"
    );
    let clean_source = concat!(
        "//! Synthetic redaction fixture with no secret material.\n\n",
        "/// Identifies the synthetic fixture application.\n",
        "pub const APP_NAME: &str = \"gruff-conformance\";\n"
    );
    fs::create_dir_all(project_root.join("src")).expect("corpus src dir");
    fs::write(project_root.join(CORPUS_AWS_PATH), aws_source).expect("aws case write");
    fs::write(project_root.join(CORPUS_AWS_SIBLING_PATH), aws_source).expect("sibling case write");
    fs::write(project_root.join(CORPUS_JWT_PATH), jwt_source).expect("jwt case write");
    fs::write(project_root.join(CORPUS_CLEAN_PATH), clean_source).expect("clean case write");
}

/// Analyse the corpus project under one config body and return its report.
/// The config always exists, so only the `sensitiveExclusions` section varies between runs.
fn analyse_corpus_with_config(project_root: &Path, config_body: &str) -> AnalysisReport {
    write_config(project_root, config_body);
    run_project_analysis(
        project_root,
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("corpus analysis succeeds")
}

/// Load config for the corpus project and return the loader's error.
/// Rejection cases need the diagnostic text, which never reaches an analysis report.
fn corpus_config_error(project_root: &Path, config_body: &str) -> String {
    write_config(project_root, config_body);
    load_config(project_root, &default_test_options()).expect_err("configuration is rejected")
}

/// Collect one report's findings as comparable `rule id @ path` pairs.
/// The sibling rule in the family case file is checked by differencing two of these sets.
fn finding_scopes(report: &AnalysisReport) -> BTreeSet<String> {
    report
        .findings
        .iter()
        .map(|finding| format!("{} @ {}", finding.rule_id, finding.file_path))
        .collect()
}

/// Assert the configured run removed exactly the declared scopes and nothing else.
/// An unintended sibling suppression fails here rather than silently hiding a finding.
fn assert_removed_scopes(
    baseline: &AnalysisReport,
    configured: &AnalysisReport,
    expected: &[String],
) {
    let removed: BTreeSet<String> = finding_scopes(baseline)
        .difference(&finding_scopes(configured))
        .cloned()
        .collect();
    let expected: BTreeSet<String> = expected.iter().cloned().collect();
    assert_eq!(removed, expected, "unintended sibling suppression");
}

/// Suppress every occurrence of one rule in one file and leave every sibling reporting.
#[test]
pub(crate) fn sensitive_exclusion_suppresses_one_rule_in_one_file() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_redaction_corpus(dir.path());

    let baseline = analyse_corpus_with_config(dir.path(), "");
    let configured = analyse_corpus_with_config(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
    reason: Synthetic AWS key used by the redaction corpus; not a live credential.
"#,
    );

    assert_removed_scopes(
        &baseline,
        &configured,
        &[format!("{AWS_RULE_ID} @ {CORPUS_AWS_PATH}")],
    );
    assert!(configured.suppressions[0].suppressed >= 1);
    // The same rule in another file and another rule in the same file both keep reporting.
    assert!(
        finding_scopes(&configured).contains(&format!("{AWS_RULE_ID} @ {CORPUS_AWS_SIBLING_PATH}"))
    );
    assert!(finding_scopes(&configured)
        .contains(&format!("sensitive-data.jwt-token @ {CORPUS_JWT_PATH}")));
}

/// Publish the family audit row, including its zero-payload keys and the text total.
#[test]
pub(crate) fn sensitive_exclusion_publishes_audit_row_and_text_total() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_redaction_corpus(dir.path());

    let report = analyse_corpus_with_config(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
    reason: Synthetic AWS key used by the redaction corpus; not a live credential.
"#,
    );

    let json: Value =
        serde_json::from_str(&render_report(&report, OutputFormat::Json)).expect("json report");
    let row = &json["suppressions"][0];
    assert_eq!(row["index"], 0);
    assert_eq!(row["rule"], AWS_RULE_ID);
    assert_eq!(row["paths"][0], CORPUS_AWS_PATH);
    assert!(row.get("symbol").is_none());
    assert_eq!(
        row["reason"],
        "Synthetic AWS key used by the redaction corpus; not a live credential."
    );
    assert_eq!(row["suppressed"], 1);

    let text = render_report(&report, OutputFormat::Text);
    assert!(
        text.contains("Suppressed findings: 1 via sensitiveExclusions[0]"),
        "{text}"
    );
    // No reported surface may carry matched value material (FAMILY-CONTRACT.md section 5).
    assert!(!text.contains("AKIA"), "{text}");
}

/// Return the one audit line a text surface publishes, so two surfaces can be compared.
fn suppression_line(text: &str) -> &str {
    text.lines()
        .find(|line| line.starts_with("Suppressed findings: "))
        .expect("text surface publishes a suppression line")
}

/// Report the suppression count on `summary` text, the surface that applies it.
/// FAMILY-CONTRACT.md section 13a: a surface may decline to filter, but it may never
/// filter in silence, and the count it publishes is the count `analyse` publishes.
#[test]
pub(crate) fn sensitive_exclusion_reports_its_count_on_summary_text() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_redaction_corpus(dir.path());

    let baseline = analyse_corpus_with_config(dir.path(), "");
    let configured = analyse_corpus_with_config(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
    reason: Synthetic AWS key used by the redaction corpus; not a live credential.
"#,
    );

    // `summary` keeps filtering: it renders the report the exclusion already shrank.
    assert_eq!(configured.findings.len() + 1, baseline.findings.len());

    let summary_text = crate::summary::render(&configured, 5, SummaryFormat::Text, 0);
    assert!(
        summary_text.contains("Suppressed findings: 1 via sensitiveExclusions[0]"),
        "{summary_text}"
    );
    // The audit line sits below the canonical block, never inside it.
    assert!(
        summary_text.find("Composite:") < summary_text.find("Suppressed findings:"),
        "{summary_text}"
    );
    // Same tree, same count: the `analyse` wording is reused, not restated.
    let analyse_text = render_report(&configured, OutputFormat::Text);
    assert_eq!(
        suppression_line(&summary_text),
        suppression_line(&analyse_text)
    );
    // No reported surface may carry matched value material (FAMILY-CONTRACT.md section 5).
    assert!(!summary_text.contains("AKIA"), "{summary_text}");
}

/// Report zero rather than failing when a declared scope matches no finding.
#[test]
pub(crate) fn sensitive_exclusion_scope_matching_nothing_reports_zero() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_redaction_corpus(dir.path());

    let baseline = analyse_corpus_with_config(dir.path(), "");
    let configured = analyse_corpus_with_config(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/app_config.rs
    reason: Retained while the fixture is being removed.
"#,
    );

    assert_removed_scopes(&baseline, &configured, &[]);
    assert_eq!(configured.suppressions[0].suppressed, 0);
    assert_eq!(configured.suppressions[0].paths, vec![CORPUS_CLEAN_PATH]);
}

/// Accept and validate a symbol, which narrows a scope no sensitive finding carries today.
#[test]
pub(crate) fn sensitive_exclusion_symbol_narrows_scope_to_nothing() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_redaction_corpus(dir.path());

    let baseline = analyse_corpus_with_config(dir.path(), "");
    let configured = analyse_corpus_with_config(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
    symbol: SyntheticFixtureSymbol
    reason: Narrowed to one symbol while the fixture is refactored.
"#,
    );

    assert_removed_scopes(&baseline, &configured, &[]);
    assert_eq!(configured.suppressions[0].suppressed, 0);
    assert_eq!(
        configured.suppressions[0].symbol.as_deref(),
        Some("SyntheticFixtureSymbol")
    );
}

/// Count two independent scopes separately and suppress each one exactly.
#[test]
pub(crate) fn sensitive_exclusion_entries_count_independently() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_redaction_corpus(dir.path());

    let baseline = analyse_corpus_with_config(dir.path(), "");
    let configured = analyse_corpus_with_config(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
    reason: Synthetic AWS key in the redaction corpus.
  - rule: sensitive-data.jwt-token
    path: src/session_token.rs
    reason: Synthetic JWT in the redaction corpus.
"#,
    );

    assert_removed_scopes(
        &baseline,
        &configured,
        &[
            format!("{AWS_RULE_ID} @ {CORPUS_AWS_PATH}"),
            format!("sensitive-data.jwt-token @ {CORPUS_JWT_PATH}"),
        ],
    );
    assert_eq!(configured.suppressions[0].index, 0);
    assert_eq!(configured.suppressions[1].index, 1);
    assert!(configured.suppressions[0].suppressed >= 1);
    assert!(configured.suppressions[1].suppressed >= 1);
}

/// Keep the same rule reporting in every file the user did not declare.
#[test]
pub(crate) fn sensitive_exclusion_leaves_same_rule_in_other_file_reporting() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_redaction_corpus(dir.path());

    let baseline = analyse_corpus_with_config(dir.path(), "");
    let configured = analyse_corpus_with_config(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_sibling.rs
    reason: Only the sibling fixture is accepted.
"#,
    );

    assert_removed_scopes(
        &baseline,
        &configured,
        &[format!("{AWS_RULE_ID} @ {CORPUS_AWS_SIBLING_PATH}")],
    );
    assert!(finding_scopes(&configured).contains(&format!("{AWS_RULE_ID} @ {CORPUS_AWS_PATH}")));
}

/// Keep both suppression channels usable together with section-local audit indexes.
#[test]
pub(crate) fn ordinary_exclusions_and_sensitive_exclusions_coexist() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_redaction_corpus(dir.path());

    let report = analyse_corpus_with_config(
        dir.path(),
        r#"
exclude:
  - rule: sensitive-data.jwt-token
    message_contains: JWT
    reason: Ordinary message matching stays available for non-sensitive redesign scope.
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
    reason: Synthetic AWS key used by the redaction corpus; not a live credential.
"#,
    );

    assert_eq!(report.suppressions[0].config_key, "exclude");
    assert_eq!(report.suppressions[0].index, 0);
    assert_eq!(report.suppressions[1].config_key, "sensitiveExclusions");
    assert_eq!(report.suppressions[1].index, 0);
    assert!(report.suppressions[1].suppressed >= 1);

    let text = render_report(&report, OutputFormat::Text);
    assert!(
        text.contains("exclude[0] sensitive-data.jwt-token"),
        "{text}"
    );
    assert!(
        text.contains("sensitiveExclusions[0] sensitive-data.aws-access-key"),
        "{text}"
    );
}

/// Reject a rationale that is missing or contains only whitespace.
#[test]
pub(crate) fn sensitive_exclusion_requires_a_rationale() {
    let dir = tempdir().expect("tempdir");

    let missing = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
"#,
    );
    assert!(
        missing.contains("missing required config key `sensitiveExclusions[0].reason`"),
        "{missing}"
    );

    let blank = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
    reason: "   "
"#,
    );
    assert!(
        blank.contains("config key `sensitiveExclusions[0].reason` must be a non-empty string"),
        "{blank}"
    );
}

/// Reject every rule value that selects more than one rule.
#[test]
pub(crate) fn sensitive_exclusion_rejects_wildcard_pillar_and_glob_rules() {
    let dir = tempdir().expect("tempdir");

    let wildcard = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: "*"
    path: src/aws_config.rs
    reason: Everything here is synthetic.
"#,
    );
    assert!(
        wildcard.contains("config key `sensitiveExclusions[0].rule` must name one exact rule id"),
        "{wildcard}"
    );

    let pillar = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data
    path: src/aws_config.rs
    reason: Everything here is synthetic.
"#,
    );
    assert!(
        pillar.contains("not the pillar selector `sensitive-data`"),
        "{pillar}"
    );

    let glob = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.*
    path: src/aws_config.rs
    reason: Everything here is synthetic.
"#,
    );
    assert!(
        glob.contains("config key `sensitiveExclusions[0].rule` must name one exact rule id"),
        "{glob}"
    );
}

/// Reject an unknown rule id and any known rule outside the sensitive-data pillar.
#[test]
pub(crate) fn sensitive_exclusion_rejects_unknown_and_non_sensitive_rules() {
    let dir = tempdir().expect("tempdir");

    let unknown = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.not-a-real-rule
    path: src/aws_config.rs
    reason: Synthetic fixture.
"#,
    );
    assert!(
        unknown.contains(
            "unknown rule id `sensitive-data.not-a-real-rule` in config key `sensitiveExclusions[0].rule`"
        ),
        "{unknown}"
    );

    let non_sensitive = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: security.process-command
    path: src/aws_config.rs
    reason: Synthetic fixture.
"#,
    );
    assert!(
        non_sensitive
            .contains("config key `sensitiveExclusions[0].rule` must name a sensitive-data rule"),
        "{non_sensitive}"
    );
}

/// Reject a missing, absolute, escaping, or glob path.
#[test]
pub(crate) fn sensitive_exclusion_rejects_unsafe_paths() {
    let dir = tempdir().expect("tempdir");

    let missing = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    reason: Synthetic fixture.
"#,
    );
    assert!(
        missing.contains("missing required config key `sensitiveExclusions[0].path`"),
        "{missing}"
    );

    let empty = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: ""
    reason: Synthetic fixture.
"#,
    );
    assert!(
        empty.contains("config key `sensitiveExclusions[0].path` must be a non-empty string"),
        "{empty}"
    );

    for absolute in ["/etc/secrets/aws.conf", "C:\\secrets\\aws.conf"] {
        let error = corpus_config_error(
            dir.path(),
            &format!(
                r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: '{absolute}'
    reason: Synthetic fixture.
"#
            ),
        );
        assert!(
            error.contains(
                "config key `sensitiveExclusions[0].path` must be a project-relative path"
            ),
            "{error}"
        );
    }

    let escape = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: ../secrets/aws.conf
    reason: Synthetic fixture.
"#,
    );
    assert!(
        escape.contains("must not contain a `..` path component"),
        "{escape}"
    );

    let glob = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: "src/*.rs"
    reason: Synthetic fixture.
"#,
    );
    assert!(glob.contains("must name one exact file"), "{glob}");
}

/// Reject every message- or value-matching key, so no suppression can name a matched secret.
#[test]
pub(crate) fn sensitive_exclusion_rejects_message_and_value_keys() {
    let dir = tempdir().expect("tempdir");

    for key in ["message_contains", "messageContains", "value", "preview"] {
        let error = corpus_config_error(
            dir.path(),
            &format!(
                r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
    {key}: synthetic
    reason: Synthetic fixture.
"#
            ),
        );
        assert!(
            error.contains(&format!(
                "unknown key `{key}` in config key `sensitiveExclusions[0]`"
            )),
            "{error}"
        );
    }
}

/// Reject a second entry claiming a scope an earlier entry already owns.
#[test]
pub(crate) fn sensitive_exclusion_rejects_duplicate_scope() {
    let dir = tempdir().expect("tempdir");

    let error = corpus_config_error(
        dir.path(),
        r#"
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
    reason: First rationale.
  - rule: sensitive-data.aws-access-key
    path: src/aws_config.rs
    reason: Second rationale.
"#,
    );
    assert!(
        error
            .contains("duplicate sensitive exclusion scope in config key `sensitiveExclusions[1]`"),
        "{error}"
    );
}
