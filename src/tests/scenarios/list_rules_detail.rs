use super::*;
use crate::rules_detail::render_rule_detail;
use crate::{rules, RuleListFormat};
use serde_json::Value;

#[test]
pub(crate) fn detail_text_renders_all_sections_for_an_enriched_rule() {
    let registry = rules::builtin_registry();
    let detail = render_rule_detail(
        "naming.placeholder-identifier",
        &registry,
        &[],
        RuleListFormat::Text,
    )
    .expect("known rule renders");

    assert!(detail.contains("Rule: naming.placeholder-identifier"));
    assert!(detail.contains("Description:"));
    assert!(detail.contains("Default options:"));
    assert!(detail.contains("extraPlaceholders"));
    assert!(detail.contains("Escape hatches:"));
    assert!(detail.contains("rules.naming.placeholder-identifier.options.extraPlaceholders"));
    assert!(detail.contains("rules.naming.placeholder-identifier.enabled"));
    assert!(detail.contains("paths.ignore"));
    assert!(detail.contains("Common false-positive shapes:"));
    assert!(detail.contains("Related rules:"));
    assert!(detail.contains("- naming.generic-function"));
}

#[test]
pub(crate) fn detail_json_exposes_structured_payload() {
    let registry = rules::builtin_registry();
    let body = render_rule_detail(
        "naming.placeholder-identifier",
        &registry,
        &[],
        RuleListFormat::Json,
    )
    .expect("known rule renders json");
    let value: Value = serde_json::from_str(&body).expect("detail JSON parses");

    assert_eq!(
        value.get("id").and_then(|v| v.as_str()),
        Some("naming.placeholder-identifier")
    );
    assert!(value.get("description").is_some());
    assert!(value
        .get("escapeHatches")
        .and_then(|v| v.as_array())
        .is_some());
    assert!(value
        .get("falsePositiveShapes")
        .and_then(|v| v.as_array())
        .is_some());
    assert!(value
        .get("relatedRules")
        .and_then(|v| v.as_array())
        .is_some());
}

#[test]
pub(crate) fn detail_text_skips_optional_sections_for_unenriched_rules() {
    let registry = rules::builtin_registry();
    let detail = render_rule_detail(
        "complexity.cyclomatic",
        &registry,
        &[],
        RuleListFormat::Text,
    )
    .expect("known rule renders");

    assert!(detail.contains("Rule: complexity.cyclomatic"));
    assert!(detail.contains("Escape hatches:"));
    assert!(
        !detail.contains("Common false-positive shapes:"),
        "rule has no FP metadata; section must be skipped",
    );
    assert!(
        !detail.contains("Related rules:"),
        "rule has no related metadata; section must be skipped",
    );
}

#[test]
pub(crate) fn unknown_rule_id_errors_with_suggestions() {
    let registry = rules::builtin_registry();
    let error = render_rule_detail(
        "naming.placeholder-identifire",
        &registry,
        &[],
        RuleListFormat::Text,
    )
    .expect_err("typo must reject");
    assert!(error.contains("Unknown rule"));
    assert!(
        error.contains("naming.placeholder-identifier"),
        "Levenshtein suggestion should surface the corrected id: {error}",
    );
}

#[test]
pub(crate) fn unknown_rule_id_with_no_near_match_errors_without_suggestions() {
    let registry = rules::builtin_registry();
    let error = render_rule_detail(
        "totally-different-thing",
        &registry,
        &[],
        RuleListFormat::Text,
    )
    .expect_err("totally novel id must reject");
    assert!(error.contains("Unknown rule"));
    assert!(
        !error.contains("Did you mean"),
        "no near-matches means no suggestion clause: {error}",
    );
}

// PR #3 review: `list-rules custom.<slug>` used to return "Unknown rule"
// even when the catalogue mode listed the same id. Pin symmetry between
// the catalogue and detail views for `custom_rules`-defined ids.

#[test]
pub(crate) fn detail_resolves_custom_rule_ids_end_to_end() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    write_config(
        dir.path(),
        r#"
custom_rules:
  - id: custom.fake-secret
    pillar: Security
    severity: warning
    confidence: 0.6
    message: Fake secret pattern
    scope: text
    pattern: 'SECRET_TOKEN'
"#,
    );
    let options = AnalysisOptions {
        paths: vec![PathBuf::from(".")],
        no_baseline: true,
        ..default_test_options()
    };
    let config = load_config(dir.path(), &options).expect("config loads");
    let registry = rules::builtin_registry();

    let text = render_rule_detail(
        "custom.fake-secret",
        &registry,
        &config.custom_rules,
        RuleListFormat::Text,
    )
    .expect("custom rule detail renders as text");
    assert!(text.contains("Rule: custom.fake-secret"));
    assert!(text.contains("Kind:                custom"));
    assert!(text.contains("Pillar:              Security"));
    assert!(text.contains("Severity:            warning"));
    assert!(text.contains("Scope:               text"));
    assert!(text.contains("SECRET_TOKEN"));
    assert!(text.contains("custom_rules[id=custom.fake-secret]"));

    let json_body = render_rule_detail(
        "custom.fake-secret",
        &registry,
        &config.custom_rules,
        RuleListFormat::Json,
    )
    .expect("custom rule detail renders as json");
    let value: Value = serde_json::from_str(&json_body).expect("custom detail json parses");
    assert_eq!(value["id"], "custom.fake-secret");
    assert_eq!(value["kind"], "custom");
    assert_eq!(value["pillar"], "security");
    assert_eq!(value["severity"], "warning");
    assert_eq!(value["scope"], "text");
    assert_eq!(value["pattern"], "SECRET_TOKEN");
    let hatches = value["escapeHatches"]
        .as_array()
        .expect("escapeHatches array");
    assert!(hatches.iter().any(|v| v == "paths.ignore"));
}

#[test]
pub(crate) fn unknown_rule_suggestion_pool_includes_custom_ids() {
    use crate::config::{CustomRule, CustomRuleScope};
    use regex::Regex;
    let registry = rules::builtin_registry();
    let custom = CustomRule {
        id: "custom.beta-marker".to_string(),
        pillar: Pillar::Documentation,
        severity: Severity::Advisory,
        confidence: Confidence::Medium,
        message: "BETA marker".to_string(),
        scope: CustomRuleScope::Text,
        pattern: "BETA".to_string(),
        compiled_pattern: Regex::new("BETA").expect("regex"),
        include_path_matchers: Vec::new(),
        exclude_path_matchers: Vec::new(),
        remediation: None,
    };
    let error = render_rule_detail(
        "custom.beta-markar",
        &registry,
        std::slice::from_ref(&custom),
        RuleListFormat::Text,
    )
    .expect_err("typo on a custom id must reject");
    assert!(error.contains("Unknown rule"));
    assert!(
        error.contains("custom.beta-marker"),
        "suggestion pool must include configured custom ids: {error}",
    );
}
