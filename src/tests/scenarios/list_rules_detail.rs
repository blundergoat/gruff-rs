use crate::rules_detail::render_rule_detail;
use crate::{rules, RuleListFormat};
use serde_json::Value;

#[test]
pub(crate) fn detail_text_renders_all_sections_for_an_enriched_rule() {
    let registry = rules::builtin_registry();
    let detail = render_rule_detail(
        "naming.placeholder-identifier",
        &registry,
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
    let detail = render_rule_detail("complexity.cyclomatic", &registry, RuleListFormat::Text)
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
    let error = render_rule_detail("totally-different-thing", &registry, RuleListFormat::Text)
        .expect_err("totally novel id must reject");
    assert!(error.contains("Unknown rule"));
    assert!(
        !error.contains("Did you mean"),
        "no near-matches means no suggestion clause: {error}",
    );
}
