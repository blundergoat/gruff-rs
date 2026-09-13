//! Rule-catalogue integrity contracts for configuration and rule-detail users.
//! These tests keep stable IDs ordered, reserve the custom namespace, and
//! require every related-rule link to resolve inside the shipped catalogue.

use super::*;

/// Build one compact rule definition for registry-construction failure tests.
const fn registry_test_definition(
    id: &'static str,
    related_rules: &'static [&'static str],
) -> rules::RuleDefinition {
    rules::RuleDefinition {
        id,
        name: "Registry contract probe",
        pillar: Pillar::Documentation,
        tier: "v0.1",
        kind: rules::RuleKind::Text,
        default_severity: Severity::Advisory,
        confidence: Confidence::High,
        threshold: None,
        options: &[],
        default_enabled: true,
        description: "Exercises rule registry validation.",
        false_positive_shapes: &[],
        related_rules,
    }
}

/// Keep built-in rule IDs unique and deterministically ordered for every consumer.
#[test]
pub(crate) fn registry_rejects_duplicate_rule_ids_and_sorts_definitions() {
    let registry = rules::builtin_registry();

    // Rule-list and config consumers must see one stable ascending catalogue.
    assert!(registry
        .definitions()
        .windows(2)
        .all(|window| window[0].id < window[1].id));
    assert!(registry.contains("security.process-command"));

    let duplicate = registry.definitions()[0];
    assert!(rules::RuleRegistry::new(vec![duplicate, duplicate]).is_err());
}

/// Keep every heuristic rule's reviewed exception guidance in the native catalogue.
#[test]
pub(crate) fn medium_and_low_confidence_rules_publish_false_positive_guidance() {
    let registry = rules::builtin_registry();
    let heuristic_rules: Vec<&rules::RuleDefinition> = registry
        .definitions()
        .iter()
        .filter(|definition| matches!(definition.confidence, Confidence::Medium | Confidence::Low))
        .collect();

    assert_eq!(heuristic_rules.len(), 30);
    for definition in heuristic_rules {
        assert!(
            !definition.false_positive_shapes.is_empty(),
            "{} lacks reviewed false-positive guidance",
            definition.id
        );
        assert!(definition.false_positive_shapes.iter().all(|shape| {
            !shape.shape.trim().is_empty() && !shape.mitigation.trim().is_empty()
        }));
    }
}

/// Pin the ratified `size.file-length` bar. The catalogue is the only place this
/// value lives, so an accidental edit here silently moves every scan's gate.
#[test]
pub(crate) fn file_length_keeps_ratified_substantive_line_bar() {
    let registry = rules::builtin_registry();
    let definition = registry
        .get("size.file-length")
        .expect("size.file-length ships in the catalogue");

    assert_eq!(
        definition
            .threshold
            .expect("size.file-length declares a threshold")
            .default,
        1000.0
    );
    assert_eq!(definition.default_severity, Severity::Error);
}

/// Keep the built-in catalogue out of the namespace reserved for user config.
#[test]
pub(crate) fn registry_reserves_custom_namespace() {
    let registry = rules::builtin_registry();

    // Config authors need every `custom.*` ID to remain available for their rules.
    assert!(registry
        .definitions()
        .iter()
        .all(|definition| !definition.id.starts_with("custom.")));

    let definition = registry_test_definition("custom.builtin", &[]);
    let error = rules::RuleRegistry::new(vec![definition])
        .expect_err("custom namespace reserved for config rules");
    assert!(
        error.contains("built-in rule id `custom.builtin` uses reserved custom namespace"),
        "{error}"
    );
}

/// Reject a related-rule link that cannot resolve in the constructed catalogue.
#[test]
pub(crate) fn rule_catalogue_rejects_dangling_related_rules() {
    let source = registry_test_definition("probe.source", &["probe.missing"]);
    let error = rules::RuleRegistry::new(vec![source])
        .expect_err("dangling related rule must reject the catalogue");

    assert_eq!(
        error,
        "rule `probe.source` references unknown related rule `probe.missing`"
    );
}

/// Keep process-command metadata linked to the canonical API-key rule ID.
#[test]
pub(crate) fn rule_catalogue_process_command_related_rules_use_canonical_ids() {
    let registry = rules::builtin_registry();
    let process_command = registry
        .get("security.process-command")
        .expect("process-command remains in the shipped catalogue");

    assert_eq!(
        process_command.related_rules,
        &[
            "security.insecure-rng-for-secrets",
            "sensitive-data.api-key-pattern"
        ]
    );
}
