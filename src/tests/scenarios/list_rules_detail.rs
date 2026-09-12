use super::*;
use crate::rules_detail::render_rule_detail;
use crate::{rules, RuleListFormat};
use serde_json::{json, Value};

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
pub(crate) fn flat_catalogue_exports_only_nonempty_false_positive_guidance() {
    let body = render_rule_list(
        Path::new("."),
        &ListRulesArgs {
            rule_id: None,
            format: RuleListFormat::Json,
            selector: None,
            config: None,
            no_config: true,
        },
    )
    .expect("flat rule catalogue renders json");
    let listing: Value = serde_json::from_str(&body).expect("catalogue JSON parses");
    let values = listing["rules"]
        .as_array()
        .expect("the catalogue is an object carrying its rules under `rules`");

    let unused_private = values
        .iter()
        .find(|value| value["id"] == "dead-code.unused-private-function")
        .expect("reviewed heuristic ships");
    assert_eq!(
        unused_private["falsePositiveShapes"]
            .as_array()
            .expect("guidance is an array")
            .len(),
        1
    );

    let cyclomatic = values
        .iter()
        .find(|value| value["id"] == "complexity.cyclomatic")
        .expect("unshaped high-confidence rule ships");
    assert!(cyclomatic.get("falsePositiveShapes").is_none());

    let heuristic_rules: Vec<&Value> = values
        .iter()
        .filter(|value| matches!(value["confidence"].as_str(), Some("medium" | "low")))
        .collect();
    assert_eq!(heuristic_rules.len(), 30);
    assert!(heuristic_rules
        .iter()
        .all(|value| value["falsePositiveShapes"]
            .as_array()
            .is_some_and(|shapes| !shapes.is_empty())));
}

#[test]
pub(crate) fn flat_catalogue_publishes_thresholds_as_named_knob_maps() {
    let body = render_rule_list(
        Path::new("."),
        &ListRulesArgs {
            rule_id: None,
            format: RuleListFormat::Json,
            selector: None,
            config: None,
            no_config: true,
        },
    )
    .expect("flat rule catalogue renders json");
    let listing: Value = serde_json::from_str(&body).expect("catalogue JSON parses");
    let rules = listing["rules"].as_array().expect("rules array");
    let by_id = |id: &str| {
        rules
            .iter()
            .find(|rule| rule["id"] == id)
            .unwrap_or_else(|| panic!("{id} ships"))
    };

    // A rule whose id has a gruff-go knob name borrows it.
    assert_eq!(
        by_id("complexity.cognitive")["thresholds"],
        json!({"maxComplexity": 15})
    );
    assert_eq!(
        by_id("size.file-length")["thresholds"],
        json!({"maxLines": 1000})
    );
    // A rule with no knob name anywhere in the family publishes the one-key map.
    assert_eq!(
        by_id("architecture.large-module")["thresholds"],
        json!({"threshold": 25})
    );
    // A rule with no threshold omits the key, and no rule publishes the retired scalar.
    assert!(by_id("security.unsafe-block").get("thresholds").is_none());
    assert!(rules.iter().all(|rule| rule.get("threshold").is_none()));
    // An integral default prints as an integer, never as `15.0`.
    assert!(body.contains("\"maxComplexity\": 15\n"));
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

/*
 * Pins the argument-order clause FAMILY-CONTRACT.md section 7 ratifies on 2026-09-06.
 *
 * Every operand-accepting command must parse to the same request whether its flags are written before or after the
 * path. The defect the clause exists to prevent is real and was shipped: gruff-go silently discarded flags placed
 * after a path, so `analyse . --fail-on=error` ran at the default threshold and a CI gate nobody had disabled
 * stopped gating.
 *
 * Reach for this test when adding a command that takes paths, or when changing how clap is wired.
 */

/// Every operand-accepting command, as the flags whose placement is under test plus the operand they surround.
const ORDER_CASES: &[(&str, &[&str], &str)] = &[
    (
        "analyse",
        &["--no-config", "--fail-on", "none", "--format", "json"],
        "src/lib.rs",
    ),
    (
        "summary",
        &["--no-config", "--format", "json"],
        "src/lib.rs",
    ),
    ("report", &["--no-config", "--format", "json"], "src/lib.rs"),
    ("hook", &["--no-config", "--format", "json"], "src/lib.rs"),
    (
        "check-ignore",
        &["--no-config", "--format", "json"],
        "src/lib.rs",
    ),
];

#[test]
pub(crate) fn every_operand_command_accepts_flags_after_the_path() {
    for (command, flags, operand) in ORDER_CASES {
        let mut before = vec!["gruff-rs", command];
        before.extend_from_slice(flags);
        before.push(operand);

        let mut after = vec!["gruff-rs", command, operand];
        after.extend_from_slice(flags);

        let parsed_before = Cli::try_parse_from(before)
            .ok()
            .map(|cli| format!("{:?}", cli.command));
        let parsed_after = Cli::try_parse_from(after)
            .ok()
            .map(|cli| format!("{:?}", cli.command));

        assert!(
            parsed_before.is_some(),
            "{command} did not parse with its flags before the path"
        );
        assert!(
            parsed_after.is_some(),
            "{command} did not parse with its flags after the path"
        );

        // The parsed request is what the run is built from, so equal requests mean equal output and equal exits.
        assert_eq!(
            parsed_before, parsed_after,
            "{command} parses differently when its flags follow the path"
        );
    }
}

#[test]
pub(crate) fn a_double_dash_ends_flag_parsing() {
    let parsed = Cli::try_parse_from([
        "gruff-rs",
        "analyse",
        "--no-config",
        "--fail-on",
        "none",
        "--",
        "-weird.rs",
    ])
    .expect("terminator parse");

    // Without the terminator `-weird.rs` would read as an unknown flag, and the file would be unreachable.
    assert!(
        format!("{:?}", parsed.command).contains("-weird.rs"),
        "the terminated operand was not kept as a path"
    );
}

#[test]
pub(crate) fn a_flag_shaped_token_is_never_an_operand() {
    let refused = Cli::try_parse_from(["gruff-rs", "analyse", ".", "--not-a-registered-flag"]);

    // A flag-shaped token that is not registered is an error wherever it appears, never a path.
    assert!(
        refused.is_err(),
        "an unregistered flag after the path was accepted as an operand"
    );
}
