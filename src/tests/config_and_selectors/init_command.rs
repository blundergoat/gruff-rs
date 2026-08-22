//! Generated-config and regeneration behavior visible to `gruff-rs init` users.
//!
//! Tests keep registry defaults, family seeds, preserved settings, and safe
//! empty legacy keys consistent through render-and-load round trips.

use super::*;

use crate::config::DEFAULT_ABBREVIATIONS;
use crate::init::{
    read_existing_ignore_patterns, read_existing_minimum_severity, render_default_config,
};
use std::collections::BTreeMap;

#[test]
pub(crate) fn default_config_round_trips_through_load_config() {
    let registry = rules::builtin_registry();
    let body = render_default_config(&registry, &[], &BTreeMap::new());

    let dir = tempdir().expect("tempdir");
    write_config(dir.path(), &body);

    let config = load_config(dir.path(), &default_test_options())
        .expect("generated default config parses cleanly");

    assert!(
        !config.ignored_paths.is_empty(),
        "default paths.ignore should not be empty"
    );
    for prefix in [".agents/", ".claude/", ".codex/", ".github/", ".goat-flow/"] {
        assert!(
            body.contains(prefix),
            "default config missing agent/CI ignore prefix `{prefix}`",
        );
    }
    for definition in registry.definitions() {
        assert!(
            config.rule_settings.contains_key(definition.id),
            "missing rule entry for `{}`",
            definition.id,
        );
    }
}

/// Keep the retired preview key visible only with its one accepted empty value.
#[test]
pub(crate) fn default_config_keeps_legacy_secret_previews_empty() {
    let body = render_default_config(&rules::builtin_registry(), &[], &BTreeMap::new());

    assert!(
        body.contains("  secretPreviews: []\n"),
        "generated config must keep the legacy key inert: {body}"
    );
}

#[test]
pub(crate) fn generated_config_reproduces_builtin_rule_defaults() {
    // Round-trip generated config because users should receive the same findings before and after running `init`.
    let registry = rules::builtin_registry();
    let body = render_default_config(&registry, &[], &BTreeMap::new());

    let dir = tempdir().expect("tempdir");
    write_config(dir.path(), &body);
    let config = load_config(dir.path(), &default_test_options())
        .expect("generated default config parses cleanly");

    for definition in registry.definitions() {
        let Some(threshold) = definition.threshold else {
            continue;
        };
        assert_eq!(
            config.threshold(definition.id),
            threshold.default,
            "generated config threshold drifts from the catalogue for `{}`",
            definition.id,
        );
        assert_eq!(
            config.severity(definition.id, definition.default_severity),
            definition.default_severity,
            "generated config severity drifts from the catalogue for `{}`",
            definition.id,
        );
    }
}

#[test]
pub(crate) fn accepted_abbreviations_match_family_contract() {
    // FAMILY-CONTRACT §8 owns this universal cross-port seed.
    const FAMILY_ABBREVIATIONS: &[&str] = &[
        "age", "app", "db", "fs", "id", "io", "key", "log", "max", "min", "now", "raw", "rx", "tx",
        "ui", "url",
    ];

    assert_eq!(DEFAULT_ABBREVIATIONS, FAMILY_ABBREVIATIONS);

    let body = render_default_config(&rules::builtin_registry(), &[], &BTreeMap::new());
    let dir = tempdir().expect("tempdir");
    write_config(dir.path(), &body);
    let config = load_config(dir.path(), &default_test_options()).expect("generated config loads");
    let loaded: Vec<&str> = config
        .accepted_abbreviations
        .iter()
        .map(String::as_str)
        .collect();

    assert_eq!(loaded, FAMILY_ABBREVIATIONS);
    let expected_comment = concat!(
        "  # acceptedAbbreviations controls which short names naming.short-variable permits.\n",
        "  # This configured list replaces (not merges) built-ins; keep these seeds and\n",
        "  # append project vocabulary below.\n",
        "  acceptedAbbreviations:\n",
    );
    assert!(body.contains(expected_comment), "generated config:\n{body}");
}

#[test]
pub(crate) fn default_config_emits_every_built_in_rule() {
    let registry = rules::builtin_registry();
    let body = render_default_config(&registry, &[], &BTreeMap::new());
    for definition in registry.definitions() {
        let needle = format!("  {}:", definition.id);
        assert!(
            body.contains(&needle),
            "default config missing entry for `{}`",
            definition.id,
        );
    }
}

#[test]
/// Generated config keeps style-preference rules visible without enabling them.
pub(crate) fn generated_config_disables_opt_in_rules() {
    let generated_config = render_default_config(&rules::builtin_registry(), &[], &BTreeMap::new());

    for (rule_id, next_rule_prefix) in [
        ("test-quality.unwrap-in-test", "\n  test-quality."),
        ("waste.unnecessary-clone-candidate", "\n  waste."),
    ] {
        let rule_entry = generated_config
            .split(&format!("  {rule_id}:"))
            .nth(1)
            .and_then(|remaining_config| remaining_config.split(next_rule_prefix).next())
            .expect("opt-in rule entry exists");
        assert!(
            rule_entry.contains("    enabled: false"),
            "{rule_id} should be opt-in in generated defaults; entry={rule_entry}"
        );
    }
}

#[test]
pub(crate) fn default_config_explains_ignores_and_baseline_starting_point() {
    let body = render_default_config(&rules::builtin_registry(), &[], &BTreeMap::new());

    assert!(body.contains("Discovery-time do-not-read patterns"));
    assert!(body.contains("gruff-rs analyse --generate-baseline"));
    assert!(body.contains("top-level `exclude` entries"));
}

#[test]
/// Ship the sensitive-suppression section commented out and describe how entries are authored.
pub(crate) fn default_config_documents_manually_authored_sensitive_exclusions() {
    let body = render_default_config(&rules::builtin_registry(), &[], &BTreeMap::new());

    assert!(body.contains("# sensitiveExclusions:"));
    assert!(body.contains("#   - rule: sensitive-data.aws-access-key"));
    assert!(body.contains("Write entries by hand"));
    assert!(body.contains("no message- or value-matching key is accepted here"));
    // A commented example must never arrive as an active suppression in a fresh project.
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join(".gruff-rs.yaml"), &body).expect("generated config write");
    let config = load_config(dir.path(), &default_test_options()).expect("generated config loads");
    assert!(config.sensitive_exclusions.is_empty());
}

#[test]
pub(crate) fn init_preserves_existing_ignore_entries_on_regenerate() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join(".gruff-rs.yaml");
    let existing = r#"paths:
  ignore:
    - .agents/**
    - custom-vendor/**
    - target/**
rules: {}
"#;
    fs::write(&config_path, existing).expect("write existing config");

    let preserved = read_existing_ignore_patterns(&config_path);
    assert_eq!(
        preserved,
        vec![
            ".agents/**".to_string(),
            "custom-vendor/**".to_string(),
            "target/**".to_string(),
        ],
        "ignore-preservation must surface every existing entry verbatim",
    );

    let body = render_default_config(&rules::builtin_registry(), &preserved, &BTreeMap::new());
    assert!(
        body.contains("    - custom-vendor/**"),
        "user-customized ignore entry was wiped on regenerate",
    );
    let target_occurrences = body.matches("    - target/**\n").count();
    assert_eq!(
        target_occurrences, 1,
        "default + existing overlap should dedupe to a single entry, got {target_occurrences}",
    );
}

#[test]
pub(crate) fn init_preserves_existing_minimum_severity_on_regenerate() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join(".gruff-rs.yaml");
    let existing = r#"schemaVersion: gruff-rs.config.v1
minimumSeverity:
  analyse: error
  report: warning
paths:
  ignore:
    - target/**
"#;
    fs::write(&config_path, existing).expect("write existing config");

    let preserved = read_existing_minimum_severity(&config_path);
    assert_eq!(
        preserved.get("analyse"),
        Some(&FailThreshold::Error),
        "analyse override must survive read",
    );
    assert_eq!(
        preserved.get("report"),
        Some(&FailThreshold::Warning),
        "report override must survive read",
    );

    let body = render_default_config(&rules::builtin_registry(), &[], &preserved);
    assert!(
        body.contains("\n  analyse: error\n"),
        "user-customized analyse threshold was wiped on regenerate:\n{body}",
    );
    assert!(
        body.contains("\n  report: warning\n"),
        "user-customized report threshold was wiped on regenerate:\n{body}",
    );
    assert!(
        !body.contains("# analyse: advisory"),
        "preserved analyse value must replace the commented placeholder",
    );
}

#[test]
pub(crate) fn read_existing_minimum_severity_returns_empty_for_missing_or_malformed() {
    let dir = tempdir().expect("tempdir");
    let missing = dir.path().join("nope.yaml");
    assert!(read_existing_minimum_severity(&missing).is_empty());

    let no_block = dir.path().join("no_block.yaml");
    fs::write(&no_block, "schemaVersion: gruff-rs.config.v1\npaths: {}\n").expect("write no_block");
    assert!(read_existing_minimum_severity(&no_block).is_empty());

    let bogus_value = dir.path().join("bogus_value.yaml");
    fs::write(
        &bogus_value,
        "minimumSeverity:\n  analyse: never\n  report: advisory\n",
    )
    .expect("write bogus_value");
    let preserved = read_existing_minimum_severity(&bogus_value);
    assert_eq!(
        preserved.get("analyse"),
        None,
        "invalid threshold value must be silently skipped"
    );
    assert_eq!(
        preserved.get("report"),
        Some(&FailThreshold::Advisory),
        "valid sibling entries are still preserved"
    );
}

#[test]
pub(crate) fn read_existing_ignore_patterns_returns_empty_for_missing_or_malformed() {
    let dir = tempdir().expect("tempdir");
    let missing = dir.path().join("nope.yaml");
    assert!(read_existing_ignore_patterns(&missing).is_empty());

    let malformed = dir.path().join("malformed.yaml");
    fs::write(&malformed, "paths: [unterminated").expect("write malformed");
    assert!(
        read_existing_ignore_patterns(&malformed).is_empty(),
        "malformed YAML must degrade to empty so --force can still repair the file",
    );

    let no_ignore = dir.path().join("no_ignore.yaml");
    fs::write(&no_ignore, "paths: {}\nrules: {}\n").expect("write no_ignore");
    assert!(read_existing_ignore_patterns(&no_ignore).is_empty());
}
