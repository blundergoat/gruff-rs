use super::*;

use crate::init::{read_existing_ignore_patterns, render_default_config};

#[test]
pub(crate) fn default_config_round_trips_through_load_config() {
    let registry = rules::builtin_registry();
    let body = render_default_config(&registry, &[]);

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

#[test]
pub(crate) fn default_config_emits_every_built_in_rule() {
    let registry = rules::builtin_registry();
    let body = render_default_config(&registry, &[]);
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
pub(crate) fn default_config_explains_ignores_and_baseline_starting_point() {
    let body = render_default_config(&rules::builtin_registry(), &[]);

    assert!(body.contains("Discovery-time do-not-read patterns"));
    assert!(body.contains("gruff-rs analyse --generate-baseline"));
    assert!(body.contains("top-level `exclude` entries"));
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

    let body = render_default_config(&rules::builtin_registry(), &preserved);
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
