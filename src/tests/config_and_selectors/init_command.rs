use super::*;

use crate::init::render_default_config;

#[test]
pub(crate) fn default_config_round_trips_through_load_config() {
    let registry = rules::builtin_registry();
    let body = render_default_config(&registry);

    let dir = tempdir().expect("tempdir");
    write_config(dir.path(), &body);

    let config = load_config(dir.path(), &default_test_options())
        .expect("generated default config parses cleanly");

    assert!(
        !config.ignored_paths.is_empty(),
        "default paths.ignore should not be empty"
    );
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
    let body = render_default_config(&registry);
    for definition in registry.definitions() {
        let needle = format!("  {}:", definition.id);
        assert!(
            body.contains(&needle),
            "default config missing entry for `{}`",
            definition.id,
        );
    }
}
