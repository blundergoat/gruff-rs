use super::*;

#[test]
pub(crate) fn analyse_resolution_falls_through_cli_then_config_then_default() {
    let mut config = Config::default();
    config
        .minimum_severity
        .insert("analyse".to_string(), FailThreshold::Error);

    // No CLI override -> config wins.
    assert_eq!(
        resolve_fail_on(None, &config, "analyse", FailThreshold::Advisory),
        FailThreshold::Error
    );
    // CLI override beats config.
    assert_eq!(
        resolve_fail_on(
            Some(FailThreshold::Warning),
            &config,
            "analyse",
            FailThreshold::Advisory
        ),
        FailThreshold::Warning
    );
    // No config entry, no CLI -> binary default.
    let empty = Config::default();
    assert_eq!(
        resolve_fail_on(None, &empty, "analyse", FailThreshold::Error),
        FailThreshold::Error
    );
}

#[test]
pub(crate) fn report_resolution_returns_none_default_when_unset() {
    let empty = Config::default();
    assert_eq!(
        resolve_fail_on(None, &empty, "report", FailThreshold::None),
        FailThreshold::None
    );

    let mut config = Config::default();
    config
        .minimum_severity
        .insert("report".to_string(), FailThreshold::Warning);
    assert_eq!(
        resolve_fail_on(None, &config, "report", FailThreshold::None),
        FailThreshold::Warning
    );
    assert_eq!(
        resolve_fail_on(
            Some(FailThreshold::Error),
            &config,
            "report",
            FailThreshold::None
        ),
        FailThreshold::Error
    );
}

#[test]
pub(crate) fn config_entry_for_one_command_does_not_leak_to_another() {
    let mut config = Config::default();
    config
        .minimum_severity
        .insert("analyse".to_string(), FailThreshold::Error);

    // analyse picks up its own override.
    assert_eq!(
        resolve_fail_on(None, &config, "analyse", FailThreshold::Advisory),
        FailThreshold::Error
    );
    // report does not see analyse's override.
    assert_eq!(
        resolve_fail_on(None, &config, "report", FailThreshold::None),
        FailThreshold::None
    );
}
