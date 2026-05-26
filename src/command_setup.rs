use super::*;

/// Resolve `project_root` and load the project's `Config` once at the CLI
/// edge. Shared by `analyse`, `report`, and `summary` so each command
/// passes a pre-loaded Config into `run_analysis_in_project` per ADR-013.
pub(crate) fn resolve_project_root_and_config(
    options: &AnalysisOptions,
) -> Result<(PathBuf, Config), String> {
    let project_root = std::env::current_dir()
        .map_err(|error| format!("unable to resolve current directory: {error}"))?;
    let config = load_config(&project_root, options)?;
    Ok((project_root, config))
}

/// Resolve the effective `fail_on` for a command via the three-tier
/// precedence rule from ADR-013: CLI flag > config key > binary default.
pub(crate) fn resolve_fail_on(
    cli_value: Option<FailThreshold>,
    config: &Config,
    command: &str,
    binary_default: FailThreshold,
) -> FailThreshold {
    cli_value
        .or_else(|| config.minimum_severity.get(command).copied())
        .unwrap_or(binary_default)
}

/// Composite helper for `analyse` and `report`: load the project root and
/// Config, resolve fail_on via the three-tier precedence, and rebuild the
/// AnalysisOptions with the resolved value. Lets the command functions
/// stay below the architecture.large-module item budget and below the
/// per-function metric thresholds.
pub(crate) fn resolve_command_setup(
    base: AnalysisOptions,
    cli_fail_on: Option<FailThreshold>,
    command: &str,
    binary_default: FailThreshold,
) -> Result<(PathBuf, AnalysisOptions, Config), String> {
    let (project_root, config) = resolve_project_root_and_config(&base)?;
    let options = AnalysisOptions {
        fail_on: resolve_fail_on(cli_fail_on, &config, command, binary_default),
        ..base
    };
    Ok((project_root, options, config))
}

/// Write the rendered report to a file when an `--output` path was
/// supplied, otherwise emit it through the standard writer. Shared so
/// `report` and any future command that has a file-or-stdout choice stay
/// below the architecture.large-module item budget in `main.rs`.
pub(crate) fn emit_report_output(
    writer: OutputWriter,
    output: Option<PathBuf>,
    outcome: RunOutcome,
    rendered: &str,
) -> Result<(), String> {
    if let Some(path) = output {
        fs::write(&path, rendered)
            .map_err(|error| format!("unable to write {}: {error}", path.display()))?;
    } else {
        writer.emit(outcome, rendered);
    }
    Ok(())
}
