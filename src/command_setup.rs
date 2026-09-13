use super::*;

/// Resolve `project_root` and load the project's `Config` once at the CLI
/// edge. Shared by `analyse`, `report`, and `summary` so each command
/// passes a pre-loaded Config into `run_analysis_in_project` per ADR-013.
pub(crate) fn resolve_project_root_and_config(
    mut options: AnalysisOptions,
    deep_scan_budget: Option<&DeepScanBudgetOverride>,
) -> Result<(PathBuf, AnalysisOptions, Config), String> {
    let caller_root = std::env::current_dir()
        .map_err(|error| format!("unable to resolve current directory: {error}"))?;
    let caller_root = caller_root.canonicalize().map_err(|error| {
        format!(
            "unable to canonicalize current directory {}: {error}",
            caller_root.display()
        )
    })?;
    let targets = resolved_scan_targets(&caller_root, &options.paths);
    let project_root = project_root_from_targets(&targets)?;
    if !options.paths.is_empty() {
        options.paths = targets
            .iter()
            .map(|target| rebase_scan_target(&project_root, target))
            .collect();
    }
    let mut config = load_config(&project_root, &options)?;
    config.apply_deep_scan_budget_override(deep_scan_budget);
    Ok((project_root, options, config))
}

fn resolved_scan_targets(caller_root: &Path, paths: &[PathBuf]) -> Vec<PathBuf> {
    if paths.is_empty() {
        return vec![caller_root.to_path_buf()];
    }
    paths
        .iter()
        .map(|path| {
            let absolute = absolutize(caller_root, path);
            absolute.canonicalize().unwrap_or(absolute)
        })
        .collect()
}

fn project_root_from_targets(targets: &[PathBuf]) -> Result<PathBuf, String> {
    let common = common_target_directory(targets)?;
    for ancestor in common.ancestors() {
        if ancestor.join("Cargo.toml").is_file() || ancestor.join(".gruff-rs.yaml").is_file() {
            return ancestor.canonicalize().map_err(|error| {
                format!(
                    "unable to canonicalize project root {}: {error}",
                    ancestor.display()
                )
            });
        }
    }
    if common.parent().is_none() && targets.len() > 1 {
        return Err("scan targets must share a project ancestor".to_string());
    }
    common.canonicalize().map_err(|error| {
        format!(
            "unable to canonicalize scan root {}: {error}",
            common.display()
        )
    })
}

fn common_target_directory(targets: &[PathBuf]) -> Result<PathBuf, String> {
    let mut directories = targets.iter().map(|target| target_directory(target));
    let mut common = directories
        .next()
        .ok_or_else(|| "unable to resolve a scan target".to_string())?;
    for directory in directories {
        while !directory.starts_with(&common) {
            if !common.pop() {
                return Err("scan targets do not share a filesystem root".to_string());
            }
        }
    }
    Ok(common)
}

fn target_directory(target: &Path) -> PathBuf {
    if target.is_dir() {
        return target.to_path_buf();
    }
    target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| target.to_path_buf())
}

fn rebase_scan_target(project_root: &Path, target: &Path) -> PathBuf {
    match target.strip_prefix(project_root) {
        Ok(relative) if relative.as_os_str().is_empty() => PathBuf::from("."),
        Ok(relative) => relative.to_path_buf(),
        Err(_) => target.to_path_buf(),
    }
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
    deep_scan_budget: Option<&DeepScanBudgetOverride>,
) -> Result<(PathBuf, AnalysisOptions, Config), String> {
    let (project_root, base, config) = resolve_project_root_and_config(base, deep_scan_budget)?;
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
