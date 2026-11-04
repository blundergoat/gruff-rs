use super::*;
use std::path::Component;

/// Resolve `project_root` and load the project's `Config` once at the CLI
/// edge. Shared by `analyse`, `report`, and `summary` so each command
/// passes a pre-loaded Config into `run_analysis_in_project` per ADR-013.
///
/// `options` holds the parsed command options, whose scan paths and three baseline paths are rebased onto the project root.
/// `deep_scan_budget` is an optional deep-scan budget override applied to the loaded config.
///
/// Returns the canonical project root, the rebased options and the loaded config.
/// Returns Err with a message when a directory cannot be resolved, the targets share no common root, or the config does not load.
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
    // A baseline path means what the user typed from the launch directory, as the targets do.
    options.baseline = rebase_typed_path(&caller_root, &project_root, options.baseline);
    options.generate_baseline =
        rebase_typed_path(&caller_root, &project_root, options.generate_baseline);
    options.migrate_baseline =
        rebase_typed_path(&caller_root, &project_root, options.migrate_baseline);
    let mut config = load_config(&project_root, &options)?;
    config.apply_deep_scan_budget_override(deep_scan_budget);
    Ok((project_root, options, config))
}

/// Turn the scan paths the user typed into absolute targets, scanning the launch directory when none were given.
///
/// `caller_root` is the canonical launch directory that relative paths are joined to, and `paths` are the scan paths as typed.
/// Returns one absolute path per entry in `paths`, canonicalized when possible, or `caller_root` alone when `paths` is empty.
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

/// Find the project root as the nearest directory at or above the targets' common directory that holds `Cargo.toml` or `.gruff-rs.yaml`.
///
/// `targets` are the absolute scan targets.
///
/// Returns that directory canonicalized, or the canonical common directory when no ancestor holds either file.
/// Returns Err when `targets` is empty or has no common directory, or when canonicalizing fails.
/// Several targets that meet only at a filesystem root holding neither marker file are also an Err.
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

/// Find the deepest directory that contains every scan target, taking a file target's parent as its directory.
///
/// `targets` are the absolute scan targets.
/// Returns that directory, or Err when `targets` is empty or the targets share no common ancestor.
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

/// Name the directory a scan target stands for: the target itself when it is a directory, otherwise its parent.
///
/// `target` is an absolute scan target, checked on disk, so a path that does not exist is treated as a file.
/// Returns `target` when it is an existing directory, otherwise its parent, or `target` itself when it has no parent.
fn target_directory(target: &Path) -> PathBuf {
    if target.is_dir() {
        return target.to_path_buf();
    }
    target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| target.to_path_buf())
}

/// Rewrite a path the user typed, such as `--baseline`, so that joined to the project root it names the file they meant
/// from the launch directory. It stays relative, with `..` for a file outside the project, so no report names a host path.
///
/// `caller_root` is the canonical launch directory and `project_root` the canonical root the rewritten path will be joined to.
/// `path` is the path as typed; an absolute path, or any path when the two roots are equal, is passed on unchanged.
///
/// Returns None when `path` is None, otherwise the path to join to `project_root`.
fn rebase_typed_path(
    caller_root: &Path,
    project_root: &Path,
    path: Option<PathBuf>,
) -> Option<PathBuf> {
    let path = path?;
    // Inside the launch directory the root and the typed path already agree, so the path is passed on as typed.
    if path.is_absolute() || caller_root == project_root {
        return Some(path);
    }
    let target = lexically_normal(&absolutize(caller_root, &path));
    let root_parts: Vec<Component<'_>> = project_root.components().collect();
    let target_parts: Vec<Component<'_>> = target.components().collect();
    let shared = root_parts
        .iter()
        .zip(&target_parts)
        .take_while(|(root_part, target_part)| root_part == target_part)
        .count();
    let mut relative = PathBuf::new();
    for _ in shared..root_parts.len() {
        relative.push("..");
    }
    for part in &target_parts[shared..] {
        relative.push(part.as_os_str());
    }
    Some(relative)
}

/// Resolve `.` and `..` without touching the filesystem, because a baseline about to be generated does not exist yet.
///
/// `path` is the absolute path built from the launch directory and the typed path.
/// Returns `path` with every `.` removed and every `..` cancelling the component before it; a `..` with nothing left to cancel is dropped.
fn lexically_normal(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                normal.pop();
            }
            Component::CurDir => {}
            other => normal.push(other.as_os_str()),
        }
    }
    normal
}

/// Express an absolute scan target relative to the project root.
///
/// `project_root` is the canonical project root and `target` is an absolute scan target.
/// Returns the part of `target` below `project_root`, `.` when it is the root itself, or `target` unchanged when it lies outside the root.
fn rebase_scan_target(project_root: &Path, target: &Path) -> PathBuf {
    match target.strip_prefix(project_root) {
        Ok(relative) if relative.as_os_str().is_empty() => PathBuf::from("."),
        Ok(relative) => relative.to_path_buf(),
        Err(_) => target.to_path_buf(),
    }
}

/// Resolve the effective `fail_on` for a command via the three-tier
/// precedence rule from ADR-013: CLI flag > config key > binary default.
///
/// `cli_value` is the threshold given on the command line, if any, and `binary_default` is the fallback when neither tier sets one.
/// `config` supplies the per-command `minimum_severity` map and `command` is the command name looked up in it.
///
/// Returns the command-line value when given, else the config value for `command`, else `binary_default`.
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
///
/// `base` is the parsed command options, rebased as `resolve_project_root_and_config` does, and `deep_scan_budget` is passed through to it.
/// `cli_fail_on`, `command` and `binary_default` feed `resolve_fail_on` as the flag value, the config lookup key and the fallback.
///
/// Returns the project root, the options with the resolved `fail_on`, and the config, or the Err from `resolve_project_root_and_config`.
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
///
/// `writer` emits the report when `output` is None, and `outcome` decides whether quiet mode suppresses it.
/// Otherwise `output` names the file written instead, replacing any file there, and `rendered` is the finished report text.
///
/// Returns Err with a message naming the path when the file cannot be written, and Ok otherwise.
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
