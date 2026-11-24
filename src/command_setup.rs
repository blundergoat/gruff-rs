//! Prepare a scan before `analyse`, `report`, or `summary` opens source files.
//! Targets determine the project config. Explicit patch, history, and baseline paths still mean what they meant from the launch directory.
//!
//! Setup errors give the CLI enough context to report why the requested scan could not start.

use super::*;
use std::path::Component;

/// A failure that stopped setup or analysis before findings could be published.
/// The failing operation sets the diagnostic category that JSON, SARIF, and hook consumers read.
/// The message tells the caller which input or operation to check.
#[derive(Debug)]
pub(crate) enum RunFailure {
    Config(String),
    ChangedRegion(String),
    Baseline(String),
    ReportPath(String),
}

impl RunFailure {
    /// Returns the diagnostic category a machine report uses to identify the operation that failed.
    pub(crate) fn diagnostic_type(&self) -> &'static str {
        match self {
            Self::Config(_) => "config-error",
            Self::ChangedRegion(_) => "changed-region",
            Self::Baseline(_) => "baseline",
            Self::ReportPath(_) => "report-path",
        }
    }

    /// Returns the original message so the terminal and machine reports explain the same failure.
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Config(message)
            | Self::ChangedRegion(message)
            | Self::Baseline(message)
            | Self::ReportPath(message) => message,
        }
    }
}

impl std::fmt::Display for RunFailure {
    /// Write the original failure through `formatter`, returning any write error.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

/// Load the target project's config before `analyse`, `report`, or `summary` starts reading source files.
///
/// `options` holds the caller's scan flags and file paths. Explicit file paths keep their launch-directory meaning.
/// An absent `deep_scan_budget` keeps the project config's budget.
///
/// Returns the canonical project root, rebased options, and loaded config, or an error when the launch directory, target root, or config is unusable.
pub(crate) fn resolve_project_root_and_config(
    mut options: AnalysisOptions,
    deep_scan_budget: Option<&DeepScanBudgetOverride>,
) -> Result<(PathBuf, AnalysisOptions, Config), String> {
    // A launch directory deleted after the shell entered it prevents reliable relative path lookup.
    let caller_root = std::env::current_dir()
        .map_err(|error| format!("unable to resolve current directory: {error}"))?;
    let caller_root = caller_root.canonicalize().map_err(|error| {
        format!(
            "unable to canonicalize current directory {}: {error}",
            caller_root.display()
        )
    })?;
    let (project_root, targets) = resolve_scan_context(&caller_root, &options.paths)?;
    options.paths = targets;
    let rebase = |path| rebase_launch_path(&caller_root, &project_root, path);
    // A Git-backed diff has no patch-file path to resolve from the launch directory.
    if let Some(DiffSelection::Patch { path, .. }) = &mut options.diff {
        // `--diff-patch -` reads the caller's input stream even when the project is elsewhere.
        if path != Path::new("-") {
            *path = rebase(path.clone());
        }
    }
    options.history_file = options.history_file.map(rebase);
    options.baseline = options.baseline.map(rebase);
    options.generate_baseline = options.generate_baseline.map(rebase);
    options.migrate_baseline = options.migrate_baseline.map(rebase);
    let mut config = load_config(&project_root, &options)?;
    config.apply_deep_scan_budget_override(deep_scan_budget);
    Ok((project_root, options, config))
}

/// Resolve `paths` from `caller_root`, using the caller as the target when no paths are supplied.
/// Returns the common project root and the scan operands rebased to that root, or a message when no common root can be resolved.
pub(crate) fn resolve_scan_context(
    caller_root: &Path,
    paths: &[PathBuf],
) -> Result<(PathBuf, Vec<PathBuf>), String> {
    let targets = absolute_scan_targets(caller_root, paths);
    let project_root = project_root_from_targets(&targets)?;
    let paths = targets
        .iter()
        .map(|target| rebase_scan_target(&project_root, target))
        .collect();
    Ok((project_root, paths))
}

/// Turn the scan paths the user typed into absolute targets, scanning the launch directory when none were given.
///
/// `caller_root` is the canonical launch directory that relative paths are joined to, and `paths` are the scan paths as typed.
/// Returns one absolute path per entry in `paths`, canonicalized when possible, or `caller_root` alone when `paths` is empty.
fn absolute_scan_targets(caller_root: &Path, paths: &[PathBuf]) -> Vec<PathBuf> {
    // Running `analyse` inside `src` scans `src`, even if the config lives one directory above it.
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

/// Find the project root as the nearest directory at or above the targets' common directory that holds `Cargo.toml`, `.gruff-rs.yaml`, or `.git`.
///
/// `targets` are the absolute scan targets.
///
/// Returns that directory canonicalized, or the canonical common directory when no ancestor holds any of those markers.
/// Returns Err when `targets` is empty or has no common directory, or when canonicalizing fails.
/// Several targets that meet only at a filesystem root holding no marker are also an Err.
fn project_root_from_targets(targets: &[PathBuf]) -> Result<PathBuf, String> {
    let shared_directory = common_target_directory(targets)?;
    // The nearest project marker makes `analyse src/lib.rs` use the config intended for that source tree,
    // and `.git` (directory or worktree/submodule gitfile) stops lookup from escaping into an unrelated parent repo.
    for ancestor in shared_directory.ancestors() {
        if ancestor.join("Cargo.toml").is_file()
            || ancestor.join(".gruff-rs.yaml").is_file()
            || ancestor.join(".git").symlink_metadata().is_ok()
        {
            return ancestor.canonicalize().map_err(|error| {
                format!(
                    "unable to canonicalize project root {}: {error}",
                    ancestor.display()
                )
            });
        }
    }
    // Files from unrelated projects need separate scans when only the filesystem root contains them both.
    if shared_directory.parent().is_none() && targets.len() > 1 {
        return Err("scan targets must share a project ancestor".to_string());
    }
    shared_directory.canonicalize().map_err(|error| {
        format!(
            "unable to canonicalize scan root {}: {error}",
            shared_directory.display()
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
    // Each additional target can move the shared directory upward before config discovery starts.
    for directory in directories {
        while !directory.starts_with(&common) {
            // For example, paths on unrelated drives cannot share a config root for one scan.
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
    // A directory target can itself carry the project config. A file takes its context from its parent.
    if target.is_dir() {
        return target.to_path_buf();
    }
    target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| target.to_path_buf())
}

/// Preserve the meaning of a path such as `--baseline ../reviewed.json` when analysis uses a different project root.
///
/// `caller_root` is the canonical launch directory and `project_root` the canonical root the rewritten path will be joined to.
/// `path` is the path as typed; an absolute path, or any path when the two roots are equal, is passed on unchanged.
///
/// Returns the path to join to `project_root`.
fn rebase_launch_path(caller_root: &Path, project_root: &Path, path: PathBuf) -> PathBuf {
    // Absolute inputs already name the intended file. When the directories match, relative inputs do too.
    if path.is_absolute() || caller_root == project_root {
        return path;
    }
    // Preserve `..` after a symlink so `--generate-baseline link/../reviewed.json` reaches the intended destination.
    let target = absolutize(caller_root, &path);
    let root_parts: Vec<Component<'_>> = project_root.components().collect();
    let target_parts: Vec<Component<'_>> = target.components().collect();
    let shared_component_count = root_parts
        .iter()
        .zip(&target_parts)
        .take_while(|(root_part, target_part)| root_part == target_part)
        .count();
    let mut relative = PathBuf::new();
    // Walk from the project root back to the directory common to the project and the caller's path.
    for _ in shared_component_count..root_parts.len() {
        relative.push("..");
    }
    // Complete the route to the caller's input or output, preserving any symlink-sensitive components they typed.
    for part in &target_parts[shared_component_count..] {
        relative.push(part.as_os_str());
    }
    relative
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

/// Choose which finding severity can make this command exit with status 1.
///
/// `cli_value` is the threshold given on the command line, if any, and `binary_default` is the fallback when neither tier sets one.
/// `config` supplies `failOn` and `command` names its entry, such as `analyse`.
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

/// Prepare `analyse` or `report` with the project config and the exit threshold that applies to that command.
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

/// Send the report to stdout or to the file named by `--output`.
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
    // A caller who asks for an output file gets it even when quiet mode suppresses stdout.
    if let Some(path) = output {
        fs::write(&path, rendered)
            .map_err(|error| format!("unable to write {}: {error}", path.display()))?;
    } else {
        writer.emit(outcome, rendered);
    }
    Ok(())
}
