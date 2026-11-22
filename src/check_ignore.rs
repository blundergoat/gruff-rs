//! Find out why a path did or did not reach a scan without running the analyzer.
//! `check-ignore` uses the target project's config and reports the rule that excluded a requested path.
//!
//! Use it after a path produces no findings. Exit codes follow `git check-ignore` so scripts can act without parsing text.

use super::*;

/// One verdict in the `check-ignore --format json` response.
/// `source` names the policy for an ignored path, and `pattern` names its matching entry when available.
/// A caller can use `ignored` for the decision even when there is no pattern to display.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckIgnoreEntry {
    path: String,
    ignored: bool,
    source: Option<IgnoreSource>,
    pattern: Option<String>,
}

/// Explain whether analysis would skip the requested paths without running any rules.
/// With no paths, a caller gets the same exit status as a request that matched no ignore rule. JSON returns an empty array.
///
/// `args` carries the paths, config choice, and output format; `verbose` appends each ignored path's source and pattern in text output.
/// `writer` receives the rendered verdicts, while errors are printed to standard error.
/// Returns exit 0 when any path is ignored, 1 when none is, and 2 when the current directory or config cannot be resolved.
pub(crate) fn run_check_ignore(
    args: CheckIgnoreArgs,
    verbose: bool,
    writer: OutputWriter,
) -> ExitCode {
    // For example, a caller can check `src/generated.rs` from a sibling directory by typing its relative path.
    let caller_root = match std::env::current_dir() {
        Ok(launch_directory) => launch_directory,
        // A deleted working directory prevents reliable lookup of the paths the caller typed.
        Err(error) => {
            eprintln!("gruff-rs: unable to resolve current directory: {error}");
            return ExitCode::from(2);
        }
    };
    let (project_root, paths) =
        match crate::command_setup::resolve_scan_context(&caller_root, &args.paths) {
            Ok(context) => context,
            // For example, targets on different drives cannot share an ignore policy for one request.
            Err(error) => {
                eprintln!("gruff-rs: {error}");
                return ExitCode::from(2);
            }
        };
    let config = match load_config_for(&project_root, args.config.as_deref(), args.no_config) {
        Ok(config) => config,
        // An invalid `paths.ignore` entry stops the request instead of returning a verdict from different settings than `analyse`.
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            return ExitCode::from(2);
        }
    };

    // An empty request has no verdicts, even though setup uses the current directory to find config.
    let entries: Vec<CheckIgnoreEntry> = paths
        .iter()
        .take(args.paths.len())
        .map(|path| check_ignore_entry(&project_root, path, &config))
        .collect();
    let any_ignored = entries.iter().any(|entry| entry.ignored);

    writer.emit_unconditional(&render_check_ignore(&entries, args.format, verbose));
    // With several paths, exit 0 means at least one was ignored. Read the verdicts to see which ones.
    if any_ignored {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Find the first policy that excludes the requested path so the caller can see where to change it.
///
/// `project_root` anchors `path`, the path to check as given, and `config` supplies the ignore policy that discovery uses.
/// An existing file is judged by the explicit-file policy alone; only another path falls through to the `.gitignore` lookup.
/// Returns the verdict with its displayed path, and the source and pattern set only when the path is ignored.
fn check_ignore_entry(project_root: &Path, path: &Path, config: &Config) -> CheckIgnoreEntry {
    let absolute = absolutize(project_root, path);
    let explicit_file = absolute.is_file();
    // Naming an existing file directly uses the explicit-file policy, which does not apply ordinary Git ignores.
    let policy_decision = if explicit_file {
        crate::discovery::classify_explicit_file(project_root, &absolute, config)
    } else {
        classify_ignored_path(project_root, &absolute, config, false)
    };
    // A configured ignore can name the exact pattern to change without consulting another policy.
    if let Some(ignored) = policy_decision {
        return CheckIgnoreEntry {
            path: ignored.path,
            ignored: true,
            source: Some(ignored.source),
            pattern: ignored.pattern,
        };
    }
    let relative = display_path(project_root, &absolute);
    // With no explicit-file exclusion, analysis would accept this file as a target.
    if explicit_file {
        return CheckIgnoreEntry {
            path: relative,
            ignored: false,
            source: None,
            pattern: None,
        };
    }
    let gitignore = gitignore_for_path(project_root, &absolute);
    // For a path still subject to Git ignores, show the original pattern so the caller can locate the rule.
    if let Some(pattern) = gitignore_match(&gitignore, &relative, &absolute) {
        return CheckIgnoreEntry {
            path: relative,
            ignored: true,
            source: Some(IgnoreSource::Gitignore),
            pattern: Some(pattern),
        };
    }
    // No ignore policy matched. The caller can now check other causes, such as file type or rule selection.
    CheckIgnoreEntry {
        path: relative,
        ignored: false,
        source: None,
        pattern: None,
    }
}

/// Build the `.gitignore` hierarchy a directory scan would see before it reached the requested path.
/// This lets a direct query account for a nested policy such as `src/.gitignore`.
///
/// `project_root` is the matcher root and top of the hierarchy, and `absolute` is the queried path whose parent directories are searched.
/// Returns one matcher over every `.gitignore` found on that route, or an empty matcher that ignores nothing when building fails.
pub(crate) fn gitignore_for_path(
    project_root: &Path,
    absolute: &Path,
) -> ignore::gitignore::Gitignore {
    let mut builder = ignore::gitignore::GitignoreBuilder::new(project_root);
    // Load parent rules first so a deeper `.gitignore` can override them just as it does during a scan.
    for directory in gitignore_directories(project_root, absolute) {
        let gitignore_path = directory.join(".gitignore");
        // Most directories have no `.gitignore`; those that do contribute their rules to one matcher.
        if gitignore_path.is_file() {
            // For example, a malformed glob should not discard the usable patterns in the same ignore file.
            let _error = builder.add(gitignore_path);
        }
    }
    // If the ignore patterns cannot form a matcher, the result has no Git ignore match to report.
    builder
        .build()
        .unwrap_or_else(|_| ignore::gitignore::Gitignore::empty())
}

/// List the directories whose `.gitignore` can claim `absolute`, from the project root down to the path's own parent.
/// Returns nothing when the path sits outside the project, because no rule in this project could apply to it.
///
/// `project_root` is always the first directory listed, and `absolute` must lie under it; `.` and `..` segments add no directory.
fn gitignore_directories(project_root: &Path, absolute: &Path) -> Vec<PathBuf> {
    // Outside the project root there is no hierarchy to rebuild, so no directory contributes rules.
    let Ok(relative) = absolute.strip_prefix(project_root) else {
        return Vec::new();
    };
    let mut directories = vec![project_root.to_path_buf()];
    let mut current = project_root.to_path_buf();
    // A path directly in the root has no parent segments, so the root's own `.gitignore` is the whole hierarchy.
    if let Some(relative_parent) = relative.parent() {
        // Visit each named directory in order so the reported match comes from the same hierarchy as a scan.
        for component in relative_parent.components() {
            // `.` and `..` are path navigation, not directories with their own ignore rules to apply.
            let std::path::Component::Normal(component) = component else {
                continue;
            };
            current.push(component);
            directories.push(current.to_path_buf());
        }
    }
    directories
}

/// Ask the rebuilt matcher whether `.gitignore` claims this path, returning the pattern that did.
/// `None` means no gitignore rule matched, or the path lies outside the matcher root and cannot be asked at all - both
/// reach the operator as "not ignored".
///
/// `gitignore` is the rebuilt matcher and `relative` the project-relative path text it is asked about.
/// `absolute` is the same path on disk, checked only to tell the matcher whether it is a directory.
/// Returns the matching pattern as written in its `.gitignore`; an explicit `!` un-ignore also gives None.
fn gitignore_match(
    gitignore: &ignore::gitignore::Gitignore,
    relative: &str,
    absolute: &Path,
) -> Option<String> {
    // Reject paths outside the matcher root. A name such as `..cache` is a directory name, not the `..` component.
    if !crate::diff::is_relative_scan_path(relative) {
        return None;
    }
    // Only an ignore match carries a pattern worth reporting; an explicit un-ignore (`!rule`) and a plain miss both leave
    // the path analysable, so they answer the same way.
    match gitignore.matched_path_or_any_parents(relative, absolute.is_dir()) {
        ignore::Match::Ignore(glob) => Some(glob.original().to_string()),
        _ => None,
    }
}

/// Render the verdicts in the format the caller asked for.
/// JSON is the shape agent consumers parse; text is what an operator reads in a terminal.
///
/// `entries` are the verdicts in request order, `format` picks JSON or text, and `verbose` adds source and pattern to text output only.
/// Returns pretty-printed JSON listing every verdict, or text listing only the ignored paths.
fn render_check_ignore(
    entries: &[CheckIgnoreEntry],
    format: CheckIgnoreFormat,
    verbose: bool,
) -> String {
    match format {
        // Every path appears in JSON, ignored or not, because a consumer needs the negative answers too.
        CheckIgnoreFormat::Json => {
            serde_json::to_string_pretty(entries).expect("check-ignore serialize")
        }
        CheckIgnoreFormat::Text => render_check_ignore_text(entries, verbose),
    }
}

/// Write an ignored-path list suitable for a shell pipeline. A script can check the exit code when the list is empty.
///
/// `entries` are the verdicts to filter, and `verbose` adds the tab-separated `source:pattern` suffix to each line.
/// Returns the ignored paths joined by newlines with no trailing newline; a missing source or pattern prints as empty.
fn render_check_ignore_text(entries: &[CheckIgnoreEntry], verbose: bool) -> String {
    let mut output = String::new();
    // Ignore hits alone go to text output so scripts can use it like `git check-ignore`.
    for entry in entries.iter().filter(|entry| entry.ignored) {
        // Separator goes before each entry after the first, leaving no trailing newline for a caller reading the last line.
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&entry.path);
        // Verbose mode names the rule that claimed the path, which is what the operator edits to change the verdict.
        if verbose {
            output.push('\t');
            // A missing pattern, such as a built-in skip, leaves an empty field so callers can still split the line at the colon.
            output.push_str(entry.source.map(IgnoreSource::as_str).unwrap_or_default());
            output.push(':');
            output.push_str(entry.pattern.as_deref().unwrap_or_default());
        }
    }
    output
}
