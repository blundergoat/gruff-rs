//! Answers "would gruff ignore this path?" without analysing anything.
//!
//! An operator reaches this from `gruff-rs check-ignore <path>` after a file produced no findings and they need to know
//! whether discovery skipped it or it simply had nothing to report. The verdict comes from the same config resolution and
//! ignore engine `analyse` uses, so an answer here is the answer discovery would have given. Exit codes mirror
//! `git check-ignore`, letting a shell caller branch on the status instead of parsing output.

use super::*;

/// One `check-ignore` verdict. `source`/`pattern` are populated only when the
/// path is ignored. This is the JSON contract agent consumers read.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckIgnoreEntry {
    path: String,
    ignored: bool,
    source: Option<IgnoreSource>,
    pattern: Option<String>,
}

/// `check-ignore` reports whether gruff would ignore each path and why, using the
/// same config resolution (`load_config_for`) and ignore engine
/// (`classify_ignored_path`) as `analyse` — no analysis is performed. Exit codes
/// mirror `git check-ignore`: 0 when at least one path is ignored, 1 when none
/// are, 2 on error.
///
/// Passing no paths is not an error: the operator gets empty output and exit 1, the same status as "nothing here is
/// ignored", so a script that branches on the exit code cannot tell the two apart.
pub(crate) fn run_check_ignore(
    args: CheckIgnoreArgs,
    verbose: bool,
    writer: OutputWriter,
) -> ExitCode {
    // e.g. the operator ran `gruff-rs check-ignore --format json src/generated.rs` from the project root after that file
    // produced no findings.
    let project_root = match std::env::current_dir() {
        Ok(project_root) => project_root,
        // The shell handed us a deleted or unreadable working directory, so no path can be resolved relative to a project
        // and the run stops before answering anything.
        Err(error) => {
            eprintln!("gruff-rs: unable to resolve current directory: {error}");
            return ExitCode::from(2);
        }
    };
    let config = match load_config_for(&project_root, args.config.as_deref(), args.no_config) {
        Ok(config) => config,
        // A broken or unreadable config would answer with different ignore rules than `analyse` uses, so the operator gets
        // the parse error instead of a verdict they cannot trust.
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            return ExitCode::from(2);
        }
    };

    let entries: Vec<CheckIgnoreEntry> = args
        .paths
        .iter()
        .map(|path| check_ignore_entry(&project_root, path, &config))
        .collect();
    let any_ignored = entries.iter().any(|entry| entry.ignored);

    writer.emit_unconditional(&render_check_ignore(&entries, args.format, verbose));
    // Git's convention: a hit is success. One ignored path among many still exits 0, so a caller checking a single path
    // gets a usable boolean and a caller checking several must read the output.
    if any_ignored {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Decide one path's verdict and record which layer claimed it.
/// Config `paths.ignore` is consulted before `.gitignore` so the reported source names the rule the operator can actually
/// edit; an unignored path still returns an entry, carrying `ignored: false`.
fn check_ignore_entry(project_root: &Path, path: &Path, config: &Config) -> CheckIgnoreEntry {
    let absolute = absolutize(project_root, path);
    // Config ignores win, and they already carry the matching pattern, so the operator is told which `.gruff-rs.yaml` entry
    // to change rather than being sent to Git.
    if let Some(ignored) = classify_ignored_path(project_root, &absolute, config, false) {
        return CheckIgnoreEntry {
            path: ignored.path,
            ignored: true,
            source: Some(ignored.source),
            pattern: ignored.pattern,
        };
    }
    let relative = display_path(project_root, &absolute);
    let gitignore = gitignore_for_path(project_root, &absolute);
    // No config rule claimed it, so Git's own ignore hierarchy decides, and the reported pattern is the `.gitignore` line
    // to change.
    if let Some(pattern) = gitignore_match(&gitignore, &relative, &absolute) {
        return CheckIgnoreEntry {
            path: relative,
            ignored: true,
            source: Some(IgnoreSource::Gitignore),
            pattern: Some(pattern),
        };
    }
    // Nothing ignores this path, so a missing finding is a genuine clean result rather than a skip.
    CheckIgnoreEntry {
        path: relative,
        ignored: false,
        source: None,
        pattern: None,
    }
}

/// The discovery walk applies gitignore via the `ignore` crate during traversal;
/// check-ignore queries the same crate's matcher per path so it can report the
/// gitignore source for an arbitrary path. Build the same hierarchy of
/// `.gitignore` files that the walk would encounter from project root to the
/// queried path's parent.
///
/// A direct query has no traversal context, so this rebuild is what stops a nested policy such as `src/.gitignore` from
/// being missed and the operator being told a genuinely ignored file is not.
pub(crate) fn gitignore_for_path(
    project_root: &Path,
    absolute: &Path,
) -> ignore::gitignore::Gitignore {
    let mut builder = ignore::gitignore::GitignoreBuilder::new(project_root);
    // Root first, then each directory on the way down, so a deeper `.gitignore` overrides a shallower one exactly as it
    // would during a walk.
    for directory in gitignore_directories(project_root, absolute) {
        let gitignore_path = directory.join(".gitignore");
        // Most directories have no `.gitignore`; those that do contribute their rules to one matcher.
        if gitignore_path.is_file() {
            // A malformed line is dropped rather than failing the query: Git itself skips lines it cannot parse, and
            // reporting a hard error here would block an answer the operator can still act on.
            let _error = builder.add(gitignore_path);
        }
    }
    // An unbuildable matcher answers "not ignored" for everything rather than aborting; the operator sees the same verdict
    // discovery would reach with no usable gitignore rules.
    builder
        .build()
        .unwrap_or_else(|_| ignore::gitignore::Gitignore::empty())
}

/// List the directories whose `.gitignore` can claim `absolute`, from the project root down to the path's own parent.
/// Returns nothing when the path sits outside the project, because no rule in this project could apply to it.
fn gitignore_directories(project_root: &Path, absolute: &Path) -> Vec<PathBuf> {
    // Outside the project root there is no hierarchy to rebuild, so no directory contributes rules.
    let Ok(relative) = absolute.strip_prefix(project_root) else {
        return Vec::new();
    };
    let mut directories = vec![project_root.to_path_buf()];
    let mut current = project_root.to_path_buf();
    // A path directly in the root has no parent segments, so the root's own `.gitignore` is the whole hierarchy.
    if let Some(relative_parent) = relative.parent() {
        for component in relative_parent.components() {
            // Only real directory names carry a `.gitignore`; a `.` or `..` segment is a traversal artifact and would build
            // a path Git never consults.
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
fn gitignore_match(
    gitignore: &ignore::gitignore::Gitignore,
    relative: &str,
    absolute: &Path,
) -> Option<String> {
    // `matched_path_or_any_parents` panics unless the path is under the matcher
    // root, so only query paths that resolved to a project-relative form.
    if relative.is_empty() || relative.starts_with('/') || relative.starts_with("..") {
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

/// Text output mirrors `git check-ignore`: emit only the ignored paths, one per
/// line. `-v/--verbose` appends `\t<source>:<pattern>` so an operator can see why.
///
/// With nothing ignored the result is an empty string, which is why the exit code rather than the output is what a shell
/// caller should test.
fn render_check_ignore_text(entries: &[CheckIgnoreEntry], verbose: bool) -> String {
    let mut output = String::new();
    // Unignored paths are dropped here so the output can be piped straight into another command, the way
    // `git check-ignore` output is.
    for entry in entries.iter().filter(|entry| entry.ignored) {
        // Separator goes before each entry after the first, leaving no trailing newline for a caller reading the last line.
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&entry.path);
        // Verbose mode names the rule that claimed the path, which is what the operator edits to change the verdict.
        if verbose {
            output.push('\t');
            // A verdict always carries its source and pattern, but an empty field prints as empty rather than aborting,
            // keeping the line shape stable for downstream parsers.
            output.push_str(entry.source.map(IgnoreSource::as_str).unwrap_or_default());
            output.push(':');
            output.push_str(entry.pattern.as_deref().unwrap_or_default());
        }
    }
    output
}
