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
pub(crate) fn run_check_ignore(
    args: CheckIgnoreArgs,
    verbose: bool,
    writer: OutputWriter,
) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(project_root) => project_root,
        Err(error) => {
            eprintln!("gruff-rs: unable to resolve current directory: {error}");
            return ExitCode::from(2);
        }
    };
    let config = match load_config_for(&project_root, args.config.as_deref(), args.no_config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            return ExitCode::from(2);
        }
    };

    let gitignore = project_gitignore(&project_root);
    let entries: Vec<CheckIgnoreEntry> = args
        .paths
        .iter()
        .map(|path| check_ignore_entry(&project_root, path, &config, &gitignore))
        .collect();
    let any_ignored = entries.iter().any(|entry| entry.ignored);

    writer.emit_unconditional(&render_check_ignore(&entries, args.format, verbose));
    if any_ignored {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn check_ignore_entry(
    project_root: &Path,
    path: &Path,
    config: &Config,
    gitignore: &ignore::gitignore::Gitignore,
) -> CheckIgnoreEntry {
    let absolute = absolutize(project_root, path);
    if let Some(ignored) = classify_ignored_path(project_root, &absolute, config, false) {
        return CheckIgnoreEntry {
            path: ignored.path,
            ignored: true,
            source: Some(ignored.source),
            pattern: ignored.pattern,
        };
    }
    let relative = display_path(project_root, &absolute);
    if let Some(pattern) = gitignore_match(gitignore, &relative, &absolute) {
        return CheckIgnoreEntry {
            path: relative,
            ignored: true,
            source: Some(IgnoreSource::Gitignore),
            pattern: Some(pattern),
        };
    }
    CheckIgnoreEntry {
        path: relative,
        ignored: false,
        source: None,
        pattern: None,
    }
}

// The discovery walk applies gitignore via the `ignore` crate during traversal;
// check-ignore queries the same crate's matcher per path so it can report the
// gitignore source for an arbitrary path without a hierarchy. Built once from
// the project-root .gitignore (no second glob engine).
fn project_gitignore(project_root: &Path) -> ignore::gitignore::Gitignore {
    let (gitignore, _io_error) = ignore::gitignore::Gitignore::new(project_root.join(".gitignore"));
    gitignore
}

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
    match gitignore.matched_path_or_any_parents(relative, absolute.is_dir()) {
        ignore::Match::Ignore(glob) => Some(glob.original().to_string()),
        _ => None,
    }
}

fn render_check_ignore(
    entries: &[CheckIgnoreEntry],
    format: CheckIgnoreFormat,
    verbose: bool,
) -> String {
    match format {
        CheckIgnoreFormat::Json => {
            serde_json::to_string_pretty(entries).expect("check-ignore serialize")
        }
        CheckIgnoreFormat::Text => render_check_ignore_text(entries, verbose),
    }
}

// Text output mirrors `git check-ignore`: emit only the ignored paths, one per
// line. `-v/--verbose` appends `\t<source>:<pattern>` so an operator can see why.
fn render_check_ignore_text(entries: &[CheckIgnoreEntry], verbose: bool) -> String {
    let mut output = String::new();
    for entry in entries.iter().filter(|entry| entry.ignored) {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&entry.path);
        if verbose {
            output.push('\t');
            output.push_str(entry.source.map(IgnoreSource::as_str).unwrap_or_default());
            output.push(':');
            output.push_str(entry.pattern.as_deref().unwrap_or_default());
        }
    }
    output
}
