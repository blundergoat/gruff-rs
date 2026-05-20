use super::*;

pub(crate) struct DiscoveryResult {
    pub(crate) files: Vec<SourceFile>,
    pub(crate) missing_paths: Vec<String>,
    pub(crate) ignored_paths: Vec<String>,
}

pub(crate) fn discover_sources(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
) -> DiscoveryResult {
    let mut files = Vec::new();
    let mut missing_paths = Vec::new();
    let ignored_paths = Arc::new(Mutex::new(BTreeSet::new()));
    let input_paths = if options.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        options.paths.clone()
    };

    for input in input_paths {
        let absolute = absolutize(project_root, &input);
        if !absolute.exists() {
            missing_paths.push(input.display().to_string());
            continue;
        }
        if absolute.is_file() {
            push_source_file(project_root, &absolute, &mut files);
            continue;
        }
        collect_directory_sources(
            project_root,
            &absolute,
            options,
            config,
            &ignored_paths,
            &mut files,
        );
    }

    files.sort_by(|left, right| left.display_path.cmp(&right.display_path));
    files.dedup_by(|left, right| left.absolute_path == right.absolute_path);

    let ignored_paths = ignored_paths
        .lock()
        .expect("ignored paths lock")
        .iter()
        .cloned()
        .collect();

    DiscoveryResult {
        files,
        missing_paths,
        ignored_paths,
    }
}

pub(crate) fn collect_directory_sources(
    project_root: &Path,
    absolute: &Path,
    options: &AnalysisOptions,
    config: &Config,
    ignored_paths: &Arc<Mutex<BTreeSet<String>>>,
    files: &mut Vec<SourceFile>,
) {
    let apply_project_ignore = !path_is_project_ignored(project_root, absolute, config);
    let include_ignored = options.include_ignored;
    let filter_root = project_root.to_path_buf();
    let filter_config = config.clone();
    let filter_ignored_paths = Arc::clone(ignored_paths);
    let mut builder = WalkBuilder::new(absolute);
    builder
        .hidden(false)
        .parents(false)
        .ignore(!include_ignored)
        .git_ignore(!include_ignored)
        .git_global(false)
        .git_exclude(!include_ignored)
        .filter_entry(move |entry| {
            should_descend(
                entry,
                &filter_root,
                include_ignored,
                &filter_config,
                apply_project_ignore,
                &filter_ignored_paths,
            )
        });

    for entry in builder.build().filter_map(Result::ok).filter(|entry| {
        entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
    }) {
        if !should_include_file(
            &entry,
            project_root,
            options,
            config,
            apply_project_ignore,
            ignored_paths,
        ) {
            continue;
        }
        push_source_file(project_root, entry.path(), files);
    }
}

pub(crate) fn should_descend(
    entry: &DirEntry,
    project_root: &Path,
    include_ignored: bool,
    config: &Config,
    apply_project_ignore: bool,
    ignored_paths: &Mutex<BTreeSet<String>>,
) -> bool {
    if entry.depth() == 0
        || !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_dir())
    {
        return true;
    }

    let relative = display_path(project_root, entry.path());
    if is_vcs_internal_dir(&relative) {
        record_ignored_path(ignored_paths, relative);
        return false;
    }

    if !include_ignored && is_default_ignored_dir(&relative) {
        record_ignored_path(ignored_paths, relative);
        return false;
    }

    if !include_ignored
        && apply_project_ignore
        && path_is_project_ignored(project_root, entry.path(), config)
    {
        record_ignored_path(ignored_paths, relative);
        return false;
    }

    true
}

pub(crate) fn should_include_file(
    entry: &DirEntry,
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    apply_project_ignore: bool,
    ignored_paths: &Mutex<BTreeSet<String>>,
) -> bool {
    if options.include_ignored || !apply_project_ignore {
        return true;
    }
    if path_is_project_ignored(project_root, entry.path(), config) {
        record_ignored_path(ignored_paths, display_path(project_root, entry.path()));
        return false;
    }
    true
}

pub(crate) fn record_ignored_path(ignored_paths: &Mutex<BTreeSet<String>>, path: String) {
    ignored_paths
        .lock()
        .expect("ignored paths lock")
        .insert(path);
}

pub(crate) fn path_is_project_ignored(project_root: &Path, path: &Path, config: &Config) -> bool {
    let relative = display_path(project_root, path);
    config
        .ignored_paths
        .iter()
        .any(|pattern| path_matches(pattern, &relative))
}

pub(crate) fn is_default_ignored_dir(relative: &str) -> bool {
    let first = relative.split('/').next().unwrap_or(relative);
    matches!(
        first,
        ".git"
            | ".hg"
            | ".svn"
            | ".idea"
            | ".vscode"
            | "build"
            | "cache"
            | "coverage"
            | "dist"
            | "generated"
            | "node_modules"
            | "target"
            | "tmp"
            | "vendor"
    )
}

pub(crate) fn is_vcs_internal_dir(relative: &str) -> bool {
    relative
        .split('/')
        .any(|component| matches!(component, ".git" | ".hg" | ".svn"))
}

pub(crate) fn push_source_file(project_root: &Path, path: &Path, files: &mut Vec<SourceFile>) {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let is_rust = extension.eq_ignore_ascii_case("rs");
    let is_text = matches!(
        extension,
        "bash"
            | "conf"
            | "config"
            | "env"
            | "ini"
            | "json"
            | "md"
            | "markdown"
            | "sh"
            | "toml"
            | "txt"
            | "xml"
            | "yaml"
            | "yml"
    ) || file_name.starts_with(".env");

    if is_rust || is_text {
        files.push(SourceFile {
            absolute_path: path.to_path_buf(),
            display_path: display_path(project_root, path),
            is_rust,
        });
    }
}
