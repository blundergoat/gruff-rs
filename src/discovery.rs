use super::*;

#[derive(Clone)]
pub(crate) struct DiscoveryResult {
    pub(crate) files: Vec<SourceFile>,
    pub(crate) missing_paths: Vec<String>,
    pub(crate) ignored_paths: Vec<String>,
    pub(crate) ignored_path_details: Vec<IgnoredPath>,
}

pub(crate) struct DiscoverySession<'a> {
    pub(crate) project_root: &'a Path,
    pub(crate) options: &'a AnalysisOptions,
    pub(crate) config: &'a Config,
    pub(crate) ignored_paths: &'a Arc<Mutex<BTreeMap<String, IgnoredPath>>>,
}

pub(crate) struct DiscoveryFilters<'a> {
    pub(crate) project_root: &'a Path,
    pub(crate) config: &'a Config,
    pub(crate) ignored_paths: &'a Mutex<BTreeMap<String, IgnoredPath>>,
    pub(crate) include_ignored: bool,
}

pub(crate) fn discover_sources(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
) -> DiscoveryResult {
    let mut files = Vec::new();
    let mut missing_paths = Vec::new();
    let ignored_paths = Arc::new(Mutex::new(BTreeMap::new()));
    let session = DiscoverySession {
        project_root,
        options,
        config,
        ignored_paths: &ignored_paths,
    };
    for input in resolve_input_paths(options) {
        collect_input_path_sources(&input, &session, &mut files, &mut missing_paths);
    }
    sort_and_dedupe_source_files(&mut files);
    let (ignored_paths, ignored_path_details) = collected_ignored(&ignored_paths);
    DiscoveryResult {
        files,
        missing_paths,
        ignored_paths,
        ignored_path_details,
    }
}

fn resolve_input_paths(options: &AnalysisOptions) -> Vec<PathBuf> {
    if options.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        options.paths.to_vec()
    }
}

fn collect_input_path_sources(
    input: &Path,
    session: &DiscoverySession<'_>,
    files: &mut Vec<SourceFile>,
    missing_paths: &mut Vec<String>,
) {
    let absolute = absolutize(session.project_root, input);
    if !absolute.exists() {
        missing_paths.push(input.display().to_string());
        return;
    }
    if absolute.is_file() {
        collect_input_file_source(session, &absolute, files);
        return;
    }
    collect_directory_sources(&absolute, session, files);
}

// Explicit file args bypass the directory walk, so the config `paths.ignore`
// check has to happen here too. A coding-agent hook passes changed files
// directly, and config-ignored files must never produce findings however they
// were supplied (ADR-018). Git/default ignores still do not apply to explicit
// paths (ADR-004): an operator can inspect those by naming the file.
fn collect_input_file_source(
    session: &DiscoverySession<'_>,
    absolute: &Path,
    files: &mut Vec<SourceFile>,
) {
    let relative = display_path(session.project_root, absolute);
    if let Some(matcher) = config_ignore_match(&relative, session.config) {
        record_ignored_path(
            session.ignored_paths,
            IgnoredPath {
                path: relative,
                source: IgnoreSource::Config,
                pattern: Some(matcher.pattern().to_string()),
            },
        );
        return;
    }
    push_source_file(session.project_root, absolute, files);
}

fn sort_and_dedupe_source_files(files: &mut Vec<SourceFile>) {
    files.sort_by(|left, right| left.display_path.cmp(&right.display_path));
    files.dedup_by(|left, right| left.absolute_path == right.absolute_path);
}

fn collected_ignored(
    ignored_paths: &Arc<Mutex<BTreeMap<String, IgnoredPath>>>,
) -> (Vec<String>, Vec<IgnoredPath>) {
    let guard = ignored_paths.lock().expect("ignored paths lock");
    let paths = guard.keys().cloned().collect();
    let details = guard.values().cloned().collect();
    (paths, details)
}

pub(crate) fn collect_directory_sources(
    absolute: &Path,
    session: &DiscoverySession<'_>,
    files: &mut Vec<SourceFile>,
) {
    let include_ignored = session.options.include_ignored;
    let builder = directory_walk_builder(absolute, session, include_ignored);

    let outer_filters = DiscoveryFilters {
        project_root: session.project_root,
        config: session.config,
        ignored_paths: session.ignored_paths,
        include_ignored,
    };
    for entry in builder.build().filter_map(Result::ok).filter(|entry| {
        entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
    }) {
        if should_include_file(&entry, &outer_filters) {
            push_source_file(session.project_root, entry.path(), files);
        }
    }
}

fn directory_walk_builder(
    absolute: &Path,
    session: &DiscoverySession<'_>,
    include_ignored: bool,
) -> WalkBuilder {
    let filter_root = session.project_root.to_path_buf();
    let filter_config = session.config.clone();
    let filter_ignored_paths = Arc::clone(session.ignored_paths);
    let mut builder = WalkBuilder::new(absolute);
    builder
        .hidden(false)
        .parents(false)
        .ignore(!include_ignored)
        .git_ignore(!include_ignored)
        .git_global(false)
        .git_exclude(!include_ignored)
        .filter_entry(move |entry| {
            let filters = DiscoveryFilters {
                project_root: &filter_root,
                config: &filter_config,
                ignored_paths: &filter_ignored_paths,
                include_ignored,
            };
            should_descend(entry, &filters)
        });
    builder
}

pub(crate) fn should_descend(entry: &DirEntry, filters: &DiscoveryFilters<'_>) -> bool {
    if entry.depth() == 0
        || !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_dir())
    {
        return true;
    }
    should_keep_entry(entry, filters)
}

pub(crate) fn should_include_file(entry: &DirEntry, filters: &DiscoveryFilters<'_>) -> bool {
    should_keep_entry(entry, filters)
}

// Shared exclusion gate for directories (descend) and files (include): classify
// the path once, record it with its reason when ignored, otherwise keep it.
fn should_keep_entry(entry: &DirEntry, filters: &DiscoveryFilters<'_>) -> bool {
    let relative = display_path(filters.project_root, entry.path());
    match classify_ignored_relative(&relative, filters.config, filters.include_ignored) {
        Some(ignored) => {
            record_ignored_path(filters.ignored_paths, ignored);
            false
        }
        None => true,
    }
}

pub(crate) fn record_ignored_path(
    ignored_paths: &Mutex<BTreeMap<String, IgnoredPath>>,
    ignored: IgnoredPath,
) {
    ignored_paths
        .lock()
        .expect("ignored paths lock")
        .entry(ignored.path.clone())
        .or_insert(ignored);
}

/// The single config-ignore engine: find the project `paths.ignore` glob that
/// matches `relative`, if any. Shared by the directory walk, explicit file args,
/// and `check-ignore`; there is no second matcher implementation.
pub(crate) fn config_ignore_match<'a>(
    relative: &str,
    config: &'a Config,
) -> Option<&'a PathMatcher> {
    config
        .ignored_path_matchers
        .iter()
        .find(|matcher| matcher.matches(relative))
}

/// Classify whether `relative` is ignored and why. Precedence:
/// 1. Config `paths.ignore` — authoritative; neither explicit paths nor
///    `--include-ignored` can override it.
/// 2. VCS internals (`.git`/`.hg`/`.svn`) — always blocked, even with
///    `--include-ignored` ("VCS internals remain blocked").
/// 3. Default/generated directories — opt-out via `--include-ignored`.
///
/// gitignore exclusions are applied by the discovery walk's `ignore`-crate
/// matchers and are not re-derived here, keeping a single ignore engine (ADR-018).
pub(crate) fn classify_ignored_relative(
    relative: &str,
    config: &Config,
    include_ignored: bool,
) -> Option<IgnoredPath> {
    if let Some(matcher) = config_ignore_match(relative, config) {
        return Some(IgnoredPath {
            path: relative.to_string(),
            source: IgnoreSource::Config,
            pattern: Some(matcher.pattern().to_string()),
        });
    }
    if let Some(component) = vcs_internal_component(relative) {
        return Some(IgnoredPath {
            path: relative.to_string(),
            source: IgnoreSource::Default,
            pattern: Some(component),
        });
    }
    if include_ignored {
        return None;
    }
    let component = default_ignored_component(relative)?;
    let source = if component == "generated" {
        IgnoreSource::Generated
    } else {
        IgnoreSource::Default
    };
    Some(IgnoredPath {
        path: relative.to_string(),
        source,
        pattern: Some(component),
    })
}

pub(crate) fn classify_ignored_path(
    project_root: &Path,
    path: &Path,
    config: &Config,
    include_ignored: bool,
) -> Option<IgnoredPath> {
    classify_ignored_relative(&display_path(project_root, path), config, include_ignored)
}

pub(crate) fn default_ignored_component(relative: &str) -> Option<String> {
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
    .then(|| first.to_string())
}

pub(crate) fn vcs_internal_component(relative: &str) -> Option<String> {
    relative
        .split('/')
        .find(|component| matches!(*component, ".git" | ".hg" | ".svn"))
        .map(str::to_string)
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
    let extension = extension.to_ascii_lowercase();
    let is_rust = extension == "rs";
    let is_text = is_supported_text_file(&extension, file_name);

    if is_rust || is_text {
        files.push(SourceFile {
            absolute_path: path.to_path_buf(),
            display_path: display_path(project_root, path),
            is_rust,
        });
    }
}

fn is_supported_text_file(extension: &str, file_name: &str) -> bool {
    matches!(
        extension,
        "bash"
            | "conf"
            | "config"
            | "crt"
            | "env"
            | "gradle"
            | "ini"
            | "json"
            | "key"
            | "lock"
            | "md"
            | "markdown"
            | "pem"
            | "properties"
            | "sh"
            | "tf"
            | "tfvars"
            | "toml"
            | "txt"
            | "xml"
            | "yaml"
            | "yml"
    ) || is_security_relevant_text_name(file_name)
}

fn is_security_relevant_text_name(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower.starts_with(".env")
        || matches!(
            lower.as_str(),
            ".dockerignore"
                | ".netrc"
                | ".npmrc"
                | ".pypirc"
                | ".yarnrc"
                | "config"
                | "containerfile"
                | "dockerfile"
                | "gnumakefile"
                | "justfile"
                | "makefile"
                | "procfile"
        )
}
