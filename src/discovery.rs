//! Choose the files a scan is allowed to open from the targets named on the command line.
//!
//! Directory scans apply project and Git ignores. Naming an individual file uses the explicit-file policy.
//! Record skipped paths and their reasons so users can explain why an expected finding is absent.

use super::*;

/// Record which requested source files can reach analysis.
///
/// The report uses the missing and ignored paths to explain gaps in the scan.
/// The file list is only discovery evidence. Reading or parsing a file can still fail later.
#[derive(Clone)]
pub(crate) struct DiscoveryResult {
    pub(crate) files: Vec<SourceFile>,
    pub(crate) missing_paths: Vec<String>,
    pub(crate) ignored_paths: Vec<String>,
    pub(crate) ignored_path_details: Vec<IgnoredPath>,
}

/// Carry the caller's scan options and config through discovery of all requested targets.
///
/// A shared ignored-path record keeps the explanation available when several targets overlap.
/// The project root gives each reported path a consistent starting point.
pub(crate) struct DiscoverySession<'a> {
    pub(crate) project_root: &'a Path,
    pub(crate) options: &'a AnalysisOptions,
    pub(crate) config: &'a Config,
    pub(crate) ignored_paths: &'a Arc<Mutex<BTreeMap<String, IgnoredPath>>>,
}

/// Apply a scan's path policy to an entry before opening it.
///
/// `--include-ignored` can relax ordinary ignores, while discovery still checks protected paths.
/// Captured skip reasons let people see what the scan excluded by policy.
pub(crate) struct DiscoveryFilters<'a> {
    pub(crate) project_root: &'a Path,
    pub(crate) config: &'a Config,
    pub(crate) ignored_paths: &'a Mutex<BTreeMap<String, IgnoredPath>>,
    pub(crate) include_ignored: bool,
}

/// Find the scannable source files under the run's input paths, recording missing inputs and the paths a config or default exclusion ignored.
/// Paths the walker's `.gitignore`, `.ignore` and git-exclude rules hide are not recorded, nor is an unscannable file excluded as minified.
/// Entries the walker cannot read are skipped without a report.
///
/// `project_root` anchors relative inputs and display paths, `options` gives the inputs and `include_ignored`, and `config` the ignore rules.
/// With no input paths, `.` is resolved against `project_root` and walked.
///
/// Returns the files sorted by display path with adjacent repeats removed, the missing inputs as given, and the ignored paths sorted by path.
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

/// Choose the input paths a discovery run starts from, defaulting to `.` when none were requested.
///
/// `options` supplies the requested input paths.
///
/// Returns a copy of those paths, or a single `.` when `options` lists none.
fn resolve_input_paths(options: &AnalysisOptions) -> Vec<PathBuf> {
    if options.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        options.paths.to_vec()
    }
}

/// Collect the sources one input path contributes, whether it names a file, a directory or nothing that exists.
///
/// `input` is resolved against the project root in `session`, which also carries the options, config and shared ignored-path record.
/// A missing `input` is pushed onto `missing_paths` as written; an existing file or directory adds its admitted sources to `files`.
/// A file goes through the explicit-file exclusions, and a directory is walked with the full ignore rules.
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

// Explicit file args bypass Git and fallback exclusions. Config policy and VCS
// internals remain authoritative for every invocation shape.
/// Admit one explicitly named file unless a config ignore glob or a VCS internal component excludes it.
///
/// `session` supplies the project root, config and ignored-path record, and `absolute` is the file's absolute path.
/// An excluded file is recorded as ignored with its reason; otherwise it goes onto `files` if it is a scannable source.
fn collect_input_file_source(
    session: &DiscoverySession<'_>,
    absolute: &Path,
    files: &mut Vec<SourceFile>,
) {
    if let Some(ignored) = classify_explicit_file(session.project_root, absolute, session.config) {
        record_ignored_path(session.ignored_paths, ignored);
        return;
    }
    push_source_file(
        session.project_root,
        absolute,
        SourceOrigin::ExplicitFile,
        files,
    );
}

/// Put discovered files in display-path order and drop a repeat of a file that sorts next to it.
///
/// `files` is sorted in place by display path, then adjacent entries with the same absolute path are cut to the first.
fn sort_and_dedupe_source_files(files: &mut Vec<SourceFile>) {
    files.sort_by(|left, right| left.display_path.cmp(&right.display_path));
    files.dedup_by(|left, right| left.absolute_path == right.absolute_path);
}

/// Copy the paths a discovery run recorded as ignored out of the shared map.
///
/// `ignored_paths` is the session's map from display path to ignore record, locked once for the copy.
/// Panics if the map's lock is poisoned.
///
/// Returns the ignored display paths and their records, both in path order.
fn collected_ignored(
    ignored_paths: &Arc<Mutex<BTreeMap<String, IgnoredPath>>>,
) -> (Vec<String>, Vec<IgnoredPath>) {
    let guard = ignored_paths.lock().expect("ignored paths lock");
    let paths = guard.keys().cloned().collect();
    let details = guard.values().cloned().collect();
    (paths, details)
}

/// Walk one input directory and add every file the ignore rules keep and the scanner supports.
///
/// `absolute` is the directory to walk, and `files` receives the admitted sources in walk order.
/// `session` supplies the root, config and ignored-path record; its `include_ignored` lifts gitignore and non-VCS default exclusions.
/// Entries the walker cannot read are skipped without a report; recording an exclusion panics if `session.ignored_paths` is poisoned.
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
            push_source_file(
                session.project_root,
                entry.path(),
                SourceOrigin::Directory,
                files,
            );
        }
    }
}

/// Configure the walker for one input directory so hidden files are visited and ignored directories are pruned before descent.
///
/// `absolute` is the requested directory, and `session` supplies the project root and config.
/// `include_ignored` turns off `.ignore`, `.gitignore` and Git exclude files. Only in-project ignore files apply.
///
/// Returns the configured builder, whose entry filter runs `should_descend` on each entry below the walk root that the ignore rules keep.
fn directory_walk_builder(
    absolute: &Path,
    session: &DiscoverySession<'_>,
    include_ignored: bool,
) -> WalkBuilder {
    let filter_root = session.project_root.to_path_buf();
    let filter_config = session.config.clone();
    let filter_ignored_paths = Arc::clone(session.ignored_paths);
    let requested = absolute.to_path_buf();
    let walk_root = if absolute.starts_with(session.project_root) {
        session.project_root
    } else {
        absolute
    };
    // Begin at the project root to load ancestor ignore files, while descending
    // only through ancestors of the requested directory and its own subtree.
    let mut builder = WalkBuilder::new(walk_root);
    builder
        .hidden(false)
        .parents(false)
        .ignore(!include_ignored)
        .git_ignore(!include_ignored)
        .git_global(false)
        .git_exclude(!include_ignored)
        .filter_entry(move |entry| {
            // Read ancestor ignore files on the route to a typed subdirectory without scanning that directory's siblings.
            if !entry.path().starts_with(&requested) {
                return requested.starts_with(entry.path());
            }
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

/// Decide whether the directory walk enters a directory, recording it as ignored when an exclusion applies.
///
/// `entry` is the walked entry, and `filters` carries the root, config, ignored-path record and `include_ignored` used to classify it.
/// The walk root and anything that is not a directory always pass.
/// Panics if an exclusion must be recorded while `filters.ignored_paths` is poisoned.
///
/// Returns true to keep the entry, false when an exclusion removes a directory and its contents from the walk.
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

/// Decide whether a walked file is kept, recording an excluded file as ignored except an unscannable one excluded as minified.
///
/// `entry` is the walked file, and `filters` carries the root, config, ignored-path record and `include_ignored` used to classify it.
/// Panics if an exclusion must be recorded while `filters.ignored_paths` is poisoned.
///
/// Returns true when `classify_ignored_path` finds no exclusion, even for an unsupported file that `push_source_file` later drops.
pub(crate) fn should_include_file(entry: &DirEntry, filters: &DiscoveryFilters<'_>) -> bool {
    should_keep_entry(entry, filters)
}

// Shared exclusion gate for directories (descend) and files (include): classify
// the path once, record it with its reason when ignored, otherwise keep it.
/// Classify a walked entry once and keep it unless an exclusion applies, recording excluded entries with their reason.
///
/// `entry` is the walked directory or file, and `filters` supplies the project root, config, `include_ignored` and ignored-path record.
/// An exclusion by the minified-file pattern is recorded only for a scannable source; every other exclusion is recorded.
/// Panics if an exclusion must be recorded while `filters.ignored_paths` is poisoned.
///
/// Returns true when `classify_ignored_path` finds no exclusion and false when it does, whether or not the entry was recorded.
fn should_keep_entry(entry: &DirEntry, filters: &DiscoveryFilters<'_>) -> bool {
    match classify_ignored_path(
        filters.project_root,
        entry.path(),
        filters.config,
        filters.include_ignored,
    ) {
        Some(ignored) => {
            // A minified file is listed only when gruff-rs would otherwise scan it, so `jquery.min.js` stays unsupported.
            if ignored.pattern.as_deref() != Some(MINIFIED_FILE_PATTERN)
                || is_scannable_source(entry.path())
            {
                record_ignored_path(filters.ignored_paths, ignored);
            }
            false
        }
        None => true,
    }
}

/// Record an ignored path in the shared map, keeping the first record seen for each path.
///
/// `ignored_paths` is the session's map keyed by display path, and `ignored` is added unless its path is already present.
/// Panics if the map's lock is poisoned.
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
///
/// `config` supplies the compiled `paths.ignore` matchers, which are tried in order.
/// Returns the first matcher that matches `relative`, or None when no ignore glob applies.
pub(crate) fn config_ignore_match<'a>(
    relative: &str,
    config: &'a Config,
) -> Option<&'a PathMatcher> {
    config
        .ignored_path_matchers
        .iter()
        .find(|matcher| matcher.matches(relative))
}

/// Explain the first path policy that applies to `relative`, in precedence order.
///
/// - Config `paths.ignore` applies even when a caller names the path directly or uses `--include-ignored`.
/// - VCS internals such as `.git` remain blocked even with `--include-ignored`.
/// - Third-party, build-output, and minified names are excluded by default even with a governing `.gitignore`.
/// - Fallback directory rules apply without a governing `.gitignore`; `--include-ignored` can bypass both default groups.
///
/// gitignore exclusions are applied by the discovery walk's `ignore`-crate
/// matchers and are not re-derived here, keeping a single ignore engine (ADR-018).
///
/// `config` supplies the ignore globs, `include_ignored` skips steps 3 and 4, `fallback_applies` enables step 4, and `is_dir` marks a directory.
/// A directory's own last component counts for step 3, and the minified check runs only when `is_dir` is false.
/// Returns the ignored path with its source and the matching glob or component, or None when no step excludes `relative`.
pub(crate) fn classify_ignored_relative(
    relative: &str,
    config: &Config,
    include_ignored: bool,
    fallback_applies: bool,
    is_dir: bool,
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
    if let Some(component) = third_party_component(relative, is_dir) {
        return Some(IgnoredPath {
            path: relative.to_string(),
            source: IgnoreSource::Default,
            pattern: Some(component),
        });
    }
    if !is_dir && is_minified_name(relative) {
        return Some(IgnoredPath {
            path: relative.to_string(),
            source: IgnoreSource::Default,
            pattern: Some(MINIFIED_FILE_PATTERN.to_string()),
        });
    }
    if !fallback_applies {
        return None;
    }
    let component = default_ignored_component(relative)?;
    Some(IgnoredPath {
        path: relative.to_string(),
        source: IgnoreSource::Default,
        pattern: Some(component),
    })
}

/// Classify a path found on disk by its display form, with the no-gitignore fallback unless `should_apply_fallback_at` finds a `.gitignore`.
/// That search covers `project_root` and the directories below it on the way to `path`, compared lexically without resolving `..`;
/// a path whose parent does not start with `project_root` gets the fallback.
///
/// `path` is matched in display form, relative to `project_root` when it has that prefix, whole otherwise; `config` supplies the ignore globs.
/// `include_ignored` lifts the non-VCS default exclusions.
///
/// Whether `path` is a directory is read from the filesystem, so a path that does not exist is classified as a file.
/// Gitignore rules themselves are not matched here, so a gitignored path can still get None.
///
/// Returns the config or default ignore record from `classify_ignored_relative`, or None when neither excludes the path.
pub(crate) fn classify_ignored_path(
    project_root: &Path,
    path: &Path,
    config: &Config,
    include_ignored: bool,
) -> Option<IgnoredPath> {
    classify_ignored_relative(
        &display_path(project_root, path),
        config,
        include_ignored,
        should_apply_fallback_at(project_root, path),
        path.is_dir(),
    )
}

/// Classify a file named directly as an input, where only a config ignore glob or a VCS internal component can exclude it.
///
/// `path` is matched in display form, relative to `project_root` when it has that prefix, whole otherwise; `config` supplies the ignore globs.
///
/// Returns the ignore record when a config glob or a VCS internal component matches, otherwise None.
pub(crate) fn classify_explicit_file(
    project_root: &Path,
    path: &Path,
    config: &Config,
) -> Option<IgnoredPath> {
    classify_ignored_relative(
        &display_path(project_root, path),
        config,
        true,
        false,
        false,
    )
}

/// Find the first component that is a fallback-ignored name: `.fleet`, `.idea`, `.vscode`, `build`, `coverage`, `node_modules` or `target`.
///
/// `relative` is a slash-separated display path, and every component, a file's own name included, is compared exactly.
///
/// Returns that component, or None when `relative` holds none of those names.
pub(crate) fn default_ignored_component(relative: &str) -> Option<String> {
    relative
        .split('/')
        .find(|component| {
            matches!(
                *component,
                ".fleet" | ".idea" | ".vscode" | "build" | "coverage" | "node_modules" | "target"
            )
        })
        .map(str::to_string)
}

/// Pattern recorded for a minified file such as `settings.min.json`, which section 7 skips as generated. The glob is
/// only a label: `is_minified_name` decides the match, `.min.` directly before the final extension.
pub(crate) const MINIFIED_FILE_PATTERN: &str = "*.min.*";

/// Return the outermost directory on `relative` that holds third-party copies or build output, lowercased over ASCII.
/// A file's own name is not a directory, so `a/Vendor/x.rs` gives `vendor` while a file named `dist` matches nothing.
///
/// `is_dir` says `relative` is itself a directory, so its last component is checked too.
/// The names checked, ignoring ASCII case, are `vendor`, `vendors`, `third_party`, `third-party`, `bower_components` and `dist`.
/// Returns None when no directory component on `relative` is one of them.
pub(crate) fn third_party_component(relative: &str, is_dir: bool) -> Option<String> {
    let components: Vec<&str> = relative.split('/').collect();
    let directories = if is_dir {
        &components[..]
    } else {
        &components[..components.len().saturating_sub(1)]
    };
    directories
        .iter()
        .map(|component| component.to_ascii_lowercase())
        .find(|component| {
            matches!(
                component.as_str(),
                "vendor" | "vendors" | "third_party" | "third-party" | "bower_components" | "dist"
            )
        })
}

/// Decide whether a base name has `.min.` directly before its final extension, such as `config.min.json`;
/// `app.min.js.map` and `admin.mini.json` do not match.
///
/// `relative` is a slash-separated path whose last component is lowercased over ASCII before the check.
/// Returns true when that name has `.min` right before a non-empty final extension, otherwise false.
pub(crate) fn is_minified_name(relative: &str) -> bool {
    let name = relative
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match name.rsplit_once('.') {
        Some((stem, extension)) => !extension.is_empty() && stem.ends_with(".min"),
        None => false,
    }
}

/// Decide whether the no-gitignore fallback exclusions apply to a path, by looking for `.gitignore` files above it.
///
/// `path` is resolved against `project_root`, and each directory from `project_root` down to its parent is checked for a `.gitignore`.
/// The parent is compared with `project_root` lexically, without normalising `..`, and one that does not start with it skips every check.
///
/// Returns false when any checked directory holds a `.gitignore` file, and true otherwise.
pub(crate) fn should_apply_fallback_at(project_root: &Path, path: &Path) -> bool {
    let absolute = absolutize(project_root, path);
    // A directory can declare its own ignore policy before discovery decides whether to enter it.
    if absolute.is_dir() && absolute.join(".gitignore").is_file() {
        return false;
    }
    // A filesystem root with no ignore file has no parent policy to prefer over defaults.
    let Some(parent) = absolute.parent() else {
        return true;
    };
    let Ok(relative_parent) = parent.strip_prefix(project_root) else {
        return true;
    };

    let mut current = project_root.to_path_buf();
    if current.join(".gitignore").is_file() {
        return false;
    }
    for component in relative_parent.components() {
        let std::path::Component::Normal(component) = component else {
            continue;
        };
        current.push(component);
        if current.join(".gitignore").is_file() {
            return false;
        }
    }
    true
}

/// Find the version-control internals directory a display path passes through, which discovery always blocks.
///
/// `relative` is a slash-separated display path; each component, the last included, is compared exactly with `.git`, `.hg` and `.svn`.
///
/// Returns the first matching component, or None when `relative` holds none of them.
pub(crate) fn vcs_internal_component(relative: &str) -> Option<String> {
    relative
        .split('/')
        .find(|component| matches!(*component, ".git" | ".hg" | ".svn"))
        .map(str::to_string)
}

/// Add a path to the discovered files when it is a scannable source, marking whether it is Rust by its `.rs` extension.
///
/// `path` is checked with `is_scannable_source` and displayed relative to `project_root` where possible; `origin` records how it was found.
/// `files` gains the new entry; an unsupported path leaves it unchanged.
pub(crate) fn push_source_file(
    project_root: &Path,
    path: &Path,
    origin: SourceOrigin,
    files: &mut Vec<SourceFile>,
) {
    let is_rust = path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"));

    if is_scannable_source(path) {
        files.push(SourceFile {
            absolute_path: path.to_path_buf(),
            display_path: display_path(project_root, path),
            is_rust,
            origin,
        });
    }
}

/// Decide whether `push_source_file` would admit a path: Rust source or a supported text or config file.
///
/// `path` is judged by its ASCII-lowercased extension and its file name, never by its contents.
/// Returns true for an `rs` extension or a file `is_supported_text_file` accepts, otherwise false.
pub(crate) fn is_scannable_source(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    extension == "rs" || is_supported_text_file(&extension, file_name)
}

/// Decide whether a non-Rust file is a text or config format that discovery admits for scanning.
///
/// `extension` must already be lowercased and is matched against a fixed list such as `json`, `toml`, `yaml` and `pem`.
/// `file_name` is passed to `is_security_relevant_text_name` for names that matter whatever their extension.
///
/// Returns true when either check accepts the file, otherwise false.
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

/// Recognise file names scanned as text whatever their extension, such as `.env` files, rc files, Dockerfiles and Makefiles.
///
/// `file_name` is compared after ASCII lowercasing, so `Dockerfile` and `dockerfile` both match.
///
/// Returns true for a name starting with `.env` or equal to one of the fixed names, otherwise false.
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

/// Decide whether a text path is security-relevant, such as a key, certificate, env file or GitHub Actions workflow.
///
/// `path` is judged by its lowercased extension (`crt`, `env`, `key`, `pem` or `tfvars`), its file name and whether it is a workflow file.
///
/// Returns true when any of those checks matches, otherwise false.
pub(crate) fn is_security_relevant_text_path(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    matches!(extension.as_str(), "crt" | "env" | "key" | "pem" | "tfvars")
        || is_security_relevant_text_name(file_name)
        || path_is_github_workflow(path)
}

/// True when `path` is a GitHub Actions workflow (`.github/workflows/*.yml` or
/// `.yaml`). Those files carry the `security.github-actions-*` rules, so invalid
/// UTF-8 there must stay visible rather than be skipped as low-risk text.
///
/// Returns true for a `yml` or `yaml` extension in any case under a `.github` component directly followed by `workflows`, else false.
fn path_is_github_workflow(path: &Path) -> bool {
    let is_yaml = path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"));
    if !is_yaml {
        return false;
    }
    let components: Vec<&str> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    components
        .windows(2)
        .any(|pair| pair[0] == ".github" && pair[1] == "workflows")
}
