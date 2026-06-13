use super::*;

#[derive(Clone)]
pub(crate) struct SourceFile {
    pub(crate) absolute_path: PathBuf,
    pub(crate) display_path: String,
    pub(crate) is_rust: bool,
    pub(crate) origin: SourceOrigin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceOrigin {
    ExplicitFile,
    Directory,
}

pub(crate) struct SourceUnit<'a> {
    pub(crate) file: &'a SourceFile,
    pub(crate) source: &'a str,
    pub(crate) rust_ast: Option<&'a syn::File>,
    line_starts: &'a OnceLock<Vec<usize>>,
}

pub(crate) struct ParsedSource {
    pub(crate) file: SourceFile,
    pub(crate) source: String,
    pub(crate) rust_ast: Option<syn::File>,
    pub(crate) diagnostics: Vec<RunDiagnostic>,
    pub(crate) line_starts: OnceLock<Vec<usize>>,
}

impl ParsedSource {
    pub(crate) fn as_source_unit(&self) -> SourceUnit<'_> {
        SourceUnit {
            file: &self.file,
            source: &self.source,
            rust_ast: self.rust_ast.as_ref(),
            line_starts: &self.line_starts,
        }
    }
}

impl SourceUnit<'_> {
    pub(crate) fn line_starts(&self) -> &[usize] {
        self.line_starts
            .get_or_init(|| crate::line_starts(self.source))
            .as_slice()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProjectCoverage {
    pub(crate) discoverable_rust_files: BTreeSet<String>,
    pub(crate) analysed_rust_files: BTreeSet<String>,
    pub(crate) diff_selection_narrowed: bool,
    pub(crate) parse_incomplete: bool,
}

impl ProjectCoverage {
    pub(crate) fn is_partial(&self) -> bool {
        if self.analysed_rust_files.is_empty() {
            return false;
        }
        // Partial when a discovered Rust file failed to parse (the cross-file
        // identifier index is then incomplete), or when any discoverable Rust file
        // was not analysed - an explicit scan whose set is not a subset of the
        // universe (e.g. a named gitignored file) is not authoritative either.
        self.parse_incomplete
            || self.diff_selection_narrowed
            || !self
                .discoverable_rust_files
                .is_subset(&self.analysed_rust_files)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectContext {
    pub(crate) root_path: PathBuf,
    pub(crate) coverage: ProjectCoverage,
    pub(crate) manifest: Option<ManifestSummary>,
    pub(crate) lockfile: Option<LockfileSummary>,
    pub(crate) rust_sources: Vec<RustSourceSummary>,
    pub(crate) identifier_counts: BTreeMap<String, usize>,
    pub(crate) modules: Vec<ModuleSummary>,
    pub(crate) items: Vec<ItemSummary>,
    pub(crate) call_names: Vec<CallNameSummary>,
    pub(crate) diagnostics: Vec<RunDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManifestSummary {
    pub(crate) file_path: String,
    pub(crate) package_line: usize,
    pub(crate) package_name: Option<String>,
    pub(crate) package_description: Option<String>,
    pub(crate) package_license: Option<String>,
    pub(crate) dependencies: Vec<DependencySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DependencySummary {
    pub(crate) name: String,
    pub(crate) section: String,
    pub(crate) line: usize,
    pub(crate) requirement: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) git: Option<String>,
    pub(crate) rev: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockfileSummary {
    pub(crate) file_path: String,
    pub(crate) packages: Vec<LockedPackageSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockedPackageSummary {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) line: usize,
    pub(crate) source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustSourceSummary {
    pub(crate) file_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleSummary {
    pub(crate) file_path: String,
    pub(crate) module_path: String,
    pub(crate) line: usize,
    pub(crate) public: bool,
    pub(crate) inline: bool,
    pub(crate) cfg_gated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ItemSummary {
    pub(crate) file_path: String,
    pub(crate) module_path: String,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) container: Option<String>,
    pub(crate) line: usize,
    pub(crate) public: bool,
    pub(crate) externally_public: bool,
    pub(crate) cfg_gated: bool,
    pub(crate) test_context: bool,
    pub(crate) trait_impl: bool,
    pub(crate) exported_by_attr: bool,
    pub(crate) allow_dead_code: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ProjectItemContext {
    pub(crate) public: bool,
    pub(crate) externally_public: bool,
    pub(crate) cfg_gated: bool,
    pub(crate) test_context: bool,
    pub(crate) container: Option<String>,
    pub(crate) trait_impl: bool,
    pub(crate) exported_by_attr: bool,
    pub(crate) allow_dead_code: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallNameSummary {
    pub(crate) file_path: String,
    pub(crate) name: String,
    pub(crate) line: usize,
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    fn coverage(discoverable: &[&str], analysed: &[&str]) -> ProjectCoverage {
        ProjectCoverage {
            discoverable_rust_files: discoverable.iter().map(|path| path.to_string()).collect(),
            analysed_rust_files: analysed.iter().map(|path| path.to_string()).collect(),
            diff_selection_narrowed: false,
            parse_incomplete: false,
        }
    }

    #[test]
    fn is_partial_flags_any_uncovered_discoverable_file() {
        // Full coverage: every discoverable file was analysed.
        assert!(!coverage(&["a.rs", "b.rs"], &["a.rs", "b.rs"]).is_partial());
        // Proper subset: a discoverable file was not analysed.
        assert!(coverage(&["a.rs", "b.rs"], &["a.rs"]).is_partial());
        // Superset: analysed covers all discoverable plus an out-of-walk extra.
        assert!(!coverage(&["a.rs"], &["a.rs", "extra.rs"]).is_partial());
        // Incomparable: an extra AND a missed discoverable file - still partial.
        assert!(coverage(&["a.rs", "b.rs"], &["a.rs", "extra.rs"]).is_partial());
        // Nothing analysed: treated as not-partial.
        assert!(!coverage(&["a.rs"], &[]).is_partial());
    }
}
