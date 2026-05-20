use super::*;

#[derive(Clone)]
pub(crate) struct SourceFile {
    pub(crate) absolute_path: PathBuf,
    pub(crate) display_path: String,
    pub(crate) is_rust: bool,
}

pub(crate) struct SourceUnit<'a> {
    pub(crate) file: &'a SourceFile,
    pub(crate) source: &'a str,
    pub(crate) rust_ast: Option<&'a syn::File>,
}

pub(crate) struct ParsedSource {
    pub(crate) file: SourceFile,
    pub(crate) source: String,
    pub(crate) rust_ast: Option<syn::File>,
    pub(crate) diagnostics: Vec<RunDiagnostic>,
}

impl ParsedSource {
    pub(crate) fn as_source_unit(&self) -> SourceUnit<'_> {
        SourceUnit {
            file: &self.file,
            source: &self.source,
            rust_ast: self.rust_ast.as_ref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectContext {
    pub(crate) root_path: PathBuf,
    pub(crate) manifest: Option<ManifestSummary>,
    pub(crate) lockfile: Option<LockfileSummary>,
    pub(crate) rust_sources: Vec<RustSourceSummary>,
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
    pub(crate) source: String,
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
    pub(crate) line: usize,
    pub(crate) public: bool,
    pub(crate) externally_public: bool,
    pub(crate) cfg_gated: bool,
    pub(crate) test_context: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProjectItemContext {
    pub(crate) public: bool,
    pub(crate) externally_public: bool,
    pub(crate) cfg_gated: bool,
    pub(crate) test_context: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallNameSummary {
    pub(crate) file_path: String,
    pub(crate) name: String,
    pub(crate) line: usize,
}
