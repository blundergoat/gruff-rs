use super::*;

/// Why a path was excluded from analysis. `config` (project `paths.ignore`) is
/// authoritative in every invocation and is never overridden by explicit paths
/// or `--include-ignored`; non-VCS `default` and `gitignore` decisions are
/// opt-out via `--include-ignored`. See ADR-018 and the family scan-input policy.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(crate) enum IgnoreSource {
    Config,
    Gitignore,
    Default,
}

impl IgnoreSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Gitignore => "gitignore",
            Self::Default => "default",
        }
    }
}

/// One ignored path with the reason it was skipped. `pattern` carries the exact
/// `paths.ignore` glob for `source: config`, and the matched directory/component
/// for `default`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IgnoredPath {
    pub(crate) path: String,
    pub(crate) source: IgnoreSource,
    pub(crate) pattern: Option<String>,
}
