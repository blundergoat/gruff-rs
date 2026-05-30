use super::*;

// Universal-programming abbreviations that earn their place in source across nearly any codebase.
// Project-specific vocabulary (e.g. domain acronyms) should be appended to this list in the user's config.
pub(crate) const DEFAULT_ABBREVIATIONS: &[&str] = &[
    "age", "app", "db", "fs", "id", "io", "key", "log", "max", "min", "now", "raw", "rx", "tx",
    "ui", "url",
];

// The only accepted value for `.gruff-rs.yaml`'s required `schemaVersion:` field.
// Introduced by ADR-013 / M08a; bumped only when the config schema breaks compatibility.
pub(crate) const SCHEMA_VERSION: &str = "gruff-rs.config.v1";

#[derive(Clone)]
pub(crate) struct AnalysisOptions {
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) config: Option<PathBuf>,
    pub(crate) no_config: bool,
    pub(crate) format: OutputFormat,
    pub(crate) fail_on: FailThreshold,
    pub(crate) include_ignored: bool,
    pub(crate) diff: Option<DiffSelection>,
    pub(crate) history_file: Option<PathBuf>,
    pub(crate) baseline: Option<PathBuf>,
    pub(crate) generate_baseline: Option<PathBuf>,
    pub(crate) no_baseline: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum DiffSelection {
    Patch(PathBuf),
    GitUnsafe(String),
}

/// Renderer-only view of which paths and diff mode the user asked for.
///
/// This is intentionally not serialised onto `AnalysisReport`. The HTML
/// renderer uses it to populate the masthead "paths" and "scope" labels; other
/// renderers ignore it.
#[derive(Clone, Default, Debug)]
pub(crate) struct RequestedScope {
    pub(crate) paths: Vec<String>,
    pub(crate) diff_label: Option<String>,
}

impl RequestedScope {
    pub(crate) fn from_options(options: &AnalysisOptions) -> Self {
        let paths = if options.paths.is_empty() {
            vec![".".to_string()]
        } else {
            options
                .paths
                .iter()
                .map(|path| path.display().to_string())
                .collect()
        };
        let diff_label = options.diff.as_ref().map(|selection| match selection {
            DiffSelection::Patch(path) => format!("diff-patch · {}", path.display()),
            DiffSelection::GitUnsafe(mode) => format!("diff-git-unsafe · {mode}"),
        });
        Self { paths, diff_label }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) schema_version: String,
    pub(crate) ignored_paths: Vec<String>,
    pub(crate) ignored_path_matchers: Vec<PathMatcher>,
    pub(crate) accepted_abbreviations: BTreeSet<String>,
    pub(crate) secret_previews: BTreeSet<String>,
    pub(crate) selectors: SelectorSet,
    pub(crate) exclusions: Vec<ExclusionRule>,
    pub(crate) custom_rules: Vec<CustomRule>,
    pub(crate) rule_settings: HashMap<String, RuleSetting>,
    pub(crate) minimum_severity: BTreeMap<String, FailThreshold>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SelectorSet {
    pub(crate) positive: BTreeSet<String>,
    pub(crate) negative: BTreeSet<String>,
    pub(crate) has_positive: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RuleSetting {
    pub(crate) enabled: Option<bool>,
    pub(crate) threshold: Option<f64>,
    pub(crate) severity: Option<Severity>,
    pub(crate) string_array_options: HashMap<String, Vec<String>>,
    /// Layer-6.5 scoring opt-out (ADR-014). When `Some(true)`, the rule's
    /// findings are still surfaced in every reporter but skip the
    /// composite-score penalty contribution. Default and `Some(false)`
    /// behave identically (rule scores normally).
    pub(crate) exclude_from_score: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExclusionRule {
    pub(crate) selector: String,
    pub(crate) rule_ids: BTreeSet<String>,
    pub(crate) paths: Vec<String>,
    pub(crate) message_contains: Option<String>,
    pub(crate) reason: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CustomRule {
    pub(crate) id: String,
    pub(crate) pillar: Pillar,
    pub(crate) severity: Severity,
    pub(crate) confidence: Confidence,
    pub(crate) message: String,
    pub(crate) scope: CustomRuleScope,
    pub(crate) pattern: String,
    pub(crate) compiled_pattern: Regex,
    pub(crate) include_path_matchers: Vec<PathMatcher>,
    pub(crate) exclude_path_matchers: Vec<PathMatcher>,
    pub(crate) remediation: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PathMatcher {
    pattern: String,
    kind: PathMatcherKind,
}

#[derive(Debug, Clone)]
enum PathMatcherKind {
    TreePrefix(String),
    Prefix(String),
    Wildcard(Regex),
}

impl PathMatcher {
    pub(crate) fn new(pattern: &str) -> Self {
        let pattern = normalize_report_path(pattern);
        let kind = if let Some(prefix) = pattern
            .strip_suffix("/**")
            .filter(|prefix| !prefix.contains('*'))
        {
            PathMatcherKind::TreePrefix(prefix.to_string())
        } else if pattern.contains('*') {
            PathMatcherKind::Wildcard(wildcard_regex(&pattern))
        } else {
            PathMatcherKind::Prefix(pattern.trim_end_matches('/').to_string())
        };
        Self { pattern, kind }
    }

    /// The original glob this matcher was compiled from, reported as the
    /// `pattern` for `source: config` ignores and by `check-ignore`.
    pub(crate) fn pattern(&self) -> &str {
        &self.pattern
    }

    pub(crate) fn matches(&self, path: &str) -> bool {
        let path = normalize_report_path(path);
        if self.pattern == path {
            return true;
        }
        match &self.kind {
            PathMatcherKind::TreePrefix(prefix) => {
                path == *prefix || path.starts_with(&format!("{prefix}/"))
            }
            PathMatcherKind::Prefix(prefix) => {
                path == *prefix || path.starts_with(&format!("{prefix}/"))
            }
            PathMatcherKind::Wildcard(regex) => regex.is_match(&path),
        }
    }
}

pub(crate) fn compile_path_matchers(patterns: &[String]) -> Vec<PathMatcher> {
    patterns
        .iter()
        .map(|pattern| PathMatcher::new(pattern))
        .collect()
}

fn wildcard_regex(pattern: &str) -> Regex {
    let tree_suffix = pattern.ends_with("/**");
    let pattern = if tree_suffix {
        &pattern[..pattern.len() - 3]
    } else {
        pattern
    };
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '*' && chars.peek() == Some(&'*') {
            chars.next();
            if regex == "^" && chars.peek() == Some(&'/') {
                chars.next();
                regex.push_str("(?:.*/)?");
            } else {
                regex.push_str(".*");
            }
        } else if character == '*' {
            regex.push_str("[^/]*");
        } else {
            regex.push_str(&regex::escape(&character.to_string()));
        }
    }
    if tree_suffix {
        regex.push_str("(?:/.*)?");
    }
    regex.push('$');
    Regex::new(&regex).expect("generated path matcher regex compiles")
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListedRule {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) pillar: Pillar,
    pub(crate) tier: String,
    pub(crate) kind: String,
    pub(crate) default_severity: Severity,
    pub(crate) confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) threshold: Option<f64>,
    pub(crate) options: Vec<rules::OptionDefinition>,
    pub(crate) default_enabled: bool,
    pub(crate) description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) custom_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pattern: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustomRuleScope {
    Text,
    RustCode,
    Comments,
}

impl CustomRuleScope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::RustCode => "rust-code",
            Self::Comments => "comments",
        }
    }
}

impl Config {
    pub(crate) fn default() -> Self {
        Self {
            schema_version: String::new(),
            ignored_paths: Vec::new(),
            ignored_path_matchers: Vec::new(),
            accepted_abbreviations: DEFAULT_ABBREVIATIONS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            secret_previews: BTreeSet::new(),
            selectors: SelectorSet::default(),
            exclusions: Vec::new(),
            custom_rules: Vec::new(),
            rule_settings: HashMap::new(),
            minimum_severity: BTreeMap::new(),
        }
    }

    pub(crate) fn is_rule_enabled(&self, rule_id: &str) -> bool {
        if self.selectors.negative.contains(rule_id) {
            return false;
        }
        if self.selectors.has_positive && !self.selectors.positive.contains(rule_id) {
            return false;
        }
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.enabled)
            .unwrap_or(true)
    }

    /// Whether the rule's findings should skip the composite-score
    /// penalty contribution. The rule still runs and findings appear in
    /// every reporter; only `src/scoring.rs` consults this. See ADR-014.
    pub(crate) fn is_rule_excluded_from_score(&self, rule_id: &str) -> bool {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.exclude_from_score)
            .unwrap_or(false)
    }

    pub(crate) fn threshold(&self, rule_id: &str, default_value: f64) -> f64 {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.threshold)
            .unwrap_or(default_value)
    }

    pub(crate) fn severity(&self, rule_id: &str, default_severity: Severity) -> Severity {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.severity)
            .unwrap_or(default_severity)
    }

    /// Returns the configured string-array option value for a rule, or `&[]`
    /// when no option is set. Used by naming dispatchers to union built-in
    /// allowlists with user-provided typed options.
    pub(crate) fn string_array_option(&self, rule_id: &str, option: &str) -> &[String] {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.string_array_options.get(option))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}
