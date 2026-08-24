//! Hold resolved command options and analyser configuration for one run.
//!
//! The loader builds these values before discovery so CLI and report paths
//! share rule settings, path filters, selectors, and exit behavior.

use super::*;

mod deep_scan;

pub(crate) use deep_scan::{DeepScanBudget, DeepScanBudgetOverride};

// Universal-programming abbreviations that earn their place in source across nearly any codebase.
// Project-specific vocabulary (e.g. domain acronyms) should be appended to this list in the user's config.
pub(crate) const DEFAULT_ABBREVIATIONS: &[&str] = &[
    "age", "app", "db", "fs", "id", "io", "key", "log", "max", "min", "now", "raw", "rx", "tx",
    "ui", "url",
];

// The only accepted value for `.gruff-rs.yaml`'s required `schemaVersion:` field.
// Introduced by ADR-013; bumped only when the config schema breaks compatibility.
pub(crate) const SCHEMA_VERSION: &str = "gruff-rs.config.v1";

#[derive(Clone)]
/// Hold the command-line choices that shape one analysis run.
///
/// Empty paths mean the user selected the current directory, while optional files are absent when that feature was not requested.
/// The loader turns these choices into one resolved `Config` before scanning.
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
/// Describe the changed-code scope selected from the CLI.
///
/// Each variant keeps the user's source choice together with the requested symbol or hunk behavior.
/// No value means the command analyses the complete selected files.
pub(crate) enum DiffSelection {
    Patch { path: PathBuf, scope: ChangedScope },
    Git { mode: String, scope: ChangedScope },
    ExplicitRanges { ranges: String, scope: ChangedScope },
}

/// Hold the path and diff labels displayed in the HTML report masthead.
///
/// This renderer-only view reflects the user's command without changing the stable report envelope.
/// A missing diff label means the user requested a normal full-file analysis.
#[derive(Clone, Default, Debug)]
pub(crate) struct RequestedScope {
    pub(crate) paths: Vec<String>,
    pub(crate) diff_label: Option<String>,
}

impl RequestedScope {
    /// Convert command options into the paths and changed-code label shown in the report UI.
    /// Empty path input is displayed as `.` because that is the directory the user asked Gruff to scan.
    pub(crate) fn from_options(options: &AnalysisOptions) -> Self {
        // No explicit path means the user selected the current project directory.
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
            DiffSelection::Patch { path, .. } => format!("diff-patch · {}", path.display()),
            DiffSelection::Git { mode, .. } => format!("diff · {mode}"),
            DiffSelection::ExplicitRanges { ranges, .. } => format!("changed-ranges · {ranges}"),
        });
        Self { paths, diff_label }
    }
}

/// Resolved analyser settings shared by discovery, rules, scoring, and reports.
///
/// Users receive one consistent interpretation of config for the whole command.
/// Missing optional sections retain the registered defaults represented here.
#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) schema_version: String,
    pub(crate) ignored_paths: Vec<String>,
    pub(crate) ignored_path_matchers: Vec<PathMatcher>,
    pub(crate) accepted_abbreviations: BTreeSet<String>,
    pub(crate) selectors: SelectorSet,
    pub(crate) exclusions: Vec<ExclusionRule>,
    pub(crate) sensitive_exclusions: Vec<SensitiveExclusionRule>,
    pub(crate) custom_rules: Vec<CustomRule>,
    pub(crate) rule_settings: HashMap<String, RuleSetting>,
    pub(crate) minimum_severity: BTreeMap<String, FailThreshold>,
    pub(crate) gate: Option<Gate>,
    pub(crate) deep_scan_budget: DeepScanBudget,
}

#[derive(Debug, Clone, Default)]
/// Hold the inclusive and exclusive rule selectors resolved from user config.
///
/// Positive selectors narrow the scan, while negative selectors always remove matching rules.
/// Empty sets mean the registered default rule selection remains active.
pub(crate) struct SelectorSet {
    pub(crate) positive: BTreeSet<String>,
    pub(crate) negative: BTreeSet<String>,
    pub(crate) has_positive: bool,
}

#[derive(Debug, Clone, Default)]
/// Hold optional user overrides for one rule.
///
/// Missing fields retain that rule's catalogue defaults in analysis and reports.
/// Empty string-array options mean the user supplied no additional values.
pub(crate) struct RuleSetting {
    pub(crate) enabled: Option<bool>,
    pub(crate) threshold: Option<f64>,
    pub(crate) severity: Option<Severity>,
    pub(crate) string_array_options: HashMap<String, Vec<String>>,
    /// `Some(true)` keeps findings visible but removes their composite-score penalty.
    /// Missing and false values keep the normal scoring behavior defined by ADR-014.
    pub(crate) exclude_from_score: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Describe one user-configured exception to a set of rule findings.
///
/// Paths and optional message text narrow the exception before its reason is shown in report context.
/// An absent message filter means every matching message in the selected paths qualifies.
pub(crate) struct ExclusionRule {
    pub(crate) selector: String,
    pub(crate) rule_ids: BTreeSet<String>,
    pub(crate) paths: Vec<String>,
    pub(crate) message_contains: Option<String>,
    pub(crate) reason: String,
}

#[derive(Debug, Clone)]
/// Hold one custom regex rule loaded from the user's project config.
///
/// Compiled path and source matchers decide where the rule runs before findings enter the report.
/// Optional remediation is absent when the configured message already tells the user what to do.
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
/// Match a normalized report path against one user-configured ignore pattern.
///
/// The original pattern remains available for `check-ignore` explanations in the UI.
/// A compiled kind keeps repeated discovery checks deterministic and efficient.
pub(crate) struct PathMatcher {
    pattern: String,
    kind: PathMatcherKind,
}

#[derive(Debug, Clone)]
/// Represent the supported path-pattern behaviors after config compilation.
///
/// Tree and plain prefixes cover common project folders, while wildcard regexes cover explicit globs.
/// Users always see the original pattern rather than this internal representation.
enum PathMatcherKind {
    TreePrefix(String),
    Prefix(String),
    Wildcard(Regex),
}

impl PathMatcher {
    /// Compile one user path pattern into the matching behavior used during discovery.
    /// A blank or plain pattern becomes a prefix; `*` selects wildcard behavior and `/**` selects a whole tree.
    pub(crate) fn new(pattern: &str) -> Self {
        let pattern = normalize_report_path(pattern);
        // The pattern shape determines how the user's ignored path is matched during discovery.
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

    /// Return the original user pattern shown by `check-ignore` and config-sourced ignore explanations.
    pub(crate) fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Check whether one normalized report path is covered by this user pattern.
    pub(crate) fn matches(&self, path: &str) -> bool {
        let path = normalize_report_path(path);
        // An exact path match should always appear ignored, regardless of the compiled pattern kind.
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

/// Compile the user's configured ignore strings once for repeated discovery checks.
/// An empty list means no config-owned path matcher can hide a discovered file.
pub(crate) fn compile_path_matchers(patterns: &[String]) -> Vec<PathMatcher> {
    patterns
        .iter()
        .map(|pattern| PathMatcher::new(pattern))
        .collect()
}

/// Translate a user wildcard pattern into the anchored regex used for report paths.
/// The generated regex is internal; UI explanations keep showing the original config text.
fn wildcard_regex(pattern: &str) -> Regex {
    let tree_suffix = pattern.ends_with("/**");
    // A tree suffix is rendered separately so the base path itself and all descendants match.
    let pattern = if tree_suffix {
        &pattern[..pattern.len() - 3]
    } else {
        pattern
    };
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();
    // Each pattern character becomes either a path-aware wildcard or escaped literal text.
    while let Some(character) = chars.next() {
        // A double star may cross directory separators in the path the user selected.
        if character == '*' && chars.peek() == Some(&'*') {
            chars.next();
            // A leading `**/` also matches a file at the project root with no directory prefix.
            if regex == "^" && chars.peek() == Some(&'/') {
                chars.next();
                regex.push_str("(?:.*/)?");
            } else {
                regex.push_str(".*");
            }
        // A single star stays inside one path segment so it matches the user's glob expectation.
        } else if character == '*' {
            regex.push_str("[^/]*");
        } else {
            regex.push_str(&regex::escape(&character.to_string()));
        }
    }
    // `/**` includes both the configured folder and anything the user placed below it.
    if tree_suffix {
        regex.push_str("(?:/.*)?");
    }
    regex.push('$');
    Regex::new(&regex).expect("generated path matcher regex compiles")
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
/// Describe one built-in or custom rule in list-rules output.
///
/// Fields expose the stable ID, defaults, options, and guidance users need before enabling or configuring a rule.
/// Optional custom fields stay absent for built-in rules so the JSON UI remains concise.
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) false_positive_shapes: Vec<rules::FalsePositiveShape>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) custom_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pattern: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Select which source text a custom user rule may inspect.
///
/// Text scans the full file, Rust code excludes masked content, and comments targets comment text.
/// The stable string form is shown in config and rule-list output.
pub(crate) enum CustomRuleScope {
    Text,
    RustCode,
    Comments,
}

impl CustomRuleScope {
    /// Return the stable config label displayed for this custom-rule scope.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::RustCode => "rust-code",
            Self::Comments => "comments",
        }
    }
}

impl Config {
    /// Build the safe settings used when the user's project has no config overrides.
    pub(crate) fn default() -> Self {
        Self {
            // An empty version records that no schema-bearing user config has been applied.
            schema_version: String::new(),
            // Empty ignore collections mean config adds no discovery exclusions to built-in behavior.
            ignored_paths: Vec::new(),
            ignored_path_matchers: Vec::new(),
            accepted_abbreviations: DEFAULT_ABBREVIATIONS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            selectors: SelectorSet::default(),
            // Empty rule collections mean the user added no exclusions, custom rules, or per-rule overrides.
            exclusions: Vec::new(),
            sensitive_exclusions: Vec::new(),
            custom_rules: Vec::new(),
            rule_settings: HashMap::new(),
            minimum_severity: BTreeMap::new(),
            // No gate means findings are governed by the selected severity threshold rather than count caps.
            gate: None,
            deep_scan_budget: DeepScanBudget::default(),
        }
    }

    /// Decide whether one rule remains active after user selectors and per-rule overrides.
    /// Unknown rules default to enabled so custom and forward-compatible definitions are not silently lost.
    pub(crate) fn is_rule_enabled(&self, rule_id: &str) -> bool {
        // A negative selector is the user's strongest request to remove this rule from the run.
        if self.selectors.negative.contains(rule_id) {
            return false;
        }
        // When the user chose a positive subset, rules outside that subset stay out of the report.
        if self.selectors.has_positive && !self.selectors.positive.contains(rule_id) {
            return false;
        }
        // An explicit per-rule toggle overrides catalogue defaults and positive-selection fallback behavior.
        if let Some(enabled) = self
            .rule_settings
            .get(rule_id)
            .and_then(|setting| setting.enabled)
        {
            return enabled;
        }
        // A selected rule without an explicit toggle remains enabled for the user's requested subset.
        if self.selectors.has_positive {
            return true;
        }
        rules::builtin_registry_cached()
            .get(rule_id)
            .map(|definition| definition.default_enabled)
            .unwrap_or(true)
    }

    /// Return whether findings stay visible but stop reducing the user's composite score.
    /// Missing configuration means normal scoring, as defined by ADR-014.
    pub(crate) fn is_rule_excluded_from_score(&self, rule_id: &str) -> bool {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.exclude_from_score)
            .unwrap_or(false)
    }

    /// Return the user's threshold override or the catalogue default shown by `list-rules` and `init`.
    pub(crate) fn threshold(&self, rule_id: &str) -> f64 {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.threshold)
            .unwrap_or_else(|| rules::builtin_threshold(rule_id))
    }

    /// Return the user's severity override or the default already attached to the applicable rule or finding.
    pub(crate) fn severity(&self, rule_id: &str, default_severity: Severity) -> Severity {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.severity)
            .unwrap_or(default_severity)
    }

    /// Return a configured string-list option for a rule so built-in and user values can be combined.
    /// An empty slice means the user did not configure that option.
    pub(crate) fn string_array_option(&self, rule_id: &str, option: &str) -> &[String] {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.string_array_options.get(option))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}
