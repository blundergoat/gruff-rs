use super::*;

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
    pub(crate) ignored_paths: Vec<String>,
    pub(crate) accepted_abbreviations: BTreeSet<String>,
    pub(crate) secret_previews: BTreeSet<String>,
    pub(crate) selectors: SelectorSet,
    pub(crate) exclusions: Vec<ExclusionRule>,
    pub(crate) custom_rules: Vec<CustomRule>,
    pub(crate) rule_settings: HashMap<String, RuleSetting>,
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
    pub(crate) include_paths: Vec<String>,
    pub(crate) exclude_paths: Vec<String>,
    pub(crate) remediation: Option<String>,
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
            ignored_paths: Vec::new(),
            accepted_abbreviations: ["id", "db", "io", "ui", "tx", "rx"]
                .into_iter()
                .map(String::from)
                .collect(),
            secret_previews: BTreeSet::new(),
            selectors: SelectorSet::default(),
            exclusions: Vec::new(),
            custom_rules: Vec::new(),
            rule_settings: HashMap::new(),
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
    /// allowlists with user-provided extras (M37 typed options).
    pub(crate) fn string_array_option(&self, rule_id: &str, option: &str) -> &[String] {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.string_array_options.get(option))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}
