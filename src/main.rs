use chrono::Utc;
use clap::builder::styling;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use ignore::{DirEntry, WalkBuilder};
use proc_macro2::LineColumn;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, OnceLock};
use syn::spanned::Spanned;
use syn::{FnArg, ImplItem, Item, ReturnType, Type, Visibility};

mod html_report;
mod rules;
mod summary;

const VERSION: &str = "0.1.0-dev";
const DEFAULT_BASELINE: &str = "gruff-baseline.json";
const DEFAULT_CONFIG_FILES: &[&str] = &[".gruff-rs.yaml"];

fn static_regex(lock: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    lock.get_or_init(|| Regex::new(pattern).expect("static regex compiles"))
}

/// Symfony-Console-style colours for help output: yellow section headers,
/// green flag/command literals, dimmed placeholders. Matches the gruff-php
/// help layout users may be coming from.
const HELP_STYLES: styling::Styles = styling::Styles::styled()
    .header(
        styling::Style::new()
            .fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Yellow)))
            .bold(),
    )
    .usage(
        styling::Style::new()
            .fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Yellow)))
            .bold(),
    )
    .literal(styling::Style::new().fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Green))))
    .placeholder(styling::Style::new().dimmed())
    .error(
        styling::Style::new()
            .fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Red)))
            .bold(),
    )
    .valid(styling::Style::new().fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Green))))
    .invalid(
        styling::Style::new().fg_color(Some(styling::Color::Ansi(styling::AnsiColor::Yellow))),
    );

const HELP_TEMPLATE: &str = "\
{before-help}{name} {version}\n\n\
\x1b[1m\x1b[33mUsage:\x1b[0m\n  {usage}\n\n\
\x1b[1m\x1b[33mOptions:\x1b[0m\n{options}\n\n\
\x1b[1m\x1b[33mAvailable commands:\x1b[0m\n{subcommands}{after-help}";

const SUBCOMMAND_HELP_TEMPLATE: &str = "\
{before-help}\x1b[1m\x1b[33mDescription:\x1b[0m\n  {about}\n\n\
\x1b[1m\x1b[33mUsage:\x1b[0m\n  {usage}\n\n\
{all-args}{after-help}";

#[derive(Parser)]
#[command(
    name = "gruff-rs",
    version = VERSION,
    about = "Rust project quality analysis.",
    styles = HELP_STYLES,
    help_template = HELP_TEMPLATE,
    subcommand_help_heading = "Available commands",
    subcommand_value_name = "command",
    arg_required_else_help = true,
)]
struct Cli {
    #[command(flatten)]
    global: GlobalOptions,
    #[command(subcommand)]
    command: Commands,
}

// Symfony-Console-style global flags shared by every subcommand.
// `--silent` and `-q/--quiet` gate the primary stdout writer. `--ansi`/`--no-ansi`
// is reserved for the text renderer's future colour mode; today the text renderer
// emits no ANSI, so these flags accept and store but otherwise do not change
// output. `-v/-vv/-vvv` is a count flag the analyzer can opt into for stderr
// debug traces. `-n/--no-interaction` is accepted for parity and ignored;
// gruff-rs is non-interactive.
#[derive(Args, Clone, Debug, Default)]
struct GlobalOptions {
    /// Do not output any message.
    #[arg(long, global = true)]
    silent: bool,
    /// Only errors are displayed. All other output is suppressed.
    #[arg(short = 'q', long, global = true)]
    quiet: bool,
    /// Force ANSI output.
    #[arg(long, global = true, conflicts_with = "no_ansi")]
    ansi: bool,
    /// Disable ANSI output.
    #[arg(long = "no-ansi", global = true)]
    no_ansi: bool,
    /// Increase the verbosity of stderr messages (-v, -vv, -vvv).
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    /// Do not ask any interactive question (accepted for CLI parity; gruff-rs is non-interactive).
    #[arg(short = 'n', long, global = true)]
    no_interaction: bool,
}

impl GlobalOptions {
    fn writer(&self) -> OutputWriter {
        OutputWriter {
            silent: self.silent,
            quiet: self.quiet,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct OutputWriter {
    silent: bool,
    quiet: bool,
}

impl OutputWriter {
    fn emit(self, outcome: RunOutcome, body: &str) {
        if self.silent {
            return;
        }
        if self.quiet && !outcome.is_failure() {
            return;
        }
        println!("{body}");
    }

    /// Emit a body that is not gated by the success/failure outcome of an
    /// analysis run (e.g. completion scripts, list-rules output).
    fn emit_unconditional(self, body: &str) {
        if self.silent {
            return;
        }
        println!("{body}");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunOutcome {
    Success,
    ThresholdHit,
    DiagnosticsFailed,
}

impl RunOutcome {
    fn classify(report: &AnalysisReport, fail_on: FailThreshold) -> Self {
        if report.diagnostics.iter().any(RunDiagnostic::is_failure) {
            return Self::DiagnosticsFailed;
        }
        if report
            .findings
            .iter()
            .any(|finding| fail_on.triggered_by(finding.severity))
        {
            return Self::ThresholdHit;
        }
        Self::Success
    }

    fn exit_code(self) -> ExitCode {
        match self {
            Self::Success => ExitCode::SUCCESS,
            Self::ThresholdHit => ExitCode::from(1),
            Self::DiagnosticsFailed => ExitCode::from(2),
        }
    }

    fn is_failure(self) -> bool {
        !matches!(self, Self::Success)
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Run gruff analysis.
    Analyse(AnalyseArgs),
    /// Render a gruff report to stdout or a file.
    Report(ReportArgs),
    /// List gruff rule metadata.
    #[command(alias = "rules")]
    ListRules(ListRulesArgs),
    /// Serve the local gruff dashboard.
    Dashboard(DashboardArgs),
    /// Print a compact digest of a scan: per-pillar finding counts, top rules, and top file offenders.
    Summary(SummaryArgs),
    /// Dump the shell completion script.
    Completion(CompletionArgs),
}

#[derive(Args, Clone)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
struct AnalyseArgs {
    #[arg(value_name = "paths")]
    paths: Vec<PathBuf>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    no_config: bool,
    #[arg(long, default_value = "text")]
    format: OutputFormat,
    #[arg(long, default_value = "error")]
    fail_on: FailThreshold,
    #[arg(long)]
    include_ignored: bool,
    #[arg(long, value_name = "MODE", requires = "diff_git_unsafe")]
    diff: Option<String>,
    #[arg(long, value_name = "PATH", conflicts_with = "diff")]
    diff_patch: Option<PathBuf>,
    #[arg(long, requires = "diff")]
    diff_git_unsafe: bool,
    #[arg(long)]
    history_file: Option<PathBuf>,
    #[arg(long, num_args = 0..=1, default_missing_value = DEFAULT_BASELINE)]
    baseline: Option<PathBuf>,
    #[arg(long, num_args = 0..=1, default_missing_value = DEFAULT_BASELINE)]
    generate_baseline: Option<PathBuf>,
    #[arg(long)]
    no_baseline: bool,
}

#[derive(Args)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
struct ReportArgs {
    #[arg(value_name = "paths")]
    paths: Vec<PathBuf>,
    #[arg(long, default_value = "html")]
    format: ReportFormat,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    no_config: bool,
    #[arg(long, default_value = "none")]
    fail_on: FailThreshold,
    #[arg(long)]
    include_ignored: bool,
    #[arg(long)]
    no_baseline: bool,
}

#[derive(Args)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
struct DashboardArgs {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 8766)]
    port: u16,
    #[arg(long, default_value = ".")]
    project_root: PathBuf,
}

#[derive(Args)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
struct ListRulesArgs {
    #[arg(long, default_value = "text")]
    format: RuleListFormat,
    /// Preview the rules matched by one exact id, dotted prefix, or pillar selector.
    #[arg(long)]
    selector: Option<String>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    no_config: bool,
}

#[derive(Args, Clone)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
struct SummaryArgs {
    #[arg(value_name = "paths")]
    paths: Vec<PathBuf>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    no_config: bool,
    #[arg(long, default_value = "text")]
    format: SummaryFormat,
    /// How many top rules and file offenders to list.
    #[arg(long, default_value_t = 10)]
    top: usize,
    #[arg(long)]
    include_ignored: bool,
}

#[derive(Args, Clone)]
#[command(help_template = SUBCOMMAND_HELP_TEMPLATE)]
struct CompletionArgs {
    /// Shell to emit completions for.
    #[arg(long, default_value = "bash")]
    shell: Shell,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
    Html,
    Markdown,
    Github,
    Hotspot,
}

impl OutputFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Sarif => "sarif",
            Self::Html => "html",
            Self::Markdown => "markdown",
            Self::Github => "github",
            Self::Hotspot => "hotspot",
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SummaryFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReportFormat {
    Html,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RuleListFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
enum FailThreshold {
    None,
    Advisory,
    Warning,
    Error,
}

impl FailThreshold {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Advisory => "advisory",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    fn triggered_by(self, severity: Severity) -> bool {
        match self {
            Self::None => false,
            Self::Advisory => true,
            Self::Warning => severity == Severity::Warning || severity == Severity::Error,
            Self::Error => severity == Severity::Error,
        }
    }
}

#[derive(Clone)]
struct AnalysisOptions {
    paths: Vec<PathBuf>,
    config: Option<PathBuf>,
    no_config: bool,
    format: OutputFormat,
    fail_on: FailThreshold,
    include_ignored: bool,
    diff: Option<DiffSelection>,
    history_file: Option<PathBuf>,
    baseline: Option<PathBuf>,
    generate_baseline: Option<PathBuf>,
    no_baseline: bool,
}

#[derive(Clone, Debug)]
enum DiffSelection {
    Patch(PathBuf),
    GitUnsafe(String),
}

/// Renderer-only view of which paths and diff mode the user asked for.
///
/// This is intentionally not serialised onto `AnalysisReport`. The HTML
/// renderer uses it to populate the masthead "paths" and "scope" labels; other
/// renderers ignore it.
#[derive(Clone, Default, Debug)]
struct RequestedScope {
    paths: Vec<String>,
    diff_label: Option<String>,
}

impl RequestedScope {
    fn from_options(options: &AnalysisOptions) -> Self {
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
struct Config {
    ignored_paths: Vec<String>,
    accepted_abbreviations: BTreeSet<String>,
    secret_previews: BTreeSet<String>,
    selectors: SelectorSet,
    exclusions: Vec<ExclusionRule>,
    custom_rules: Vec<CustomRule>,
    rule_settings: HashMap<String, RuleSetting>,
}

#[derive(Debug, Clone, Default)]
struct SelectorSet {
    positive: BTreeSet<String>,
    negative: BTreeSet<String>,
    has_positive: bool,
}

#[derive(Debug, Clone, Default)]
struct RuleSetting {
    enabled: Option<bool>,
    threshold: Option<f64>,
    severity: Option<Severity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExclusionRule {
    selector: String,
    rule_ids: BTreeSet<String>,
    paths: Vec<String>,
    message_contains: Option<String>,
    reason: String,
}

#[derive(Debug, Clone)]
struct CustomRule {
    id: String,
    pillar: Pillar,
    severity: Severity,
    confidence: Confidence,
    message: String,
    scope: CustomRuleScope,
    pattern: String,
    compiled_pattern: Regex,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    remediation: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListedRule {
    id: String,
    name: String,
    pillar: Pillar,
    tier: String,
    kind: String,
    default_severity: Severity,
    confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold: Option<f64>,
    options: Vec<rules::OptionDefinition>,
    default_enabled: bool,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustomRuleScope {
    Text,
    RustCode,
    Comments,
}

impl CustomRuleScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::RustCode => "rust-code",
            Self::Comments => "comments",
        }
    }
}

impl Config {
    fn default() -> Self {
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

    fn rule_enabled(&self, rule_id: &str) -> bool {
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

    fn threshold(&self, rule_id: &str, default_value: f64) -> f64 {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.threshold)
            .unwrap_or(default_value)
    }

    fn severity(&self, rule_id: &str, default_severity: Severity) -> Severity {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.severity)
            .unwrap_or(default_severity)
    }
}

#[derive(Clone)]
struct SourceFile {
    absolute_path: PathBuf,
    display_path: String,
    is_rust: bool,
}

struct SourceUnit<'a> {
    file: &'a SourceFile,
    source: &'a str,
    rust_ast: Option<&'a syn::File>,
}

struct ParsedSource {
    file: SourceFile,
    source: String,
    rust_ast: Option<syn::File>,
    diagnostics: Vec<RunDiagnostic>,
}

impl ParsedSource {
    fn unit(&self) -> SourceUnit<'_> {
        SourceUnit {
            file: &self.file,
            source: &self.source,
            rust_ast: self.rust_ast.as_ref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectContext {
    root_path: PathBuf,
    manifest: Option<ManifestSummary>,
    lockfile: Option<LockfileSummary>,
    rust_sources: Vec<RustSourceSummary>,
    modules: Vec<ModuleSummary>,
    items: Vec<ItemSummary>,
    call_names: Vec<CallNameSummary>,
    diagnostics: Vec<RunDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestSummary {
    file_path: String,
    package_line: usize,
    package_name: Option<String>,
    package_description: Option<String>,
    package_license: Option<String>,
    dependencies: Vec<DependencySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DependencySummary {
    name: String,
    section: String,
    line: usize,
    requirement: Option<String>,
    path: Option<String>,
    git: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockfileSummary {
    file_path: String,
    packages: Vec<LockedPackageSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockedPackageSummary {
    name: String,
    version: String,
    line: usize,
    source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustSourceSummary {
    file_path: String,
    source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModuleSummary {
    file_path: String,
    module_path: String,
    line: usize,
    public: bool,
    inline: bool,
    cfg_gated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ItemSummary {
    file_path: String,
    module_path: String,
    name: String,
    kind: String,
    line: usize,
    public: bool,
    cfg_gated: bool,
    test_context: bool,
}

#[derive(Debug, Clone, Copy)]
struct ProjectItemContext {
    public: bool,
    cfg_gated: bool,
    test_context: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallNameSummary {
    file_path: String,
    name: String,
    line: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum Severity {
    Advisory,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum Pillar {
    Size,
    Complexity,
    DeadCode,
    Waste,
    Naming,
    Documentation,
    Modernisation,
    Security,
    SensitiveData,
    TestQuality,
    Design,
}

const SCORE_PILLARS: &[Pillar] = &[
    Pillar::Size,
    Pillar::Complexity,
    Pillar::DeadCode,
    Pillar::Waste,
    Pillar::Naming,
    Pillar::Documentation,
    Pillar::Modernisation,
    Pillar::Security,
    Pillar::SensitiveData,
    Pillar::TestQuality,
    Pillar::Design,
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Finding {
    rule_id: String,
    message: String,
    file_path: String,
    line: Option<usize>,
    end_line: Option<usize>,
    column: Option<usize>,
    severity: Severity,
    pillar: Pillar,
    secondary_pillars: Vec<Pillar>,
    tier: String,
    confidence: Confidence,
    symbol: Option<String>,
    remediation: Option<String>,
    metadata: Value,
    fingerprint: String,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    fn new(
        rule_id: &str,
        message: impl Into<String>,
        file_path: impl Into<String>,
        line: Option<usize>,
        severity: Severity,
        pillar: Pillar,
        confidence: Confidence,
        symbol: Option<String>,
        remediation: Option<String>,
        metadata: Value,
    ) -> Self {
        let file_path = file_path.into();
        let message = message.into();
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(file_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(line.unwrap_or_default().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(symbol.clone().unwrap_or_default().as_bytes());
        let fingerprint = format!("{:x}", hasher.finalize())[..16].to_string();

        Self {
            rule_id: rule_id.to_string(),
            message,
            file_path,
            line,
            end_line: None,
            column: None,
            severity,
            pillar,
            secondary_pillars: Vec::new(),
            tier: "v0.1".to_string(),
            confidence,
            symbol,
            remediation,
            metadata,
            fingerprint,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RunDiagnostic {
    diagnostic_type: String,
    message: String,
    file_path: Option<String>,
    line: Option<usize>,
}

impl RunDiagnostic {
    fn is_failure(&self) -> bool {
        matches!(
            self.diagnostic_type.as_str(),
            "missing-path"
                | "read-error"
                | "parse-error"
                | "manifest-read-error"
                | "manifest-parse-error"
                | "lockfile-read-error"
                | "lockfile-parse-error"
                | "history-error"
        )
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AnalysisReport {
    schema_version: String,
    tool: ToolInfo,
    run: RunInfo,
    summary: Summary,
    paths: PathSummary,
    diagnostics: Vec<RunDiagnostic>,
    suppressions: Vec<SuppressionSummary>,
    findings: Vec<Finding>,
    score: ScoreReport,
    baseline: Option<BaselineReport>,
    #[serde(skip)]
    suppressed_findings: Vec<SuppressedFinding>,
}

#[derive(Debug, Serialize)]
struct ToolInfo {
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunInfo {
    project_root: String,
    format: String,
    fail_on: String,
    generated_at: String,
}

#[derive(Debug, Serialize)]
struct Summary {
    advisory: usize,
    warning: usize,
    error: usize,
    total: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PathSummary {
    analysed_files: usize,
    ignored_paths: Vec<String>,
    missing_paths: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BaselineReport {
    path: String,
    source: String,
    suppressed: usize,
    generated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct SuppressionSummary {
    index: usize,
    rule: String,
    paths: Vec<String>,
    message_contains: Option<String>,
    reason: String,
    suppressed: usize,
}

#[derive(Debug, Clone)]
struct SuppressedFinding {
    finding: Finding,
    suppression: SuppressionSummary,
}

#[derive(Debug, Clone, Default)]
struct ReportSuppressions {
    summaries: Vec<SuppressionSummary>,
    suppressed_findings: Vec<SuppressedFinding>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScoreReport {
    composite: f64,
    grade: String,
    pillars: Vec<PillarScore>,
    top_offenders: Vec<FileScore>,
}

#[derive(Debug, Serialize)]
struct PillarScore {
    pillar: Pillar,
    score: f64,
    findings: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileScore {
    file_path: String,
    score: f64,
    findings: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BaselineData {
    schema_version: Option<String>,
    entries: Vec<BaselineEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BaselineEntry {
    fingerprint: String,
    rule_id: String,
    file_path: String,
    line: Option<usize>,
    symbol: Option<String>,
    message: String,
}

#[derive(Clone)]
struct FunctionBlock {
    name: String,
    param_count: usize,
    start_line: usize,
    line_count: usize,
    body: String,
    is_public: bool,
    is_test: bool,
    test_context: bool,
    is_async: bool,
    returns_bool: bool,
    ignore_without_reason: bool,
}

struct FunctionMetrics {
    total_tokens: usize,
    unique_tokens: usize,
    halstead_volume: f64,
    maintainability_score: f64,
}

impl FunctionBlock {
    fn is_test_context(&self) -> bool {
        self.is_test || self.test_context
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let global = cli.global.clone();
    let writer = global.writer();
    match cli.command {
        Commands::Analyse(args) => {
            let options = options_from_analyse(args);
            let scope = RequestedScope::from_options(&options);
            match run_analysis(&options) {
                Ok(report) => {
                    let outcome = RunOutcome::classify(&report, options.fail_on);
                    let rendered = render_report_with_scope(&report, &scope, options.format);
                    writer.emit(outcome, &rendered);
                    outcome.exit_code()
                }
                Err(error) => {
                    eprintln!("gruff-rs: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Commands::Report(args) => run_report(args, writer),
        Commands::ListRules(args) => run_list_rules(args, writer),
        Commands::Dashboard(args) => run_dashboard(args),
        Commands::Summary(args) => run_summary(args, writer),
        Commands::Completion(args) => run_completion(args, writer),
    }
}

fn options_from_analyse(args: AnalyseArgs) -> AnalysisOptions {
    let diff = match (args.diff_patch, args.diff) {
        (Some(path), None) => Some(DiffSelection::Patch(path)),
        (None, Some(mode)) => Some(DiffSelection::GitUnsafe(mode)),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap prevents --diff and --diff-patch together"),
    };
    AnalysisOptions {
        paths: args.paths,
        config: args.config,
        no_config: args.no_config,
        format: args.format,
        fail_on: args.fail_on,
        include_ignored: args.include_ignored,
        diff,
        history_file: args.history_file,
        baseline: args.baseline,
        generate_baseline: args.generate_baseline,
        no_baseline: args.no_baseline,
    }
}

fn run_report(args: ReportArgs, writer: OutputWriter) -> ExitCode {
    let format = match args.format {
        ReportFormat::Html => OutputFormat::Html,
        ReportFormat::Json => OutputFormat::Json,
    };
    let options = AnalysisOptions {
        paths: args.paths,
        config: args.config,
        no_config: args.no_config,
        format,
        fail_on: args.fail_on,
        include_ignored: args.include_ignored,
        diff: None,
        history_file: None,
        baseline: None,
        generate_baseline: None,
        no_baseline: args.no_baseline,
    };

    let scope = RequestedScope::from_options(&options);
    match run_analysis(&options) {
        Ok(report) => {
            let outcome = RunOutcome::classify(&report, args.fail_on);
            let rendered = render_report_with_scope(&report, &scope, format);
            if let Some(output) = args.output {
                if let Err(error) = fs::write(&output, rendered) {
                    eprintln!("gruff-rs: unable to write {}: {error}", output.display());
                    return ExitCode::from(2);
                }
            } else {
                writer.emit(outcome, &rendered);
            }
            outcome.exit_code()
        }
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            ExitCode::from(2)
        }
    }
}

fn run_list_rules(args: ListRulesArgs, writer: OutputWriter) -> ExitCode {
    let project_root = match std::env::current_dir() {
        Ok(project_root) => project_root,
        Err(error) => {
            eprintln!("gruff-rs: unable to resolve current directory: {error}");
            return ExitCode::from(2);
        }
    };
    let body = match render_rule_list(&project_root, &args) {
        Ok(body) => body,
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            return ExitCode::from(2);
        }
    };
    writer.emit_unconditional(&body);
    ExitCode::SUCCESS
}

fn render_rule_list(project_root: &Path, args: &ListRulesArgs) -> Result<String, String> {
    let registry = rules::builtin_registry();
    let config = list_rules_config(project_root, args)?;
    if let Some(selector) = &args.selector {
        let ids = expand_rule_selector_with_custom(
            selector,
            &registry,
            &config.custom_rules,
            "rules --selector",
        )?;
        return Ok(match args.format {
            RuleListFormat::Json => serde_json::to_string_pretty(&ids).expect("rules serialize"),
            RuleListFormat::Text => ids.into_iter().collect::<Vec<_>>().join("\n"),
        });
    }
    let rules = listed_rules(&registry, &config.custom_rules);
    Ok(match args.format {
        RuleListFormat::Json => serde_json::to_string_pretty(&rules).expect("rules serialize"),
        RuleListFormat::Text => {
            let mut out = String::new();
            for rule in rules {
                out.push_str(&format!(
                    "{} [{}] {:?} {:?} - {}\n",
                    rule.id, rule.tier, rule.pillar, rule.default_severity, rule.description
                ));
            }
            out.trim_end_matches('\n').to_string()
        }
    })
}

fn list_rules_config(project_root: &Path, args: &ListRulesArgs) -> Result<Config, String> {
    load_config(
        project_root,
        &AnalysisOptions {
            paths: Vec::new(),
            config: args.config.clone(),
            no_config: args.no_config,
            format: OutputFormat::Json,
            fail_on: FailThreshold::None,
            include_ignored: false,
            diff: None,
            history_file: None,
            baseline: None,
            generate_baseline: None,
            no_baseline: true,
        },
    )
}

fn listed_rules(registry: &rules::RuleRegistry, custom_rules: &[CustomRule]) -> Vec<ListedRule> {
    let mut listed: Vec<ListedRule> = registry
        .definitions()
        .iter()
        .map(listed_builtin_rule)
        .collect();
    listed.extend(custom_rules.iter().map(listed_custom_rule));
    listed
}

fn listed_builtin_rule(definition: &rules::RuleDefinition) -> ListedRule {
    ListedRule {
        id: definition.id.to_string(),
        name: definition.name.to_string(),
        pillar: definition.pillar,
        tier: definition.tier.to_string(),
        kind: rule_kind_name(definition.kind).to_string(),
        default_severity: definition.default_severity,
        confidence: definition.confidence,
        threshold: definition.threshold.map(|threshold| threshold.default),
        options: definition.options.to_vec(),
        default_enabled: definition.default_enabled,
        description: definition.description.to_string(),
        custom_scope: None,
        pattern: None,
    }
}

fn listed_custom_rule(rule: &CustomRule) -> ListedRule {
    ListedRule {
        id: rule.id.clone(),
        name: custom_rule_name(&rule.id),
        pillar: rule.pillar,
        tier: "v0.1".to_string(),
        kind: "custom".to_string(),
        default_severity: rule.severity,
        confidence: rule.confidence,
        threshold: None,
        options: Vec::new(),
        default_enabled: true,
        description: rule.message.clone(),
        custom_scope: Some(rule.scope.as_str().to_string()),
        pattern: Some(rule.pattern.clone()),
    }
}

fn rule_kind_name(kind: rules::RuleKind) -> &'static str {
    match kind {
        rules::RuleKind::Project => "project",
        rules::RuleKind::Text => "text",
        rules::RuleKind::Rust => "rust",
    }
}

fn custom_rule_name(rule_id: &str) -> String {
    rule_id
        .strip_prefix("custom.")
        .unwrap_or(rule_id)
        .split('-')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut word = first.to_ascii_uppercase().to_string();
                    word.push_str(chars.as_str());
                    word
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_summary(args: SummaryArgs, writer: OutputWriter) -> ExitCode {
    let options = AnalysisOptions {
        paths: args.paths,
        config: args.config,
        no_config: args.no_config,
        format: OutputFormat::Text,
        fail_on: FailThreshold::None,
        include_ignored: args.include_ignored,
        diff: None,
        history_file: None,
        baseline: None,
        generate_baseline: None,
        no_baseline: false,
    };

    match run_analysis(&options) {
        Ok(report) => {
            let outcome = RunOutcome::classify(&report, FailThreshold::None);
            let rendered = summary::render(&report, args.top, args.format);
            writer.emit(outcome, &rendered);
            outcome.exit_code()
        }
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            ExitCode::from(2)
        }
    }
}

fn run_completion(args: CompletionArgs, writer: OutputWriter) -> ExitCode {
    if writer.silent {
        return ExitCode::SUCCESS;
    }
    let mut command = Cli::command();
    let bin_name = command.get_name().to_string();
    clap_complete::generate(args.shell, &mut command, bin_name, &mut std::io::stdout());
    ExitCode::SUCCESS
}

fn run_analysis(options: &AnalysisOptions) -> Result<AnalysisReport, String> {
    let project_root = std::env::current_dir()
        .map_err(|error| format!("unable to resolve current directory: {error}"))?;
    run_analysis_in_project(&project_root, options)
}

fn missing_path_diagnostics(missing_paths: &[String]) -> Vec<RunDiagnostic> {
    missing_paths
        .iter()
        .map(|missing_path| RunDiagnostic {
            diagnostic_type: "missing-path".to_string(),
            message: format!("Input path does not exist: {missing_path}"),
            file_path: Some(missing_path.clone()),
            line: None,
        })
        .collect()
}

fn resolve_baseline(
    project_root: &Path,
    options: &AnalysisOptions,
    findings: &mut Vec<Finding>,
) -> Result<Option<BaselineReport>, String> {
    if let Some(path) = &options.generate_baseline {
        let baseline_path = absolutize(project_root, path);
        write_baseline(&baseline_path, findings)?;
        return Ok(Some(BaselineReport {
            path: display_path(project_root, &baseline_path),
            source: "generated".to_string(),
            suppressed: 0,
            generated: true,
        }));
    }
    if options.no_baseline {
        return Ok(None);
    }
    let selected = options
        .baseline
        .as_ref()
        .map(|path| (absolutize(project_root, path), "explicit"))
        .or_else(|| {
            let default = project_root.join(DEFAULT_BASELINE);
            default.exists().then_some((default, "default"))
        });
    let Some((baseline_path, source)) = selected else {
        return Ok(None);
    };
    let before = findings.len();
    apply_baseline(&baseline_path, findings)?;
    Ok(Some(BaselineReport {
        path: display_path(project_root, &baseline_path),
        source: source.to_string(),
        suppressed: before.saturating_sub(findings.len()),
        generated: false,
    }))
}

fn sort_and_dedupe_findings(findings: &mut Vec<Finding>) {
    findings.sort_by(|left, right| {
        (
            left.file_path.as_str(),
            left.line.unwrap_or_default(),
            left.rule_id.as_str(),
            left.message.as_str(),
        )
            .cmp(&(
                right.file_path.as_str(),
                right.line.unwrap_or_default(),
                right.rule_id.as_str(),
                right.message.as_str(),
            ))
    });
    findings.dedup_by(|left, right| left.fingerprint == right.fingerprint);
}

fn apply_report_exclusions(
    findings: Vec<Finding>,
    exclusions: &[ExclusionRule],
) -> (
    Vec<Finding>,
    Vec<SuppressionSummary>,
    Vec<SuppressedFinding>,
) {
    if exclusions.is_empty() {
        return (findings, Vec::new(), Vec::new());
    }

    let mut summaries: Vec<SuppressionSummary> = exclusions
        .iter()
        .enumerate()
        .map(|(index, exclusion)| SuppressionSummary {
            index,
            rule: exclusion.selector.clone(),
            paths: exclusion.paths.clone(),
            message_contains: exclusion.message_contains.clone(),
            reason: exclusion.reason.clone(),
            suppressed: 0,
        })
        .collect();
    let mut kept = Vec::new();
    let mut suppressed = Vec::new();

    for finding in findings {
        if let Some(index) = exclusions
            .iter()
            .position(|exclusion| exclusion_matches_finding(exclusion, &finding))
        {
            summaries[index].suppressed += 1;
            suppressed.push(SuppressedFinding {
                finding,
                suppression: summaries[index].clone(),
            });
        } else {
            kept.push(finding);
        }
    }

    (kept, summaries, suppressed)
}

fn exclusion_matches_finding(exclusion: &ExclusionRule, finding: &Finding) -> bool {
    if !exclusion.rule_ids.contains(&finding.rule_id) {
        return false;
    }
    if !exclusion.paths.is_empty() {
        let file_path = normalize_report_path(&finding.file_path);
        if !exclusion
            .paths
            .iter()
            .any(|pattern| path_matches(pattern, &file_path))
        {
            return false;
        }
    }
    exclusion
        .message_contains
        .as_ref()
        .is_none_or(|message| finding.message.contains(message))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct DiffPatchLineMap {
    lines_by_file: BTreeMap<String, BTreeSet<usize>>,
}

impl DiffPatchLineMap {
    fn changed_files(&self) -> BTreeSet<String> {
        self.lines_by_file.keys().cloned().collect()
    }
}

fn read_diff_patch(project_root: &Path, path: &Path) -> Result<String, String> {
    if path == Path::new("-") {
        let mut patch = String::new();
        std::io::stdin()
            .read_to_string(&mut patch)
            .map_err(|error| format!("unable to read --diff-patch from stdin: {error}"))?;
        return Ok(patch);
    }
    let patch_path = absolutize(project_root, path);
    fs::read_to_string(&patch_path)
        .map_err(|error| format!("unable to read --diff-patch {}: {error}", path.display()))
}

#[derive(Default)]
struct DiffPatchState {
    current_file: Option<String>,
    current_new_line: Option<usize>,
}

enum DiffHunkLineKind {
    NewSide,
    OldSideOnly,
    NoNewlineMarker,
    OutsideHunk,
}

fn parse_unified_diff(patch: &str) -> DiffPatchLineMap {
    let mut line_map = DiffPatchLineMap::default();
    let mut state = DiffPatchState::default();

    for raw_line in patch.lines() {
        let line = raw_line.trim_end_matches('\r');
        if should_handle_diff_header(line, &mut state, &mut line_map) {
            continue;
        }
        record_diff_hunk_line(line, &mut state, &mut line_map);
    }

    line_map
}

fn should_handle_diff_header(
    line: &str,
    state: &mut DiffPatchState,
    line_map: &mut DiffPatchLineMap,
) -> bool {
    if let Some(path) = line.strip_prefix("+++ ") {
        state.current_file = parse_diff_path(path);
        state.current_new_line = None;
        ensure_diff_file_entry(line_map, &state.current_file);
        return true;
    }

    if line.starts_with("diff --git ")
        || line.starts_with("Binary files ")
        || line == "GIT binary patch"
    {
        state.current_new_line = None;
        return true;
    }

    if line.starts_with("@@") {
        state.current_new_line = parse_hunk_new_start(line);
        ensure_diff_file_entry(line_map, &state.current_file);
        return true;
    }

    false
}

fn ensure_diff_file_entry(line_map: &mut DiffPatchLineMap, current_file: &Option<String>) {
    if let Some(file) = current_file {
        line_map.lines_by_file.entry(file.clone()).or_default();
    }
}

fn record_diff_hunk_line(line: &str, state: &mut DiffPatchState, line_map: &mut DiffPatchLineMap) {
    let Some(new_line) = state.current_new_line.as_mut() else {
        return;
    };
    let Some(file) = &state.current_file else {
        return;
    };

    match diff_hunk_line_kind(line) {
        DiffHunkLineKind::NewSide => {
            line_map
                .lines_by_file
                .entry(file.clone())
                .or_default()
                .insert(*new_line);
            *new_line += 1;
        }
        DiffHunkLineKind::OldSideOnly | DiffHunkLineKind::NoNewlineMarker => {}
        DiffHunkLineKind::OutsideHunk => state.current_new_line = None,
    }
}

fn diff_hunk_line_kind(line: &str) -> DiffHunkLineKind {
    if line.starts_with('\\') {
        DiffHunkLineKind::NoNewlineMarker
    } else if line.starts_with('-') {
        DiffHunkLineKind::OldSideOnly
    } else if line.starts_with('+') || line.starts_with(' ') {
        DiffHunkLineKind::NewSide
    } else {
        DiffHunkLineKind::OutsideHunk
    }
}

fn parse_diff_path(raw_path: &str) -> Option<String> {
    let path = raw_path
        .split_once('\t')
        .map(|(path, _)| path)
        .unwrap_or(raw_path)
        .trim();
    if path == "/dev/null" {
        return None;
    }
    let unprefixed = path
        .strip_prefix("b/")
        .or_else(|| path.strip_prefix("a/"))
        .unwrap_or(path);
    let normalized = normalize_report_path(unprefixed);
    (!normalized.is_empty()).then_some(normalized)
}

fn parse_hunk_new_start(line: &str) -> Option<usize> {
    let plus = line.find('+')?;
    let rest = &line[plus + 1..];
    let digits: String = rest
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    let start = digits.parse::<usize>().ok()?;
    Some(start.max(1))
}

fn normalize_report_path(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

fn apply_diff_patch_filter(
    mut report: AnalysisReport,
    patch: &DiffPatchLineMap,
    analysed_files: &BTreeSet<String>,
) -> AnalysisReport {
    let total_findings = report.findings.len();
    let changed_files = patch.changed_files();
    let missing_files: Vec<String> = changed_files
        .iter()
        .filter(|file| !analysed_files.contains(*file))
        .cloned()
        .collect();
    let mut kept = Vec::new();

    for finding in std::mem::take(&mut report.findings) {
        if diff_patch_keeps_finding(&finding, patch, &changed_files) {
            kept.push(finding);
        }
    }
    report
        .suppressed_findings
        .retain(|suppressed| diff_patch_keeps_finding(&suppressed.finding, patch, &changed_files));
    recount_suppressions(&mut report.suppressions, &report.suppressed_findings);

    let kept_findings = kept.len();
    let suppressed_findings = total_findings.saturating_sub(kept_findings);
    report.findings = kept;
    report.summary = summarize(&report.findings);
    report.score = score_report(&report.findings);
    report.diagnostics.push(RunDiagnostic {
        diagnostic_type: "patch-filter".to_string(),
        message: patch_filter_message(
            total_findings,
            kept_findings,
            suppressed_findings,
            &missing_files,
        ),
        file_path: None,
        line: None,
    });
    report
}

fn recount_suppressions(
    summaries: &mut [SuppressionSummary],
    suppressed_findings: &[SuppressedFinding],
) {
    for summary in summaries.iter_mut() {
        summary.suppressed = 0;
    }
    for suppressed in suppressed_findings {
        if let Some(summary) = summaries.get_mut(suppressed.suppression.index) {
            summary.suppressed += 1;
        }
    }
}

fn diff_patch_keeps_finding(
    finding: &Finding,
    patch: &DiffPatchLineMap,
    changed_files: &BTreeSet<String>,
) -> bool {
    let file_path = normalize_report_path(&finding.file_path);
    if !changed_files.contains(&file_path) {
        return false;
    }
    let Some(line) = finding.line else {
        return true;
    };
    patch
        .lines_by_file
        .get(&file_path)
        .is_some_and(|lines| lines.contains(&line))
}

fn patch_filter_message(
    total_findings: usize,
    kept_findings: usize,
    suppressed_findings: usize,
    missing_files: &[String],
) -> String {
    let mut message = format!(
        "Patch filter kept {kept_findings} of {total_findings} findings; suppressed {suppressed_findings} outside changed new-side lines."
    );
    if missing_files.is_empty() {
        message.push_str(" All patch files were analysed.");
    } else {
        message.push_str(&format!(
            " Patch files not analysed: {}.",
            missing_files.join(", ")
        ));
    }
    message
}

fn run_analysis_in_project(
    project_root: &Path,
    options: &AnalysisOptions,
) -> Result<AnalysisReport, String> {
    let config = load_config(project_root, options)?;
    let mut discovery = discover_sources(project_root, options, &config);
    let mut diagnostics = missing_path_diagnostics(&discovery.missing_paths);
    apply_git_diff_selection(options, &mut discovery, &mut diagnostics)?;
    let analysed_paths = analysed_display_paths(&discovery.files);
    let mut findings =
        analyse_discovered_sources(project_root, &discovery.files, &config, &mut diagnostics);
    let baseline_report = resolve_baseline(project_root, options, &mut findings)?;
    sort_and_dedupe_findings(&mut findings);
    let (findings, summaries, suppressed_findings) =
        apply_report_exclusions(findings, &config.exclusions);
    let suppressions = ReportSuppressions {
        summaries,
        suppressed_findings,
    };
    let report = build_report(
        project_root,
        options,
        discovery,
        diagnostics,
        findings,
        baseline_report,
        suppressions,
    );
    let mut report = apply_diff_selection(project_root, options, report, &analysed_paths)?;
    record_history_if_requested(project_root, options, &mut report);
    Ok(report)
}

fn apply_git_diff_selection(
    options: &AnalysisOptions,
    discovery: &mut DiscoveryResult,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Result<(), String> {
    let Some(DiffSelection::GitUnsafe(mode)) = &options.diff else {
        return Ok(());
    };

    let changed = changed_files(mode)?;
    discovery
        .files
        .retain(|file| changed.contains(&file.display_path));
    diagnostics.push(RunDiagnostic {
        diagnostic_type: "diff-git-unsafe".to_string(),
        message: format!(
            "Unsafe Git diff mode `{mode}` executed `git diff --name-only`; use --diff-patch for no-execute filtering."
        ),
        file_path: None,
        line: None,
    });

    Ok(())
}

fn analysed_display_paths(files: &[SourceFile]) -> BTreeSet<String> {
    files.iter().map(|file| file.display_path.clone()).collect()
}

fn analyse_discovered_sources(
    project_root: &Path,
    files: &[SourceFile],
    config: &Config,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Vec<Finding> {
    let (parsed_sources, read_diagnostics) = read_and_parse_sources(files);
    diagnostics.extend(read_diagnostics);

    let project_context = build_project_context(project_root, &parsed_sources);
    diagnostics.extend(project_context.diagnostics.iter().cloned());

    let mut findings = analyse_project(&project_context, config);
    for parsed_source in &parsed_sources {
        findings.extend(analyse_source(&parsed_source.unit(), config));
        diagnostics.extend(parsed_source.diagnostics.iter().cloned());
    }
    findings
}

fn apply_diff_selection(
    project_root: &Path,
    options: &AnalysisOptions,
    report: AnalysisReport,
    analysed_paths: &BTreeSet<String>,
) -> Result<AnalysisReport, String> {
    let Some(DiffSelection::Patch(path)) = &options.diff else {
        return Ok(report);
    };

    let patch_text = read_diff_patch(project_root, path)?;
    let patch = parse_unified_diff(&patch_text);
    Ok(apply_diff_patch_filter(report, &patch, analysed_paths))
}

fn record_history_if_requested(
    project_root: &Path,
    options: &AnalysisOptions,
    report: &mut AnalysisReport,
) {
    if let Some(history_file) = &options.history_file {
        record_history(
            project_root,
            history_file,
            &report.findings,
            &mut report.diagnostics,
        );
    }
}

fn build_report(
    project_root: &Path,
    options: &AnalysisOptions,
    discovery: DiscoveryResult,
    diagnostics: Vec<RunDiagnostic>,
    findings: Vec<Finding>,
    baseline_report: Option<BaselineReport>,
    suppressions: ReportSuppressions,
) -> AnalysisReport {
    let summary = summarize(&findings);
    let score = score_report(&findings);
    AnalysisReport {
        schema_version: "gruff.analysis.v1".to_string(),
        tool: ToolInfo {
            name: "gruff-rs".to_string(),
            version: VERSION.to_string(),
        },
        run: RunInfo {
            project_root: project_root.display().to_string(),
            format: options.format.as_str().to_string(),
            fail_on: options.fail_on.as_str().to_string(),
            generated_at: Utc::now().to_rfc3339(),
        },
        summary,
        paths: PathSummary {
            analysed_files: discovery.files.len(),
            ignored_paths: discovery.ignored_paths,
            missing_paths: discovery.missing_paths,
        },
        diagnostics,
        suppressions: suppressions.summaries,
        findings,
        score,
        baseline: baseline_report,
        suppressed_findings: suppressions.suppressed_findings,
    }
}

struct DiscoveryResult {
    files: Vec<SourceFile>,
    missing_paths: Vec<String>,
    ignored_paths: Vec<String>,
}

fn discover_sources(
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

fn collect_directory_sources(
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

fn should_descend(
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

fn should_include_file(
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

fn record_ignored_path(ignored_paths: &Mutex<BTreeSet<String>>, path: String) {
    ignored_paths
        .lock()
        .expect("ignored paths lock")
        .insert(path);
}

fn path_is_project_ignored(project_root: &Path, path: &Path, config: &Config) -> bool {
    let relative = display_path(project_root, path);
    config
        .ignored_paths
        .iter()
        .any(|pattern| path_matches(pattern, &relative))
}

fn is_default_ignored_dir(relative: &str) -> bool {
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

fn is_vcs_internal_dir(relative: &str) -> bool {
    relative
        .split('/')
        .any(|component| matches!(component, ".git" | ".hg" | ".svn"))
}

fn push_source_file(project_root: &Path, path: &Path, files: &mut Vec<SourceFile>) {
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

fn load_config(project_root: &Path, options: &AnalysisOptions) -> Result<Config, String> {
    let mut config = Config::default();
    if options.no_config {
        return Ok(config);
    }

    let Some((path, value)) = read_config_value(project_root, options)? else {
        return Ok(config);
    };
    apply_config_value(&path, &value, &mut config)?;
    Ok(config)
}

fn read_config_value(
    project_root: &Path,
    options: &AnalysisOptions,
) -> Result<Option<(PathBuf, Value)>, String> {
    let config_path = options
        .config
        .as_ref()
        .map(|path| absolutize(project_root, path))
        .or_else(|| default_config_path(project_root));
    let Some(path) = config_path else {
        return Ok(None);
    };

    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("unable to read config {}: {error}", path.display()))?;
    Ok(Some((path.clone(), parse_config_value(&path, &raw)?)))
}

fn apply_config_value(path: &Path, value: &Value, config: &mut Config) -> Result<(), String> {
    let root = value
        .as_object()
        .ok_or_else(|| format!("config {} must be a JSON object", path.display()))?;
    reject_unknown_keys(
        root,
        &["paths", "allowlists", "rules", "exclude", "custom_rules"],
        "config root",
    )?;

    if let Some(paths_value) = root.get("paths") {
        apply_paths_section(paths_value, config)?;
    }
    if let Some(allowlists_value) = root.get("allowlists") {
        apply_allowlists_section(allowlists_value, config)?;
    }
    if let Some(custom_rules_value) = root.get("custom_rules") {
        apply_custom_rules_section(custom_rules_value, config)?;
    }
    if let Some(rules_value) = root.get("rules") {
        apply_rules_section(rules_value, config)?;
    }
    if let Some(exclude_value) = root.get("exclude") {
        apply_exclusions_section(exclude_value, config)?;
    }
    Ok(())
}

fn apply_paths_section(paths_value: &Value, config: &mut Config) -> Result<(), String> {
    let paths = paths_value
        .as_object()
        .ok_or_else(|| "config key `paths` must be an object".to_string())?;
    reject_unknown_keys(paths, &["ignore"], "config key `paths`")?;
    if let Some(ignore) = paths.get("ignore") {
        config.ignored_paths = string_array(ignore, "paths.ignore")?;
    }
    Ok(())
}

fn apply_allowlists_section(allowlists_value: &Value, config: &mut Config) -> Result<(), String> {
    let allowlists = allowlists_value
        .as_object()
        .ok_or_else(|| "config key `allowlists` must be an object".to_string())?;
    reject_unknown_keys(
        allowlists,
        &["acceptedAbbreviations", "secretPreviews"],
        "config key `allowlists`",
    )?;
    if let Some(abbreviations) = allowlists.get("acceptedAbbreviations") {
        config.accepted_abbreviations =
            string_array(abbreviations, "allowlists.acceptedAbbreviations")?
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect();
    }
    if let Some(previews) = allowlists.get("secretPreviews") {
        config.secret_previews = string_array(previews, "allowlists.secretPreviews")?
            .into_iter()
            .collect();
    }
    Ok(())
}

fn apply_rules_section(rules_value: &Value, config: &mut Config) -> Result<(), String> {
    let registry = rules::builtin_registry();
    let rules = rules_value
        .as_object()
        .ok_or_else(|| "config key `rules` must be an object".to_string())?;

    apply_selector_settings(
        rules,
        &registry,
        &config.custom_rules,
        &mut config.selectors,
    )?;
    apply_custom_rule_settings(
        rules,
        &registry,
        &config.custom_rules,
        &mut config.rule_settings,
    )?;
    for (key, rule_value) in rules {
        if matches!(key.as_str(), "select" | "ignore" | "custom") {
            continue;
        }
        insert_rule_setting(
            key,
            rule_value,
            &registry,
            &config.custom_rules,
            &mut config.rule_settings,
            "rules",
        )?;
    }
    Ok(())
}

fn apply_custom_rules_section(
    custom_rules_value: &Value,
    config: &mut Config,
) -> Result<(), String> {
    let registry = rules::builtin_registry();
    let entries = custom_rules_value
        .as_array()
        .ok_or_else(|| "config key `custom_rules` must be an array".to_string())?;
    let mut custom_rules = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, entry_value) in entries.iter().enumerate() {
        let custom_rule = parse_custom_rule(index, entry_value, &registry)?;
        if !seen.insert(custom_rule.id.clone()) {
            return Err(format!(
                "duplicate custom rule id `{}` in config key `custom_rules[{index}].id`",
                custom_rule.id
            ));
        }
        custom_rules.push(custom_rule);
    }
    custom_rules.sort_by(|left, right| left.id.cmp(&right.id));
    config.custom_rules = custom_rules;
    Ok(())
}

fn parse_custom_rule(
    index: usize,
    entry_value: &Value,
    registry: &rules::RuleRegistry,
) -> Result<CustomRule, String> {
    let entry_path = format!("custom_rules[{index}]");
    let entry = entry_value
        .as_object()
        .ok_or_else(|| format!("config key `{entry_path}` must be an object"))?;
    reject_unknown_keys(
        entry,
        &[
            "id",
            "pillar",
            "severity",
            "confidence",
            "message",
            "scope",
            "pattern",
            "include_paths",
            "exclude_paths",
            "remediation",
        ],
        &format!("config key `{entry_path}`"),
    )?;

    let id = required_config_string(entry, "id", &format!("{entry_path}.id"))?;
    validate_custom_rule_id(&id, &format!("{entry_path}.id"), registry)?;
    let pillar = parse_required_pillar(entry, "pillar", &format!("{entry_path}.pillar"))?;
    let severity = parse_required_severity(entry, "severity", &format!("{entry_path}.severity"))?;
    let confidence = entry
        .get("confidence")
        .map(|value| parse_custom_confidence(value, &format!("{entry_path}.confidence")))
        .transpose()?
        .unwrap_or(Confidence::Medium);
    let message = required_non_empty_config_string(entry, "message", &entry_path)?;
    let scope = parse_custom_rule_scope(
        &required_config_string(entry, "scope", &format!("{entry_path}.scope"))?,
        &format!("{entry_path}.scope"),
    )?;
    let pattern = required_non_empty_config_string(entry, "pattern", &entry_path)?;
    let compiled_pattern = Regex::new(&pattern).map_err(|error| {
        format!("config key `{entry_path}.pattern` failed to compile regex: {error}")
    })?;
    let include_paths = optional_normalized_string_array(
        entry,
        "include_paths",
        &format!("{entry_path}.include_paths"),
    )?;
    let exclude_paths = optional_normalized_string_array(
        entry,
        "exclude_paths",
        &format!("{entry_path}.exclude_paths"),
    )?;
    let remediation = entry
        .get("remediation")
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("config key `{entry_path}.remediation` must be a string"))
        })
        .transpose()?;

    Ok(CustomRule {
        id,
        pillar,
        severity,
        confidence,
        message,
        scope,
        pattern,
        compiled_pattern,
        include_paths,
        exclude_paths,
        remediation,
    })
}

fn validate_custom_rule_id(
    id: &str,
    path: &str,
    registry: &rules::RuleRegistry,
) -> Result<(), String> {
    let Some(slug) = id.strip_prefix("custom.") else {
        return Err(format!(
            "config key `{path}` must start with the reserved `custom.` namespace"
        ));
    };
    if slug.is_empty()
        || slug.starts_with('-')
        || slug.ends_with('-')
        || !slug.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    {
        return Err(format!(
            "config key `{path}` must use `custom.<slug>` with lowercase ASCII letters, digits, and hyphens"
        ));
    }
    if registry.contains(id) {
        return Err(format!(
            "config key `{path}` collides with built-in rule id `{id}`"
        ));
    }
    Ok(())
}

fn parse_required_pillar(
    object: &serde_json::Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Pillar, String> {
    let pillar = required_config_string(object, key, path)?;
    parse_pillar_selector(&pillar).ok_or_else(|| {
        format!(
            "unknown pillar `{pillar}` in `{path}`; expected a public pillar such as Documentation"
        )
    })
}

fn parse_required_severity(
    object: &serde_json::Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Severity, String> {
    let severity = required_config_string(object, key, path)?;
    parse_severity_name(&severity).ok_or_else(|| {
        format!("unknown severity `{severity}` in `{path}`; expected advisory, warning, or error")
    })
}

fn parse_severity_name(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "advisory" => Some(Severity::Advisory),
        "warning" => Some(Severity::Warning),
        "error" => Some(Severity::Error),
        _ => None,
    }
}

fn parse_custom_confidence(value: &Value, path: &str) -> Result<Confidence, String> {
    let number = value
        .as_f64()
        .ok_or_else(|| format!("config key `{path}` must be a number from 0.0 to 1.0"))?;
    if !(0.0..=1.0).contains(&number) {
        return Err(format!("config key `{path}` must be between 0.0 and 1.0"));
    }
    if number >= 0.85 {
        Ok(Confidence::High)
    } else if number >= 0.5 {
        Ok(Confidence::Medium)
    } else {
        Ok(Confidence::Low)
    }
}

fn parse_custom_rule_scope(value: &str, path: &str) -> Result<CustomRuleScope, String> {
    match value.trim() {
        "text" => Ok(CustomRuleScope::Text),
        "rust-code" => Ok(CustomRuleScope::RustCode),
        "comments" => Ok(CustomRuleScope::Comments),
        other => Err(format!(
            "unknown custom rule scope `{other}` in `{path}`; expected text, rust-code, or comments"
        )),
    }
}

fn optional_normalized_string_array(
    object: &serde_json::Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Vec<String>, String> {
    object
        .get(key)
        .map(|value| {
            string_array(value, path).map(|paths| {
                paths
                    .into_iter()
                    .map(|path| normalize_report_path(&path))
                    .collect()
            })
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn apply_exclusions_section(exclude_value: &Value, config: &mut Config) -> Result<(), String> {
    let registry = rules::builtin_registry();
    let entries = exclude_value
        .as_array()
        .ok_or_else(|| "config key `exclude` must be an array".to_string())?;
    let mut exclusions = Vec::new();
    for (index, entry_value) in entries.iter().enumerate() {
        exclusions.push(parse_exclusion_rule(
            index,
            entry_value,
            &registry,
            &config.custom_rules,
        )?);
    }
    config.exclusions = exclusions;
    Ok(())
}

fn parse_exclusion_rule(
    index: usize,
    entry_value: &Value,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
) -> Result<ExclusionRule, String> {
    let entry_path = format!("exclude[{index}]");
    let entry = entry_value
        .as_object()
        .ok_or_else(|| format!("config key `{entry_path}` must be an object"))?;
    reject_unknown_keys(
        entry,
        &["rule", "paths", "message_contains", "reason"],
        &format!("config key `{entry_path}`"),
    )?;

    let selector = required_config_string(entry, "rule", &format!("{entry_path}.rule"))?;
    let rule_ids = expand_rule_selector_with_custom(
        &selector,
        registry,
        custom_rules,
        &format!("{entry_path}.rule"),
    )?;
    let paths = entry
        .get("paths")
        .map(|value| {
            string_array(value, &format!("{entry_path}.paths")).map(|paths| {
                paths
                    .into_iter()
                    .map(|path| normalize_report_path(&path))
                    .collect()
            })
        })
        .transpose()?
        .unwrap_or_default();
    let message_contains = entry
        .get("message_contains")
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                format!("config key `{entry_path}.message_contains` must be a string")
            })
        })
        .transpose()?;
    let reason = required_config_string(entry, "reason", &format!("{entry_path}.reason"))?;
    if reason.trim().is_empty() {
        return Err(format!(
            "config key `{entry_path}.reason` must be a non-empty string"
        ));
    }
    if message_contains
        .as_deref()
        .is_some_and(|message| message.is_empty())
    {
        return Err(format!(
            "config key `{entry_path}.message_contains` must be a non-empty string"
        ));
    }

    Ok(ExclusionRule {
        selector,
        rule_ids,
        paths,
        message_contains,
        reason,
    })
}

fn required_non_empty_config_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    entry_path: &str,
) -> Result<String, String> {
    let path = format!("{entry_path}.{key}");
    let value = required_config_string(object, key, &path)?;
    if value.trim().is_empty() {
        return Err(format!("config key `{path}` must be a non-empty string"));
    }
    Ok(value)
}

fn required_config_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<String, String> {
    object
        .get(key)
        .ok_or_else(|| format!("missing required config key `{path}`"))?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("config key `{path}` must be a string"))
}

fn apply_selector_settings(
    rules: &serde_json::Map<String, Value>,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    selectors: &mut SelectorSet,
) -> Result<(), String> {
    if let Some(select_value) = rules.get("select") {
        selectors.positive =
            expand_rule_selectors(select_value, registry, custom_rules, "rules.select")?;
        selectors.has_positive = !selectors.positive.is_empty();
    }
    if let Some(ignore_value) = rules.get("ignore") {
        selectors.negative =
            expand_rule_selectors(ignore_value, registry, custom_rules, "rules.ignore")?;
    }
    Ok(())
}

fn apply_custom_rule_settings(
    rules: &serde_json::Map<String, Value>,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    settings: &mut HashMap<String, RuleSetting>,
) -> Result<(), String> {
    let Some(custom_value) = rules.get("custom") else {
        return Ok(());
    };
    let custom = custom_value
        .as_object()
        .ok_or_else(|| "config key `rules.custom` must be an object".to_string())?;
    for (rule_id, rule_value) in custom {
        insert_rule_setting(
            rule_id,
            rule_value,
            registry,
            custom_rules,
            settings,
            "rules.custom",
        )?;
    }
    Ok(())
}

fn insert_rule_setting(
    rule_id: &str,
    rule_value: &Value,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    settings: &mut HashMap<String, RuleSetting>,
    context: &str,
) -> Result<(), String> {
    let is_builtin = registry.contains(rule_id);
    let is_custom = custom_rules.iter().any(|rule| rule.id == rule_id);
    if !is_builtin && !is_custom {
        return Err(format!(
            "unknown rule id `{rule_id}` in config key `{context}`"
        ));
    }
    if settings.contains_key(rule_id) {
        return Err(format!("duplicate rule config for `{rule_id}`"));
    }
    let setting = parse_rule_setting(rule_id, rule_value, registry, is_custom)?;
    settings.insert(rule_id.to_string(), setting);
    Ok(())
}

fn parse_rule_setting(
    rule_id: &str,
    rule_value: &Value,
    registry: &rules::RuleRegistry,
    is_custom: bool,
) -> Result<RuleSetting, String> {
    let rule_object = rule_value
        .as_object()
        .ok_or_else(|| format!("config for rule `{rule_id}` must be an object"))?;
    reject_unknown_keys(
        rule_object,
        &["enabled", "threshold", "severity", "options"],
        &format!("config for rule `{rule_id}`"),
    )?;

    let mut setting = RuleSetting {
        enabled: parse_rule_enabled(rule_id, rule_object)?,
        ..RuleSetting::default()
    };
    if is_custom {
        if rule_object
            .keys()
            .any(|key| !matches!(key.as_str(), "enabled"))
        {
            return Err(format!(
                "custom rule `{rule_id}` only supports `enabled` under `rules`"
            ));
        }
        return Ok(setting);
    }
    apply_rule_thresholds(rule_id, rule_object, registry, &mut setting)?;
    validate_optional_rule_options(rule_id, rule_object, registry)?;
    Ok(setting)
}

fn parse_rule_enabled(
    rule_id: &str,
    rule_object: &serde_json::Map<String, Value>,
) -> Result<Option<bool>, String> {
    rule_object
        .get("enabled")
        .map(|enabled| {
            enabled
                .as_bool()
                .ok_or_else(|| format!("config key `rules.{rule_id}.enabled` must be a boolean"))
        })
        .transpose()
}

fn apply_rule_thresholds(
    rule_id: &str,
    rule_object: &serde_json::Map<String, Value>,
    registry: &rules::RuleRegistry,
    setting: &mut RuleSetting,
) -> Result<(), String> {
    match (rule_object.get("threshold"), rule_object.get("severity")) {
        (Some(threshold_value), Some(severity_value)) => {
            apply_threshold(rule_id, threshold_value, severity_value, registry, setting)?;
        }
        (Some(_), None) => {
            return Err(format!(
                "config key `rules.{rule_id}.severity` is required when `threshold` is configured"
            ));
        }
        (None, Some(_)) => {
            return Err(format!(
                "config key `rules.{rule_id}.severity` requires `threshold`"
            ));
        }
        (None, None) => {}
    }
    Ok(())
}

fn validate_optional_rule_options(
    rule_id: &str,
    rule_object: &serde_json::Map<String, Value>,
    registry: &rules::RuleRegistry,
) -> Result<(), String> {
    if let Some(options_value) = rule_object.get("options") {
        validate_rule_options(rule_id, options_value, registry)?;
    }
    Ok(())
}

fn apply_threshold(
    rule_id: &str,
    threshold_value: &Value,
    severity_value: &Value,
    registry: &rules::RuleRegistry,
    setting: &mut RuleSetting,
) -> Result<(), String> {
    ensure_rule_supports_threshold(registry, rule_id)?;
    let number = threshold_value
        .as_f64()
        .ok_or_else(|| format!("threshold `rules.{rule_id}.threshold` must be a number"))?;
    let severity = severity_value
        .as_str()
        .and_then(parse_severity_name)
        .ok_or_else(|| {
            format!("config key `rules.{rule_id}.severity` must be advisory, warning, or error")
        })?;
    setting.threshold = Some(number);
    setting.severity = Some(severity);
    Ok(())
}

fn validate_rule_options(
    rule_id: &str,
    options_value: &Value,
    registry: &rules::RuleRegistry,
) -> Result<(), String> {
    let options = options_value
        .as_object()
        .ok_or_else(|| format!("config key `rules.{rule_id}.options` must be an object"))?;
    for name in options.keys() {
        if !registry.supports_option(rule_id, name) {
            return Err(format!("unknown option `{name}` for rule `{rule_id}`"));
        }
    }
    Ok(())
}

fn expand_rule_selectors(
    selectors_value: &Value,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    path: &str,
) -> Result<BTreeSet<String>, String> {
    let selectors = string_array(selectors_value, path)?;
    let mut expanded = BTreeSet::new();
    for (index, selector) in selectors.iter().enumerate() {
        let selector_path = selector_config_path(path, index);
        expanded.extend(expand_rule_selector_with_custom(
            selector,
            registry,
            custom_rules,
            &selector_path,
        )?);
    }
    Ok(expanded)
}

fn selector_config_path(path: &str, index: usize) -> String {
    format!("{path}[{index}]")
}

#[cfg(test)]
fn expand_rule_selector(
    selector: &str,
    registry: &rules::RuleRegistry,
    path: &str,
) -> Result<BTreeSet<String>, String> {
    expand_rule_selector_with_custom(selector, registry, &[], path)
}

fn expand_rule_selector_with_custom(
    selector: &str,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    path: &str,
) -> Result<BTreeSet<String>, String> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(format!(
            "empty selector in `{path}`; expected exact rule id, dotted prefix, or public pillar"
        ));
    }
    reject_unsupported_selector_syntax(selector, path)?;
    let catalog = rule_selector_catalog(registry, custom_rules);
    exact_rule_selector(selector, &catalog)
        .or_else(|| pillar_rule_selector(selector, &catalog))
        .or_else(|| prefix_rule_selector(selector, &catalog))
        .ok_or_else(|| {
            format!(
                "unknown selector `{selector}` in `{path}`; expected exact rule id, dotted prefix, or public pillar such as Security"
            )
        })
}

fn reject_unsupported_selector_syntax(selector: &str, path: &str) -> Result<(), String> {
    if selector.contains(':') {
        return Err(format!(
            "unsupported selector `{selector}` in `{path}`; tier/profile selectors are reserved for future registry metadata"
        ));
    }
    if selector.contains('*') && !selector.ends_with(".*") {
        return Err(format!(
            "unsupported selector `{selector}` in `{path}`; only dotted prefix selectors such as `security.*` are supported"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct RuleSelectorEntry {
    id: String,
    pillar: Pillar,
}

fn rule_selector_catalog(
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
) -> Vec<RuleSelectorEntry> {
    let mut entries: Vec<RuleSelectorEntry> = registry
        .definitions()
        .iter()
        .map(|definition| RuleSelectorEntry {
            id: definition.id.to_string(),
            pillar: definition.pillar,
        })
        .collect();
    entries.extend(custom_rules.iter().map(|rule| RuleSelectorEntry {
        id: rule.id.clone(),
        pillar: rule.pillar,
    }));
    entries
}

fn exact_rule_selector(selector: &str, entries: &[RuleSelectorEntry]) -> Option<BTreeSet<String>> {
    if entries.iter().any(|entry| entry.id == selector) {
        return Some(BTreeSet::from([selector.to_string()]));
    }
    None
}

fn pillar_rule_selector(selector: &str, entries: &[RuleSelectorEntry]) -> Option<BTreeSet<String>> {
    let pillar = parse_pillar_selector(selector)?;
    Some(
        entries
            .iter()
            .filter(|entry| entry.pillar == pillar)
            .map(|entry| entry.id.clone())
            .collect(),
    )
}

fn prefix_rule_selector(selector: &str, entries: &[RuleSelectorEntry]) -> Option<BTreeSet<String>> {
    let prefix = selector.strip_suffix(".*").unwrap_or(selector);
    let prefix_with_dot = format!("{prefix}.");
    let matches: BTreeSet<String> = entries
        .iter()
        .filter(|entry| entry.id.starts_with(&prefix_with_dot))
        .map(|entry| entry.id.clone())
        .collect();
    if !matches.is_empty() {
        return Some(matches);
    }
    None
}

fn parse_pillar_selector(selector: &str) -> Option<Pillar> {
    let normalized = normalize_selector_name(selector);
    PILLAR_SELECTOR_NAMES
        .iter()
        .find_map(|(name, pillar)| (normalize_selector_name(name) == normalized).then_some(*pillar))
}

fn normalize_selector_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(|character| character.to_lowercase())
        .collect()
}

const PILLAR_SELECTOR_NAMES: &[(&str, Pillar)] = &[
    ("Size", Pillar::Size),
    ("Complexity", Pillar::Complexity),
    ("DeadCode", Pillar::DeadCode),
    ("Dead code", Pillar::DeadCode),
    ("Waste", Pillar::Waste),
    ("Naming", Pillar::Naming),
    ("Documentation", Pillar::Documentation),
    ("Modernisation", Pillar::Modernisation),
    ("Security", Pillar::Security),
    ("SensitiveData", Pillar::SensitiveData),
    ("Sensitive data", Pillar::SensitiveData),
    ("TestQuality", Pillar::TestQuality),
    ("Test quality", Pillar::TestQuality),
    ("Design", Pillar::Design),
];

fn default_config_path(project_root: &Path) -> Option<PathBuf> {
    DEFAULT_CONFIG_FILES
        .iter()
        .map(|name| project_root.join(name))
        .find(|path| path.exists())
}

fn parse_config_value(path: &Path, raw: &str) -> Result<Value, String> {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "yaml" | "yml" => serde_yaml::from_str(raw)
            .map_err(|error| format!("invalid config YAML {}: {error}", path.display())),
        "json" => Err(format!(
            "unsupported config extension `json`; use .gruff-rs.yaml or another YAML config path instead: {}",
            path.display()
        )),
        _ => serde_yaml::from_str(raw)
            .map_err(|error| format!("invalid config YAML {}: {error}", path.display())),
    }
}

fn ensure_rule_supports_threshold(
    registry: &rules::RuleRegistry,
    rule_id: &str,
) -> Result<(), String> {
    let definition = registry
        .get(rule_id)
        .ok_or_else(|| format!("unknown rule id `{rule_id}` in config"))?;
    if definition.threshold.is_some() {
        Ok(())
    } else {
        Err(format!(
            "config key `rules.{rule_id}.threshold` is only supported for rules with one numeric threshold"
        ))
    }
}

fn reject_unknown_keys(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    for key in object.keys() {
        if !allowed.iter().any(|allowed_key| allowed_key == key) {
            return Err(format!("unknown key `{key}` in {context}"));
        }
    }
    Ok(())
}

fn string_array(value: &Value, path: &str) -> Result<Vec<String>, String> {
    let array = value
        .as_array()
        .ok_or_else(|| format!("config key `{path}` must be an array"))?;
    array
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_str()
                .map(String::from)
                .ok_or_else(|| format!("config key `{path}[{index}]` must be a string"))
        })
        .collect()
}

fn read_and_parse_sources(files: &[SourceFile]) -> (Vec<ParsedSource>, Vec<RunDiagnostic>) {
    let mut parsed_sources = Vec::new();
    let mut diagnostics = Vec::new();

    for source_file in files {
        match fs::read_to_string(&source_file.absolute_path) {
            Ok(source) => parsed_sources.push(parse_source_file(source_file.clone(), source)),
            Err(error) => diagnostics.push(RunDiagnostic {
                diagnostic_type: "read-error".to_string(),
                message: format!("Unable to read file: {error}"),
                file_path: Some(source_file.display_path.clone()),
                line: Some(1),
            }),
        }
    }

    (parsed_sources, diagnostics)
}

fn parse_source_file(file: SourceFile, source: String) -> ParsedSource {
    if !file.is_rust {
        return ParsedSource {
            file,
            source,
            rust_ast: None,
            diagnostics: Vec::new(),
        };
    }

    match syn::parse_file(&source) {
        Ok(ast) => ParsedSource {
            file,
            source,
            rust_ast: Some(ast),
            diagnostics: Vec::new(),
        },
        Err(error) => {
            let display_path = file.display_path.clone();
            ParsedSource {
                file,
                source,
                rust_ast: None,
                diagnostics: vec![RunDiagnostic {
                    diagnostic_type: "parse-error".to_string(),
                    message: format!("Rust parser error: {error}"),
                    file_path: Some(display_path),
                    line: Some(line_from_span(error.span().start())),
                }],
            }
        }
    }
}

fn line_from_span(position: LineColumn) -> usize {
    position.line.max(1)
}

fn build_project_context(project_root: &Path, sources: &[ParsedSource]) -> ProjectContext {
    let mut diagnostics = Vec::new();
    let manifest = read_manifest_summary(project_root, &mut diagnostics);
    let lockfile = read_lockfile_summary(project_root, &mut diagnostics);
    let mut index = project_index(sources);
    sort_project_index(&mut index);

    ProjectContext {
        root_path: project_root.to_path_buf(),
        manifest,
        lockfile,
        rust_sources: index.rust_sources,
        modules: index.modules,
        items: index.items,
        call_names: index.call_names,
        diagnostics,
    }
}

struct ProjectIndex {
    rust_sources: Vec<RustSourceSummary>,
    modules: Vec<ModuleSummary>,
    items: Vec<ItemSummary>,
    call_names: Vec<CallNameSummary>,
}

fn project_index(sources: &[ParsedSource]) -> ProjectIndex {
    let mut rust_sources = Vec::new();
    let mut modules = Vec::new();
    let mut items = Vec::new();
    let mut call_names = Vec::new();

    for source in sources {
        if let Some(ast) = &source.rust_ast {
            rust_sources.push(RustSourceSummary {
                file_path: source.file.display_path.clone(),
                source: source.source.clone(),
            });
            let module_path = inferred_file_module_path(&source.file);
            collect_project_rust_index(
                &source.file,
                &source.source,
                ast,
                &module_path,
                &mut modules,
                &mut items,
                &mut call_names,
            );
        }
    }
    ProjectIndex {
        rust_sources,
        modules,
        items,
        call_names,
    }
}

fn sort_project_index(index: &mut ProjectIndex) {
    sort_project_modules(&mut index.modules);
    sort_project_items(&mut index.items);
    index.call_names.sort_by(|left, right| {
        (left.file_path.as_str(), left.name.as_str(), left.line).cmp(&(
            right.file_path.as_str(),
            right.name.as_str(),
            right.line,
        ))
    });
    index.call_names.dedup();
    index
        .rust_sources
        .sort_by(|left, right| left.file_path.cmp(&right.file_path));
}

fn sort_project_modules(modules: &mut [ModuleSummary]) {
    modules.sort_by(|left, right| {
        (
            left.file_path.as_str(),
            left.module_path.as_str(),
            left.line,
            left.inline,
            left.cfg_gated,
        )
            .cmp(&(
                right.file_path.as_str(),
                right.module_path.as_str(),
                right.line,
                right.inline,
                right.cfg_gated,
            ))
    });
}

fn sort_project_items(items: &mut [ItemSummary]) {
    items.sort_by(|left, right| {
        (
            left.file_path.as_str(),
            left.module_path.as_str(),
            left.name.as_str(),
            left.kind.as_str(),
            left.line,
            left.cfg_gated,
            left.test_context,
        )
            .cmp(&(
                right.file_path.as_str(),
                right.module_path.as_str(),
                right.name.as_str(),
                right.kind.as_str(),
                right.line,
                right.cfg_gated,
                right.test_context,
            ))
    });
}

fn read_manifest_summary(
    project_root: &Path,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Option<ManifestSummary> {
    let raw = read_manifest_raw(project_root, diagnostics)?;
    let value = parse_manifest_value(&raw, diagnostics)?;
    Some(ManifestSummary {
        file_path: "Cargo.toml".to_string(),
        package_line: manifest_package_line(&raw),
        package_name: manifest_package_field(&value, "name"),
        package_description: manifest_package_field(&value, "description"),
        package_license: manifest_package_field(&value, "license"),
        dependencies: manifest_dependencies(&value, &raw),
    })
}

fn read_manifest_raw(project_root: &Path, diagnostics: &mut Vec<RunDiagnostic>) -> Option<String> {
    let path = project_root.join("Cargo.toml");
    if !path.exists() {
        return None;
    }
    Some(match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => {
            diagnostics.push(RunDiagnostic {
                diagnostic_type: "manifest-read-error".to_string(),
                message: format!("Unable to read Cargo.toml: {error}"),
                file_path: Some("Cargo.toml".to_string()),
                line: Some(1),
            });
            return None;
        }
    })
}

fn parse_manifest_value(raw: &str, diagnostics: &mut Vec<RunDiagnostic>) -> Option<toml::Value> {
    Some(match raw.parse::<toml::Value>() {
        Ok(value) => value,
        Err(_) => {
            diagnostics.push(RunDiagnostic {
                diagnostic_type: "manifest-parse-error".to_string(),
                message:
                    "Invalid Cargo.toml; fix TOML syntax before project rules use manifest data."
                        .to_string(),
                file_path: Some("Cargo.toml".to_string()),
                line: Some(1),
            });
            return None;
        }
    })
}

fn manifest_package_field(value: &toml::Value, field: &str) -> Option<String> {
    value
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get(field))
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

fn manifest_dependencies(value: &toml::Value, raw: &str) -> Vec<DependencySummary> {
    let dependency_lines = manifest_dependency_lines(raw);
    let mut dependencies = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        collect_manifest_dependencies(value, section, &dependency_lines, &mut dependencies);
    }
    dependencies.sort_by(|left, right| {
        (left.section.as_str(), left.name.as_str())
            .cmp(&(right.section.as_str(), right.name.as_str()))
    });
    dependencies
}

fn collect_manifest_dependencies(
    value: &toml::Value,
    section: &str,
    dependency_lines: &HashMap<(String, String), usize>,
    dependencies: &mut Vec<DependencySummary>,
) {
    let Some(table) = value.get(section).and_then(toml::Value::as_table) else {
        return;
    };

    for (name, dependency) in table {
        let (requirement, path, git) = if let Some(requirement) = dependency.as_str() {
            (Some(requirement.to_string()), None, None)
        } else if let Some(table) = dependency.as_table() {
            (
                table
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
                table
                    .get("path")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
                table
                    .get("git")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
            )
        } else {
            (None, None, None)
        };

        dependencies.push(DependencySummary {
            name: name.clone(),
            section: section.to_string(),
            line: dependency_lines
                .get(&(section.to_string(), name.clone()))
                .copied()
                .unwrap_or(1),
            requirement,
            path,
            git,
        });
    }
}

fn manifest_package_line(raw: &str) -> usize {
    raw.lines()
        .enumerate()
        .find_map(|(index, line)| (line.trim() == "[package]").then_some(index + 1))
        .unwrap_or(1)
}

fn manifest_dependency_lines(raw: &str) -> HashMap<(String, String), usize> {
    let mut lines = HashMap::new();
    let mut current_section: Option<String> = None;

    for (index, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = trimmed.trim_matches(&['[', ']'][..]).to_string();
            current_section = matches!(
                section.as_str(),
                "dependencies" | "dev-dependencies" | "build-dependencies"
            )
            .then_some(section);
            continue;
        }

        let Some(section) = &current_section else {
            continue;
        };
        let Some((name, _)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim().trim_matches('"').trim_matches('\'');
        if !name.is_empty() && !name.starts_with('#') {
            lines.insert((section.clone(), name.to_string()), index + 1);
        }
    }

    lines
}

fn read_lockfile_summary(
    project_root: &Path,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Option<LockfileSummary> {
    let raw = read_lockfile_raw(project_root, diagnostics)?;
    let value = parse_lockfile_value(&raw, diagnostics)?;
    Some(LockfileSummary {
        file_path: "Cargo.lock".to_string(),
        packages: locked_packages(&value, &raw),
    })
}

fn read_lockfile_raw(project_root: &Path, diagnostics: &mut Vec<RunDiagnostic>) -> Option<String> {
    let path = project_root.join("Cargo.lock");
    if !path.exists() {
        return None;
    }
    Some(match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => {
            diagnostics.push(RunDiagnostic {
                diagnostic_type: "lockfile-read-error".to_string(),
                message: format!("Unable to read Cargo.lock: {error}"),
                file_path: Some("Cargo.lock".to_string()),
                line: Some(1),
            });
            return None;
        }
    })
}

fn parse_lockfile_value(raw: &str, diagnostics: &mut Vec<RunDiagnostic>) -> Option<toml::Value> {
    Some(match raw.parse::<toml::Value>() {
        Ok(value) => value,
        Err(_) => {
            diagnostics.push(RunDiagnostic {
                diagnostic_type: "lockfile-parse-error".to_string(),
                message: "Invalid Cargo.lock; regenerate or fix TOML syntax before project rules use lockfile data."
                    .to_string(),
                file_path: Some("Cargo.lock".to_string()),
                line: Some(1),
            });
            return None;
        }
    })
}

fn locked_packages(value: &toml::Value, raw: &str) -> Vec<LockedPackageSummary> {
    let package_lines = lockfile_package_lines(raw);
    let mut packages = value
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|package| {
            let table = package.as_table()?;
            let name = table.get("name")?.as_str()?.to_string();
            let version = table.get("version")?.as_str()?.to_string();
            let source = table
                .get("source")
                .and_then(toml::Value::as_str)
                .map(str::to_string);
            let line = package_lines
                .get(&(name.clone(), version.clone()))
                .copied()
                .unwrap_or(1);
            Some(LockedPackageSummary {
                name,
                version,
                line,
                source,
            })
        })
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| {
        (
            left.name.as_str(),
            left.version.as_str(),
            left.source.as_deref(),
        )
            .cmp(&(
                right.name.as_str(),
                right.version.as_str(),
                right.source.as_deref(),
            ))
    });
    packages
}

fn lockfile_package_lines(raw: &str) -> HashMap<(String, String), usize> {
    let mut lines = HashMap::new();
    let mut current_name: Option<(String, usize)> = None;

    for (index, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            current_name = None;
            continue;
        }
        if let Some(name) = quoted_toml_value(trimmed, "name") {
            current_name = Some((name, index + 1));
            continue;
        }
        if let (Some((name, line)), Some(version)) =
            (&current_name, quoted_toml_value(trimmed, "version"))
        {
            lines.insert((name.clone(), version), *line);
        }
    }

    lines
}

fn quoted_toml_value(line: &str, key: &str) -> Option<String> {
    let (left, right) = line.split_once('=')?;
    if left.trim() != key {
        return None;
    }
    Some(right.trim().trim_matches('"').to_string())
}

fn collect_project_rust_index(
    file: &SourceFile,
    source: &str,
    ast: &syn::File,
    module_path: &str,
    modules: &mut Vec<ModuleSummary>,
    items: &mut Vec<ItemSummary>,
    call_names: &mut Vec<CallNameSummary>,
) {
    collect_project_items(file, &ast.items, module_path, false, false, modules, items);
    collect_call_names(file, source, call_names);
}

fn collect_project_items(
    file: &SourceFile,
    syn_items: &[Item],
    module_path: &str,
    cfg_context: bool,
    test_context: bool,
    modules: &mut Vec<ModuleSummary>,
    items: &mut Vec<ItemSummary>,
) {
    let scope = ProjectItemScope {
        file,
        module_path,
        cfg_context,
        test_context,
    };
    for item in syn_items {
        collect_project_item(scope, item, modules, items);
    }
}

#[derive(Clone, Copy)]
struct ProjectItemScope<'a> {
    file: &'a SourceFile,
    module_path: &'a str,
    cfg_context: bool,
    test_context: bool,
}

fn collect_project_item(
    scope: ProjectItemScope<'_>,
    item: &Item,
    modules: &mut Vec<ModuleSummary>,
    items: &mut Vec<ItemSummary>,
) {
    match item {
        Item::Fn(item_fn) => collect_project_function(scope, item_fn, items),
        Item::Struct(item_struct) => collect_project_struct(scope, item_struct, items),
        Item::Enum(item_enum) => collect_project_enum(scope, item_enum, items),
        Item::Trait(item_trait) => collect_project_trait(scope, item_trait, items),
        Item::Impl(item_impl) => collect_project_impl(scope, item_impl, items),
        Item::Mod(item_mod) => collect_project_module(scope, item_mod, modules, items),
        _ => {}
    }
}

fn collect_project_function(
    scope: ProjectItemScope<'_>,
    item_fn: &syn::ItemFn,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope.file,
        scope.module_path,
        item_fn.sig.ident.to_string(),
        "function",
        line_from_span(item_fn.sig.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_fn.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_fn.attrs),
            test_context: scope.test_context || has_test_attr(&item_fn.attrs),
        },
    ));
}

fn collect_project_struct(
    scope: ProjectItemScope<'_>,
    item_struct: &syn::ItemStruct,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope.file,
        scope.module_path,
        item_struct.ident.to_string(),
        "struct",
        line_from_span(item_struct.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_struct.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_struct.attrs),
            test_context: scope.test_context,
        },
    ));
}

fn collect_project_enum(
    scope: ProjectItemScope<'_>,
    item_enum: &syn::ItemEnum,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope.file,
        scope.module_path,
        item_enum.ident.to_string(),
        "enum",
        line_from_span(item_enum.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_enum.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_enum.attrs),
            test_context: scope.test_context,
        },
    ));
}

fn collect_project_trait(
    scope: ProjectItemScope<'_>,
    item_trait: &syn::ItemTrait,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope.file,
        scope.module_path,
        item_trait.ident.to_string(),
        "trait",
        line_from_span(item_trait.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&item_trait.vis),
            cfg_gated: scope.cfg_context || has_cfg_attr(&item_trait.attrs),
            test_context: scope.test_context,
        },
    ));
}

fn collect_project_impl(
    scope: ProjectItemScope<'_>,
    item_impl: &syn::ItemImpl,
    items: &mut Vec<ItemSummary>,
) {
    for impl_item in &item_impl.items {
        if let ImplItem::Fn(method) = impl_item {
            collect_project_method(scope, item_impl, method, items);
        }
    }
}

fn collect_project_method(
    scope: ProjectItemScope<'_>,
    item_impl: &syn::ItemImpl,
    method: &syn::ImplItemFn,
    items: &mut Vec<ItemSummary>,
) {
    items.push(project_item(
        scope.file,
        scope.module_path,
        method.sig.ident.to_string(),
        "method",
        line_from_span(method.sig.ident.span().start()),
        ProjectItemContext {
            public: visibility_is_public(&method.vis),
            cfg_gated: scope.cfg_context
                || has_cfg_attr(&item_impl.attrs)
                || has_cfg_attr(&method.attrs),
            test_context: scope.test_context || has_test_attr(&method.attrs),
        },
    ));
}

fn collect_project_module(
    scope: ProjectItemScope<'_>,
    item_mod: &syn::ItemMod,
    modules: &mut Vec<ModuleSummary>,
    items: &mut Vec<ItemSummary>,
) {
    let current_module = module_name(scope.module_path, &item_mod.ident.to_string());
    let module_cfg_gated = scope.cfg_context || has_cfg_attr(&item_mod.attrs);
    let module_test_context = scope.test_context || is_test_module(item_mod);
    modules.push(ModuleSummary {
        file_path: scope.file.display_path.clone(),
        module_path: current_module.clone(),
        line: line_from_span(item_mod.ident.span().start()),
        public: visibility_is_public(&item_mod.vis),
        inline: item_mod.content.is_some(),
        cfg_gated: module_cfg_gated,
    });
    if let Some((_, nested)) = &item_mod.content {
        collect_project_items(
            scope.file,
            nested,
            &current_module,
            module_cfg_gated,
            module_test_context,
            modules,
            items,
        );
    }
}

fn project_item(
    file: &SourceFile,
    module_path: &str,
    name: String,
    kind: &str,
    line: usize,
    context: ProjectItemContext,
) -> ItemSummary {
    ItemSummary {
        file_path: file.display_path.clone(),
        module_path: module_path.to_string(),
        name,
        kind: kind.to_string(),
        line,
        public: context.public,
        cfg_gated: context.cfg_gated,
        test_context: context.test_context,
    }
}

fn module_name(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}::{name}")
    }
}

fn inferred_file_module_path(file: &SourceFile) -> String {
    let Some(path) = file.display_path.strip_prefix("src/") else {
        return String::new();
    };
    if matches!(path, "lib.rs" | "main.rs") {
        return String::new();
    }

    let without_extension = path
        .strip_suffix("/mod.rs")
        .or_else(|| path.strip_suffix(".rs"))
        .unwrap_or(path);
    without_extension.replace('/', "::")
}

fn has_cfg_attr(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
}

fn has_cfg_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }

        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        let compact_tokens = list.tokens.to_string().replace(' ', "");
        if compact_tokens.contains("not(test)") {
            return false;
        }
        compact_tokens == "test"
            || compact_tokens.starts_with("test,")
            || compact_tokens.contains("any(test")
            || compact_tokens.contains("all(test")
            || compact_tokens.contains(",test")
            || compact_tokens.ends_with(",test)")
    })
}

fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| path_ends_with(attr, "test"))
}

fn path_ends_with(attr: &syn::Attribute, name: &str) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == name)
}

fn is_test_module(item_mod: &syn::ItemMod) -> bool {
    item_mod.ident == "tests"
        || has_test_attr(&item_mod.attrs)
        || has_cfg_test_attr(&item_mod.attrs)
}

fn collect_call_names(file: &SourceFile, source: &str, call_names: &mut Vec<CallNameSummary>) {
    static CALL_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
    let call_name_regex = static_regex(&CALL_NAME_REGEX, r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(");
    let line_starts = line_starts(source);
    for capture in call_name_regex.captures_iter(source) {
        let Some(name) = capture.get(1) else {
            continue;
        };
        if !is_call_name_candidate(name.as_str()) {
            continue;
        }
        push_call_name(file, source.len(), &line_starts, name, call_names);
    }
}

fn is_call_name_candidate(name: &str) -> bool {
    !matches!(
        name,
        "fn" | "if" | "match" | "while" | "for" | "loop" | "return"
    )
}

fn push_call_name(
    file: &SourceFile,
    source_len: usize,
    line_starts: &[usize],
    name: regex::Match<'_>,
    call_names: &mut Vec<CallNameSummary>,
) {
    call_names.push(CallNameSummary {
        file_path: file.display_path.clone(),
        name: name.as_str().to_string(),
        line: byte_line_from_starts(line_starts, name.start().min(source_len)),
    });
}

fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(index + 1);
        }
    }
    starts
}

fn byte_line_from_starts(line_starts: &[usize], byte_index: usize) -> usize {
    line_starts.partition_point(|line_start| *line_start <= byte_index)
}

fn visibility_is_public(visibility: &Visibility) -> bool {
    !matches!(visibility, Visibility::Inherited)
}

fn analyse_project(context: &ProjectContext, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !context.root_path.join("README.md").exists() && config.rule_enabled("docs.missing-readme") {
        findings.push(Finding::new(
            "docs.missing-readme",
            "Project root does not contain a README.md file.",
            "README.md",
            Some(1),
            Severity::Advisory,
            Pillar::Documentation,
            Confidence::High,
            None,
            Some(
                "Add a README.md that explains the project purpose and local commands.".to_string(),
            ),
            json!({}),
        ));
    }

    analyse_dependency_rules(context, config, &mut findings);
    analyse_architecture_rules(context, config, &mut findings);
    analyse_project_dead_code_rules(context, config, &mut findings);

    findings
}

fn analyse_architecture_rules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_module_fan_out(context, config, findings);
    analyse_public_api_surface(context, config, findings);
    analyse_large_modules(context, config, findings);
}

fn analyse_module_fan_out(context: &ProjectContext, config: &Config, findings: &mut Vec<Finding>) {
    let rule_id = "architecture.module-fan-out";
    if !config.rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id, 8.0) as usize;
    let mut by_file: BTreeMap<&str, Vec<&ModuleSummary>> = BTreeMap::new();
    for module in context.modules.iter().filter(|module| !module.cfg_gated) {
        by_file
            .entry(module.file_path.as_str())
            .or_default()
            .push(module);
    }

    for (file_path, modules) in by_file {
        if modules.len() <= threshold {
            continue;
        }
        let first_line = modules.iter().map(|module| module.line).min().unwrap_or(1);
        findings.push(Finding::new(
            rule_id,
            format!(
                "File `{file_path}` declares {} child modules, above the threshold of {threshold}.",
                modules.len()
            ),
            file_path.to_string(),
            Some(first_line),
            config.severity(rule_id, Severity::Advisory),
            Pillar::Design,
            Confidence::High,
            Some(file_path.to_string()),
            Some(
                "Split module declarations across clearer parent modules when the fan-out grows."
                    .to_string(),
            ),
            json!({ "modules": modules.len(), "threshold": threshold }),
        ));
    }
}

fn analyse_public_api_surface(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "architecture.public-api-surface";
    if !config.rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id, 12.0) as usize;
    let mut by_module: BTreeMap<(String, String), Vec<&ItemSummary>> = BTreeMap::new();
    for item in context.items.iter().filter(|item| {
        item.public && !item.cfg_gated && !item.test_context && item.kind != "method"
    }) {
        by_module
            .entry((item.file_path.clone(), item.module_path.clone()))
            .or_default()
            .push(item);
    }

    for ((file_path, module_path), items) in by_module {
        if items.len() <= threshold {
            continue;
        }
        let first_line = items.iter().map(|item| item.line).min().unwrap_or(1);
        let module = module_label(&file_path, &module_path);
        findings.push(Finding::new(
            rule_id,
            format!(
                "Module `{module}` exposes {} public items, above the threshold of {threshold}.",
                items.len()
            ),
            file_path,
            Some(first_line),
            config.severity(rule_id, Severity::Advisory),
            Pillar::Design,
            Confidence::High,
            Some(module.clone()),
            Some(
                "Group related public API items behind smaller modules or facade types."
                    .to_string(),
            ),
            json!({ "publicItems": items.len(), "threshold": threshold, "module": module }),
        ));
    }
}

fn analyse_large_modules(context: &ProjectContext, config: &Config, findings: &mut Vec<Finding>) {
    let rule_id = "architecture.large-module";
    if !config.rule_enabled(rule_id) {
        return;
    }
    let threshold = config.threshold(rule_id, 25.0) as usize;
    let mut by_module: BTreeMap<(String, String), Vec<&ItemSummary>> = BTreeMap::new();
    for item in context
        .items
        .iter()
        .filter(|item| !item.cfg_gated && !item.test_context)
    {
        by_module
            .entry((item.file_path.clone(), item.module_path.clone()))
            .or_default()
            .push(item);
    }

    for ((file_path, module_path), items) in by_module {
        if items.len() <= threshold {
            continue;
        }
        let first_line = items.iter().map(|item| item.line).min().unwrap_or(1);
        let module = module_label(&file_path, &module_path);
        findings.push(Finding::new(
            rule_id,
            format!(
                "Module `{module}` contains {} indexed items, above the threshold of {threshold}.",
                items.len()
            ),
            file_path,
            Some(first_line),
            config.severity(rule_id, Severity::Advisory),
            Pillar::Design,
            Confidence::High,
            Some(module.clone()),
            Some(
                "Split unrelated responsibilities into smaller modules with narrower APIs."
                    .to_string(),
            ),
            json!({ "items": items.len(), "threshold": threshold, "module": module }),
        ));
    }
}

fn module_label(file_path: &str, module_path: &str) -> String {
    if module_path.is_empty() {
        file_path.to_string()
    } else {
        module_path.to_string()
    }
}

fn analyse_project_dead_code_rules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "dead-code.unused-private-item-candidate";
    if !config.rule_enabled(rule_id) {
        return;
    }

    for item in context.items.iter().filter(|item| {
        !item.public
            && !item.cfg_gated
            && !item.test_context
            && matches!(item.kind.as_str(), "function" | "struct" | "enum" | "trait")
            && item.name != "main"
    }) {
        if rust_identifier_occurrences(context, &item.name) > 1 {
            continue;
        }
        let symbol = item_symbol(item);
        findings.push(Finding::new(
            rule_id,
            format!(
                "Private {} `{}` is an unused candidate; no other discovered Rust source references its name.",
                item.kind, item.name
            ),
            item.file_path.clone(),
            Some(item.line),
            Severity::Advisory,
            Pillar::DeadCode,
            Confidence::Medium,
            Some(symbol.clone()),
            Some(
                "Remove the item, make the reference explicit, or keep it documented if it is used through macros or cfg-specific builds."
                    .to_string(),
            ),
            json!({ "kind": item.kind.as_str(), "module": item.module_path.as_str(), "candidate": true }),
        ));
    }
}

fn item_symbol(item: &ItemSummary) -> String {
    if item.module_path.is_empty() {
        item.name.clone()
    } else {
        format!("{}::{}", item.module_path, item.name)
    }
}

fn rust_identifier_occurrences(context: &ProjectContext, name: &str) -> usize {
    context
        .rust_sources
        .iter()
        .map(|source| identifier_occurrences(&source.source, name))
        .sum()
}

fn identifier_occurrences(source: &str, name: &str) -> usize {
    let pattern = format!(r"\b{}\b", regex::escape(name));
    Regex::new(&pattern)
        .expect("escaped identifier regex compiles")
        .find_iter(source)
        .count()
}

fn analyse_dependency_rules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if let Some(manifest) = &context.manifest {
        analyse_manifest_metadata(manifest, config, findings);
        for dependency in &manifest.dependencies {
            analyse_manifest_dependency(manifest, dependency, config, findings);
        }
    }

    if let Some(lockfile) = &context.lockfile {
        analyse_lockfile_duplicates(lockfile, config, findings);
    }
}

fn analyse_manifest_metadata(
    manifest: &ManifestSummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "dependency.missing-package-metadata";
    if !config.rule_enabled(rule_id) {
        return;
    }

    let mut missing = Vec::new();
    if is_missing_text(manifest.package_description.as_deref()) {
        missing.push("description");
    }
    if is_missing_text(manifest.package_license.as_deref()) {
        missing.push("license");
    }
    if missing.is_empty() {
        return;
    }

    let package = manifest
        .package_name
        .clone()
        .unwrap_or_else(|| "package".to_string());
    findings.push(Finding::new(
        rule_id,
        format!(
            "Package `{package}` is missing Cargo metadata: {}.",
            missing.join(", ")
        ),
        manifest.file_path.clone(),
        Some(manifest.package_line),
        Severity::Advisory,
        Pillar::Documentation,
        Confidence::High,
        Some(package),
        Some("Add package description and license metadata to Cargo.toml.".to_string()),
        json!({ "missing": missing }),
    ));
}

fn analyse_manifest_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_git_dependency(manifest, dependency, config, findings);
    analyse_path_dependency(manifest, dependency, config, findings);
    analyse_wildcard_dependency(manifest, dependency, config, findings);
}

fn analyse_git_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if let Some(git) = &dependency.git {
        let rule_id = "dependency.git-source";
        if config.rule_enabled(rule_id) {
            findings.push(Finding::new(
                rule_id,
                format!(
                    "Dependency `{}` in `{}` uses a git source.",
                    dependency.name, dependency.section
                ),
                manifest.file_path.clone(),
                Some(dependency.line),
                Severity::Warning,
                Pillar::Security,
                Confidence::High,
                Some(dependency.name.clone()),
                Some(
                    "Prefer a crates.io release, or pin and review the git dependency.".to_string(),
                ),
                json!({ "section": dependency.section, "git": git }),
            ));
        }
    }
}

fn analyse_path_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if let Some(path) = &dependency.path {
        let rule_id = "dependency.path-source";
        if config.rule_enabled(rule_id) {
            findings.push(Finding::new(
                rule_id,
                format!(
                    "Dependency `{}` in `{}` uses a local path source.",
                    dependency.name, dependency.section
                ),
                manifest.file_path.clone(),
                Some(dependency.line),
                Severity::Advisory,
                Pillar::Security,
                Confidence::High,
                Some(dependency.name.clone()),
                Some("Confirm the path dependency is intentional and available in CI.".to_string()),
                json!({ "section": dependency.section, "path": path }),
            ));
        }
    }
}

fn analyse_wildcard_dependency(
    manifest: &ManifestSummary,
    dependency: &DependencySummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if let Some(requirement) = &dependency.requirement {
        let rule_id = "dependency.wildcard-version";
        if config.rule_enabled(rule_id) && is_wildcard_requirement(requirement) {
            findings.push(Finding::new(
                rule_id,
                format!(
                    "Dependency `{}` in `{}` uses wildcard version `{requirement}`.",
                    dependency.name, dependency.section
                ),
                manifest.file_path.clone(),
                Some(dependency.line),
                Severity::Warning,
                Pillar::Security,
                Confidence::High,
                Some(dependency.name.clone()),
                Some("Use an explicit compatible version requirement.".to_string()),
                json!({ "section": dependency.section, "requirement": requirement }),
            ));
        }
    }
}

fn analyse_lockfile_duplicates(
    lockfile: &LockfileSummary,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "dependency.duplicate-locked-version";
    if !config.rule_enabled(rule_id) {
        return;
    }
    let allowed_versions = config.threshold(rule_id, 1.0) as usize;
    let mut by_name: BTreeMap<&str, Vec<&LockedPackageSummary>> = BTreeMap::new();
    for package in &lockfile.packages {
        by_name.entry(&package.name).or_default().push(package);
    }

    for (name, packages) in by_name {
        let versions: BTreeSet<&str> = packages
            .iter()
            .map(|package| package.version.as_str())
            .collect();
        if versions.len() <= allowed_versions {
            continue;
        }
        let first_line = packages
            .iter()
            .map(|package| package.line)
            .min()
            .unwrap_or(1);
        let versions: Vec<&str> = versions.into_iter().collect();
        findings.push(Finding::new(
            rule_id,
            format!(
                "Package `{name}` is locked at {} versions, above the threshold of {allowed_versions}.",
                versions.len()
            ),
            lockfile.file_path.clone(),
            Some(first_line),
            config.severity(rule_id, Severity::Advisory),
            Pillar::Security,
            Confidence::High,
            Some(name.to_string()),
            Some("Align dependency requirements so Cargo can resolve a single version when possible.".to_string()),
            json!({ "versions": versions }),
        ));
    }
}

fn is_missing_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

fn is_wildcard_requirement(requirement: &str) -> bool {
    requirement
        .split(',')
        .any(|part| part.trim() == "*" || part.trim().ends_with(".*"))
}

fn analyse_source(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    let mut findings = built_in_rules::analyse(unit, config);
    findings.extend(custom_rules::analyse(unit, config));
    findings
}

mod built_in_rules {
    use super::*;

    struct RegexRule {
        rule_id: &'static str,
        regex: &'static OnceLock<Regex>,
        pattern: &'static str,
        message: &'static str,
    }

    static AWS_ACCESS_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
    static PRIVATE_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
    static JWT_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
    static DATABASE_URL_PASSWORD_REGEX: OnceLock<Regex> = OnceLock::new();
    static API_KEY_PATTERN_REGEX: OnceLock<Regex> = OnceLock::new();

    const SENSITIVE_PATTERNS: &[RegexRule] = &[
        RegexRule {
            rule_id: "sensitive-data.aws-access-key",
            regex: &AWS_ACCESS_KEY_REGEX,
            pattern: r"AKIA[0-9A-Z]{16}",
            message: "AWS access key pattern detected.",
        },
        RegexRule {
            rule_id: "sensitive-data.private-key",
            regex: &PRIVATE_KEY_REGEX,
            pattern: r"BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY",
            message: "Private key block detected.",
        },
        RegexRule {
            rule_id: "sensitive-data.jwt-token",
            regex: &JWT_TOKEN_REGEX,
            pattern: r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            message: "JWT-looking token detected.",
        },
        RegexRule {
            rule_id: "sensitive-data.database-url-password",
            regex: &DATABASE_URL_PASSWORD_REGEX,
            pattern: r"[a-z]+://[^:\s]+:[^@\s]+@",
            message: "Database URL appears to include a password.",
        },
        RegexRule {
            rule_id: "sensitive-data.api-key-pattern",
            regex: &API_KEY_PATTERN_REGEX,
            pattern: r"(sk_(?:live|test)_[A-Za-z0-9]{16,}|pk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{32,}|Endpoint=sb://[^;\s]+;[^\s]*SharedAccessKey=[A-Za-z0-9+/=]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})",
            message: "API key pattern detected.",
        },
    ];

    static TEST_ASSERTION_REGEX: OnceLock<Regex> = OnceLock::new();
    static SLEEP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();
    static LOOP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();
    static CONDITIONAL_LOGIC_REGEX: OnceLock<Regex> = OnceLock::new();
    static UNWRAP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();
    static PROCESS_COMMAND_REGEX: OnceLock<Regex> = OnceLock::new();
    static PANIC_MACRO_REGEX: OnceLock<Regex> = OnceLock::new();
    static PLACEHOLDER_MACRO_REGEX: OnceLock<Regex> = OnceLock::new();
    static UNWRAP_EXPECT_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
    static UNSAFE_BLOCK_REGEX: OnceLock<Regex> = OnceLock::new();
    static CLONE_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
    static VARIABLE_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    static ENV_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
    static HIGH_ENTROPY_STRING_REGEX: OnceLock<Regex> = OnceLock::new();
    static CYCLOMATIC_COMPLEXITY_REGEX: OnceLock<Regex> = OnceLock::new();
    static NPATH_BRANCH_REGEX: OnceLock<Regex> = OnceLock::new();
    static NPATH_BOOLEAN_REGEX: OnceLock<Regex> = OnceLock::new();
    static METRIC_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
    static LOOP_START_REGEX: OnceLock<Regex> = OnceLock::new();
    static PERF_REGEX_IN_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
    static PERF_FORMAT_IN_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
    static PERF_CLONE_IN_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
    static UNBOUNDED_CHANNEL_REGEX: OnceLock<Regex> = OnceLock::new();
    static LOCK_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    static UNREACHABLE_TERMINATOR_REGEX: OnceLock<Regex> = OnceLock::new();
    static NON_WHITESPACE_REGEX: OnceLock<Regex> = OnceLock::new();
    static TRIVIAL_ASSERT_REGEX: OnceLock<Regex> = OnceLock::new();
    static SAME_LITERAL_ASSERT_REGEX: OnceLock<Regex> = OnceLock::new();

    const TEST_CHECKS: &[RegexRule] = &[
        RegexRule {
            rule_id: "test-quality.sleep-in-test",
            regex: &SLEEP_IN_TEST_REGEX,
            pattern: r"(std::thread::sleep|tokio::time::sleep)",
            message: "Test sleeps instead of synchronising on behaviour.",
        },
        RegexRule {
            rule_id: "test-quality.loop-in-test",
            regex: &LOOP_IN_TEST_REGEX,
            pattern: r"\b(for|while|loop)\b",
            message: "Test contains loop logic.",
        },
        RegexRule {
            rule_id: "test-quality.conditional-logic",
            regex: &CONDITIONAL_LOGIC_REGEX,
            pattern: r"\b(if|match)\b",
            message: "Test contains conditional logic.",
        },
        RegexRule {
            rule_id: "test-quality.unwrap-in-test",
            regex: &UNWRAP_IN_TEST_REGEX,
            pattern: r"\.unwrap\(\)",
            message: "Test uses unwrap(), which can hide setup intent.",
        },
    ];

    /// Run enabled text and Rust rules for one parsed source unit.
    pub(crate) fn analyse(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        analyse_text_rules(unit.file, unit.source, unit.rust_ast, config, &mut findings);
        if let Some(ast) = unit.rust_ast {
            analyse_rust_rules(unit.file, unit.source, ast, config, &mut findings);
        }
        findings
            .into_iter()
            .filter(|finding| config.rule_enabled(&finding.rule_id))
            .collect()
    }

    fn analyse_text_rules(
        file: &SourceFile,
        source: &str,
        rust_ast: Option<&syn::File>,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let line_count = source.lines().count();
        let rule_id = "size.file-length";
        let threshold = config.threshold(rule_id, 600.0) as usize;
        if line_count > threshold {
            findings.push(finding(
                rule_id,
                format!("File has {line_count} lines, above the threshold of {threshold}."),
                file,
                Some(1),
                config.severity(rule_id, Severity::Warning),
                Pillar::Size,
            ));
        }

        let todo_count = source.matches("TODO").count() + source.matches("FIXME").count();
        let rule_id = "docs.todo-density";
        if todo_count >= config.threshold(rule_id, 4.0) as usize {
            findings.push(finding(
                rule_id,
                format!("File contains {todo_count} TODO/FIXME markers."),
                file,
                Some(first_matching_line(source, "TODO").unwrap_or(1)),
                config.severity(rule_id, Severity::Advisory),
                Pillar::Documentation,
            ));
        }

        analyse_sensitive_data(file, source, rust_ast, config, findings);
    }

    fn analyse_sensitive_data(
        file: &SourceFile,
        source: &str,
        rust_ast: Option<&syn::File>,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        for rule in SENSITIVE_PATTERNS {
            for capture in static_regex(rule.regex, rule.pattern).find_iter(source) {
                let preview = redact(capture.as_str());
                if config.secret_previews.contains(&preview) {
                    continue;
                }
                findings.push(Finding::new(
                    rule.rule_id,
                    rule.message,
                    file.display_path.clone(),
                    Some(byte_line(source, capture.start())),
                    Severity::Error,
                    Pillar::SensitiveData,
                    Confidence::High,
                    None,
                    Some("Remove the secret and load it from a secure runtime source.".to_string()),
                    json!({ "preview": preview }),
                ));
            }
        }

        analyse_env_like_secrets(file, source, rust_ast, config, findings);
        analyse_high_entropy_strings(file, source, config, findings);
    }

    fn analyse_env_like_secrets(
        file: &SourceFile,
        source: &str,
        rust_ast: Option<&syn::File>,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let regex = static_regex(
            &ENV_LIKE_SECRET_REGEX,
            r#"\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|DATABASE_URL)[A-Z0-9_]*\s*=\s*["']?([^"'\s]+)"#,
        );
        let test_ranges = rust_ast.map(test_context_line_ranges).unwrap_or_default();

        for capture in regex.find_iter(source) {
            let line = byte_line(source, capture.start());
            if line_in_ranges(line, &test_ranges) {
                continue;
            }
            let preview = redact(capture.as_str());
            if config.secret_previews.contains(&preview) {
                continue;
            }
            findings.push(Finding::new(
                "sensitive-data.hardcoded-env-value",
                "Hardcoded environment-style secret assignment detected.",
                file.display_path.clone(),
                Some(line),
                Severity::Error,
                Pillar::SensitiveData,
                Confidence::High,
                None,
                Some(
                    "Load secret values from runtime configuration instead of source.".to_string(),
                ),
                json!({ "preview": preview }),
            ));
        }
    }

    fn test_context_line_ranges(ast: &syn::File) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        for item in &ast.items {
            collect_test_context_line_ranges(item, false, &mut ranges);
        }
        ranges
    }

    fn collect_test_context_line_ranges(
        item: &Item,
        test_context: bool,
        ranges: &mut Vec<(usize, usize)>,
    ) {
        match item {
            Item::Fn(item_fn) => collect_function_test_range(item, item_fn, test_context, ranges),
            Item::Impl(item_impl) => {
                collect_impl_test_ranges(item, item_impl, test_context, ranges)
            }
            Item::Mod(item_mod) => collect_module_test_ranges(item, item_mod, test_context, ranges),
            _ => {
                if test_context {
                    push_item_line_range(item, ranges);
                }
            }
        }
    }

    fn collect_function_test_range(
        item: &Item,
        item_fn: &syn::ItemFn,
        test_context: bool,
        ranges: &mut Vec<(usize, usize)>,
    ) {
        if test_context || has_test_attr(&item_fn.attrs) || has_cfg_test_attr(&item_fn.attrs) {
            push_item_line_range(item, ranges);
        }
    }

    fn collect_impl_test_ranges(
        item: &Item,
        item_impl: &syn::ItemImpl,
        test_context: bool,
        ranges: &mut Vec<(usize, usize)>,
    ) {
        let item_test_context =
            test_context || has_test_attr(&item_impl.attrs) || has_cfg_test_attr(&item_impl.attrs);
        if item_test_context {
            push_item_line_range(item, ranges);
        }
        for impl_item in &item_impl.items {
            if let ImplItem::Fn(method) = impl_item {
                collect_impl_method_test_range(method, item_test_context, ranges);
            }
        }
    }

    fn collect_impl_method_test_range(
        method: &syn::ImplItemFn,
        item_test_context: bool,
        ranges: &mut Vec<(usize, usize)>,
    ) {
        if item_test_context || has_test_attr(&method.attrs) || has_cfg_test_attr(&method.attrs) {
            push_span_line_range(method.span(), ranges);
        }
    }

    fn collect_module_test_ranges(
        item: &Item,
        item_mod: &syn::ItemMod,
        test_context: bool,
        ranges: &mut Vec<(usize, usize)>,
    ) {
        let item_test_context = test_context || is_test_module(item_mod);
        if item_test_context {
            push_item_line_range(item, ranges);
        }
        if let Some((_, items)) = &item_mod.content {
            for nested in items {
                collect_test_context_line_ranges(nested, item_test_context, ranges);
            }
        }
    }

    fn push_item_line_range(item: &Item, ranges: &mut Vec<(usize, usize)>) {
        push_span_line_range(item.span(), ranges);
    }

    fn push_span_line_range(span: proc_macro2::Span, ranges: &mut Vec<(usize, usize)>) {
        let start = line_from_span(span.start());
        let end = line_from_span(span.end()).max(start);
        ranges.push((start, end));
    }

    fn line_in_ranges(line: usize, ranges: &[(usize, usize)]) -> bool {
        ranges
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&line))
    }

    fn analyse_high_entropy_strings(
        file: &SourceFile,
        source: &str,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let regex = static_regex(
            &HIGH_ENTROPY_STRING_REGEX,
            r#""([A-Za-z0-9+/=_-]{32,})"|'([A-Za-z0-9+/=_-]{32,})'"#,
        );

        for captures in regex.captures_iter(source) {
            let Some(secret) = captures.get(1).or_else(|| captures.get(2)) else {
                continue;
            };
            let value = secret.as_str();
            if !looks_high_entropy(value) {
                continue;
            }
            let preview = redact(value);
            if config.secret_previews.contains(&preview) {
                continue;
            }
            findings.push(Finding::new(
                "sensitive-data.high-entropy-string",
                "High-entropy string literal detected.",
                file.display_path.clone(),
                Some(byte_line(source, secret.start())),
                Severity::Error,
                Pillar::SensitiveData,
                Confidence::Medium,
                None,
                Some("Move generated secrets to a secure runtime secret source.".to_string()),
                json!({ "preview": preview, "entropy": shannon_entropy(value) }),
            ));
        }
    }

    fn analyse_rust_rules(
        file: &SourceFile,
        source: &str,
        ast: &syn::File,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let blocks = rust_function_blocks(ast, source);
        analyse_blocks(file, &blocks, config, findings);
        analyse_process_commands(file, source, findings);
        analyse_line_rules(file, source, config, findings);
        analyse_item_rules(file, ast, findings);
        analyse_dead_code(file, ast, source, findings);
    }

    fn analyse_blocks(
        file: &SourceFile,
        blocks: &[FunctionBlock],
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        for block in blocks {
            analyse_block(file, block, config, findings);
        }
    }

    fn analyse_block(
        file: &SourceFile,
        block: &FunctionBlock,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let searchable_body = strip_rust_string_literals(&block.body);
        if block.is_test {
            analyse_test_block(file, block, config, findings);
        }
        if block.is_test_context() {
            return;
        }

        analyse_block_size(file, block, config, findings);
        let cyclomatic = analyse_block_complexity(file, block, &searchable_body, config, findings);
        analyse_metric_block(file, block, &searchable_body, cyclomatic, config, findings);
        analyse_performance_block(file, block, &searchable_body, findings);
        analyse_design_block(file, block, cyclomatic, findings);
        analyse_block_naming(file, block, findings);
        analyse_public_function_doc(file, block, findings);
        analyse_error_handling_block(file, block, &searchable_body, findings);
        analyse_concurrency_block(file, block, &searchable_body, findings);
    }

    fn analyse_block_size(
        file: &SourceFile,
        block: &FunctionBlock,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let rule_id = "size.function-length";
        let threshold = config.threshold(rule_id, 50.0) as usize;
        if block.line_count > threshold {
            findings.push(block_finding(
                rule_id,
                format!(
                    "Function `{}` has {} lines, above the threshold of {threshold}.",
                    block.name, block.line_count
                ),
                file,
                block,
                config.severity(rule_id, Severity::Warning),
                Pillar::Size,
            ));
        }

        let params = block.param_count;
        let rule_id = "size.parameter-count";
        if params > config.threshold(rule_id, 5.0) as usize {
            findings.push(block_finding(
                rule_id,
                format!("Function `{}` declares {params} parameters.", block.name),
                file,
                block,
                config.severity(rule_id, Severity::Warning),
                Pillar::Size,
            ));
        }
    }

    fn analyse_block_complexity(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) -> usize {
        let cyclomatic = count_regex(
            searchable_body,
            static_regex(
                &CYCLOMATIC_COMPLEXITY_REGEX,
                r"\b(if|else if|match|for|while|loop)\b|\?|&&|\|\|",
            ),
        ) + 1;
        analyse_cyclomatic_complexity(file, block, cyclomatic, config, findings);
        let nesting = max_nesting_depth(searchable_body);
        analyse_nesting_depth(file, block, nesting, config, findings);
        analyse_npath_complexity(
            file,
            block,
            approximate_npath(searchable_body),
            config,
            findings,
        );
        analyse_cognitive_complexity(file, block, cyclomatic, nesting, config, findings);
        cyclomatic
    }

    fn analyse_cyclomatic_complexity(
        file: &SourceFile,
        block: &FunctionBlock,
        cyclomatic: usize,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let rule_id = "complexity.cyclomatic";
        if cyclomatic <= config.threshold(rule_id, 10.0) as usize {
            return;
        }
        findings.push(block_finding_with_metadata(
            rule_id,
            format!(
                "Function `{}` has cyclomatic complexity {cyclomatic}.",
                block.name
            ),
            file,
            block,
            config.severity(rule_id, Severity::Warning),
            Pillar::Complexity,
            json!({ "complexity": cyclomatic }),
        ));
    }

    fn analyse_nesting_depth(
        file: &SourceFile,
        block: &FunctionBlock,
        nesting: usize,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let rule_id = "complexity.nesting-depth";
        if nesting <= config.threshold(rule_id, 4.0) as usize {
            return;
        }
        findings.push(block_finding_with_metadata(
            rule_id,
            format!("Function `{}` has nesting depth {nesting}.", block.name),
            file,
            block,
            config.severity(rule_id, Severity::Warning),
            Pillar::Complexity,
            json!({ "nestingDepth": nesting }),
        ));
    }

    fn analyse_npath_complexity(
        file: &SourceFile,
        block: &FunctionBlock,
        npath: usize,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let rule_id = "complexity.npath";
        if npath <= config.threshold(rule_id, 100.0) as usize {
            return;
        }
        findings.push(block_finding_with_extras(
            rule_id,
            format!(
                "Function `{}` has approximate NPath complexity {npath}.",
                block.name
            ),
            file,
            block,
            config.severity(rule_id, Severity::Warning),
            Pillar::Complexity,
            BlockFindingExtras {
                confidence: Confidence::Medium,
                remediation: None,
                metadata: json!({ "npath": npath, "approximation": "branch-doubling" }),
            },
        ));
    }

    fn analyse_cognitive_complexity(
        file: &SourceFile,
        block: &FunctionBlock,
        cyclomatic: usize,
        nesting: usize,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let cognitive = cyclomatic + nesting.saturating_mul(2);
        let rule_id = "complexity.cognitive";
        if cognitive <= config.threshold(rule_id, 15.0) as usize {
            return;
        }
        findings.push(block_finding_with_metadata(
            rule_id,
            format!(
                "Function `{}` has cognitive complexity {cognitive}.",
                block.name
            ),
            file,
            block,
            config.severity(rule_id, Severity::Warning),
            Pillar::Complexity,
            json!({ "complexity": cognitive, "cyclomatic": cyclomatic, "nestingDepth": nesting }),
        ));
    }

    fn analyse_design_block(
        file: &SourceFile,
        block: &FunctionBlock,
        cyclomatic: usize,
        findings: &mut Vec<Finding>,
    ) {
        if block.line_count > 45 && cyclomatic > 10 {
            findings.push(block_finding(
                "design.god-function",
                format!("Function `{}` is both long and complex.", block.name),
                file,
                block,
                Severity::Warning,
                Pillar::Design,
            ));
        }
    }

    fn analyse_block_naming(file: &SourceFile, block: &FunctionBlock, findings: &mut Vec<Finding>) {
        if is_generic_name(&block.name) {
            findings.push(block_finding(
                "naming.generic-function",
                format!(
                    "Function `{}` is too generic to explain intent.",
                    block.name
                ),
                file,
                block,
                Severity::Advisory,
                Pillar::Naming,
            ));
        }
        analyse_boolean_block_name(file, block, findings);
        analyse_placeholder_block_name(file, block, findings);
    }

    fn analyse_boolean_block_name(
        file: &SourceFile,
        block: &FunctionBlock,
        findings: &mut Vec<Finding>,
    ) {
        if block.returns_bool && !is_boolean_predicate_name(&block.name) {
            findings.push(block_finding(
                "naming.boolean-prefix",
                format!(
                    "Boolean function `{}` should read like a predicate.",
                    block.name
                ),
                file,
                block,
                Severity::Advisory,
                Pillar::Naming,
            ));
        }
    }

    fn analyse_placeholder_block_name(
        file: &SourceFile,
        block: &FunctionBlock,
        findings: &mut Vec<Finding>,
    ) {
        if is_placeholder_identifier(&block.name) {
            findings.push(block_finding_with_extras(
                "naming.placeholder-identifier",
                format!(
                    "Function `{}` uses a placeholder name instead of domain language.",
                    block.name
                ),
                file,
                block,
                Severity::Advisory,
                Pillar::Naming,
                BlockFindingExtras {
                    confidence: Confidence::Medium,
                    remediation: None,
                    metadata: json!({}),
                },
            ));
        }
    }

    fn analyse_public_function_doc(
        file: &SourceFile,
        block: &FunctionBlock,
        findings: &mut Vec<Finding>,
    ) {
        if block.is_public && !has_doc_comment_before(&block.body) {
            findings.push(block_finding(
                "docs.missing-public-doc",
                format!(
                    "Public function `{}` is missing a Rust doc comment.",
                    block.name
                ),
                file,
                block,
                Severity::Advisory,
                Pillar::Documentation,
            ));
        }
    }

    fn analyse_error_handling_block(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        analyse_panic_block(file, block, searchable_body, findings);
        analyse_placeholder_block(file, block, searchable_body, findings);
        analyse_public_unwrap_block(file, block, searchable_body, findings);
    }

    fn analyse_panic_block(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        let has_panic =
            static_regex(&PANIC_MACRO_REGEX, r"\bpanic!\s*\(").is_match(searchable_body);
        if has_panic && !has_nearby_invariant_comment(searchable_body) {
            findings.push(block_finding_with_extras(
                "error-handling.production-panic",
                format!(
                    "Function `{}` calls panic! in production code.",
                    block.name
                ),
                file,
                block,
                Severity::Warning,
                Pillar::Waste,
                BlockFindingExtras {
                    confidence: Confidence::High,
                    remediation: Some(
                        "Return an error or document the invariant that makes the panic unreachable."
                            .to_string(),
                    ),
                    metadata: json!({ "macro": "panic!" }),
                },
            ));
        }
    }

    fn analyse_placeholder_block(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        if static_regex(&PLACEHOLDER_MACRO_REGEX, r"\b(todo!|unimplemented!)\s*\(")
            .is_match(searchable_body)
        {
            findings.push(block_finding_with_extras(
                "error-handling.unimplemented-placeholder",
                format!(
                    "Function `{}` contains todo!/unimplemented! placeholder code.",
                    block.name
                ),
                file,
                block,
                Severity::Warning,
                Pillar::Waste,
                BlockFindingExtras {
                    confidence: Confidence::High,
                    remediation: Some(
                        "Replace the placeholder with implemented behavior before shipping."
                            .to_string(),
                    ),
                    metadata: json!({ "macros": ["todo!", "unimplemented!"] }),
                },
            ));
        }
    }

    fn analyse_public_unwrap_block(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        let has_unwrap = static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(")
            .is_match(searchable_body);
        if block.is_public && has_unwrap {
            findings.push(block_finding_with_extras(
                "error-handling.public-unwrap",
                format!(
                    "Public function `{}` uses unwrap()/expect() in its implementation.",
                    block.name
                ),
                file,
                block,
                Severity::Warning,
                Pillar::Waste,
                BlockFindingExtras {
                    confidence: Confidence::High,
                    remediation: Some(
                        "Return a Result or map the failure into the public API contract."
                            .to_string(),
                    ),
                    metadata: json!({}),
                },
            ));
        }
    }

    fn analyse_metric_block(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        cyclomatic: usize,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let metrics = function_metrics(searchable_body, cyclomatic);
        analyse_halstead_volume(file, block, &metrics, config, findings);
        analyse_maintainability_pressure(file, block, &metrics, cyclomatic, config, findings);
    }

    fn analyse_halstead_volume(
        file: &SourceFile,
        block: &FunctionBlock,
        metrics: &FunctionMetrics,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let volume_threshold = config.threshold("metrics.halstead-volume", 1500.0);
        if metrics.halstead_volume > volume_threshold {
            let rule_id = "metrics.halstead-volume";
            findings.push(block_finding_with_extras(
                rule_id,
                format!(
                    "Function `{}` has Halstead-style volume {:.1}, above the threshold of {:.1}.",
                    block.name, metrics.halstead_volume, volume_threshold
                ),
                file,
                block,
                config.severity(rule_id, Severity::Advisory),
                Pillar::Complexity,
                BlockFindingExtras {
                    confidence: Confidence::Medium,
                    remediation: Some(
                        "Split dense logic into smaller functions with simpler token flow."
                            .to_string(),
                    ),
                    metadata: json!({
                        "totalTokens": metrics.total_tokens,
                        "uniqueTokens": metrics.unique_tokens,
                        "halsteadVolume": round1(metrics.halstead_volume),
                        "threshold": volume_threshold
                    }),
                },
            ));
        }
    }

    fn analyse_maintainability_pressure(
        file: &SourceFile,
        block: &FunctionBlock,
        metrics: &FunctionMetrics,
        cyclomatic: usize,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let minimum_score = config.threshold("metrics.maintainability-pressure", 45.0);
        if metrics.maintainability_score < minimum_score {
            let rule_id = "metrics.maintainability-pressure";
            findings.push(block_finding_with_extras(
                rule_id,
                format!(
                    "Function `{}` has maintainability pressure score {:.1}, below the minimum of {:.1}.",
                    block.name, metrics.maintainability_score, minimum_score
                ),
                file,
                block,
                config.severity(rule_id, Severity::Advisory),
                Pillar::Complexity,
                BlockFindingExtras {
                    confidence: Confidence::Medium,
                    remediation: Some(
                        "Reduce line count, branching, or token volume before relying on this function as stable hot-path code."
                            .to_string(),
                    ),
                    metadata: json!({
                        "score": round1(metrics.maintainability_score),
                        "minimum": minimum_score,
                        "totalTokens": metrics.total_tokens,
                        "cyclomatic": cyclomatic,
                        "halsteadVolume": round1(metrics.halstead_volume)
                    }),
                },
            ));
        }
    }

    struct PerformanceCheck {
        rule_id: &'static str,
        regex: &'static OnceLock<Regex>,
        pattern: &'static str,
        severity: Severity,
        confidence: Confidence,
        label: &'static str,
        remediation: &'static str,
    }

    const PERFORMANCE_CHECKS: &[PerformanceCheck] = &[
        PerformanceCheck {
            rule_id: "performance.regex-in-loop",
            regex: &PERF_REGEX_IN_LOOP_REGEX,
            pattern: r"\bRegex::new\s*\(",
            severity: Severity::Warning,
            confidence: Confidence::High,
            label: "Regex::new",
            remediation: "Move regex construction out of the loop or cache the compiled regex.",
        },
        PerformanceCheck {
            rule_id: "performance.format-in-loop",
            regex: &PERF_FORMAT_IN_LOOP_REGEX,
            pattern: r"\bformat!\s*\(",
            severity: Severity::Advisory,
            confidence: Confidence::Medium,
            label: "format!",
            remediation:
                "Reuse buffers or move formatting out of the loop when allocation matters.",
        },
        PerformanceCheck {
            rule_id: "performance.clone-in-loop",
            regex: &PERF_CLONE_IN_LOOP_REGEX,
            pattern: r"\.clone\s*\(",
            severity: Severity::Advisory,
            confidence: Confidence::Medium,
            label: "clone()",
            remediation: "Clone outside the loop or borrow values when ownership permits.",
        },
    ];

    fn analyse_performance_block(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        for check in PERFORMANCE_CHECKS {
            let occurrences =
                loop_pattern_count(searchable_body, static_regex(check.regex, check.pattern));
            if occurrences > 0 {
                push_performance_finding(file, block, check, occurrences, findings);
            }
        }
    }

    fn push_performance_finding(
        file: &SourceFile,
        block: &FunctionBlock,
        check: &PerformanceCheck,
        occurrences: usize,
        findings: &mut Vec<Finding>,
    ) {
        findings.push(block_finding_with_extras(
            check.rule_id,
            format!(
                "Function `{}` calls {} inside a loop {} time(s).",
                block.name, check.label, occurrences
            ),
            file,
            block,
            check.severity,
            Pillar::Waste,
            BlockFindingExtras {
                confidence: check.confidence,
                remediation: Some(check.remediation.to_string()),
                metadata: json!({ "pattern": check.label, "occurrences": occurrences }),
            },
        ));
    }

    fn analyse_concurrency_block(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        if block.is_async {
            analyse_async_blocking_calls(file, block, searchable_body, findings);
            analyse_lock_across_await(file, block, searchable_body, findings);
        }

        if static_regex(
            &UNBOUNDED_CHANNEL_REGEX,
            r"\b(std::sync::mpsc::channel|mpsc::unbounded_channel|unbounded_channel)(?:\s*::\s*<[^>]+>)?\s*\(",
        )
            .is_match(searchable_body)
        {
            findings.push(block_finding_with_extras(
                "concurrency.unbounded-channel",
                format!(
                    "Function `{}` creates an unbounded channel.",
                    block.name
                ),
                file,
                block,
                Severity::Advisory,
                Pillar::Waste,
                BlockFindingExtras {
                    confidence: Confidence::Medium,
                    remediation: Some(
                        "Prefer a bounded channel or document the producer/consumer backpressure policy."
                            .to_string(),
                    ),
                    metadata: json!({ "pattern": "unbounded-channel" }),
                },
            ));
        }
    }

    fn analyse_async_blocking_calls(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        let blocking_patterns = [
            ("std::thread::sleep", "std::thread::sleep"),
            ("std::fs::read_to_string", "std::fs::read_to_string"),
            ("std::fs::read", "std::fs::read"),
            ("std::fs::write", "std::fs::write"),
            ("std::process::Command::new", "std::process::Command::new"),
        ];
        for (pattern, label) in blocking_patterns {
            if searchable_body.contains(pattern) {
                findings.push(block_finding_with_extras(
                    "concurrency.blocking-call-in-async",
                    format!(
                        "Async function `{}` calls blocking API `{label}`.",
                        block.name
                    ),
                    file,
                    block,
                    Severity::Warning,
                    Pillar::Waste,
                    BlockFindingExtras {
                        confidence: Confidence::Medium,
                        remediation: Some(
                            "Use an async equivalent or move blocking work behind a dedicated blocking task."
                                .to_string(),
                        ),
                        metadata: json!({ "pattern": label }),
                    },
                ));
                break;
            }
        }
    }

    fn analyse_lock_across_await(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        let lock_binding = static_regex(
            &LOCK_BINDING_REGEX,
            r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\.(?:lock|read|write)\s*\([^;]*;",
        );
        let lines: Vec<&str> = searchable_body.lines().collect();
        for (line_index, line) in lines.iter().enumerate() {
            let Some(captures) = lock_binding.captures(line) else {
                continue;
            };
            let guard = captures
                .get(1)
                .map(|guard| guard.as_str())
                .unwrap_or("guard");
            let later_lines = &lines[line_index + 1..];
            let dropped_before_await = later_lines
                .iter()
                .take_while(|candidate| !candidate.contains(".await"))
                .any(|candidate| candidate.contains(&format!("drop({guard})")));
            if later_lines
                .iter()
                .any(|candidate| candidate.contains(".await"))
                && !dropped_before_await
            {
                findings.push(block_finding_with_extras(
                    "concurrency.lock-across-await",
                    format!(
                        "Async function `{}` appears to hold lock guard `{guard}` across await.",
                        block.name
                    ),
                    file,
                    block,
                    Severity::Warning,
                    Pillar::Waste,
                    BlockFindingExtras {
                        confidence: Confidence::Medium,
                        remediation: Some(
                            "Drop the guard before awaiting or use an async-aware lock."
                                .to_string(),
                        ),
                        metadata: json!({ "guard": guard }),
                    },
                ));
                break;
            }
        }
    }

    fn analyse_test_block(
        file: &SourceFile,
        block: &FunctionBlock,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        analyse_ignored_test(file, block, findings);
        analyse_test_size(file, block, config, findings);
        let searchable_body = strip_rust_string_literals(&block.body);
        analyse_test_assertions(file, block, &searchable_body, findings);
        analyse_test_regex_checks(file, block, &searchable_body, findings);
    }

    fn analyse_ignored_test(file: &SourceFile, block: &FunctionBlock, findings: &mut Vec<Finding>) {
        if block.ignore_without_reason {
            findings.push(block_finding(
                "test-quality.ignored-without-reason",
                format!(
                    "Ignored test `{}` does not explain why it is skipped.",
                    block.name
                ),
                file,
                block,
                Severity::Advisory,
                Pillar::TestQuality,
            ));
        }
    }

    fn analyse_test_size(
        file: &SourceFile,
        block: &FunctionBlock,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let rule_id = "test-quality.long-test";
        let threshold = config.threshold(rule_id, 80.0) as usize;
        if block.line_count > threshold {
            findings.push(block_finding_with_metadata(
                rule_id,
                format!(
                    "Test `{}` has {} lines, above the threshold of {threshold}.",
                    block.name, block.line_count
                ),
                file,
                block,
                config.severity(rule_id, Severity::Advisory),
                Pillar::TestQuality,
                json!({ "lines": block.line_count }),
            ));
        }
    }

    fn analyse_test_assertions(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        if has_trivial_assertion(searchable_body) {
            findings.push(block_finding(
                "test-quality.trivial-assertion",
                format!("Test `{}` contains a trivial assertion.", block.name),
                file,
                block,
                Severity::Warning,
                Pillar::TestQuality,
            ));
        }

        if !static_regex(
            &TEST_ASSERTION_REGEX,
            r"\b(assert!|assert_eq!|assert_ne!|matches!|panic!|assert_[A-Za-z0-9_]*\s*\()",
        )
        .is_match(searchable_body)
        {
            findings.push(block_finding(
                "test-quality.no-assertions",
                format!(
                    "Test `{}` does not appear to make an assertion.",
                    block.name
                ),
                file,
                block,
                Severity::Warning,
                Pillar::TestQuality,
            ));
        }
    }

    fn analyse_test_regex_checks(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        for rule in TEST_CHECKS {
            if static_regex(rule.regex, rule.pattern).is_match(searchable_body) {
                findings.push(block_finding(
                    rule.rule_id,
                    rule.message,
                    file,
                    block,
                    Severity::Advisory,
                    Pillar::TestQuality,
                ));
            }
        }
    }

    fn analyse_line_rules(
        file: &SourceFile,
        source: &str,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let searchable_source = strip_rust_string_literals(source);
        let lines: Vec<&str> = searchable_source.lines().collect();
        let context = LineRuleContext {
            file,
            lines: &lines,
            config,
        };

        for (line_index, line) in lines.iter().enumerate() {
            context.analyse_line(line_index, line, findings);
        }

        analyse_unreachable(file, &searchable_source, findings);
    }

    struct LineRuleContext<'a> {
        file: &'a SourceFile,
        lines: &'a [&'a str],
        config: &'a Config,
    }

    impl LineRuleContext<'_> {
        fn analyse_line(&self, line_index: usize, line: &str, findings: &mut Vec<Finding>) {
            let line_number = line_index + 1;
            self.analyse_safety_line(line, line_index, line_number, findings);
            self.analyse_waste_line(line, line_number, findings);
            self.analyse_variable_names(line, line_number, findings);
        }

        fn analyse_safety_line(
            &self,
            line: &str,
            line_index: usize,
            line_number: usize,
            findings: &mut Vec<Finding>,
        ) {
            let has_unsafe = static_regex(&UNSAFE_BLOCK_REGEX, r"\bunsafe\s*\{").is_match(line);
            if has_unsafe && !has_nearby_safety_comment(self.lines, line_index) {
                findings.push(finding(
                    "security.unsafe-block",
                    "Unsafe block lacks a nearby SAFETY rationale.",
                    self.file,
                    Some(line_number),
                    Severity::Warning,
                    Pillar::Security,
                ));
            }
        }

        fn analyse_waste_line(&self, line: &str, line_number: usize, findings: &mut Vec<Finding>) {
            if static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(").is_match(line)
                && !line.contains("#[test]")
            {
                findings.push(finding(
                    "waste.unwrap-expect",
                    "unwrap()/expect() can turn recoverable errors into panics.",
                    self.file,
                    Some(line_number),
                    Severity::Advisory,
                    Pillar::Waste,
                ));
            }

            if static_regex(&CLONE_CALL_REGEX, r"\.clone\(\)").is_match(line) {
                findings.push(finding(
                    "waste.unnecessary-clone-candidate",
                    "clone() call may be avoidable; confirm ownership requires it.",
                    self.file,
                    Some(line_number),
                    Severity::Advisory,
                    Pillar::Waste,
                ));
            }
        }

        fn analyse_variable_names(
            &self,
            line: &str,
            line_number: usize,
            findings: &mut Vec<Finding>,
        ) {
            let variable_regex = static_regex(
                &VARIABLE_BINDING_REGEX,
                r"\b(?:let|for)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)",
            );
            for variable in variable_regex
                .captures_iter(line)
                .filter_map(|captures| captures.get(1))
            {
                let name = variable.as_str();
                if is_placeholder_identifier(name) {
                    findings.push(Finding::new(
                        "naming.placeholder-identifier",
                        format!(
                            "Variable `{name}` uses a placeholder name instead of domain language."
                        ),
                        self.file.display_path.clone(),
                        Some(line_number),
                        Severity::Advisory,
                        Pillar::Naming,
                        Confidence::Medium,
                        Some(name.to_string()),
                        Some("Use a name that describes the domain role.".to_string()),
                        json!({}),
                    ));
                }

                if name.len() <= 2
                    && !matches!(name, "i" | "j" | "k")
                    && !name.starts_with('_')
                    && !self
                        .config
                        .accepted_abbreviations
                        .contains(&name.to_ascii_lowercase())
                {
                    findings.push(Finding::new(
                        "naming.short-variable",
                        format!("Variable `{name}` is too short to explain intent."),
                        self.file.display_path.clone(),
                        Some(line_number),
                        Severity::Advisory,
                        Pillar::Naming,
                        Confidence::Medium,
                        Some(name.to_string()),
                        Some("Use a name that describes the domain role.".to_string()),
                        json!({}),
                    ));
                }
            }
        }
    }

    fn analyse_process_commands(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
        let command_regex = static_regex(
            &PROCESS_COMMAND_REGEX,
            r"(std::process::Command|Command)::new\s*\(",
        );
        let searchable = strip_rust_string_literals(source);
        for (line_index, line) in searchable.lines().enumerate() {
            if command_regex.is_match(line) {
                findings.push(finding(
                    "security.process-command",
                    "Process command execution is used; validate command arguments are not user-controlled.",
                    file,
                    Some(line_index + 1),
                    Severity::Warning,
                    Pillar::Security,
                ));
            }
        }
    }

    fn analyse_item_rules(file: &SourceFile, ast: &syn::File, findings: &mut Vec<Finding>) {
        for item in &ast.items {
            analyse_public_item(file, item, findings);
        }
    }

    fn analyse_public_item(file: &SourceFile, item: &Item, findings: &mut Vec<Finding>) {
        match item {
            Item::Mod(item_mod) => analyse_public_module_item(file, item_mod, findings),
            Item::Struct(item_struct) => analyse_public_struct_item(file, item_struct, findings),
            Item::Enum(item_enum) => {
                analyse_public_named_item_doc(
                    file,
                    &item_enum.vis,
                    &item_enum.attrs,
                    item_enum.ident.to_string(),
                    item_enum.ident.span(),
                    findings,
                );
            }
            Item::Trait(item_trait) => {
                analyse_public_named_item_doc(
                    file,
                    &item_trait.vis,
                    &item_trait.attrs,
                    item_trait.ident.to_string(),
                    item_trait.ident.span(),
                    findings,
                );
            }
            _ => {}
        }
    }

    fn analyse_public_module_item(
        file: &SourceFile,
        item_mod: &syn::ItemMod,
        findings: &mut Vec<Finding>,
    ) {
        analyse_public_named_item_doc(
            file,
            &item_mod.vis,
            &item_mod.attrs,
            item_mod.ident.to_string(),
            item_mod.ident.span(),
            findings,
        );
        if let Some((_, items)) = &item_mod.content {
            for nested in items {
                analyse_public_item(file, nested, findings);
            }
        }
    }

    fn analyse_public_struct_item(
        file: &SourceFile,
        item_struct: &syn::ItemStruct,
        findings: &mut Vec<Finding>,
    ) {
        analyse_public_named_item_doc(
            file,
            &item_struct.vis,
            &item_struct.attrs,
            item_struct.ident.to_string(),
            item_struct.ident.span(),
            findings,
        );
        for field in &item_struct.fields {
            if is_public(&field.vis) {
                push_public_field_finding(file, field.span(), findings);
            }
        }
    }

    fn analyse_public_named_item_doc(
        file: &SourceFile,
        visibility: &Visibility,
        attrs: &[syn::Attribute],
        name: String,
        span: proc_macro2::Span,
        findings: &mut Vec<Finding>,
    ) {
        if is_public(visibility) && !has_doc_attr(attrs) {
            push_missing_public_item_doc(file, name, span, findings);
        }
    }

    fn push_public_field_finding(
        file: &SourceFile,
        span: proc_macro2::Span,
        findings: &mut Vec<Finding>,
    ) {
        findings.push(finding(
            "modernisation.public-field",
            "Public struct field exposes representation; prefer accessors when invariants matter.",
            file,
            Some(line_from_span(span.start())),
            Severity::Advisory,
            Pillar::Modernisation,
        ));
    }

    fn push_missing_public_item_doc(
        file: &SourceFile,
        name: String,
        span: proc_macro2::Span,
        findings: &mut Vec<Finding>,
    ) {
        findings.push(Finding::new(
            "docs.missing-public-doc",
            format!("Public item `{name}` is missing a Rust doc comment."),
            file.display_path.clone(),
            Some(line_from_span(span.start())),
            Severity::Advisory,
            Pillar::Documentation,
            Confidence::Medium,
            Some(name),
            Some("Add a /// doc comment explaining the public API contract.".to_string()),
            json!({}),
        ));
    }

    fn analyse_dead_code(
        file: &SourceFile,
        ast: &syn::File,
        source: &str,
        findings: &mut Vec<Finding>,
    ) {
        for item in &ast.items {
            analyse_dead_code_item(file, item, source, false, findings);
        }
    }

    fn analyse_dead_code_item(
        file: &SourceFile,
        item: &Item,
        source: &str,
        test_context: bool,
        findings: &mut Vec<Finding>,
    ) {
        match item {
            Item::Fn(item_fn) => {
                analyse_dead_item_fn(file, item_fn, source, test_context, findings)
            }
            Item::Impl(item_impl) => {
                analyse_dead_impl(file, item_impl, source, test_context, findings)
            }
            Item::Mod(item_mod) => analyse_dead_mod(file, item_mod, source, test_context, findings),
            _ => {}
        }
    }

    fn analyse_dead_item_fn(
        file: &SourceFile,
        item_fn: &syn::ItemFn,
        source: &str,
        test_context: bool,
        findings: &mut Vec<Finding>,
    ) {
        analyse_dead_function(
            file,
            source,
            DeadFunctionCandidate {
                visibility: &item_fn.vis,
                attrs: &item_fn.attrs,
                name: item_fn.sig.ident.to_string(),
                span: item_fn.sig.ident.span(),
                test_context,
            },
            findings,
        );
    }

    fn analyse_dead_impl(
        file: &SourceFile,
        item_impl: &syn::ItemImpl,
        source: &str,
        test_context: bool,
        findings: &mut Vec<Finding>,
    ) {
        for impl_item in &item_impl.items {
            if let ImplItem::Fn(method) = impl_item {
                analyse_dead_impl_method(file, method, source, test_context, findings);
            }
        }
    }

    fn analyse_dead_impl_method(
        file: &SourceFile,
        method: &syn::ImplItemFn,
        source: &str,
        test_context: bool,
        findings: &mut Vec<Finding>,
    ) {
        analyse_dead_function(
            file,
            source,
            DeadFunctionCandidate {
                visibility: &method.vis,
                attrs: &method.attrs,
                name: method.sig.ident.to_string(),
                span: method.sig.ident.span(),
                test_context,
            },
            findings,
        );
    }

    fn analyse_dead_mod(
        file: &SourceFile,
        item_mod: &syn::ItemMod,
        source: &str,
        test_context: bool,
        findings: &mut Vec<Finding>,
    ) {
        let Some((_, items)) = &item_mod.content else {
            return;
        };
        let nested_test_context = test_context || is_test_module(item_mod);
        for nested in items {
            analyse_dead_code_item(file, nested, source, nested_test_context, findings);
        }
    }

    struct DeadFunctionCandidate<'a> {
        visibility: &'a Visibility,
        attrs: &'a [syn::Attribute],
        name: String,
        span: proc_macro2::Span,
        test_context: bool,
    }

    fn analyse_dead_function(
        file: &SourceFile,
        source: &str,
        candidate: DeadFunctionCandidate<'_>,
        findings: &mut Vec<Finding>,
    ) {
        let DeadFunctionCandidate {
            visibility,
            attrs,
            name,
            span,
            test_context,
        } = candidate;
        if is_public(visibility) || name == "main" || has_test_attr(attrs) || test_context {
            return;
        }
        if function_call_count(source, &name) == 0 {
            findings.push(Finding::new(
                "dead-code.unused-private-function",
                format!("Private function `{name}` appears to be unused in this file."),
                file.display_path.clone(),
                Some(line_from_span(span.start())),
                Severity::Advisory,
                Pillar::DeadCode,
                Confidence::Low,
                Some(name),
                Some("Remove the function or add a real call site.".to_string()),
                json!({}),
            ));
        }
    }

    fn function_call_count(source: &str, name: &str) -> usize {
        static CACHE: OnceLock<Mutex<HashMap<String, (Regex, Regex)>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let (call_regex, simple_definition_regex) = {
            let mut guard = cache.lock().expect("function call regex cache");
            guard
                .entry(name.to_string())
                .or_insert_with(|| {
                    let escaped = regex::escape(name);
                    let call = Regex::new(&format!(r"\b{escaped}\s*(?:::\s*<[^>]+>)?\s*\("))
                        .expect("generated function-call regex compiles");
                    let definition = Regex::new(&format!(r"\bfn\s+{escaped}\s*\("))
                        .expect("generated function-definition regex compiles");
                    (call, definition)
                })
                .clone()
        };
        let count = call_regex.find_iter(source).count();
        if simple_definition_regex.is_match(source) {
            count.saturating_sub(1)
        } else {
            count
        }
    }

    fn analyse_unreachable(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
        let terminator = static_regex(
            &UNREACHABLE_TERMINATOR_REGEX,
            r"\b(return|panic!|todo!|unimplemented!)",
        );
        let useful = static_regex(&NON_WHITESPACE_REGEX, r"\S");
        let mut previous_terminated = false;
        for (line_index, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if previous_terminated && useful.is_match(trimmed) && !trimmed.starts_with('}') {
                findings.push(finding(
                    "waste.unreachable-code",
                    "Statement appears after a terminating statement.",
                    file,
                    Some(line_index + 1),
                    Severity::Warning,
                    Pillar::Waste,
                ));
            }
            previous_terminated = terminator.is_match(trimmed) && trimmed.ends_with(';');
        }
    }

    fn rust_function_blocks(ast: &syn::File, source: &str) -> Vec<FunctionBlock> {
        let lines: Vec<&str> = source.lines().collect();
        let mut blocks = Vec::new();

        for item in &ast.items {
            collect_function_blocks(item, &lines, false, &mut blocks);
        }

        blocks
    }

    fn collect_function_blocks(
        item: &Item,
        lines: &[&str],
        test_context: bool,
        blocks: &mut Vec<FunctionBlock>,
    ) {
        match item {
            Item::Fn(item_fn) => push_item_function_block(item_fn, lines, test_context, blocks),
            Item::Impl(item_impl) => {
                push_impl_function_blocks(item_impl, lines, test_context, blocks)
            }
            Item::Mod(item_mod) => {
                collect_module_function_blocks(item_mod, lines, test_context, blocks)
            }
            _ => {}
        }
    }

    fn push_item_function_block(
        item_fn: &syn::ItemFn,
        lines: &[&str],
        test_context: bool,
        blocks: &mut Vec<FunctionBlock>,
    ) {
        blocks.push(function_block_from_parts(FunctionBlockParts {
            lines,
            name: item_fn.sig.ident.to_string(),
            param_count: count_params(&item_fn.sig.inputs),
            visibility: &item_fn.vis,
            attrs: &item_fn.attrs,
            test_context,
            is_async: item_fn.sig.asyncness.is_some(),
            returns_bool: returns_bool(&item_fn.sig.output),
            name_start: item_fn.sig.ident.span().start(),
            block_end: item_fn.block.span().end(),
        }));
    }

    fn push_impl_function_blocks(
        item_impl: &syn::ItemImpl,
        lines: &[&str],
        test_context: bool,
        blocks: &mut Vec<FunctionBlock>,
    ) {
        for impl_item in &item_impl.items {
            if let ImplItem::Fn(method) = impl_item {
                push_impl_method_function_block(method, lines, test_context, blocks);
            }
        }
    }

    fn push_impl_method_function_block(
        method: &syn::ImplItemFn,
        lines: &[&str],
        test_context: bool,
        blocks: &mut Vec<FunctionBlock>,
    ) {
        blocks.push(function_block_from_parts(FunctionBlockParts {
            lines,
            name: method.sig.ident.to_string(),
            param_count: count_params(&method.sig.inputs),
            visibility: &method.vis,
            attrs: &method.attrs,
            test_context,
            is_async: method.sig.asyncness.is_some(),
            returns_bool: returns_bool(&method.sig.output),
            name_start: method.sig.ident.span().start(),
            block_end: method.block.span().end(),
        }));
    }

    fn collect_module_function_blocks(
        item_mod: &syn::ItemMod,
        lines: &[&str],
        test_context: bool,
        blocks: &mut Vec<FunctionBlock>,
    ) {
        let Some((_, items)) = &item_mod.content else {
            return;
        };
        let nested_test_context = test_context || is_test_module(item_mod);
        for nested in items {
            collect_function_blocks(nested, lines, nested_test_context, blocks);
        }
    }

    struct FunctionBlockParts<'a> {
        lines: &'a [&'a str],
        name: String,
        param_count: usize,
        visibility: &'a Visibility,
        attrs: &'a [syn::Attribute],
        test_context: bool,
        is_async: bool,
        returns_bool: bool,
        name_start: LineColumn,
        block_end: LineColumn,
    }

    fn function_block_from_parts(parts: FunctionBlockParts<'_>) -> FunctionBlock {
        let function_index = line_from_span(parts.name_start).saturating_sub(1);
        let start = function_start_index(parts.lines, function_index);
        let end = line_from_span(parts.block_end)
            .saturating_sub(1)
            .min(parts.lines.len().saturating_sub(1))
            .max(start);
        let body = line_slice(parts.lines, start, end);
        let is_test = has_test_attr(parts.attrs);

        FunctionBlock {
            name: parts.name,
            param_count: parts.param_count,
            start_line: start + 1,
            line_count: end.saturating_sub(start) + 1,
            body,
            is_public: is_public(parts.visibility),
            is_test,
            test_context: parts.test_context,
            is_async: parts.is_async,
            returns_bool: parts.returns_bool,
            ignore_without_reason: has_ignore_without_reason(parts.attrs),
        }
    }

    fn function_start_index(lines: &[&str], index: usize) -> usize {
        let mut start = index;
        while start > 0 {
            let previous = lines[start - 1].trim();
            if previous.starts_with("#[") || previous.starts_with("///") || previous.is_empty() {
                start -= 1;
                continue;
            }
            break;
        }
        start
    }

    fn line_slice(lines: &[&str], start: usize, end: usize) -> String {
        if lines.is_empty() {
            return String::new();
        }
        lines[start..=end].join("\n")
    }

    fn count_params(inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> usize {
        inputs
            .iter()
            .filter(|input| !matches!(input, FnArg::Receiver(_)))
            .count()
    }

    fn returns_bool(output: &ReturnType) -> bool {
        let ReturnType::Type(_, ty) = output else {
            return false;
        };
        let Type::Path(path) = ty.as_ref() else {
            return false;
        };
        path.path.is_ident("bool")
    }

    fn is_public(visibility: &Visibility) -> bool {
        !matches!(visibility, Visibility::Inherited)
    }

    fn has_doc_attr(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident("doc"))
    }

    fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident("test"))
    }

    fn has_ignore_without_reason(attrs: &[syn::Attribute]) -> bool {
        attrs
            .iter()
            .filter(|attr| attr.path().is_ident("ignore"))
            .any(|attr| match &attr.meta {
                syn::Meta::Path(_) => true,
                syn::Meta::List(list) => list.tokens.is_empty(),
                syn::Meta::NameValue(value) => match &value.value {
                    syn::Expr::Lit(lit) => match &lit.lit {
                        syn::Lit::Str(reason) => reason.value().trim().is_empty(),
                        _ => true,
                    },
                    _ => true,
                },
            })
    }

    fn has_doc_comment_before(block: &str) -> bool {
        block
            .lines()
            .take_while(|line| !line.contains("fn "))
            .any(|line| line.trim_start().starts_with("///"))
    }

    fn is_generic_name(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "process" | "handle" | "do_it" | "run" | "execute" | "manage"
        )
    }

    fn is_boolean_predicate_name(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            lower if lower.starts_with("is_")
                || lower.starts_with("has_")
                || lower.starts_with("can_")
                || lower.starts_with("should_")
                || lower.starts_with("allows_")
                || lower.starts_with("supports_")
                || lower.starts_with("contains_")
                || lower.starts_with("needs_")
                || lower.starts_with("uses_")
        )
    }

    fn is_placeholder_identifier(name: &str) -> bool {
        matches!(name, "foo" | "bar" | "baz" | "qux")
    }

    pub(super) fn strip_rust_string_literals(source: &str) -> String {
        let bytes = source.as_bytes();
        let mut output = String::with_capacity(source.len());
        let mut index = 0usize;

        while index < bytes.len() {
            if let Some(raw_end) = raw_string_end(bytes, index) {
                mask_bytes(bytes, index, raw_end, &mut output);
                index = raw_end;
                continue;
            }

            if bytes[index] == b'"' {
                output.push(' ');
                index += 1;
                while index < bytes.len() {
                    let byte = bytes[index];
                    mask_byte(byte, &mut output);
                    index += 1;
                    if byte == b'\\' && index < bytes.len() {
                        mask_byte(bytes[index], &mut output);
                        index += 1;
                        continue;
                    }
                    if byte == b'"' {
                        break;
                    }
                }
                continue;
            }

            output.push(bytes[index] as char);
            index += 1;
        }

        output
    }

    pub(super) fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
        let (hashes, cursor) = raw_string_opening(bytes, start)?;
        find_raw_string_end(bytes, hashes, cursor).or(Some(bytes.len()))
    }

    fn raw_string_opening(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
        (bytes.get(start).copied()? == b'r').then_some(())?;
        let mut cursor = start + 1;
        let hashes = count_raw_string_hashes(bytes, &mut cursor);
        (bytes.get(cursor) == Some(&b'"')).then_some((hashes, cursor + 1))
    }

    fn count_raw_string_hashes(bytes: &[u8], cursor: &mut usize) -> usize {
        let mut hashes = 0usize;
        while bytes.get(*cursor) == Some(&b'#') {
            hashes += 1;
            *cursor += 1;
        }
        hashes
    }

    fn find_raw_string_end(bytes: &[u8], hashes: usize, mut cursor: usize) -> Option<usize> {
        while cursor < bytes.len() {
            if bytes[cursor] == b'"' && raw_string_hashes_match(bytes, cursor + 1, hashes) {
                return Some(cursor + 1 + hashes);
            }
            cursor += 1;
        }
        None
    }

    fn raw_string_hashes_match(bytes: &[u8], start: usize, hashes: usize) -> bool {
        bytes
            .get(start..start + hashes)
            .is_some_and(|slice| slice.iter().all(|byte| *byte == b'#'))
    }

    fn mask_bytes(bytes: &[u8], start: usize, end: usize, output: &mut String) {
        for byte in &bytes[start..end] {
            mask_byte(*byte, output);
        }
    }

    fn mask_byte(byte: u8, output: &mut String) {
        if byte == b'\n' {
            output.push('\n');
        } else {
            output.push(' ');
        }
    }

    fn max_nesting_depth(source: &str) -> usize {
        let mut depth = 0usize;
        let mut max_depth = 0usize;
        for character in source.chars() {
            match character {
                '{' => {
                    depth += 1;
                    max_depth = max_depth.max(depth);
                }
                '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        max_depth.saturating_sub(1)
    }

    fn approximate_npath(source: &str) -> usize {
        let branch_decisions = count_regex(
            source,
            static_regex(&NPATH_BRANCH_REGEX, r"\b(if|match|for|while|loop)\b"),
        );
        let boolean_decisions =
            count_regex(source, static_regex(&NPATH_BOOLEAN_REGEX, r"&&|\|\||\?"));
        let mut paths = 1usize;
        for _ in 0..branch_decisions.min(20) {
            paths = paths.saturating_mul(2);
        }
        paths.saturating_add(boolean_decisions)
    }

    fn function_metrics(source: &str, cyclomatic: usize) -> FunctionMetrics {
        let tokens = metric_tokens(source);
        let unique_tokens: BTreeSet<&str> = tokens.iter().map(String::as_str).collect();
        let total_tokens = tokens.len();
        let unique_count = unique_tokens.len();
        let halstead_volume = if unique_count <= 1 {
            0.0
        } else {
            total_tokens as f64 * (unique_count as f64).log2()
        };
        let pressure =
            total_tokens as f64 * 0.08 + cyclomatic as f64 * 2.0 + halstead_volume / 60.0;
        let maintainability_score = 100.0 - pressure.min(100.0);

        FunctionMetrics {
            total_tokens,
            unique_tokens: unique_count,
            halstead_volume,
            maintainability_score,
        }
    }

    fn metric_tokens(source: &str) -> Vec<String> {
        static_regex(
            &METRIC_TOKEN_REGEX,
            r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|==|!=|<=|>=|&&|\|\||::|->|=>|[{}()\[\];,.:+\-*/%&|^!<>?=]",
        )
        .find_iter(source)
        .map(|token| token.as_str().to_string())
        .collect()
    }

    fn round1(value: f64) -> f64 {
        (value * 10.0).round() / 10.0
    }

    fn loop_pattern_count(source: &str, pattern: &Regex) -> usize {
        let loop_start = static_regex(&LOOP_START_REGEX, r"\b(for|while|loop)\b");
        let mut state = LoopPatternState::default();

        for line in source.lines() {
            state.process_line(line, pattern, loop_start);
        }

        state.occurrences
    }

    #[derive(Default)]
    struct LoopPatternState {
        depth: usize,
        loop_depths: Vec<usize>,
        pending_loop: bool,
        occurrences: usize,
    }

    impl LoopPatternState {
        fn process_line(&mut self, line: &str, pattern: &Regex, loop_start: &Regex) {
            let matches: Vec<usize> = pattern.find_iter(line).map(|found| found.start()).collect();
            let mut next_match = 0usize;
            if loop_start.is_match(line) {
                self.pending_loop = true;
            }
            for (byte_index, character) in line.char_indices() {
                next_match = self.count_matches_until(&matches, next_match, byte_index);
                self.apply_source_char(character);
            }
            self.count_remaining_matches(&matches, next_match);
        }

        fn count_matches_until(
            &mut self,
            matches: &[usize],
            mut next_match: usize,
            byte_index: usize,
        ) -> usize {
            while next_match < matches.len() && matches[next_match] <= byte_index {
                self.count_match_inside_loop();
                next_match += 1;
            }
            next_match
        }

        fn count_remaining_matches(&mut self, matches: &[usize], mut next_match: usize) {
            while next_match < matches.len() {
                self.count_match_inside_loop();
                next_match += 1;
            }
        }

        fn count_match_inside_loop(&mut self) {
            if !self.loop_depths.is_empty() {
                self.occurrences += 1;
            }
        }

        fn apply_source_char(&mut self, character: char) {
            match character {
                '{' => self.enter_scope(),
                '}' => self.leave_scope(),
                _ => {}
            }
        }

        fn enter_scope(&mut self) {
            self.depth += 1;
            if self.pending_loop {
                self.loop_depths.push(self.depth);
                self.pending_loop = false;
            }
        }

        fn leave_scope(&mut self) {
            self.loop_depths
                .retain(|loop_depth| *loop_depth < self.depth);
            self.depth = self.depth.saturating_sub(1);
        }
    }

    fn has_nearby_safety_comment(lines: &[&str], line_index: usize) -> bool {
        let start = line_index.saturating_sub(3);
        lines[start..=line_index]
            .iter()
            .any(|line| line.contains("SAFETY:"))
    }

    fn has_nearby_invariant_comment(source: &str) -> bool {
        source
            .lines()
            .any(|line| line.contains("PANIC:") || line.contains("INVARIANT:"))
    }

    fn has_trivial_assertion(source: &str) -> bool {
        let literal_assert =
            static_regex(&TRIVIAL_ASSERT_REGEX, r"\bassert!\s*\(\s*(true|false)\s*\)");
        if literal_assert.is_match(source) {
            return true;
        }

        let same_literal = static_regex(
            &SAME_LITERAL_ASSERT_REGEX,
            r#"\bassert_eq!\s*\(\s*([0-9]+|"[^"]*"|'[^']*')\s*,\s*([0-9]+|"[^"]*"|'[^']*')\s*\)"#,
        );
        let has_same_literal = same_literal.captures_iter(source).any(|captures| {
            captures.get(1).map(|left| left.as_str()) == captures.get(2).map(|right| right.as_str())
        });
        has_same_literal
    }

    fn finding(
        rule_id: &str,
        message: impl Into<String>,
        file: &SourceFile,
        line: Option<usize>,
        severity: Severity,
        pillar: Pillar,
    ) -> Finding {
        Finding::new(
            rule_id,
            message,
            file.display_path.clone(),
            line,
            severity,
            pillar,
            Confidence::High,
            None,
            None,
            json!({}),
        )
    }

    fn block_finding(
        rule_id: &str,
        message: impl Into<String>,
        file: &SourceFile,
        block: &FunctionBlock,
        severity: Severity,
        pillar: Pillar,
    ) -> Finding {
        block_finding_with_metadata(rule_id, message, file, block, severity, pillar, json!({}))
    }

    fn block_finding_with_metadata(
        rule_id: &str,
        message: impl Into<String>,
        file: &SourceFile,
        block: &FunctionBlock,
        severity: Severity,
        pillar: Pillar,
        metadata: Value,
    ) -> Finding {
        block_finding_with_extras(
            rule_id,
            message,
            file,
            block,
            severity,
            pillar,
            BlockFindingExtras {
                confidence: Confidence::High,
                remediation: None,
                metadata,
            },
        )
    }

    struct BlockFindingExtras {
        confidence: Confidence,
        remediation: Option<String>,
        metadata: Value,
    }

    fn block_finding_with_extras(
        rule_id: &str,
        message: impl Into<String>,
        file: &SourceFile,
        block: &FunctionBlock,
        severity: Severity,
        pillar: Pillar,
        extras: BlockFindingExtras,
    ) -> Finding {
        Finding::new(
            rule_id,
            message,
            file.display_path.clone(),
            Some(block.start_line),
            severity,
            pillar,
            extras.confidence,
            Some(block.name.clone()),
            extras.remediation,
            extras.metadata,
        )
    }

    fn count_regex(source: &str, pattern: &Regex) -> usize {
        pattern.find_iter(source).count()
    }

    fn first_matching_line(source: &str, needle: &str) -> Option<usize> {
        source
            .lines()
            .enumerate()
            .find_map(|(index, line)| line.contains(needle).then_some(index + 1))
    }

    fn byte_line(source: &str, byte_index: usize) -> usize {
        source[..byte_index.min(source.len())]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1
    }

    fn redact(value: &str) -> String {
        let char_count = value.chars().count();
        if char_count <= 8 {
            return format!("{} (redacted, {char_count} chars)", "*".repeat(char_count));
        }
        let start: String = value.chars().take(4).collect();
        let end: String = value
            .chars()
            .rev()
            .take(4)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        format!("{start}...{end} (redacted, {char_count} chars)")
    }

    fn looks_high_entropy(value: &str) -> bool {
        if value.chars().count() < 32 {
            return false;
        }
        let has_upper = value
            .chars()
            .any(|character| character.is_ascii_uppercase());
        let has_lower = value
            .chars()
            .any(|character| character.is_ascii_lowercase());
        let has_digit = value.chars().any(|character| character.is_ascii_digit());
        has_upper && has_lower && has_digit && shannon_entropy(value) >= 4.2
    }

    fn shannon_entropy(value: &str) -> f64 {
        let mut counts: HashMap<char, usize> = HashMap::new();
        for character in value.chars() {
            *counts.entry(character).or_default() += 1;
        }
        let length = value.chars().count() as f64;
        counts
            .values()
            .map(|count| {
                let probability = *count as f64 / length;
                -probability * probability.log2()
            })
            .sum()
    }
}

mod custom_rules {
    use super::*;
    use std::borrow::Cow;

    pub(crate) fn analyse(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        let line_starts = line_starts(unit.source);
        for rule in &config.custom_rules {
            if !config.rule_enabled(&rule.id) || !custom_rule_applies_to_path(rule, unit.file) {
                continue;
            }
            let Some(scope_source) = scoped_source(rule.scope, unit) else {
                continue;
            };
            findings.extend(evaluate_rule(
                unit,
                rule,
                scope_source.as_ref(),
                &line_starts,
            ));
        }
        findings
    }

    fn evaluate_rule(
        unit: &SourceUnit<'_>,
        rule: &CustomRule,
        source: &str,
        line_starts: &[usize],
    ) -> Vec<Finding> {
        rule.compiled_pattern
            .find_iter(source)
            .map(|matched| {
                Finding::new(
                    &rule.id,
                    rule.message.clone(),
                    unit.file.display_path.clone(),
                    Some(finding_line_for_match(
                        source,
                        line_starts,
                        matched.start(),
                        matched.end(),
                    )),
                    rule.severity,
                    rule.pillar,
                    rule.confidence,
                    Some(format!("byte:{}", matched.start())),
                    rule.remediation.clone(),
                    json!({ "scope": rule.scope.as_str() }),
                )
            })
            .collect()
    }

    fn finding_line_for_match(
        source: &str,
        line_starts: &[usize],
        start: usize,
        end: usize,
    ) -> usize {
        let line_byte = source
            .as_bytes()
            .get(start..end)
            .and_then(|matched| {
                matched
                    .iter()
                    .position(|byte| !byte.is_ascii_whitespace())
                    .map(|offset| start + offset)
            })
            .unwrap_or(start)
            .min(source.len());
        byte_line_from_starts(line_starts, line_byte)
    }

    fn custom_rule_applies_to_path(rule: &CustomRule, file: &SourceFile) -> bool {
        let path = normalize_report_path(&file.display_path);
        (rule.include_paths.is_empty()
            || rule
                .include_paths
                .iter()
                .any(|pattern| path_matches(pattern, &path)))
            && !rule
                .exclude_paths
                .iter()
                .any(|pattern| path_matches(pattern, &path))
    }

    fn scoped_source<'a>(scope: CustomRuleScope, unit: &'a SourceUnit<'_>) -> Option<Cow<'a, str>> {
        match scope {
            CustomRuleScope::Text => Some(Cow::Borrowed(unit.source)),
            CustomRuleScope::RustCode => unit
                .file
                .is_rust
                .then(|| Cow::Owned(built_in_rules::strip_rust_string_literals(unit.source))),
            CustomRuleScope::Comments => unit
                .file
                .is_rust
                .then(|| Cow::Owned(rust_comment_scope_source(unit.source))),
        }
    }

    fn rust_comment_scope_source(source: &str) -> String {
        let bytes = source.as_bytes();
        let mut output = bytes
            .iter()
            .map(|byte| if *byte == b'\n' { b'\n' } else { b' ' })
            .collect::<Vec<u8>>();
        let mut index = 0usize;
        while index < bytes.len() {
            if let Some(raw_end) = built_in_rules::raw_string_end(bytes, index) {
                index = raw_end;
                continue;
            }
            if bytes[index] == b'"' {
                index = skip_quoted_string(bytes, index);
                continue;
            }
            if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
                index = copy_line_comment(bytes, &mut output, index);
                continue;
            }
            if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                index = copy_block_comment(bytes, &mut output, index);
                continue;
            }
            index += 1;
        }
        String::from_utf8(output).expect("comment scope source stays utf-8")
    }

    fn skip_quoted_string(bytes: &[u8], start: usize) -> usize {
        let mut index = start + 1;
        while index < bytes.len() {
            let byte = bytes[index];
            index += 1;
            if byte == b'\\' && index < bytes.len() {
                index += 1;
                continue;
            }
            if byte == b'"' {
                break;
            }
        }
        index
    }

    fn copy_line_comment(bytes: &[u8], output: &mut [u8], start: usize) -> usize {
        let mut index = start;
        while index < bytes.len() && bytes[index] != b'\n' {
            output[index] = bytes[index];
            index += 1;
        }
        index
    }

    fn copy_block_comment(bytes: &[u8], output: &mut [u8], start: usize) -> usize {
        let mut index = start;
        while index < bytes.len() {
            output[index] = bytes[index];
            if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                output[index + 1] = bytes[index + 1];
                return index + 2;
            }
            index += 1;
        }
        index
    }
}

fn summarize(findings: &[Finding]) -> Summary {
    let advisory = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Advisory)
        .count();
    let warning = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Warning)
        .count();
    let error = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .count();
    Summary {
        advisory,
        warning,
        error,
        total: findings.len(),
    }
}

fn score_report(findings: &[Finding]) -> ScoreReport {
    let pillars = pillar_scores(findings);
    let composite = composite_score(&pillars);
    let top_offenders = top_file_scores(findings);

    ScoreReport {
        composite,
        grade: grade(composite),
        pillars,
        top_offenders,
    }
}

fn pillar_scores(findings: &[Finding]) -> Vec<PillarScore> {
    let mut by_pillar: BTreeMap<Pillar, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        by_pillar.entry(finding.pillar).or_default().push(finding);
    }

    let mut pillar_order: Vec<Pillar> = SCORE_PILLARS.to_vec();
    for pillar in by_pillar.keys() {
        if !pillar_order.contains(pillar) {
            pillar_order.push(*pillar);
        }
    }

    let pillars: Vec<PillarScore> = pillar_order
        .into_iter()
        .map(|pillar| {
            let pillar_findings = by_pillar.get(&pillar).cloned().unwrap_or_default();
            let penalty: f64 = pillar_findings
                .iter()
                .map(|finding| finding_penalty(finding))
                .sum();
            PillarScore {
                pillar,
                score: (100.0 - penalty).max(0.0),
                findings: pillar_findings.len(),
            }
        })
        .collect();
    pillars
}

fn composite_score(pillars: &[PillarScore]) -> f64 {
    if pillars.is_empty() {
        100.0
    } else {
        pillars.iter().map(|pillar| pillar.score).sum::<f64>() / pillars.len() as f64
    }
}

fn top_file_scores(findings: &[Finding]) -> Vec<FileScore> {
    let mut file_counts: BTreeMap<String, (usize, f64)> = BTreeMap::new();
    for finding in findings {
        let entry = file_counts
            .entry(finding.file_path.clone())
            .or_insert((0, 0.0));
        entry.0 += 1;
        entry.1 += finding_penalty(finding);
    }
    let mut top_offenders: Vec<FileScore> = file_counts
        .into_iter()
        .map(|(file_path, (findings, penalty))| FileScore {
            file_path,
            score: (100.0 - penalty).max(0.0),
            findings,
        })
        .collect();
    top_offenders.sort_by(|left, right| {
        left.score
            .total_cmp(&right.score)
            .then_with(|| right.findings.cmp(&left.findings))
            .then_with(|| left.file_path.cmp(&right.file_path))
    });
    top_offenders.truncate(10);
    top_offenders
}

fn finding_penalty(finding: &Finding) -> f64 {
    severity_penalty(finding.severity) * confidence_weight(finding.confidence)
}

fn severity_penalty(severity: Severity) -> f64 {
    match severity {
        Severity::Advisory => 1.5,
        Severity::Warning => 4.0,
        Severity::Error => 8.0,
    }
}

fn confidence_weight(confidence: Confidence) -> f64 {
    match confidence {
        Confidence::Low => 0.5,
        Confidence::Medium => 0.75,
        Confidence::High => 1.0,
    }
}

fn grade(score: f64) -> String {
    match score {
        value if value >= 90.0 => "A",
        value if value >= 80.0 => "B",
        value if value >= 70.0 => "C",
        value if value >= 60.0 => "D",
        _ => "F",
    }
    .to_string()
}

#[cfg(test)]
fn render_report(report: &AnalysisReport, format: OutputFormat) -> String {
    render_report_with_scope(report, &RequestedScope::default(), format)
}

fn render_report_with_scope(
    report: &AnalysisReport,
    scope: &RequestedScope,
    format: OutputFormat,
) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).expect("report serializes"),
        OutputFormat::Sarif => render_sarif(report),
        OutputFormat::Html => html_report::render(report, scope),
        OutputFormat::Markdown => render_markdown(report),
        OutputFormat::Github => render_github(report),
        OutputFormat::Hotspot => render_hotspot(report),
        OutputFormat::Text => render_text(report),
    }
}

fn render_text(report: &AnalysisReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("gruff-rs {}\n", report.tool.version));
    output.push_str(&format!(
        "Score: {:.1} ({}) | Findings: {} advisory, {} warning, {} error\n",
        report.score.composite,
        report.score.grade,
        report.summary.advisory,
        report.summary.warning,
        report.summary.error
    ));
    output.push_str(&format!(
        "Analysed files: {}\n",
        report.paths.analysed_files
    ));

    if !report.diagnostics.is_empty() {
        output.push_str("\nDiagnostics:\n");
        for diagnostic in &report.diagnostics {
            output.push_str(&format!(
                "- {}: {}{}\n",
                diagnostic.diagnostic_type,
                diagnostic.message,
                diagnostic
                    .file_path
                    .as_ref()
                    .map(|path| format!(" ({path})"))
                    .unwrap_or_default()
            ));
        }
    }

    if !report.findings.is_empty() {
        output.push_str("\nFindings:\n");
        for finding in &report.findings {
            output.push_str(&format!(
                "- [{}] {}:{} {} - {}\n",
                severity_label(finding.severity),
                finding.file_path,
                finding.line.unwrap_or(1),
                finding.rule_id,
                finding.message
            ));
        }
    }

    let suppressed = total_suppressed_findings(&report.suppressions);
    if suppressed > 0 {
        let details = report
            .suppressions
            .iter()
            .filter(|summary| summary.suppressed > 0)
            .map(|summary| {
                format!(
                    "exclude[{}] {}: {} ({})",
                    summary.index, summary.rule, summary.suppressed, summary.reason
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        output.push_str(&format!(
            "\nSuppressed findings: {suppressed} via {details}\n"
        ));
    }

    output
}

fn total_suppressed_findings(suppressions: &[SuppressionSummary]) -> usize {
    suppressions.iter().map(|summary| summary.suppressed).sum()
}

fn render_markdown(report: &AnalysisReport) -> String {
    let mut output = format!(
        "# gruff-rs report\n\nScore: **{:.1} ({})**\n\nFindings: {} advisory, {} warning, {} error.\n",
        report.score.composite,
        report.score.grade,
        report.summary.advisory,
        report.summary.warning,
        report.summary.error
    );
    for finding in report.findings.iter().take(50) {
        output.push_str(&format!(
            "\n- `{}` `{}`:{} - {}",
            finding.rule_id,
            finding.file_path,
            finding.line.unwrap_or(1),
            finding.message
        ));
    }
    output
}

fn render_github(report: &AnalysisReport) -> String {
    report
        .findings
        .iter()
        .map(|finding| {
            format!(
                "::{} file={},line={},title={}::{}",
                github_level(finding.severity),
                finding.file_path,
                finding.line.unwrap_or(1),
                escape_command(&finding.rule_id),
                escape_command(&finding.message)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_hotspot(report: &AnalysisReport) -> String {
    serde_json::to_string_pretty(&json!({
        "schemaVersion": "gruff.hotspot.v1",
        "tool": report.tool,
        "score": report.score.composite,
        "files": report.score.top_offenders,
    }))
    .expect("hotspot serializes")
}

fn render_sarif(report: &AnalysisReport) -> String {
    let registry = rules::builtin_registry();
    let rule_indices: HashMap<&str, usize> = registry
        .definitions()
        .iter()
        .enumerate()
        .map(|(index, definition)| (definition.id, index))
        .collect();
    let mut rules = Vec::new();
    for definition in registry.definitions() {
        rules.push(sarif_rule(definition));
    }
    let mut results: Vec<Value> = report
        .findings
        .iter()
        .map(|finding| sarif_result(finding, &rule_indices))
        .collect();
    results.extend(
        report
            .suppressed_findings
            .iter()
            .map(|suppressed| sarif_suppressed_result(suppressed, &rule_indices)),
    );

    serde_json::to_string_pretty(&json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": &report.tool.name,
                        "semanticVersion": &report.tool.version,
                        "rules": rules,
                    },
                },
                "invocations": [
                    sarif_invocation(report),
                ],
                "results": results,
                "properties": {
                    "gruffSchemaVersion": &report.schema_version,
                    "generatedAt": &report.run.generated_at,
                    "score": report.score.composite,
                    "grade": &report.score.grade,
                },
            },
        ],
    }))
    .expect("sarif serializes")
}

fn sarif_rule(definition: &rules::RuleDefinition) -> Value {
    json!({
        "id": definition.id,
        "name": definition.name,
        "shortDescription": {
            "text": definition.name,
        },
        "fullDescription": {
            "text": definition.description,
        },
        "help": {
            "text": definition.description,
        },
        "defaultConfiguration": {
            "level": sarif_level(definition.default_severity),
        },
        "properties": sarif_rule_properties(definition),
    })
}

fn sarif_rule_properties(definition: &rules::RuleDefinition) -> Value {
    let mut properties = Map::new();
    properties.insert("pillar".to_string(), json!(definition.pillar));
    properties.insert("tier".to_string(), json!(definition.tier));
    properties.insert("kind".to_string(), json!(definition.kind));
    properties.insert(
        "defaultSeverity".to_string(),
        json!(definition.default_severity),
    );
    properties.insert("confidence".to_string(), json!(definition.confidence));
    properties.insert(
        "defaultEnabled".to_string(),
        json!(definition.default_enabled),
    );
    if let Some(threshold) = definition.threshold {
        properties.insert("threshold".to_string(), json!(threshold.default));
    }
    if !definition.options.is_empty() {
        properties.insert("options".to_string(), json!(definition.options));
    }
    Value::Object(properties)
}

fn sarif_invocation(report: &AnalysisReport) -> Value {
    let mut notifications = Vec::new();
    for diagnostic in &report.diagnostics {
        notifications.push(sarif_notification(diagnostic));
    }
    json!({
        "executionSuccessful": !report.diagnostics.iter().any(RunDiagnostic::is_failure),
        "toolExecutionNotifications": notifications,
    })
}

fn sarif_notification(diagnostic: &RunDiagnostic) -> Value {
    let mut notification = Map::new();
    notification.insert(
        "descriptor".to_string(),
        json!({
            "id": &diagnostic.diagnostic_type,
        }),
    );
    notification.insert(
        "level".to_string(),
        json!(sarif_diagnostic_level(diagnostic)),
    );
    notification.insert(
        "message".to_string(),
        json!({
            "text": &diagnostic.message,
        }),
    );
    if let Some(locations) = sarif_diagnostic_locations(diagnostic) {
        notification.insert("locations".to_string(), locations);
    }
    Value::Object(notification)
}

fn sarif_diagnostic_level(diagnostic: &RunDiagnostic) -> &'static str {
    if diagnostic.is_failure() {
        "error"
    } else if diagnostic.diagnostic_type == "diff-git-unsafe" {
        "warning"
    } else {
        "note"
    }
}

fn sarif_diagnostic_locations(diagnostic: &RunDiagnostic) -> Option<Value> {
    diagnostic.file_path.as_ref().map(|file_path| {
        json!([
            {
                "physicalLocation": sarif_physical_location_from_parts(
                    file_path,
                    diagnostic.line,
                    None,
                    None,
                ),
            },
        ])
    })
}

fn sarif_result(finding: &Finding, rule_indices: &HashMap<&str, usize>) -> Value {
    let mut result = json!({
        "ruleId": &finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": {
            "text": &finding.message,
        },
        "locations": sarif_result_locations(finding),
        "partialFingerprints": {
            "gruffFingerprint": &finding.fingerprint,
        },
        "properties": sarif_result_properties(finding),
    });
    if let Some(rule_index) = rule_indices.get(finding.rule_id.as_str()) {
        result["ruleIndex"] = json!(rule_index);
    }
    result
}

fn sarif_suppressed_result(
    suppressed: &SuppressedFinding,
    rule_indices: &HashMap<&str, usize>,
) -> Value {
    let mut result = sarif_result(&suppressed.finding, rule_indices);
    if let Value::Object(result_object) = &mut result {
        result_object.insert(
            "suppressions".to_string(),
            json!([
                {
                    "kind": "inSource",
                    "justification": &suppressed.suppression.reason,
                },
            ]),
        );
    }
    result
}

fn sarif_result_locations(finding: &Finding) -> Value {
    json!([
        {
            "physicalLocation": sarif_physical_location_from_parts(
                &finding.file_path,
                finding.line,
                finding.column,
                finding.end_line,
            ),
        },
    ])
}

fn sarif_result_properties(finding: &Finding) -> Value {
    let mut properties = Map::new();
    properties.insert("severity".to_string(), json!(finding.severity));
    properties.insert("pillar".to_string(), json!(finding.pillar));
    properties.insert("tier".to_string(), json!(&finding.tier));
    properties.insert("confidence".to_string(), json!(finding.confidence));
    if !finding.secondary_pillars.is_empty() {
        properties.insert(
            "secondaryPillars".to_string(),
            json!(&finding.secondary_pillars),
        );
    }
    if let Some(symbol) = &finding.symbol {
        properties.insert("symbol".to_string(), json!(symbol));
    }
    if let Some(remediation) = &finding.remediation {
        properties.insert("remediation".to_string(), json!(remediation));
    }
    if !finding.metadata.is_null() {
        properties.insert("metadata".to_string(), finding.metadata.clone());
    }
    Value::Object(properties)
}

fn sarif_physical_location_from_parts(
    file_path: &str,
    line: Option<usize>,
    column: Option<usize>,
    end_line: Option<usize>,
) -> Value {
    let mut location = Map::new();
    location.insert(
        "artifactLocation".to_string(),
        json!({
            "uri": sarif_uri(file_path),
        }),
    );
    if let Some(line) = line {
        let mut region = Map::new();
        region.insert("startLine".to_string(), json!(line));
        if let Some(column) = column {
            region.insert("startColumn".to_string(), json!(column));
        }
        if let Some(end_line) = end_line {
            region.insert("endLine".to_string(), json!(end_line));
        }
        location.insert("region".to_string(), Value::Object(region));
    }
    Value::Object(location)
}

fn sarif_uri(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_start_matches("./");
    let path = if trimmed.is_empty() { "." } else { trimmed };
    let mut encoded = String::new();
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                encoded.push(byte as char);
            }
            _ => {
                push_percent_encoded(&mut encoded, byte);
            }
        }
    }
    encoded
}

fn push_percent_encoded(encoded: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    encoded.push('%');
    encoded.push(HEX[(byte >> 4) as usize] as char);
    encoded.push(HEX[(byte & 0x0F) as usize] as char);
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advisory => "note",
    }
}

fn github_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advisory => "notice",
    }
}

fn escape_command(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\n', "%0A")
        .replace('\r', "%0D")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn changed_files(mode: &str) -> Result<BTreeSet<String>, String> {
    let mut command = std::process::Command::new("git");
    command.arg("diff").arg("--name-only");
    match mode {
        "working-tree" | "unstaged" => {}
        "staged" => {
            command.arg("--cached");
        }
        other => {
            command.arg(other);
        }
    }
    let output = command
        .output()
        .map_err(|error| format!("unable to execute git diff for --diff: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.replace('\\', "/"))
        .collect())
}

fn write_baseline(path: &Path, findings: &[Finding]) -> Result<(), String> {
    let entries: Vec<BaselineEntry> = findings
        .iter()
        .map(|finding| BaselineEntry {
            fingerprint: finding.fingerprint.clone(),
            rule_id: finding.rule_id.clone(),
            file_path: finding.file_path.clone(),
            line: finding.line,
            symbol: finding.symbol.clone(),
            message: finding.message.clone(),
        })
        .collect();
    let value = json!({
        "schemaVersion": "gruff.baseline.v1",
        "generatedAt": Utc::now().to_rfc3339(),
        "entries": entries,
    });
    fs::write(
        path,
        serde_json::to_string_pretty(&value).expect("baseline serializes"),
    )
    .map_err(|error| format!("unable to write baseline {}: {error}", path.display()))
}

fn apply_baseline(path: &Path, findings: &mut Vec<Finding>) -> Result<(), String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("unable to read baseline {}: {error}", path.display()))?;
    let data: BaselineData = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid baseline {}: {error}", path.display()))?;
    if data.schema_version.as_deref() != Some("gruff.baseline.v1") {
        return Err(format!("unsupported baseline schema in {}", path.display()));
    }
    let keys: BTreeSet<(String, String, String)> = data
        .entries
        .into_iter()
        .map(|entry| (entry.fingerprint, entry.rule_id, entry.file_path))
        .collect();
    findings.retain(|finding| {
        !keys.contains(&(
            finding.fingerprint.clone(),
            finding.rule_id.clone(),
            finding.file_path.clone(),
        ))
    });
    Ok(())
}

fn record_history(
    project_root: &Path,
    history_file: &Path,
    findings: &[Finding],
    diagnostics: &mut Vec<RunDiagnostic>,
) {
    let path = absolutize(project_root, history_file);
    let mut entries = fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
        .unwrap_or_default();
    entries.push(json!({
        "recordedAt": Utc::now().to_rfc3339(),
        "findings": findings.len(),
        "score": score_report(findings).composite,
    }));
    if entries.len() > 100 {
        entries = entries.split_off(entries.len() - 100);
    }
    if let Err(error) = fs::write(
        &path,
        serde_json::to_string_pretty(&entries).expect("history serializes"),
    ) {
        diagnostics.push(RunDiagnostic {
            diagnostic_type: "history-error".to_string(),
            message: format!("Unable to write history file: {error}"),
            file_path: Some(display_path(project_root, &path)),
            line: None,
        });
    }
}

fn run_dashboard(args: DashboardArgs) -> ExitCode {
    let address = format!("{}:{}", args.host, args.port);
    let listener = match TcpListener::bind(&address) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("gruff-rs: unable to bind {address}: {error}");
            return ExitCode::from(2);
        }
    };
    println!("gruff-rs dashboard listening at http://{address}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_dashboard_request(stream, &args.project_root),
            Err(error) => eprintln!("gruff-rs: dashboard connection error: {error}"),
        }
    }

    ExitCode::SUCCESS
}

fn handle_dashboard_request(mut stream: TcpStream, default_root: &Path) {
    let mut buffer = [0u8; 4096];
    let bytes_read = match stream.read(&mut buffer) {
        Ok(bytes_read) => bytes_read,
        Err(_) => return,
    };
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request.lines().next().unwrap_or_default();
    let target = request_line.split_whitespace().nth(1).unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let response = dashboard_response(path, query, default_root);
    respond(
        &mut stream,
        response.status,
        response.content_type,
        &response.body,
    );
}

struct DashboardResponse {
    status: &'static str,
    content_type: &'static str,
    body: String,
}

fn dashboard_response(path: &str, query: &str, default_root: &Path) -> DashboardResponse {
    match path {
        "/health" => DashboardResponse {
            status: "200 OK",
            content_type: "text/plain; charset=utf-8",
            body: "ok".to_string(),
        },
        "/scan" => {
            let params = parse_query(query);
            let root = params
                .get("projectRoot")
                .map(PathBuf::from)
                .unwrap_or_else(|| default_root.to_path_buf());
            let scan_path = params
                .get("path")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            if !root.is_dir() {
                return DashboardResponse {
                    status: "400 Bad Request",
                    content_type: "text/plain; charset=utf-8",
                    body: "invalid projectRoot".to_string(),
                };
            }
            let options = AnalysisOptions {
                paths: vec![scan_path],
                config: None,
                no_config: false,
                format: OutputFormat::Html,
                fail_on: FailThreshold::None,
                include_ignored: false,
                diff: None,
                history_file: None,
                baseline: None,
                generate_baseline: None,
                no_baseline: false,
            };
            let scope = RequestedScope::from_options(&options);
            let body = run_analysis_in_project(&root, &options)
                .map(|report| dashboard_shell(&report, &scope, &root))
                .unwrap_or_else(|error| format!("<pre>{}</pre>", html_escape(&error)));
            DashboardResponse {
                status: "200 OK",
                content_type: "text/html; charset=utf-8",
                body,
            }
        }
        "/" => DashboardResponse {
            status: "200 OK",
            content_type: "text/html; charset=utf-8",
            body: dashboard_index(default_root),
        },
        _ => DashboardResponse {
            status: "404 Not Found",
            content_type: "text/plain; charset=utf-8",
            body: "not found".to_string(),
        },
    }
}

fn dashboard_index(root: &Path) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gruff-rs dashboard</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 0; background: #f7f8fa; color: #172026; }}
    header {{ background: #172026; color: white; padding: 20px 24px; }}
    main {{ max-width: 960px; margin: 0 auto; padding: 24px; }}
    form {{ display: grid; gap: 12px; background: white; border: 1px solid #d9e0e7; border-radius: 8px; padding: 16px; }}
    input, button {{ font: inherit; padding: 10px; }}
    button {{ background: #146c5f; color: white; border: 0; border-radius: 6px; cursor: pointer; }}
  </style>
</head>
<body>
  <header><h1>gruff-rs dashboard</h1></header>
  <main>
    <form action="/scan" method="get">
      <label>Project root <input name="projectRoot" value="{root}"></label>
      <label>Path <input name="path" value="."></label>
      <button type="submit">Run scan</button>
    </form>
  </main>
</body>
</html>"#,
        root = html_escape(&root.display().to_string())
    )
}

fn dashboard_shell(report: &AnalysisReport, scope: &RequestedScope, root: &Path) -> String {
    let report_html = html_report::render(report, scope);
    let banner = format!(
        r#"<div class="dashboard-banner" role="region" aria-label="Dashboard scan"><strong>Dashboard scan</strong> · Project: <code>{}</code> · <a href="/">Change target</a></div>"#,
        html_escape(&root.display().to_string())
    );
    if let Some(position) = report_html.find("<body>") {
        let insert_at = position + "<body>".len();
        let mut output = String::with_capacity(report_html.len() + banner.len());
        output.push_str(&report_html[..insert_at]);
        output.push_str(&banner);
        output.push_str(&report_html[insert_at..]);
        output
    } else {
        format!("{banner}{report_html}")
    }
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(hex) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                output.push(hex);
                index += 3;
                continue;
            }
        }
        output.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&output).to_string()
}

fn absolutize(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string()
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == path {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if pattern.contains('*') {
        let escaped = regex::escape(pattern)
            .replace("\\*\\*", ".*")
            .replace("\\*", "[^/]*");
        return Regex::new(&format!("^{escaped}$"))
            .map(|regex| regex.is_match(path))
            .unwrap_or(false);
    }
    path.starts_with(pattern.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use tempfile::tempdir;

    const PROCESS_COMMAND_NEW: &str = "std::process::Command::new";

    fn analysis_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("analysis lock")
    }

    fn analyse_test_paths(paths: Vec<PathBuf>) -> AnalysisReport {
        analyse_project_paths(Path::new("."), paths)
    }

    fn analyse_project_paths(project_root: &Path, paths: Vec<PathBuf>) -> AnalysisReport {
        run_analysis_in_project(
            project_root,
            &AnalysisOptions {
                paths,
                config: None,
                no_config: true,
                format: OutputFormat::Json,
                fail_on: FailThreshold::None,
                include_ignored: false,
                diff: None,
                history_file: None,
                baseline: None,
                generate_baseline: None,
                no_baseline: true,
            },
        )
        .expect("analysis succeeds")
    }

    fn run_project_analysis(
        project_root: &Path,
        options: AnalysisOptions,
    ) -> Result<AnalysisReport, String> {
        run_analysis_in_project(project_root, &options)
    }

    fn test_finding(
        rule_id: &str,
        file_path: &str,
        line: usize,
        severity: Severity,
        pillar: Pillar,
    ) -> Finding {
        test_finding_with_confidence(rule_id, file_path, line, severity, pillar, Confidence::High)
    }

    fn test_finding_with_confidence(
        rule_id: &str,
        file_path: &str,
        line: usize,
        severity: Severity,
        pillar: Pillar,
        confidence: Confidence,
    ) -> Finding {
        Finding::new(
            rule_id,
            format!("{rule_id} message"),
            file_path,
            Some(line),
            severity,
            pillar,
            confidence,
            Some("symbol".to_string()),
            Some("Remediate the issue.".to_string()),
            json!({}),
        )
    }

    fn sample_report() -> AnalysisReport {
        let findings = vec![Finding::new(
            "security.process-command",
            "Use <escaped> command & args",
            "src/lib.rs",
            Some(7),
            Severity::Warning,
            Pillar::Security,
            Confidence::High,
            Some("run".to_string()),
            Some("Validate command arguments.".to_string()),
            json!({}),
        )];
        sample_report_with(findings, Vec::new())
    }

    fn sample_report_with(
        findings: Vec<Finding>,
        diagnostics: Vec<RunDiagnostic>,
    ) -> AnalysisReport {
        let summary = summarize(&findings);
        let score = score_report(&findings);
        AnalysisReport {
            schema_version: "gruff.analysis.v1".to_string(),
            tool: ToolInfo {
                name: "gruff-rs".to_string(),
                version: VERSION.to_string(),
            },
            run: RunInfo {
                project_root: ".".to_string(),
                format: "json".to_string(),
                fail_on: "none".to_string(),
                generated_at: "2026-05-13T00:00:00Z".to_string(),
            },
            summary,
            paths: PathSummary {
                analysed_files: 1,
                ignored_paths: Vec::new(),
                missing_paths: Vec::new(),
            },
            diagnostics,
            suppressions: Vec::new(),
            findings,
            score,
            baseline: None,
            suppressed_findings: Vec::new(),
        }
    }

    fn sample_sarif(report: &AnalysisReport) -> Value {
        serde_json::from_str(&render_report(report, OutputFormat::Sarif)).expect("sarif report")
    }

    #[test]
    fn diff_patch_parser_maps_new_side_lines_for_renames_crlf_and_deletions() {
        let patch = concat!(
            "diff --git a/src/old.rs b/src/new.rs\r\n",
            "similarity index 80%\r\n",
            "rename from src/old.rs\r\n",
            "rename to src/new.rs\r\n",
            "--- a/src/old.rs\r\n",
            "+++ b/src/new.rs\r\n",
            "@@ -1,3 +10,4 @@\r\n",
            " context\r\n",
            "-old\r\n",
            "+new\r\n",
            " keep\r\n",
            "+added\r\n",
            "diff --git a/src/delete.rs b/src/delete.rs\r\n",
            "--- a/src/delete.rs\r\n",
            "+++ b/src/delete.rs\r\n",
            "@@ -4,2 +4,0 @@\r\n",
            "-old\r\n",
            "-old\r\n",
            "diff --git a/bin.dat b/bin.dat\r\n",
            "Binary files a/bin.dat and b/bin.dat differ\r\n",
        );

        let parsed = parse_unified_diff(patch);

        assert_eq!(
            parsed.lines_by_file.get("src/new.rs"),
            Some(&BTreeSet::from([10, 11, 12, 13]))
        );
        assert_eq!(
            parsed.lines_by_file.get("src/delete.rs"),
            Some(&BTreeSet::new())
        );
        assert!(!parsed.lines_by_file.contains_key("bin.dat"));
        assert!(parse_unified_diff("").lines_by_file.is_empty());
    }

    #[test]
    fn diff_patch_filter_keeps_only_changed_lines_and_line_less_findings() {
        let mut line_less = test_finding(
            "architecture.public-api-surface",
            "src/lib.rs",
            1,
            Severity::Advisory,
            Pillar::Design,
        );
        line_less.line = None;
        let report = sample_report_with(
            vec![
                test_finding(
                    "security.process-command",
                    "src/lib.rs",
                    11,
                    Severity::Warning,
                    Pillar::Security,
                ),
                test_finding(
                    "waste.unwrap-expect",
                    "src/lib.rs",
                    12,
                    Severity::Advisory,
                    Pillar::Waste,
                ),
                test_finding(
                    "docs.missing-public-doc",
                    "src/other.rs",
                    11,
                    Severity::Advisory,
                    Pillar::Documentation,
                ),
                line_less,
            ],
            Vec::new(),
        );
        let patch = parse_unified_diff(
            "\
diff --git a/src/lib.rs b/src/lib.rs\n\
--- a/src/lib.rs\n\
+++ b/src/lib.rs\n\
@@ -10,2 +11,1 @@\n\
+changed\n\
diff --git a/missing.rs b/missing.rs\n\
--- a/missing.rs\n\
+++ b/missing.rs\n\
@@ -1,1 +1,1 @@\n\
-old\n\
+new\n",
        );
        let analysed = BTreeSet::from(["src/lib.rs".to_string()]);

        let filtered = apply_diff_patch_filter(report, &patch, &analysed);
        eprintln!(
            "diff_patch kept rule ids: {:?}; suppressed count: {}",
            filtered
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            2
        );

        assert_eq!(filtered.findings.len(), 2);
        assert!(filtered
            .findings
            .iter()
            .any(|finding| finding.rule_id == "security.process-command"));
        assert!(filtered
            .findings
            .iter()
            .any(|finding| finding.rule_id == "architecture.public-api-surface"));
        assert_eq!(filtered.summary.total, 2);
        assert_eq!(filtered.diagnostics.len(), 1);
        assert_eq!(filtered.diagnostics[0].diagnostic_type, "patch-filter");
        assert!(!filtered.diagnostics[0].is_failure());
        assert!(filtered.diagnostics[0]
            .message
            .contains("Patch filter kept 2 of 4 findings; suppressed 2"));
        assert!(filtered.diagnostics[0]
            .message
            .contains("Patch files not analysed: missing.rs"));
    }

    #[test]
    fn diff_patch_analysis_filters_after_baseline_without_failing_on_summary_diagnostic() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        let patch_path = dir.path().join("fixture.patch");
        fs::write(
            &patch_path,
            [
                "\
diff --git a/fixtures/sample.rs b/fixtures/sample.rs\n\
--- a/fixtures/sample.rs\n\
+++ b/fixtures/sample.rs\n\
@@ -11,1 +11,1 @@\n\
+        ",
                PROCESS_COMMAND_NEW,
                "(command).arg(url).spawn().unwrap();\n",
            ]
            .concat(),
        )
        .expect("patch write");
        let options = AnalysisOptions {
            paths: vec![PathBuf::from("fixtures/sample.rs")],
            no_config: true,
            diff: Some(DiffSelection::Patch(patch_path)),
            no_baseline: true,
            ..default_test_options()
        };

        let report = run_project_analysis(Path::new("."), options).expect("analysis succeeds");

        assert!(report.findings.len() < 12);
        assert!(!report.findings.is_empty());
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.file_path == "fixtures/sample.rs" && finding.line == Some(11)));
        assert_eq!(
            report
                .diagnostics
                .last()
                .map(|diagnostic| diagnostic.diagnostic_type.as_str()),
            Some("patch-filter")
        );
        assert_eq!(
            RunOutcome::classify(&report, FailThreshold::None),
            RunOutcome::Success
        );
    }

    #[test]
    fn diff_patch_diagnostics_are_sarif_notifications_without_failed_execution() {
        let report = sample_report_with(
            Vec::new(),
            vec![RunDiagnostic {
                diagnostic_type: "patch-filter".to_string(),
                message: "Patch filter kept 0 of 0 findings; suppressed 0 outside changed new-side lines. All patch files were analysed.".to_string(),
                file_path: None,
                line: None,
            }],
        );

        let sarif = sample_sarif(&report);

        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            true
        );
        let notification = &sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0];
        assert_eq!(notification["descriptor"]["id"], "patch-filter");
        assert_eq!(notification["level"], "note");
    }

    #[test]
    fn diff_requires_explicit_unsafe_git_flag() {
        let without_flag = Cli::try_parse_from(["gruff-rs", "analyse", "--diff", "working-tree"]);
        assert!(without_flag.is_err());

        let with_flag = Cli::try_parse_from([
            "gruff-rs",
            "analyse",
            "--diff",
            "working-tree",
            "--diff-git-unsafe",
        ]);
        assert!(with_flag.is_ok());
    }

    #[test]
    fn exclusion_filter_counts_rule_path_message_and_unmatched_entries() {
        let registry = rules::builtin_registry();
        let findings = vec![
            test_finding(
                "docs.missing-public-doc",
                "src/lib.rs",
                1,
                Severity::Advisory,
                Pillar::Documentation,
            ),
            test_finding(
                "security.process-command",
                "tests/fixture.rs",
                4,
                Severity::Warning,
                Pillar::Security,
            ),
            test_finding(
                "waste.unwrap-expect",
                "src/lib.rs",
                5,
                Severity::Advisory,
                Pillar::Waste,
            ),
            Finding::new(
                "size.parameter-count",
                "too many params",
                "src/lib.rs",
                Some(9),
                Severity::Warning,
                Pillar::Size,
                Confidence::High,
                Some("process".to_string()),
                None,
                json!({}),
            ),
            test_finding(
                "security.process-command",
                "src/lib.rs",
                6,
                Severity::Warning,
                Pillar::Security,
            ),
        ];
        let exclusions = vec![
            ExclusionRule {
                selector: "docs.missing-public-doc".to_string(),
                rule_ids: expand_rule_selector("docs.missing-public-doc", &registry, "test.rule")
                    .expect("exact selector"),
                paths: Vec::new(),
                message_contains: None,
                reason: "legacy docs debt".to_string(),
            },
            ExclusionRule {
                selector: "security.process-command".to_string(),
                rule_ids: expand_rule_selector("security.process-command", &registry, "test.rule")
                    .expect("exact selector"),
                paths: vec!["tests/**".to_string()],
                message_contains: None,
                reason: "test fixture command".to_string(),
            },
            ExclusionRule {
                selector: "waste.unwrap-expect".to_string(),
                rule_ids: expand_rule_selector("waste.unwrap-expect", &registry, "test.rule")
                    .expect("exact selector"),
                paths: Vec::new(),
                message_contains: Some("unwrap".to_string()),
                reason: "accepted unwrap".to_string(),
            },
            ExclusionRule {
                selector: "size.parameter-count".to_string(),
                rule_ids: expand_rule_selector("size.parameter-count", &registry, "test.rule")
                    .expect("exact selector"),
                paths: vec!["src/**".to_string()],
                message_contains: Some("params".to_string()),
                reason: "generated adapter".to_string(),
            },
            ExclusionRule {
                selector: "sensitive-data.aws-access-key".to_string(),
                rule_ids: expand_rule_selector(
                    "sensitive-data.aws-access-key",
                    &registry,
                    "test.rule",
                )
                .expect("exact selector"),
                paths: Vec::new(),
                message_contains: None,
                reason: "unused exclusion stays auditable".to_string(),
            },
        ];

        let (kept, summaries, suppressed) = apply_report_exclusions(findings, &exclusions);
        eprintln!(
            "exclusion kept rule ids: {:?}; suppression counts: {:?}",
            kept.iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            summaries
                .iter()
                .map(|summary| summary.suppressed)
                .collect::<Vec<_>>()
        );

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].file_path, "src/lib.rs");
        assert_eq!(kept[0].rule_id, "security.process-command");
        assert_eq!(
            summaries
                .iter()
                .map(|summary| summary.suppressed)
                .collect::<Vec<_>>(),
            vec![1, 1, 1, 1, 0]
        );
        assert_eq!(suppressed.len(), 4);
    }

    #[test]
    fn exclusion_config_rejects_missing_reason_unknown_rule_and_bad_shapes() {
        let dir = tempdir().expect("tempdir");
        let options = default_test_options();

        write_config(
            dir.path(),
            r#"
exclude:
  - rule: security.process-command
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("missing reason rejected");
        assert!(error.contains("missing required config key `exclude[0].reason`"));

        write_config(
            dir.path(),
            r#"
exclude:
  - rule: unknown.rule
    reason: "unknown rule"
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("unknown rule rejected");
        assert!(error.contains("unknown selector `unknown.rule`"), "{error}");
        assert!(error.contains("exclude[0].rule"), "{error}");

        write_config(
            dir.path(),
            r#"
exclude:
  - rule: security.process-command
    paths: "tests/**"
    reason: "bad paths"
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("bad paths rejected");
        assert!(error.contains("config key `exclude[0].paths` must be an array"));
    }

    #[test]
    fn exclusion_config_reuses_rule_selector_parsing() {
        let dir = tempdir().expect("tempdir");
        write_config(
            dir.path(),
            r#"
exclude:
  - rule: security.*
    reason: "all security findings are reviewed separately"
"#,
        );

        let config = load_config(dir.path(), &default_test_options())
            .expect("exclusion selector config loads");

        assert_eq!(config.exclusions.len(), 1);
        assert!(config.exclusions[0]
            .rule_ids
            .contains("security.process-command"));
        assert!(config.exclusions[0]
            .rule_ids
            .contains("security.unsafe-block"));
    }

    #[test]
    fn report_level_exclusions_hide_findings_without_skipping_discovery() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::create_dir_all(dir.path().join("tests")).expect("tests dir");
        fs::write(
            dir.path().join("src/lib.rs"),
            concat!(
                "pub fn run_src() {\n",
                "    std::process::Command::new(\"sh\").spawn().unwrap();\n",
                "}\n"
            ),
        )
        .expect("src write");
        fs::write(
            dir.path().join("tests/process.rs"),
            concat!(
                "pub fn run_test() {\n",
                "    std::process::Command::new(\"sh\").spawn().unwrap();\n",
                "}\n"
            ),
        )
        .expect("tests write");
        write_config(
            dir.path(),
            r#"
exclude:
  - rule: security.process-command
    paths: ["tests/**"]
    reason: "test-only synthetic command"
"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![
                    PathBuf::from("src/lib.rs"),
                    PathBuf::from("tests/process.rs"),
                ],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");

        assert_eq!(report.paths.analysed_files, 2);
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "security.process-command" && finding.file_path == "src/lib.rs"
        }));
        assert!(!report.findings.iter().any(|finding| {
            finding.rule_id == "security.process-command" && finding.file_path == "tests/process.rs"
        }));
        assert_eq!(total_suppressed_findings(&report.suppressions), 1);
        assert_eq!(report.suppressions[0].reason, "test-only synthetic command");

        let json_output = render_report(&report, OutputFormat::Json);
        let json: Value = serde_json::from_str(&json_output).expect("json report");
        assert_eq!(json["suppressions"][0]["suppressed"], 1);
        assert_eq!(
            json["suppressions"][0]["reason"],
            "test-only synthetic command"
        );
        assert!(json["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .all(|finding| {
                finding["ruleId"] != "security.process-command"
                    || finding["filePath"] != "tests/process.rs"
            }));
    }

    #[test]
    fn sarif_suppression_results_carry_in_source_justification() {
        let registry = rules::builtin_registry();
        let finding = test_finding(
            "security.process-command",
            "tests/fixture.rs",
            4,
            Severity::Warning,
            Pillar::Security,
        );
        let exclusions = vec![ExclusionRule {
            selector: "security.process-command".to_string(),
            rule_ids: expand_rule_selector("security.process-command", &registry, "test.rule")
                .expect("exact selector"),
            paths: vec!["tests/**".to_string()],
            message_contains: None,
            reason: "test-only synthetic command".to_string(),
        }];
        let (findings, suppressions, suppressed_findings) =
            apply_report_exclusions(vec![finding], &exclusions);
        let mut report = sample_report_with(findings, Vec::new());
        report.summary = summarize(&report.findings);
        report.score = score_report(&report.findings);
        report.suppressions = suppressions;
        report.suppressed_findings = suppressed_findings;

        assert!(report.findings.is_empty());
        let sarif = sample_sarif(&report);
        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "security.process-command");
        assert_eq!(result["suppressions"][0]["kind"], "inSource");
        assert_eq!(
            result["suppressions"][0]["justification"],
            "test-only synthetic command"
        );
    }

    fn rule_ids(report: &AnalysisReport) -> BTreeSet<&str> {
        report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect()
    }

    fn assert_has_rule(report: &AnalysisReport, rule_id: &str) {
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule_id),
            "expected rule `{rule_id}` in findings: {:?}",
            rule_ids(report)
        );
    }

    fn assert_missing_rule(report: &AnalysisReport, rule_id: &str) {
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule_id),
            "unexpected rule `{rule_id}` in findings: {:?}",
            rule_ids(report)
        );
    }

    fn metric_metadata_number(
        report: &AnalysisReport,
        rule_id: &str,
        symbol: &str,
        key: &str,
    ) -> f64 {
        report
            .findings
            .iter()
            .find(|finding| finding.rule_id == rule_id && finding.symbol.as_deref() == Some(symbol))
            .and_then(|finding| finding.metadata.get(key))
            .and_then(Value::as_f64)
            .unwrap_or_else(|| panic!("missing `{key}` metadata for `{rule_id}` `{symbol}`"))
    }

    fn default_test_options() -> AnalysisOptions {
        AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            config: None,
            no_config: false,
            format: OutputFormat::Json,
            fail_on: FailThreshold::None,
            include_ignored: false,
            diff: None,
            history_file: None,
            baseline: None,
            generate_baseline: None,
            no_baseline: true,
        }
    }

    fn write_config(dir: &Path, body: &str) {
        fs::write(dir.join(".gruff-rs.yaml"), body).expect("yaml config write");
    }

    fn project_context_for_test(project_root: &Path) -> ProjectContext {
        let options = AnalysisOptions {
            paths: vec![PathBuf::from(".")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        };
        let discovery = discover_sources(project_root, &options, &Config::default());
        let (parsed_sources, read_diagnostics) = read_and_parse_sources(&discovery.files);
        assert!(read_diagnostics.is_empty(), "{read_diagnostics:?}");
        build_project_context(project_root, &parsed_sources)
    }

    #[test]
    fn fixture_scan_contract_preserves_existing_sample_findings() {
        let _guard = analysis_lock();
        let report = analyse_test_paths(vec![PathBuf::from("fixtures/sample.rs")]);

        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
        assert_eq!(report.summary.total, report.findings.len());
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.file_path == "fixtures/sample.rs")
                .count(),
            12
        );

        let expected = [
            (
                "docs.missing-public-doc",
                Severity::Advisory,
                "fixtures/sample.rs",
                Some(1),
                Some("SampleAnalyzer"),
                "33f9dd5201230832",
            ),
            (
                "modernisation.public-field",
                Severity::Advisory,
                "fixtures/sample.rs",
                Some(2),
                None,
                "bc7bce7d0361e8e7",
            ),
            (
                "docs.missing-public-doc",
                Severity::Advisory,
                "fixtures/sample.rs",
                Some(7),
                Some("process"),
                "44dc31cc3f2fddf6",
            ),
            (
                "error-handling.public-unwrap",
                Severity::Warning,
                "fixtures/sample.rs",
                Some(7),
                Some("process"),
                "826987132b0ba61b",
            ),
            (
                "naming.generic-function",
                Severity::Advisory,
                "fixtures/sample.rs",
                Some(7),
                Some("process"),
                "c3694de68d5ae921",
            ),
            (
                "size.parameter-count",
                Severity::Warning,
                "fixtures/sample.rs",
                Some(7),
                Some("process"),
                "ec04a7b3fcf15f6d",
            ),
            (
                "security.process-command",
                Severity::Warning,
                "fixtures/sample.rs",
                Some(11),
                None,
                "c83527501efb5e12",
            ),
            (
                "waste.unwrap-expect",
                Severity::Advisory,
                "fixtures/sample.rs",
                Some(11),
                None,
                "80bf1a6b54a67ccf",
            ),
            (
                "sensitive-data.aws-access-key",
                Severity::Error,
                "fixtures/sample.rs",
                Some(16),
                None,
                "1aae444024c630df",
            ),
            (
                "sensitive-data.database-url-password",
                Severity::Error,
                "fixtures/sample.rs",
                Some(17),
                None,
                "79a7540d1b61cf02",
            ),
            (
                "test-quality.no-assertions",
                Severity::Warning,
                "fixtures/sample.rs",
                Some(23),
                Some("test_sleeps_without_assertion"),
                "7d01e1f8fa08edc9",
            ),
            (
                "test-quality.sleep-in-test",
                Severity::Advisory,
                "fixtures/sample.rs",
                Some(23),
                Some("test_sleeps_without_assertion"),
                "8e9591ae5cdf9beb",
            ),
        ];

        for (rule_id, severity, path, line, symbol, fingerprint) in expected {
            assert!(
                report.findings.iter().any(|finding| {
                    finding.rule_id == rule_id
                        && finding.severity == severity
                        && finding.file_path == path
                        && finding.line == line
                        && finding.symbol.as_deref() == symbol
                        && finding.fingerprint == fingerprint
                }),
                "missing expected fixture finding `{rule_id}` at {path}:{line:?}"
            );
        }
    }

    #[test]
    fn analysis_finds_core_rust_smells() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        let rust_file = dir.path().join("bad.rs");
        fs::write(
            &rust_file,
            [
                r#"pub struct Bad {
    pub name: String,
}

impl Bad {
    pub fn process(a: bool, b: Vec<String>, c: String, d: String, e: String, f: String) {
        if a {
            "#,
                PROCESS_COMMAND_NEW,
                r#"("sh").arg("-c").arg(c).spawn().unwrap();
        }
        println!("{}{}{}", d, e, f);
    }
}

#[test]
fn test_no_assert() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}
"#,
            ]
            .concat(),
        )
        .expect("fixture write");
        let report = analyse_project_paths(dir.path(), vec![PathBuf::from(".")]);

        let rule_ids: BTreeSet<&str> = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        assert!(rule_ids.contains("security.process-command"));
        assert!(rule_ids.contains("size.parameter-count"));
        assert!(rule_ids.contains("test-quality.no-assertions"));
        assert!(rule_ids.contains("modernisation.public-field"));
    }

    #[test]
    fn registry_rejects_duplicate_rule_ids_and_sorts_definitions() {
        let registry = rules::builtin_registry();
        assert!(registry
            .definitions()
            .windows(2)
            .all(|window| window[0].id < window[1].id));
        assert!(registry.contains("security.process-command"));

        let duplicate = registry.definitions()[0];
        assert!(rules::RuleRegistry::new(vec![duplicate, duplicate]).is_err());
    }

    #[test]
    fn config_rejects_unknown_root_keys_and_rule_ids() {
        let dir = tempdir().expect("tempdir");
        let options = default_test_options();

        write_config(dir.path(), r#"{ "unknown": true }"#);
        let error = load_config(dir.path(), &options).expect_err("unknown root key rejected");
        assert!(error.contains("unknown key `unknown`"), "{error}");

        write_config(
            dir.path(),
            r#"{ "rules": { "unknown.rule": { "enabled": false } } }"#,
        );
        let error = load_config(dir.path(), &options).expect_err("unknown rule rejected");
        assert!(error.contains("unknown rule id `unknown.rule`"), "{error}");
    }

    #[test]
    fn config_rejects_threshold_maps_and_unknown_options() {
        let dir = tempdir().expect("tempdir");
        let options = default_test_options();

        write_config(
            dir.path(),
            r#"{ "rules": { "size.parameter-count": { "thresholds": { "bogus": 1 } } } }"#,
        );
        let error = load_config(dir.path(), &options).expect_err("threshold map rejected");
        assert!(
            error.contains("unknown key `thresholds` in config for rule `size.parameter-count`"),
            "{error}"
        );

        write_config(
            dir.path(),
            r#"{ "rules": { "size.parameter-count": { "options": { "bogus": true } } } }"#,
        );
        let error = load_config(dir.path(), &options).expect_err("unknown option rejected");
        assert!(error.contains("unknown option `bogus`"), "{error}");
    }

    #[test]
    fn rust_yaml_config_is_the_only_default_config_name() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("sample.rs"),
            r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String) {
    println!("{}{}{}{}{}", b, c, d, e, f);
    if a {
        println!("active");
    }
}
"#,
        )
        .expect("fixture write");
        write_config(
            dir.path(),
            r#"
rules:
  size.parameter-count:
    threshold: 10
    severity: warning
"#,
        );

        let yaml_default = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("gruff-rs yaml config is the preferred default");
        assert_missing_rule(&yaml_default, "size.parameter-count");
    }

    #[test]
    fn unsupported_config_extensions_are_rejected() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("config.json"), "{}").expect("unsupported config write");
        let error = load_config(
            dir.path(),
            &AnalysisOptions {
                config: Some(PathBuf::from("config.json")),
                ..default_test_options()
            },
        )
        .expect_err("unsupported config extension rejected");
        assert!(
            error.contains("unsupported config extension `json`"),
            "{error}"
        );
    }

    #[test]
    fn threshold_overrides_require_one_value_and_one_severity() {
        let dir = tempdir().expect("tempdir");
        let options = default_test_options();

        write_config(
            dir.path(),
            r#"
rules:
  complexity.cognitive:
    threshold: 20
    severity: error
"#,
        );
        let config = load_config(dir.path(), &options).expect("threshold and severity accepted");
        assert_eq!(config.threshold("complexity.cognitive", 15.0), 20.0);
        assert_eq!(
            config.severity("complexity.cognitive", Severity::Warning),
            Severity::Error
        );

        write_config(
            dir.path(),
            r#"
rules:
  complexity.cognitive:
    threshold: 20
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("severity required");
        assert!(
            error.contains(
                "config key `rules.complexity.cognitive.severity` is required when `threshold` is configured"
            ),
            "{error}"
        );

        write_config(
            dir.path(),
            r#"
rules:
  complexity.cognitive:
    severity: warning
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("threshold required");
        assert!(
            error.contains("config key `rules.complexity.cognitive.severity` requires `threshold`"),
            "{error}"
        );
    }

    #[test]
    fn config_disables_rules_and_overrides_threshold() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("sample.rs"),
            [
                r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String) {
    if a {
        "#,
                PROCESS_COMMAND_NEW,
                r#"("sh").arg("-c").arg(b).spawn().unwrap();
    }
    println!("{}{}{}{}", c, d, e, f);
}
"#,
            ]
            .concat(),
        )
        .expect("fixture write");
        write_config(
            dir.path(),
            r#"{
  "rules": {
    "security.process-command": { "enabled": false },
    "size.parameter-count": { "threshold": 10, "severity": "warning" }
  }
}"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");

        let rule_ids: BTreeSet<&str> = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        assert!(!rule_ids.contains("security.process-command"));
        assert!(!rule_ids.contains("size.parameter-count"));
    }

    #[test]
    fn selector_set_matches_registry_with_negative_precedence() {
        let registry = rules::builtin_registry();
        let mut config = Config::default();
        config.selectors.positive =
            expand_rule_selector("Security", &registry, "test").expect("pillar selector");
        config.selectors.has_positive = true;
        config.selectors.negative =
            expand_rule_selector("security.process-command", &registry, "test")
                .expect("exact selector");

        let enabled: Vec<&str> = registry
            .definitions()
            .iter()
            .map(|definition| definition.id)
            .filter(|rule_id| config.rule_enabled(rule_id))
            .collect();
        eprintln!("selector enabled ids: {enabled:?}");

        assert!(config.rule_enabled("security.unsafe-block"));
        assert!(!config.rule_enabled("security.process-command"));
        assert!(!config.rule_enabled("docs.missing-readme"));
    }

    #[test]
    fn selector_config_supports_empty_pillar_prefix_exact_negative_and_custom_blocks() {
        let dir = tempdir().expect("tempdir");
        let options = default_test_options();

        write_config(
            dir.path(),
            r#"
rules:
  select: []
"#,
        );
        let config = load_config(dir.path(), &options).expect("empty selector accepted");
        assert!(config.rule_enabled("security.process-command"));
        assert!(config.rule_enabled("docs.missing-readme"));

        write_config(
            dir.path(),
            r#"
rules:
  select: ["Security"]
"#,
        );
        let config = load_config(dir.path(), &options).expect("pillar selector accepted");
        assert!(config.rule_enabled("security.process-command"));
        assert!(config.rule_enabled("security.unsafe-block"));
        assert!(!config.rule_enabled("docs.missing-readme"));

        write_config(
            dir.path(),
            r#"
rules:
  select: ["security"]
  ignore: ["security.process-command"]
"#,
        );
        let config =
            load_config(dir.path(), &options).expect("prefix and exact selectors accepted");
        assert!(!config.rule_enabled("security.process-command"));
        assert!(config.rule_enabled("security.unsafe-block"));
        assert!(!config.rule_enabled("docs.missing-readme"));

        write_config(
            dir.path(),
            r#"
rules:
  select: ["security.unsafe-block"]
  custom:
    security.unsafe-block:
      enabled: false
"#,
        );
        let config = load_config(dir.path(), &options).expect("custom exact block accepted");
        assert!(!config.rule_enabled("security.unsafe-block"));
        assert!(!config.rule_enabled("security.process-command"));
    }

    #[test]
    fn selector_config_rejects_unknown_pillar_prefix_exact_and_shapes() {
        let dir = tempdir().expect("tempdir");
        let options = default_test_options();

        write_config(
            dir.path(),
            r#"
rules:
  select: ["Securtiy"]
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("unknown pillar rejected");
        assert!(error.contains("unknown selector `Securtiy`"), "{error}");
        assert!(error.contains("rules.select[0]"), "{error}");

        write_config(
            dir.path(),
            r#"
rules:
  select: ["does-not-exist.*"]
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("unknown prefix rejected");
        assert!(
            error.contains("unknown selector `does-not-exist.*`"),
            "{error}"
        );

        write_config(
            dir.path(),
            r#"
rules:
  select: ["security*"]
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("unsupported glob rejected");
        assert!(
            error.contains("unsupported selector `security*`"),
            "{error}"
        );

        write_config(
            dir.path(),
            r#"
rules:
  custom:
    unknown.rule:
      enabled: false
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("unknown exact id rejected");
        assert!(error.contains("unknown rule id `unknown.rule`"), "{error}");
    }

    #[test]
    fn list_rules_selector_preview_is_deterministic() {
        let text = render_rule_list(
            Path::new("."),
            &ListRulesArgs {
                format: RuleListFormat::Text,
                selector: Some("Security".to_string()),
                config: None,
                no_config: true,
            },
        )
        .expect("selector preview");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            vec![
                "dependency.duplicate-locked-version",
                "dependency.git-source",
                "dependency.path-source",
                "dependency.wildcard-version",
                "security.process-command",
                "security.unsafe-block"
            ]
        );

        let json_output = render_rule_list(
            Path::new("."),
            &ListRulesArgs {
                format: RuleListFormat::Json,
                selector: Some("performance.*".to_string()),
                config: None,
                no_config: true,
            },
        )
        .expect("selector json preview");
        let ids: Vec<String> = serde_json::from_str(&json_output).expect("selector json");
        assert_eq!(
            ids,
            vec![
                "performance.clone-in-loop",
                "performance.format-in-loop",
                "performance.regex-in-loop"
            ]
        );
    }

    #[test]
    fn custom_rule_text_scope_emits_deterministic_findings_with_builtins() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("src/lib.rs"),
            concat!(
                "pub fn undocumented() {\n",
                "    let marker = \"ALPHA\";\n",
                "}\n",
                "// BETA\n"
            ),
        )
        .expect("fixture write");
        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.beta
    pillar: Documentation
    severity: advisory
    message: Beta marker
    scope: text
    pattern: BETA
  - id: custom.alpha
    pillar: Documentation
    severity: advisory
    message: Alpha marker
    scope: text
    pattern: ALPHA
"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("src/lib.rs")],
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        let ids: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        eprintln!("custom rule deterministic ids: {ids:?}");

        assert_eq!(
            ids,
            vec!["docs.missing-public-doc", "custom.alpha", "custom.beta"]
        );
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![Some(1), Some(2), Some(4)]
        );
    }

    #[test]
    fn custom_rule_rust_code_scope_masks_string_literals_and_text_scope_does_not() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("src/lib.rs"),
            "fn string_only() {\n    let marker = \"HACK\";\n}\n",
        )
        .expect("fixture write");
        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.hack-code
    pillar: Documentation
    severity: warning
    message: Code marker
    scope: rust-code
    pattern: HACK
  - id: custom.hack-text
    pillar: Documentation
    severity: warning
    message: Text marker
    scope: text
    pattern: HACK
rules:
  select: ["custom.*"]
"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("src/lib.rs")],
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");

        assert_has_rule(&report, "custom.hack-text");
        assert_missing_rule(&report, "custom.hack-code");
    }

    #[test]
    fn custom_rule_comments_scope_matches_comments_not_strings() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("src/lib.rs"),
            concat!(
                "fn comments() {\n",
                "    let marker = \"// HACK\";\n",
                "}\n",
                "// HACK\n"
            ),
        )
        .expect("fixture write");
        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.comment-hack
    pillar: Documentation
    severity: warning
    message: Comment marker
    scope: comments
    pattern: '(?m)^\s*//\s*HACK\b'
rules:
  select: ["custom.*"]
"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("src/lib.rs")],
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        let comment_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "custom.comment-hack")
            .collect();

        assert_eq!(comment_findings.len(), 1);
        assert_eq!(comment_findings[0].line, Some(4));
    }

    #[test]
    fn custom_rule_include_exclude_paths_are_honored() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src/generated")).expect("generated dir");
        fs::create_dir_all(dir.path().join("tests")).expect("tests dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(dir.path().join("src/lib.rs"), "ALLOW_MARKER\n").expect("src write");
        fs::write(dir.path().join("src/generated/lib.rs"), "ALLOW_MARKER\n")
            .expect("generated write");
        fs::write(dir.path().join("tests/fixture.rs"), "ALLOW_MARKER\n").expect("tests write");
        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.path-marker
    pillar: Documentation
    severity: advisory
    message: Path marker
    scope: text
    pattern: ALLOW_MARKER
    include_paths: ["src/**"]
    exclude_paths: ["src/generated/**"]
rules:
  select: ["custom.*"]
"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("src"), PathBuf::from("tests")],
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        let paths: Vec<&str> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "custom.path-marker")
            .map(|finding| finding.file_path.as_str())
            .collect();

        assert_eq!(paths, vec!["src/lib.rs"]);
    }

    #[test]
    fn custom_rule_config_rejects_duplicate_id_missing_prefix_bad_regex_and_bad_settings() {
        let dir = tempdir().expect("tempdir");
        let options = default_test_options();

        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.dup
    pillar: Documentation
    severity: advisory
    message: First
    scope: text
    pattern: FIRST
  - id: custom.dup
    pillar: Documentation
    severity: advisory
    message: Second
    scope: text
    pattern: SECOND
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("duplicate rejected");
        assert!(
            error.contains("duplicate custom rule id `custom.dup`"),
            "{error}"
        );

        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: no-prefix
    pillar: Documentation
    severity: advisory
    message: Missing prefix
    scope: text
    pattern: MARKER
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("prefix rejected");
        assert!(
            error.contains("must start with the reserved `custom.` namespace"),
            "{error}"
        );
        assert!(error.contains("custom_rules[0].id"), "{error}");

        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.bad-regex
    pillar: Documentation
    severity: advisory
    message: Bad regex
    scope: text
    pattern: '['
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("bad regex rejected");
        assert!(
            error.contains("config key `custom_rules[0].pattern` failed to compile regex"),
            "{error}"
        );

        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.threshold
    pillar: Documentation
    severity: advisory
    message: Threshold
    scope: text
    pattern: MARKER
rules:
  custom.threshold:
    threshold: 1
"#,
        );
        let error = load_config(dir.path(), &options).expect_err("bad setting rejected");
        assert!(
            error.contains("custom rule `custom.threshold` only supports `enabled`"),
            "{error}"
        );
    }

    #[test]
    fn custom_rule_no_match_is_ok() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(dir.path().join("src/lib.rs"), "fn clean() {}\n").expect("fixture write");
        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.no-match
    pillar: Documentation
    severity: advisory
    message: No match
    scope: text
    pattern: ABSENT_MARKER
rules:
  select: ["custom.*"]
"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("src/lib.rs")],
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");

        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    #[test]
    fn custom_rule_findings_pass_selection_exclusion_baseline_and_diff() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("src/lib.rs"),
            "fn selected() {}\nCUSTOM_MARKER\n",
        )
        .expect("selected write");
        fs::write(dir.path().join("src/excluded.rs"), "CUSTOM_MARKER\n").expect("excluded write");
        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.marker
    pillar: Documentation
    severity: warning
    message: Custom marker
    scope: text
    pattern: CUSTOM_MARKER
rules:
  select: ["custom.marker"]
exclude:
  - rule: custom.marker
    paths: ["src/excluded.rs"]
    reason: generated custom marker
"#,
        );

        let selected = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("src")],
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("selection and exclusion analysis succeeds");
        assert_eq!(selected.findings.len(), 1);
        assert_eq!(selected.findings[0].rule_id, "custom.marker");
        assert_eq!(selected.findings[0].file_path, "src/lib.rs");
        assert_missing_rule(&selected, "docs.missing-public-doc");
        assert_eq!(total_suppressed_findings(&selected.suppressions), 1);

        let baseline_path = dir.path().join("baseline.json");
        write_baseline(&baseline_path, &[selected.findings[0].clone()]).expect("baseline write");
        let baseline_filtered = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("src")],
                baseline: Some(PathBuf::from("baseline.json")),
                no_baseline: false,
                ..default_test_options()
            },
        )
        .expect("baseline analysis succeeds");
        assert!(baseline_filtered.findings.is_empty());
        assert_eq!(
            baseline_filtered
                .baseline
                .as_ref()
                .map(|baseline| baseline.suppressed),
            Some(1)
        );

        fs::write(
            dir.path().join("src/lib.rs"),
            "CUSTOM_MARKER\nfn gap() {}\nCUSTOM_MARKER\n",
        )
        .expect("diff fixture rewrite");
        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.marker
    pillar: Documentation
    severity: warning
    message: Custom marker
    scope: text
    pattern: CUSTOM_MARKER
rules:
  select: ["custom.marker"]
"#,
        );
        fs::write(
            dir.path().join("custom.patch"),
            concat!(
                "diff --git a/src/lib.rs b/src/lib.rs\n",
                "--- a/src/lib.rs\n",
                "+++ b/src/lib.rs\n",
                "@@ -3,1 +3,1 @@\n",
                "+CUSTOM_MARKER\n"
            ),
        )
        .expect("patch write");
        let diff_filtered = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("src/lib.rs")],
                diff: Some(DiffSelection::Patch(PathBuf::from("custom.patch"))),
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("diff analysis succeeds");
        assert_eq!(diff_filtered.findings.len(), 1);
        assert_eq!(diff_filtered.findings[0].line, Some(3));
        assert!(diff_filtered
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.diagnostic_type == "patch-filter"));
    }

    #[test]
    fn custom_rule_list_rules_includes_configured_rules_and_selectors() {
        let dir = tempdir().expect("tempdir");
        write_config(
            dir.path(),
            r#"
custom_rules:
  - id: custom.second
    pillar: Documentation
    severity: advisory
    message: Second custom rule
    scope: text
    pattern: SECOND
  - id: custom.first
    pillar: Security
    severity: warning
    message: First custom rule
    scope: text
    pattern: FIRST
"#,
        );

        let json_output = render_rule_list(
            dir.path(),
            &ListRulesArgs {
                format: RuleListFormat::Json,
                selector: None,
                config: None,
                no_config: false,
            },
        )
        .expect("rule list json");
        let rules: Vec<Value> = serde_json::from_str(&json_output).expect("rule list json");
        let ids: Vec<&str> = rules
            .iter()
            .map(|rule| rule["id"].as_str().expect("id"))
            .collect();
        let first_custom = ids
            .iter()
            .position(|id| id.starts_with("custom."))
            .expect("custom rule listed");
        assert!(ids[..first_custom]
            .iter()
            .all(|id| !id.starts_with("custom.")));
        assert_eq!(&ids[first_custom..], ["custom.first", "custom.second"]);
        assert!(rules.iter().any(|rule| {
            rule["id"] == "custom.first"
                && rule["kind"] == "custom"
                && rule["customScope"] == "text"
                && rule["pattern"] == "FIRST"
        }));

        let selector_output = render_rule_list(
            dir.path(),
            &ListRulesArgs {
                format: RuleListFormat::Json,
                selector: Some("custom.*".to_string()),
                config: None,
                no_config: false,
            },
        )
        .expect("custom selector");
        let selected: Vec<String> = serde_json::from_str(&selector_output).expect("selector json");
        assert_eq!(selected, vec!["custom.first", "custom.second"]);
    }

    #[test]
    fn registry_reserves_custom_namespace() {
        assert!(rules::builtin_registry()
            .definitions()
            .iter()
            .all(|definition| !definition.id.starts_with("custom.")));

        let definition = rules::RuleDefinition {
            id: "custom.builtin",
            name: "Reserved",
            pillar: Pillar::Documentation,
            tier: "v0.1",
            kind: rules::RuleKind::Text,
            default_severity: Severity::Advisory,
            confidence: Confidence::High,
            threshold: None,
            options: &[],
            default_enabled: true,
            description: "Reserved namespace probe.",
        };
        let error = rules::RuleRegistry::new(vec![definition])
            .expect_err("custom namespace reserved for config rules");
        assert!(
            error.contains("built-in rule id `custom.builtin` uses reserved custom namespace"),
            "{error}"
        );
    }

    #[test]
    fn fingerprint_stable_for_custom_rule() {
        let finding = Finding::new(
            "custom.no-hack",
            "HACK marker",
            "src/lib.rs",
            Some(2),
            Severity::Warning,
            Pillar::Documentation,
            Confidence::Medium,
            Some("byte:12".to_string()),
            None,
            json!({ "scope": "comments" }),
        );

        assert_eq!(finding.fingerprint, "223b4b2c56b0f0e1");
    }

    #[test]
    fn legacy_config_byte_identical_rule_blocks_remain_selector_neutral() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("sample.rs"),
            [
                r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String) {
    if a {
        "#,
                PROCESS_COMMAND_NEW,
                r#"("sh").arg("-c").arg(b).spawn().unwrap();
    }
    println!("{}{}{}{}", c, d, e, f);
}
"#,
            ]
            .concat(),
        )
        .expect("fixture write");
        write_config(
            dir.path(),
            r#"{
  "rules": {
    "security.process-command": { "enabled": false }
  }
}"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");

        assert_missing_rule(&report, "security.process-command");
        assert_has_rule(&report, "size.parameter-count");
    }

    #[test]
    fn config_secret_previews_allowlist_only_matching_synthetic_values() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        let accepted_fixture = concat!("ghp_", "aaaaaaaaaaaaaaaaaaaaaa");
        let unlisted_secret = concat!("ghp_", "bbbbbbbbbbbbbbbbbbbbbb");
        let sample = format!(
            r#"pub fn entry() {{
    let accepted_fixture = "{accepted_fixture}";
    let unlisted_secret = "{unlisted_secret}";
    println!("{{accepted_fixture}}{{unlisted_secret}}");
}}
"#
        );
        fs::write(dir.path().join("sample.rs"), sample).expect("fixture write");
        write_config(
            dir.path(),
            r#"
allowlists:
  secretPreviews:
    - "ghp_...aaaa (redacted, 26 chars)"
"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        let api_key_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "sensitive-data.api-key-pattern")
            .collect();

        assert_eq!(
            api_key_findings.len(),
            1,
            "expected only the unlisted API key preview to remain; findings={api_key_findings:?}"
        );
        assert_eq!(
            api_key_findings[0].metadata["preview"],
            "ghp_...bbbb (redacted, 26 chars)"
        );
    }

    #[test]
    fn rule_fixtures_prove_complexity_and_naming_rules() {
        let _guard = analysis_lock();
        let positive = analyse_test_paths(vec![PathBuf::from(
            "tests/fixtures/rules/complexity_naming_positive.rs",
        )]);
        let negative = analyse_test_paths(vec![PathBuf::from(
            "tests/fixtures/rules/complexity_naming_negative.rs",
        )]);

        assert_has_rule(&positive, "complexity.nesting-depth");
        assert_has_rule(&positive, "complexity.npath");
        assert_has_rule(&positive, "naming.boolean-prefix");
        assert_has_rule(&positive, "naming.placeholder-identifier");

        assert_missing_rule(&negative, "complexity.nesting-depth");
        assert_missing_rule(&negative, "complexity.npath");
        assert_missing_rule(&negative, "naming.boolean-prefix");
        assert_missing_rule(&negative, "naming.placeholder-identifier");
    }

    #[test]
    fn rule_fixtures_prove_security_sensitive_and_test_quality_rules() {
        let _guard = analysis_lock();
        let security_positive = analyse_test_paths(vec![PathBuf::from(
            "tests/fixtures/rules/security_sensitive_positive.rs",
        )]);
        let security_negative = analyse_test_paths(vec![PathBuf::from(
            "tests/fixtures/rules/security_sensitive_negative.rs",
        )]);
        let test_positive = analyse_test_paths(vec![PathBuf::from(
            "tests/fixtures/rules/test_quality_positive.rs",
        )]);
        let test_negative = analyse_test_paths(vec![PathBuf::from(
            "tests/fixtures/rules/test_quality_negative.rs",
        )]);

        assert_has_rule(&security_positive, "security.unsafe-block");
        assert_has_rule(&security_positive, "sensitive-data.hardcoded-env-value");
        assert_has_rule(&security_positive, "sensitive-data.high-entropy-string");

        assert_missing_rule(&security_negative, "security.unsafe-block");
        assert_missing_rule(&security_negative, "sensitive-data.hardcoded-env-value");
        assert_missing_rule(&security_negative, "sensitive-data.high-entropy-string");

        assert_has_rule(&test_positive, "test-quality.ignored-without-reason");
        assert_has_rule(&test_positive, "test-quality.long-test");
        assert_has_rule(&test_positive, "test-quality.trivial-assertion");

        assert_missing_rule(&test_negative, "test-quality.ignored-without-reason");
        assert_missing_rule(&test_negative, "test-quality.long-test");
        assert_missing_rule(&test_negative, "test-quality.trivial-assertion");
        assert_missing_rule(&test_negative, "test-quality.sleep-in-test");
        assert_missing_rule(&test_negative, "test-quality.no-assertions");
    }

    #[test]
    fn project_model_indexes_manifest_modules_items_and_calls_deterministically() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "project-model-fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1"
regex = { version = "1", default-features = false }

[dev-dependencies]
tempfile = "3"
"#,
        )
        .expect("manifest write");
        fs::write(
            dir.path().join("Cargo.lock"),
            r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "project-model-fixture"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("lockfile write");
        fs::write(
            dir.path().join("src/lib.rs"),
            r#"pub mod api {
    pub struct Public;

    fn helper() {}

    pub fn call_helper() {
        helper();
    }

    impl Public {
        pub fn new() -> Self {
            Public
        }
    }
}

mod external;
"#,
        )
        .expect("lib write");
        fs::write(
            dir.path().join("src/external.rs"),
            "pub fn visible_external() {}\n",
        )
        .expect("external write");

        let first = project_context_for_test(dir.path());
        let second = project_context_for_test(dir.path());

        assert_eq!(first.manifest, second.manifest);
        assert_eq!(first.lockfile, second.lockfile);
        assert_eq!(first.modules, second.modules);
        assert_eq!(first.items, second.items);
        assert_eq!(first.call_names, second.call_names);
        assert!(first.diagnostics.is_empty(), "{:?}", first.diagnostics);

        let manifest = first.manifest.as_ref().expect("manifest summary");
        assert_eq!(manifest.file_path, "Cargo.toml");
        assert_eq!(
            manifest.package_name.as_deref(),
            Some("project-model-fixture")
        );
        assert!(manifest.dependencies.iter().any(|dependency| {
            dependency.section == "dependencies"
                && dependency.name == "serde"
                && dependency.requirement.as_deref() == Some("1")
        }));
        assert!(manifest.dependencies.iter().any(|dependency| {
            dependency.section == "dev-dependencies"
                && dependency.name == "tempfile"
                && dependency.requirement.as_deref() == Some("3")
        }));

        let lockfile = first.lockfile.as_ref().expect("lockfile summary");
        assert_eq!(lockfile.file_path, "Cargo.lock");
        assert!(lockfile
            .packages
            .iter()
            .any(|package| package.name == "serde" && package.version == "1.0.0"));

        assert!(first.modules.iter().any(|module| {
            module.file_path == "src/lib.rs"
                && module.module_path == "api"
                && module.public
                && module.inline
        }));
        assert!(first.modules.iter().any(|module| {
            module.file_path == "src/lib.rs"
                && module.module_path == "external"
                && !module.public
                && !module.inline
        }));
        assert!(first.items.iter().any(|item| {
            item.file_path == "src/lib.rs"
                && item.module_path == "api"
                && item.name == "Public"
                && item.kind == "struct"
                && item.public
        }));
        assert!(first.items.iter().any(|item| {
            item.file_path == "src/lib.rs"
                && item.module_path == "api"
                && item.name == "helper"
                && item.kind == "function"
                && !item.public
        }));
        assert!(first.call_names.iter().any(|call| {
            call.file_path == "src/lib.rs" && call.name == "helper" && call.line == 7
        }));
    }

    #[test]
    fn project_model_handles_missing_and_invalid_cargo_metadata() {
        let _guard = analysis_lock();
        let missing_dir = tempdir().expect("tempdir");
        fs::create_dir_all(missing_dir.path().join("src")).expect("src dir");
        fs::write(missing_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(missing_dir.path().join("src/lib.rs"), "pub fn ready() {}\n").expect("lib write");
        let missing = project_context_for_test(missing_dir.path());
        assert!(missing.manifest.is_none());
        assert!(missing.lockfile.is_none());
        assert!(missing.diagnostics.is_empty(), "{:?}", missing.diagnostics);

        let invalid_manifest_dir = tempdir().expect("tempdir");
        fs::write(invalid_manifest_dir.path().join("README.md"), "# Fixture\n")
            .expect("readme write");
        fs::write(invalid_manifest_dir.path().join("Cargo.toml"), "[package\n")
            .expect("manifest write");
        let invalid_manifest = project_context_for_test(invalid_manifest_dir.path());
        assert!(invalid_manifest.manifest.is_none());
        assert_eq!(invalid_manifest.diagnostics.len(), 1);
        assert_eq!(
            invalid_manifest.diagnostics[0].diagnostic_type,
            "manifest-parse-error"
        );
        assert_eq!(
            invalid_manifest.diagnostics[0].file_path.as_deref(),
            Some("Cargo.toml")
        );
        assert!(!invalid_manifest.diagnostics[0]
            .message
            .to_ascii_lowercase()
            .contains("parser"));

        let invalid_lock_dir = tempdir().expect("tempdir");
        fs::write(invalid_lock_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            invalid_lock_dir.path().join("Cargo.toml"),
            r#"[package]
name = "invalid-lock-fixture"
version = "0.1.0"
"#,
        )
        .expect("manifest write");
        fs::write(invalid_lock_dir.path().join("Cargo.lock"), "[package\n")
            .expect("lockfile write");
        let invalid_lock = project_context_for_test(invalid_lock_dir.path());
        assert!(invalid_lock.manifest.is_some());
        assert_eq!(invalid_lock.diagnostics.len(), 1);
        assert_eq!(
            invalid_lock.diagnostics[0].diagnostic_type,
            "lockfile-parse-error"
        );
        assert_eq!(
            invalid_lock.diagnostics[0].file_path.as_deref(),
            Some("Cargo.lock")
        );
    }

    #[test]
    fn dependency_rules_flag_local_manifest_and_lockfile_posture() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "dependency-positive-fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
wildcard = "*"
gitdep = { git = "https://example.invalid/repo.git", rev = "1111111111111111111111111111111111111111" }
pathdep = { path = "../local-path" }
"#,
        )
        .expect("manifest write");
        fs::write(
            dir.path().join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "duplicate"
version = "1.0.0"

[[package]]
name = "duplicate"
version = "2.0.0"

[[package]]
name = "duplicate"
version = "3.0.0"
"#,
        )
        .expect("lockfile write");

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");

        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
        assert_has_rule(&report, "dependency.git-source");
        assert_has_rule(&report, "dependency.path-source");
        assert_has_rule(&report, "dependency.wildcard-version");
        assert_has_rule(&report, "dependency.duplicate-locked-version");
        assert_has_rule(&report, "dependency.missing-package-metadata");

        let git = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "dependency.git-source")
            .expect("git source finding");
        assert_eq!(git.file_path, "Cargo.toml");
        assert_eq!(git.line, Some(8));
        assert_eq!(git.symbol.as_deref(), Some("gitdep"));
        assert_eq!(git.pillar, Pillar::Security);

        let metadata = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "dependency.missing-package-metadata")
            .expect("metadata finding");
        assert_eq!(metadata.file_path, "Cargo.toml");
        assert_eq!(metadata.line, Some(1));
        assert_eq!(metadata.pillar, Pillar::Documentation);

        let duplicate = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "dependency.duplicate-locked-version")
            .expect("duplicate lockfile finding");
        assert_eq!(duplicate.file_path, "Cargo.lock");
        assert_eq!(duplicate.line, Some(4));
        assert_eq!(duplicate.symbol.as_deref(), Some("duplicate"));

        let security = report
            .score
            .pillars
            .iter()
            .find(|pillar| pillar.pillar == Pillar::Security)
            .expect("security score");
        assert!(
            security.findings >= 4,
            "expected dependency findings to affect security: {security:?}"
        );
    }

    #[test]
    fn dependency_rules_accept_clean_manifest_and_config_threshold() {
        let _guard = analysis_lock();
        let clean_dir = tempdir().expect("tempdir");
        fs::write(clean_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            clean_dir.path().join("Cargo.toml"),
            r#"[package]
name = "dependency-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dependency rule tests."
license = "MIT"

[dependencies]
serde = "1"
"#,
        )
        .expect("manifest write");
        fs::write(
            clean_dir.path().join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "serde"
version = "1.0.0"
"#,
        )
        .expect("lockfile write");
        let clean = run_project_analysis(
            clean_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("clean analysis succeeds");
        assert_missing_rule(&clean, "dependency.git-source");
        assert_missing_rule(&clean, "dependency.path-source");
        assert_missing_rule(&clean, "dependency.wildcard-version");
        assert_missing_rule(&clean, "dependency.duplicate-locked-version");
        assert_missing_rule(&clean, "dependency.missing-package-metadata");

        let threshold_dir = tempdir().expect("tempdir");
        fs::write(threshold_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            threshold_dir.path().join("Cargo.toml"),
            r#"[package]
name = "dependency-threshold-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dependency threshold tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            threshold_dir.path().join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "duplicate"
version = "1.0.0"

[[package]]
name = "duplicate"
version = "2.0.0"

[[package]]
name = "duplicate"
version = "3.0.0"
"#,
        )
        .expect("lockfile write");
        write_config(
            threshold_dir.path(),
            r#"
rules:
  dependency.duplicate-locked-version:
    threshold: 3
    severity: advisory
"#,
        );
        let thresholded = run_project_analysis(
            threshold_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("thresholded analysis succeeds");
        assert_missing_rule(&thresholded, "dependency.duplicate-locked-version");

        write_config(
            threshold_dir.path(),
            r#"
rules:
  dependency.duplicate-locked-version:
    threshold: 2
    severity: severe
"#,
        );
        let error =
            load_config(threshold_dir.path(), &default_test_options()).expect_err("bad threshold");
        assert!(
            error.contains(
                "config key `rules.dependency.duplicate-locked-version.severity` must be advisory, warning, or error"
            ),
            "{error}"
        );
    }

    #[test]
    fn architecture_rules_flag_module_shape_and_public_surface() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "architecture-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for architecture rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            dir.path().join("src/lib.rs"),
            r#"pub mod api {
    pub struct One;
    pub struct Two;
    pub enum Three {
        Ready,
    }
    pub trait Four {}
}
mod alpha;
mod beta;
mod gamma;
"#,
        )
        .expect("lib write");
        write_config(
            dir.path(),
            r#"
rules:
  architecture.module-fan-out:
    threshold: 2
    severity: advisory
  architecture.public-api-surface:
    threshold: 2
    severity: advisory
  architecture.large-module:
    threshold: 3
    severity: advisory
"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("architecture analysis succeeds");

        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
        assert_has_rule(&report, "architecture.module-fan-out");
        assert_has_rule(&report, "architecture.public-api-surface");
        assert_has_rule(&report, "architecture.large-module");

        let fan_out = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "architecture.module-fan-out")
            .expect("module fan-out finding");
        assert_eq!(fan_out.file_path, "src/lib.rs");
        assert_eq!(fan_out.line, Some(1));
        assert_eq!(fan_out.symbol.as_deref(), Some("src/lib.rs"));
        assert_eq!(fan_out.metadata["modules"], json!(4));
        assert!(fan_out.message.contains("4 child modules"));

        let public_surface = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "architecture.public-api-surface")
            .expect("public API finding");
        assert_eq!(public_surface.symbol.as_deref(), Some("api"));
        assert_eq!(public_surface.metadata["publicItems"], json!(4));

        let large_module = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "architecture.large-module")
            .expect("large module finding");
        assert_eq!(large_module.symbol.as_deref(), Some("api"));
        assert_eq!(large_module.metadata["items"], json!(4));
    }

    #[test]
    fn architecture_rules_accept_small_modules_and_validate_threshold() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "architecture-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for architecture rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            dir.path().join("src/lib.rs"),
            r#"pub mod api {
    pub struct One;
}
mod alpha;
"#,
        )
        .expect("lib write");

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("small architecture analysis succeeds");
        assert_missing_rule(&report, "architecture.module-fan-out");
        assert_missing_rule(&report, "architecture.public-api-surface");
        assert_missing_rule(&report, "architecture.large-module");

        write_config(
            dir.path(),
            r#"
rules:
  architecture.large-module:
    threshold: 2
    severity: severe
"#,
        );
        let error =
            load_config(dir.path(), &default_test_options()).expect_err("bad threshold rejected");
        assert!(
            error.contains(
                "config key `rules.architecture.large-module.severity` must be advisory, warning, or error"
            ),
            "{error}"
        );
    }

    #[test]
    fn dead_code_project_candidates_use_conservative_cross_file_evidence() {
        let _guard = analysis_lock();
        let positive_dir = tempdir().expect("tempdir");
        fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
        fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            positive_dir.path().join("Cargo.toml"),
            r#"[package]
name = "dead-code-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dead-code rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            positive_dir.path().join("src/lib.rs"),
            r#"fn isolated_helper() {}

struct HiddenType;

enum HiddenEnum {
    Ready,
}

trait HiddenTrait {}

fn referenced_helper() {}

pub fn entry() {
    referenced_helper();
}
"#,
        )
        .expect("positive lib write");

        let positive = run_project_analysis(
            positive_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("dead-code positive analysis succeeds");
        assert_has_rule(&positive, "dead-code.unused-private-item-candidate");
        let candidate = positive
            .findings
            .iter()
            .find(|finding| {
                finding.rule_id == "dead-code.unused-private-item-candidate"
                    && finding.symbol.as_deref() == Some("isolated_helper")
            })
            .expect("isolated helper candidate");
        assert!(candidate.message.contains("candidate"));
        assert!(matches!(candidate.confidence, Confidence::Medium));
        assert_eq!(candidate.metadata["candidate"], json!(true));

        let negative_dir = tempdir().expect("tempdir");
        fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
        fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            negative_dir.path().join("Cargo.toml"),
            r#"[package]
name = "dead-code-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for dead-code rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            negative_dir.path().join("src/lib.rs"),
            r#"macro_rules! register {
    ($item:ident) => {};
}

fn macro_registered() {}
register!(macro_registered);

#[cfg(feature = "optional")]
fn cfg_only() {}

#[test]
fn test_only_helper() {}

mod tests {
    fn module_test_helper() {}
}

fn referenced_helper() {}

pub fn entry() {
    referenced_helper();
}
"#,
        )
        .expect("negative lib write");

        let negative = run_project_analysis(
            negative_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("dead-code negative analysis succeeds");
        assert_missing_rule(&negative, "dead-code.unused-private-item-candidate");
    }

    #[test]
    fn error_handling_rules_flag_production_hazards_and_skip_tests() {
        let _guard = analysis_lock();
        let positive_dir = tempdir().expect("tempdir");
        fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
        fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            positive_dir.path().join("Cargo.toml"),
            r#"[package]
name = "error-handling-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for error-handling rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            positive_dir.path().join("src/lib.rs"),
            r#"pub fn parse_public(input: &str) -> usize {
    input.parse::<usize>().unwrap()
}

pub fn production_panic(flag: bool) {
    if flag {
        panic!("broken invariant");
    }
}

fn unfinished() {
    todo!("finish this branch");
}

fn private_unwrap(input: &str) -> usize {
    input.parse::<usize>().unwrap()
}
"#,
        )
        .expect("positive lib write");

        let positive = run_project_analysis(
            positive_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("error-handling positive analysis succeeds");
        assert_has_rule(&positive, "error-handling.production-panic");
        assert_has_rule(&positive, "error-handling.unimplemented-placeholder");
        assert_has_rule(&positive, "error-handling.public-unwrap");
        assert_has_rule(&positive, "waste.unwrap-expect");

        let public_unwrap = positive
            .findings
            .iter()
            .find(|finding| finding.rule_id == "error-handling.public-unwrap")
            .expect("public unwrap finding");
        assert_eq!(public_unwrap.symbol.as_deref(), Some("parse_public"));
        assert_eq!(public_unwrap.severity, Severity::Warning);
        assert!(matches!(public_unwrap.confidence, Confidence::High));
        assert!(public_unwrap
            .remediation
            .as_deref()
            .is_some_and(|message| message.contains("Result")));

        let panic = positive
            .findings
            .iter()
            .find(|finding| finding.rule_id == "error-handling.production-panic")
            .expect("production panic finding");
        assert_eq!(panic.symbol.as_deref(), Some("production_panic"));
        assert!(panic.message.contains("panic!"));

        let negative_dir = tempdir().expect("tempdir");
        fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
        fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            negative_dir.path().join("Cargo.toml"),
            r#"[package]
name = "error-handling-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for error-handling rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            negative_dir.path().join("src/lib.rs"),
            r#"pub fn parse_public(input: &str) -> Result<usize, std::num::ParseIntError> {
    input.parse::<usize>()
}

pub fn documented_invariant(flag: bool) {
    // PANIC: this branch represents an impossible state checked by the caller.
    if flag {
        panic!("documented invariant");
    }
}

#[test]
fn panic_in_test() {
    panic!("expected failure");
}

mod tests {
    pub fn helper_placeholder() {
        todo!("test helper");
    }
}
"#,
        )
        .expect("negative lib write");

        let negative = run_project_analysis(
            negative_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("error-handling negative analysis succeeds");
        assert_missing_rule(&negative, "error-handling.production-panic");
        assert_missing_rule(&negative, "error-handling.unimplemented-placeholder");
        assert_missing_rule(&negative, "error-handling.public-unwrap");
    }

    #[test]
    fn concurrency_rules_flag_narrow_async_and_channel_patterns() {
        let _guard = analysis_lock();
        let positive_dir = tempdir().expect("tempdir");
        fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
        fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            positive_dir.path().join("Cargo.toml"),
            r#"[package]
name = "concurrency-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for concurrency rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            positive_dir.path().join("src/lib.rs"),
            r#"pub async fn blocks_runtime() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}

pub async fn holds_lock(lock: &std::sync::Mutex<String>) {
    let guard = lock.lock().unwrap();
    async_step().await;
    println!("{}", *guard);
}

pub fn creates_unbounded_channel() {
    let (_tx, _rx) = std::sync::mpsc::channel::<String>();
}

async fn async_step() {}
"#,
        )
        .expect("positive lib write");

        let positive = run_project_analysis(
            positive_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("concurrency positive analysis succeeds");
        assert_has_rule(&positive, "concurrency.blocking-call-in-async");
        assert_has_rule(&positive, "concurrency.lock-across-await");
        assert_has_rule(&positive, "concurrency.unbounded-channel");

        let blocking = positive
            .findings
            .iter()
            .find(|finding| finding.rule_id == "concurrency.blocking-call-in-async")
            .expect("blocking async finding");
        assert_eq!(blocking.symbol.as_deref(), Some("blocks_runtime"));
        assert!(blocking.message.contains("std::thread::sleep"));
        assert!(matches!(blocking.confidence, Confidence::Medium));

        let lock = positive
            .findings
            .iter()
            .find(|finding| finding.rule_id == "concurrency.lock-across-await")
            .expect("lock across await finding");
        assert_eq!(lock.symbol.as_deref(), Some("holds_lock"));
        assert_eq!(lock.metadata["guard"], json!("guard"));

        let negative_dir = tempdir().expect("tempdir");
        fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
        fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            negative_dir.path().join("Cargo.toml"),
            r#"[package]
name = "concurrency-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for concurrency rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            negative_dir.path().join("src/lib.rs"),
            r#"pub async fn async_timer() {
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
}

pub async fn drops_before_await(lock: &std::sync::Mutex<String>) {
    let guard = lock.lock().unwrap();
    drop(guard);
    async_step().await;
}

pub fn bounded_channel() {
    let (_tx, _rx) = tokio::sync::mpsc::channel::<String>(16);
}

mod tests {
    pub async fn blocking_test_helper() {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    pub fn test_channel_helper() {
        let (_tx, _rx) = std::sync::mpsc::channel::<String>();
    }
}

async fn async_step() {}
"#,
        )
        .expect("negative lib write");

        let negative = run_project_analysis(
            negative_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("concurrency negative analysis succeeds");
        assert_missing_rule(&negative, "concurrency.blocking-call-in-async");
        assert_missing_rule(&negative, "concurrency.lock-across-await");
        assert_missing_rule(&negative, "concurrency.unbounded-channel");
    }

    #[test]
    fn performance_rules_flag_loop_scoped_hotspots() {
        let _guard = analysis_lock();
        let positive_dir = tempdir().expect("tempdir");
        fs::create_dir_all(positive_dir.path().join("src")).expect("src dir");
        fs::write(positive_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            positive_dir.path().join("Cargo.toml"),
            r#"[package]
name = "performance-positive-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for performance rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            positive_dir.path().join("src/lib.rs"),
            r#"pub fn loop_hotspots(values: &[String]) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        let regex = Regex::new("ready").unwrap();
        if regex.is_match(value) {
            output.push(format!("{}", value.clone()));
        }
    }
    output
}
"#,
        )
        .expect("positive lib write");

        let positive = run_project_analysis(
            positive_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("performance positive analysis succeeds");
        assert_has_rule(&positive, "performance.regex-in-loop");
        assert_has_rule(&positive, "performance.format-in-loop");
        assert_has_rule(&positive, "performance.clone-in-loop");

        let regex = positive
            .findings
            .iter()
            .find(|finding| finding.rule_id == "performance.regex-in-loop")
            .expect("regex-in-loop finding");
        assert_eq!(regex.symbol.as_deref(), Some("loop_hotspots"));
        assert_eq!(regex.metadata["pattern"], json!("Regex::new"));
        assert_eq!(regex.metadata["occurrences"], json!(1));
        assert!(regex.message.contains("Regex::new"));

        let waste = positive
            .score
            .pillars
            .iter()
            .find(|pillar| pillar.pillar == Pillar::Waste)
            .expect("waste score");
        assert!(
            waste.findings >= 3,
            "expected performance findings in waste: {waste:?}"
        );

        let negative_dir = tempdir().expect("tempdir");
        fs::create_dir_all(negative_dir.path().join("src")).expect("src dir");
        fs::write(negative_dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            negative_dir.path().join("Cargo.toml"),
            r#"[package]
name = "performance-negative-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for performance rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            negative_dir.path().join("src/lib.rs"),
            r#"pub fn setup_outside_loop(values: &[String]) -> Vec<String> {
    let regex = Regex::new("ready").unwrap();
    let label = format!("{}", values.len());
    let cloned = label.clone();
    let mut output = Vec::new();
    for value in values {
        if regex.is_match(value) {
            output.push(cloned.to_string());
        }
    }
    output
}
"#,
        )
        .expect("negative lib write");

        let negative = run_project_analysis(
            negative_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("performance negative analysis succeeds");
        assert_missing_rule(&negative, "performance.regex-in-loop");
        assert_missing_rule(&negative, "performance.format-in-loop");
        assert_missing_rule(&negative, "performance.clone-in-loop");
    }

    #[test]
    fn metrics_rules_calibrate_threshold_and_formatting_stability() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "metrics-fixture"
version = "0.1.0"
edition = "2021"
description = "Synthetic fixture for metrics rule tests."
license = "MIT"
"#,
        )
        .expect("manifest write");
        fs::write(
            dir.path().join("src/lib.rs"),
            r#"pub fn compact(input: i32) -> i32 { if input > 0 { input + 1 } else { input - 1 } }

pub fn spaced(input: i32) -> i32 {
    if input > 0 {
        input + 1
    } else {
        input - 1
    }
}

pub fn complex_metric(values: &[i32]) -> i32 {
    let mut total = 0;
    for value in values {
        if *value > 10 {
            total += *value;
        } else if *value < -10 {
            total -= *value;
        } else {
            total += 1;
        }
        match *value {
            0 => total += 3,
            1 | 2 => total += 5,
            _ => total += 8,
        }
        while total < 100 {
            total += *value;
            if total % 2 == 0 {
                total += 1;
            }
            break;
        }
    }
    total
}
"#,
        )
        .expect("metrics lib write");
        write_config(
            dir.path(),
            r#"
rules:
  metrics.halstead-volume:
    threshold: 1
    severity: advisory
  metrics.maintainability-pressure:
    threshold: 100
    severity: advisory
"#,
        );

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("metrics analysis succeeds");
        assert_has_rule(&report, "metrics.halstead-volume");
        assert_has_rule(&report, "metrics.maintainability-pressure");

        let compact_volume = metric_metadata_number(
            &report,
            "metrics.halstead-volume",
            "compact",
            "halsteadVolume",
        );
        let spaced_volume = metric_metadata_number(
            &report,
            "metrics.halstead-volume",
            "spaced",
            "halsteadVolume",
        );
        assert_eq!(compact_volume, spaced_volume);

        let compact_score = metric_metadata_number(
            &report,
            "metrics.maintainability-pressure",
            "compact",
            "score",
        );
        let spaced_score = metric_metadata_number(
            &report,
            "metrics.maintainability-pressure",
            "spaced",
            "score",
        );
        assert_eq!(compact_score, spaced_score);

        let complex = report
            .findings
            .iter()
            .find(|finding| {
                finding.rule_id == "metrics.halstead-volume"
                    && finding.symbol.as_deref() == Some("complex_metric")
            })
            .expect("complex metric volume finding");
        assert!(complex.metadata["totalTokens"].as_u64().unwrap_or_default() > 50);
        assert!(complex
            .metadata
            .get("halsteadVolume")
            .and_then(Value::as_f64)
            .is_some_and(|volume| volume > 100.0));

        let complexity = report
            .score
            .pillars
            .iter()
            .find(|pillar| pillar.pillar == Pillar::Complexity)
            .expect("complexity score");
        assert!(
            complexity.findings >= 2,
            "expected metric findings in complexity: {complexity:?}"
        );

        write_config(
            dir.path(),
            r#"
rules:
  metrics.halstead-volume:
    threshold: 1
    severity: severe
"#,
        );
        let error =
            load_config(dir.path(), &default_test_options()).expect_err("bad metric threshold");
        assert!(
            error.contains(
                "config key `rules.metrics.halstead-volume.severity` must be advisory, warning, or error"
            ),
            "{error}"
        );
    }

    #[test]
    fn missing_readme_is_project_scoped() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("lib.rs"), "pub fn documented() {}\n").expect("fixture write");

        let missing = analyse_project_paths(dir.path(), vec![PathBuf::from("lib.rs")]);
        fs::write(dir.path().join("README.md"), "# Temporary fixture\n").expect("readme write");
        let present = analyse_project_paths(dir.path(), vec![PathBuf::from("lib.rs")]);

        assert_has_rule(&missing, "docs.missing-readme");
        assert_missing_rule(&present, "docs.missing-readme");
    }

    #[test]
    fn baseline_generation_and_exact_suppression_are_stable() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("sample.rs"),
            [
                r#"pub fn process(command: String) {
    "#,
                PROCESS_COMMAND_NEW,
                r#"("sh").arg(command).spawn().unwrap();
}
"#,
            ]
            .concat(),
        )
        .expect("fixture write");

        let before = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        assert!(!before.findings.is_empty());

        let baseline_path = dir.path().join("baseline.json");
        write_baseline(&baseline_path, &[before.findings[0].clone()]).expect("baseline write");

        let suppressed = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                baseline: Some(PathBuf::from("baseline.json")),
                no_config: true,
                no_baseline: false,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        assert_eq!(suppressed.findings.len(), before.findings.len() - 1);
        assert_eq!(
            suppressed
                .baseline
                .as_ref()
                .map(|baseline| baseline.suppressed),
            Some(1)
        );

        let mut baseline_json: Value =
            serde_json::from_str(&fs::read_to_string(&baseline_path).expect("baseline read"))
                .expect("baseline json");
        baseline_json["entries"][0]["message"] = json!("changed message stays suppressible");
        fs::write(
            &baseline_path,
            serde_json::to_string_pretty(&baseline_json).expect("baseline serialize"),
        )
        .expect("baseline rewrite");
        let message_changed = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                baseline: Some(PathBuf::from("baseline.json")),
                no_config: true,
                no_baseline: false,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        assert_eq!(
            message_changed
                .baseline
                .as_ref()
                .map(|baseline| baseline.suppressed),
            Some(1)
        );

        baseline_json["entries"][0]["filePath"] = json!("other.rs");
        fs::write(
            &baseline_path,
            serde_json::to_string_pretty(&baseline_json).expect("baseline serialize"),
        )
        .expect("baseline rewrite");
        let file_changed = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                baseline: Some(PathBuf::from("baseline.json")),
                no_config: true,
                no_baseline: false,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        assert_eq!(file_changed.findings.len(), before.findings.len());
        assert_eq!(
            file_changed
                .baseline
                .as_ref()
                .map(|baseline| baseline.suppressed),
            Some(0)
        );
    }

    #[test]
    fn baseline_generation_and_failure_modes_are_reported_cleanly() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("fixture write");

        let generated_path = dir.path().join("baseline.json");
        let generated = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                generate_baseline: Some(PathBuf::from("baseline.json")),
                no_config: true,
                ..default_test_options()
            },
        )
        .expect("baseline generation succeeds");
        assert!(generated
            .baseline
            .as_ref()
            .is_some_and(|baseline| baseline.generated));
        let baseline_json: Value =
            serde_json::from_str(&fs::read_to_string(&generated_path).expect("baseline read"))
                .expect("baseline json");
        assert_eq!(baseline_json["schemaVersion"], "gruff.baseline.v1");
        assert!(baseline_json["entries"].as_array().is_some());

        fs::write(
            dir.path().join("bad-baseline.json"),
            r#"{ "schemaVersion": "wrong", "entries": [] }"#,
        )
        .expect("bad baseline write");
        let invalid_schema = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                baseline: Some(PathBuf::from("bad-baseline.json")),
                no_config: true,
                no_baseline: false,
                ..default_test_options()
            },
        )
        .expect_err("invalid baseline schema rejected");
        assert!(invalid_schema.contains("unsupported baseline schema"));

        let missing = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                baseline: Some(PathBuf::from("missing-baseline.json")),
                no_config: true,
                no_baseline: false,
                ..default_test_options()
            },
        )
        .expect_err("missing baseline rejected");
        assert!(missing.contains("unable to read baseline"));
    }

    #[test]
    fn scoring_includes_all_static_pillars_and_weights_findings() {
        let clean = score_report(&[]);
        assert_eq!(clean.composite, 100.0);
        assert_eq!(clean.grade, "A");
        assert_eq!(clean.pillars.len(), SCORE_PILLARS.len());
        assert!(clean.pillars.iter().all(|pillar| pillar.findings == 0));

        let findings = vec![
            test_finding(
                "security.process-command",
                "src/a.rs",
                1,
                Severity::Error,
                Pillar::Security,
            ),
            test_finding_with_confidence(
                "dead-code.unused-private-function",
                "src/b.rs",
                1,
                Severity::Warning,
                Pillar::DeadCode,
                Confidence::Low,
            ),
            test_finding(
                "docs.todo-density",
                "src/b.rs",
                2,
                Severity::Advisory,
                Pillar::Documentation,
            ),
        ];
        let score = score_report(&findings);
        assert_eq!(score.grade, "A");
        assert_eq!(score.top_offenders[0].file_path, "src/a.rs");
        let security = score
            .pillars
            .iter()
            .find(|pillar| pillar.pillar == Pillar::Security)
            .expect("security pillar");
        let dead_code = score
            .pillars
            .iter()
            .find(|pillar| pillar.pillar == Pillar::DeadCode)
            .expect("dead-code pillar");
        assert_eq!(security.score, 92.0);
        assert_eq!(dead_code.score, 98.0);

        assert_eq!(grade(90.0), "A");
        assert_eq!(grade(80.0), "B");
        assert_eq!(grade(70.0), "C");
        assert_eq!(grade(60.0), "D");
        assert_eq!(grade(59.9), "F");
    }

    #[test]
    fn source_discovery_covers_ignores_text_files_and_missing_paths() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join(".git/hooks")).expect("git hooks dir");
        fs::create_dir_all(dir.path().join(".git/info")).expect("git info dir");
        fs::create_dir_all(dir.path().join(".agents/skills")).expect("agents dir");
        fs::create_dir_all(dir.path().join(".claude")).expect("claude dir");
        fs::create_dir_all(dir.path().join(".codex/hooks")).expect("codex dir");
        fs::create_dir_all(dir.path().join(".github/workflows")).expect("github dir");
        fs::create_dir_all(dir.path().join(".goat-flow")).expect("goat dir");
        fs::create_dir_all(dir.path().join("local")).expect("local dir");
        fs::create_dir_all(dir.path().join("nested")).expect("nested dir");
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::create_dir_all(dir.path().join("target")).expect("target dir");
        fs::create_dir_all(dir.path().join("ignored")).expect("ignored dir");
        fs::write(
            dir.path().join(".gitignore"),
            "local/**\n.goat-flow/audit-cache.json\n",
        )
        .expect("gitignore write");
        fs::write(dir.path().join(".git/info/exclude"), "info-excluded.env\n")
            .expect("git exclude write");
        fs::write(
            dir.path().join(".git/hooks/pre-commit.sh"),
            "DATABASE_PASSWORD=git-hook-secret-123\n",
        )
        .expect("git hook write");
        fs::write(dir.path().join("nested/.gitignore"), "secret.env\n")
            .expect("nested gitignore write");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("info-excluded.env"),
            concat!("DATABASE_", "PASSWORD=info-excluded-secret-123\n"),
        )
        .expect("info excluded write");
        fs::write(
            dir.path().join(".agents/skills/demo.md"),
            "# Demo\nDATABASE_PASSWORD=agents-secret-123\n",
        )
        .expect("agents write");
        fs::write(
            dir.path().join(".claude/settings.json"),
            r#"{"DATABASE_PASSWORD":"claude-secret-123"}"#,
        )
        .expect("claude write");
        fs::write(
            dir.path().join(".codex/hooks/deny-dangerous.sh"),
            "DATABASE_PASSWORD=codex-secret-123\n",
        )
        .expect("codex write");
        fs::write(
            dir.path().join(".github/workflows/ci.yml"),
            "env:\n  DATABASE_PASSWORD=github-secret-123\n",
        )
        .expect("github write");
        fs::write(
            dir.path().join(".goat-flow/architecture.md"),
            "# Architecture\nDATABASE_PASSWORD=goat-secret-123\n",
        )
        .expect("goat write");
        fs::write(
            dir.path().join(".goat-flow/audit-cache.json"),
            r#"{"DATABASE_PASSWORD":"ignored-goat-secret-123"}"#,
        )
        .expect("goat cache write");
        fs::write(
            dir.path().join("src/lib.rs"),
            "/// Ready.\npub fn is_ready() -> bool { true }\n",
        )
        .expect("rust write");
        fs::write(
            dir.path().join("local/secret.env"),
            concat!("DATABASE_", "PASSWORD=local-secret-123\n"),
        )
        .expect("local secret write");
        fs::write(
            dir.path().join("nested/secret.env"),
            concat!("DATABASE_", "PASSWORD=nested-secret-123\n"),
        )
        .expect("nested secret write");
        fs::write(
            dir.path().join("nested/visible.env"),
            concat!("DATABASE_", "PASSWORD=visible-secret-123\n"),
        )
        .expect("nested visible write");
        fs::write(
            dir.path().join("target/secret.env"),
            concat!("DATABASE_", "PASSWORD=target-secret-123\n"),
        )
        .expect("target secret write");
        fs::write(
            dir.path().join("ignored/secret.env"),
            concat!("DATABASE_", "PASSWORD=ignored-secret-123\n"),
        )
        .expect("ignored secret write");
        write_config(dir.path(), r#"{ "paths": { "ignore": ["ignored/**"] } }"#);

        let discovery = discover_sources(
            dir.path(),
            &AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
            &load_config(
                dir.path(),
                &AnalysisOptions {
                    paths: vec![PathBuf::from(".")],
                    no_config: false,
                    no_baseline: true,
                    ..default_test_options()
                },
            )
            .expect("config loads"),
        );
        let discovered_paths: BTreeSet<&str> = discovery
            .files
            .iter()
            .map(|file| file.display_path.as_str())
            .collect();
        assert!(discovered_paths.contains(".agents/skills/demo.md"));
        assert!(discovered_paths.contains(".claude/settings.json"));
        assert!(discovered_paths.contains(".codex/hooks/deny-dangerous.sh"));
        assert!(discovered_paths.contains(".github/workflows/ci.yml"));
        assert!(discovered_paths.contains(".goat-flow/architecture.md"));
        assert!(discovered_paths.contains("nested/visible.env"));
        assert!(discovered_paths.contains("src/lib.rs"));
        assert!(!discovered_paths.contains(".git/hooks/pre-commit.sh"));
        assert!(!discovered_paths.contains(".goat-flow/audit-cache.json"));
        assert!(!discovered_paths.contains("info-excluded.env"));
        assert!(!discovered_paths.contains("local/secret.env"));
        assert!(!discovered_paths.contains("nested/secret.env"));
        assert!(!discovered_paths.contains("target/secret.env"));
        assert!(!discovered_paths.contains("ignored/secret.env"));

        let default_scan = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        assert!(default_scan
            .paths
            .ignored_paths
            .contains(&"target".to_string()));
        assert!(default_scan
            .paths
            .ignored_paths
            .contains(&"ignored".to_string()));
        assert!(default_scan.findings.iter().any(|finding| {
            finding.rule_id == "sensitive-data.hardcoded-env-value"
                && finding.file_path == ".github/workflows/ci.yml"
        }));
        assert!(!default_scan.findings.iter().any(|finding| {
            finding.rule_id == "sensitive-data.hardcoded-env-value"
                && finding.file_path == "local/secret.env"
        }));
        assert!(!default_scan.findings.iter().any(|finding| {
            finding.rule_id == "sensitive-data.hardcoded-env-value"
                && finding.file_path == "info-excluded.env"
        }));
        assert!(!default_scan.findings.iter().any(|finding| {
            finding.rule_id == "sensitive-data.hardcoded-env-value"
                && finding.file_path == ".git/hooks/pre-commit.sh"
        }));

        let include_ignored = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: false,
                include_ignored: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        assert!(include_ignored.findings.iter().any(|finding| {
            finding.rule_id == "sensitive-data.hardcoded-env-value"
                && finding.file_path == "local/secret.env"
        }));
        assert!(include_ignored.findings.iter().any(|finding| {
            finding.rule_id == "sensitive-data.hardcoded-env-value"
                && finding.file_path == "ignored/secret.env"
        }));
        assert!(include_ignored.findings.iter().any(|finding| {
            finding.rule_id == "sensitive-data.hardcoded-env-value"
                && finding.file_path == "info-excluded.env"
        }));
        assert!(include_ignored.findings.iter().any(|finding| {
            finding.rule_id == "sensitive-data.hardcoded-env-value"
                && finding.file_path == "target/secret.env"
        }));
        assert!(!include_ignored.findings.iter().any(|finding| {
            finding.rule_id == "sensitive-data.hardcoded-env-value"
                && finding.file_path == ".git/hooks/pre-commit.sh"
        }));

        let text_scan = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("local/secret.env")],
                no_config: true,
                include_ignored: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("text scan succeeds");
        assert_has_rule(&text_scan, "sensitive-data.hardcoded-env-value");

        let missing = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("missing.rs")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("missing path is diagnostic, not hard error");
        assert_eq!(missing.diagnostics.len(), 1);
        assert_eq!(missing.diagnostics[0].diagnostic_type, "missing-path");
    }

    #[test]
    fn report_renderers_escape_and_preserve_contracts() {
        let report = sample_report();

        let json_output = render_report(&report, OutputFormat::Json);
        let decoded: Value = serde_json::from_str(&json_output).expect("json report");
        assert_eq!(decoded["schemaVersion"], "gruff.analysis.v1");
        assert_eq!(decoded["findings"][0]["ruleId"], "security.process-command");

        let sarif: Value = serde_json::from_str(&render_report(&report, OutputFormat::Sarif))
            .expect("sarif report");
        assert_eq!(OutputFormat::Sarif.as_str(), "sarif");
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "gruff-rs");
        assert_eq!(
            sarif["runs"][0]["properties"]["gruffSchemaVersion"],
            "gruff.analysis.v1"
        );
        let sarif_rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("sarif rules");
        let sarif_rule_ids: Vec<&str> = sarif_rules
            .iter()
            .map(|rule| rule["id"].as_str().expect("sarif rule id"))
            .collect();
        let mut sorted_rule_ids = sarif_rule_ids.clone();
        sorted_rule_ids.sort_unstable();
        assert_eq!(sarif_rule_ids, sorted_rule_ids);
        let rule_index = sarif_rule_ids
            .iter()
            .position(|rule_id| *rule_id == "security.process-command")
            .expect("security rule in sarif driver");
        let sarif_result = &sarif["runs"][0]["results"][0];
        assert_eq!(sarif_result["ruleId"], "security.process-command");
        assert_eq!(sarif_result["ruleIndex"].as_u64(), Some(rule_index as u64));
        assert_eq!(sarif_result["level"], "warning");
        assert_eq!(
            sarif_result["message"]["text"],
            "Use <escaped> command & args"
        );
        assert_eq!(
            sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/lib.rs"
        );
        assert_eq!(
            sarif_result["locations"][0]["physicalLocation"]["region"]["startLine"],
            7
        );
        assert_eq!(
            sarif_result["partialFingerprints"]["gruffFingerprint"].as_str(),
            Some(report.findings[0].fingerprint.as_str())
        );

        let text = render_report(&report, OutputFormat::Text);
        assert!(text.contains("gruff-rs"));
        assert!(text.contains("security.process-command"));

        let markdown = render_report(&report, OutputFormat::Markdown);
        assert!(markdown.starts_with("# gruff-rs report"));
        assert!(markdown.contains("`security.process-command`"));

        let github = render_report(&report, OutputFormat::Github);
        assert!(github.starts_with("::warning file=src/lib.rs,line=7"));

        let html = render_report(&report, OutputFormat::Html);
        assert!(html.contains("Use &lt;escaped&gt; command &amp; args"));
        assert!(!html.contains("Use <escaped> command & args"));

        let hotspot: Value = serde_json::from_str(&render_report(&report, OutputFormat::Hotspot))
            .expect("hotspot json");
        assert_eq!(hotspot["schemaVersion"], "gruff.hotspot.v1");
        assert_eq!(hotspot["files"][0]["filePath"], "src/lib.rs");
    }

    #[test]
    fn sarif_contract_covers_rules_locations_levels_and_metadata() {
        let mut error = Finding::new(
            "complexity.cyclomatic",
            "Complex function",
            r".\src\space name.rs",
            Some(10),
            Severity::Error,
            Pillar::Complexity,
            Confidence::Medium,
            Some("complex".to_string()),
            Some("Split branches.".to_string()),
            json!({}),
        );
        error.column = Some(5);
        error.end_line = Some(12);
        error.secondary_pillars = vec![Pillar::Size];

        let advisory = Finding::new(
            "docs.todo-density",
            "Too many TODOs",
            "src/hash#name.rs",
            None,
            Severity::Advisory,
            Pillar::Documentation,
            Confidence::Low,
            None,
            None,
            Value::Null,
        );
        let unknown = Finding::new(
            "custom.example",
            "Custom warning",
            "src/q?percent%.rs",
            Some(3),
            Severity::Warning,
            Pillar::Naming,
            Confidence::High,
            Some("custom".to_string()),
            None,
            json!({ "detail": "kept" }),
        );
        let report = sample_report_with(vec![error, advisory, unknown], Vec::new());
        let sarif = sample_sarif(&report);

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules");
        let cyclomatic_rule = rules
            .iter()
            .find(|rule| rule["id"] == "complexity.cyclomatic")
            .expect("cyclomatic rule");
        assert_eq!(cyclomatic_rule["defaultConfiguration"]["level"], "warning");
        assert_eq!(cyclomatic_rule["properties"]["threshold"], json!(10.0));
        assert!(cyclomatic_rule["properties"]["options"].is_null());

        let results = sarif["runs"][0]["results"].as_array().expect("results");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[0]["ruleId"], "complexity.cyclomatic");
        assert!(results[0]["ruleIndex"].is_number());
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/space%20name.rs"
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            10
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["startColumn"],
            5
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["endLine"],
            12
        );
        assert!(results[0]["locations"][0]["physicalLocation"]["region"]["endColumn"].is_null());
        assert_eq!(results[0]["properties"]["secondaryPillars"][0], "size");
        assert_eq!(results[0]["properties"]["metadata"], json!({}));
        assert_eq!(results[0]["properties"]["remediation"], "Split branches.");

        assert_eq!(results[1]["level"], "note");
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/hash%23name.rs"
        );
        assert!(results[1]["locations"][0]["physicalLocation"]["region"].is_null());
        assert!(results[1]["properties"]["metadata"].is_null());

        assert_eq!(results[2]["level"], "warning");
        assert_eq!(results[2]["ruleId"], "custom.example");
        assert!(results[2]["ruleIndex"].is_null());
        assert_eq!(
            results[2]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/q%3Fpercent%25.rs"
        );
        assert_eq!(results[2]["properties"]["metadata"]["detail"], "kept");
    }

    #[test]
    fn sarif_uri_encodes_reserved_path_characters() {
        assert_eq!(sarif_uri("./src/lib.rs"), "src/lib.rs");
        assert_eq!(sarif_uri(r"src\lib.rs"), "src/lib.rs");
        assert_eq!(sarif_uri("src/space name.rs"), "src/space%20name.rs");
        assert_eq!(sarif_uri("src/hash#name.rs"), "src/hash%23name.rs");
        assert_eq!(sarif_uri("src/q?name.rs"), "src/q%3Fname.rs");
        assert_eq!(sarif_uri("src/percent%name.rs"), "src/percent%25name.rs");
        assert_eq!(sarif_uri(""), ".");
    }

    #[test]
    fn sarif_location_ignores_column_without_start_line() {
        let location = sarif_physical_location_from_parts("src/lib.rs", None, Some(5), Some(7));
        assert_eq!(location["artifactLocation"]["uri"], "src/lib.rs");
        assert!(location["region"].is_null());
    }

    #[test]
    fn sarif_maps_diagnostics_to_invocation_notifications() {
        let report = sample_report_with(
            Vec::new(),
            vec![RunDiagnostic {
                diagnostic_type: "missing-path".to_string(),
                message: "Input path does not exist: missing.rs".to_string(),
                file_path: Some("missing.rs".to_string()),
                line: None,
            }],
        );
        let sarif = sample_sarif(&report);

        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert!(sarif["runs"][0]["invocations"][0]["commandLine"].is_null());
        assert!(sarif["runs"][0]["invocations"][0]["arguments"].is_null());
        assert!(sarif["runs"][0]["invocations"][0]["workingDirectory"].is_null());
        let notification = &sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0];
        assert_eq!(notification["descriptor"]["id"], "missing-path");
        assert_eq!(notification["level"], "error");
        assert!(notification["message"]["text"]
            .as_str()
            .expect("message")
            .contains("missing.rs"));
        assert_eq!(
            notification["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "missing.rs"
        );
        assert_eq!(
            sarif["runs"][0]["results"]
                .as_array()
                .expect("results")
                .len(),
            0
        );
    }

    #[test]
    fn sarif_marks_clean_invocation_successful() {
        let sarif = sample_sarif(&sample_report());
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            true
        );
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
                .as_array()
                .expect("notifications")
                .len(),
            0
        );
    }

    #[test]
    fn sarif_parse_error_keeps_text_rule_results() {
        let report = analyse_test_paths(vec![PathBuf::from("tests/fixtures/parser/invalid.rs")]);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].diagnostic_type, "parse-error");
        assert_has_rule(&report, "sensitive-data.aws-access-key");

        let sarif = sample_sarif(&report);
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["descriptor"]["id"],
            "parse-error"
        );
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["locations"][0]
                ["physicalLocation"]["artifactLocation"]["uri"],
            "tests/fixtures/parser/invalid.rs"
        );
        let result_rule_ids: Vec<&str> = sarif["runs"][0]["results"]
            .as_array()
            .expect("results")
            .iter()
            .map(|result| result["ruleId"].as_str().expect("rule id"))
            .collect();
        assert!(
            result_rule_ids.contains(&"sensitive-data.aws-access-key"),
            "{result_rule_ids:?}"
        );
    }

    #[test]
    fn report_json_keeps_deterministic_finding_order() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(dir.path().join("b.rs"), "pub fn process() {}\n").expect("b write");
        fs::write(dir.path().join("a.rs"), "pub fn process() {}\n").expect("a write");

        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("b.rs"), PathBuf::from("a.rs")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");

        let ordered_paths: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.file_path.as_str())
            .collect();
        assert_eq!(ordered_paths, vec!["a.rs", "a.rs", "b.rs", "b.rs"]);
    }

    #[test]
    fn dashboard_scan_preserves_cwd_and_report_paths() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("sample write");
        let cwd_before = std::env::current_dir().expect("cwd");
        let query = format!(
            "projectRoot={}&path=sample.rs",
            dir.path().to_string_lossy()
        );

        let response = dashboard_response("/scan", &query, Path::new("."));

        assert_eq!(response.status, "200 OK");
        assert_eq!(std::env::current_dir().expect("cwd"), cwd_before);
        assert!(response.body.contains("Dashboard scan"));
        assert!(response.body.contains("sample.rs"));
        assert!(!response
            .body
            .contains(&dir.path().join("sample.rs").display().to_string()));
    }

    #[test]
    fn parser_handles_raw_strings_macros_impls_and_test_attributes() {
        let _guard = analysis_lock();
        let report = analyse_test_paths(vec![
            PathBuf::from("tests/fixtures/parser/raw_strings.rs"),
            PathBuf::from("tests/fixtures/parser/macros_impls.rs"),
        ]);

        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);

        let parameter_count = report
            .findings
            .iter()
            .find(|finding| {
                finding.rule_id == "size.parameter-count"
                    && finding.file_path == "tests/fixtures/parser/macros_impls.rs"
                    && finding.symbol.as_deref() == Some("process")
            })
            .expect("impl method parameter-count finding");
        assert_eq!(parameter_count.line, Some(12));

        let no_assertions = report
            .findings
            .iter()
            .find(|finding| {
                finding.rule_id == "test-quality.no-assertions"
                    && finding.file_path == "tests/fixtures/parser/macros_impls.rs"
                    && finding.symbol.as_deref() == Some("test_macro_fixture")
            })
            .expect("test attribute no-assertions finding");
        assert_eq!(no_assertions.line, Some(20));
    }

    #[test]
    fn invalid_rust_reports_parse_error_and_keeps_text_rules() {
        let _guard = analysis_lock();
        let report = analyse_test_paths(vec![PathBuf::from("tests/fixtures/parser/invalid.rs")]);

        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].diagnostic_type, "parse-error");
        assert_eq!(
            report.diagnostics[0].file_path.as_deref(),
            Some("tests/fixtures/parser/invalid.rs")
        );

        let rule_ids: BTreeSet<&str> = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        assert!(rule_ids.contains("sensitive-data.aws-access-key"));
        assert!(!rule_ids.contains("size.function-length"));
    }

    #[test]
    fn json_report_uses_schema_version() {
        let report = AnalysisReport {
            schema_version: "gruff.analysis.v1".to_string(),
            tool: ToolInfo {
                name: "gruff-rs".to_string(),
                version: VERSION.to_string(),
            },
            run: RunInfo {
                project_root: ".".to_string(),
                format: "json".to_string(),
                fail_on: "none".to_string(),
                generated_at: Utc::now().to_rfc3339(),
            },
            summary: Summary {
                advisory: 0,
                warning: 0,
                error: 0,
                total: 0,
            },
            paths: PathSummary {
                analysed_files: 0,
                ignored_paths: Vec::new(),
                missing_paths: Vec::new(),
            },
            diagnostics: Vec::new(),
            suppressions: Vec::new(),
            findings: Vec::new(),
            score: ScoreReport {
                composite: 100.0,
                grade: "A".to_string(),
                pillars: Vec::new(),
                top_offenders: Vec::new(),
            },
            baseline: None,
            suppressed_findings: Vec::new(),
        };

        let rendered = render_report(&report, OutputFormat::Json);
        assert!(rendered.contains("\"schemaVersion\": \"gruff.analysis.v1\""));
    }

    const CALIBRATION_BASELINE_MANIFEST: &str = r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "Calibration baseline."
license = "MIT"

[dependencies]
serde = "1"
"#;

    const CALIBRATION_BASELINE_LOCKFILE: &str = r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "calibration-fixture"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

    fn calibration_baseline(root: &Path) {
        fs::create_dir_all(root.join("src")).expect("calibration src dir");
        fs::write(root.join("README.md"), "# Calibration\n").expect("calibration readme");
        fs::write(root.join("Cargo.toml"), CALIBRATION_BASELINE_MANIFEST)
            .expect("calibration manifest");
        fs::write(root.join("Cargo.lock"), CALIBRATION_BASELINE_LOCKFILE)
            .expect("calibration lockfile");
    }

    fn write_lib(root: &Path, content: &str) {
        fs::write(root.join("src/lib.rs"), content).expect("calibration lib");
    }

    fn baseline_with_lib(root: &Path, lib_content: &str) {
        calibration_baseline(root);
        write_lib(root, lib_content);
    }

    fn module_with_n_items(count: usize) -> String {
        let mut body = String::from("/// Probe.\n");
        for index in 0..count {
            body.push_str(&format!("/// Item {index}.\npub fn item_{index}() {{}}\n"));
        }
        body
    }

    fn module_with_n_mod_decls(count: usize) -> String {
        let mut body = String::from("/// Root.\n");
        for index in 0..count {
            body.push_str(&format!("mod child_{index} {{ pub fn unused() {{}} }}\n"));
        }
        body
    }

    type Setup = Box<dyn Fn(&Path)>;

    struct CalibrationCase {
        rule_id: &'static str,
        positive: Setup,
        negative: Setup,
    }

    fn case(rule_id: &'static str, positive: Setup, negative: Setup) -> CalibrationCase {
        CalibrationCase {
            rule_id,
            positive,
            negative,
        }
    }

    fn run_calibration_case(case: &CalibrationCase) -> (bool, bool) {
        let positive_dir = tempdir().expect("calibration positive tempdir");
        (case.positive)(positive_dir.path());
        let positive_report = run_project_analysis(
            positive_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("calibration positive analysis succeeds");
        let positive_fired = positive_report
            .findings
            .iter()
            .any(|finding| finding.rule_id == case.rule_id);

        let negative_dir = tempdir().expect("calibration negative tempdir");
        (case.negative)(negative_dir.path());
        let negative_report = run_project_analysis(
            negative_dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("calibration negative analysis succeeds");
        let negative_fired = negative_report
            .findings
            .iter()
            .any(|finding| finding.rule_id == case.rule_id);

        (positive_fired, negative_fired)
    }

    fn calibration_cases() -> Vec<CalibrationCase> {
        vec![
            // ----- architecture -----
            case(
                "architecture.large-module",
                Box::new(|root| baseline_with_lib(root, &module_with_n_items(28))),
                Box::new(|root| baseline_with_lib(root, &module_with_n_items(3))),
            ),
            case(
                "architecture.module-fan-out",
                Box::new(|root| baseline_with_lib(root, &module_with_n_mod_decls(10))),
                Box::new(|root| baseline_with_lib(root, &module_with_n_mod_decls(2))),
            ),
            case(
                "architecture.public-api-surface",
                Box::new(|root| baseline_with_lib(root, &module_with_n_items(15))),
                Box::new(|root| baseline_with_lib(root, &module_with_n_items(3))),
            ),
            // ----- complexity -----
            case(
                "complexity.cognitive",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub fn complex(items: &[i32], flag_a: bool, flag_b: bool, flag_c: bool) -> i32 {
    let mut total = 0;
    for value in items {
        if flag_a {
            if flag_b {
                if flag_c {
                    if *value > 0 {
                        total += value;
                    } else if *value < 0 {
                        total -= value;
                    }
                }
            }
        }
        if flag_a && flag_b {
            total += 1;
        } else if flag_b || flag_c {
            total -= 1;
        }
    }
    total
}
"#,
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub fn simple(value: i32) -> i32 {
    value + 1
}
"#,
                    )
                }),
            ),
            case(
                "complexity.cyclomatic",
                Box::new(|root| {
                    let mut body = String::from("/// Probe.\npub fn many_branches(value: i32) -> i32 {\n    let mut total = 0;\n");
                    for index in 0..15 {
                        body.push_str(&format!(
                            "    if value == {index} {{ total += {index}; }}\n"
                        ));
                    }
                    body.push_str("    total\n}\n");
                    baseline_with_lib(root, &body);
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn straight_line(value: i32) -> i32 { value + 1 }\n",
                    )
                }),
            ),
            case(
                "complexity.nesting-depth",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub fn deeply_nested(flag_a: bool, flag_b: bool, flag_c: bool, flag_d: bool, flag_e: bool) -> i32 {
    if flag_a {
        if flag_b {
            if flag_c {
                if flag_d {
                    if flag_e {
                        return 1;
                    }
                }
            }
        }
    }
    0
}
"#,
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub fn shallow(flag_a: bool, flag_b: bool) -> i32 {
    if flag_a && flag_b {
        return 1;
    }
    0
}
"#,
                    )
                }),
            ),
            case(
                "complexity.npath",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub fn many_paths(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool, g: bool, h: bool) -> i32 {
    if a { 1 } else { 0 };
    if b { 1 } else { 0 };
    if c { 1 } else { 0 };
    if d { 1 } else { 0 };
    if e { 1 } else { 0 };
    if f { 1 } else { 0 };
    if g { 1 } else { 0 };
    if h { 1 } else { 0 };
    0
}
"#,
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn linear(a: bool) -> i32 { if a { 1 } else { 0 } }\n",
                    )
                }),
            ),
            // ----- concurrency -----
            case(
                "concurrency.blocking-call-in-async",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub async fn blocks() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}
"#,
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn synchronous() { std::thread::sleep(std::time::Duration::from_millis(1)); }\n",
                    )
                }),
            ),
            case(
                "concurrency.lock-across-await",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub async fn holds(lock: &std::sync::Mutex<i32>) {
    let guard = lock.lock().unwrap();
    other().await;
    println!("{}", *guard);
}

async fn other() {}
"#,
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub async fn drops_first(lock: &std::sync::Mutex<i32>) {
    let guard = lock.lock().unwrap();
    drop(guard);
    other().await;
}

async fn other() {}
"#,
                    )
                }),
            ),
            case(
                "concurrency.unbounded-channel",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn make_channel() { let (_tx, _rx) = std::sync::mpsc::channel::<i32>(); }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn make_channel() { let (_tx, _rx) = std::sync::mpsc::sync_channel::<i32>(16); }\n",
                    )
                }),
            ),
            // ----- dead code -----
            case(
                "dead-code.unused-private-function",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\nfn never_called() {}\npub fn entry() {}\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\nfn helper() {}\npub fn entry() { helper(); }\n",
                    )
                }),
            ),
            case(
                "dead-code.unused-private-item-candidate",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\nfn unused_isolated_widget() {}\npub fn entry() {}\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\nfn helper_widget() {}\npub fn entry() { helper_widget(); }\n",
                    )
                }),
            ),
            // ----- dependency -----
            case(
                "dependency.duplicate-locked-version",
                Box::new(|root| {
                    calibration_baseline(root);
                    fs::write(
                        root.join("Cargo.lock"),
                        r#"# generated
version = 3

[[package]]
name = "calibration-fixture"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "serde"
version = "1.0.1"
"#,
                    )
                    .expect("dup lock");
                    write_lib(root, "/// Probe.\npub fn entry() {}\n");
                }),
                Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
            ),
            case(
                "dependency.git-source",
                Box::new(|root| {
                    calibration_baseline(root);
                    fs::write(
                        root.join("Cargo.toml"),
                        r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "git source fixture"
license = "MIT"

[dependencies]
serde = { git = "https://example.test/serde" }
"#,
                    )
                    .expect("git manifest");
                    write_lib(root, "/// Probe.\npub fn entry() {}\n");
                }),
                Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
            ),
            case(
                "dependency.missing-package-metadata",
                Box::new(|root| {
                    fs::create_dir_all(root.join("src")).expect("src dir");
                    fs::write(root.join("README.md"), "# Calibration\n").expect("readme");
                    fs::write(
                        root.join("Cargo.toml"),
                        r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
"#,
                    )
                    .expect("bare manifest");
                    fs::write(root.join("Cargo.lock"), CALIBRATION_BASELINE_LOCKFILE)
                        .expect("lockfile");
                    write_lib(root, "/// Probe.\npub fn entry() {}\n");
                }),
                Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
            ),
            case(
                "dependency.path-source",
                Box::new(|root| {
                    calibration_baseline(root);
                    fs::write(
                        root.join("Cargo.toml"),
                        r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "path source fixture"
license = "MIT"

[dependencies]
helper = { path = "../helper" }
"#,
                    )
                    .expect("path manifest");
                    write_lib(root, "/// Probe.\npub fn entry() {}\n");
                }),
                Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
            ),
            case(
                "dependency.wildcard-version",
                Box::new(|root| {
                    calibration_baseline(root);
                    fs::write(
                        root.join("Cargo.toml"),
                        r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "wildcard fixture"
license = "MIT"

[dependencies]
serde = "*"
"#,
                    )
                    .expect("wildcard manifest");
                    write_lib(root, "/// Probe.\npub fn entry() {}\n");
                }),
                Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
            ),
            // ----- design -----
            case(
                "design.god-function",
                Box::new(|root| {
                    let mut body = String::from(
                        "/// Probe.\npub fn god(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) -> i32 {\n    let mut total = 0;\n",
                    );
                    for index in 0..60 {
                        body.push_str(&format!(
                            "    if a && b {{\n        total += {index};\n    }}\n"
                        ));
                    }
                    body.push_str("    total\n}\n");
                    baseline_with_lib(root, &body);
                }),
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub fn small(a: i32) -> i32 { a + 1 }\n")
                }),
            ),
            // ----- docs -----
            case(
                "docs.missing-public-doc",
                Box::new(|root| baseline_with_lib(root, "pub fn undocumented_entry() {}\n")),
                Box::new(|root| {
                    baseline_with_lib(root, "/// Documented entry.\npub fn entry() {}\n")
                }),
            ),
            case(
                "docs.missing-readme",
                Box::new(|root| {
                    fs::create_dir_all(root.join("src")).expect("src dir");
                    fs::write(root.join("Cargo.toml"), CALIBRATION_BASELINE_MANIFEST)
                        .expect("manifest");
                    fs::write(root.join("Cargo.lock"), CALIBRATION_BASELINE_LOCKFILE)
                        .expect("lockfile");
                    write_lib(root, "/// Probe.\npub fn entry() {}\n");
                }),
                Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
            ),
            case(
                "docs.todo-density",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\n// TODO: one\n// TODO: two\n// FIXME: three\n// TODO: four\npub fn entry() {}\n",
                    )
                }),
                Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
            ),
            // ----- error handling -----
            case(
                "error-handling.production-panic",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn always_panics() { panic!(\"boom\"); }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub fn returns_value() -> i32 { 1 }\n")
                }),
            ),
            case(
                "error-handling.public-unwrap",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let value: Option<i32> = Some(1); value.unwrap(); }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() -> Option<i32> { Some(1) }\n",
                    )
                }),
            ),
            case(
                "error-handling.unimplemented-placeholder",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() -> i32 { todo!(\"unfinished\") }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub fn entry() -> i32 { 0 }\n")
                }),
            ),
            // ----- metrics -----
            case(
                "metrics.halstead-volume",
                Box::new(|root| {
                    let mut body = String::from(
                        "/// Probe.\npub fn dense(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {\n    let mut acc = 0;\n",
                    );
                    for index in 0..60 {
                        body.push_str(&format!(
                            "    acc = acc + (a * {index}) - (b ^ {index}) | (c & {index}) + (d % ({index} + 1)) * (e + {index});\n"
                        ));
                    }
                    body.push_str("    acc\n}\n");
                    baseline_with_lib(root, &body);
                }),
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub fn small(a: i32) -> i32 { a + 1 }\n")
                }),
            ),
            case(
                "metrics.maintainability-pressure",
                Box::new(|root| {
                    let mut body = String::from(
                        "/// Probe.\npub fn dense(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {\n    let mut acc = 0;\n",
                    );
                    for index in 0..60 {
                        body.push_str(&format!(
                            "    if a == {index} {{ acc += b * {index} - c + d / ({index} + 1) - e; }}\n"
                        ));
                    }
                    body.push_str("    acc\n}\n");
                    baseline_with_lib(root, &body);
                }),
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub fn small(a: i32) -> i32 { a + 1 }\n")
                }),
            ),
            // ----- modernisation -----
            case(
                "modernisation.public-field",
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub struct Wide { pub value: i32 }\n")
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub struct Narrow { value: i32 }\nimpl Narrow { /// Read.\npub fn value(&self) -> i32 { self.value } }\n",
                    )
                }),
            ),
            // ----- naming -----
            case(
                "naming.boolean-prefix",
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub fn ready() -> bool { true }\n")
                }),
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub fn is_ready() -> bool { true }\n")
                }),
            ),
            case(
                "naming.generic-function",
                Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn process() {}\n")),
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub fn ingest_payload() {}\n")
                }),
            ),
            case(
                "naming.placeholder-identifier",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let foo = 1; let _ = foo; }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let count = 1; let _ = count; }\n",
                    )
                }),
            ),
            case(
                "naming.short-variable",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() -> i32 { let xy = 1; xy + 1 }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() -> i32 { let count = 1; count + 1 }\n",
                    )
                }),
            ),
            // ----- performance -----
            case(
                "performance.clone-in-loop",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub fn entry(values: Vec<String>) {
    for value in values {
        let _owned = value.clone();
    }
}
"#,
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(value: &String) { let _owned = value.clone(); }\n",
                    )
                }),
            ),
            case(
                "performance.format-in-loop",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub fn entry(values: Vec<i32>) {
    for value in values {
        let _formatted = format!("{value}");
    }
}
"#,
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(value: i32) { let _formatted = format!(\"{value}\"); }\n",
                    )
                }),
            ),
            case(
                "performance.regex-in-loop",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        r#"/// Probe.
pub fn entry(values: Vec<i32>) {
    for value in values {
        let _compiled = regex::Regex::new("^a$");
        let _consume = value;
    }
}
"#,
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _compiled = regex::Regex::new(\"^a$\"); }\n",
                    )
                }),
            ),
            // ----- security -----
            case(
                "security.process-command",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = std::process::Command::new(\"ls\"); }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() -> &'static str { \"ls\" }\n",
                    )
                }),
            ),
            case(
                "security.unsafe-block",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(p: *const u8) -> u8 { unsafe { *p } }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(p: *const u8) -> u8 {\n    // SAFETY: caller validated pointer.\n    unsafe { *p }\n}\n",
                    )
                }),
            ),
            // ----- sensitive data -----
            case(
                "sensitive-data.api-key-pattern",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"ghp_aaaaaaaaaaaaaaaaaaaaaa\"; }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"safe-string\"; }\n",
                    )
                }),
            ),
            case(
                "sensitive-data.aws-access-key",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"AKIAABCDEFGHIJKLMNOP\"; }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"safe-string\"; }\n",
                    )
                }),
            ),
            case(
                "sensitive-data.database-url-password",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"postgres://user:secret@db/app\"; }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"postgres://db/app\"; }\n",
                    )
                }),
            ),
            case(
                "sensitive-data.hardcoded-env-value",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"DATABASE_PASSWORD=correct-horse-battery-123\"; }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"DATABASE_PASSWORD\"; }\n",
                    )
                }),
            ),
            case(
                "sensitive-data.high-entropy-string",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"Q7m2P9x8R4s6T1v3W5y7Z0a2B4c6D8e0\"; }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"hello world\"; }\n",
                    )
                }),
            ),
            case(
                "sensitive-data.jwt-token",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"; }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"plain-string\"; }\n",
                    )
                }),
            ),
            case(
                "sensitive-data.private-key",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"-----BEGIN RSA PRIVATE KEY-----\"; }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() { let _ = \"plain-string\"; }\n",
                    )
                }),
            ),
            // ----- size -----
            case(
                "size.file-length",
                Box::new(|root| {
                    let mut body = String::from("/// Probe.\npub fn entry() {}\n");
                    for index in 0..620 {
                        body.push_str(&format!("// filler line {index}\n"));
                    }
                    baseline_with_lib(root, &body);
                }),
                Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
            ),
            case(
                "size.function-length",
                Box::new(|root| {
                    let mut body = String::from("/// Probe.\npub fn long_entry() {\n");
                    for index in 0..60 {
                        body.push_str(&format!("    let _ = {index};\n"));
                    }
                    body.push_str("}\n");
                    baseline_with_lib(root, &body);
                }),
                Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
            ),
            case(
                "size.parameter-count",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 { a + b + c + d + e + f }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub fn entry(a: i32) -> i32 { a }\n")
                }),
            ),
            // ----- test quality -----
            case(
                "test-quality.conditional-logic",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        let value = 1;\n        if value > 0 { assert_eq!(value, 1); } else { assert_eq!(value, 0); }\n    }\n}\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(2 + 2, 4); }\n}\n",
                    )
                }),
            ),
            case(
                "test-quality.ignored-without-reason",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    #[ignore]\n    fn skipped() { assert_eq!(1, 1); }\n}\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    #[ignore = \"flaky on CI\"]\n    fn skipped() { assert_eq!(1, 1); }\n}\n",
                    )
                }),
            ),
            case(
                "test-quality.long-test",
                Box::new(|root| {
                    let mut body = String::from(
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn long() {\n        let value = 0;\n",
                    );
                    for index in 0..90 {
                        body.push_str(&format!("        let value = value + {index};\n"));
                    }
                    body.push_str("        assert_eq!(value, 4005);\n    }\n}\n");
                    baseline_with_lib(root, &body);
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn quick() { assert_eq!(2 + 2, 4); }\n}\n",
                    )
                }),
            ),
            case(
                "test-quality.loop-in-test",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        let mut sum = 0;\n        for index in 0..3 { sum += index; }\n        assert_eq!(sum, 3);\n    }\n}\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(1 + 2, 3); }\n}\n",
                    )
                }),
            ),
            case(
                "test-quality.no-assertions",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { let _ = 1; }\n}\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(1, 1); }\n}\n",
                    )
                }),
            ),
            case(
                "test-quality.sleep-in-test",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        std::thread::sleep(std::time::Duration::from_millis(1));\n        assert_eq!(1, 1);\n    }\n}\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(2, 2); }\n}\n",
                    )
                }),
            ),
            case(
                "test-quality.trivial-assertion",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert!(true); }\n}\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { let actual = 2 + 2; assert_eq!(actual, 4); }\n}\n",
                    )
                }),
            ),
            case(
                "test-quality.unwrap-in-test",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() {\n        let value: Option<i32> = Some(1);\n        let v = value.unwrap();\n        assert_eq!(v, 1);\n    }\n}\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn check() { assert_eq!(1, 1); }\n}\n",
                    )
                }),
            ),
            // ----- waste -----
            case(
                "waste.unnecessary-clone-candidate",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(value: &String) -> String { value.clone() }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry(value: String) -> String { value }\n",
                    )
                }),
            ),
            case(
                "waste.unreachable-code",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\npub fn entry() -> i32 {\n    return 1;\n    let _ignored = 2;\n    3\n}\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(root, "/// Probe.\npub fn entry() -> i32 { 1 }\n")
                }),
            ),
            case(
                "waste.unwrap-expect",
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\nfn entry() { let value: Option<i32> = Some(1); value.unwrap(); }\n",
                    )
                }),
                Box::new(|root| {
                    baseline_with_lib(
                        root,
                        "/// Probe.\nfn entry(value: Option<i32>) -> Option<i32> { value }\n",
                    )
                }),
            ),
        ]
    }

    #[test]
    fn rule_calibration_matrix_covers_every_rule() {
        let _guard = analysis_lock();
        let cases = calibration_cases();
        let registry = crate::rules::builtin_registry();

        let cases_by_rule: BTreeSet<&str> = cases.iter().map(|case| case.rule_id).collect();
        let registry_ids: BTreeSet<&str> = registry
            .definitions()
            .iter()
            .map(|definition| definition.id)
            .collect();

        let missing_cases: Vec<&str> = registry_ids.difference(&cases_by_rule).copied().collect();
        let stale_cases: Vec<&str> = cases_by_rule.difference(&registry_ids).copied().collect();

        let mut report_lines: Vec<String> = Vec::new();
        let mut missing_positive: Vec<&str> = Vec::new();
        let mut leaked_negative: Vec<&str> = Vec::new();

        for case in &cases {
            let (positive_fired, negative_fired) = run_calibration_case(case);
            report_lines.push(format!(
                "{rule}: positive={positive} negative={negative}",
                rule = case.rule_id,
                positive = if positive_fired { "FIRES" } else { "MISS" },
                negative = if negative_fired { "FIRES" } else { "silent" },
            ));
            if !positive_fired {
                missing_positive.push(case.rule_id);
            }
            if negative_fired {
                leaked_negative.push(case.rule_id);
            }
        }

        eprintln!("\n=== Calibration matrix ===");
        for line in &report_lines {
            eprintln!("{line}");
        }
        eprintln!(
            "Coverage: {}/{} rules have calibration cases. Missing: {missing_cases:?}. Stale: {stale_cases:?}",
            cases_by_rule.len(),
            registry_ids.len(),
        );
        eprintln!(
            "Under-strict (positive missed): {missing_positive:?}\nOver-strict (negative fired): {leaked_negative:?}\n"
        );

        assert!(
            missing_cases.is_empty(),
            "calibration matrix missing cases for rules: {missing_cases:?}"
        );
        assert!(
            stale_cases.is_empty(),
            "calibration matrix references unknown rules: {stale_cases:?}"
        );
        assert!(
            missing_positive.is_empty() && leaked_negative.is_empty(),
            "calibration mismatches: under-strict={missing_positive:?}, over-strict={leaked_negative:?}"
        );
    }

    /// Proves that `naming.short-variable` ignores idiomatic throwaway bindings.
    #[test]
    fn calibration_naming_short_variable_ignores_underscore_binding() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        baseline_with_lib(
            dir.path(),
            "/// Probe.\npub fn entry() { let value = 1; let _ = value; }\n",
        );
        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        let underscore_finding = report.findings.iter().find(|finding| {
            finding.rule_id == "naming.short-variable" && finding.symbol.as_deref() == Some("_")
        });
        assert!(
            underscore_finding.is_none(),
            "calibration expected `naming.short-variable` to ignore `let _`; \
             findings={:?}",
            rule_ids(&report)
        );
    }

    /// Proves that `performance.clone-in-loop` catches single-line loop bodies.
    #[test]
    fn calibration_performance_loop_rules_catch_single_line_loops() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        baseline_with_lib(
            dir.path(),
            "/// Probe.\npub fn entry(values: Vec<String>) { for value in values { let _ = value.clone(); } }\n",
        );
        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        assert_has_rule(&report, "performance.clone-in-loop");
    }

    /// Proves that `dead-code.unused-private-function` skips harness entry points.
    #[test]
    fn calibration_dead_code_skips_test_attr_and_main() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        baseline_with_lib(
            dir.path(),
            r#"/// Probe.
pub fn library_entry() {}

#[cfg(test)]
mod inner {
    #[test]
    fn private_test_only_called_by_runner() {
        assert_eq!(1, 1);
    }
}

fn main() {}
"#,
        );
        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        let main_dead = report.findings.iter().any(|finding| {
            finding.rule_id == "dead-code.unused-private-function"
                && finding.symbol.as_deref() == Some("main")
        });
        let test_dead = report.findings.iter().any(|finding| {
            finding.rule_id == "dead-code.unused-private-function"
                && finding.symbol.as_deref() == Some("private_test_only_called_by_runner")
        });
        assert!(
            !main_dead,
            "calibration expected `dead-code.unused-private-function` to skip `fn main`; \
             findings={:?}",
            rule_ids(&report)
        );
        assert!(
            !test_dead,
            "calibration expected `dead-code.unused-private-function` to skip `#[test]` fn; \
             findings={:?}",
            rule_ids(&report)
        );
    }

    /// Proves that `security.process-command` catches live process construction
    /// while ignoring command snippets embedded in fixture strings.
    #[test]
    fn calibration_security_process_command_detects_code_not_fixture_text() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        baseline_with_lib(
            dir.path(),
            r##"/// Probe.
pub fn live_command() {
    let mut command = std::process::Command::new("git");
    command.arg("status");
}

/// Probe.
pub fn fixture_text() {
    let snippet = r#"std::process::Command::new("sh");"#;
    println!("{snippet}");
}
"##,
        );
        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        let command_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "security.process-command")
            .collect();
        assert_eq!(
            command_findings.len(),
            1,
            "calibration expected exactly one live process-command finding; findings={command_findings:?}"
        );
        assert_eq!(command_findings[0].symbol.as_deref(), None);
        assert_eq!(command_findings[0].line, Some(3));
    }

    /// Proves that test-context functions keep dedicated test-quality checks
    /// without also receiving production complexity, metric, and size findings.
    #[test]
    fn calibration_complexity_metrics_size_skip_test_context() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        let mut body = String::from(
            "/// Probe.\npub fn entry() {}\n#[cfg(test)]\nmod fixtures {\n    #[test]\n    fn long_setup() {\n        let mut total = 0;\n",
        );
        for index in 0..90 {
            body.push_str(&format!("        if {index} > 0 {{ total += {index}; }}\n"));
        }
        body.push_str("        assert_eq!(total, 4005);\n    }\n}\n");
        baseline_with_lib(dir.path(), &body);
        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        assert_has_rule(&report, "test-quality.long-test");
        for rule_id in [
            "size.function-length",
            "complexity.cyclomatic",
            "complexity.nesting-depth",
            "complexity.npath",
            "complexity.cognitive",
            "metrics.halstead-volume",
            "metrics.maintainability-pressure",
        ] {
            assert!(
                !report.findings.iter().any(|finding| {
                    finding.rule_id == rule_id && finding.symbol.as_deref() == Some("long_setup")
                }),
                "calibration expected `{rule_id}` to skip test function `long_setup`; findings={:?}",
                rule_ids(&report)
            );
        }
    }

    /// Proves that `sensitive-data.api-key-pattern` recognises common synthetic
    /// provider-shaped tokens beyond the original narrow prefix set.
    #[test]
    fn calibration_api_key_pattern_detects_common_formats() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        baseline_with_lib(
            dir.path(),
            r#"/// Probe.
pub fn entry() {
    let _stripe_test = "sk_test_aaaaaaaaaaaaaaaaaaaaaaaa";
    let _stripe_pub = "pk_live_aaaaaaaaaaaaaaaaaaaaaaaa";
    let _github_oauth = "gho_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _openai_legacy = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _google_api = "AIzaSyAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _azure_bus = "Endpoint=sb://example.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
}
"#,
        );
        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        let api_key_findings = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "sensitive-data.api-key-pattern")
            .count();
        assert_eq!(
            api_key_findings,
            6,
            "calibration expected all common synthetic API-key formats to fire; findings={:?}",
            rule_ids(&report)
        );
    }

    /// Proves that `sensitive-data.hardcoded-env-value` still catches
    /// production Rust literals but ignores fixture strings in test context.
    #[test]
    fn calibration_hardcoded_env_value_skips_test_fixture_strings() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        baseline_with_lib(
            dir.path(),
            r#"/// Probe.
pub fn entry() {
    let production = "DATABASE_PASSWORD=production-secret-123";
    assert!(production.contains("DATABASE_PASSWORD"));
}

#[cfg(test)]
mod fixtures {
    #[test]
    fn fixture_text_contains_secret_pattern() {
        let fixture = "DATABASE_PASSWORD=correct-horse-battery-123";
        assert!(fixture.contains("PASSWORD"));
    }
}
"#,
        );
        let report = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from(".")],
                no_config: true,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect("analysis succeeds");
        let hardcoded_env_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "sensitive-data.hardcoded-env-value")
            .collect();
        assert_eq!(
            hardcoded_env_findings.len(),
            1,
            "calibration expected only the production env-style assignment to fire; findings={:?}",
            rule_ids(&report)
        );
        assert_eq!(hardcoded_env_findings[0].line, Some(3));
    }
}
