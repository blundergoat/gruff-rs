use chrono::Utc;
use clap::builder::styling;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use proc_macro2::LineColumn;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;
use syn::spanned::Spanned;
use syn::{FnArg, ImplItem, Item, ReturnType, Type, Visibility};
use walkdir::{DirEntry, WalkDir};

mod html_report;
mod rules;
mod summary;

const VERSION: &str = "0.1.0-dev";
const DEFAULT_BASELINE: &str = "gruff-baseline.json";
const DEFAULT_CONFIG_FILES: &[&str] = &[".gruff.yaml", ".gruff.yml", ".gruff.json"];

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
        if !report.diagnostics.is_empty() {
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
    #[arg(long, value_name = "MODE")]
    diff: Option<String>,
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
    diff: Option<String>,
    history_file: Option<PathBuf>,
    baseline: Option<PathBuf>,
    generate_baseline: Option<PathBuf>,
    no_baseline: bool,
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
        let diff_label = options.diff.as_ref().map(|mode| format!("diff · {mode}"));
        Self { paths, diff_label }
    }
}

#[derive(Debug, Clone)]
struct Config {
    ignored_paths: Vec<String>,
    accepted_abbreviations: BTreeSet<String>,
    secret_previews: BTreeSet<String>,
    rule_settings: HashMap<String, RuleSetting>,
}

#[derive(Debug, Clone, Default)]
struct RuleSetting {
    enabled: Option<bool>,
    thresholds: HashMap<String, f64>,
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
            rule_settings: HashMap::new(),
        }
    }

    fn rule_enabled(&self, rule_id: &str) -> bool {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.enabled)
            .unwrap_or(true)
    }

    fn threshold(&self, rule_id: &str, name: &str, default_value: f64) -> f64 {
        self.rule_settings
            .get(rule_id)
            .and_then(|setting| setting.thresholds.get(name))
            .copied()
            .unwrap_or(default_value)
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AnalysisReport {
    schema_version: String,
    tool: ToolInfo,
    run: RunInfo,
    summary: Summary,
    paths: PathSummary,
    diagnostics: Vec<RunDiagnostic>,
    findings: Vec<Finding>,
    score: ScoreReport,
    baseline: Option<BaselineReport>,
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
    AnalysisOptions {
        paths: args.paths,
        config: args.config,
        no_config: args.no_config,
        format: args.format,
        fail_on: args.fail_on,
        include_ignored: args.include_ignored,
        diff: args.diff,
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
    let registry = rules::builtin_registry();
    let body = match args.format {
        RuleListFormat::Json => {
            serde_json::to_string_pretty(registry.definitions()).expect("rules serialize")
        }
        RuleListFormat::Text => {
            let mut out = String::new();
            for definition in registry.definitions() {
                out.push_str(&format!(
                    "{} [{}] {:?} {:?} - {}\n",
                    definition.id,
                    definition.tier,
                    definition.pillar,
                    definition.default_severity,
                    definition.description
                ));
            }
            out.trim_end_matches('\n').to_string()
        }
    };
    writer.emit_unconditional(&body);
    ExitCode::SUCCESS
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

fn run_analysis_in_project(
    project_root: &Path,
    options: &AnalysisOptions,
) -> Result<AnalysisReport, String> {
    let config = load_config(project_root, options)?;
    let mut discovery = discover_sources(project_root, options, &config);

    if let Some(mode) = &options.diff {
        let changed = changed_files(mode)?;
        discovery
            .files
            .retain(|file| changed.contains(&file.display_path));
    }

    let mut findings = Vec::new();
    let mut diagnostics = Vec::new();

    for missing_path in &discovery.missing_paths {
        diagnostics.push(RunDiagnostic {
            diagnostic_type: "missing-path".to_string(),
            message: format!("Input path does not exist: {missing_path}"),
            file_path: Some(missing_path.clone()),
            line: None,
        });
    }

    let (parsed_sources, read_diagnostics) = read_and_parse_sources(&discovery.files);
    diagnostics.extend(read_diagnostics);

    let project_context = build_project_context(project_root, &parsed_sources);
    diagnostics.extend(project_context.diagnostics.iter().cloned());
    findings.extend(analyse_project(&project_context, &config));

    for parsed_source in &parsed_sources {
        findings.extend(analyse_source(&parsed_source.unit(), &config));
        diagnostics.extend(parsed_source.diagnostics.iter().cloned());
    }

    let mut baseline_report = None;
    if let Some(path) = &options.generate_baseline {
        let baseline_path = absolutize(project_root, path);
        write_baseline(&baseline_path, &findings)?;
        baseline_report = Some(BaselineReport {
            path: display_path(project_root, &baseline_path),
            source: "generated".to_string(),
            suppressed: 0,
            generated: true,
        });
    } else if !options.no_baseline {
        let selected = options
            .baseline
            .as_ref()
            .map(|path| (absolutize(project_root, path), "explicit"))
            .or_else(|| {
                let default = project_root.join(DEFAULT_BASELINE);
                default.exists().then_some((default, "default"))
            });

        if let Some((baseline_path, source)) = selected {
            let before = findings.len();
            apply_baseline(&baseline_path, &mut findings)?;
            baseline_report = Some(BaselineReport {
                path: display_path(project_root, &baseline_path),
                source: source.to_string(),
                suppressed: before.saturating_sub(findings.len()),
                generated: false,
            });
        }
    }

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

    if let Some(history_file) = &options.history_file {
        record_history(project_root, history_file, &findings, &mut diagnostics);
    }

    let summary = summarize(&findings);
    let score = score_report(&findings);

    Ok(AnalysisReport {
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
        findings,
        score,
        baseline: baseline_report,
    })
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
    let mut ignored_paths = BTreeSet::new();
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

        let walker = WalkDir::new(&absolute).into_iter().filter_entry(|entry| {
            should_descend(entry, project_root, options, config, &mut ignored_paths)
        });

        for entry in walker
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
        {
            push_source_file(project_root, entry.path(), &mut files);
        }
    }

    files.sort_by(|left, right| left.display_path.cmp(&right.display_path));
    files.dedup_by(|left, right| left.absolute_path == right.absolute_path);

    DiscoveryResult {
        files,
        missing_paths,
        ignored_paths: ignored_paths.into_iter().collect(),
    }
}

fn should_descend(
    entry: &DirEntry,
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    ignored_paths: &mut BTreeSet<String>,
) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }

    let relative = display_path(project_root, entry.path());
    if !options.include_ignored && is_default_ignored_dir(&relative) {
        ignored_paths.insert(relative);
        return false;
    }

    if config
        .ignored_paths
        .iter()
        .any(|pattern| path_matches(pattern, &relative))
    {
        ignored_paths.insert(relative);
        return false;
    }

    true
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
        "conf" | "config" | "env" | "ini" | "json" | "toml" | "xml" | "yaml" | "yml"
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

    let config_path = options
        .config
        .as_ref()
        .map(|path| absolutize(project_root, path))
        .or_else(|| default_config_path(project_root));

    let Some(path) = config_path else {
        return Ok(config);
    };

    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("unable to read config {}: {error}", path.display()))?;
    let value = parse_config_value(&path, &raw)?;
    let root = value
        .as_object()
        .ok_or_else(|| format!("config {} must be a JSON object", path.display()))?;
    reject_unknown_keys(root, &["paths", "allowlists", "rules"], "config root")?;

    if let Some(paths_value) = root.get("paths") {
        let paths = paths_value
            .as_object()
            .ok_or_else(|| "config key `paths` must be an object".to_string())?;
        reject_unknown_keys(paths, &["ignore"], "config key `paths`")?;
        if let Some(ignore) = paths.get("ignore") {
            config.ignored_paths = string_array(ignore, "paths.ignore")?;
        }
    }

    if let Some(allowlists_value) = root.get("allowlists") {
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
    }

    if let Some(rules_value) = root.get("rules") {
        let registry = rules::builtin_registry();
        let rules = rules_value
            .as_object()
            .ok_or_else(|| "config key `rules` must be an object".to_string())?;
        for (rule_id, rule_value) in rules {
            if !registry.contains(rule_id) {
                return Err(format!("unknown rule id `{rule_id}` in config"));
            }
            let rule_object = rule_value
                .as_object()
                .ok_or_else(|| format!("config for rule `{rule_id}` must be an object"))?;
            reject_unknown_keys(
                rule_object,
                &["enabled", "threshold", "thresholds", "options"],
                &format!("config for rule `{rule_id}`"),
            )?;

            let mut setting = RuleSetting::default();
            if let Some(enabled) = rule_object.get("enabled") {
                setting.enabled = Some(enabled.as_bool().ok_or_else(|| {
                    format!("config key `rules.{rule_id}.enabled` must be a boolean")
                })?);
            }
            if rule_object.contains_key("threshold") && rule_object.contains_key("thresholds") {
                return Err(format!(
                    "config for rule `{rule_id}` cannot use both `threshold` and `thresholds`"
                ));
            }
            if let Some(threshold_value) = rule_object.get("threshold") {
                let threshold_name = single_threshold_name(&registry, rule_id)?;
                let number = threshold_value.as_f64().ok_or_else(|| {
                    format!("threshold `rules.{rule_id}.threshold` must be a number")
                })?;
                setting
                    .thresholds
                    .insert(threshold_name.to_string(), number);
            }
            if let Some(thresholds_value) = rule_object.get("thresholds") {
                let thresholds = thresholds_value.as_object().ok_or_else(|| {
                    format!("config key `rules.{rule_id}.thresholds` must be an object")
                })?;
                for (name, threshold) in thresholds {
                    if !registry.supports_threshold(rule_id, name) {
                        return Err(format!("unknown threshold `{name}` for rule `{rule_id}`"));
                    }
                    let number = threshold.as_f64().ok_or_else(|| {
                        format!("threshold `rules.{rule_id}.thresholds.{name}` must be a number")
                    })?;
                    setting.thresholds.insert(name.clone(), number);
                }
            }
            if let Some(options_value) = rule_object.get("options") {
                let options = options_value.as_object().ok_or_else(|| {
                    format!("config key `rules.{rule_id}.options` must be an object")
                })?;
                for name in options.keys() {
                    if !registry.supports_option(rule_id, name) {
                        return Err(format!("unknown option `{name}` for rule `{rule_id}`"));
                    }
                }
            }
            config.rule_settings.insert(rule_id.clone(), setting);
        }
    }

    Ok(config)
}

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
        "json" => serde_json::from_str(raw)
            .map_err(|error| format!("invalid config JSON {}: {error}", path.display())),
        _ => serde_yaml::from_str(raw)
            .map_err(|error| format!("invalid config YAML {}: {error}", path.display())),
    }
}

fn single_threshold_name<'a>(
    registry: &'a rules::RuleRegistry,
    rule_id: &str,
) -> Result<&'a str, String> {
    let definition = registry
        .get(rule_id)
        .ok_or_else(|| format!("unknown rule id `{rule_id}` in config"))?;
    if definition.thresholds.len() == 1 {
        Ok(definition.thresholds[0].name)
    } else {
        Err(format!(
            "config key `rules.{rule_id}.threshold` is only supported for rules with exactly one threshold"
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
    call_names.sort_by(|left, right| {
        (left.file_path.as_str(), left.name.as_str(), left.line).cmp(&(
            right.file_path.as_str(),
            right.name.as_str(),
            right.line,
        ))
    });
    call_names.dedup();
    rust_sources.sort_by(|left, right| left.file_path.cmp(&right.file_path));

    ProjectContext {
        root_path: project_root.to_path_buf(),
        manifest,
        lockfile,
        rust_sources,
        modules,
        items,
        call_names,
        diagnostics,
    }
}

fn read_manifest_summary(
    project_root: &Path,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Option<ManifestSummary> {
    let path = project_root.join("Cargo.toml");
    if !path.exists() {
        return None;
    }

    let raw = match fs::read_to_string(&path) {
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
    };

    let value = match raw.parse::<toml::Value>() {
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
    };

    let package_name = value
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let package_description = value
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("description"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let package_license = value
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("license"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let dependency_lines = manifest_dependency_lines(&raw);
    let mut dependencies = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        collect_manifest_dependencies(&value, section, &dependency_lines, &mut dependencies);
    }
    dependencies.sort_by(|left, right| {
        (left.section.as_str(), left.name.as_str())
            .cmp(&(right.section.as_str(), right.name.as_str()))
    });

    Some(ManifestSummary {
        file_path: "Cargo.toml".to_string(),
        package_line: manifest_package_line(&raw),
        package_name,
        package_description,
        package_license,
        dependencies,
    })
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
    let path = project_root.join("Cargo.lock");
    if !path.exists() {
        return None;
    }

    let raw = match fs::read_to_string(&path) {
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
    };

    let value = match raw.parse::<toml::Value>() {
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
    };

    let package_lines = lockfile_package_lines(&raw);
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

    Some(LockfileSummary {
        file_path: "Cargo.lock".to_string(),
        packages,
    })
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
    for item in syn_items {
        match item {
            Item::Fn(item_fn) => items.push(project_item(
                file,
                module_path,
                item_fn.sig.ident.to_string(),
                "function",
                line_from_span(item_fn.sig.ident.span().start()),
                ProjectItemContext {
                    public: visibility_is_public(&item_fn.vis),
                    cfg_gated: cfg_context || has_cfg_attr(&item_fn.attrs),
                    test_context: test_context || has_test_attr(&item_fn.attrs),
                },
            )),
            Item::Struct(item_struct) => items.push(project_item(
                file,
                module_path,
                item_struct.ident.to_string(),
                "struct",
                line_from_span(item_struct.ident.span().start()),
                ProjectItemContext {
                    public: visibility_is_public(&item_struct.vis),
                    cfg_gated: cfg_context || has_cfg_attr(&item_struct.attrs),
                    test_context,
                },
            )),
            Item::Enum(item_enum) => items.push(project_item(
                file,
                module_path,
                item_enum.ident.to_string(),
                "enum",
                line_from_span(item_enum.ident.span().start()),
                ProjectItemContext {
                    public: visibility_is_public(&item_enum.vis),
                    cfg_gated: cfg_context || has_cfg_attr(&item_enum.attrs),
                    test_context,
                },
            )),
            Item::Trait(item_trait) => items.push(project_item(
                file,
                module_path,
                item_trait.ident.to_string(),
                "trait",
                line_from_span(item_trait.ident.span().start()),
                ProjectItemContext {
                    public: visibility_is_public(&item_trait.vis),
                    cfg_gated: cfg_context || has_cfg_attr(&item_trait.attrs),
                    test_context,
                },
            )),
            Item::Impl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(method) = impl_item {
                        items.push(project_item(
                            file,
                            module_path,
                            method.sig.ident.to_string(),
                            "method",
                            line_from_span(method.sig.ident.span().start()),
                            ProjectItemContext {
                                public: visibility_is_public(&method.vis),
                                cfg_gated: cfg_context
                                    || has_cfg_attr(&item_impl.attrs)
                                    || has_cfg_attr(&method.attrs),
                                test_context: test_context || has_test_attr(&method.attrs),
                            },
                        ));
                    }
                }
            }
            Item::Mod(item_mod) => {
                let current_module = module_name(module_path, &item_mod.ident.to_string());
                let module_cfg_gated = cfg_context || has_cfg_attr(&item_mod.attrs);
                let module_test_context = test_context || is_test_module(item_mod);
                modules.push(ModuleSummary {
                    file_path: file.display_path.clone(),
                    module_path: current_module.clone(),
                    line: line_from_span(item_mod.ident.span().start()),
                    public: visibility_is_public(&item_mod.vis),
                    inline: item_mod.content.is_some(),
                    cfg_gated: module_cfg_gated,
                });
                if let Some((_, nested)) = &item_mod.content {
                    collect_project_items(
                        file,
                        nested,
                        &current_module,
                        module_cfg_gated,
                        module_test_context,
                        modules,
                        items,
                    );
                }
            }
            _ => {}
        }
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
    item_mod.ident == "tests" || has_test_attr(&item_mod.attrs)
}

fn collect_call_names(file: &SourceFile, source: &str, call_names: &mut Vec<CallNameSummary>) {
    let regex = Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(").expect("static regex compiles");
    for capture in regex.captures_iter(source) {
        let Some(name) = capture.get(1) else {
            continue;
        };
        if matches!(
            name.as_str(),
            "fn" | "if" | "match" | "while" | "for" | "loop" | "return"
        ) {
            continue;
        }
        call_names.push(CallNameSummary {
            file_path: file.display_path.clone(),
            name: name.as_str().to_string(),
            line: byte_line(source, name.start()),
        });
    }
}

fn visibility_is_public(visibility: &Visibility) -> bool {
    !matches!(visibility, Visibility::Inherited)
}

fn byte_line(source: &str, byte_index: usize) -> usize {
    source[..byte_index.min(source.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
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
    let threshold = config.threshold(rule_id, "modules", 8.0) as usize;
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
            Severity::Advisory,
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
    let threshold = config.threshold(rule_id, "items", 12.0) as usize;
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
            Severity::Advisory,
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
    let threshold = config.threshold(rule_id, "items", 25.0) as usize;
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
            Severity::Advisory,
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
    let allowed_versions = config.threshold(rule_id, "versions", 2.0) as usize;
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
            Severity::Advisory,
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
    built_in_rules::analyse(unit, config)
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
            pattern: r"(sk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})",
            message: "API key pattern detected.",
        },
    ];

    static TEST_ASSERTION_REGEX: OnceLock<Regex> = OnceLock::new();
    static SLEEP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();
    static LOOP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();
    static CONDITIONAL_LOGIC_REGEX: OnceLock<Regex> = OnceLock::new();
    static UNWRAP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();

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
        analyse_text_rules(unit.file, unit.source, config, &mut findings);
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
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let line_count = source.lines().count();
        let file_warn = config.threshold("size.file-length", "warn", 400.0) as usize;
        let file_error = config.threshold("size.file-length", "error", 800.0) as usize;
        if line_count > file_error {
            findings.push(finding(
                "size.file-length",
                format!("File has {line_count} lines, above the error threshold of {file_error}."),
                file,
                Some(1),
                Severity::Error,
                Pillar::Size,
            ));
        } else if line_count > file_warn {
            findings.push(finding(
                "size.file-length",
                format!("File has {line_count} lines, above the warning threshold of {file_warn}."),
                file,
                Some(1),
                Severity::Warning,
                Pillar::Size,
            ));
        }

        let todo_count = source.matches("TODO").count() + source.matches("FIXME").count();
        if todo_count >= config.threshold("docs.todo-density", "markers", 4.0) as usize {
            findings.push(finding(
                "docs.todo-density",
                format!("File contains {todo_count} TODO/FIXME markers."),
                file,
                Some(first_matching_line(source, "TODO").unwrap_or(1)),
                Severity::Advisory,
                Pillar::Documentation,
            ));
        }

        analyse_sensitive_data(file, source, config, findings);
    }

    fn analyse_sensitive_data(
        file: &SourceFile,
        source: &str,
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

        analyse_env_like_secrets(file, source, config, findings);
        analyse_high_entropy_strings(file, source, config, findings);
    }

    fn analyse_env_like_secrets(
        file: &SourceFile,
        source: &str,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let regex = Regex::new(
            r#"\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|DATABASE_URL)[A-Z0-9_]*\s*=\s*["']?([^"'\s]+)"#,
        )
        .expect("static regex compiles");

        for capture in regex.find_iter(source) {
            let preview = redact(capture.as_str());
            if config.secret_previews.contains(&preview) {
                continue;
            }
            findings.push(Finding::new(
                "sensitive-data.hardcoded-env-value",
                "Hardcoded environment-style secret assignment detected.",
                file.display_path.clone(),
                Some(byte_line(source, capture.start())),
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

    fn analyse_high_entropy_strings(
        file: &SourceFile,
        source: &str,
        config: &Config,
        findings: &mut Vec<Finding>,
    ) {
        let regex = Regex::new(r#""([A-Za-z0-9+/=_-]{32,})"|'([A-Za-z0-9+/=_-]{32,})'"#)
            .expect("static regex compiles");

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
            let searchable_body = strip_rust_string_literals(&block.body);
            let method_warn = config.threshold("size.function-length", "warn", 30.0) as usize;
            let method_error = config.threshold("size.function-length", "error", 60.0) as usize;
            if block.line_count > method_error {
                findings.push(block_finding(
                    "size.function-length",
                    format!(
                        "Function `{}` has {} lines, above the error threshold of {method_error}.",
                        block.name, block.line_count
                    ),
                    file,
                    block,
                    Severity::Error,
                    Pillar::Size,
                ));
            } else if block.line_count > method_warn {
                findings.push(block_finding(
                    "size.function-length",
                    format!(
                        "Function `{}` has {} lines, above the warning threshold of {method_warn}.",
                        block.name, block.line_count
                    ),
                    file,
                    block,
                    Severity::Warning,
                    Pillar::Size,
                ));
            }

            let params = block.param_count;
            if params > config.threshold("size.parameter-count", "warn", 5.0) as usize {
                findings.push(block_finding(
                    "size.parameter-count",
                    format!("Function `{}` declares {params} parameters.", block.name),
                    file,
                    block,
                    Severity::Warning,
                    Pillar::Size,
                ));
            }

            let cyclomatic = count_regex(
                &searchable_body,
                r"\b(if|else if|match|for|while|loop)\b|\?|&&|\|\|",
            ) + 1;
            if cyclomatic > config.threshold("complexity.cyclomatic", "error", 20.0) as usize {
                findings.push(block_finding_with_metadata(
                    "complexity.cyclomatic",
                    format!(
                        "Function `{}` has cyclomatic complexity {cyclomatic}.",
                        block.name
                    ),
                    file,
                    block,
                    Severity::Error,
                    Pillar::Complexity,
                    json!({ "complexity": cyclomatic }),
                ));
            } else if cyclomatic > config.threshold("complexity.cyclomatic", "warn", 10.0) as usize
            {
                findings.push(block_finding_with_metadata(
                    "complexity.cyclomatic",
                    format!(
                        "Function `{}` has cyclomatic complexity {cyclomatic}.",
                        block.name
                    ),
                    file,
                    block,
                    Severity::Warning,
                    Pillar::Complexity,
                    json!({ "complexity": cyclomatic }),
                ));
            }

            let nesting = max_nesting_depth(&searchable_body);
            let nesting_error = config.threshold("complexity.nesting-depth", "error", 6.0) as usize;
            let nesting_warn = config.threshold("complexity.nesting-depth", "warn", 4.0) as usize;
            if nesting > nesting_error {
                findings.push(block_finding_with_metadata(
                    "complexity.nesting-depth",
                    format!("Function `{}` has nesting depth {nesting}.", block.name),
                    file,
                    block,
                    Severity::Error,
                    Pillar::Complexity,
                    json!({ "nestingDepth": nesting }),
                ));
            } else if nesting > nesting_warn {
                findings.push(block_finding_with_metadata(
                    "complexity.nesting-depth",
                    format!("Function `{}` has nesting depth {nesting}.", block.name),
                    file,
                    block,
                    Severity::Warning,
                    Pillar::Complexity,
                    json!({ "nestingDepth": nesting }),
                ));
            }

            let npath = approximate_npath(&searchable_body);
            let npath_error = config.threshold("complexity.npath", "error", 128.0) as usize;
            let npath_warn = config.threshold("complexity.npath", "warn", 32.0) as usize;
            if npath > npath_error {
                findings.push(block_finding_with_extras(
                    "complexity.npath",
                    format!(
                        "Function `{}` has approximate NPath complexity {npath}.",
                        block.name
                    ),
                    file,
                    block,
                    Severity::Error,
                    Pillar::Complexity,
                    BlockFindingExtras {
                        confidence: Confidence::Medium,
                        remediation: None,
                        metadata: json!({ "npath": npath, "approximation": "branch-doubling" }),
                    },
                ));
            } else if npath > npath_warn {
                findings.push(block_finding_with_extras(
                    "complexity.npath",
                    format!(
                        "Function `{}` has approximate NPath complexity {npath}.",
                        block.name
                    ),
                    file,
                    block,
                    Severity::Warning,
                    Pillar::Complexity,
                    BlockFindingExtras {
                        confidence: Confidence::Medium,
                        remediation: None,
                        metadata: json!({ "npath": npath, "approximation": "branch-doubling" }),
                    },
                ));
            }

            let cognitive = cyclomatic + nesting.saturating_mul(2);
            if cognitive > config.threshold("complexity.cognitive", "warn", 15.0) as usize {
                findings.push(block_finding_with_metadata(
                    "complexity.cognitive",
                    format!(
                        "Function `{}` has cognitive complexity {cognitive}.",
                        block.name
                    ),
                    file,
                    block,
                    Severity::Warning,
                    Pillar::Complexity,
                    json!({ "complexity": cognitive, "cyclomatic": cyclomatic, "nestingDepth": nesting }),
                ));
            }

            analyse_metric_block(file, block, &searchable_body, cyclomatic, config, findings);
            analyse_performance_block(file, block, &searchable_body, findings);

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

            if block.is_test {
                analyse_test_block(file, block, config, findings);
            }
            if !block.is_test_context() {
                analyse_error_handling_block(file, block, &searchable_body, findings);
                analyse_concurrency_block(file, block, &searchable_body, findings);
            }
        }
    }

    fn analyse_error_handling_block(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        if Regex::new(r"\bpanic!\s*\(")
            .expect("static regex compiles")
            .is_match(searchable_body)
            && !has_nearby_invariant_comment(searchable_body)
        {
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

        if Regex::new(r"\b(todo!|unimplemented!)\s*\(")
            .expect("static regex compiles")
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

        if block.is_public
            && Regex::new(r"\.(unwrap|expect)\s*\(")
                .expect("static regex compiles")
                .is_match(searchable_body)
        {
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
        let volume_threshold = config.threshold("metrics.halstead-volume", "volume", 900.0);
        if metrics.halstead_volume > volume_threshold {
            findings.push(block_finding_with_extras(
                "metrics.halstead-volume",
                format!(
                    "Function `{}` has Halstead-style volume {:.1}, above the threshold of {:.1}.",
                    block.name, metrics.halstead_volume, volume_threshold
                ),
                file,
                block,
                Severity::Advisory,
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

        let minimum_score = config.threshold("metrics.maintainability-pressure", "minimum", 45.0);
        if metrics.maintainability_score < minimum_score {
            findings.push(block_finding_with_extras(
                "metrics.maintainability-pressure",
                format!(
                    "Function `{}` has maintainability pressure score {:.1}, below the minimum of {:.1}.",
                    block.name, metrics.maintainability_score, minimum_score
                ),
                file,
                block,
                Severity::Advisory,
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

    fn analyse_performance_block(
        file: &SourceFile,
        block: &FunctionBlock,
        searchable_body: &str,
        findings: &mut Vec<Finding>,
    ) {
        let checks = [
            PerformanceCheck {
                rule_id: "performance.regex-in-loop",
                pattern: r"\bRegex::new\s*\(",
                severity: Severity::Warning,
                confidence: Confidence::High,
                label: "Regex::new",
                remediation: "Move regex construction out of the loop or cache the compiled regex.",
            },
            PerformanceCheck {
                rule_id: "performance.format-in-loop",
                pattern: r"\bformat!\s*\(",
                severity: Severity::Advisory,
                confidence: Confidence::Medium,
                label: "format!",
                remediation:
                    "Reuse buffers or move formatting out of the loop when allocation matters.",
            },
            PerformanceCheck {
                rule_id: "performance.clone-in-loop",
                pattern: r"\.clone\s*\(",
                severity: Severity::Advisory,
                confidence: Confidence::Medium,
                label: "clone()",
                remediation: "Clone outside the loop or borrow values when ownership permits.",
            },
        ];

        for check in checks {
            let occurrences = loop_pattern_count(searchable_body, check.pattern);
            if occurrences == 0 {
                continue;
            }
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
    }

    struct PerformanceCheck {
        rule_id: &'static str,
        pattern: &'static str,
        severity: Severity,
        confidence: Confidence,
        label: &'static str,
        remediation: &'static str,
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

        if Regex::new(
            r"\b(std::sync::mpsc::channel|mpsc::unbounded_channel|unbounded_channel)(?:\s*::\s*<[^>]+>)?\s*\(",
        )
            .expect("static regex compiles")
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
        let lock_binding = Regex::new(
            r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\.(?:lock|read|write)\s*\([^;]*;",
        )
        .expect("static regex compiles");
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

        let long_test_warn = config.threshold("test-quality.long-test", "warn", 30.0) as usize;
        if block.line_count > long_test_warn {
            findings.push(block_finding_with_metadata(
                "test-quality.long-test",
                format!(
                    "Test `{}` has {} lines, above the warning threshold of {long_test_warn}.",
                    block.name, block.line_count
                ),
                file,
                block,
                Severity::Advisory,
                Pillar::TestQuality,
                json!({ "lines": block.line_count }),
            ));
        }

        let searchable_body = strip_rust_string_literals(&block.body);

        if has_trivial_assertion(&searchable_body) {
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
        .is_match(&searchable_body)
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

        for rule in TEST_CHECKS {
            if static_regex(rule.regex, rule.pattern).is_match(&searchable_body) {
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
        let command_regex = Regex::new(r"(std::process::Command|Command)::new\s*\(")
            .expect("static regex compiles");
        let unwrap_regex = Regex::new(r"\.(unwrap|expect)\s*\(").expect("static regex compiles");
        let unsafe_regex = Regex::new(r"\bunsafe\s*\{").expect("static regex compiles");
        let clone_regex = Regex::new(r"\.clone\(\)").expect("static regex compiles");
        let variable_regex = Regex::new(r"\b(?:let|for)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)")
            .expect("static regex compiles");
        let lines: Vec<&str> = searchable_source.lines().collect();

        for (line_index, line) in lines.iter().enumerate() {
            let line_number = line_index + 1;

            if command_regex.is_match(line) {
                findings.push(finding(
                "security.process-command",
                "Process command execution is used; validate command arguments are not user-controlled.",
                file,
                Some(line_number),
                Severity::Warning,
                Pillar::Security,
            ));
            }

            if unsafe_regex.is_match(line) && !has_nearby_safety_comment(&lines, line_index) {
                findings.push(finding(
                    "security.unsafe-block",
                    "Unsafe block lacks a nearby SAFETY rationale.",
                    file,
                    Some(line_number),
                    Severity::Warning,
                    Pillar::Security,
                ));
            }

            if unwrap_regex.is_match(line) && !line.contains("#[test]") {
                findings.push(finding(
                    "waste.unwrap-expect",
                    "unwrap()/expect() can turn recoverable errors into panics.",
                    file,
                    Some(line_number),
                    Severity::Advisory,
                    Pillar::Waste,
                ));
            }

            if clone_regex.is_match(line) {
                findings.push(finding(
                    "waste.unnecessary-clone-candidate",
                    "clone() call may be avoidable; confirm ownership requires it.",
                    file,
                    Some(line_number),
                    Severity::Advisory,
                    Pillar::Waste,
                ));
            }

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
                        file.display_path.clone(),
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
                    && !config
                        .accepted_abbreviations
                        .contains(&name.to_ascii_lowercase())
                {
                    findings.push(Finding::new(
                        "naming.short-variable",
                        format!("Variable `{name}` is too short to explain intent."),
                        file.display_path.clone(),
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

        analyse_unreachable(file, &searchable_source, findings);
    }

    fn analyse_item_rules(file: &SourceFile, ast: &syn::File, findings: &mut Vec<Finding>) {
        for item in &ast.items {
            analyse_public_item(file, item, findings);
        }
    }

    fn analyse_public_item(file: &SourceFile, item: &Item, findings: &mut Vec<Finding>) {
        match item {
            Item::Mod(item_mod) => {
                if is_public(&item_mod.vis) && !has_doc_attr(&item_mod.attrs) {
                    push_missing_public_item_doc(
                        file,
                        item_mod.ident.to_string(),
                        item_mod.ident.span(),
                        findings,
                    );
                }
                if let Some((_, items)) = &item_mod.content {
                    for nested in items {
                        analyse_public_item(file, nested, findings);
                    }
                }
            }
            Item::Struct(item_struct) => {
                if is_public(&item_struct.vis) && !has_doc_attr(&item_struct.attrs) {
                    push_missing_public_item_doc(
                        file,
                        item_struct.ident.to_string(),
                        item_struct.ident.span(),
                        findings,
                    );
                }
                for field in &item_struct.fields {
                    if is_public(&field.vis) {
                        findings.push(finding(
                        "modernisation.public-field",
                        "Public struct field exposes representation; prefer accessors when invariants matter.",
                        file,
                        Some(line_from_span(field.span().start())),
                        Severity::Advisory,
                        Pillar::Modernisation,
                    ));
                    }
                }
            }
            Item::Enum(item_enum) => {
                if is_public(&item_enum.vis) && !has_doc_attr(&item_enum.attrs) {
                    push_missing_public_item_doc(
                        file,
                        item_enum.ident.to_string(),
                        item_enum.ident.span(),
                        findings,
                    );
                }
            }
            Item::Trait(item_trait) => {
                if is_public(&item_trait.vis) && !has_doc_attr(&item_trait.attrs) {
                    push_missing_public_item_doc(
                        file,
                        item_trait.ident.to_string(),
                        item_trait.ident.span(),
                        findings,
                    );
                }
            }
            _ => {}
        }
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
            analyse_dead_code_item(file, item, source, findings);
        }
    }

    fn analyse_dead_code_item(
        file: &SourceFile,
        item: &Item,
        source: &str,
        findings: &mut Vec<Finding>,
    ) {
        match item {
            Item::Fn(item_fn) => analyse_dead_function(
                file,
                &item_fn.vis,
                item_fn.sig.ident.to_string(),
                item_fn.sig.ident.span(),
                source,
                findings,
            ),
            Item::Impl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(method) = impl_item {
                        analyse_dead_function(
                            file,
                            &method.vis,
                            method.sig.ident.to_string(),
                            method.sig.ident.span(),
                            source,
                            findings,
                        );
                    }
                }
            }
            Item::Mod(item_mod) => {
                if let Some((_, items)) = &item_mod.content {
                    for nested in items {
                        analyse_dead_code_item(file, nested, source, findings);
                    }
                }
            }
            _ => {}
        }
    }

    fn analyse_dead_function(
        file: &SourceFile,
        visibility: &Visibility,
        name: String,
        span: proc_macro2::Span,
        source: &str,
        findings: &mut Vec<Finding>,
    ) {
        if is_public(visibility) {
            return;
        }
        let needle = format!("{name}(");
        if source.matches(&needle).count() <= 1 {
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

    fn analyse_unreachable(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
        let terminator =
            Regex::new(r"\b(return|panic!|todo!|unimplemented!)").expect("static regex compiles");
        let useful = Regex::new(r"\S").expect("static regex compiles");
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
            Item::Fn(item_fn) => blocks.push(function_block_from_parts(FunctionBlockParts {
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
            })),
            Item::Impl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(method) = impl_item {
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
                }
            }
            Item::Mod(item_mod) => {
                if let Some((_, items)) = &item_mod.content {
                    let nested_test_context = test_context || item_mod.ident == "tests";
                    for nested in items {
                        collect_function_blocks(nested, lines, nested_test_context, blocks);
                    }
                }
            }
            _ => {}
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

    fn strip_rust_string_literals(source: &str) -> String {
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

    fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
        if bytes.get(start).copied()? != b'r' {
            return None;
        }

        let mut cursor = start + 1;
        let mut hashes = 0usize;
        while bytes.get(cursor) == Some(&b'#') {
            hashes += 1;
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'"') {
            return None;
        }
        cursor += 1;

        while cursor < bytes.len() {
            if bytes[cursor] == b'"' {
                let mut hash_cursor = cursor + 1;
                let mut matched = 0usize;
                while matched < hashes && bytes.get(hash_cursor) == Some(&b'#') {
                    matched += 1;
                    hash_cursor += 1;
                }
                if matched == hashes {
                    return Some(hash_cursor);
                }
            }
            cursor += 1;
        }

        Some(bytes.len())
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
        let branch_decisions = count_regex(source, r"\b(if|match|for|while|loop)\b");
        let boolean_decisions = count_regex(source, r"&&|\|\||\?");
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
        Regex::new(
            r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|==|!=|<=|>=|&&|\|\||::|->|=>|[{}()\[\];,.:+\-*/%&|^!<>?=]",
        )
        .expect("static regex compiles")
        .find_iter(source)
        .map(|token| token.as_str().to_string())
        .collect()
    }

    fn round1(value: f64) -> f64 {
        (value * 10.0).round() / 10.0
    }

    fn loop_pattern_count(source: &str, pattern: &str) -> usize {
        let pattern = Regex::new(pattern).expect("static regex compiles");
        let loop_start = Regex::new(r"\b(for|while|loop)\b").expect("static regex compiles");
        let mut depth = 0usize;
        let mut loop_depths = Vec::new();
        let mut pending_loop = false;
        let mut occurrences = 0usize;

        for line in source.lines() {
            if !loop_depths.is_empty() && pattern.is_match(line) {
                occurrences += pattern.find_iter(line).count();
            }
            if loop_start.is_match(line) {
                pending_loop = true;
            }

            for character in line.chars() {
                match character {
                    '{' => {
                        depth += 1;
                        if pending_loop {
                            loop_depths.push(depth);
                            pending_loop = false;
                        }
                    }
                    '}' => {
                        loop_depths.retain(|loop_depth| *loop_depth < depth);
                        depth = depth.saturating_sub(1);
                    }
                    _ => {}
                }
            }
        }

        occurrences
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
            Regex::new(r"\bassert!\s*\(\s*(true|false)\s*\)").expect("static regex compiles");
        if literal_assert.is_match(source) {
            return true;
        }

        let same_literal = Regex::new(
            r#"\bassert_eq!\s*\(\s*([0-9]+|"[^"]*"|'[^']*')\s*,\s*([0-9]+|"[^"]*"|'[^']*')\s*\)"#,
        )
        .expect("static regex compiles");
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

    fn count_regex(source: &str, pattern: &str) -> usize {
        Regex::new(pattern)
            .expect("static regex compiles")
            .find_iter(source)
            .count()
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

    let composite = if pillars.is_empty() {
        100.0
    } else {
        pillars.iter().map(|pillar| pillar.score).sum::<f64>() / pillars.len() as f64
    };

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

    ScoreReport {
        composite,
        grade: grade(composite),
        pillars,
        top_offenders,
    }
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

    output
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

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
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
            diagnostics: Vec::new(),
            findings,
            score,
            baseline: None,
        }
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

    fn write_default_config(dir: &Path, body: &str) {
        fs::write(dir.join(".gruff.json"), body).expect("config write");
    }

    fn write_yaml_config(dir: &Path, body: &str) {
        fs::write(dir.join(".gruff.yaml"), body).expect("yaml config write");
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
        assert_eq!(report.summary.total, 13);

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
            (
                "dead-code.unused-private-function",
                Severity::Advisory,
                "fixtures/sample.rs",
                Some(25),
                Some("test_sleeps_without_assertion"),
                "b83f8c23ee44d8f3",
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
            r#"pub struct Bad {
    pub name: String,
}

impl Bad {
    pub fn process(a: bool, b: Vec<String>, c: String, d: String, e: String, f: String) {
        if a {
            std::process::Command::new("sh").arg("-c").arg(c).spawn().unwrap();
        }
        println!("{}{}{}", d, e, f);
    }
}

#[test]
fn test_no_assert() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}
"#,
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

        write_default_config(dir.path(), r#"{ "unknown": true }"#);
        let error = load_config(dir.path(), &options).expect_err("unknown root key rejected");
        assert!(error.contains("unknown key `unknown`"), "{error}");

        write_default_config(
            dir.path(),
            r#"{ "rules": { "unknown.rule": { "enabled": false } } }"#,
        );
        let error = load_config(dir.path(), &options).expect_err("unknown rule rejected");
        assert!(error.contains("unknown rule id `unknown.rule`"), "{error}");
    }

    #[test]
    fn config_rejects_unknown_thresholds_and_options() {
        let dir = tempdir().expect("tempdir");
        let options = default_test_options();

        write_default_config(
            dir.path(),
            r#"{ "rules": { "size.parameter-count": { "thresholds": { "bogus": 1 } } } }"#,
        );
        let error = load_config(dir.path(), &options).expect_err("unknown threshold rejected");
        assert!(error.contains("unknown threshold `bogus`"), "{error}");

        write_default_config(
            dir.path(),
            r#"{ "rules": { "size.parameter-count": { "options": { "bogus": true } } } }"#,
        );
        let error = load_config(dir.path(), &options).expect_err("unknown option rejected");
        assert!(error.contains("unknown option `bogus`"), "{error}");
    }

    #[test]
    fn yaml_config_is_default_and_json_config_still_works_explicitly() {
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
        write_default_config(dir.path(), r#"{ "unknown": true }"#);
        write_yaml_config(
            dir.path(),
            r#"
rules:
  size.parameter-count:
    threshold: 10
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
        .expect("yaml config is the preferred default");
        assert_missing_rule(&yaml_default, "size.parameter-count");

        let json_explicit = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("sample.rs")],
                config: Some(PathBuf::from(".gruff.json")),
                no_config: false,
                no_baseline: true,
                ..default_test_options()
            },
        )
        .expect_err("explicit json config is still parsed and validated");
        assert!(
            json_explicit.contains("unknown key `unknown`"),
            "{json_explicit}"
        );
    }

    #[test]
    fn yaml_threshold_shorthand_is_strict() {
        let dir = tempdir().expect("tempdir");
        let options = default_test_options();

        write_yaml_config(
            dir.path(),
            r#"
rules:
  complexity.cognitive:
    threshold: 20
"#,
        );
        let config =
            load_config(dir.path(), &options).expect("single threshold shorthand accepted");
        assert_eq!(config.threshold("complexity.cognitive", "warn", 15.0), 20.0);

        write_yaml_config(
            dir.path(),
            r#"
rules:
  complexity.cyclomatic:
    threshold: 20
"#,
        );
        let error =
            load_config(dir.path(), &options).expect_err("multi-threshold shorthand rejected");
        assert!(
            error.contains("threshold` is only supported for rules with exactly one threshold"),
            "{error}"
        );
    }

    #[test]
    fn config_disables_rules_and_overrides_thresholds() {
        let _guard = analysis_lock();
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("sample.rs"),
            r#"pub fn process(a: bool, b: String, c: String, d: String, e: String, f: String) {
    if a {
        std::process::Command::new("sh").arg("-c").arg(b).spawn().unwrap();
    }
    println!("{}{}{}{}", c, d, e, f);
}
"#,
        )
        .expect("fixture write");
        write_default_config(
            dir.path(),
            r#"{
  "rules": {
    "security.process-command": { "enabled": false },
    "size.parameter-count": { "thresholds": { "warn": 10 } }
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
        write_yaml_config(
            threshold_dir.path(),
            r#"
rules:
  dependency.duplicate-locked-version:
    threshold: 3
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

        write_yaml_config(
            threshold_dir.path(),
            r#"
rules:
  dependency.duplicate-locked-version:
    thresholds:
      bogus: 2
"#,
        );
        let error =
            load_config(threshold_dir.path(), &default_test_options()).expect_err("bad threshold");
        assert!(
            error.contains(
                "unknown threshold `bogus` for rule `dependency.duplicate-locked-version`"
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
        write_yaml_config(
            dir.path(),
            r#"
rules:
  architecture.module-fan-out:
    threshold: 2
  architecture.public-api-surface:
    threshold: 2
  architecture.large-module:
    threshold: 3
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
    fn architecture_rules_accept_small_modules_and_validate_thresholds() {
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

        write_yaml_config(
            dir.path(),
            r#"
rules:
  architecture.large-module:
    thresholds:
      bogus: 2
"#,
        );
        let error =
            load_config(dir.path(), &default_test_options()).expect_err("bad threshold rejected");
        assert!(
            error.contains("unknown threshold `bogus` for rule `architecture.large-module`"),
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
    fn metrics_rules_calibrate_thresholds_and_formatting_stability() {
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
        write_yaml_config(
            dir.path(),
            r#"
rules:
  metrics.halstead-volume:
    threshold: 1
  metrics.maintainability-pressure:
    threshold: 100
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

        write_yaml_config(
            dir.path(),
            r#"
rules:
  metrics.halstead-volume:
    thresholds:
      bogus: 1
"#,
        );
        let error =
            load_config(dir.path(), &default_test_options()).expect_err("bad metric threshold");
        assert!(
            error.contains("unknown threshold `bogus` for rule `metrics.halstead-volume`"),
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
            r#"pub fn process(command: String) {
    std::process::Command::new("sh").arg(command).spawn().unwrap();
}
"#,
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
        fs::create_dir_all(dir.path().join("src")).expect("src dir");
        fs::create_dir_all(dir.path().join("target")).expect("target dir");
        fs::create_dir_all(dir.path().join("ignored")).expect("ignored dir");
        fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
        fs::write(
            dir.path().join("src/lib.rs"),
            "/// Ready.\npub fn is_ready() -> bool { true }\n",
        )
        .expect("rust write");
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
        write_default_config(dir.path(), r#"{ "paths": { "ignore": ["ignored/**"] } }"#);

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
        assert_missing_rule(&default_scan, "sensitive-data.hardcoded-env-value");

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
        assert_has_rule(&include_ignored, "sensitive-data.hardcoded-env-value");

        let text_scan = run_project_analysis(
            dir.path(),
            AnalysisOptions {
                paths: vec![PathBuf::from("target/secret.env")],
                no_config: true,
                include_ignored: true,
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
            findings: Vec::new(),
            score: ScoreReport {
                composite: 100.0,
                grade: "A".to_string(),
                pillars: Vec::new(),
                top_offenders: Vec::new(),
            },
            baseline: None,
        };

        let rendered = render_report(&report, OutputFormat::Json);
        assert!(rendered.contains("\"schemaVersion\": \"gruff.analysis.v1\""));
    }
}
