use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};
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
use walkdir::{DirEntry, WalkDir};

const VERSION: &str = "0.1.0-dev";
const DEFAULT_BASELINE: &str = "gruff-baseline.json";

#[derive(Parser)]
#[command(
    name = "gruff-rs",
    version = VERSION,
    about = "Rust project quality analysis."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Analyse(AnalyseArgs),
    Report(ReportArgs),
    Dashboard(DashboardArgs),
}

#[derive(Args, Clone)]
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
struct DashboardArgs {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 8766)]
    port: u16,
    #[arg(long, default_value = ".")]
    project_root: PathBuf,
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
enum ReportFormat {
    Html,
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

#[derive(Debug, Clone, Serialize)]
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
    params: String,
    start_line: usize,
    line_count: usize,
    body: String,
    is_public: bool,
    is_test: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Analyse(args) => {
            let options = options_from_analyse(args);
            match run_analysis(&options) {
                Ok(report) => {
                    println!("{}", render_report(&report, options.format));
                    exit_for(&report, options.fail_on)
                }
                Err(error) => {
                    eprintln!("gruff-rs: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Commands::Report(args) => run_report(args),
        Commands::Dashboard(args) => run_dashboard(args),
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

fn run_report(args: ReportArgs) -> ExitCode {
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

    match run_analysis(&options) {
        Ok(report) => {
            let rendered = render_report(&report, format);
            if let Some(output) = args.output {
                if let Err(error) = fs::write(&output, rendered) {
                    eprintln!("gruff-rs: unable to write {}: {error}", output.display());
                    return ExitCode::from(2);
                }
            } else {
                println!("{rendered}");
            }
            exit_for(&report, args.fail_on)
        }
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            ExitCode::from(2)
        }
    }
}

fn run_analysis(options: &AnalysisOptions) -> Result<AnalysisReport, String> {
    let project_root = std::env::current_dir()
        .map_err(|error| format!("unable to resolve current directory: {error}"))?;
    let config = load_config(&project_root, options)?;
    let mut discovery = discover_sources(&project_root, options, &config);

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

    for source_file in &discovery.files {
        match fs::read_to_string(&source_file.absolute_path) {
            Ok(source) => {
                diagnostics.extend(parse_diagnostics(source_file, &source));
                findings.extend(analyse_source(source_file, &source, &config));
            }
            Err(error) => diagnostics.push(RunDiagnostic {
                diagnostic_type: "read-error".to_string(),
                message: format!("Unable to read file: {error}"),
                file_path: Some(source_file.display_path.clone()),
                line: Some(1),
            }),
        }
    }

    let mut baseline_report = None;
    if let Some(path) = &options.generate_baseline {
        let baseline_path = absolutize(&project_root, path);
        write_baseline(&baseline_path, &findings)?;
        baseline_report = Some(BaselineReport {
            path: display_path(&project_root, &baseline_path),
            source: "generated".to_string(),
            suppressed: 0,
            generated: true,
        });
    } else if !options.no_baseline {
        let selected = options
            .baseline
            .as_ref()
            .map(|path| (absolutize(&project_root, path), "explicit"))
            .or_else(|| {
                let default = project_root.join(DEFAULT_BASELINE);
                default.exists().then_some((default, "default"))
            });

        if let Some((baseline_path, source)) = selected {
            let before = findings.len();
            apply_baseline(&baseline_path, &mut findings)?;
            baseline_report = Some(BaselineReport {
                path: display_path(&project_root, &baseline_path),
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
        record_history(&project_root, history_file, &findings, &mut diagnostics);
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
        .or_else(|| {
            let default = project_root.join(".gruff.json");
            default.exists().then_some(default)
        });

    let Some(path) = config_path else {
        return Ok(config);
    };

    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("unable to read config {}: {error}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid config JSON {}: {error}", path.display()))?;

    if let Some(paths) = value.get("paths").and_then(Value::as_object) {
        if let Some(ignore) = paths.get("ignore").and_then(Value::as_array) {
            config.ignored_paths = ignore
                .iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect();
        }
    }

    if let Some(allowlists) = value.get("allowlists").and_then(Value::as_object) {
        if let Some(abbreviations) = allowlists
            .get("acceptedAbbreviations")
            .and_then(Value::as_array)
        {
            config.accepted_abbreviations = abbreviations
                .iter()
                .filter_map(Value::as_str)
                .map(|value| value.to_ascii_lowercase())
                .collect();
        }
        if let Some(previews) = allowlists.get("secretPreviews").and_then(Value::as_array) {
            config.secret_previews = previews
                .iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect();
        }
    }

    if let Some(rules) = value.get("rules").and_then(Value::as_object) {
        for (rule_id, rule_value) in rules {
            let mut setting = RuleSetting::default();
            if let Some(enabled) = rule_value.get("enabled").and_then(Value::as_bool) {
                setting.enabled = Some(enabled);
            }
            if let Some(thresholds) = rule_value.get("thresholds").and_then(Value::as_object) {
                for (name, threshold) in thresholds {
                    if let Some(number) = threshold.as_f64() {
                        setting.thresholds.insert(name.clone(), number);
                    }
                }
            }
            config.rule_settings.insert(rule_id.clone(), setting);
        }
    }

    Ok(config)
}

fn parse_diagnostics(file: &SourceFile, source: &str) -> Vec<RunDiagnostic> {
    if !file.is_rust {
        return Vec::new();
    }

    let mut braces = 0isize;
    let mut parentheses = 0isize;
    let mut brackets = 0isize;

    for (index, line) in source.lines().enumerate() {
        for character in line.chars() {
            match character {
                '{' => braces += 1,
                '}' => braces -= 1,
                '(' => parentheses += 1,
                ')' => parentheses -= 1,
                '[' => brackets += 1,
                ']' => brackets -= 1,
                _ => {}
            }
        }
        if braces < 0 || parentheses < 0 || brackets < 0 {
            return vec![RunDiagnostic {
                diagnostic_type: "parse-error".to_string(),
                message: "Unbalanced Rust delimiters detected.".to_string(),
                file_path: Some(file.display_path.clone()),
                line: Some(index + 1),
            }];
        }
    }

    if braces != 0 || parentheses != 0 || brackets != 0 {
        return vec![RunDiagnostic {
            diagnostic_type: "parse-error".to_string(),
            message: "Unbalanced Rust delimiters detected.".to_string(),
            file_path: Some(file.display_path.clone()),
            line: Some(source.lines().count().max(1)),
        }];
    }

    Vec::new()
}

fn analyse_source(file: &SourceFile, source: &str, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    analyse_text_rules(file, source, config, &mut findings);
    if file.is_rust {
        analyse_rust_rules(file, source, config, &mut findings);
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
    let patterns = [
        (
            "sensitive-data.aws-access-key",
            r"AKIA[0-9A-Z]{16}",
            "AWS access key pattern detected.",
        ),
        (
            "sensitive-data.private-key",
            r"BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY",
            "Private key block detected.",
        ),
        (
            "sensitive-data.jwt-token",
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "JWT-looking token detected.",
        ),
        (
            "sensitive-data.database-url-password",
            r"[a-z]+://[^:\s]+:[^@\s]+@",
            "Database URL appears to include a password.",
        ),
        (
            "sensitive-data.api-key-pattern",
            r"(sk_live_|ghp_|sk-ant-|xox[baprs]-|OPENAI_API_KEY)",
            "API key pattern detected.",
        ),
    ];

    for (rule_id, pattern, message) in patterns {
        let regex = Regex::new(pattern).expect("static regex compiles");
        for capture in regex.find_iter(source) {
            let preview = redact(capture.as_str());
            if config.secret_previews.contains(&preview) {
                continue;
            }
            findings.push(Finding::new(
                rule_id,
                message,
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
}

fn analyse_rust_rules(
    file: &SourceFile,
    source: &str,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let blocks = rust_function_blocks(source);
    analyse_blocks(file, &blocks, config, findings);
    analyse_line_rules(file, source, config, findings);
    analyse_item_rules(file, source, findings);
    analyse_dead_code(file, source, findings);
}

fn analyse_blocks(
    file: &SourceFile,
    blocks: &[FunctionBlock],
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    for block in blocks {
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

        let params = count_parameters(&block.params);
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
            &block.body,
            r"\b(if|else if|match|for|while|loop)\b|\?|&&|\|\|",
        ) + 1;
        if cyclomatic > config.threshold("complexity.cyclomatic", "error", 20.0) as usize {
            findings.push(block_finding(
                "complexity.cyclomatic",
                format!(
                    "Function `{}` has cyclomatic complexity {cyclomatic}.",
                    block.name
                ),
                file,
                block,
                Severity::Error,
                Pillar::Complexity,
            ));
        } else if cyclomatic > config.threshold("complexity.cyclomatic", "warn", 10.0) as usize {
            findings.push(block_finding(
                "complexity.cyclomatic",
                format!(
                    "Function `{}` has cyclomatic complexity {cyclomatic}.",
                    block.name
                ),
                file,
                block,
                Severity::Warning,
                Pillar::Complexity,
            ));
        }

        let nesting = max_nesting_depth(&block.body);
        let cognitive = cyclomatic + nesting;
        if cognitive > config.threshold("complexity.cognitive", "warn", 15.0) as usize {
            findings.push(block_finding(
                "complexity.cognitive",
                format!(
                    "Function `{}` has cognitive complexity {cognitive}.",
                    block.name
                ),
                file,
                block,
                Severity::Warning,
                Pillar::Complexity,
            ));
        }

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
            analyse_test_block(file, block, findings);
        }
    }
}

fn analyse_test_block(file: &SourceFile, block: &FunctionBlock, findings: &mut Vec<Finding>) {
    if !Regex::new(r"\b(assert!|assert_eq!|assert_ne!|matches!|panic!)")
        .expect("static regex compiles")
        .is_match(&block.body)
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

    let checks = [
        (
            "test-quality.sleep-in-test",
            r"(std::thread::sleep|tokio::time::sleep)",
            "Test sleeps instead of synchronising on behaviour.",
        ),
        (
            "test-quality.loop-in-test",
            r"\b(for|while|loop)\b",
            "Test contains loop logic.",
        ),
        (
            "test-quality.conditional-logic",
            r"\b(if|match)\b",
            "Test contains conditional logic.",
        ),
        (
            "test-quality.unwrap-in-test",
            r"\.unwrap\(\)",
            "Test uses unwrap(), which can hide setup intent.",
        ),
    ];

    for (rule_id, pattern, message) in checks {
        if Regex::new(pattern)
            .expect("static regex compiles")
            .is_match(&block.body)
        {
            findings.push(block_finding(
                rule_id,
                message,
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
    let command_regex =
        Regex::new(r"(std::process::Command|Command)::new\s*\(").expect("static regex compiles");
    let unwrap_regex = Regex::new(r"\.(unwrap|expect)\s*\(").expect("static regex compiles");
    let unsafe_regex = Regex::new(r"\bunsafe\s*\{").expect("static regex compiles");
    let clone_regex = Regex::new(r"\.clone\(\)").expect("static regex compiles");
    let variable_regex = Regex::new(r"\b(?:let|for)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)")
        .expect("static regex compiles");

    for (line_index, line) in source.lines().enumerate() {
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

        if unsafe_regex.is_match(line) {
            findings.push(finding(
                "security.unsafe-block",
                "Unsafe block requires a clear safety invariant.",
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

    analyse_unreachable(file, source, findings);
}

fn analyse_item_rules(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
    let item_regex = Regex::new(r"\bpub\s+(struct|enum|trait)\s+([A-Za-z_][A-Za-z0-9_]*)")
        .expect("static regex compiles");
    for captures in item_regex.captures_iter(source) {
        let Some(name) = captures.get(2) else {
            continue;
        };
        let line = byte_line(source, name.start());
        if !has_doc_comment_before_line(source, line) {
            findings.push(Finding::new(
                "docs.missing-public-doc",
                format!(
                    "Public item `{}` is missing a Rust doc comment.",
                    name.as_str()
                ),
                file.display_path.clone(),
                Some(line),
                Severity::Advisory,
                Pillar::Documentation,
                Confidence::Medium,
                Some(name.as_str().to_string()),
                Some("Add a /// doc comment explaining the public API contract.".to_string()),
                json!({}),
            ));
        }
    }

    let public_field_regex =
        Regex::new(r"\bpub\s+[A-Za-z_][A-Za-z0-9_]*\s*:").expect("static regex compiles");
    for field in public_field_regex.find_iter(source) {
        findings.push(finding(
            "modernisation.public-field",
            "Public struct field exposes representation; prefer accessors when invariants matter.",
            file,
            Some(byte_line(source, field.start())),
            Severity::Advisory,
            Pillar::Modernisation,
        ));
    }
}

fn analyse_dead_code(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
    let private_fn_regex =
        Regex::new(r"(?m)^\s*fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(").expect("static regex compiles");
    for captures in private_fn_regex.captures_iter(source) {
        let Some(name) = captures.get(1) else {
            continue;
        };
        let needle = format!("{}(", name.as_str());
        if source.matches(&needle).count() <= 1 {
            findings.push(Finding::new(
                "dead-code.unused-private-function",
                format!(
                    "Private function `{}` appears to be unused in this file.",
                    name.as_str()
                ),
                file.display_path.clone(),
                Some(byte_line(source, name.start())),
                Severity::Advisory,
                Pillar::DeadCode,
                Confidence::Low,
                Some(name.as_str().to_string()),
                Some("Remove the function or add a real call site.".to_string()),
                json!({}),
            ));
        }
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

fn rust_function_blocks(source: &str) -> Vec<FunctionBlock> {
    let function_regex = Regex::new(
        r"(pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)",
    )
    .expect("static regex compiles");
    let lines: Vec<&str> = source.lines().collect();
    let mut blocks = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        let Some(captures) = function_regex.captures(line) else {
            continue;
        };
        let Some(name) = captures.get(2) else {
            continue;
        };
        let params = captures
            .get(3)
            .map(|value| value.as_str())
            .unwrap_or_default()
            .to_string();
        let start = function_start_index(&lines, index);
        let mut depth = 0isize;
        let mut seen_open = false;
        let mut end = index;

        for (inner_index, inner_line) in lines.iter().enumerate().skip(index) {
            for character in inner_line.chars() {
                match character {
                    '{' => {
                        depth += 1;
                        seen_open = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            end = inner_index;
            if seen_open && depth <= 0 {
                break;
            }
        }

        let body = lines[start..=end].join("\n");
        let is_public = captures.get(1).is_some();
        let is_test = lines[start..=index]
            .iter()
            .any(|candidate| candidate.contains("#[test]"))
            || name.as_str().starts_with("test_");
        blocks.push(FunctionBlock {
            name: name.as_str().to_string(),
            params,
            start_line: start + 1,
            line_count: end.saturating_sub(start) + 1,
            body,
            is_public,
            is_test,
        });
    }

    blocks
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

fn count_parameters(params: &str) -> usize {
    params
        .split(',')
        .map(str::trim)
        .filter(|param| {
            !param.is_empty() && *param != "self" && *param != "&self" && *param != "&mut self"
        })
        .count()
}

fn has_doc_comment_before(block: &str) -> bool {
    block
        .lines()
        .take_while(|line| !line.contains("fn "))
        .any(|line| line.trim_start().starts_with("///"))
}

fn has_doc_comment_before_line(source: &str, line: usize) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    if line <= 1 {
        return false;
    }
    let mut index = line.saturating_sub(2);
    loop {
        let current = lines.get(index).map(|line| line.trim()).unwrap_or_default();
        if current.starts_with("///") {
            return true;
        }
        if !current.is_empty() && !current.starts_with("#[") {
            return false;
        }
        if index == 0 {
            break;
        }
        index -= 1;
    }
    false
}

fn is_generic_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "process" | "handle" | "do_it" | "run" | "execute" | "manage"
    )
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
    Finding::new(
        rule_id,
        message,
        file.display_path.clone(),
        Some(block.start_line),
        severity,
        pillar,
        Confidence::High,
        Some(block.name.clone()),
        None,
        json!({}),
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

    let pillars: Vec<PillarScore> = by_pillar
        .iter()
        .map(|(pillar, pillar_findings)| {
            let penalty: f64 = pillar_findings
                .iter()
                .map(|finding| severity_penalty(finding.severity))
                .sum();
            PillarScore {
                pillar: *pillar,
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
        entry.1 += severity_penalty(finding.severity);
    }
    let mut top_offenders: Vec<FileScore> = file_counts
        .into_iter()
        .map(|(file_path, (findings, penalty))| FileScore {
            file_path,
            score: (100.0 - penalty).max(0.0),
            findings,
        })
        .collect();
    top_offenders.sort_by(|left, right| left.score.total_cmp(&right.score));
    top_offenders.truncate(10);

    ScoreReport {
        composite,
        grade: grade(composite),
        pillars,
        top_offenders,
    }
}

fn severity_penalty(severity: Severity) -> f64 {
    match severity {
        Severity::Advisory => 1.5,
        Severity::Warning => 4.0,
        Severity::Error => 8.0,
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

fn render_report(report: &AnalysisReport, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).expect("report serializes"),
        OutputFormat::Html => render_html(report),
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

fn render_html(report: &AnalysisReport) -> String {
    let findings = report
        .findings
        .iter()
        .take(250)
        .map(|finding| {
            format!(
                "<li><strong>{}</strong> <code>{}</code>:{}<br>{}</li>",
                html_escape(&finding.rule_id),
                html_escape(&finding.file_path),
                finding.line.unwrap_or(1),
                html_escape(&finding.message)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let pillars = report
        .score
        .pillars
        .iter()
        .map(|pillar| {
            format!(
                "<tr><td>{:?}</td><td>{:.1}</td><td>{}</td></tr>",
                pillar.pillar, pillar.score, pillar.findings
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gruff-rs report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 0; color: #172026; background: #f7f8fa; }}
    header {{ background: #172026; color: white; padding: 24px; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 24px; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
    .stat, section {{ background: white; border: 1px solid #d9e0e7; border-radius: 8px; padding: 16px; }}
    code {{ background: #eef2f6; padding: 1px 4px; border-radius: 4px; }}
    li {{ margin: 0 0 12px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td, th {{ border-bottom: 1px solid #e5e9ef; padding: 8px; text-align: left; }}
  </style>
</head>
<body>
  <header>
    <h1>gruff-rs</h1>
    <p>Score {score:.1} ({grade}) · {total} findings · {files} files</p>
  </header>
  <main>
    <div class="stats">
      <div class="stat"><strong>{advisory}</strong><br>Advisory</div>
      <div class="stat"><strong>{warning}</strong><br>Warning</div>
      <div class="stat"><strong>{error}</strong><br>Error</div>
      <div class="stat"><strong>{files}</strong><br>Files</div>
    </div>
    <section>
      <h2>Pillars</h2>
      <table><thead><tr><th>Pillar</th><th>Score</th><th>Findings</th></tr></thead><tbody>{pillars}</tbody></table>
    </section>
    <section>
      <h2>Findings</h2>
      <ol>{findings}</ol>
    </section>
  </main>
</body>
</html>"#,
        score = report.score.composite,
        grade = report.score.grade,
        total = report.summary.total,
        files = report.paths.analysed_files,
        advisory = report.summary.advisory,
        warning = report.summary.warning,
        error = report.summary.error,
        pillars = pillars,
        findings = findings
    )
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

fn exit_for(report: &AnalysisReport, fail_on: FailThreshold) -> ExitCode {
    if !report.diagnostics.is_empty() {
        return ExitCode::from(2);
    }
    if report
        .findings
        .iter()
        .any(|finding| fail_on.triggered_by(finding.severity))
    {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
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

    match path {
        "/health" => respond(&mut stream, "200 OK", "text/plain; charset=utf-8", "ok"),
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
            let previous_dir = std::env::current_dir().ok();
            if std::env::set_current_dir(&root).is_err() {
                respond(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain; charset=utf-8",
                    "invalid projectRoot",
                );
                return;
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
            let body = run_analysis(&options)
                .map(|report| dashboard_shell(&report, &root))
                .unwrap_or_else(|error| format!("<pre>{}</pre>", html_escape(&error)));
            if let Some(previous_dir) = previous_dir {
                let _ = std::env::set_current_dir(previous_dir);
            }
            respond(&mut stream, "200 OK", "text/html; charset=utf-8", &body);
        }
        "/" => respond(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            &dashboard_index(default_root),
        ),
        _ => respond(
            &mut stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found",
        ),
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

fn dashboard_shell(report: &AnalysisReport, root: &Path) -> String {
    let report_html = render_html(report);
    report_html.replace(
        "<main>",
        &format!(
            r#"<main><section><strong>Dashboard scan</strong><br>Project: <code>{}</code><br><a href="/">Change target</a></section>"#,
            html_escape(&root.display().to_string())
        ),
    )
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
    use tempfile::tempdir;

    #[test]
    fn analysis_finds_core_rust_smells() {
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
        let previous = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(dir.path()).expect("set cwd");

        let report = run_analysis(&AnalysisOptions {
            paths: vec![PathBuf::from(".")],
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
        })
        .expect("analysis succeeds");
        std::env::set_current_dir(previous).expect("restore cwd");

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
