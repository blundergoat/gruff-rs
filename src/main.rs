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
use std::time::Instant;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{FnArg, ImplItem, Item, ReturnType, Type, Visibility};

mod analyse_project;
mod analysis;
mod baseline;
mod cli;
mod command_setup;
mod config;
mod config_loader;
mod dashboard;
mod diff;
mod discovery;
mod html_report;
mod init;
mod parser;
mod project;
mod render;
mod report;
mod rules;
mod rules_detail;
mod scoring;
mod source;
mod summary;

pub(crate) use parser::{
    byte_line_from_starts, extract_rust_comments, line_starts, rust_code_reference_source,
    static_regex, strip_rust_comments_after_string_mask, strip_rust_string_literals, RustComment,
};
#[cfg(test)]
pub(crate) use project::read_and_parse_sources;
pub(crate) use project::{
    build_project_context, has_cfg_test_attr, has_test_attr, is_test_module, line_from_span,
};

pub(crate) use analyse_project::analyse_project;
#[cfg(test)]
use analysis::apply_report_exclusions;
pub(crate) use analysis::run_analysis_in_project;
#[cfg(test)]
pub(crate) use baseline::write_baseline;
pub(crate) use baseline::{
    record_history, resolve_baseline, rule_deltas_from_counts, BaselineResolution,
};
use cli::{
    AnalyseArgs, Cli, Commands, CompletionArgs, DashboardArgs, FailThreshold, ListRulesArgs,
    OutputFormat, OutputWriter, ReportArgs, ReportFormat, RuleListFormat, RunOutcome, SummaryArgs,
    SummaryFormat,
};
#[cfg(test)]
use command_setup::resolve_fail_on;
use command_setup::{emit_report_output, resolve_command_setup, resolve_project_root_and_config};
use config::{
    compile_path_matchers, AnalysisOptions, Config, CustomRule, CustomRuleScope, DiffSelection,
    ExclusionRule, ListedRule, PathMatcher, RequestedScope, RuleSetting, SelectorSet,
    SCHEMA_VERSION,
};
#[cfg(test)]
use config_loader::expand_rule_selector;
use config_loader::{expand_rule_selector_with_custom, load_config};
#[cfg(test)]
pub(crate) use dashboard::dashboard_response;
use dashboard::run_dashboard;
use diff::{apply_diff_patch_filter, normalize_report_path, parse_unified_diff, read_diff_patch};
use discovery::{discover_sources, DiscoveryResult};
pub(crate) use render::html_escape;
use render::render_report_with_scope;
#[cfg(test)]
pub(crate) use render::{
    render_report, sarif_physical_location_from_parts, sarif_uri, total_suppressed_findings,
};
use report::{
    pillar_label, AnalysisReport, BaselineData, BaselineEntry, BaselineReport, Confidence,
    FileScore, Finding, FindingDescriptor, PathSummary, Pillar, PillarScore, ReportSuppressions,
    RuleDelta, RunDiagnostic, RunInfo, ScoreReport, Severity, Summary, SuppressedFinding,
    SuppressionSummary, ToolInfo, SCORE_PILLARS,
};
pub(crate) use scoring::{grade, score_report, summarize};
use source::{
    CallNameSummary, DependencySummary, ItemSummary, LockedPackageSummary, LockfileSummary,
    ManifestSummary, ModuleSummary, ParsedSource, ProjectContext, ProjectItemContext,
    RustSourceSummary, SourceFile, SourceUnit,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_BASELINE: &str = "gruff-baseline.json";
const DEFAULT_CONFIG_FILES: &[&str] = &[".gruff-rs.yaml"];

#[derive(Clone)]
struct FunctionBlock {
    name: String,
    param_count: usize,
    start_line: usize,
    line_count: usize,
    body: String,
    is_externally_public: bool,
    is_test: bool,
    test_context: bool,
    is_async: bool,
    returns_bool: bool,
    returns_result: bool,
    ignore_without_reason: bool,
    body_is_declarative_literal: bool,
}

impl FunctionBlock {
    pub(crate) fn is_test_context(&self) -> bool {
        self.is_test || self.test_context
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let global = cli.global;
    let writer = global.writer();
    let no_interaction = global.is_non_interactive();
    let project_root = std::env::current_dir().ok();
    let root = project_root.as_deref();
    match cli.command {
        Commands::Analyse(args) => run_analyse_command(args, writer, root, no_interaction),
        Commands::Report(args) => {
            init::prompt_for_command(root, args.config.as_deref(), args.no_config, no_interaction);
            run_report(args, writer)
        }
        Commands::ListRules(args) => run_list_rules(args, writer),
        Commands::Dashboard(args) => {
            init::prompt_for_command(
                Some(args.project_root.as_path()),
                None,
                false,
                no_interaction,
            );
            run_dashboard(args)
        }
        Commands::Summary(args) => {
            init::prompt_for_command(root, args.config.as_deref(), args.no_config, no_interaction);
            run_summary(args, writer)
        }
        Commands::Completion(args) => run_completion(args, writer),
        Commands::Init(args) => init::run_init(args, writer),
    }
}

fn run_analyse_command(
    args: AnalyseArgs,
    writer: OutputWriter,
    project_root: Option<&Path>,
    no_interaction: bool,
) -> ExitCode {
    init::prompt_for_command(
        project_root,
        args.config.as_deref(),
        args.no_config,
        no_interaction,
    );
    let cli_fail_on = args.fail_on;
    let base = options_from_analyse(args, FailThreshold::Advisory);
    let (project_root, options, config) =
        match resolve_command_setup(base, cli_fail_on, "analyse", FailThreshold::Advisory) {
            Ok(triple) => triple,
            Err(error) => {
                eprintln!("gruff-rs: {error}");
                return ExitCode::from(2);
            }
        };
    let scope = RequestedScope::from_options(&options);
    let started = Instant::now();
    match run_analysis_in_project(&project_root, &options, &config) {
        Ok(report) => {
            let duration_ms = Some(started.elapsed().as_millis());
            let outcome = RunOutcome::classify(&report, options.fail_on);
            let rendered = render_report_with_scope(&report, &scope, options.format, duration_ms);
            writer.emit(outcome, &rendered);
            outcome.exit_code()
        }
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            ExitCode::from(2)
        }
    }
}

fn options_from_analyse(args: AnalyseArgs, fail_on: FailThreshold) -> AnalysisOptions {
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
        fail_on,
        include_ignored: args.include_ignored,
        diff,
        history_file: args.history_file,
        baseline: args.baseline,
        generate_baseline: args.generate_baseline,
        no_baseline: args.no_baseline,
    }
}

fn options_from_report(args: &ReportArgs, fail_on: FailThreshold) -> AnalysisOptions {
    let format = match args.format {
        ReportFormat::Html => OutputFormat::Html,
        ReportFormat::Json => OutputFormat::Json,
    };
    AnalysisOptions {
        paths: args.paths.clone(),
        config: args.config.clone(),
        no_config: args.no_config,
        format,
        fail_on,
        include_ignored: args.include_ignored,
        diff: None,
        history_file: None,
        baseline: None,
        generate_baseline: None,
        no_baseline: args.no_baseline,
    }
}

fn run_report(args: ReportArgs, writer: OutputWriter) -> ExitCode {
    let cli_fail_on = args.fail_on;
    let output = args.output.clone();
    let base = options_from_report(&args, FailThreshold::None);
    let (project_root, options, config) =
        match resolve_command_setup(base, cli_fail_on, "report", FailThreshold::None) {
            Ok(triple) => triple,
            Err(error) => {
                eprintln!("gruff-rs: {error}");
                return ExitCode::from(2);
            }
        };
    let scope = RequestedScope::from_options(&options);
    let started = Instant::now();
    match run_analysis_in_project(&project_root, &options, &config) {
        Ok(report) => {
            let duration_ms = Some(started.elapsed().as_millis());
            let outcome = RunOutcome::classify(&report, options.fail_on);
            let rendered = render_report_with_scope(&report, &scope, options.format, duration_ms);
            match emit_report_output(writer, output, outcome, &rendered) {
                Ok(()) => outcome.exit_code(),
                Err(error) => {
                    eprintln!("gruff-rs: {error}");
                    ExitCode::from(2)
                }
            }
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
    if let Some(rule_id) = &args.rule_id {
        return rules_detail::render_rule_detail(
            rule_id,
            &registry,
            &config.custom_rules,
            args.format,
        );
    }
    if let Some(selector) = &args.selector {
        return render_selector_output(selector, &registry, &config.custom_rules, args.format);
    }
    let rules = listed_rules(&registry, &config.custom_rules);
    Ok(format_listed_rules(&rules, args.format))
}

fn render_selector_output(
    selector: &str,
    registry: &rules::RuleRegistry,
    custom_rules: &[CustomRule],
    format: RuleListFormat,
) -> Result<String, String> {
    let ids =
        expand_rule_selector_with_custom(selector, registry, custom_rules, "rules --selector")?;
    Ok(match format {
        RuleListFormat::Json => serde_json::to_string_pretty(&ids).expect("rules serialize"),
        RuleListFormat::Text => ids.into_iter().collect::<Vec<_>>().join("\n"),
    })
}

fn format_listed_rules(rules: &[ListedRule], format: RuleListFormat) -> String {
    match format {
        RuleListFormat::Json => serde_json::to_string_pretty(rules).expect("rules serialize"),
        RuleListFormat::Text => render_listed_rules_text(rules),
    }
}

fn render_listed_rules_text(rules: &[ListedRule]) -> String {
    let mut out = String::new();
    for rule in rules {
        out.push_str(&format!(
            "{} [{}] {:?} {:?} - {}\n",
            rule.id, rule.tier, rule.pillar, rule.default_severity, rule.description
        ));
    }
    out.trim_end_matches('\n').to_string()
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

pub(crate) fn listed_builtin_rule(definition: &rules::RuleDefinition) -> ListedRule {
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

pub(crate) fn listed_custom_rule(rule: &CustomRule) -> ListedRule {
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
    let (project_root, config) = match resolve_project_root_and_config(&options) {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            return ExitCode::from(2);
        }
    };

    let started = Instant::now();
    match run_analysis_in_project(&project_root, &options, &config) {
        Ok(report) => {
            let duration_ms = started.elapsed().as_millis();
            let outcome = RunOutcome::classify(&report, FailThreshold::None);
            let rendered = summary::render(&report, args.top, args.format, duration_ms);
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
    if writer.is_silent() {
        return ExitCode::SUCCESS;
    }
    let mut command = Cli::command();
    let bin_name = command.get_name().to_string();
    clap_complete::generate(args.shell, &mut command, bin_name, &mut std::io::stdout());
    ExitCode::SUCCESS
}

pub(crate) fn analyse_source(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    let mut findings = built_in_rules::analyse(unit, config);
    findings.extend(custom_rules::analyse(unit, config));
    findings
}

mod built_in_rules;

mod custom_rules;

pub(crate) fn changed_files(mode: &str) -> Result<BTreeSet<String>, String> {
    let mut command = std::process::Command::new("git");
    command.arg("diff").arg("--name-only").arg("-z");
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
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).replace('\\', "/"))
        .collect())
}

pub(crate) fn absolutize(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

pub(crate) fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string()
}

#[cfg(test)]
mod tests;
