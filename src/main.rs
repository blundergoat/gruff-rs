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
use syn::visit::Visit;
use syn::{FnArg, ImplItem, Item, ReturnType, Type, Visibility};

mod analyse_project;
mod analysis;
mod cli;
mod config;
mod config_loader;
mod dashboard;
mod diff;
mod discovery;
mod html_report;
mod parser;
mod project;
mod render;
mod report;
mod rules;
mod scoring;
mod source;
mod summary;

pub(crate) use parser::{
    byte_line_from_starts, extract_rust_comments, line_starts, static_regex,
    strip_rust_comments_after_string_mask, strip_rust_string_literals, RustComment,
};
pub(crate) use project::{
    build_project_context, has_cfg_test_attr, has_test_attr, is_test_module, line_from_span,
    read_and_parse_sources,
};

pub(crate) use analyse_project::analyse_project;
#[cfg(test)]
use analysis::apply_report_exclusions;
use analysis::run_analysis;
pub(crate) use analysis::run_analysis_in_project;
use cli::{
    AnalyseArgs, Cli, Commands, CompletionArgs, DashboardArgs, FailThreshold, ListRulesArgs,
    OutputFormat, OutputWriter, ReportArgs, ReportFormat, RuleListFormat, RunOutcome, SummaryArgs,
    SummaryFormat,
};
use config::{
    AnalysisOptions, Config, CustomRule, CustomRuleScope, DiffSelection, ExclusionRule, ListedRule,
    RequestedScope, RuleSetting, SelectorSet,
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
    AnalysisReport, BaselineData, BaselineEntry, BaselineReport, Confidence, FileScore, Finding,
    FindingDescriptor, PathSummary, Pillar, PillarScore, ReportSuppressions, RunDiagnostic,
    RunInfo, ScoreReport, Severity, Summary, SuppressedFinding, SuppressionSummary, ToolInfo,
    SCORE_PILLARS,
};
pub(crate) use scoring::{grade, score_report, summarize};
use source::{
    CallNameSummary, DependencySummary, ItemSummary, LockedPackageSummary, LockfileSummary,
    ManifestSummary, ModuleSummary, ParsedSource, ProjectContext, ProjectItemContext,
    RustSourceSummary, SourceFile, SourceUnit,
};

const VERSION: &str = "0.1.0-dev";
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
    let global = cli.global;
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
    if writer.is_silent() {
        return ExitCode::SUCCESS;
    }
    let mut command = Cli::command();
    let bin_name = command.get_name().to_string();
    clap_complete::generate(args.shell, &mut command, bin_name, &mut std::io::stdout());
    ExitCode::SUCCESS
}

fn analyse_source(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    let mut findings = built_in_rules::analyse(unit, config);
    findings.extend(custom_rules::analyse(unit, config));
    findings
}

mod built_in_rules;

mod custom_rules;

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
mod tests;
