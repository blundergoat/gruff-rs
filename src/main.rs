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

mod cli;
mod config;
mod config_loader;
mod dashboard;
mod discovery;
mod html_report;
mod parser;
mod render;
mod report;
mod rules;
mod source;
mod summary;

pub(crate) use parser::{
    byte_line_from_starts, extract_rust_comments, line_starts, static_regex,
    strip_rust_comments_after_string_mask, strip_rust_string_literals, RustComment,
};

use cli::{
    AnalyseArgs, Cli, Commands, CompletionArgs, DashboardArgs, FailThreshold, ListRulesArgs,
    OutputFormat, OutputWriter, ReportArgs, ReportFormat, RuleListFormat, RunOutcome, SummaryArgs,
    SummaryFormat,
};
use config::{
    AnalysisOptions, Config, CustomRule, CustomRuleScope, DiffSelection, ExclusionRule, ListedRule,
    RequestedScope, RuleSetting, SelectorSet,
};
use discovery::{discover_sources, DiscoveryResult};
#[cfg(test)]
pub(crate) use dashboard::dashboard_response;
use dashboard::run_dashboard;
pub(crate) use render::html_escape;
use render::render_report_with_scope;
#[cfg(test)]
pub(crate) use render::{
    render_report, sarif_physical_location_from_parts, sarif_uri, total_suppressed_findings,
};
use report::{
    AnalysisReport, BaselineData, BaselineEntry, BaselineReport, Confidence, FileScore, Finding,
    PathSummary, Pillar, PillarScore, ReportSuppressions, RunDiagnostic, RunInfo, ScoreReport,
    Severity, Summary, SuppressedFinding, SuppressionSummary, ToolInfo, SCORE_PILLARS,
};
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
    if writer.is_silent() {
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
        findings.extend(analyse_source(&parsed_source.as_source_unit(), config));
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
            externally_public: visibility_is_externally_public(&item_fn.vis),
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
            externally_public: visibility_is_externally_public(&item_struct.vis),
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
            externally_public: visibility_is_externally_public(&item_enum.vis),
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
            externally_public: visibility_is_externally_public(&item_trait.vis),
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
            externally_public: visibility_is_externally_public(&method.vis),
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
        externally_public: context.externally_public,
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
    let line_offsets = line_starts(source);
    for capture in call_name_regex.captures_iter(source) {
        let Some(name) = capture.get(1) else {
            continue;
        };
        if !is_call_name_candidate(name.as_str()) {
            continue;
        }
        push_call_name(file, source.len(), &line_offsets, name, call_names);
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

fn visibility_is_public(visibility: &Visibility) -> bool {
    !matches!(visibility, Visibility::Inherited)
}

/// Returns true only for unrestricted `pub` items. `pub(crate)`, `pub(super)`,
/// and `pub(in path)` are reachable inside the crate but not part of the
/// external API surface, so the reportable public-API rules
/// (`modernisation.public-field`, `docs.missing-public-doc`,
/// `error-handling.public-unwrap`, `architecture.public-api-surface`) use this
/// stricter helper. Dead-code reachability and project-model indexing keep
/// using the lenient `visibility_is_public` above.
fn visibility_is_externally_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
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
        item.externally_public && !item.cfg_gated && !item.test_context && item.kind != "method"
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

mod built_in_rules;

mod custom_rules;

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
