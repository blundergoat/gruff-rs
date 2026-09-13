//! Gruff's CLI entry point assembles commands, analysis services, and report output.
//! Users reach this crate through a subcommand, which routes source discovery and
//! rule findings into deterministic renderers and process-exit classification.

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
use std::os::unix::fs::MetadataExt;
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
mod baseline_file;
mod baseline_identity;
mod changed_region;
mod check_ignore;
mod cli;
mod command_setup;
mod config;
mod config_loader;
mod dashboard;
mod diff;
mod discovery;
mod gate;
mod hook;
mod html_report;
mod ignore_policy;
mod init;
mod machine_contract;
mod migrate_config;
mod parser;
mod project;
mod render;
mod report;
mod report_identity;
mod rules;
mod rules_detail;
mod scoring;
mod selectors;
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
#[cfg(test)]
pub(crate) use analysis::project_coverage_for_test;
pub(crate) use analysis::{apply_gate_diagnostic, run_analysis_in_project};
#[cfg(test)]
pub(crate) use baseline::write_baseline;
#[cfg(test)]
pub(crate) use baseline::{apply_baseline, migrate_baseline};
pub(crate) use baseline::{
    record_history, resolve_baseline, rule_deltas_from_counts, BaselineCollision,
    BaselineResolution,
};
use baseline_file::{BaselineData, BaselineEntry, SensitiveCounts, SensitiveSummary};
#[cfg(test)]
pub(crate) use baseline_identity::{compute_identity_for, normalise_measured_values};
pub(crate) use baseline_identity::{
    declaration_position_by_line, declaration_position_from_blocks, finding_identities,
    FindingIdentity, TOOL_LANGUAGE,
};
use changed_region::{
    apply_diff_file_selection, patch_intersects_finding_with_scope, resolve_diff_filter,
    ChangedScope, ResolvedDiffFilter,
};
use check_ignore::run_check_ignore;
use cli::{
    AnalyseArgs, CheckIgnoreArgs, CheckIgnoreFormat, Cli, Commands, CompletionArgs, DashboardArgs,
    FailThreshold, ListRulesArgs, OutputFormat, OutputWriter, ReportArgs, ReportFormat,
    RuleListFormat, RunOutcome, SummaryArgs, SummaryFormat,
};
#[cfg(test)]
use command_setup::resolve_fail_on;
use command_setup::{emit_report_output, resolve_command_setup, resolve_project_root_and_config};
use config::{
    compile_path_matchers, AnalysisOptions, Config, CustomRule, CustomRuleScope, DeepScanBudget,
    DeepScanBudgetOverride, DiffSelection, ExclusionRule, ListedRule, PathMatcher, RequestedScope,
    RuleSetting, SelectorSet, SCHEMA_VERSION,
};
#[cfg(test)]
use config_loader::expand_rule_selector;
use config_loader::{
    expand_rule_selector_with_custom, load_config, load_config_for, SensitiveExclusionRule,
};
#[cfg(test)]
pub(crate) use dashboard::dashboard_response;
use dashboard::run_dashboard;
#[cfg(test)]
use diff::apply_diff_patch_filter;
use diff::{
    apply_changed_region_filter, normalize_report_path, parse_unified_diff,
    patch_intersects_finding, patch_range_intersects, read_diff_patch, summarize_changed_findings,
    DiffPatchLineMap,
};
use discovery::{classify_ignored_path, discover_sources, DiscoveryResult};
use gate::{Gate, GateOnMatch, GateScope};
use ignore_policy::{IgnoreSource, IgnoredPath};
pub(crate) use machine_contract::{MachineDiffContext, MachineReportContext};
use render::render_report_with_scope;
pub(crate) use render::{html_escape, render_text_suppressions};
#[cfg(test)]
pub(crate) use render::{
    render_report, sarif_physical_location_from_parts, sarif_uri, total_suppressed_findings,
};
use report::{
    pillar_label, AnalysisReport, BaselineReport, Confidence, FileScore, Finding,
    FindingDescriptor, PathSummary, Pillar, PillarScore, ReportSuppressions, RuleDelta,
    RunDiagnostic, RunInfo, ScoreReport, Severity, Summary, SuppressedFinding, SuppressionSummary,
    ToolInfo, SCORE_PILLARS,
};
use report_identity::FindingScope;
pub(crate) use scoring::{
    grade, render_composite_block, score_report, summarize, RuleWeight, ScoreCluster,
};
use selectors::{DisplaySelectors, ExecutionSelectors};
use source::{
    CallNameSummary, DependencySummary, ItemSummary, LockedPackageSummary, LockfileSummary,
    ManifestSummary, ModuleSummary, ParsedSource, ProjectContext, ProjectCoverage,
    ProjectItemContext, RustSourceSummary, SourceFile, SourceOrigin, SourceUnit,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_BASELINE: &str = "gruff-baseline.json";
const DEFAULT_CONFIG_FILES: &[&str] = &[".gruff-rs.yaml"];

fn main() -> ExitCode {
    let cli = Cli::parse();
    let global = cli.global;
    let writer = global.writer();
    let no_interaction = global.is_non_interactive();
    let project_root = std::env::current_dir().ok();
    let root = project_root.as_deref();
    match cli.command {
        Commands::Analyse(args) => run_analyse_command(*args, writer, root, no_interaction),
        Commands::Hook(args) => hook::run_hook_command(args, writer),
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
        Commands::CheckIgnore(args) => run_check_ignore(args, global.verbose > 0, writer),
        Commands::Completion(args) => run_completion(args, writer),
        Commands::Init(args) => init::run_init(args, writer),
        Commands::MigrateConfig(args) => migrate_config::run_migrate_config(args, &writer),
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
    let fail_on_new = args.fail_on_new;
    let deep_scan_budget = args.deep_scan_budget.clone();
    let base = options_from_analyse(args, FailThreshold::Advisory);
    let (project_root, options, config) = match resolve_command_setup(
        base,
        cli_fail_on,
        "analyse",
        FailThreshold::Advisory,
        deep_scan_budget.as_ref(),
    ) {
        Ok(triple) => triple,
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            return ExitCode::from(2);
        }
    };
    // The execution selectors choose which rules run, so they narrow the config before anything is scanned.
    let config = analyse_run_config(config, &options, fail_on_new);
    let scope = RequestedScope::from_options(&options);
    let started = Instant::now();
    match run_analysis_in_project(&project_root, &options, &config) {
        Ok(mut report) => emit_analyse_report(
            &mut report,
            &options,
            &config,
            &scope,
            Some(started.elapsed().as_millis()),
            &writer,
        ),
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            ExitCode::from(2)
        }
    }
}

/// Score the run, decide its exit code, then narrow what the report shows and render it.
///
/// The order matters: the score and the exit code are decided by what actually ran, and only then does the
/// presentation filter hide anything, which is what keeps a hidden finding counted.
fn emit_analyse_report(
    report: &mut AnalysisReport,
    options: &AnalysisOptions,
    config: &Config,
    scope: &RequestedScope,
    duration_ms: Option<u128>,
    writer: &OutputWriter,
) -> ExitCode {
    apply_gate_diagnostic(report, config.gate.as_ref());
    let outcome = RunOutcome::classify(report, options.fail_on, config.gate.as_ref());
    report.machine_context.exit_code = outcome.numeric_code();
    apply_display_selectors(report, &options.display, config.display_floor);
    let rendered = render_report_with_scope(report, scope, options.format, duration_ms);
    writer.emit(outcome, &rendered);
    outcome.exit_code()
}

/// Narrow the config to what this run executes, folding in `--fail-on-new` before the selectors.
fn analyse_run_config(mut config: Config, options: &AnalysisOptions, fail_on_new: bool) -> Config {
    if fail_on_new {
        apply_fail_on_new(&mut config);
    }
    config.with_execution_selectors(&options.execution)
}

/// Hide from the report every finding the user's presentation selectors exclude.
///
/// The score, the counts and the exit code are already decided by the time this runs, which is what makes these
/// filters presentation: a hidden finding still counted.
fn apply_display_selectors(
    report: &mut AnalysisReport,
    selectors: &DisplaySelectors,
    configured_floor: Option<Severity>,
) {
    // The flag wins over the project's configured floor, because typing it is the user overriding their own default.
    let effective = DisplaySelectors {
        min_severity: selectors.min_severity.or(configured_floor),
        ..selectors.clone()
    };

    if !effective.is_requested() {
        return;
    }

    report.findings.retain(|finding| effective.allows(finding));
}

/// Fold the `--fail-on-new` flag into the gate as `scope: new` with a default
/// `error: 0` cap (ADR-003 baseline-aware gate-scope addendum). An existing `gate:`
/// block keeps its other caps but is forced to fail-on-match: the flag is named and
/// documented to *fail* on new findings, so it overrides a prior `onMatch: warn`. The
/// missing-baseline precondition is enforced later by `Gate::scope_precondition_error`
/// during analysis (a config error, exit 2).
pub(crate) fn apply_fail_on_new(config: &mut Config) {
    let gate = config.gate.get_or_insert_with(Gate::default);
    gate.scope = GateScope::New;
    gate.on_match = GateOnMatch::Fail;
    if gate.error.is_none() {
        gate.error = Some(0);
    }
}

fn options_from_analyse(args: AnalyseArgs, fail_on: FailThreshold) -> AnalysisOptions {
    let execution = execution_selectors_from(&args);
    let display = display_selectors_from(&args);
    let diff = match (args.changed_ranges, args.since, args.diff_patch, args.diff) {
        (Some(ranges), None, None, None) => Some(DiffSelection::ExplicitRanges {
            ranges,
            scope: args.changed_scope,
        }),
        (None, Some(base), None, None) => Some(DiffSelection::Git {
            mode: base,
            scope: args.changed_scope,
        }),
        (None, None, Some(path), None) => Some(DiffSelection::Patch {
            path,
            scope: args.changed_scope,
        }),
        (None, None, None, Some(mode)) if mode == "-" => Some(DiffSelection::Patch {
            path: PathBuf::from("-"),
            scope: args.changed_scope,
        }),
        (None, None, None, Some(mode)) => Some(DiffSelection::Git {
            mode,
            scope: args.changed_scope,
        }),
        (None, None, None, None) => None,
        _ => unreachable!("clap prevents multiple changed-region selectors"),
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
        migrate_baseline: args.migrate_baseline,
        force_baseline_overwrite: args.force,
        no_baseline: args.no_baseline,
        execution,
        display,
    }
}

/// Collect the four flags that decide which rules run, so the score moves with them.
fn execution_selectors_from(args: &AnalyseArgs) -> ExecutionSelectors {
    ExecutionSelectors {
        include_rules: args.include_rule.clone(),
        exclude_rules: args.exclude_rule.clone(),
        include_pillars: args.include_pillar.clone(),
        exclude_pillars: args.exclude_pillar.clone(),
    }
}

/// Collect the five flags that decide what the report shows, none of which changes execution or the score.
fn display_selectors_from(args: &AnalyseArgs) -> DisplaySelectors {
    DisplaySelectors {
        min_severity: args.min_severity,
        show_rules: args.show_rule.clone(),
        hide_rules: args.hide_rule.clone(),
        show_pillars: args.show_pillar.clone(),
        hide_pillars: args.hide_pillar.clone(),
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
        migrate_baseline: None,
        force_baseline_overwrite: false,
        no_baseline: args.no_baseline,
        execution: ExecutionSelectors::default(),
        display: DisplaySelectors::default(),
    }
}

fn run_report(args: ReportArgs, writer: OutputWriter) -> ExitCode {
    let cli_fail_on = args.fail_on;
    let output = args.output.clone();
    let deep_scan_budget = args.deep_scan_budget.clone();
    let base = options_from_report(&args, FailThreshold::None);
    let (project_root, options, config) = match resolve_command_setup(
        base,
        cli_fail_on,
        "report",
        FailThreshold::None,
        deep_scan_budget.as_ref(),
    ) {
        Ok(triple) => triple,
        Err(error) => {
            eprintln!("gruff-rs: {error}");
            return ExitCode::from(2);
        }
    };
    let scope = RequestedScope::from_options(&options);
    let started = Instant::now();
    match run_analysis_in_project(&project_root, &options, &config) {
        Ok(mut report) => {
            let duration_ms = Some(started.elapsed().as_millis());
            apply_gate_diagnostic(&mut report, config.gate.as_ref());
            let outcome = RunOutcome::classify(&report, options.fail_on, config.gate.as_ref());
            report.machine_context.exit_code = outcome.numeric_code();
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

/// The catalogue envelope every port publishes: an object carrying the rules under `rules`.
#[derive(Serialize)]
struct RuleListing<'a> {
    rules: &'a [ListedRule],
}

fn format_listed_rules(rules: &[ListedRule], format: RuleListFormat) -> String {
    match format {
        RuleListFormat::Json => {
            serde_json::to_string_pretty(&RuleListing { rules }).expect("rules serialize")
        }
        RuleListFormat::Text => render_listed_rules_text(rules),
    }
}

/// Knob names gruff-go already publishes for a single-threshold rule, keyed by rule id. The
/// family listing shape (M09, ratified 2026-09-09) carries every threshold as a named map; a rule
/// whose id has no knob name anywhere in the family publishes the one-key map `{"threshold": N}`
/// so no new permanent public identifier is invented.
const LISTING_THRESHOLD_KNOB_NAMES: &[(&str, &str)] = &[
    ("complexity.cognitive", "maxComplexity"),
    ("complexity.cyclomatic", "maxComplexity"),
    ("complexity.nesting-depth", "maxDepth"),
    ("size.file-length", "maxLines"),
    ("size.function-length", "maxLines"),
    ("size.parameter-count", "maxParameters"),
];

/// Project a built-in rule's default threshold into the family listing map. An integral default
/// prints as an integer (`25`, not `25.0`) so a typed consumer reads one number shape across ports.
fn listing_thresholds(definition: &rules::RuleDefinition) -> Option<Map<String, Value>> {
    let threshold = definition.threshold?;
    let knob = LISTING_THRESHOLD_KNOB_NAMES
        .iter()
        .find(|(rule_id, _)| *rule_id == definition.id)
        .map_or("threshold", |(_, knob)| knob);
    let value = if threshold.default.fract() == 0.0 {
        json!(threshold.default as i64)
    } else {
        json!(threshold.default)
    };
    let mut thresholds = Map::new();
    thresholds.insert(knob.to_string(), value);
    Some(thresholds)
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
            migrate_baseline: None,
            force_baseline_overwrite: false,
            no_baseline: true,
            execution: ExecutionSelectors::default(),
            display: DisplaySelectors::default(),
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
        thresholds: listing_thresholds(definition),
        options: definition.options.to_vec(),
        default_enabled: definition.default_enabled,
        description: definition.description.to_string(),
        false_positive_shapes: definition.false_positive_shapes.to_vec(),
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
        thresholds: None,
        options: Vec::new(),
        default_enabled: true,
        description: rule.message.clone(),
        false_positive_shapes: Vec::new(),
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
    let deep_scan_budget = args.deep_scan_budget.clone();
    let output_format = match args.format {
        SummaryFormat::Text => OutputFormat::Text,
        SummaryFormat::Json => OutputFormat::Json,
    };
    let options = AnalysisOptions {
        paths: args.paths,
        config: args.config,
        no_config: args.no_config,
        format: output_format,
        fail_on: FailThreshold::None,
        include_ignored: args.include_ignored,
        diff: None,
        history_file: None,
        baseline: None,
        generate_baseline: None,
        migrate_baseline: None,
        force_baseline_overwrite: false,
        no_baseline: false,
        execution: ExecutionSelectors::default(),
        display: DisplaySelectors::default(),
    };
    let (project_root, options, config) =
        match resolve_project_root_and_config(options, deep_scan_budget.as_ref()) {
            Ok(triple) => triple,
            Err(error) => {
                eprintln!("gruff-rs: {error}");
                return ExitCode::from(2);
            }
        };

    let started = Instant::now();
    match run_analysis_in_project(&project_root, &options, &config) {
        Ok(mut report) => {
            let duration_ms = started.elapsed().as_millis();
            // `summary` is a read-only reporting command: like `--fail-on` (passed as
            // `None` above), the `gate:` block must not change its exit code.
            let outcome = RunOutcome::classify(&report, FailThreshold::None, None);
            report.machine_context.exit_code = outcome.numeric_code();
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

pub(crate) fn analyse_source_with_artifacts(
    unit: &SourceUnit<'_>,
    config: &Config,
    retain_function_blocks: bool,
) -> built_in_rules::SourceAnalysisArtifacts {
    let mut artifacts =
        built_in_rules::analyse_with_artifacts(unit, config, retain_function_blocks);
    artifacts
        .findings
        .extend(custom_rules::analyse(unit, config));
    artifacts
}

mod built_in_rules;
pub(crate) use built_in_rules::FunctionBlock;

mod custom_rules;

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
