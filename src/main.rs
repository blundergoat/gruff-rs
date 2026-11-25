//! Start the requested `gruff-rs` command from a shell or CI job.
//!
//! Scan commands resolve the target and config, run the requested checks, and render the result.
//! The same outcome determines what the caller sees and which exit status their script receives.

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
#[cfg(unix)]
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
mod inline_suppressions;
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
    build_project_context, has_cfg_test_attr, has_export_attr, has_test_attr,
    is_reached_without_rust_reference, is_test_module, line_from_span,
};

pub(crate) use analyse_project::analyse_project;
#[cfg(test)]
use analysis::apply_report_exclusions;
#[cfg(test)]
pub(crate) use analysis::project_coverage_for_test;
pub(crate) use analysis::{apply_gate_diagnostic, failed_run_report, run_analysis_in_project};
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
    finding_identities_with_inventory, is_baseline_eligible, same_named_lines_from_blocks,
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
use command_setup::{
    emit_report_output, resolve_command_setup, resolve_project_root_and_config, RunFailure,
};
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

/// Parse the command line and dispatch to the chosen subcommand's runner.
///
/// The analyse, report, dashboard and summary commands call `init::prompt_for_command` before they run; the other commands start directly.
///
/// Returns the selected subcommand's exit code, which becomes the process exit status.
fn main() -> ExitCode {
    let cli = Cli::parse();
    let global = cli.global;
    let writer = global.writer();
    let no_interaction = global.is_non_interactive();
    let launch_directory = std::env::current_dir().ok();
    let offer_scan_config = |paths: &[PathBuf], config_path: Option<&Path>, no_config| {
        prompt_for_scan_config(
            launch_directory.as_deref(),
            paths,
            config_path,
            no_config,
            no_interaction,
        );
    };
    match cli.command {
        Commands::Analyse(args) => {
            offer_scan_config(&args.paths, args.config.as_deref(), args.no_config);
            run_analyse_command(*args, writer)
        }
        Commands::Hook(args) => hook::run_hook_command(args, writer),
        Commands::Report(args) => {
            offer_scan_config(&args.paths, args.config.as_deref(), args.no_config);
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
            offer_scan_config(&args.paths, args.config.as_deref(), args.no_config);
            run_summary(args, writer)
        }
        Commands::CheckIgnore(args) => run_check_ignore(args, global.verbose > 0, writer),
        Commands::Completion(args) => run_completion(args, writer),
        Commands::Init(args) => init::run_init(args, writer),
        Commands::MigrateConfig(args) => migrate_config::run_migrate_config(args, &writer),
    }
}

/// Run `analyse` and send findings or a setup failure to the selected output format.
///
/// `args` holds the parsed analyse flags, and `writer` is where the report or the failure envelope is written.
///
/// Returns exit code 2 when setup or analysis fails, otherwise the outcome's exit code from the findings, the fail threshold and the gate.
fn run_analyse_command(args: AnalyseArgs, writer: OutputWriter) -> ExitCode {
    let cli_fail_on = args.fail_on;
    let fail_on_new = args.fail_on_new;
    let min_confidence = args.min_confidence;
    let deep_scan_budget = args.deep_scan_budget.clone();
    let requested_options =
        options_from_analyse(args, cli_fail_on.unwrap_or(FailThreshold::Advisory));
    let (project_root, mut options, config) = match analyse_setup(
        requested_options,
        cli_fail_on,
        deep_scan_budget.as_ref(),
        writer,
    ) {
        Ok(triple) => triple,
        Err(code) => return code,
    };
    // Apply flags such as `--include-rule` now so the same selection controls findings and scores.
    let scope = RequestedScope::from_options(&options);
    let config = match analyse_run_config(config, &mut options, fail_on_new) {
        Ok(config) => config,
        // For example, a caller using a retired rule ID gets a config diagnostic instead of an empty scan.
        Err(error) => {
            return emit_failed_run_report(
                &project_root,
                &options,
                &RunFailure::Config(error),
                writer,
                None,
            );
        }
    };
    let started = Instant::now();
    match run_analysis_in_project(&project_root, &options, &config) {
        Ok(mut report) => emit_analyse_report(
            &mut report,
            &options,
            &config,
            &scope,
            Some(started.elapsed().as_millis()),
            &writer,
            min_confidence,
        ),
        // A missing baseline requested by the caller still produces their JSON or SARIF failure report.
        Err(error) => emit_failed_run_report(&project_root, &options, &error, writer, None),
    }
}

/// Offer config setup at the project the caller selected for `analyse`, `report`, or `summary`.
///
/// `caller_root` is the launch directory, if available. Empty `paths` normally select that directory.
/// An explicit `config_path`, `no_config`, or `no_interaction` lets the caller bypass the prompt.
fn prompt_for_scan_config(
    caller_root: Option<&Path>,
    paths: &[PathBuf],
    config_path: Option<&Path>,
    no_config: bool,
    no_interaction: bool,
) {
    // A caller who supplied or disabled config, or is running unattended, gets no interactive setup question.
    if no_interaction || no_config || config_path.is_some() {
        return;
    }
    let project_root = caller_root.and_then(|root| {
        command_setup::resolve_scan_context(root, paths)
            .ok()
            .map(|(root, _)| root)
    });
    init::prompt_for_command(project_root.as_deref(), None, false, false);
}

/// Resolve what `analyse` should scan before checking source files, with a machine report if setup fails.
///
/// `requested_options` holds the parsed flags. An absent `cli_fail_on` or `deep_scan_budget` lets config and defaults supply the value.
/// `writer` receives the failure envelope when setup fails.
/// Returns the resolved project root, options and config, or an Err holding exit code 2 after the failure is reported.
#[allow(clippy::result_large_err)]
fn analyse_setup(
    requested_options: AnalysisOptions,
    cli_fail_on: Option<FailThreshold>,
    deep_scan_budget: Option<&DeepScanBudgetOverride>,
    writer: OutputWriter,
) -> Result<(PathBuf, AnalysisOptions, Config), ExitCode> {
    match resolve_command_setup(
        requested_options.clone(),
        cli_fail_on,
        "analyse",
        FailThreshold::Advisory,
        deep_scan_budget,
    ) {
        Ok(triple) => Ok(triple),
        // For example, a missing `--config` file still yields an exit code and diagnostic in the requested format.
        Err(error) => {
            let (root, options) = failed_setup_context(requested_options);
            Err(emit_failed_run_report(
                &root,
                &options,
                &RunFailure::Config(error),
                writer,
                None,
            ))
        }
    }
}

/// Recover the requested scope for a machine report when configuration could not be loaded.
/// Returns the project and rebased `options`, using the operands as typed if the project could not be resolved.
fn failed_setup_context(mut options: AnalysisOptions) -> (PathBuf, AnalysisOptions) {
    // Keep the caller's intended paths in a failure report when the launch directory and targets are still available.
    if let Ok(caller_root) = std::env::current_dir() {
        // For example, a malformed config need not prevent reporting the directory the caller selected.
        if let Ok((root, paths)) = command_setup::resolve_scan_context(&caller_root, &options.paths)
        {
            options.paths = paths;
            return (root, options);
        }
    }
    (PathBuf::from("."), options)
}

/// Give JSON and SARIF callers a structured failure when a scan cannot start or finish.
/// Human-readable requests get the error on stderr.
///
/// `project_root`, `options` and `error` build the report. With no `output` file, `writer` sends it to stdout.
/// Returns exit code 2 in every case; a format other than JSON or SARIF returns before any envelope is built.
fn emit_failed_run_report(
    project_root: &Path,
    options: &AnalysisOptions,
    error: &RunFailure,
    writer: OutputWriter,
    output: Option<PathBuf>,
) -> ExitCode {
    eprintln!("gruff-rs: {error}");
    // Terminal users already have the error, while automation needs an envelope it can parse.
    if !matches!(options.format, OutputFormat::Json | OutputFormat::Sarif) {
        return ExitCode::from(2);
    }

    let report = failed_run_report(project_root, options, error);
    let scope = RequestedScope::from_options(options);
    let rendered = render_report_with_scope(&report, &scope, options.format, None);
    // If a report path is read-only, explain why report delivery also failed and keep exit status 2.
    if let Err(error) = emit_report_output(writer, output, RunOutcome::DiagnosticsFailed, &rendered)
    {
        eprintln!("gruff-rs: {error}");
    }
    ExitCode::from(2)
}

/// Score the run, decide its exit code, then narrow what the report shows and render it.
///
/// The order matters: the score and the exit code are decided by what actually ran, and only then does the
/// presentation filter hide anything, which is what keeps a hidden finding counted.
///
/// `report` gains the gate diagnostic and exit code, then loses hidden findings; `options` gives the fail threshold, selectors and format.
/// `config` gives the gate and display floor, `scope` and `duration_ms` go to the renderer, and `writer` emits the result.
/// `min_confidence` is the minimum confidence used by the severity threshold.
///
/// Returns the exit code the outcome classified before any finding was hidden.
fn emit_analyse_report(
    report: &mut AnalysisReport,
    options: &AnalysisOptions,
    config: &Config,
    scope: &RequestedScope,
    duration_ms: Option<u128>,
    writer: &OutputWriter,
    min_confidence: Confidence,
) -> ExitCode {
    apply_gate_diagnostic(report, config.gate.as_ref());
    let outcome = RunOutcome::classify_with_confidence(
        report,
        options.fail_on,
        config.gate.as_ref(),
        min_confidence,
    );
    report.machine_context.exit_code = outcome.numeric_code();
    apply_display_selectors(report, &options.display, config.display_floor);
    let rendered = render_report_with_scope(report, scope, options.format, duration_ms);
    writer.emit(outcome, &rendered);
    outcome.exit_code()
}

/// Narrow the config to what this run executes, folding in `--fail-on-new` and validating display and execution selectors.
///
/// `config` is the loaded config to narrow, `options` supplies the execution and display selectors (normalized in place),
/// and `fail_on_new` says whether the flag was given.
/// Returns the narrowed config, whose gate is first forced to new-findings scope when `fail_on_new` is true, or an error on an unknown selector.
fn analyse_run_config(
    mut config: Config,
    options: &mut AnalysisOptions,
    fail_on_new: bool,
) -> Result<Config, String> {
    if fail_on_new {
        apply_fail_on_new(&mut config);
    }
    options.display = options.display.validated(&config)?;
    config.with_execution_selectors(&options.execution)
}

/// Hide from the report every finding the user's presentation selectors exclude.
///
/// The score, the counts and the exit code are already decided by the time this runs, which is what makes these
/// filters presentation: a hidden finding still counted.
///
/// `report` loses the excluded findings, `selectors` are the display flags, and `configured_floor` is the config's display floor, if any.
/// A minimum severity in `selectors` overrides `configured_floor`; no filtering is attempted when neither requests a filter.
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

/// Make `--fail-on-new` act on new findings, with a default cap of zero errors.
/// `config` keeps any existing gate limits and switches to failing on a match. Analysis reports exit 2 when no baseline is available.
pub(crate) fn apply_fail_on_new(config: &mut Config) {
    let gate = config.gate.get_or_insert_with(Gate::default);
    gate.scope = GateScope::New;
    gate.on_match = GateOnMatch::Fail;
    // Callers without an error cap expect a newly introduced error to fail the gate.
    if gate.error.is_none() {
        gate.error = Some(0);
    }
}

/// Map the parsed `analyse` flags onto the analysis options, choosing at most one changed-region selection.
///
/// `args` is consumed for its paths, config, baseline, selector and changed-region flags, and `fail_on` becomes the options' fail threshold.
/// A `diff` value of `-` selects a patch at path `-`, and any other `diff` value is a Git mode, as `since` is.
/// Panics through `unreachable!` if `args` sets more than one changed-region flag, which clap normally prevents.
///
/// Returns the options, with `diff` set to None when no changed-region flag was given.
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
///
/// `args` supplies the include and exclude rule and pillar flags, which are cloned.
/// Returns the execution selectors holding those four lists unchanged.
fn execution_selectors_from(args: &AnalyseArgs) -> ExecutionSelectors {
    ExecutionSelectors {
        include_rules: args.include_rule.clone(),
        exclude_rules: args.exclude_rule.clone(),
        include_pillars: args.include_pillar.clone(),
        exclude_pillars: args.exclude_pillar.clone(),
    }
}

/// Collect the five flags that decide what the report shows, none of which changes execution or the score.
///
/// `args` supplies the minimum severity and the show and hide rule and pillar flags.
/// Returns the display selectors holding those five values unchanged.
fn display_selectors_from(args: &AnalyseArgs) -> DisplaySelectors {
    DisplaySelectors {
        min_severity: args.min_severity,
        show_rules: args.show_rule.clone(),
        hide_rules: args.hide_rule.clone(),
        show_pillars: args.show_pillar.clone(),
        hide_pillars: args.hide_pillar.clone(),
    }
}

/// Map the parsed `report` flags onto analysis options, leaving diff, history, baseline path and selectors unset.
///
/// `args` supplies the paths, config flags, `include_ignored`, `no_baseline` and the HTML or JSON format; `fail_on` becomes the fail threshold.
///
/// Returns the options for a report run, with HTML or JSON output matching the requested report format.
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

/// Run the `report` subcommand: resolve setup, analyse the project and publish the HTML or JSON report.
///
/// `args` holds the report flags, including the output target, and `writer` is handed to `emit_report_output` with that target.
/// JSON failures publish an invalidated report to the same output destination.
///
/// Returns exit code 2 when setup, analysis or writing an output file fails, otherwise the outcome's code from the report, threshold and gate.
fn run_report(args: ReportArgs, writer: OutputWriter) -> ExitCode {
    let cli_fail_on = args.fail_on;
    let output = args.output.clone();
    let deep_scan_budget = args.deep_scan_budget.clone();
    let base = options_from_report(&args, FailThreshold::None);
    let (project_root, options, config) = match resolve_command_setup(
        base.clone(),
        cli_fail_on,
        "report",
        FailThreshold::None,
        deep_scan_budget.as_ref(),
    ) {
        Ok(triple) => triple,
        Err(error) => {
            let (root, options) = failed_setup_context(base);
            return emit_failed_run_report(
                &root,
                &options,
                &RunFailure::Config(error),
                writer,
                output,
            );
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
            apply_display_selectors(&mut report, &options.display, config.display_floor);
            let rendered = render_report_with_scope(&report, &scope, options.format, duration_ms);
            match emit_report_output(writer, output, outcome, &rendered) {
                Ok(()) => outcome.exit_code(),
                Err(error) => {
                    eprintln!("gruff-rs: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Err(error) => emit_failed_run_report(&project_root, &options, &error, writer, output),
    }
}

/// Run the rule-listing subcommand from the current directory, writing the catalogue, one rule's detail or a selector's expansion.
///
/// `args` picks the format, the optional rule id or selector, and the config to read custom rules from.
/// `writer` emits the body through `emit_unconditional`.
///
/// Returns success once the body is written, or exit code 2 after printing the error when the current directory or rendering fails.
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

/// Render the rule-listing body: one rule's detail when `args` names a rule id, else a selector's expansion, else the full catalogue.
///
/// `project_root` is where the config holding custom rules is loaded from, and `args` supplies the rule id, selector, format and config flags.
///
/// Returns the rendered text, or Err with the message when loading the config, rendering the rule detail or expanding the selector fails.
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

/// Expand a rule selector into the rule ids it names, for the rule listing's selector mode.
///
/// `selector` is expanded against the built-in `registry` and the configured `custom_rules`, and `format` picks a JSON array or one id per line.
///
/// Returns the formatted ids, or Err when `expand_rule_selector_with_custom` rejects the selector.
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

/// Return the rule catalogue in the shared JSON envelope.
///
/// Automation reads the `rules` key even when the list is empty.
/// Listing rules does not require a source scan.
#[derive(Serialize)]
struct RuleListing<'a> {
    rules: &'a [ListedRule],
}

/// Format the rule catalogue as the family JSON envelope or as text, one entry per rule in the order given.
///
/// `rules` are the listed rules in order, and `format` chooses pretty JSON under a `rules` key or the text rendering.
///
/// Returns the formatted catalogue, which for an empty `rules` is an empty string or a JSON object with an empty array.
fn format_listed_rules(rules: &[ListedRule], format: RuleListFormat) -> String {
    match format {
        RuleListFormat::Json => {
            serde_json::to_string_pretty(&RuleListing { rules }).expect("rules serialize")
        }
        RuleListFormat::Text => render_listed_rules_text(rules),
    }
}

/// Reuse the family's published option name for each single-threshold rule in `list-rules`.
/// If the family has no name for a rule's threshold, publish `{"threshold": N}`.
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
///
/// `definition` supplies the rule id and default threshold; a rule with detector parameters publishes each one's default under its own name.
/// A lone threshold is published under its gruff-go knob name, or under `threshold` when gruff-go has none.
/// Returns the knob map, or None when the rule has neither detector parameters nor a threshold.
fn listing_thresholds(definition: &rules::RuleDefinition) -> Option<Map<String, Value>> {
    // A detector's named parameters are its knob map, published under the names config reads.
    let parameters = rules::detector_parameters(definition.id);
    if !parameters.is_empty() {
        let mut thresholds = Map::new();
        for parameter in parameters {
            thresholds.insert(
                parameter.name.to_string(),
                listing_number(parameter.default),
            );
        }
        return Some(thresholds);
    }
    let threshold = definition.threshold?;
    let knob = LISTING_THRESHOLD_KNOB_NAMES
        .iter()
        .find(|(rule_id, _)| *rule_id == definition.id)
        .map_or("threshold", |(_, knob)| knob);
    let mut thresholds = Map::new();
    thresholds.insert(knob.to_string(), listing_number(threshold.default));
    Some(thresholds)
}

/// An integral value prints as an integer (`25`, not `25.0`) so a typed consumer reads one number shape.
///
/// Returns `value` as a JSON integer when it has no fractional part, otherwise as a JSON float.
fn listing_number(value: f64) -> Value {
    if value.fract() == 0.0 {
        json!(value as i64)
    } else {
        json!(value)
    }
}

/// Render the text rule catalogue, one entry per rule with its id, tier, pillar, default severity and description.
///
/// `rules` are rendered in the order given, and a description is written as is, so an embedded newline spreads its entry over several lines.
///
/// Returns the entries separated by newlines with trailing newlines trimmed, or an empty string for an empty `rules`.
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

/// Load the project config the rule listing reads custom rules from, with no baseline and no command-line selectors in the options.
///
/// `project_root` is where the config is looked up, and `args` supplies the explicit config path and the no-config flag.
///
/// Returns the loaded config, or Err with the loader's message when loading fails.
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

/// List every built-in rule in registry order followed by the configured custom rules, in the catalogue's shape.
///
/// `registry` supplies the built-in definitions and `custom_rules` the configured custom rules, which follow them.
///
/// Returns the built-in entries followed by one entry per custom rule.
fn listed_rules(registry: &rules::RuleRegistry, custom_rules: &[CustomRule]) -> Vec<ListedRule> {
    let mut listed: Vec<ListedRule> = registry
        .definitions()
        .iter()
        .map(listed_builtin_rule)
        .collect();
    listed.extend(custom_rules.iter().map(listed_custom_rule));
    listed
}

/// Describe one built-in rule as a catalogue entry, with its listing thresholds and no custom scope or pattern.
///
/// `definition` supplies the id, name, pillar, tier, kind, severity, confidence, options, enabled flag, description and false-positive shapes.
///
/// Returns the catalogue entry, whose thresholds come from `listing_thresholds` and are None for a rule without any.
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

/// Describe one configured custom rule as a catalogue entry, enabled by default at tier `v0.1` with kind `custom`.
///
/// `rule` supplies the id, pillar, severity, confidence, scope, pattern and message, which becomes the description.
///
/// Returns the catalogue entry, named from the id by `custom_rule_name` and carrying no thresholds, options or false-positive shapes.
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

/// Name a rule kind the way the rule catalogue publishes it.
///
/// `kind` is the built-in rule's kind from its definition.
///
/// Returns `project`, `text` or `rust` for the matching kind.
fn rule_kind_name(kind: rules::RuleKind) -> &'static str {
    match kind {
        rules::RuleKind::Project => "project",
        rules::RuleKind::Text => "text",
        rules::RuleKind::Rust => "rust",
    }
}

/// Derive a display name from a custom rule id, such as `custom.no-todo` becoming `No Todo`.
///
/// `rule_id` has any `custom.` prefix removed, then each non-empty hyphen-separated part gets an ASCII-uppercased first letter.
///
/// Returns the parts joined by single spaces, which is empty when `rule_id` holds only the prefix or hyphens.
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

/// Run the `summary` subcommand: analyse the project and render the text or JSON summary of the report.
///
/// `args` supplies the paths, config flags, `include_ignored`, deep-scan budget, `top` count and format; `writer` emits the rendered summary.
/// Neither a fail threshold nor the `gate:` block changes its exit code, because `summary` only reports.
///
/// Returns exit code 2 after printing the error when setup or analysis fails, otherwise the code classified with no threshold or gate.
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
        match resolve_project_root_and_config(options.clone(), deep_scan_budget.as_ref()) {
            Ok(triple) => triple,
            Err(error) => {
                let (root, options) = failed_setup_context(options);
                return emit_failed_summary(&root, &options, &RunFailure::Config(error), writer);
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
        Err(error) => emit_failed_summary(&project_root, &options, &error, writer),
    }
}

/// Emit the summary schema with an invalidated run when JSON is requested.
/// `project_root` and `options` describe the attempted run. `writer` receives the diagnostic from `error`.
/// Returns exit code 2.
fn emit_failed_summary(
    project_root: &Path,
    options: &AnalysisOptions,
    error: &RunFailure,
    writer: OutputWriter,
) -> ExitCode {
    eprintln!("gruff-rs: {error}");
    // `summary --format json` retains its schema so a caller can distinguish a failed scan from a zero-finding summary.
    if matches!(options.format, OutputFormat::Json) {
        let report = failed_run_report(project_root, options, error);
        writer.emit_unconditional(&machine_contract::render_summary(&report));
    }
    ExitCode::from(2)
}

/// Generate the shell completion script for the CLI and write it straight to stdout.
///
/// `args` names the target shell, and `writer` is only checked for silence: a silent writer suppresses the script.
///
/// Returns success, including when a silent writer suppresses the script.
fn run_completion(args: CompletionArgs, writer: OutputWriter) -> ExitCode {
    if writer.is_silent() {
        return ExitCode::SUCCESS;
    }
    let mut command = Cli::command();
    let bin_name = command.get_name().to_string();
    clap_complete::generate(args.shell, &mut command, bin_name, &mut std::io::stdout());
    ExitCode::SUCCESS
}

/// Run the per-source built-in and custom rules that `config` enables and that apply to one source unit, gathering their findings.
///
/// `unit` is the source unit to check, and `config` is the run's config, handed to both the built-in and the custom rule passes.
///
/// Returns the built-in findings followed by the custom-rule findings, which is empty when nothing matched.
#[cfg(test)]
pub(crate) fn analyse_source(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    let mut findings = built_in_rules::analyse(unit, config);
    findings.extend(custom_rules::analyse(unit, config));
    findings
}

/// Run the per-source built-in and custom rules that `config` enables and that apply to one source unit, keeping the built-in pass's artifacts.
///
/// `unit` is the source to check, and `config` is the run's config, handed to both the built-in and the custom rule passes.
/// `retain_function_blocks` is forwarded unchanged to the built-in pass as its request to keep function blocks.
///
/// Returns the built-in pass's artifacts with the custom-rule findings appended to its findings.
/// Their function blocks are None without a Rust syntax tree, or when neither an enabled rule nor `retain_function_blocks` asked for them.
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

/// Resolve a possibly relative path against a root directory without touching the filesystem.
///
/// `root` is the directory a relative `path` is joined onto, and an absolute `path` is kept as given.
///
/// Returns the resulting path with no `.` or `..` components removed and no symlinks resolved.
pub(crate) fn absolutize(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// Turn a path into the forward-slash, root-relative text reports display.
///
/// `root` is stripped from the front of `path` when it is a prefix, and otherwise `path` is kept whole.
///
/// Returns the path text with backslashes turned into forward slashes and leading `./` prefixes removed; non-UTF-8 bytes are replaced.
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
