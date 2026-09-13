use super::*;

pub(crate) fn missing_path_diagnostics(missing_paths: &[String]) -> Vec<RunDiagnostic> {
    missing_paths
        .iter()
        .map(|missing_path| RunDiagnostic {
            diagnostic_type: "missing-path".to_string(),
            message: format!("Input path does not exist: {missing_path}"),
            file_path: Some(missing_path.clone()),
            line: None,
            invalidates_run: None,
        })
        .collect()
}

// ADR-014: when excludeFromScore is set on a Security or SensitiveData
// rule, surface a non-fatal warning so the choice is user-visible.
// rule_settings is a HashMap, so sort matched rule ids before emitting
// for deterministic output. Custom rules can't reach this state — the
// config loader rejects excludeFromScore outside `enabled` for them.
fn excluded_security_rule_diagnostics(config: &Config) -> Vec<RunDiagnostic> {
    let mut ids = collect_excluded_security_rule_ids(config);
    ids.sort_by_key(|(rule_id, _)| *rule_id);
    ids.into_iter()
        .map(|(rule_id, pillar)| excluded_security_rule_diagnostic(rule_id, pillar))
        .collect()
}

fn collect_excluded_security_rule_ids(config: &Config) -> Vec<(&str, Pillar)> {
    let registry = rules::builtin_registry();
    config
        .rule_settings
        .iter()
        .filter(|(_, setting)| setting.exclude_from_score == Some(true))
        .filter_map(|(rule_id, _)| {
            let definition = registry.get(rule_id)?;
            matches!(definition.pillar, Pillar::Security | Pillar::SensitiveData)
                .then_some((rule_id.as_str(), definition.pillar))
        })
        .collect()
}

fn excluded_security_rule_diagnostic(rule_id: &str, pillar: Pillar) -> RunDiagnostic {
    RunDiagnostic {
        diagnostic_type: "excluded-security-rule-from-score".to_string(),
        message: format!(
            "Rule `{rule_id}` ({pillar:?} pillar) is configured with `excludeFromScore: true`; its findings still surface but no longer affect the composite score."
        ),
        file_path: None,
        line: None,
        invalidates_run: None,
    }
}

pub(crate) fn sort_and_dedupe_findings(findings: &mut Vec<Finding>) {
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

/// Remove the findings both suppression channels claim and count every configured entry.
/// The returned summaries carry `exclude` rows first, then `sensitiveExclusions` rows.
pub(crate) fn apply_report_exclusions(
    findings: Vec<Finding>,
    exclusions: &[ExclusionRule],
    sensitive_exclusions: &[SensitiveExclusionRule],
) -> (
    Vec<Finding>,
    Vec<SuppressionSummary>,
    Vec<SuppressedFinding>,
) {
    if exclusions.is_empty() && sensitive_exclusions.is_empty() {
        return (findings, Vec::new(), Vec::new());
    }

    let mut summaries = initial_suppression_summaries(exclusions);
    let exclude_rows = summaries.len();
    summaries.extend(initial_sensitive_suppression_summaries(
        sensitive_exclusions,
    ));
    let (kept, mut suppressed) =
        partition_excluded_findings(findings, exclusions, &mut summaries[..exclude_rows]);
    let (kept, sensitive_suppressed) =
        partition_sensitive_findings(kept, sensitive_exclusions, &mut summaries[exclude_rows..]);
    suppressed.extend(sensitive_suppressed);
    (kept, summaries, suppressed)
}

fn initial_suppression_summaries(exclusions: &[ExclusionRule]) -> Vec<SuppressionSummary> {
    exclusions
        .iter()
        .enumerate()
        .map(|(index, exclusion)| SuppressionSummary {
            index,
            rule: exclusion.selector.clone(),
            paths: exclusion.paths.clone(),
            message_contains: exclusion.message_contains.clone(),
            // Ordinary exclusions have no symbol scope, so this stays null in every report.
            symbol: None,
            reason: exclusion.reason.clone(),
            suppressed: 0,
            config_key: "exclude",
        })
        .collect()
}

/// Publish one audit row per sensitive exclusion, including entries that match nothing.
/// A zero count is a valid result, so a fixed fixture never breaks the user's build.
fn initial_sensitive_suppression_summaries(
    sensitive_exclusions: &[SensitiveExclusionRule],
) -> Vec<SuppressionSummary> {
    sensitive_exclusions
        .iter()
        .enumerate()
        .map(|(index, exclusion)| SuppressionSummary {
            index,
            rule: exclusion.rule_id.clone(),
            paths: vec![exclusion.path.clone()],
            // This section accepts no message matcher, so no row can describe a matched value.
            message_contains: None,
            symbol: exclusion.symbol.clone(),
            reason: exclusion.reason.clone(),
            suppressed: 0,
            config_key: "sensitiveExclusions",
        })
        .collect()
}

fn partition_excluded_findings(
    findings: Vec<Finding>,
    exclusions: &[ExclusionRule],
    summaries: &mut [SuppressionSummary],
) -> (Vec<Finding>, Vec<SuppressedFinding>) {
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = Vec::new();
    let path_matchers: Vec<Vec<PathMatcher>> = exclusions
        .iter()
        .map(|exclusion| compile_path_matchers(&exclusion.paths))
        .collect();
    for finding in findings {
        match exclusions
            .iter()
            .enumerate()
            .position(|(index, exclusion)| {
                exclusion_matches_finding_with_paths(exclusion, &path_matchers[index], &finding)
            }) {
            Some(index) => {
                summaries[index].suppressed += 1;
                suppressed.push(SuppressedFinding {
                    finding,
                    suppression: summaries[index].clone(),
                });
            }
            None => kept.push(finding),
        }
    }
    (kept, suppressed)
}

fn exclusion_matches_finding_with_paths(
    exclusion: &ExclusionRule,
    path_matchers: &[PathMatcher],
    finding: &Finding,
) -> bool {
    if !exclusion.rule_ids.contains(&finding.rule_id) {
        return false;
    }
    if !path_matchers.is_empty() {
        let file_path = normalize_report_path(&finding.file_path);
        if !path_matchers
            .iter()
            .any(|matcher| matcher.matches(&file_path))
        {
            return false;
        }
    }
    exclusion
        .message_contains
        .as_ref()
        .is_none_or(|message| finding.message.contains(message))
}

/// Remove the sensitive-data findings inside a declared exclusion scope and count each entry.
/// Findings outside every declared scope pass through untouched.
fn partition_sensitive_findings(
    findings: Vec<Finding>,
    sensitive_exclusions: &[SensitiveExclusionRule],
    summaries: &mut [SuppressionSummary],
) -> (Vec<Finding>, Vec<SuppressedFinding>) {
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = Vec::new();
    for finding in findings {
        match sensitive_exclusions
            .iter()
            .position(|exclusion| sensitive_exclusion_matches_finding(exclusion, &finding))
        {
            Some(index) => {
                summaries[index].suppressed += 1;
                suppressed.push(SuppressedFinding {
                    finding,
                    suppression: summaries[index].clone(),
                });
            }
            None => kept.push(finding),
        }
    }
    (kept, suppressed)
}

/// Decide whether one finding falls inside one declared sensitive exclusion scope.
/// Every comparison is exact: no glob, prefix, message, or value matching participates.
fn sensitive_exclusion_matches_finding(
    exclusion: &SensitiveExclusionRule,
    finding: &Finding,
) -> bool {
    if exclusion.rule_id != finding.rule_id {
        return false;
    }
    // The normalised display path is compared so the caller's working directory cannot change the result.
    if exclusion.path != normalize_report_path(&finding.file_path) {
        return false;
    }
    exclusion
        .symbol
        .as_deref()
        .is_none_or(|symbol| finding.symbol.as_deref() == Some(symbol))
}

pub(crate) fn run_analysis_in_project(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
) -> Result<AnalysisReport, String> {
    let mut discovery = discover_sources(project_root, options, config);
    let mut diagnostics = missing_path_diagnostics(&discovery.missing_paths);
    diagnostics.extend(excluded_security_rule_diagnostics(config));
    let diff_filter = resolve_diff_filter(project_root, options, &discovery.files)?;
    let pre_diff_rust_paths = rust_display_paths(&discovery.files);
    apply_diff_file_selection(&mut discovery, diff_filter.as_ref());
    let coverage = project_coverage(
        project_root,
        options,
        config,
        &discovery,
        &pre_diff_rust_paths,
        diff_filter.as_ref(),
    );
    let inputs = collect_report_inputs(
        project_root,
        options,
        config,
        discovery,
        diagnostics,
        coverage,
        diff_filter.as_ref(),
    )?;
    let mut report = build_report(project_root, options, config, inputs);
    record_history_if_requested(project_root, options, config, &mut report);
    Ok(report)
}

pub(crate) fn apply_gate_diagnostic(report: &mut AnalysisReport, gate: Option<&Gate>) {
    let Some(gate) = gate else {
        return;
    };
    let diagnostic = match gate.scope_precondition_error(report) {
        Some(message) => RunDiagnostic {
            diagnostic_type: "gate-config-error".to_string(),
            message,
            file_path: None,
            line: None,
            invalidates_run: None,
        },
        None => gate.diagnostic(report),
    };
    report.diagnostics.push(diagnostic);
}

fn collect_report_inputs(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    discovery: DiscoveryResult,
    mut diagnostics: Vec<RunDiagnostic>,
    coverage: ProjectCoverage,
    diff_filter: Option<&ResolvedDiffFilter>,
) -> Result<ReportInputs, String> {
    let analysed_paths = analysed_display_paths(&discovery.files);
    let (mut findings, all_findings, function_blocks_by_file) = analysed_findings(
        project_root,
        config,
        &discovery,
        coverage,
        has_symbol_scope_diff(diff_filter),
        &mut diagnostics,
    );
    let (baseline_report, per_rule_deltas, all_findings_summary) = resolve_run_baseline(
        project_root,
        options,
        &mut findings,
        &function_blocks_by_file,
        &mut diagnostics,
    )?;
    let (findings, summaries, suppressed_findings) =
        apply_report_exclusions(findings, &config.exclusions, &config.sensitive_exclusions);
    let inputs = ReportInputs {
        discovery,
        diagnostics,
        findings,
        baseline_report,
        suppressions: report_suppressions(summaries, suppressed_findings),
        per_rule_deltas,
        suppressed_count: None,
        all_findings_summary: Some(all_findings_summary),
        all_findings,
        machine_diff: machine_diff_context(options, diff_filter),
    };
    Ok(apply_changed_region_to_inputs(
        project_root,
        options,
        config,
        inputs,
        diff_filter,
        &analysed_paths,
        &function_blocks_by_file,
    ))
}

/// Run the rules over the discovered sources and hand back the findings, a pre-baseline copy, and the parsed functions.
///
/// The pre-baseline copy is what a gate scoped to everything counts, so it is taken before suppression drops the
/// debt the user already accepted; the parsed functions are what name a finding by the declaration it sits on.
#[allow(clippy::type_complexity)]
fn analysed_findings(
    project_root: &Path,
    config: &Config,
    discovery: &DiscoveryResult,
    coverage: ProjectCoverage,
    has_symbol_scope: bool,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> (
    Vec<Finding>,
    Vec<Finding>,
    BTreeMap<String, Vec<FunctionBlock>>,
) {
    let AnalysisArtifacts {
        mut findings,
        function_blocks_by_file,
    } = analyse_discovered_sources_with_artifacts(
        project_root,
        &discovery.files,
        config,
        coverage,
        has_symbol_scope,
        diagnostics,
    );
    sort_and_dedupe_findings(&mut findings);
    // Naming every finding before the baseline filters any of them keeps one alert one alert: code scanning reads
    // the same identity the baseline does, and a finding hidden from this report keeps the ordinal it was ranked with.
    name_findings(&mut findings, &function_blocks_by_file);
    let all_findings = findings.clone();
    (findings, all_findings, function_blocks_by_file)
}

/// Attach each ordinary finding's durable identity, which SARIF publishes as its code-scanning fingerprint.
///
/// A sensitive finding is left unnamed, because it has no durable identity at all; a finding this run cannot name
/// keeps `None` and is published without a fingerprint rather than with a guessed one.
fn name_findings(findings: &mut [Finding], blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>) {
    let declaration_position = declaration_position_from_blocks(blocks_by_file);
    let Ok(identities) = finding_identities(findings, &declaration_position) else {
        return;
    };
    for (finding, named) in findings.iter_mut().zip(identities) {
        // The subject travels beside the identity so a consumer can recompute the identity from the payload alone.
        let (identity, subject) = match named {
            Some(named) => (Some(named.identity), Some(named.subject)),
            None => (None, None),
        };
        finding.baseline_identity = identity;
        finding.baseline_subject = subject;
    }
}

fn has_symbol_scope_diff(diff_filter: Option<&ResolvedDiffFilter>) -> bool {
    diff_filter.is_some_and(|filter| filter.scope == ChangedScope::Symbol)
}

fn report_suppressions(
    summaries: Vec<SuppressionSummary>,
    suppressed_findings: Vec<SuppressedFinding>,
) -> ReportSuppressions {
    ReportSuppressions {
        summaries,
        suppressed_findings,
    }
}

/// Run the changed-region filter over an already-assembled report and re-pack
/// the filtered findings, suppressions, deltas, and suppressed-count back into
/// `ReportInputs`. With no diff filter the inputs pass through untouched.
/// `discovery` and `baseline_report` pass through unchanged - the filter only
/// narrows findings to the changed region.
fn apply_changed_region_to_inputs(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    inputs: ReportInputs,
    diff_filter: Option<&ResolvedDiffFilter>,
    analysed_paths: &BTreeSet<String>,
    function_blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
) -> ReportInputs {
    let Some(diff_filter) = diff_filter else {
        return inputs;
    };
    let discovery = inputs.discovery.clone();
    let baseline_report = inputs.baseline_report.clone();
    let all_findings = inputs.all_findings.clone();
    let report = build_report(project_root, options, config, inputs);
    let report = apply_changed_region_filter(
        report,
        &diff_filter.patch,
        analysed_paths,
        config,
        function_blocks_by_file,
        diff_filter.scope,
    );
    let all_findings_summary =
        changed_scope_all_summary(&all_findings, diff_filter, function_blocks_by_file);
    ReportInputs {
        discovery,
        all_findings_summary: Some(all_findings_summary),
        diagnostics: report.diagnostics,
        findings: report.findings,
        baseline_report,
        suppressions: ReportSuppressions {
            summaries: report.suppressions,
            suppressed_findings: report.suppressed_findings,
        },
        per_rule_deltas: report.per_rule_deltas,
        suppressed_count: report.suppressed_count,
        all_findings,
        machine_diff: report.machine_context.diff,
    }
}

fn machine_diff_context(
    options: &AnalysisOptions,
    diff_filter: Option<&ResolvedDiffFilter>,
) -> Option<MachineDiffContext> {
    let filter = diff_filter?;
    let selection = options.diff.as_ref()?;
    let mode = match selection {
        DiffSelection::Patch { path, .. } if path == Path::new("-") => "stdin".to_string(),
        DiffSelection::Patch { .. } => "patch".to_string(),
        DiffSelection::Git { mode, .. } => mode.clone(),
        DiffSelection::ExplicitRanges { .. } => "changed-ranges".to_string(),
    };
    Some(MachineDiffContext {
        mode,
        changed_files: filter.patch.changed_files().into_iter().collect(),
    })
}

fn changed_scope_all_summary(
    all_findings: &[Finding],
    diff_filter: &ResolvedDiffFilter,
    function_blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
) -> Summary {
    summarize_changed_findings(
        all_findings,
        &diff_filter.patch,
        function_blocks_by_file,
        diff_filter.scope,
    )
}

/// What meeting the baseline produced: the report section, per-rule movement, and the pre-baseline summary.
///
/// The summary is taken before suppression drops the unchanged findings, so a gate scoped to everything can
/// still count the debt the user has already accepted.
type RunBaseline = (Option<BaselineReport>, Option<Vec<RuleDelta>>, Summary);

/// Meet the baseline for this run and turn every collision it found into a diagnostic the user reads.
///
/// Findings are named by the declaration they sit on, so two findings inside one function share an identity while
/// a second function of the same name takes its own, which is what keeps one review from covering both.
fn resolve_run_baseline(
    project_root: &Path,
    options: &AnalysisOptions,
    findings: &mut Vec<Finding>,
    function_blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Result<RunBaseline, String> {
    let declaration_position = declaration_position_from_blocks(function_blocks_by_file);
    let (resolution, all_findings_summary) =
        resolve_baseline(project_root, options, findings, &declaration_position)?;
    let (report, deltas, collisions) = split_baseline_resolution(resolution);
    diagnostics.extend(collision_diagnostics(&collisions));
    Ok((report, deltas, all_findings_summary))
}

fn split_baseline_resolution(
    resolution: Option<BaselineResolution>,
) -> (
    Option<BaselineReport>,
    Option<Vec<RuleDelta>>,
    Vec<BaselineCollision>,
) {
    let Some(BaselineResolution {
        report,
        deltas,
        collisions,
    }) = resolution
    else {
        return (None, None, Vec::new());
    };
    let deltas = (!report.generated && !deltas.is_empty()).then_some(deltas);
    (Some(report), deltas, collisions)
}

/// Name every identity that covered two declarations, so a user sees which ones could not be told apart.
///
/// Neither finding is suppressed and the run is not invalidated: hiding either would let one review cover a
/// finding nobody read, which is exactly what the declaration ordinal exists to prevent.
fn collision_diagnostics(collisions: &[BaselineCollision]) -> Vec<RunDiagnostic> {
    collisions
        .iter()
        .map(|collision| RunDiagnostic {
            diagnostic_type: "baseline-collision".to_string(),
            message: format!(
                "collision: identity {} covers {} declarations of {} for rule {} in {}; none is suppressed",
                collision.identity,
                collision.subjects.len(),
                collision.subjects.join(", "),
                collision.rule_id,
                collision.path,
            ),
            file_path: Some(collision.path.clone()),
            line: None,
            invalidates_run: Some(false),
        })
        .collect()
}

pub(crate) fn analysed_display_paths(files: &[SourceFile]) -> BTreeSet<String> {
    files.iter().map(|file| file.display_path.clone()).collect()
}

fn rust_display_paths(files: &[SourceFile]) -> BTreeSet<String> {
    files
        .iter()
        .filter(|file| file.is_rust)
        .map(|file| file.display_path.clone())
        .collect()
}

fn project_coverage(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    discovery: &DiscoveryResult,
    pre_diff_rust_paths: &BTreeSet<String>,
    diff_filter: Option<&ResolvedDiffFilter>,
) -> ProjectCoverage {
    let analysed_rust_files = rust_display_paths(&discovery.files);
    if !config.is_rule_enabled("dead-code.unused-private-item-candidate") {
        return ProjectCoverage {
            discoverable_rust_files: analysed_rust_files.clone(),
            analysed_rust_files,
            diff_selection_narrowed: false,
            parse_incomplete: false,
        };
    }

    let discoverable_rust_files = discover_project_rust_universe(project_root, options, config);
    let diff_selection_narrowed = diff_filter.is_some_and(|filter| {
        !filter.explicit_ranges && !pre_diff_rust_paths.is_subset(&analysed_rust_files)
    });
    ProjectCoverage {
        discoverable_rust_files,
        analysed_rust_files,
        diff_selection_narrowed,
        parse_incomplete: false,
    }
}

fn discover_project_rust_universe(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
) -> BTreeSet<String> {
    let mut universe_options = options.clone();
    universe_options.paths = vec![PathBuf::from(".")];
    universe_options.diff = None;
    rust_display_paths(&discover_sources(project_root, &universe_options, config).files)
}

#[cfg(test)]
pub(crate) fn project_coverage_for_test(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
) -> Result<ProjectCoverage, String> {
    let mut discovery = discover_sources(project_root, options, config);
    let diff_filter = resolve_diff_filter(project_root, options, &discovery.files)?;
    let pre_diff_rust_paths = rust_display_paths(&discovery.files);
    apply_diff_file_selection(&mut discovery, diff_filter.as_ref());
    Ok(project_coverage(
        project_root,
        options,
        config,
        &discovery,
        &pre_diff_rust_paths,
        diff_filter.as_ref(),
    ))
}

pub(crate) struct AnalysisArtifacts {
    pub(crate) findings: Vec<Finding>,
    pub(crate) function_blocks_by_file: BTreeMap<String, Vec<FunctionBlock>>,
}

pub(crate) fn analyse_discovered_sources_with_artifacts(
    project_root: &Path,
    files: &[SourceFile],
    config: &Config,
    coverage: ProjectCoverage,
    retain_function_blocks: bool,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> AnalysisArtifacts {
    let capabilities = AnalysisCapabilities::from_config(config);
    let (parsed_sources, read_diagnostics) = crate::project::read_and_parse_sources_with_options(
        files,
        capabilities.parse_rust,
        &config.deep_scan_budget,
    );
    diagnostics.extend(read_diagnostics);
    let mut blocks_by_file = BTreeMap::new();

    let mut findings = if capabilities.project_context {
        let project_context = build_project_context(project_root, &parsed_sources, coverage);
        diagnostics.extend(project_context.diagnostics.iter().cloned());
        analyse_project(&project_context, config, diagnostics)
    } else {
        Vec::new()
    };
    for parsed_source in &parsed_sources {
        let source_unit = parsed_source.as_source_unit();
        if retain_function_blocks {
            let source_artifacts =
                crate::analyse_source_with_artifacts(&source_unit, config, retain_function_blocks);
            if let Some(blocks) = source_artifacts.function_blocks {
                blocks_by_file.insert(parsed_source.file.display_path.clone(), blocks);
            }
            findings.extend(source_artifacts.findings);
        } else {
            findings.extend(crate::analyse_source(&source_unit, config));
        }
        diagnostics.extend(parsed_source.diagnostics.iter().cloned());
    }
    AnalysisArtifacts {
        findings,
        function_blocks_by_file: blocks_by_file,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AnalysisCapabilities {
    parse_rust: bool,
    project_context: bool,
}

impl AnalysisCapabilities {
    pub(crate) fn from_config(config: &Config) -> Self {
        let registry = rules::builtin_registry();
        let mut capabilities = Self {
            parse_rust: false,
            project_context: false,
        };

        for definition in registry.definitions() {
            if !config.is_rule_enabled(definition.id) {
                continue;
            }
            capabilities.include_builtin_rule(definition);
        }

        for rule in &config.custom_rules {
            if config.is_rule_enabled(&rule.id) {
                capabilities.include_custom_rule(rule);
            }
        }

        capabilities
    }

    fn include_builtin_rule(&mut self, definition: &rules::RuleDefinition) {
        match definition.kind {
            rules::RuleKind::Project => {
                self.project_context = true;
                self.parse_rust = true;
            }
            rules::RuleKind::Rust => {
                self.parse_rust = true;
            }
            rules::RuleKind::Text => {
                if text_rule_needs_rust_ast(definition.id) {
                    self.parse_rust = true;
                }
            }
        }
    }

    fn include_custom_rule(&mut self, rule: &CustomRule) {
        match rule.scope {
            CustomRuleScope::Text | CustomRuleScope::RustCode | CustomRuleScope::Comments => {}
        }
    }
}

fn text_rule_needs_rust_ast(rule_id: &str) -> bool {
    rule_id == "sensitive-data.hardcoded-env-value"
}

pub(crate) fn record_history_if_requested(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    report: &mut AnalysisReport,
) {
    if let Some(history_file) = &options.history_file {
        record_history(
            project_root,
            history_file,
            &report.findings,
            config,
            report.score.evaluated_files,
            &mut report.diagnostics,
        );
    }
}

pub(crate) struct ReportInputs {
    pub(crate) discovery: DiscoveryResult,
    pub(crate) diagnostics: Vec<RunDiagnostic>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) baseline_report: Option<BaselineReport>,
    pub(crate) suppressions: ReportSuppressions,
    pub(crate) per_rule_deltas: Option<Vec<RuleDelta>>,
    pub(crate) suppressed_count: Option<usize>,
    pub(crate) all_findings_summary: Option<Summary>,
    pub(crate) all_findings: Vec<Finding>,
    pub(crate) machine_diff: Option<MachineDiffContext>,
}

fn report_run_info(project_root: &Path, options: &AnalysisOptions) -> RunInfo {
    RunInfo {
        project_root: project_root.display().to_string(),
        format: options.format.as_str().to_string(),
        fail_on: options.fail_on.as_str().to_string(),
        generated_at: Utc::now().to_rfc3339(),
    }
}

fn report_path_summary(discovery: DiscoveryResult) -> PathSummary {
    PathSummary {
        analysed_files: discovery.files.len(),
        ignored_paths: discovery.ignored_paths,
        ignored_path_details: discovery.ignored_path_details,
        missing_paths: discovery.missing_paths,
    }
}

pub(crate) fn build_report(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    inputs: ReportInputs,
) -> AnalysisReport {
    let ReportInputs {
        discovery,
        diagnostics,
        findings,
        baseline_report,
        suppressions,
        per_rule_deltas,
        suppressed_count,
        all_findings_summary,
        all_findings: _,
        machine_diff,
    } = inputs;
    let summary = summarize(&findings);
    // Only Rust files carry code to score, so the ratified denominator is narrower than
    // analysed_files, which also counts the text inputs the raw-text rules read.
    let evaluated_files = discovery.files.iter().filter(|file| file.is_rust).count();
    let score = score_report(&findings, config, evaluated_files);
    let machine_context = machine_contract::report_context(project_root, options, machine_diff);
    AnalysisReport {
        schema_version: "gruff.analysis.v3".to_string(),
        tool: ToolInfo {
            name: "gruff-rs".to_string(),
            version: VERSION.to_string(),
        },
        run: report_run_info(project_root, options),
        summary,
        paths: report_path_summary(discovery),
        diagnostics,
        suppressions: suppressions.summaries,
        findings,
        suppressed_count,
        score,
        baseline: baseline_report,
        per_rule_deltas,
        suppressed_findings: suppressions.suppressed_findings,
        all_findings_summary,
        machine_context,
    }
}
