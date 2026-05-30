use super::*;

pub(crate) fn missing_path_diagnostics(missing_paths: &[String]) -> Vec<RunDiagnostic> {
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

pub(crate) fn apply_report_exclusions(
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

    let mut summaries = initial_suppression_summaries(exclusions);
    let (kept, suppressed) = partition_excluded_findings(findings, exclusions, &mut summaries);
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
            reason: exclusion.reason.clone(),
            suppressed: 0,
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

pub(crate) fn run_analysis_in_project(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
) -> Result<AnalysisReport, String> {
    let mut discovery = discover_sources(project_root, options, config);
    let mut diagnostics = missing_path_diagnostics(&discovery.missing_paths);
    diagnostics.extend(excluded_security_rule_diagnostics(config));
    let diff_filter = resolve_diff_filter(project_root, options, &discovery.files)?;
    apply_diff_file_selection(&mut discovery, diff_filter.as_ref());
    let analysed_paths = analysed_display_paths(&discovery.files);
    let inputs = collect_report_inputs(
        project_root,
        options,
        config,
        discovery,
        diagnostics,
        diff_filter.as_ref(),
        &analysed_paths,
    )?;
    let mut report = build_report(project_root, options, config, inputs);
    // Surface the per-severity gate decision (ADR-003 M02 addendum) as a non-fatal
    // diagnostic; the exit-code effect is applied by `RunOutcome::classify`.
    if let Some(gate) = &config.gate {
        report.diagnostics.push(gate.diagnostic(&report.summary));
    }
    record_history_if_requested(project_root, options, config, &mut report);
    Ok(report)
}

fn collect_report_inputs(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    discovery: DiscoveryResult,
    mut diagnostics: Vec<RunDiagnostic>,
    diff_filter: Option<&ResolvedDiffFilter>,
    analysed_paths: &BTreeSet<String>,
) -> Result<ReportInputs, String> {
    let AnalysisArtifacts {
        mut findings,
        function_blocks_by_file,
    } = analyse_discovered_sources_with_artifacts(
        project_root,
        &discovery.files,
        config,
        &mut diagnostics,
    );
    // Dedupe before baseline so perRuleDeltas match the final report (footguns/report.md).
    sort_and_dedupe_findings(&mut findings);
    let baseline_resolution = resolve_baseline(project_root, options, &mut findings)?;
    let (findings, summaries, suppressed_findings) =
        apply_report_exclusions(findings, &config.exclusions);
    let (baseline_report, per_rule_deltas) = split_baseline_resolution(baseline_resolution);
    let inputs = ReportInputs {
        discovery,
        diagnostics,
        findings,
        baseline_report,
        suppressions: ReportSuppressions {
            summaries,
            suppressed_findings,
        },
        per_rule_deltas,
        suppressed_count: None,
    };
    match diff_filter {
        Some(diff_filter) => Ok(apply_changed_region_to_inputs(
            project_root,
            options,
            config,
            inputs,
            diff_filter,
            analysed_paths,
            &function_blocks_by_file,
        )),
        None => Ok(inputs),
    }
}

/// Run the changed-region filter over an already-assembled report and re-pack
/// the filtered findings, suppressions, deltas, and suppressed-count back into
/// `ReportInputs`. `discovery` and `baseline_report` pass through unchanged - the
/// filter only narrows findings to the changed region.
fn apply_changed_region_to_inputs(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    inputs: ReportInputs,
    diff_filter: &ResolvedDiffFilter,
    analysed_paths: &BTreeSet<String>,
    function_blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
) -> ReportInputs {
    let discovery = inputs.discovery.clone();
    let baseline_report = inputs.baseline_report.clone();
    let report = build_report(project_root, options, config, inputs);
    let report = apply_changed_region_filter(
        report,
        &diff_filter.patch,
        analysed_paths,
        config,
        function_blocks_by_file,
        diff_filter.scope,
    );
    ReportInputs {
        discovery,
        diagnostics: report.diagnostics,
        findings: report.findings,
        baseline_report,
        suppressions: ReportSuppressions {
            summaries: report.suppressions,
            suppressed_findings: report.suppressed_findings,
        },
        per_rule_deltas: report.per_rule_deltas,
        suppressed_count: report.suppressed_count,
    }
}

fn split_baseline_resolution(
    resolution: Option<BaselineResolution>,
) -> (Option<BaselineReport>, Option<Vec<RuleDelta>>) {
    let Some(BaselineResolution { report, deltas }) = resolution else {
        return (None, None);
    };
    let deltas = (!report.generated && !deltas.is_empty()).then_some(deltas);
    (Some(report), deltas)
}

pub(crate) fn analysed_display_paths(files: &[SourceFile]) -> BTreeSet<String> {
    files.iter().map(|file| file.display_path.clone()).collect()
}

pub(crate) struct AnalysisArtifacts {
    pub(crate) findings: Vec<Finding>,
    pub(crate) function_blocks_by_file: BTreeMap<String, Vec<FunctionBlock>>,
}

pub(crate) fn analyse_discovered_sources_with_artifacts(
    project_root: &Path,
    files: &[SourceFile],
    config: &Config,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> AnalysisArtifacts {
    let capabilities = AnalysisCapabilities::from_config(config);
    let (parsed_sources, read_diagnostics) =
        crate::project::read_and_parse_sources_with_options(files, capabilities.parse_rust);
    diagnostics.extend(read_diagnostics);
    let blocks_by_file = function_blocks_by_file(&parsed_sources);

    let mut findings = if capabilities.project_context {
        let project_context = build_project_context(project_root, &parsed_sources);
        diagnostics.extend(project_context.diagnostics.iter().cloned());
        analyse_project(&project_context, config)
    } else {
        Vec::new()
    };
    for parsed_source in &parsed_sources {
        findings.extend(analyse_source(&parsed_source.as_source_unit(), config));
        diagnostics.extend(parsed_source.diagnostics.iter().cloned());
    }
    AnalysisArtifacts {
        findings,
        function_blocks_by_file: blocks_by_file,
    }
}

fn function_blocks_by_file(sources: &[ParsedSource]) -> BTreeMap<String, Vec<FunctionBlock>> {
    sources
        .iter()
        .filter_map(|source| {
            let ast = source.rust_ast.as_ref()?;
            Some((
                source.file.display_path.clone(),
                crate::built_in_rules::rust_function_blocks(ast, &source.source),
            ))
        })
        .collect()
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
    } = inputs;
    let summary = summarize(&findings);
    let score = score_report(&findings, config);
    AnalysisReport {
        schema_version: "gruff.analysis.v2".to_string(),
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
            ignored_path_details: discovery.ignored_path_details,
            missing_paths: discovery.missing_paths,
        },
        diagnostics,
        suppressions: suppressions.summaries,
        findings,
        suppressed_count,
        score,
        baseline: baseline_report,
        per_rule_deltas,
        suppressed_findings: suppressions.suppressed_findings,
    }
}
