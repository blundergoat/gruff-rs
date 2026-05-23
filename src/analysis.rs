use super::*;

pub(crate) fn run_analysis(options: &AnalysisOptions) -> Result<AnalysisReport, String> {
    let project_root = std::env::current_dir()
        .map_err(|error| format!("unable to resolve current directory: {error}"))?;
    run_analysis_in_project(&project_root, options)
}

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

pub(crate) fn resolve_baseline(
    project_root: &Path,
    options: &AnalysisOptions,
    findings: &mut Vec<Finding>,
) -> Result<Option<BaselineReport>, String> {
    if let Some(path) = &options.generate_baseline {
        return generate_baseline_report(project_root, path, findings).map(Some);
    }
    if options.no_baseline {
        return Ok(None);
    }
    let Some((baseline_path, source)) = select_baseline_path(project_root, options) else {
        return Ok(None);
    };
    apply_selected_baseline(project_root, &baseline_path, source, findings).map(Some)
}

fn generate_baseline_report(
    project_root: &Path,
    path: &Path,
    findings: &[Finding],
) -> Result<BaselineReport, String> {
    let baseline_path = absolutize(project_root, path);
    write_baseline(&baseline_path, findings)?;
    Ok(BaselineReport {
        path: display_path(project_root, &baseline_path),
        source: "generated".to_string(),
        suppressed: 0,
        generated: true,
    })
}

fn select_baseline_path(
    project_root: &Path,
    options: &AnalysisOptions,
) -> Option<(PathBuf, &'static str)> {
    if let Some(path) = options.baseline.as_ref() {
        return Some((absolutize(project_root, path), "explicit"));
    }
    let default = project_root.join(DEFAULT_BASELINE);
    default.exists().then_some((default, "default"))
}

fn apply_selected_baseline(
    project_root: &Path,
    baseline_path: &Path,
    source: &str,
    findings: &mut Vec<Finding>,
) -> Result<BaselineReport, String> {
    let before = findings.len();
    apply_baseline(baseline_path, findings)?;
    Ok(BaselineReport {
        path: display_path(project_root, baseline_path),
        source: source.to_string(),
        suppressed: before.saturating_sub(findings.len()),
        generated: false,
    })
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
        ReportInputs {
            discovery,
            diagnostics,
            findings,
            baseline_report,
            suppressions,
        },
    );
    let mut report = apply_diff_selection(project_root, options, report, &analysed_paths)?;
    record_history_if_requested(project_root, options, &mut report);
    Ok(report)
}

pub(crate) fn apply_git_diff_selection(
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

pub(crate) fn analysed_display_paths(files: &[SourceFile]) -> BTreeSet<String> {
    files.iter().map(|file| file.display_path.clone()).collect()
}

pub(crate) fn analyse_discovered_sources(
    project_root: &Path,
    files: &[SourceFile],
    config: &Config,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Vec<Finding> {
    let capabilities = AnalysisCapabilities::from_config(config);
    let (parsed_sources, read_diagnostics) =
        crate::project::read_and_parse_sources_with_options(files, capabilities.parse_rust);
    diagnostics.extend(read_diagnostics);

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
    findings
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

pub(crate) fn apply_diff_selection(
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
    if !patch_text.trim().is_empty() && !patch.saw_hunk {
        return Err(
            "--diff-patch input is not a parseable unified diff; refusing to suppress findings."
                .to_string(),
        );
    }
    Ok(apply_diff_patch_filter(report, &patch, analysed_paths))
}

pub(crate) fn record_history_if_requested(
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

pub(crate) struct ReportInputs {
    pub(crate) discovery: DiscoveryResult,
    pub(crate) diagnostics: Vec<RunDiagnostic>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) baseline_report: Option<BaselineReport>,
    pub(crate) suppressions: ReportSuppressions,
}

pub(crate) fn build_report(
    project_root: &Path,
    options: &AnalysisOptions,
    inputs: ReportInputs,
) -> AnalysisReport {
    let ReportInputs {
        discovery,
        diagnostics,
        findings,
        baseline_report,
        suppressions,
    } = inputs;
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
