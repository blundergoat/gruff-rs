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

pub(crate) fn exclusion_matches_finding(exclusion: &ExclusionRule, finding: &Finding) -> bool {
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
