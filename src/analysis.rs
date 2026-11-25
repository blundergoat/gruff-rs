//! Project analysis reads selected files, runs rule families, and assembles report evidence.
//!
//! A developer can scan a directory or name individual files.
//! External test-module ownership is proved only from the selected, parsed directory scan.

use super::*;

/// Turn each requested input path that does not exist into a `missing-path` diagnostic for the report.
///
/// `missing_paths` holds the requested paths that discovery could not find.
/// Returns one diagnostic per entry, in input order, naming the path in its message and file; an empty slice yields an empty list.
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

/// Warn about each Security or SensitiveData built-in rule set to `excludeFromScore: true`, so the score exclusion stays visible.
/// Config rejects this option on custom rules. Built-in warnings follow rule ID order so report diffs stay useful.
///
/// `config` supplies the per-rule settings to inspect.
/// Returns one `excluded-security-rule-from-score` diagnostic per such rule, sorted by rule id; with none configured the list is empty.
fn excluded_security_rule_diagnostics(config: &Config) -> Vec<RunDiagnostic> {
    let mut ids = collect_excluded_security_rule_ids(config);
    ids.sort_by_key(|(rule_id, _)| *rule_id);
    ids.into_iter()
        .map(|(rule_id, pillar)| excluded_security_rule_diagnostic(rule_id, pillar))
        .collect()
}

/// Find the built-in Security and SensitiveData rules whose settings set `excludeFromScore` to true.
///
/// `config` supplies the per-rule settings; a rule id the built-in registry does not know is skipped.
/// Returns each matching rule id with its pillar, unsorted; no match yields an empty list.
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

/// Build the warning that one score-excluded Security or SensitiveData rule still reports findings but no longer affects the composite score.
///
/// `rule_id` is the rule named in the message and `pillar` is its pillar, printed in debug form beside it.
/// Returns an `excluded-security-rule-from-score` diagnostic with no file, no line and no run-invalidation flag.
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

/// Order findings deterministically for the report and drop repeats that share a fingerprint.
///
/// `findings` is sorted in place by file path, line (a missing line sorts as 0), rule id and message.
/// Consecutive entries with equal fingerprints then collapse to the first; equal fingerprints the sort leaves apart both stay.
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

/// The one rule the family's built-in lockfile skip covers; every other sensitive-data rule still reads a lockfile.
const BUILT_IN_LOCKFILE_RULE: &str = "sensitive-data.high-entropy-string";

/// The rationale every port publishes on a built-in lockfile audit row.
const BUILT_IN_LOCKFILE_REASON: &str = "Lockfile digests are published integrity hashes, so the entropy rule skips package-manager lockfiles by name.";

/// The ratified package-manager lockfile names, matched by exact base name at any depth.
const BUILT_IN_LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "Cargo.lock",
    "go.sum",
    "uv.lock",
    "poetry.lock",
];

/// Remove the findings both suppression channels claim and count every configured entry.
/// The returned summaries carry `exclude` rows first, then `sensitiveExclusions` rows, then built-in rows.
///
/// `findings` holds the findings to filter, and each one goes to the first channel that claims it, in the row order above.
/// `exclusions` and `sensitive_exclusions` are the configured `exclude` and `sensitiveExclusions` entries.
/// Returns the kept findings, the audit rows with their counts, and each suppressed finding paired with the row that claimed it.
pub(crate) fn apply_report_exclusions(
    findings: Vec<Finding>,
    exclusions: &[ExclusionRule],
    sensitive_exclusions: &[SensitiveExclusionRule],
) -> (
    Vec<Finding>,
    Vec<SuppressionSummary>,
    Vec<SuppressedFinding>,
) {
    // The built-in lockfile skip runs whether or not the user configured anything, so there is no early return.
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
    // A configured entry claims its findings first, so its count stays what the user wrote it for.
    let (kept, lockfile_suppressed) = partition_built_in_lockfile_findings(kept, &mut summaries);
    suppressed.extend(lockfile_suppressed);
    // The lockfile skip runs first, so `tests/Cargo.lock` gets one audit row, not two.
    let (kept, test_path_suppressed) = partition_built_in_test_path_findings(kept, &mut summaries);
    suppressed.extend(test_path_suppressed);
    (kept, summaries, suppressed)
}

/// Remove the entropy rule's findings from package-manager lockfiles and append one audit row per lockfile that
/// had any, after the configured rows.
///
/// A lockfile has legitimate integrity hashes, so its high-entropy findings are counted and suppressed under `FAMILY-CONTRACT.md` section 13a.
/// A file with no such finding gets no audit row. More specific sensitive-data rules can still report on that file.
///
/// `findings` holds the findings still to filter; `summaries` gains one row per lockfile in path order, indexed from 0.
/// Returns the kept findings and each skipped finding paired with its lockfile's row; with nothing skipped, `summaries` is unchanged.
fn partition_built_in_lockfile_findings(
    findings: Vec<Finding>,
    summaries: &mut Vec<SuppressionSummary>,
) -> (Vec<Finding>, Vec<SuppressedFinding>) {
    let mut kept = Vec::with_capacity(findings.len());
    let mut skipped: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for finding in findings {
        if finding.rule_id == BUILT_IN_LOCKFILE_RULE && is_built_in_lockfile(&finding.file_path) {
            skipped
                .entry(finding.file_path.clone())
                .or_default()
                .push(finding);
            continue;
        }
        kept.push(finding);
    }
    let mut suppressed = Vec::new();
    // Built-in rows are numbered among themselves, so the index means the same thing in every port however many
    // entries the user configured, and it keeps this port's section-local numbering. `source` is what tells a
    // consumer which channel a row came from.
    for (built_in_index, (lockfile, lockfile_findings)) in skipped.into_iter().enumerate() {
        let summary = SuppressionSummary {
            index: built_in_index,
            rule: BUILT_IN_LOCKFILE_RULE.to_string(),
            paths: vec![lockfile],
            message_contains: None,
            symbol: None,
            reason: BUILT_IN_LOCKFILE_REASON.to_string(),
            suppressed: lockfile_findings.len(),
            source: Some("built-in"),
            config_key: "builtInLockfile",
        };
        for finding in lockfile_findings {
            suppressed.push(SuppressedFinding {
                finding,
                suppression: summary.clone(),
            });
        }
        summaries.push(summary);
    }
    (kept, suppressed)
}

/// Decide whether a path's base name is one of the ratified package-manager lockfiles.
///
/// `file_path` is a finding's path; backslashes count as separators and the base name must match exactly, including case.
/// Returns true when the base name is on the lockfile list, at any depth, and false otherwise.
fn is_built_in_lockfile(file_path: &str) -> bool {
    let normalized = file_path.replace('\\', "/");
    let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);
    BUILT_IN_LOCKFILE_NAMES.contains(&file_name)
}

/// Reasons on each `builtInTestPath[...]` audit row, indexed by `usize::from(security)`: the sensitive-data reason at 0
/// and the security reason at 1, which says a test calls insecure APIs on purpose. Every port publishes these exact
/// words (FAMILY-CONTRACT.md section 13a), so reordering the array swaps the reason on every row.
const BUILT_IN_TEST_PATH_REASONS: [&str; 2] = [
    "Test, fixture and example files hold sample credentials, so sensitive-data rules skip them by path.",
    "Test, fixture and example files exercise insecure calls on purpose, so security rules skip them by path.",
];

/// The one sensitive-data rule that still reads test paths, because finding realistic personal data in fixtures is its job.
const BUILT_IN_TEST_PATH_EXEMPT_RULE: &str = "sensitive-data.pii-test-fixture";

/// Directory names, compared case-insensitively, that make a path test code, e.g. `tests/` or `Fixtures/`.
const BUILT_IN_TEST_PATH_DIRECTORIES: &[&str] = &[
    "test",
    "tests",
    "__tests__",
    "spec",
    "testdata",
    "fixtures",
    "examples",
];

/// Matches a whole base name that marks a test file in any family language, e.g. `keys_test.go` or `login.spec.ts`.
const BUILT_IN_TEST_FILE_NAME_PATTERN: &str = r"^(?:.*_test\.go|test_.*\.py|.*_test\.py|.*Test\.php|.*\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs))$";

static BUILT_IN_TEST_FILE_NAME_REGEX: OnceLock<Regex> = OnceLock::new();

/// Hide sensitive-data and security findings in test, fixture and example files, and publish one audit row per hidden file and rule.
///
/// A user scanning a project with sample keys or a deliberate `Command::new("sh")` in `tests/fixtures/` sees
/// `builtInTestPath[...]` rows instead of findings. The skip is never silent, and the fixture-PII rule keeps reading
/// these files (FAMILY-CONTRACT.md section 13a).
///
/// `findings` holds the findings still to filter; `summaries` gains one row per file and rule, indexed after the built-in rows it already holds.
/// Here sensitive-data means a rule id starting `sensitive-data.` and security means the Security pillar; fixture-PII stays exempt.
/// Returns the kept findings and each skipped finding paired with its row; with nothing skipped, `summaries` is unchanged.
fn partition_built_in_test_path_findings(
    findings: Vec<Finding>,
    summaries: &mut Vec<SuppressionSummary>,
) -> (Vec<Finding>, Vec<SuppressedFinding>) {
    let (kept, skipped_by_file_and_rule) = split_test_path_findings(findings);
    // Built-in rows are numbered among themselves, so the first test-path row follows the last lockfile row.
    let first_index = summaries
        .iter()
        .filter(|summary| summary.source.is_some())
        .count();
    let mut suppressed = Vec::new();
    // One row per file and rule, which text output shows as `builtInTestPath[tests/keys.rs] sensitive-data.aws-access-key: 2`.
    for (offset, ((file_path, rule_id), skipped_findings)) in
        skipped_by_file_and_rule.into_iter().enumerate()
    {
        let security = skipped_findings
            .iter()
            .any(|item| matches!(item.pillar, Pillar::Security));
        let summary = SuppressionSummary {
            index: first_index + offset,
            rule: rule_id,
            paths: vec![file_path],
            message_contains: None,
            symbol: None,
            reason: BUILT_IN_TEST_PATH_REASONS[usize::from(security)].to_string(),
            suppressed: skipped_findings.len(),
            source: Some("built-in"),
            config_key: "builtInTestPath",
        };
        for finding in skipped_findings {
            suppressed.push(SuppressedFinding {
                finding,
                suppression: summary.clone(),
            });
        }
        summaries.push(summary);
    }
    (kept, suppressed)
}

/// Sensitive-data and security findings in test code, grouped by (path, rule); a BTreeMap orders the keys by UTF-8 bytes, as every port does.
type TestPathFindingsByFileAndRule = BTreeMap<(String, String), Vec<Finding>>;

/// Split findings into the ones the report keeps and the skipped findings in test code, grouped by file and rule.
///
/// A finding in `findings` is skipped on a test path when it is Security-pillar or its rule id starts `sensitive-data.`, except fixture-PII.
/// Returns the kept findings in input order and the skipped ones keyed by path and rule in byte order; either side may be empty.
fn split_test_path_findings(
    findings: Vec<Finding>,
) -> (Vec<Finding>, TestPathFindingsByFileAndRule) {
    let mut kept = Vec::with_capacity(findings.len());
    let mut skipped_by_file_and_rule = TestPathFindingsByFileAndRule::new();
    // Each finding either stays in the report or is folded into its file's audit row.
    for finding in findings {
        // Every security-pillar finding, `dependency.git-source` included, and every sensitive-data finding but the
        // fixture-PII rule's is skipped in test code.
        let skipped_rule = (matches!(finding.pillar, Pillar::Security)
            && !finding.rule_id.starts_with("custom."))
            || (finding.rule_id.starts_with("sensitive-data.")
                && finding.rule_id != BUILT_IN_TEST_PATH_EXEMPT_RULE);
        if skipped_rule && is_built_in_test_path(&finding.file_path) {
            skipped_by_file_and_rule
                .entry((finding.file_path.clone(), finding.rule_id.clone()))
                .or_default()
                .push(finding);
            continue;
        }
        kept.push(finding);
    }
    (kept, skipped_by_file_and_rule)
}

/// Decide whether a finding's file is test, fixture or example code, e.g. `tests/fixtures/keys.json` or `keys_test.go`.
///
/// `file_path` is the finding's path, with backslashes read as separators; any listed directory name, in any letter case, marks test code.
/// Returns true for such a directory on the path or a base name matching the family test-file pattern, and false otherwise.
fn is_built_in_test_path(file_path: &str) -> bool {
    let normalized = file_path.replace('\\', "/");
    let mut segments: Vec<&str> = normalized.split('/').collect();
    let file_name = segments.pop().unwrap_or_default();
    // Any directory on the path, compared case-insensitively, or the file name alone can mark test code.
    segments.iter().any(|directory| {
        BUILT_IN_TEST_PATH_DIRECTORIES.contains(&directory.to_ascii_lowercase().as_str())
    }) || static_regex(
        &BUILT_IN_TEST_FILE_NAME_REGEX,
        BUILT_IN_TEST_FILE_NAME_PATTERN,
    )
    .is_match(file_name)
}

/// Build the zero-count audit row for each configured `exclude` entry before any finding is matched.
///
/// `exclusions` holds the configured entries; each row copies an entry's selector, paths, message filter and reason, indexed by its position.
/// Returns one row per entry in order, with no symbol, no source and the `exclude` config key; no entries yield an empty list.
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
            // A configured row names no source; only the built-in lockfile skip does.
            source: None,
            config_key: "exclude",
        })
        .collect()
}

/// Publish one audit row per sensitive exclusion, including entries that match nothing.
/// A zero count is a valid result, so a fixed fixture never breaks the user's build.
///
/// `sensitive_exclusions` holds the configured `sensitiveExclusions` entries; each row takes an entry's rule, single path, symbol and reason.
/// Returns one zero-count row per entry, indexed by position, with no source and no message filter; no entries yield an empty list.
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
            // A configured row names no source; only the built-in lockfile skip does.
            source: None,
            config_key: "sensitiveExclusions",
        })
        .collect()
}

/// Remove the findings a configured `exclude` entry claims and count each entry's matches in its audit row.
///
/// `findings` holds the findings to filter and `exclusions` the configured entries; a finding goes to the first entry that matches it.
/// `summaries` holds the entries' rows in the same order, and each match raises that row's `suppressed` count.
/// A match on an entry with no row in `summaries` panics on the index.
///
/// Returns the unmatched findings and each matched finding paired with a copy of its row, whose count is the running total at that match.
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

/// Decide whether one configured `exclude` entry covers one finding.
///
/// `exclusion` supplies the rule ids and optional message substring, and `path_matchers` its compiled path patterns.
/// `finding` is the finding under test, compared in normalised report form; sensitive-data findings are never matched here.
/// Returns true when `finding` is non-sensitive and matches the rule id, path filter (if any), and message substring (if set).
fn exclusion_matches_finding_with_paths(
    exclusion: &ExclusionRule,
    path_matchers: &[PathMatcher],
    finding: &Finding,
) -> bool {
    // Keep sensitive-data findings exclusively in `sensitiveExclusions`, even if a caller builds `Config` without the loader.
    if matches!(finding.pillar, Pillar::SensitiveData)
        || finding.rule_id.starts_with("sensitive-data.")
    {
        return false;
    }
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
///
/// `findings` holds the findings to filter and `sensitive_exclusions` the declared scopes; a finding goes to the first scope that matches it.
/// `summaries` holds the scopes' rows in the same order; each match raises its row's `suppressed` count, and a match with no row panics.
/// Returns the unmatched findings and each matched finding paired with a copy of its row, whose count is the running total at that match.
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
///
/// `exclusion` gives the scope's rule id, report path and optional symbol, and `finding` is the finding under test.
/// Returns true when the rule ids are equal, the finding's normalised path equals the scope's path, and the symbol matches if one is named.
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

/// Analyse the selected sources under a project root and assemble the report, recording history when the options ask for it.
///
/// `project_root` is where discovery and diff resolution start, and `config` supplies the rule settings.
/// `options` carries the requested paths, diff selection, baseline settings, output format and optional history file.
/// Returns the report, whose diagnostics include missing paths and score-excluded security rules; Err holds a diff or baseline failure.
pub(crate) fn run_analysis_in_project(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
) -> Result<AnalysisReport, RunFailure> {
    let mut discovery = discover_sources(project_root, options, config);
    let mut diagnostics = missing_path_diagnostics(&discovery.missing_paths);
    diagnostics.extend(excluded_security_rule_diagnostics(config));
    let diff_filter = resolve_diff_filter(project_root, options, &discovery.files)
        .map_err(RunFailure::ChangedRegion)?;
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
    )
    .map_err(RunFailure::Baseline)?;
    let mut report = build_report(project_root, options, config, inputs);
    if matches!(options.format, OutputFormat::Json) {
        machine_contract::validate_required_paths(&report).map_err(RunFailure::ReportPath)?;
    }
    record_history_if_requested(project_root, options, config, &mut report);
    Ok(report)
}

/// Append the gate's diagnostic to the report, or a `gate-config-error` diagnostic when the gate's scope precondition fails.
///
/// `report` is the finished report whose diagnostics gain one entry, and `gate` is the configured gate; None leaves the report unchanged.
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

/// Analyse the discovered sources, meet the baseline and apply suppressions to gather everything `build_report` needs.
///
/// `project_root` roots the analysis, baseline and suppressions, and `config` supplies the rule and suppression settings.
/// `options` selects the baseline and diff behaviour, and `discovery` lists the selected sources and moves into the inputs.
///
/// `diagnostics` holds the diagnostics so far, to which source, project and baseline-collision diagnostics are added.
/// `coverage` describes which Rust files the scan covered, and `diff_filter`, when set, narrows the inputs to the changed region.
/// Returns the report inputs; Err holds the message when the baseline cannot be resolved.
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
    let (findings, function_blocks_by_file) =
        analysed_findings(project_root, config, &discovery, coverage, &mut diagnostics);
    // Apply configured, built-in, and inline suppressions before baseline matching or generation.
    // This keeps explicit exclusions ahead of baseline states and out of newly generated baselines (`baseline.v3.json`).
    let (mut findings, summaries, suppressed_findings) =
        crate::inline_suppressions::apply_all_suppressions(findings, config, project_root);
    let all_findings = findings.clone();
    let excluded_identities = baseline::excluded_baseline_identities(&suppressed_findings);
    let (baseline_report, per_rule_deltas, all_findings_summary) = resolve_run_baseline(
        project_root,
        options,
        &mut findings,
        &function_blocks_by_file,
        &excluded_identities,
        &mut diagnostics,
    )?;
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

/// Run the rules over the discovered sources and hand back the named findings and the parsed functions.
///
/// `project_root`, `config` and `discovery` give the root, rule settings and selected files; `coverage` says which Rust files the scan covered.
/// `diagnostics` gains every source-read, parse and project-context diagnostic.
/// Returns the sorted, deduplicated and named findings and the parsed functions keyed by display path.
fn analysed_findings(
    project_root: &Path,
    config: &Config,
    discovery: &DiscoveryResult,
    coverage: ProjectCoverage,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> (Vec<Finding>, BTreeMap<String, Vec<FunctionBlock>>) {
    let AnalysisArtifacts {
        mut findings,
        function_blocks_by_file,
    } = analyse_discovered_sources_with_artifacts(
        project_root,
        &discovery.files,
        config,
        coverage,
        // Every run keeps the parsed functions: the baseline identity names a finding by the function it sits
        // on and counts every same-named function, which an empty map would reduce to ranking findings by line.
        true,
        diagnostics,
    );
    sort_and_dedupe_findings(&mut findings);
    // Naming every finding before suppressions or the baseline filter any of them keeps one alert one alert:
    // code scanning reads the same identity the baseline does, and excluded siblings preserve full-file ordinals.
    name_findings(&mut findings, &function_blocks_by_file);
    (findings, function_blocks_by_file)
}

/// Attach each ordinary finding's durable identity, which SARIF publishes as its code-scanning fingerprint.
///
/// A sensitive finding is left unnamed, because it has no durable identity at all; a finding this run cannot name
/// keeps `None` and is published without a fingerprint rather than with a guessed one.
///
/// `findings` is updated in place: each one's baseline identity and subject are set together, or both cleared when it cannot be named.
/// `blocks_by_file` holds each file's parsed functions, which supply declaration positions and same-named function lines.
/// If the identities cannot be computed, every finding is left as it was.
fn name_findings(findings: &mut [Finding], blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>) {
    let declaration_position = declaration_position_from_blocks(blocks_by_file);
    let same_named = same_named_lines_from_blocks(blocks_by_file);
    let Ok(identities) =
        finding_identities_with_inventory(findings, &declaration_position, Some(&same_named))
    else {
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

/// Pack the suppression audit rows and the suppressed findings into the report's suppression section.
///
/// `summaries` holds the audit rows and `suppressed_findings` each suppressed finding with the row that claimed it.
/// Returns both lists unchanged inside one `ReportSuppressions`.
fn report_suppressions(
    summaries: Vec<SuppressionSummary>,
    suppressed_findings: Vec<SuppressedFinding>,
) -> ReportSuppressions {
    ReportSuppressions {
        summaries,
        suppressed_findings,
    }
}

/// Apply a caller's changed-code scope to findings, suppressions, and counts before building the final report.
/// An absent diff filter keeps the whole result. Discovery and baseline metadata still describe what the run used.
///
/// `project_root`, `options` and `config` rebuild the report from `inputs`, and `diff_filter` supplies the patch and changed-region scope.
/// `analysed_paths` lists the analysed files; `function_blocks_by_file` holds the parsed functions the changed-region filter reads.
/// Returns the filtered inputs, with the all-findings summary recounted for the changed scope; with no `diff_filter`, `inputs` itself.
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

/// Describe the diff that narrowed this run for the report's machine context.
///
/// `options` supplies the requested diff selection and `diff_filter` the resolved filter whose patch lists the changed files.
/// Returns the diff mode and the changed files, or None when either the filter or the selection is absent.
/// The mode is `stdin` for a patch read from `-`, `patch` for a patch file, `changed-ranges` for explicit ranges, or the git mode as given.
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

/// Summarise the pre-baseline findings under the diff filter's changed-region scope for the report's all-findings summary.
///
/// `all_findings` holds the findings before baseline and suppression, and `diff_filter` gives the patch and the scope.
/// `function_blocks_by_file` holds the parsed functions by file, passed through to the changed-findings summary.
/// Returns the `Summary` that `summarize_changed_findings` computes for the changed scope.
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
/// Eligible findings with a usable symbol are named by rule, file, symbol and declaration ordinal, so findings of one rule that name one
/// function share an identity while a same-named function gets another ordinal, which keeps one review from covering both.
///
/// `project_root` and `options` locate the baseline; applying it can drop entries from `findings` and sets `baseline_status` on the rest.
/// `function_blocks_by_file` supplies declaration positions, and `excluded_identities` keeps counts for findings an `exclude` entry removed.
/// `diagnostics` gains one `baseline-collision` entry per collision.
///
/// Returns the report section, per-rule deltas and pre-baseline summary; Err holds a resolution failure.
/// Both sections are None without a baseline, and the deltas are also None for a generated baseline or an empty delta list.
fn resolve_run_baseline(
    project_root: &Path,
    options: &AnalysisOptions,
    findings: &mut Vec<Finding>,
    function_blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
    excluded_identities: &BTreeMap<String, usize>,
    diagnostics: &mut Vec<RunDiagnostic>,
) -> Result<RunBaseline, String> {
    let position = declaration_position_from_blocks(function_blocks_by_file);
    let (resolution, summary) = resolve_baseline(
        project_root,
        options,
        findings,
        &position,
        excluded_identities,
    )?;
    let (report, deltas, collisions) = split_baseline_resolution(resolution);
    diagnostics.extend(baseline::collision_diagnostics(&collisions));
    Ok((report, deltas, summary))
}

/// Unpack a baseline resolution into its report section, its per-rule deltas and the collisions it found.
///
/// `resolution` is the baseline outcome, or None when the run produced none.
/// Returns the report and collisions as given, plus the deltas only when the report is not freshly generated and the list is non-empty.
/// A None `resolution` returns None for both sections and no collisions.
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

/// Collect the display path of every analysed source file, Rust or not.
///
/// `files` holds the discovered sources.
/// Returns the distinct display paths in sorted order; no files yield an empty set.
pub(crate) fn analysed_display_paths(files: &[SourceFile]) -> BTreeSet<String> {
    files.iter().map(|file| file.display_path.clone()).collect()
}

/// Collect the display paths of the Rust sources among the discovered files.
///
/// `files` holds the discovered sources; only those flagged as Rust count.
/// Returns the distinct Rust display paths in sorted order, empty when no file is Rust.
fn rust_display_paths(files: &[SourceFile]) -> BTreeSet<String> {
    files
        .iter()
        .filter(|file| file.is_rust)
        .map(|file| file.display_path.clone())
        .collect()
}

/// Compare the Rust files this run analyses with those a whole-project scan would find, so later steps can spot a partial scan.
///
/// `project_root`, `options` and `config` drive a rediscovery of the whole project, done only when the unused-private-item rule is enabled.
/// `discovery` holds this run's files after diff selection, `pre_diff_rust_paths` its Rust paths before it, and `diff_filter` the resolved diff.
///
/// Returns the analysed and discoverable Rust paths, flagged as diff-narrowed when a diff that is not explicit ranges dropped Rust files.
/// With the rule off, both sets hold the analysed paths and nothing is flagged; `parse_incomplete` is always false here.
fn project_coverage(
    project_root: &Path,
    options: &AnalysisOptions,
    config: &Config,
    discovery: &DiscoveryResult,
    pre_diff_rust_paths: &BTreeSet<String>,
    diff_filter: Option<&ResolvedDiffFilter>,
) -> ProjectCoverage {
    let analysed_rust_files = rust_display_paths(&discovery.files);
    let needs_universe = config.is_rule_enabled("dead-code.unused-private-item-candidate")
        || config.is_rule_enabled("waste.unwrap-expect");
    // Without the two rules that reason across the whole crate, the scanned files are all the coverage the report needs.
    if !needs_universe {
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

/// Find every Rust source a whole-project scan would discover, regardless of the paths and diff this run requested.
///
/// `project_root` is where discovery starts and `config` supplies its settings.
/// `options` is cloned with its paths replaced by `.` and its diff cleared, so every other discovery option still applies.
/// Returns the sorted Rust display paths found, empty when the project has none.
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

/// Check whether a caller's targets cover enough of the project to run project-wide rules in a test.
///
/// `project_root`, `options`, and `config` describe the requested scan and discovery policies.
/// Returns project coverage, or the diagnostic for an invalid diff selection.
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

/// Evidence retained after reading the requested sources.
///
/// Findings feed the report. Parsed function blocks let a baseline or changed-symbol scan tie a finding to its declaration.
/// The block map stays empty when a caller does not request it.
pub(crate) struct AnalysisArtifacts {
    pub(crate) findings: Vec<Finding>,
    pub(crate) function_blocks_by_file: BTreeMap<String, Vec<FunctionBlock>>,
}

/// Analyze the selected sources and retain optional function evidence for the report.
///
/// `project_root` roots project-wide checks, `files` are the sources to read, and `config` selects rules and the deep-scan budget.
/// `coverage` proves external test ownership, `retain_function_blocks` keeps parsed functions, and `diagnostics` collects errors.
///
/// Returns unsorted project and per-file findings plus parsed function blocks keyed by display path (empty when `retain_function_blocks` is false).
pub(crate) fn analyse_discovered_sources_with_artifacts(
    project_root: &Path,
    files: &[SourceFile],
    config: &Config,
    mut coverage: ProjectCoverage,
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
    // Reflect unreadable, unparsed, or budget-bounded Rust files before proving external test ownership.
    let parsed_rust_paths: BTreeSet<&str> = parsed_sources
        .iter()
        .filter(|parsed_source| parsed_source.file.is_rust && parsed_source.rust_ast.is_some())
        .map(|parsed_source| parsed_source.file.display_path.as_str())
        .collect();
    coverage.parse_incomplete |= coverage
        .analysed_rust_files
        .iter()
        .any(|path| !parsed_rust_paths.contains(path.as_str()));
    let mut blocks_by_file = BTreeMap::new();
    let external_tests = source_proven_external_test_modules(&parsed_sources, &coverage);
    // Skip building project-wide graphs when the caller selected only single-file rules.
    let mut findings = if capabilities.project_context {
        let context = build_project_context(project_root, &parsed_sources, coverage);
        diagnostics.extend(context.diagnostics.iter().cloned());
        analyse_project(&context, config, diagnostics)
    } else {
        Vec::new()
    };
    // Each selected file receives only test ownership proved by another selected Rust source.
    for parsed in &parsed_sources {
        let unit = parsed.as_source_unit(external_tests.contains(&parsed.file.display_path));
        let artifacts = crate::analyse_source_with_artifacts(&unit, config, retain_function_blocks);
        // Keep parsed function spans when baselines or changed-symbol filters need declaration matching.
        if let Some(blocks) = artifacts.function_blocks {
            blocks_by_file.insert(parsed.file.display_path.clone(), blocks);
        }
        findings.extend(artifacts.findings);
        diagnostics.extend(parsed.diagnostics.iter().cloned());
    }
    AnalysisArtifacts {
        findings,
        function_blocks_by_file: blocks_by_file,
    }
}

/// Find external `tests.rs` modules whose selected parent compiles them only for tests.
/// Partial and single-file scans keep production warnings because their module owner is unproved.
///
/// `sources` holds the parsed sources, and a partial `coverage` returns an empty set at once.
/// Returns the display paths of directory-scanned, parsed files that exactly one declaration claims, when that declaration is test-only.
fn source_proven_external_test_modules(
    sources: &[ParsedSource],
    coverage: &ProjectCoverage,
) -> BTreeSet<String> {
    // A narrowed scan may omit a production owner for the same source file.
    if coverage.is_partial() {
        return BTreeSet::new();
    }
    let selected_rust_paths: BTreeSet<&str> = sources
        .iter()
        .filter(|source| source.file.origin == SourceOrigin::Directory && source.rust_ast.is_some())
        .map(|source| source.file.display_path.as_str())
        .collect();
    let mut module_declarations: BTreeMap<String, Vec<bool>> = BTreeMap::new();
    // Every selected parent contributes its ownership claim before any test-file warning is removed.
    for parent in sources {
        if let Some((child_path, declarations)) = external_test_declarations(parent) {
            module_declarations
                .entry(child_path)
                .or_default()
                .extend(declarations);
        }
    }

    module_declarations
        .into_iter()
        .filter(|(path, declarations)| {
            selected_rust_paths.contains(path.as_str())
                && declarations.len() == 1
                && declarations[0]
        })
        .map(|(path, _)| path)
        .collect()
}

/// Read only direct crate-root or `mod.rs` declarations for their sibling `tests.rs`.
/// A path override or another owner makes the user's test-only ownership claim ambiguous.
///
/// `parent` is a parsed source, considered only when it is a directory-scanned `main.rs`, `lib.rs` or `mod.rs` with a syntax tree.
/// Returns the sibling `tests.rs` path and one flag per out-of-line module named `tests` or carrying a `path` or `cfg_attr` attribute.
/// A flag is true only for `mod tests` with a test cfg and no such attribute; None when the parent does not qualify or declares no such module.
fn external_test_declarations(parent: &ParsedSource) -> Option<(String, Vec<bool>)> {
    // An explicitly named file may have an unseen production owner.
    if parent.file.origin != SourceOrigin::Directory {
        return None;
    }
    // A source without parsed Rust cannot prove the declaration the user wrote.
    let Some(ast) = &parent.rust_ast else {
        return None;
    };
    let parent_path = Path::new(&parent.file.display_path);
    // Other module files have different child-path rules, so their ownership stays unproved.
    if !matches!(
        parent_path.file_name().and_then(|name| name.to_str()),
        Some("main.rs" | "lib.rs" | "mod.rs")
    ) {
        return None;
    }
    let child_path =
        normalize_report_path(&parent_path.with_file_name("tests.rs").to_string_lossy());
    let mut declarations = Vec::new();
    // Only external declarations can assign this file; inline modules remain local to the parent.
    for item in &ast.items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        // An inline module does not make a separate `tests.rs` file test-only.
        if module.content.is_some() {
            continue;
        }
        let has_path_override = module
            .attrs
            .iter()
            .any(|attr| attr.path().is_ident("path") || attr.path().is_ident("cfg_attr"));
        // A custom path may assign `tests.rs` to another production module.
        if module.ident != "tests" && !has_path_override {
            continue;
        }
        let test_only =
            module.ident == "tests" && !has_path_override && has_cfg_test_attr(&module.attrs);
        declarations.push(test_only);
    }
    (!declarations.is_empty()).then_some((child_path, declarations))
}

/// Work needed to honour the selected rules.
///
/// A caller who selects only text rules can finish without parsing Rust.
/// Project-wide rules can request the additional context needed to report results across files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AnalysisCapabilities {
    parse_rust: bool,
    project_context: bool,
}

impl AnalysisCapabilities {
    /// Work out from the enabled rules whether the run must parse Rust and build the project context.
    ///
    /// `config` says which built-in and custom rules are enabled.
    /// Returns the capabilities the enabled built-in rules need; custom rules add none, and both stay false when no rule needs them.
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

    /// Turn on the capabilities one enabled built-in rule needs.
    ///
    /// `definition` is the enabled rule: a project rule turns on Rust parsing and the project context, and a Rust rule turns on parsing.
    /// A text rule turns on parsing only when it needs the syntax tree; no rule ever turns a capability off.
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

    /// Account for one enabled custom rule, whose every scope leaves the run's capabilities unchanged.
    ///
    /// `rule` is the custom rule; matching on its scope means a new scope will not compile until it is handled here.
    fn include_custom_rule(&mut self, rule: &CustomRule) {
        match rule.scope {
            CustomRuleScope::Text | CustomRuleScope::RustCode | CustomRuleScope::Comments => {}
        }
    }
}

/// Private-key findings read the syntax tree to prove a header-only constant is a native format detector,
/// so a run that selects only text rules still parses Rust when it includes this one.
///
/// `rule_id` is the id of the text rule being considered.
/// Returns true only for `sensitive-data.private-key`.
fn text_rule_needs_rust_ast(rule_id: &str) -> bool {
    rule_id == "sensitive-data.private-key"
}

/// Record this run's finding count and composite score in the history file when the options name one, and do nothing otherwise.
///
/// `project_root` and `config` are passed to the history writer, and `options` names the history file, if any.
/// `report` supplies the findings and evaluated-file count, and its diagnostics may gain entries from the history writer.
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

/// Gather the scan results needed to assemble a report.
///
/// Findings, diagnostics, and suppressions explain what happened. Discovery records what the run could see.
/// Baseline and changed-region sections are present when the caller requested those comparisons.
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

/// Build the report's run block from the project root, the options and the current time.
///
/// `project_root` is shown as given, and `options` supplies the output format and fail-on level.
/// Returns the run info, stamped with the current UTC time in RFC 3339 form.
fn report_run_info(project_root: &Path, options: &AnalysisOptions) -> RunInfo {
    RunInfo {
        project_root: project_root.display().to_string(),
        format: options.format.as_str().to_string(),
        fail_on: options.fail_on.as_str().to_string(),
        generated_at: Utc::now().to_rfc3339(),
    }
}

/// Turn the discovery result into the report's path section.
///
/// `discovery` is consumed for its file count, ignored paths with their details, and missing paths.
/// Returns the path summary with the number of analysed files and those three lists moved in unchanged.
fn report_path_summary(discovery: DiscoveryResult) -> PathSummary {
    PathSummary {
        analysed_files: discovery.files.len(),
        ignored_paths: discovery.ignored_paths,
        ignored_path_details: discovery.ignored_path_details,
        missing_paths: discovery.missing_paths,
    }
}

/// Build the v3 envelope a run that could not start still owes a caller who asked for a machine format.
///
/// A run that never started has no findings and nothing discovered, so the envelope carries one
/// run-invalidating diagnostic and empty everything else. Printing only to stderr would leave a JSON consumer
/// with no diagnostic, no type and no run block to read, where every other port publishes all three.
///
/// `project_root` and `options` fill the run block and machine context.
/// `error` supplies the diagnostic category and message.
/// Returns the report with that single run-invalidating diagnostic and no findings, discovered paths, suppressions, baseline or deltas.
pub(crate) fn failed_run_report(
    project_root: &Path,
    options: &AnalysisOptions,
    error: &RunFailure,
) -> AnalysisReport {
    let mut report = build_report(
        project_root,
        options,
        &Config::default(),
        ReportInputs {
            discovery: DiscoveryResult {
                files: Vec::new(),
                missing_paths: Vec::new(),
                ignored_paths: Vec::new(),
                ignored_path_details: Vec::new(),
            },
            diagnostics: vec![RunDiagnostic {
                diagnostic_type: error.diagnostic_type().to_string(),
                message: error.message().to_string(),
                file_path: None,
                line: None,
                invalidates_run: Some(true),
            }],
            findings: Vec::new(),
            baseline_report: None,
            suppressions: ReportSuppressions {
                summaries: Vec::new(),
                suppressed_findings: Vec::new(),
            },
            per_rule_deltas: None,
            suppressed_count: None,
            all_findings_summary: None,
            all_findings: Vec::new(),
            machine_diff: None,
        },
    );
    report.machine_context.exit_code = RunOutcome::DiagnosticsFailed.numeric_code();
    report
}

/// Assemble the `gruff.analysis.v3` report from the collected inputs, computing the summary and score from the kept findings.
///
/// `project_root` and `options` fill the run block and machine context, `config` feeds the scoring, and `inputs` supplies every report section.
/// Returns the report, with the score's file count limited to Rust files; the pre-baseline findings in `inputs` are dropped.
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
    let evaluated_files = scoring::evaluated_rust_files(&discovery.files, &diagnostics);
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
