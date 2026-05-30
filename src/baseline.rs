use super::*;

pub(crate) fn write_baseline(path: &Path, findings: &[Finding]) -> Result<(), String> {
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

type BaselineKey = (String, String, String);

fn finding_key(finding: &Finding) -> BaselineKey {
    (
        finding.fingerprint.clone(),
        finding.rule_id.clone(),
        finding.file_path.clone(),
    )
}

fn entry_key(entry: &BaselineEntry) -> BaselineKey {
    (
        entry.fingerprint.clone(),
        entry.rule_id.clone(),
        entry.file_path.clone(),
    )
}

fn load_baseline_entries(path: &Path) -> Result<Vec<BaselineEntry>, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("unable to read baseline {}: {error}", path.display()))?;
    let data: BaselineData = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid baseline {}: {error}", path.display()))?;
    if data.schema_version.as_deref() != Some("gruff.baseline.v1") {
        return Err(format!("unsupported baseline schema in {}", path.display()));
    }
    Ok(data.entries)
}

/// Tri-state classification counts for a baseline comparison (ADR-002 M01
/// addendum). `new` = current findings matched by no baseline entry,
/// `unchanged` = current findings matched by a baseline entry (dropped from the
/// default list), `absent` = baseline entries matched by no current finding
/// (resolved). Computed from the current findings vs the on-disk baseline only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BaselineCounts {
    pub(crate) new: usize,
    pub(crate) unchanged: usize,
    pub(crate) absent: usize,
}

/// Apply a baseline file to `findings`, returning the per-rule
/// introduced/removed deltas (ADR-014) and the tri-state counts (ADR-002 M01
/// addendum) computed against the baseline snapshot. "Introduced"/`new` =
/// current findings not matched by any baseline entry (the surviving findings
/// after `retain`). "Removed"/`absent` = baseline entries that did not match any
/// current finding. `unchanged` = current findings matched by the baseline (the
/// dropped set).
pub(crate) fn apply_baseline(
    path: &Path,
    findings: &mut Vec<Finding>,
) -> Result<(Vec<RuleDelta>, BaselineCounts), String> {
    let entries = load_baseline_entries(path)?;
    let baseline_keys: BTreeSet<BaselineKey> = entries.iter().map(entry_key).collect();
    let current_keys: BTreeSet<BaselineKey> = findings.iter().map(finding_key).collect();
    let deltas = baseline_rule_deltas(findings, &entries, &baseline_keys, &current_keys);
    let unchanged = findings
        .iter()
        .filter(|finding| baseline_keys.contains(&finding_key(finding)))
        .count();
    let absent = entries
        .iter()
        .filter(|entry| !current_keys.contains(&entry_key(entry)))
        .count();
    findings.retain(|finding| !baseline_keys.contains(&finding_key(finding)));
    let counts = BaselineCounts {
        new: findings.len(),
        unchanged,
        absent,
    };
    Ok((deltas, counts))
}

fn baseline_rule_deltas(
    findings: &[Finding],
    entries: &[BaselineEntry],
    baseline_keys: &BTreeSet<BaselineKey>,
    current_keys: &BTreeSet<BaselineKey>,
) -> Vec<RuleDelta> {
    let mut introduced_per_rule: BTreeMap<String, usize> = BTreeMap::new();
    for finding in findings {
        if !baseline_keys.contains(&finding_key(finding)) {
            *introduced_per_rule
                .entry(finding.rule_id.clone())
                .or_insert(0) += 1;
        }
    }
    let mut removed_per_rule: BTreeMap<String, usize> = BTreeMap::new();
    for entry in entries {
        if !current_keys.contains(&entry_key(entry)) {
            *removed_per_rule.entry(entry.rule_id.clone()).or_insert(0) += 1;
        }
    }
    rule_deltas_from_counts(&introduced_per_rule, &removed_per_rule)
}

pub(crate) fn rule_deltas_from_counts(
    introduced_per_rule: &BTreeMap<String, usize>,
    removed_per_rule: &BTreeMap<String, usize>,
) -> Vec<RuleDelta> {
    let mut rule_ids: BTreeSet<&str> = BTreeSet::new();
    rule_ids.extend(introduced_per_rule.keys().map(String::as_str));
    rule_ids.extend(removed_per_rule.keys().map(String::as_str));
    rule_ids
        .into_iter()
        .map(|rule_id| {
            let introduced = introduced_per_rule.get(rule_id).copied().unwrap_or(0);
            let removed = removed_per_rule.get(rule_id).copied().unwrap_or(0);
            RuleDelta {
                rule_id: rule_id.to_string(),
                introduced,
                removed,
                net: introduced as i64 - removed as i64,
            }
        })
        .collect()
}

pub(crate) struct BaselineResolution {
    pub(crate) report: BaselineReport,
    /// Per-rule introduced/removed counts versus the applied baseline.
    /// Empty when generating a fresh baseline (no comparison context).
    pub(crate) deltas: Vec<RuleDelta>,
}

pub(crate) fn resolve_baseline(
    project_root: &Path,
    options: &AnalysisOptions,
    findings: &mut Vec<Finding>,
) -> Result<Option<BaselineResolution>, String> {
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
) -> Result<BaselineResolution, String> {
    let baseline_path = absolutize(project_root, path);
    write_baseline(&baseline_path, findings)?;
    Ok(BaselineResolution {
        report: BaselineReport {
            path: display_path(project_root, &baseline_path),
            source: "generated".to_string(),
            suppressed: 0,
            new_count: 0,
            unchanged_count: 0,
            absent_count: 0,
            generated: true,
        },
        deltas: Vec::new(),
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
) -> Result<BaselineResolution, String> {
    let (deltas, counts) = apply_baseline(baseline_path, findings)?;
    Ok(BaselineResolution {
        report: BaselineReport {
            path: display_path(project_root, baseline_path),
            source: source.to_string(),
            suppressed: counts.unchanged,
            new_count: counts.new,
            unchanged_count: counts.unchanged,
            absent_count: counts.absent,
            generated: false,
        },
        deltas,
    })
}

pub(crate) fn record_history(
    project_root: &Path,
    history_file: &Path,
    findings: &[Finding],
    config: &Config,
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
        "score": score_report(findings, config).composite,
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
