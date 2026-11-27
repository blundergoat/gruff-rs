//! Apply the reviewed findings a caller supplied with `analyse --baseline`.
//!
//! Rows store line-free identities and occurrence counts. Reformatting preserves a review, and extra occurrences remain visible.
//! Generation counts sensitive findings without storing their identities. A 0.5 baseline gives the caller a migration command.

use super::*;

/// The family baseline this port writes and reads; a file naming anything else is refused rather than guessed at.
pub(crate) const BASELINE_SCHEMA_VERSION: &str = "gruff.baseline.v3";

/// The 0.5 baseline a migration accepts as input. Reading one for suppression fails closed and names the command.
pub(crate) const LEGACY_BASELINE_SCHEMA_VERSION: &str = "gruff.baseline.v1";

/// The three keys the five 0.5 writers used for their row list: go and py wrote `findings`, php wrote `groups`, and
/// rs and ts wrote `entries`. A file naming two of them cannot be read the same way twice, so it is refused.
const LEGACY_ROW_CONTAINERS: &[&str] = &["findings", "groups", "entries"];

/// Why a generated baseline stores no sensitive occurrence, written into the file so a reader meets the rule there.
const SENSITIVE_INELIGIBILITY_REASON: &str = "Sensitive findings are never baselinable; they are counted here and stay visible until fixed or excluded with a reason.";

/// Keys a v3 row may never carry; each one is a way a stored baseline could expire on an edit or leak a finding's text.
const FORBIDDEN_OCCURRENCE_KEYS: &[&str] = &[
    "line",
    "endLine",
    "column",
    "message",
    "severity",
    "confidence",
];

/// How one run met the baseline: what stayed hidden, what is new, and which identities could not be told apart.
///
/// The counts feed the report the user reads; `collisions` becomes one diagnostic each, because a collision is
/// reported by name and suppresses nothing.
#[derive(Debug)]
pub(crate) struct BaselineApplication {
    pub(crate) counts: BaselineCounts,
    pub(crate) deltas: Vec<RuleDelta>,
    pub(crate) collisions: Vec<BaselineCollision>,
    pub(crate) entries: usize,
}

/// One identity that covers two declarations, so neither of them can be hidden.
///
/// A user meets this when two same-named declarations in one file cannot be told apart; the run names both
/// subjects so they can see exactly which review would have covered the wrong one.
#[derive(Debug)]
pub(crate) struct BaselineCollision {
    pub(crate) identity: String,
    pub(crate) rule_id: String,
    pub(crate) path: String,
    pub(crate) subjects: Vec<String>,
}

/// Counts that tell a caller what happened when a scan applied a baseline.
///
/// `new`, `collision`, and `not_eligible` all still fail the run; only `unchanged` is hidden, and `absent` counts
/// the reviewed occurrences the user has since fixed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BaselineCounts {
    pub(crate) new: usize,
    pub(crate) unchanged: usize,
    pub(crate) absent: usize,
    pub(crate) collision: usize,
    pub(crate) not_eligible: usize,
}

/// Outcome of migrating a reviewed 0.5 baseline.
///
/// The command uses these counts to explain how many entries carry forward.
/// Sensitive findings are counted apart from the entries a later scan can apply.
#[derive(Debug)]
pub(crate) struct BaselineMigration {
    pub(crate) entries: usize,
    /// Current findings the 0.5 rows covered, before sensitive ones were set aside.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) accepted: usize,
    pub(crate) sensitive_counted: usize,
}

/// Write the reviewed debt of this run: one row per identity, with sensitive findings counted and never stored.
#[cfg(test)]
pub(crate) fn write_baseline(path: &Path, findings: &[Finding]) -> Result<usize, String> {
    write_baseline_with_positions(path, findings, &declaration_position_by_line)
}

/// Write a baseline using this run's parsed functions to rank same-named declarations.
///
/// `path` is the file to create or overwrite with the v3 document, and `findings` are this run's findings.
/// `declaration_position` gives each finding's declaration position, which the identity uses to rank same-named declarations.
/// Returns the number of rows written, or an error when the identities cannot be built or the file cannot be written.
pub(crate) fn write_baseline_with_positions(
    path: &Path,
    findings: &[Finding],
    declaration_position: &dyn Fn(&Finding) -> usize,
) -> Result<usize, String> {
    let document = baseline_document(findings, declaration_position)?;
    let entries = document
        .occurrences
        .as_ref()
        .map_or(0, |occurrences| occurrences.len());
    fs::write(
        path,
        serde_json::to_string_pretty(&document).expect("baseline serializes"),
    )
    .map_err(|error| format!("unable to write baseline {}: {error}", path.display()))?;
    Ok(entries)
}

/// Build the document a generated baseline writes, ordered so two identical runs produce the same rows in the same order.
///
/// `findings` are the findings to record; `declaration_position` gives each one's declaration position to rank same-named ones.
/// A finding left without an identity is stored nowhere, and is counted by rule in the sensitive summary when it is not baseline-eligible.
/// Returns the v3 document with one row per identity holding its occurrence count, or an error when the identities cannot be built.
fn baseline_document(
    findings: &[Finding],
    declaration_position: &dyn Fn(&Finding) -> usize,
) -> Result<BaselineData, String> {
    let identities = finding_identities(findings, declaration_position)?;
    let mut rows: BTreeMap<String, BaselineEntry> = BTreeMap::new();
    let mut sensitive_by_rule: BTreeMap<String, usize> = BTreeMap::new();

    for (finding, named) in findings.iter().zip(identities.iter()) {
        // A sensitive finding is counted by rule and stored nowhere, so no row can ever hide a secret. A finding
        // left unnamed for its symbol is stored nowhere either, and is never counted as sensitive.
        let Some(named) = named else {
            if !is_baseline_eligible(finding) {
                *sensitive_by_rule
                    .entry(finding.rule_id.clone())
                    .or_insert(0) += 1;
            }
            continue;
        };
        rows.entry(named.identity.clone())
            .and_modify(|entry| entry.count += 1)
            .or_insert_with(|| BaselineEntry {
                identity: named.identity.clone(),
                count: 1,
                rule_id: Some(finding.rule_id.clone()),
                path: Some(finding.file_path.clone()),
                subject: Some(named.subject.clone()),
            });
    }

    Ok(BaselineData {
        schema_version: Some(BASELINE_SCHEMA_VERSION.to_string()),
        tool_language: Some(TOOL_LANGUAGE.to_string()),
        generated_at: Some(Utc::now().to_rfc3339()),
        occurrences: Some(rows.into_values().collect()),
        sensitive: Some(SensitiveSummary {
            eligible: false,
            reason: SENSITIVE_INELIGIBILITY_REASON.to_string(),
            counts: SensitiveCounts {
                total: sensitive_by_rule.values().sum(),
                by_rule: sensitive_by_rule,
            },
        }),
    })
}

/// Protect an older, unreadable, or unrecognized baseline at the shared default path during an upgrade.
///
/// `output_path` is where the baseline will be written, and only a file with the default baseline name is checked; `force` skips the check.
/// Returns success for an absent file or the current schema, or an error directing the caller to migrate or choose another output path.
fn require_overwritable_default_path(output_path: &Path, force: bool) -> Result<(), String> {
    // A caller can choose a distinct destination or use `--force` to opt into replacing a baseline.
    if force || output_path.file_name().and_then(|name| name.to_str()) != Some(DEFAULT_BASELINE) {
        return Ok(());
    }
    let existing = match fs::read_to_string(output_path) {
        Ok(existing) => existing,
        // A first-time generation has no accepted review file to protect.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        // An unreadable file, such as one owned by another user, may still contain accepted reviews.
        Err(error) => {
            return Err(format!(
                "unable to verify existing baseline {}: {error}",
                output_path.display()
            ))
        }
    };
    let document = serde_json::from_str::<Value>(&existing).unwrap_or(Value::Null);
    let schema = document.get("schemaVersion").and_then(Value::as_str);
    // A current baseline can be regenerated in place. A legacy or unidentified one keeps its rollback value.
    if schema == Some(BASELINE_SCHEMA_VERSION) {
        return Ok(());
    }
    Err(format!(
        "{} is a {:?} baseline, not {BASELINE_SCHEMA_VERSION:?}; generating over it would destroy the retreat path. Migrate it with `gruff-rs analyse --migrate-baseline {} --generate-baseline <new path>`, or pass --force to overwrite it",
        output_path.display(),
        schema.unwrap_or("unrecognized"),
        output_path.display(),
    ))
}

/// Read one v3 baseline, refusing a 0.5 layout, another port's file, and any row that could expire or leak.
///
/// `path` is the baseline file to read, shown in every error message.
/// Returns the parsed document, or an error when the file cannot be read or parsed, names another schema or port, or fails row validation.
fn load_baseline(path: &Path) -> Result<BaselineData, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("unable to read baseline {}: {error}", path.display()))?;
    let document: BaselineData = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid baseline {}: {error}", path.display()))?;

    // A 0.5 file fails closed and names the command that carries its reviews forward, so nothing is silently dropped.
    if document.schema_version.as_deref() == Some(LEGACY_BASELINE_SCHEMA_VERSION) {
        return Err(format!(
            "baseline {} is a 0.5 baseline; migrate it to a separate file with `gruff-rs analyse --migrate-baseline {} --generate-baseline <new path>`, the original is preserved",
            path.display(),
            path.display(),
        ));
    }
    if document.schema_version.as_deref() != Some(BASELINE_SCHEMA_VERSION) {
        return Err(format!("unsupported baseline schema in {}", path.display()));
    }
    // A baseline names its writer, so another port's file is refused instead of reporting every row resolved.
    if document.tool_language.as_deref() != Some(TOOL_LANGUAGE) {
        return Err(format!(
            "baseline {} was written by {} and this run is {TOOL_LANGUAGE}; baselines are not shared across languages",
            path.display(),
            document.tool_language.as_deref().unwrap_or("an unnamed port"),
        ));
    }
    validate_rows(path, &raw, document.occurrences.as_deref().unwrap_or(&[]))?;
    Ok(document)
}

/// Refuse a stored row that omits its identity, suppresses nothing, or carries a field that would expire on an edit.
///
/// `entries` are the parsed rows to check; `raw` is the file's unparsed text, searched for forbidden keys under `occurrences`.
/// `path` names the file in error messages. An identity must be 16 lowercase hex characters and a count must be positive.
/// Returns an error for the first violation found; text that does not parse as JSON skips the forbidden-key check.
fn validate_rows(path: &Path, raw: &str, entries: &[BaselineEntry]) -> Result<(), String> {
    let raw_rows: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
    let mut identities = BTreeSet::new();
    let mut total = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        // An identity that is not the ratified digest shape cannot have come from a generator.
        if entry.identity.len() != 16
            || !entry
                .identity
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        {
            return Err(format!(
                "baseline {} occurrences[{index}].identity must be 16 lowercase hex characters",
                path.display()
            ));
        }
        // A count below one would mean a reviewed identity that suppresses nothing, which is a hand edit gone wrong.
        if entry.count == 0 {
            return Err(format!(
                "baseline {} occurrences[{index}].count must be a positive integer",
                path.display()
            ));
        }
        // Reject duplicate review rows so a caller's accepted count cannot depend on which row is read last.
        if !identities.insert(entry.identity.as_str()) {
            return Err(format!(
                "baseline {} occurrences[{index}].identity is duplicated",
                path.display()
            ));
        }
        // A malformed total must surface as a baseline error before the comparison calculates resolved debt.
        total = total.checked_add(entry.count).ok_or_else(|| {
            format!(
                "baseline {} occurrence counts exceed the supported total",
                path.display()
            )
        })?;
    }

    let Some(rows) = raw_rows.get("occurrences").and_then(Value::as_array) else {
        return Ok(());
    };
    for (index, row) in rows.iter().enumerate() {
        for forbidden in FORBIDDEN_OCCURRENCE_KEYS {
            // A positional field is how a 0.5 baseline expired on every edit, so its presence fails the file.
            if row.get(forbidden).is_some() {
                return Err(format!(
                    "baseline {} occurrences[{index}] carries forbidden key \"{forbidden}\"",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Apply a baseline to this run: hide the reviewed occurrences, keep everything else, and say what moved.
///
/// Findings are classified in the ratified order: a sensitive finding is never eligible, an identity over two
/// declarations is a collision that hides nothing, occurrences within the reviewed count are unchanged, and the
/// rest are new. The reviewed count is spent lowest line first, so two ports hide the same occurrences.
///
/// `path` is the baseline file to load, and `declaration_position` gives each finding's declaration position for identity naming.
/// `findings` is changed in place: every finding gets its baseline status, then the unchanged ones are removed.
/// Returns the counts, per-rule deltas, collisions, and resolved rows, or an error when loading the baseline or naming identities fails.
#[cfg(test)]
pub(crate) fn apply_baseline(
    path: &Path,
    findings: &mut Vec<Finding>,
    declaration_position: &dyn Fn(&Finding) -> usize,
) -> Result<BaselineApplication, String> {
    apply_baseline_with_exclusions(path, findings, declaration_position, &BTreeMap::new())
}

/// Apply a baseline to this run while preserving counts for ordinary findings already removed by `exclude` entries.
///
/// `path` is the baseline to load, `findings` updates in place via `declaration_position`, and `excluded_identities` tracks `exclude` counts.
/// Returns counts, per-rule deltas, collisions, and entry count, or an error when loading the file or naming identities fails.
pub(crate) fn apply_baseline_with_exclusions(
    path: &Path,
    findings: &mut Vec<Finding>,
    declaration_position: &dyn Fn(&Finding) -> usize,
    excluded_identities: &BTreeMap<String, usize>,
) -> Result<BaselineApplication, String> {
    let document = load_baseline(path)?;
    let reviewed: BTreeMap<&str, usize> = document
        .occurrences
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|entry| (entry.identity.as_str(), entry.count))
        .collect();

    let identities = finding_identities(findings, declaration_position)?;
    let groups = group_by_identity(findings, &identities);
    let statuses = classify(findings, &identities, &groups, &reviewed);
    let counts = count_statuses(&statuses);
    let resolved = resolved_surplus(
        document.occurrences.as_deref().unwrap_or(&[]),
        &groups,
        &statuses,
        excluded_identities,
    );
    let deltas = rule_deltas(findings, &statuses, &resolved);
    let collisions_by_identity = collided_identities(&groups);

    // A consumer that cannot see why a finding survived cannot tell a genuinely new problem from one the identity
    // could not separate, so the status travels with the finding rather than only in a count.
    for (finding, status) in findings.iter_mut().zip(statuses.iter()) {
        finding.baseline_status = Some(status.as_str().to_string());
    }

    let mut index = 0;
    findings.retain(|_| {
        let hidden = statuses[index] == BaselineStatus::Unchanged;
        index += 1;
        !hidden
    });

    Ok(BaselineApplication {
        counts: BaselineCounts {
            absent: resolved.iter().map(|entry| entry.count).sum(),
            ..counts
        },
        deltas,
        collisions: collisions_by_identity,
        entries: document.occurrences.as_ref().map_or(0, Vec::len),
    })
}

/// Carry a 0.5 baseline's reviews into a new v3 file, leaving the original byte-identical.
///
/// The reviews are re-identified from the current scan rather than translated, because a 0.5 digest names a line
/// and this one does not. A finding the 0.5 file never accepted stays visible.
///
/// `input_path` is the 0.5 baseline to read, `output_path` the separate file the v3 document is written to, and `findings` the current scan.
/// `declaration_position` gives each accepted finding's declaration position for identity naming.
/// Returns the rows written, the findings accepted, and the sensitive findings counted.
///
/// It errors when the paths name one file, the input is unreadable or not a 0.5 baseline, or naming identities or writing fails.
/// It also errors when the input's bytes changed by the time the write finished.
pub(crate) fn migrate_baseline(
    input_path: &Path,
    output_path: &Path,
    findings: &[Finding],
    declaration_position: &dyn Fn(&Finding) -> usize,
) -> Result<BaselineMigration, String> {
    require_distinct_paths(input_path, output_path)?;
    let original = fs::read(input_path)
        .map_err(|error| format!("unable to read baseline {}: {error}", input_path.display()))?;
    let rows = legacy_rows(input_path, &original)?;
    let accepted = accepted_by_legacy(&rows, findings);
    let document = baseline_document(&accepted, declaration_position)?;
    let sensitive_counted = document
        .sensitive
        .as_ref()
        .map_or(0, |sensitive| sensitive.counts.total);
    let entries = document
        .occurrences
        .as_ref()
        .map_or(0, |occurrences| occurrences.len());

    fs::write(
        output_path,
        serde_json::to_string_pretty(&document).expect("baseline serializes"),
    )
    .map_err(|error| {
        format!(
            "unable to write baseline {}: {error}",
            output_path.display()
        )
    })?;

    // The 0.5 file is the user's way back, so the migration proves it survived rather than assuming it did.
    let after = fs::read(input_path)
        .map_err(|error| format!("unable to read baseline {}: {error}", input_path.display()))?;
    if after != original {
        return Err(format!(
            "migration changed its own input: {}",
            input_path.display()
        ));
    }

    Ok(BaselineMigration {
        entries,
        accepted: accepted.len(),
        sensitive_counted,
    })
}

/// Refuse an output that is the input by spelling, resolved link target, or inode.
///
/// A symlink resolves to the same real path; a hard link does not, but shares the inode, and either one would let
/// an out-of-place migration overwrite the retreat copy it is supposed to preserve.
///
/// `input_path` is the 0.5 baseline being migrated and `output_path` the destination, which need not exist yet.
/// Returns an error naming the input when the two resolve to the same path or share an inode.
fn require_distinct_paths(input_path: &Path, output_path: &Path) -> Result<(), String> {
    let resolved_input = fs::canonicalize(input_path).unwrap_or_else(|_| input_path.to_path_buf());
    let resolved_output =
        fs::canonicalize(output_path).unwrap_or_else(|_| output_path.to_path_buf());
    if resolved_input == resolved_output || is_same_inode(input_path, output_path) {
        return Err(format!(
            "migration output must be a different file from its input: {}",
            input_path.display()
        ));
    }
    Ok(())
}

/// Report whether two paths name one file on disk, which a hard link makes true under two different names on Unix.
///
/// `input_path` and `output_path` are the two paths whose file identity is compared.
/// Returns true when both share a device and inode on Unix, or resolve to the same canonical path elsewhere.
/// Returns false when they differ or either cannot be read.
fn is_same_inode(input_path: &Path, output_path: &Path) -> bool {
    #[cfg(unix)]
    {
        let (Ok(input), Ok(output)) = (fs::metadata(input_path), fs::metadata(output_path)) else {
            // A missing output is the ordinary case: there is nothing to collide with yet.
            return false;
        };
        input.dev() == output.dev() && input.ino() == output.ino()
    }
    #[cfg(not(unix))]
    {
        let (Ok(input), Ok(output)) = (fs::canonicalize(input_path), fs::canonicalize(output_path))
        else {
            return false;
        };
        input == output
    }
}

/// Read the rows of a 0.5 baseline, the only shape a migration accepts as its input.
///
/// A file naming more than one of the three 0.5 container keys is refused: the five 0.5 writers used three of them,
/// so such a file migrates differently in different ports, and refusing it is the only reading that is the same
/// everywhere.
///
/// `path` names the file in error messages and `contents` are its raw bytes.
/// Returns a copy of the rows in the single container that holds a list.
/// It errors when the bytes are not JSON, the schema is not `gruff.baseline.v1`, or no container or more than one holds a list.
fn legacy_rows(path: &Path, contents: &[u8]) -> Result<Vec<Value>, String> {
    let document: Value = serde_json::from_slice(contents)
        .map_err(|error| format!("invalid baseline {}: {error}", path.display()))?;
    if document.get("schemaVersion").and_then(Value::as_str) != Some(LEGACY_BASELINE_SCHEMA_VERSION)
    {
        return Err(format!(
            "migration input {} is not a 0.5 baseline",
            path.display()
        ));
    }
    let present: Vec<&str> = LEGACY_ROW_CONTAINERS
        .iter()
        .copied()
        .filter(|container| document.get(container).and_then(Value::as_array).is_some())
        .collect();
    if present.len() > 1 {
        return Err(format!(
            "migration input {} carries more than one row container ({}); a migration input must name exactly one",
            path.display(),
            present.join(", "),
        ));
    }
    let container = present.first().ok_or_else(|| {
        format!(
            "migration input {} must carry an \"entries\" or \"findings\" list",
            path.display()
        )
    })?;
    let rows = document
        .get(container)
        .and_then(Value::as_array)
        .expect("the container was found by its array shape");
    Ok(rows.clone())
}

/// Keep the current findings a 0.5 baseline had already accepted, matching only on fields that file stored.
///
/// A row is matched on its rule and path, narrowed by its symbol and message when it recorded them, and it accepts
/// as many occurrences as the file held. A finding the old baseline never covered stays visible.
///
/// `rows` are the 0.5 rows, whose path is read from `filePath` or else `file`, and `findings` are the current scan's findings.
/// Returns clones of the accepted findings sorted by line then column, and an empty list when no row covers any finding.
fn accepted_by_legacy(rows: &[Value], findings: &[Finding]) -> Vec<Finding> {
    let mut budget: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows {
        let raw_path = match row_text(row, "filePath") {
            path if path.is_empty() => row_text(row, "file"),
            path => path,
        };
        let path = normalize_report_path(&raw_path);
        let key = acceptance_key(
            &row_text(row, "ruleId"),
            &path,
            &row_text(row, "symbol"),
            &row_text(row, "message"),
        );
        *budget.entry(key).or_insert(0) += 1;
    }

    let mut ordered: Vec<&Finding> = findings.iter().collect();
    // Lowest line first, so a row covering fewer occurrences than exist today accepts the same ones on every port.
    ordered.sort_by_key(|finding| {
        (
            finding.line.unwrap_or(usize::MAX),
            finding.column.unwrap_or(0),
        )
    });

    ordered
        .into_iter()
        .filter(|finding| can_spend_legacy_budget(&mut budget, finding))
        .cloned()
        .collect()
}

/// Report whether one 0.5 row still covers this finding, spending it when it does.
///
/// A sparser 0.5 writer stored fewer fields, so the wider shapes are tried in turn and no accepted debt is lost.
///
/// `budget` maps each row shape to its unspent count and is decremented in place on a match; `finding` is the finding to cover.
/// Shapes run from rule, path, symbol, and message together down to rule and path alone.
/// Returns true when a shape with remaining budget was spent, and false when none covers the finding.
fn can_spend_legacy_budget(budget: &mut BTreeMap<String, usize>, finding: &Finding) -> bool {
    let symbol = finding.symbol.as_deref().unwrap_or_default();
    let path = normalize_report_path(&finding.file_path);
    for candidate in [
        acceptance_key(&finding.rule_id, &path, symbol, &finding.message),
        acceptance_key(&finding.rule_id, &path, symbol, ""),
        acceptance_key(&finding.rule_id, &path, "", &finding.message),
        acceptance_key(&finding.rule_id, &path, "", ""),
    ] {
        if let Some(remaining) = budget.get_mut(&candidate) {
            if *remaining > 0 {
                *remaining -= 1;
                return true;
            }
        }
    }
    false
}

/// Join the fields a 0.5 row could narrow on into one key, so a row and a finding compare as whole shapes.
///
/// `rule_id` and `path` always take part; `symbol` and `message` are empty when that shape does not narrow on them.
/// Returns the four fields joined with NUL separators.
fn acceptance_key(rule_id: &str, path: &str, symbol: &str, message: &str) -> String {
    format!("{rule_id}\0{path}\0{symbol}\0{message}")
}

/// Read one stored 0.5 field, treating an absent or non-text value as a field that row never narrowed on.
///
/// `row` is one 0.5 row and `key` the field name to read.
/// Returns the field's text, or an empty string when it is absent or not a string.
fn row_text(row: &Value, key: &str) -> String {
    row.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// What a reviewed baseline means for a current finding.
///
/// A matched occurrence can be hidden. A new, ambiguous, or ineligible occurrence stays visible.
/// The spelling is part of the machine report and hook contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaselineStatus {
    New,
    Unchanged,
    Collision,
    NotEligible,
}

impl BaselineStatus {
    /// Name this status as the ratified vocabulary spells it, for the payload a consumer reads.
    ///
    /// Returns `new`, `unchanged`, `collision`, or `notEligible`.
    fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Unchanged => "unchanged",
            Self::Collision => "collision",
            Self::NotEligible => "notEligible",
        }
    }
}

/// Every occurrence of one identity in this run, plus what it takes to judge them together.
///
/// The rule id and path are borrowed from the findings themselves, so grouping a large run allocates nothing
/// beyond the identity keys the map needs.
struct IdentityGroup<'a> {
    indexes: Vec<usize>,
    declarations: BTreeSet<&'a str>,
    subjects: Vec<&'a str>,
    rule_id: &'a str,
    path: &'a str,
}

/// Bucket every eligible finding by identity, remembering the declarations and subjects each one covers.
///
/// `findings` are this run's findings, and `identities` holds each one's identity at the same index, None for a finding left unnamed.
/// Returns the groups keyed by identity, each with its finding indexes, distinct declarations, and subjects in first-seen order.
///
/// Panics when `identities` is shorter than `findings`.
fn group_by_identity<'a>(
    findings: &'a [Finding],
    identities: &'a [Option<FindingIdentity>],
) -> BTreeMap<&'a str, IdentityGroup<'a>> {
    let mut groups: BTreeMap<&str, IdentityGroup> = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        // A sensitive finding has no identity, so it joins no group and no reviewed row can ever reach it.
        let Some(named) = identities[index].as_ref() else {
            continue;
        };
        let group = groups
            .entry(named.identity.as_str())
            .or_insert_with(|| IdentityGroup {
                indexes: Vec::new(),
                declarations: BTreeSet::new(),
                subjects: Vec::new(),
                rule_id: finding.rule_id.as_str(),
                path: finding.file_path.as_str(),
            });
        group.indexes.push(index);
        group.declarations.insert(named.declaration_key.as_str());
        if !group.subjects.contains(&named.subject.as_str()) {
            group.subjects.push(named.subject.as_str());
        }
    }
    groups
}

/// Label every finding, spending each identity's reviewed count on its lowest lines first.
///
/// The run is walked once in file order rather than per identity, so two ports hide the same occurrences for
/// identical input rather than merely the same number of them.
///
/// `findings` and `identities` are index-aligned; `groups` comes from `group_by_identity` and marks collided identities.
/// `reviewed` maps each baselined identity to the occurrence count it hides.
/// Returns one status per finding at its index: not eligible without an identity, collision, unchanged within the count, or new.
///
/// Panics when `identities` is shorter than `findings`.
fn classify(
    findings: &[Finding],
    identities: &[Option<FindingIdentity>],
    groups: &BTreeMap<&str, IdentityGroup>,
    reviewed: &BTreeMap<&str, usize>,
) -> Vec<BaselineStatus> {
    let mut statuses = vec![BaselineStatus::New; findings.len()];
    let mut spent_per_identity: BTreeMap<&str, usize> = BTreeMap::new();

    for index in spend_order(findings) {
        // Sensitive findings are labelled before any lookup, so no reviewed row can reach a secret; a finding left
        // unnamed for its symbol takes the same label, because no reviewed row can name it either.
        let Some(named) = identities[index].as_ref() else {
            statuses[index] = BaselineStatus::NotEligible;
            continue;
        };
        let identity = named.identity.as_str();
        // One identity over two declarations cannot separate them, so neither is hidden and the run names both.
        if groups
            .get(identity)
            .is_some_and(|group| group.declarations.len() > 1)
        {
            statuses[index] = BaselineStatus::Collision;
            continue;
        }
        let spent = spent_per_identity.entry(identity).or_insert(0);
        statuses[index] = if *spent < reviewed.get(identity).copied().unwrap_or(0) {
            BaselineStatus::Unchanged
        } else {
            BaselineStatus::New
        };
        *spent += 1;
    }
    statuses
}

/// Order this run's findings by line then column, which is the ratified order a reviewed count is spent in.
///
/// `findings` are this run's findings, which are left untouched.
/// Returns their indexes sorted by line then column, with a finding that has no line placed last and ties kept in their original order.
fn spend_order(findings: &[Finding]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..findings.len()).collect();
    order.sort_by_key(|index| {
        (
            findings[*index].line.unwrap_or(usize::MAX),
            findings[*index].column.unwrap_or(0),
        )
    });
    order
}

/// Total each status, so the report can show what was hidden and what stays visible for the run's exit policy to judge.
///
/// `statuses` are the per-finding labels from `classify`.
/// Returns the new, unchanged, collision, and not-eligible totals, with `absent` left at zero for `apply_baseline` to fill.
fn count_statuses(statuses: &[BaselineStatus]) -> BaselineCounts {
    let mut counts = BaselineCounts::default();
    for status in statuses {
        match status {
            BaselineStatus::New => counts.new += 1,
            BaselineStatus::Unchanged => counts.unchanged += 1,
            BaselineStatus::Collision => counts.collision += 1,
            BaselineStatus::NotEligible => counts.not_eligible += 1,
        }
    }
    counts
}

/// Find every reviewed identity with fewer live occurrences than reviewed, which is debt the user has since fixed.
///
/// `entries` are the baseline rows, `groups` this run's identity groups, `statuses` the labels that mark a collided group,
/// and `excluded_identities` counts ordinary findings removed by configured `exclude` entries so they do not mark a reviewed row resolved.
/// Returns one row per baseline row with more reviewed than live-plus-excluded occurrences, holding the surplus; collided identities are skipped.
///
/// Panics when `statuses` has no entry for a matching group's first finding.
fn resolved_surplus(
    entries: &[BaselineEntry],
    groups: &BTreeMap<&str, IdentityGroup>,
    statuses: &[BaselineStatus],
    excluded_identities: &BTreeMap<String, usize>,
) -> Vec<BaselineEntry> {
    entries
        .iter()
        .filter_map(|entry| {
            let group = groups.get(entry.identity.as_str());
            // A collided identity is accounted for by its collision; counting it resolved would double-report it.
            if group.is_some_and(|group| statuses[group.indexes[0]] == BaselineStatus::Collision) {
                return None;
            }
            let live = group.map_or(0, |group| group.indexes.len())
                + excluded_identities
                    .get(entry.identity.as_str())
                    .copied()
                    .unwrap_or(0);
            let surplus = entry.count.saturating_sub(live);
            (surplus > 0).then(|| BaselineEntry {
                identity: entry.identity.clone(),
                count: surplus,
                rule_id: entry.rule_id.clone(),
                path: entry.path.clone(),
                subject: entry.subject.clone(),
            })
        })
        .collect()
}

/// List the identities that covered two declarations, so the run can name each one for the user.
///
/// `groups` are this run's identity groups.
/// Returns one collision per identity whose group spans more than one declaration, in identity order, with its rule, path, and subjects.
fn collided_identities(groups: &BTreeMap<&str, IdentityGroup>) -> Vec<BaselineCollision> {
    groups
        .iter()
        .filter(|(_, group)| group.declarations.len() > 1)
        .map(|(identity, group)| BaselineCollision {
            identity: (*identity).to_string(),
            rule_id: group.rule_id.to_string(),
            path: group.path.to_string(),
            subjects: group
                .subjects
                .iter()
                .map(|subject| (*subject).to_string())
                .collect(),
        })
        .collect()
}

/// Report per-rule movement against the baseline: what this run introduced, and what the user resolved (ADR-014).
///
/// `findings` and `statuses` are index-aligned; every finding not labelled unchanged counts as introduced for its rule.
/// `resolved` are the surplus rows, each adding its count as removed for its rule, or for `unknown` when the row names none.
/// Returns one delta per rule seen on either side, sorted by rule id.
///
/// Panics when `statuses` is shorter than `findings`.
fn rule_deltas(
    findings: &[Finding],
    statuses: &[BaselineStatus],
    resolved: &[BaselineEntry],
) -> Vec<RuleDelta> {
    let mut introduced_per_rule: BTreeMap<String, usize> = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        if statuses[index] != BaselineStatus::Unchanged {
            *introduced_per_rule
                .entry(finding.rule_id.clone())
                .or_insert(0) += 1;
        }
    }
    let mut removed_per_rule: BTreeMap<String, usize> = BTreeMap::new();
    for entry in resolved {
        let rule_id = entry
            .rule_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        *removed_per_rule.entry(rule_id).or_insert(0) += entry.count;
    }
    rule_deltas_from_counts(&introduced_per_rule, &removed_per_rule)
}

/// Combine per-rule introduced and removed counts into one delta row per rule.
///
/// `introduced_per_rule` and `removed_per_rule` map rule ids to counts; a rule missing from one side counts zero there.
/// Returns the deltas sorted by rule id, each with net equal to introduced minus removed, and an empty list when both maps are empty.
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

/// Publish the result of applying or generating a baseline.
///
/// The report explains how the baseline was used. Per-rule deltas compare with earlier reviews when available.
/// Collisions give callers an actionable diagnostic when two declarations cannot be distinguished.
pub(crate) struct BaselineResolution {
    pub(crate) report: BaselineReport,
    /// Per-rule introduced/removed counts versus the applied baseline.
    /// Empty when generating a fresh baseline (no comparison context).
    pub(crate) deltas: Vec<RuleDelta>,
    /// Identities that covered two declarations; each becomes a diagnostic the user reads.
    pub(crate) collisions: Vec<BaselineCollision>,
}

/// Apply or generate the caller's baseline. Capture the full severity tally first so `gate.scope: all` can still include reviewed debt.
///
/// `findings` is updated in place when the selected baseline covers a reviewed occurrence.
/// `project_root` anchors relative baseline paths, and `options` decides whether to generate, migrate, apply, or skip a baseline.
///
/// `declaration_position` gives each finding's declaration position for identity naming.
/// `excluded_identities` records how many findings each configured `exclude` entry removed.
///
/// Returns the resolution, None when no baseline applies, paired with the pre-baseline summary, or the error from the chosen action.
pub(crate) fn resolve_baseline(
    project_root: &Path,
    options: &AnalysisOptions,
    findings: &mut Vec<Finding>,
    declaration_position: &dyn Fn(&Finding) -> usize,
    excluded_identities: &BTreeMap<String, usize>,
) -> Result<(Option<BaselineResolution>, Summary), String> {
    let all_findings_summary = summarize(findings);
    let resolution = resolve_baseline_inner(
        project_root,
        options,
        findings,
        declaration_position,
        excluded_identities,
    )?;
    Ok((resolution, all_findings_summary))
}

/// Carry out the baseline action requested by `options`: generate or migrate a file, apply a baseline, or skip.
///
/// `project_root` anchors relative paths, `declaration_position` ranks same-named declarations, and `excluded_identities` tracks `exclude` counts.
/// `findings` is updated in place only when applying a baseline (attaching statuses and removing unchanged findings).
///
/// Returns `Ok(None)` when no baseline runs, `Ok(Some(_))` on generation/application, or `Err` with host paths rewritten to caller-facing names.
fn resolve_baseline_inner(
    project_root: &Path,
    options: &AnalysisOptions,
    findings: &mut Vec<Finding>,
    declaration_position: &dyn Fn(&Finding) -> usize,
    excluded_identities: &BTreeMap<String, usize>,
) -> Result<Option<BaselineResolution>, String> {
    // The user asked to capture the current state, so write a baseline rather than compare against one.
    if let Some(path) = &options.generate_baseline {
        return generate_baseline_report(
            project_root,
            path,
            options.migrate_baseline.as_deref(),
            options.force_baseline_overwrite,
            findings,
            declaration_position,
        )
        .map(Some);
    }
    // Migration writes a second file rather than converting one, so it needs the destination the user chose.
    if options.migrate_baseline.is_some() {
        return Err(
            "--migrate-baseline requires --generate-baseline <new path>; the 0.5 file is never converted in place"
                .to_string(),
        );
    }
    if options.no_baseline {
        return Ok(None);
    }
    let Some((baseline_path, source)) = select_baseline_path(project_root, options) else {
        return Ok(None);
    };
    apply_selected_baseline(
        project_root,
        &baseline_path,
        source,
        findings,
        declaration_position,
        excluded_identities,
    )
    .map_err(|error| baseline_named_as_given(&error, &baseline_path, options))
    .map(Some)
}

/// A load error names the absolute path it read, and the envelope may not publish a host path, so the message names the
/// baseline as the run was given it, or by the default file name when it was discovered.
///
/// `error` is the message to rewrite, `baseline_path` the path it was read from, and `options` holds any `--baseline` value.
/// Returns the message with each occurrence of that path replaced by the given value, or by the default file name when none was given.
fn baseline_named_as_given(error: &str, baseline_path: &Path, options: &AnalysisOptions) -> String {
    let shown = options
        .baseline
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_BASELINE));
    error.replace(
        &baseline_path.display().to_string(),
        &shown.display().to_string(),
    )
}

/// Write a generated or migrated baseline and describe it as a report whose comparison counts are all zero.
///
/// `project_root` anchors `path`, the baseline file to write, and the report's displayed path; `migrate_path` names an optional 0.5 input.
/// `force` allows overwriting a non-v3 file at the default path; `findings` and `declaration_position` are passed on to the writer.
/// Returns a report marked generated, with no deltas or collisions, or an error when the default path is protected or writing fails.
fn generate_baseline_report(
    project_root: &Path,
    path: &Path,
    migrate_path: Option<&Path>,
    force: bool,
    findings: &[Finding],
    declaration_position: &dyn Fn(&Finding) -> usize,
) -> Result<BaselineResolution, String> {
    let baseline_path = absolutize(project_root, path);
    let redact_paths = |error: String| -> String {
        let mut message = error.replace(
            &baseline_path.display().to_string(),
            &path.display().to_string(),
        );
        if let Some(input) = migrate_path {
            let resolved_input = absolutize(project_root, input);
            message = message.replace(
                &resolved_input.display().to_string(),
                &input.display().to_string(),
            );
        }
        message
    };
    // A generate at the shared default path never destroys a 0.5 baseline by accident; --force is the way to mean it.
    require_overwritable_default_path(&baseline_path, force).map_err(&redact_paths)?;
    let (entries, sensitive_counted, source) = write_generated_baseline(
        project_root,
        &baseline_path,
        migrate_path,
        findings,
        declaration_position,
    )
    .map_err(&redact_paths)?;

    Ok(BaselineResolution {
        report: BaselineReport {
            path: baseline_display_path(project_root, &baseline_path),
            source: source.to_string(),
            suppressed: 0,
            new_count: 0,
            unchanged_count: 0,
            absent_count: 0,
            collision_count: 0,
            not_eligible_count: 0,
            sensitive_counted,
            entries,
            generated: true,
        },
        deltas: Vec::new(),
        collisions: Vec::new(),
    })
}

/// Write the baseline a generate asked for, and report what it holds and where it came from.
///
/// A migration re-identifies the 0.5 reviews from this scan and writes them beside the original, which stays
/// byte-identical; an ordinary generate records the current findings and carries nothing across.
///
/// `baseline_path` is the file to write, `migrate_path` the optional 0.5 input resolved against `project_root`, and `findings` the scan.
/// `declaration_position` gives each finding's declaration position for identity naming.
/// Returns the rows written, the sensitive findings counted, and the source `generated` or `migrated`, or the build or write error.
fn write_generated_baseline(
    project_root: &Path,
    baseline_path: &Path,
    migrate_path: Option<&Path>,
    findings: &[Finding],
    declaration_position: &dyn Fn(&Finding) -> usize,
) -> Result<(usize, usize, &'static str), String> {
    let Some(input) = migrate_path else {
        let document = baseline_document(findings, declaration_position)?;
        let sensitive_counted = document
            .sensitive
            .as_ref()
            .map_or(0, |sensitive| sensitive.counts.total);
        let entries = write_baseline_with_positions(baseline_path, findings, declaration_position)?;
        return Ok((entries, sensitive_counted, "generated"));
    };
    let migration = migrate_baseline(
        &absolutize(project_root, input),
        baseline_path,
        findings,
        declaration_position,
    )?;
    Ok((migration.entries, migration.sensitive_counted, "migrated"))
}

/// Choose the baseline a run compares against: the `--baseline` file when given, otherwise the default file when it exists.
///
/// `project_root` anchors a relative `--baseline` path and is where the default file is looked for; `options` supplies that path.
/// Returns the resolved path with source `explicit` or `default`, or None when no path was given and no default file exists.
/// An explicit path is returned without checking that it exists.
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

/// Apply the chosen baseline file to this run and describe the outcome as a `BaselineResolution`.
///
/// `baseline_path` displays under `project_root` with `source` (`explicit` or `default`); `findings` updates via `declaration_position`.
/// `excluded_identities` preserves counts for findings removed by `exclude` so reviewed baseline rows are not falsely marked resolved.
///
/// Returns the baseline report, per-rule deltas, and collisions, or an error when reading or applying the baseline fails.
fn apply_selected_baseline(
    project_root: &Path,
    baseline_path: &Path,
    source: &str,
    findings: &mut Vec<Finding>,
    declaration_position: &dyn Fn(&Finding) -> usize,
    excluded_identities: &BTreeMap<String, usize>,
) -> Result<BaselineResolution, String> {
    let application = apply_baseline_with_exclusions(
        baseline_path,
        findings,
        declaration_position,
        excluded_identities,
    )?;
    Ok(BaselineResolution {
        report: BaselineReport {
            path: baseline_display_path(project_root, baseline_path),
            source: source.to_string(),
            suppressed: application.counts.unchanged,
            new_count: application.counts.new,
            unchanged_count: application.counts.unchanged,
            absent_count: application.counts.absent,
            collision_count: application.counts.collision,
            not_eligible_count: application.counts.not_eligible,
            sensitive_counted: 0,
            entries: application.entries,
            generated: false,
        },
        deltas: application.deltas,
        collisions: application.collisions,
    })
}

/// Count durable baseline identities removed by configured `exclude` rules so baseline matching does not mark them resolved.
///
/// `suppressed_findings` holds every suppressed finding across configured, built-in, and inline channels.
/// Returns a map from baseline identity to excluded count for `exclude` entries only, or an empty map when none match.
pub(crate) fn excluded_baseline_identities(
    suppressed_findings: &[SuppressedFinding],
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for suppressed in suppressed_findings {
        // Only config `exclude` entries count; the baseline still treats other suppression kinds as absent findings.
        if suppressed.suppression.config_key == "exclude" {
            // A finding without a baseline identity, such as a sensitive-data finding, has no baseline row to keep.
            if let Some(identity) = suppressed.finding.baseline_identity.as_deref() {
                *counts.entry(identity.to_string()).or_insert(0) += 1;
            }
        }
    }
    counts
}

/// Name every identity that covered two declarations, so a user sees which ones could not be told apart.
///
/// `collisions` lists the identities the baseline found shared between declarations.
/// Returns one non-fatal `baseline-collision` diagnostic per collision naming its identity, subjects, rule, and file.
pub(crate) fn collision_diagnostics(collisions: &[BaselineCollision]) -> Vec<RunDiagnostic> {
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

/// Returns the baseline `path` relative to `project_root` after resolving filesystem components when possible.
fn baseline_display_path(project_root: &Path, path: &Path) -> String {
    match (project_root.canonicalize(), path.canonicalize()) {
        (Ok(root), Ok(resolved)) => display_path(&root, &resolved),
        _ => display_path(project_root, path),
    }
}

/// Append this run's finding count and composite score to the JSON history file, keeping only the newest 100 entries.
///
/// `history_file` is resolved against `project_root`; `findings`, `config`, and `evaluated_files` feed the recorded count and score.
/// Each entry also records the current time; a missing, unreadable, or malformed history file starts a new list holding only this entry.
/// `diagnostics` gains a `history-error` diagnostic when the file cannot be written.
pub(crate) fn record_history(
    project_root: &Path,
    history_file: &Path,
    findings: &[Finding],
    config: &Config,
    evaluated_files: usize,
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
        "score": score_report(findings, config, evaluated_files).composite,
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
            invalidates_run: None,
        });
    }
}
