//! Read the unified patch a developer passes to `analyse --diff-patch` or supplies through standard input.
//!
//! Keep the new-side paths and line ranges so the report can show findings relevant to the edit.
//! A deletion with no new lines contributes no line range to inspect.

use super::*;

/// Record the new-side lines a patch lets a changed-code scan inspect.
///
/// File-only entries cover changes with no usable hunk context. A file can also have no added lines.
/// Callers can list the changed files even when none contributes a line to filter.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DiffPatchLineMap {
    pub(crate) lines_by_file: BTreeMap<String, BTreeSet<usize>>,
    pub(crate) whole_files: BTreeSet<String>,
    pub(crate) saw_hunk: bool,
}

impl DiffPatchLineMap {
    /// List the files this map records, including entries with no added lines and whole-file changes.
    ///
    /// Returns the sorted union of the files in `lines_by_file`, including those with no added lines, and those in `whole_files`.
    pub(crate) fn changed_files(&self) -> BTreeSet<String> {
        self.lines_by_file
            .keys()
            .chain(self.whole_files.iter())
            .cloned()
            .collect()
    }
}

/// Read the unified diff a `--diff-patch` run filters by, from standard input when the path is `-`.
///
/// `project_root` anchors a relative `path`, and `path` is the patch file, or `-` for standard input.
/// Returns the patch text, or Err naming stdin or `path` when it cannot be read.
pub(crate) fn read_diff_patch(project_root: &Path, path: &Path) -> Result<String, String> {
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

/// Track where the patch reader is in the file and new-side hunk.
///
/// Until a file and line have been read, there is no changed line for a finding to match.
/// The reader resets the position when the next file or hunk begins.
#[derive(Default)]
pub(crate) struct DiffPatchState {
    current_file: Option<String>,
    current_new_line: Option<usize>,
}

/// Decide how a patch line affects the location of a finding on the new side.
///
/// Added lines enter the changed region. Context advances the new-side location without marking it changed.
/// Old-side lines and the newline marker contribute no new-side locations.
pub(crate) enum DiffHunkLineKind {
    Added,
    Context,
    OldSideOnly,
    NoNewlineMarker,
    OutsideHunk,
}

/// Collect the new-side line numbers each file gains in a unified diff, so findings can be matched against the changed region.
///
/// `patch` is the diff text; trailing carriage returns are ignored, and inside a hunk a `+++` line counts as an added line, not a header.
/// Returns the added new-side line numbers per named file, an empty set for a file with none, and `saw_hunk` set once a hunk header parses.
pub(crate) fn parse_unified_diff(patch: &str) -> DiffPatchLineMap {
    let mut line_map = DiffPatchLineMap::default();
    let mut state = DiffPatchState::default();

    for raw_line in patch.lines() {
        let line = raw_line.trim_end_matches('\r');
        if state.current_new_line.is_some() && diff_hunk_line_kind(line).is_inside_hunk() {
            record_diff_hunk_line(line, &mut state, &mut line_map);
            continue;
        }
        if should_handle_diff_header(line, &mut state, &mut line_map) {
            continue;
        }
        record_diff_hunk_line(line, &mut state, &mut line_map);
    }

    line_map
}

/// Apply a file or hunk header line to the parse state, so the lines after it are attributed to the right file and new-side line.
///
/// `line` is one patch line with any trailing carriage return removed.
/// `state` takes the file from a `+++` line or the start of an `@@` hunk, and a `diff --git` or binary marker ends the current hunk.
/// `line_map` gains an empty entry for the current file and has `saw_hunk` set once a hunk start parses.
///
/// Returns true when `line` was one of these headers, and false when it must be handled as hunk content.
pub(crate) fn should_handle_diff_header(
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
        if state.current_new_line.is_some() {
            line_map.saw_hunk = true;
        }
        return true;
    }

    false
}

/// Register the current file in the line map before any added line, so a file whose hunks only delete still counts as changed.
///
/// `line_map` gains an empty line set for `current_file` unless it has one, and nothing happens when `current_file` is None.
pub(crate) fn ensure_diff_file_entry(
    line_map: &mut DiffPatchLineMap,
    current_file: &Option<String>,
) {
    if let Some(file) = current_file {
        line_map.lines_by_file.entry(file.clone()).or_default();
    }
}

/// Advance the new-side line counter over one hunk line, recording the line number when the line was added.
///
/// `line` is the patch line; nothing happens unless `state` has both a current file and an open hunk.
/// `state` advances its new-side line on added and context lines and closes the hunk on a line that cannot be hunk content.
/// `line_map` gains the new-side number of each added line under the current file.
pub(crate) fn record_diff_hunk_line(
    line: &str,
    state: &mut DiffPatchState,
    line_map: &mut DiffPatchLineMap,
) {
    let Some(new_line) = state.current_new_line.as_mut() else {
        return;
    };
    let Some(file) = &state.current_file else {
        return;
    };

    match diff_hunk_line_kind(line) {
        DiffHunkLineKind::Added => {
            line_map
                .lines_by_file
                .entry(file.clone())
                .or_default()
                .insert(*new_line);
            *new_line += 1;
        }
        DiffHunkLineKind::Context => {
            *new_line += 1;
        }
        DiffHunkLineKind::OldSideOnly | DiffHunkLineKind::NoNewlineMarker => {}
        DiffHunkLineKind::OutsideHunk => state.current_new_line = None,
    }
}

/// Classify one patch line by its first character, as it would read inside a hunk.
///
/// `line` is the patch line without its trailing carriage return.
/// Returns `NoNewlineMarker` for `\`, `OldSideOnly` for `-`, `Added` for `+` and `Context` for a space.
/// Any other line, including an empty one, is `OutsideHunk`.
pub(crate) fn diff_hunk_line_kind(line: &str) -> DiffHunkLineKind {
    if line.starts_with('\\') {
        DiffHunkLineKind::NoNewlineMarker
    } else if line.starts_with('-') {
        DiffHunkLineKind::OldSideOnly
    } else if line.starts_with('+') {
        DiffHunkLineKind::Added
    } else if line.starts_with(' ') {
        DiffHunkLineKind::Context
    } else {
        DiffHunkLineKind::OutsideHunk
    }
}

impl DiffHunkLineKind {
    /// Tell whether a line of this kind continues an open hunk.
    ///
    /// Returns true for added, context, old-side-only and no-newline-marker lines, and false for `OutsideHunk`.
    fn is_inside_hunk(&self) -> bool {
        matches!(
            self,
            Self::Added | Self::Context | Self::OldSideOnly | Self::NoNewlineMarker
        )
    }
}

/// Turn the path text of a `+++` header into the report-relative path findings use.
///
/// `raw_path` may be C-quoted or carry a tab-separated timestamp, and one leading `b/` or `a/` prefix is stripped from it.
/// Returns the normalised path, or None for `/dev/null` or a path that is empty after normalising.
pub(crate) fn parse_diff_path(raw_path: &str) -> Option<String> {
    let unquoted = unquote_git_path(raw_path);
    let path = unquoted
        .as_deref()
        .unwrap_or(raw_path)
        .split_once('\t')
        .map(|(path, _)| path)
        .unwrap_or_else(|| unquoted.as_deref().unwrap_or(raw_path))
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

pub(crate) use git_quoted::unquote_git_path;

mod git_quoted {
    /// Decode a quoted git path's octal, newline, carriage-return and tab escapes; any other escaped byte just loses its backslash.
    ///
    /// `raw_path` is the path text; whitespace around it is ignored.
    /// Returns the decoded path, with invalid UTF-8 replaced lossily, or None when `raw_path` is not wrapped in double quotes.
    pub(crate) fn unquote_git_path(raw_path: &str) -> Option<String> {
        let trimmed = raw_path.trim();
        if !(trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2) {
            return None;
        }
        let inner = &trimmed[1..trimmed.len() - 1];
        let inner_bytes = inner.as_bytes();
        let mut bytes = Vec::with_capacity(inner.len());
        let mut index = 0usize;
        while index < inner_bytes.len() {
            index = push_unquoted_byte(inner_bytes, index, &mut bytes);
        }
        Some(String::from_utf8_lossy(&bytes).to_string())
    }

    /// Decode one character of a quoted git path, either a literal byte or a backslash escape.
    ///
    /// `bytes` is the text between the quotes, and `index` is where this character starts; an `index` at or past the end panics.
    /// `output` gains the decoded byte, or a lone backslash when the text ends in one.
    /// Returns the index just after the consumed character or escape.
    fn push_unquoted_byte(bytes: &[u8], index: usize, output: &mut Vec<u8>) -> usize {
        if bytes[index] != b'\\' {
            output.push(bytes[index]);
            return index + 1;
        }

        let escape_start = index + 1;
        if let Some((value, next_index)) = read_octal_escape(bytes, escape_start) {
            output.push(value);
            return next_index;
        }

        match bytes.get(escape_start).copied() {
            Some(escaped) => {
                output.push(escaped_byte(escaped));
                escape_start + 1
            }
            None => {
                output.push(b'\\');
                escape_start
            }
        }
    }

    /// Read a git octal escape of one to three digits, the form git uses for non-ASCII path bytes.
    ///
    /// `bytes` is the quoted path text and `start` is the index just after the backslash.
    /// Returns the byte value, capped at 255, with the index after the last digit, or None when no octal digit is at `start`.
    fn read_octal_escape(bytes: &[u8], start: usize) -> Option<(u8, usize)> {
        bytes.get(start).copied().filter(|byte| is_octal(*byte))?;
        let mut value = 0u8;
        let mut index = start;
        for _ in 0..3 {
            let Some(octal) = bytes.get(index).copied().filter(|byte| is_octal(*byte)) else {
                break;
            };
            value = value.saturating_mul(8).saturating_add(octal - b'0');
            index += 1;
        }
        Some((value, index))
    }

    /// Test whether a byte is an ASCII octal digit, the only digits a git path escape uses.
    ///
    /// `byte` is the candidate escape character.
    /// Returns true for `0` through `7`.
    fn is_octal(byte: u8) -> bool {
        matches!(byte, b'0'..=b'7')
    }

    /// Decode the character after a backslash in a quoted git path when it does not start an octal escape.
    ///
    /// `byte` is the escaped character.
    /// Returns a newline, carriage return or tab for `n`, `r` and `t`, and `byte` itself otherwise, as for an escaped quote or backslash.
    fn escaped_byte(byte: u8) -> u8 {
        match byte {
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            other => other,
        }
    }
}

/// Read the new-side start line from an `@@` hunk header.
///
/// `line` is the hunk header; the digits after its first `+` are taken.
/// Returns the start line, raised to 1 when the header says 0, or None without a `+` or digits after it, or when they overflow `usize`.
pub(crate) fn parse_hunk_new_start(line: &str) -> Option<usize> {
    let plus = line.find('+')?;
    let rest = &line[plus + 1..];
    let digits: String = rest
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    let start = digits.parse::<usize>().ok()?;
    Some(start.max(1))
}

/// Bring a patch or finding path into one form, so the two can be compared directly.
///
/// `path` is a file path from a patch or a finding.
/// Returns `path` with backslashes turned into forward slashes and every leading `./` removed.
pub(crate) fn normalize_report_path(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

/// Returns whether `path` consists of project-relative components without parent traversal.
pub(crate) fn is_relative_scan_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\0')
        && Path::new(path).components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

/// Exercise the hunk-only behavior of `--diff-patch` on an existing report in a test.
///
/// `patch` selects changed lines, `analysed_files` records what was scanned, and `config` supplies score settings.
/// Returns the filtered `report` with the updated counts and diagnostic.
#[cfg(test)]
pub(crate) fn apply_diff_patch_filter(
    report: AnalysisReport,
    patch: &DiffPatchLineMap,
    analysed_files: &BTreeSet<String>,
    config: &Config,
) -> AnalysisReport {
    apply_changed_region_filter(
        report,
        patch,
        analysed_files,
        config,
        &BTreeMap::new(),
        ChangedScope::Hunk,
    )
}

/// Narrow a finished report to the findings inside the changed region and rescore it, recording what was dropped.
///
/// `report` is consumed, `patch` is the parsed diff, and `analysed_files` lets patch files the run never scanned be named.
/// `config` drives the rescoring, and `function_blocks_by_file` and `scope` feed the check that decides which findings touch the change.
///
/// Returns the report holding only intersecting findings, with its summary and score recomputed over them.
/// Its per-rule deltas count kept findings as introduced and dropped ones as removed, and are None when there are none.
/// Its suppressed-finding audit is narrowed the same way, `suppressed_count` holds the dropped count, and a `patch-filter` diagnostic is added.
pub(crate) fn apply_changed_region_filter(
    mut report: AnalysisReport,
    patch: &DiffPatchLineMap,
    analysed_files: &BTreeSet<String>,
    config: &Config,
    function_blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
    scope: ChangedScope,
) -> AnalysisReport {
    let total_findings = report.findings.len();
    let changed_files = patch.changed_files();
    let missing_files = unanalysed_patch_files(&changed_files, analysed_files);
    let DiffPatchPartition { kept, suppressed } = partition_findings_by_patch(
        &mut report,
        patch,
        &changed_files,
        function_blocks_by_file,
        scope,
    );
    let kept_findings = kept.len();
    let suppressed_findings = total_findings.saturating_sub(kept_findings);

    let deltas = patch_rule_deltas(&kept, &suppressed);
    report.findings = kept;
    report.summary = summarize(&report.findings);
    // Under a diff, align the pre-baseline summary with the filtered set so
    // `gate.scope: all` gates over the changed region too (ADR-003 addendum).
    report.all_findings_summary = Some(report.summary);
    // Rescoring the changed region keeps the run's own denominator, so the delta measures the
    // findings the diff selected rather than the difference between two project sizes.
    report.score = score_report(&report.findings, config, report.score.evaluated_files);
    report.per_rule_deltas = (!deltas.is_empty()).then_some(deltas);
    report.suppressed_count = Some(suppressed_findings);
    push_patch_filter_diagnostic(
        &mut report,
        total_findings,
        kept_findings,
        suppressed_findings,
        &missing_files,
    );
    report
}

/// Summarise only the findings that touch the changed region, leaving the findings themselves untouched.
///
/// `findings` are the run's findings and `patch` is the parsed diff.
/// `function_blocks_by_file` and `scope` feed the same intersection check `apply_changed_region_filter` uses.
/// Returns the summary of the intersecting findings.
pub(crate) fn summarize_changed_findings(
    findings: &[Finding],
    patch: &DiffPatchLineMap,
    function_blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
    scope: ChangedScope,
) -> Summary {
    let changed_files = patch.changed_files();
    let changed_findings: Vec<Finding> = findings
        .iter()
        .filter(|finding| {
            patch_intersects_finding_with_scope(
                finding,
                patch,
                &changed_files,
                function_blocks_by_file,
                scope,
            )
        })
        .cloned()
        .collect();
    summarize(&changed_findings)
}

/// Count, per rule, the findings the changed-region filter kept as introduced and those it dropped as removed.
///
/// `kept` are the findings inside the changed region and `suppressed` are those outside it.
/// Returns the per-rule deltas that `rule_deltas_from_counts` builds from those two counts.
fn patch_rule_deltas(kept: &[Finding], suppressed: &[Finding]) -> Vec<RuleDelta> {
    let mut introduced_per_rule: BTreeMap<String, usize> = BTreeMap::new();
    for finding in kept {
        *introduced_per_rule
            .entry(finding.rule_id.clone())
            .or_insert(0) += 1;
    }
    let mut removed_per_rule: BTreeMap<String, usize> = BTreeMap::new();
    for finding in suppressed {
        *removed_per_rule.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }
    crate::rule_deltas_from_counts(&introduced_per_rule, &removed_per_rule)
}

/// Find the recorded patch files that the run never analysed, so the filter diagnostic can name them.
///
/// `changed_files` are the files the patch map records and `analysed_files` the files the run scanned.
/// Returns the changed files missing from `analysed_files` in sorted order, or an empty list when all were analysed.
fn unanalysed_patch_files(
    changed_files: &BTreeSet<String>,
    analysed_files: &BTreeSet<String>,
) -> Vec<String> {
    changed_files
        .iter()
        .filter(|file| !analysed_files.contains(*file))
        .cloned()
        .collect()
}

/// Separate findings that belong in a changed-code report from those filtered out.
///
/// The kept rows are presented to the caller for review.
/// The excluded rows support the audit of what stayed outside this edit's scope.
struct DiffPatchPartition {
    kept: Vec<Finding>,
    suppressed: Vec<Finding>,
}

/// Split the report's findings into those that touch the changed region and those that do not.
///
/// `report` is changed in place: its findings are moved out, and suppressed findings outside the region leave its audit and counts.
/// `patch`, `changed_files`, `function_blocks_by_file` and `scope` feed the intersection check that decides each finding.
/// Returns the kept findings and the dropped ones, each in their original order.
fn partition_findings_by_patch(
    report: &mut AnalysisReport,
    patch: &DiffPatchLineMap,
    changed_files: &BTreeSet<String>,
    function_blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
    scope: ChangedScope,
) -> DiffPatchPartition {
    let mut kept = Vec::new();
    let mut suppressed = Vec::new();
    for finding in std::mem::take(&mut report.findings) {
        if patch_intersects_finding_with_scope(
            &finding,
            patch,
            changed_files,
            function_blocks_by_file,
            scope,
        ) {
            kept.push(finding);
        } else {
            suppressed.push(finding);
        }
    }
    report.suppressed_findings.retain(|suppressed| {
        patch_intersects_finding_with_scope(
            &suppressed.finding,
            patch,
            changed_files,
            function_blocks_by_file,
            scope,
        )
    });
    recount_suppressions(&mut report.suppressions, &report.suppressed_findings);
    DiffPatchPartition { kept, suppressed }
}

/// Record what the changed-region filter did as a `patch-filter` diagnostic on the report.
///
/// `report` gains the diagnostic, which names no file or line and leaves `invalidates_run` unset.
/// `total_findings`, `kept_findings` and `suppressed_findings` are the filter's before, kept and dropped counts.
/// `missing_files` are the patch files the run did not analyse, named in the message.
fn push_patch_filter_diagnostic(
    report: &mut AnalysisReport,
    total_findings: usize,
    kept_findings: usize,
    suppressed_findings: usize,
    missing_files: &[String],
) {
    report.diagnostics.push(RunDiagnostic {
        diagnostic_type: "patch-filter".to_string(),
        message: patch_filter_message(
            total_findings,
            kept_findings,
            suppressed_findings,
            missing_files,
        ),
        file_path: None,
        line: None,
        invalidates_run: None,
    });
}

/// Recompute each suppression summary's count from the suppressed findings that remain after a filter dropped some.
///
/// `summaries` are changed in place: every count is reset to 0, then raised by one per finding whose config key and index match.
/// `suppressed_findings` are the suppressed findings still in the report; one matching no summary is not counted.
pub(crate) fn recount_suppressions(
    summaries: &mut [SuppressionSummary],
    suppressed_findings: &[SuppressedFinding],
) {
    for summary in summaries.iter_mut() {
        summary.suppressed = 0;
    }
    for suppressed in suppressed_findings {
        // Entry indexes are section-local, so a row is identified by its config key and index together.
        if let Some(summary) = summaries.iter_mut().find(|summary| {
            summary.config_key == suppressed.suppression.config_key
                && summary.index == suppressed.suppression.index
        }) {
            summary.suppressed += 1;
        }
    }
}

/// Decide whether one finding falls inside the changed region by its file and line span.
///
/// `finding` gives the file and line span, `patch` the added lines and whole-file changes, and `changed_files` the files the map records.
///
/// Returns false for a file outside `changed_files`, and true for a whole-file change or a finding with no line.
/// Otherwise it returns whether an added line falls from the finding's line through its end line, a missing or earlier end meaning one line.
pub(crate) fn patch_intersects_finding(
    finding: &Finding,
    patch: &DiffPatchLineMap,
    changed_files: &BTreeSet<String>,
) -> bool {
    let file_path = normalize_report_path(&finding.file_path);
    if !changed_files.contains(&file_path) {
        return false;
    }
    if patch.whole_files.contains(&file_path) {
        return true;
    }
    let Some(line) = finding.line else {
        return true;
    };
    let end_line = finding.end_line.unwrap_or(line).max(line);
    patch_range_intersects(patch, &file_path, line, end_line)
}

/// True when any changed line of `file_path` lies in `start..=end`, or the whole
/// file changed. Shared by `patch_intersects_finding` here and the symbol-scope
/// check in `changed_region`.
///
/// `patch` holds the added lines and whole-file changes, and `file_path` is the normalised report path to look up.
/// `start` and `end` are the first and last line of the span, both inclusive.
/// Returns true on a whole-file change or an added line inside the span, and false otherwise, including for a file the patch never names.
pub(crate) fn patch_range_intersects(
    patch: &DiffPatchLineMap,
    file_path: &str,
    start: usize,
    end: usize,
) -> bool {
    if patch.whole_files.contains(file_path) {
        return true;
    }
    patch
        .lines_by_file
        .get(file_path)
        .is_some_and(|lines| (start..=end).any(|line| lines.contains(&line)))
}

/// Word the `patch-filter` diagnostic so a reader sees how much the changed-region filter kept and which patch files went unanalysed.
///
/// `total_findings`, `kept_findings` and `suppressed_findings` are the counts quoted in the message.
/// `missing_files` are listed comma-separated as patch files not analysed.
/// Returns the message, ending with a note that all patch files were analysed when `missing_files` is empty.
pub(crate) fn patch_filter_message(
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
