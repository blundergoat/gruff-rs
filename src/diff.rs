use super::*;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DiffPatchLineMap {
    pub(crate) lines_by_file: BTreeMap<String, BTreeSet<usize>>,
    pub(crate) saw_hunk: bool,
}

impl DiffPatchLineMap {
    pub(crate) fn changed_files(&self) -> BTreeSet<String> {
        self.lines_by_file.keys().cloned().collect()
    }
}

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

#[derive(Default)]
pub(crate) struct DiffPatchState {
    current_file: Option<String>,
    current_new_line: Option<usize>,
}

pub(crate) enum DiffHunkLineKind {
    Added,
    Context,
    OldSideOnly,
    NoNewlineMarker,
    OutsideHunk,
}

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

pub(crate) fn ensure_diff_file_entry(
    line_map: &mut DiffPatchLineMap,
    current_file: &Option<String>,
) {
    if let Some(file) = current_file {
        line_map.lines_by_file.entry(file.clone()).or_default();
    }
}

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
    fn is_inside_hunk(&self) -> bool {
        matches!(
            self,
            Self::Added | Self::Context | Self::OldSideOnly | Self::NoNewlineMarker
        )
    }
}

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
        index = push_unquoted_git_path_byte(inner_bytes, index, &mut bytes);
    }
    Some(String::from_utf8_lossy(&bytes).to_string())
}

fn push_unquoted_git_path_byte(bytes: &[u8], index: usize, output: &mut Vec<u8>) -> usize {
    if bytes[index] != b'\\' {
        output.push(bytes[index]);
        return index + 1;
    }

    let escape_start = index + 1;
    if let Some((value, next_index)) = read_git_octal_escape(bytes, escape_start) {
        output.push(value);
        return next_index;
    }

    match bytes.get(escape_start).copied() {
        Some(escaped) => {
            output.push(git_escaped_byte(escaped));
            escape_start + 1
        }
        None => {
            output.push(b'\\');
            escape_start
        }
    }
}

fn read_git_octal_escape(bytes: &[u8], start: usize) -> Option<(u8, usize)> {
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

fn is_octal(byte: u8) -> bool {
    matches!(byte, b'0'..=b'7')
}

fn git_escaped_byte(byte: u8) -> u8 {
    match byte {
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        other => other,
    }
}

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

pub(crate) fn normalize_report_path(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

pub(crate) fn apply_diff_patch_filter(
    mut report: AnalysisReport,
    patch: &DiffPatchLineMap,
    analysed_files: &BTreeSet<String>,
) -> AnalysisReport {
    let total_findings = report.findings.len();
    let changed_files = patch.changed_files();
    let missing_files = unanalysed_patch_files(&changed_files, analysed_files);
    let kept = retain_findings_in_patch(&mut report, patch, &changed_files);
    let kept_findings = kept.len();
    let suppressed_findings = total_findings.saturating_sub(kept_findings);

    report.findings = kept;
    report.summary = summarize(&report.findings);
    report.score = score_report(&report.findings);
    push_patch_filter_diagnostic(
        &mut report,
        total_findings,
        kept_findings,
        suppressed_findings,
        &missing_files,
    );
    report
}

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

fn retain_findings_in_patch(
    report: &mut AnalysisReport,
    patch: &DiffPatchLineMap,
    changed_files: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut kept = Vec::new();
    for finding in std::mem::take(&mut report.findings) {
        if patch_intersects_finding(&finding, patch, changed_files) {
            kept.push(finding);
        }
    }
    report
        .suppressed_findings
        .retain(|suppressed| patch_intersects_finding(&suppressed.finding, patch, changed_files));
    recount_suppressions(&mut report.suppressions, &report.suppressed_findings);
    kept
}

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
    });
}

pub(crate) fn recount_suppressions(
    summaries: &mut [SuppressionSummary],
    suppressed_findings: &[SuppressedFinding],
) {
    for summary in summaries.iter_mut() {
        summary.suppressed = 0;
    }
    for suppressed in suppressed_findings {
        if let Some(summary) = summaries.get_mut(suppressed.suppression.index) {
            summary.suppressed += 1;
        }
    }
}

pub(crate) fn patch_intersects_finding(
    finding: &Finding,
    patch: &DiffPatchLineMap,
    changed_files: &BTreeSet<String>,
) -> bool {
    let file_path = normalize_report_path(&finding.file_path);
    if !changed_files.contains(&file_path) {
        return false;
    }
    let Some(line) = finding.line else {
        return true;
    };
    patch
        .lines_by_file
        .get(&file_path)
        .is_some_and(|lines| lines.contains(&line))
}

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
