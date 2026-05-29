use super::*;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DiffPatchLineMap {
    pub(crate) lines_by_file: BTreeMap<String, BTreeSet<usize>>,
    pub(crate) whole_files: BTreeSet<String>,
    pub(crate) saw_hunk: bool,
}

impl DiffPatchLineMap {
    pub(crate) fn changed_files(&self) -> BTreeSet<String> {
        self.lines_by_file
            .keys()
            .chain(self.whole_files.iter())
            .cloned()
            .collect()
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

pub(crate) fn explicit_ranges_patch(
    ranges: &str,
    files: &[SourceFile],
) -> Result<DiffPatchLineMap, String> {
    let lines = parse_changed_ranges(ranges)?;
    let mut line_map = DiffPatchLineMap {
        saw_hunk: true,
        ..DiffPatchLineMap::default()
    };
    for file in files {
        line_map
            .lines_by_file
            .insert(file.display_path.clone(), lines.clone());
    }
    Ok(line_map)
}

pub(crate) fn git_diff_patch(
    project_root: &Path,
    mode: &str,
    paths: &[PathBuf],
) -> Result<DiffPatchLineMap, String> {
    let patch = match mode {
        "working-tree" => git_output(
            project_root,
            &git_args_with_paths(&["diff", "--unified=0", "HEAD"], paths),
        )?,
        "staged" => git_output(
            project_root,
            &git_args_with_paths(&["diff", "--cached", "--unified=0"], paths),
        )?,
        "unstaged" => git_output(
            project_root,
            &git_args_with_paths(&["diff", "--unified=0"], paths),
        )?,
        base => git_output(
            project_root,
            &git_args_with_paths(&["diff", "--unified=0", base], paths),
        )?,
    };
    let mut parsed = parse_unified_diff(&patch);
    if mode == "working-tree" {
        for path in git_untracked_files(project_root, paths)? {
            parsed.whole_files.insert(path.clone());
            parsed.lines_by_file.entry(path).or_default();
        }
    }
    Ok(parsed)
}

fn parse_changed_ranges(ranges: &str) -> Result<BTreeSet<usize>, String> {
    let mut lines = BTreeSet::new();
    for raw_part in ranges.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        let (start, end) = match part.split_once('-') {
            Some((start, end)) => (
                parse_positive_line(start, part)?,
                parse_positive_line(end, part)?,
            ),
            None => {
                let line = parse_positive_line(part, part)?;
                (line, line)
            }
        };
        if end < start {
            return Err(format!(
                "invalid changed range `{part}`: end must be >= start"
            ));
        }
        lines.extend(start..=end);
    }
    if lines.is_empty() {
        return Err("--changed-ranges must include at least one line or range".to_string());
    }
    Ok(lines)
}

fn parse_positive_line(raw: &str, original: &str) -> Result<usize, String> {
    let value = raw.parse::<usize>().map_err(|_| {
        format!("invalid changed range `{original}`: line numbers must be integers")
    })?;
    if value == 0 {
        return Err(format!(
            "invalid changed range `{original}`: line numbers must be >= 1"
        ));
    }
    Ok(value)
}

fn git_args_with_paths(prefix: &[&str], paths: &[PathBuf]) -> Vec<String> {
    prefix
        .iter()
        .map(|value| value.to_string())
        .chain(std::iter::once("--".to_string()))
        .chain(paths.iter().map(|path| path.display().to_string()))
        .collect()
}

fn git_output(project_root: &Path, args: &[String]) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(project_root)
        .args(args)
        .output()
        .map_err(|error| format!("unable to execute git diff: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn git_untracked_files(project_root: &Path, paths: &[PathBuf]) -> Result<Vec<String>, String> {
    let output = git_output(
        project_root,
        &git_args_with_paths(&["ls-files", "--others", "--exclude-standard"], paths),
    )?;
    Ok(output
        .lines()
        .map(normalize_report_path)
        .filter(|path| !path.is_empty())
        .collect())
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

pub(crate) use git_quoted::unquote_git_path;

mod git_quoted {
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

    fn is_octal(byte: u8) -> bool {
        matches!(byte, b'0'..=b'7')
    }

    fn escaped_byte(byte: u8) -> u8 {
        match byte {
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            other => other,
        }
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
    report.score = score_report(&report.findings, config);
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

struct DiffPatchPartition {
    kept: Vec<Finding>,
    suppressed: Vec<Finding>,
}

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
    if patch.whole_files.contains(&file_path) {
        return true;
    }
    let Some(line) = finding.line else {
        return true;
    };
    let end_line = finding.end_line.unwrap_or(line).max(line);
    patch_range_intersects(patch, &file_path, line, end_line)
}

fn patch_intersects_finding_with_scope(
    finding: &Finding,
    patch: &DiffPatchLineMap,
    changed_files: &BTreeSet<String>,
    function_blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
    scope: ChangedScope,
) -> bool {
    if patch_intersects_finding(finding, patch, changed_files) {
        return true;
    }
    if scope == ChangedScope::Hunk {
        return false;
    }
    let Some(line) = finding.line else {
        return false;
    };
    let file_path = normalize_report_path(&finding.file_path);
    let Some(blocks) = function_blocks_by_file.get(&file_path) else {
        return false;
    };
    let Some(block) = enclosing_block(line, finding.symbol.as_deref(), blocks) else {
        return false;
    };
    let block_end = block.start_line + block.line_count.saturating_sub(1);
    patch_range_intersects(patch, &file_path, block.start_line, block_end)
}

fn patch_range_intersects(
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

fn enclosing_block<'a>(
    line: usize,
    symbol: Option<&str>,
    blocks: &'a [FunctionBlock],
) -> Option<&'a FunctionBlock> {
    blocks
        .iter()
        .filter(|block| {
            let end = block.start_line + block.line_count.saturating_sub(1);
            line >= block.start_line && line <= end && symbol_matches(symbol, &block.name)
        })
        .min_by_key(|block| block.line_count)
        .or_else(|| {
            blocks
                .iter()
                .filter(|block| {
                    let end = block.start_line + block.line_count.saturating_sub(1);
                    line >= block.start_line && line <= end
                })
                .min_by_key(|block| block.line_count)
        })
}

fn symbol_matches(symbol: Option<&str>, block_name: &str) -> bool {
    symbol.is_none_or(|symbol| symbol == block_name || symbol.ends_with(&format!(".{block_name}")))
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
