use super::*;

/// Whether a touched line pulls in its whole enclosing symbol (`Symbol`) or only
/// the changed hunk (`Hunk`) when scoping findings to a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum ChangedScope {
    Symbol,
    Hunk,
}

/// A resolved changed-region filter: the line map to scope findings against, the
/// symbol/hunk scope, and whether it came from explicit `--changed-ranges` (which
/// must not also narrow the analysed file set, since the ranges already scope it).
pub(crate) struct ResolvedDiffFilter {
    pub(crate) patch: DiffPatchLineMap,
    pub(crate) scope: ChangedScope,
    pub(crate) explicit_ranges: bool,
}

/// Resolve the requested diff selection into a `ResolvedDiffFilter`, or `None`
/// when no diff mode was requested. Acquires the line map per mode: a unified
/// patch (`--diff-patch`), a Git diff (`--diff`/`--since`), or explicit ranges.
pub(crate) fn resolve_diff_filter(
    project_root: &Path,
    options: &AnalysisOptions,
    files: &[SourceFile],
) -> Result<Option<ResolvedDiffFilter>, String> {
    let Some(selection) = &options.diff else {
        return Ok(None);
    };
    let filter = match selection {
        DiffSelection::Patch { path, scope } => ResolvedDiffFilter {
            patch: parse_patch_selection(project_root, path)?,
            scope: *scope,
            explicit_ranges: false,
        },
        DiffSelection::Git { mode, scope } => ResolvedDiffFilter {
            patch: git_diff_patch(project_root, mode, &options.paths)?,
            scope: *scope,
            explicit_ranges: false,
        },
        DiffSelection::ExplicitRanges { ranges, scope } => ResolvedDiffFilter {
            patch: explicit_ranges_patch(ranges, files)?,
            scope: *scope,
            explicit_ranges: true,
        },
    };
    Ok(Some(filter))
}

/// Read and parse a `--diff-patch` file into a line map, erroring when the input
/// is not a parseable unified diff.
fn parse_patch_selection(project_root: &Path, path: &Path) -> Result<DiffPatchLineMap, String> {
    let patch_text = read_diff_patch(project_root, path)?;
    let patch = parse_unified_diff(&patch_text);
    if !patch.saw_hunk && patch.changed_files().is_empty() {
        return Err(format!(
            "--diff-patch {} is not a parseable unified diff",
            path.display()
        ));
    }
    Ok(patch)
}

/// Narrow discovery to the patch's changed files for file-based diff modes;
/// explicit-range mode keeps every analysed file because the ranges already
/// scope the findings.
pub(crate) fn apply_diff_file_selection(
    discovery: &mut DiscoveryResult,
    diff_filter: Option<&ResolvedDiffFilter>,
) {
    let Some(diff_filter) = diff_filter else {
        return;
    };
    if diff_filter.explicit_ranges {
        return;
    }
    let changed = diff_filter.patch.changed_files();
    discovery
        .files
        .retain(|file| changed.contains(&file.display_path));
}

/// Build a `DiffPatchLineMap` from explicit `--changed-ranges` (e.g. `3-3,8-10`)
/// applied to every analysed file. Git-free: the caller already knows which lines
/// changed, so a coding-agent hook can pass them straight in.
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

/// Build a `DiffPatchLineMap` by running `git diff` for `mode` (a ref or one of
/// `working-tree`/`staged`/`unstaged`). Executes Git, so it is only reached from
/// the `--diff-git-unsafe`-gated modes. `working-tree` also folds in untracked
/// files as whole-file changes.
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

/// Parse a `--changed-ranges` value (comma-separated `start-end` or single lines)
/// into the set of 1-based line numbers it covers. Errors on non-integers,
/// zero/negative lines, reversed ranges, or an empty result.
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

/// Parse one `--changed-ranges` line number, requiring a `>= 1` integer.
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

/// Build a git argv: `prefix` tokens, a `--` separator, then the paths. Keeps the
/// path operands after `--` so a path that looks like a flag is never misread.
fn git_args_with_paths(prefix: &[&str], paths: &[PathBuf]) -> Vec<String> {
    prefix
        .iter()
        .map(|value| value.to_string())
        .chain(std::iter::once("--".to_string()))
        .chain(paths.iter().map(|path| path.display().to_string()))
        .collect()
}

/// Build a `git -C <root> <args>` command without running it. Arguments go to
/// git as argv entries, never through a shell, so a ref or path in `args` is
/// inert data git receives rather than an interpreted command line - the reason
/// this is safe despite the dynamic arguments. Construction is split from
/// execution so the call site stays a plain builder.
fn git_command(project_root: &Path, args: &[String]) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command.arg("-C").arg(project_root).args(args);
    command
}

/// Run a git command under `project_root` and return its stdout, mapping a
/// non-zero exit or spawn failure to an `Err` with git's stderr. Only reached
/// from the Git-backed diff modes, which require `--diff-git-unsafe`.
fn git_output(project_root: &Path, args: &[String]) -> Result<String, String> {
    let output = git_command(project_root, args)
        .output()
        .map_err(|error| format!("unable to execute git diff: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// List untracked, non-ignored files under `paths` via `git ls-files --others
/// --exclude-standard`, normalised to report paths. Used to treat new files as
/// whole-file changes in `working-tree` mode.
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

/// Decide whether a finding falls inside the changed region, honouring the
/// symbol/hunk scope. Under `Symbol`, a finding on an unchanged line still counts
/// when its enclosing function block overlaps a changed line (so a signature
/// finding survives a body-only edit); under `Hunk`, only the changed lines do.
pub(crate) fn patch_intersects_finding_with_scope(
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

/// Find the smallest function block containing `line` - preferring one whose name
/// matches `symbol`, then falling back to any block - so a finding maps to the
/// tightest enclosing function for symbol-scope checks.
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

/// Match a finding's `symbol` against a block name, accepting an exact match or a
/// dotted suffix (e.g. `Type.method` matches block `method`). `None` matches any.
fn symbol_matches(symbol: Option<&str>, block_name: &str) -> bool {
    symbol.is_none_or(|symbol| symbol == block_name || symbol.ends_with(&format!(".{block_name}")))
}
