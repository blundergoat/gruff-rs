//! Limit findings to the changed code a developer or hook asked to check.
//!
//! A hook can pass `--changed-ranges 3-3,8-10` or `--diff-patch` without invoking Git.
//! Git-backed modes invoke Git explicitly. All modes use the selected hunk or symbol scope to decide which findings remain visible.

use super::*;

/// Choose how far a changed-code scan looks beyond a touched line.
///
/// `Symbol` includes the enclosing declaration. `Hunk` keeps findings within the edited lines.
/// The CLI and hook use this setting to explain the scope in their output.
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
///
/// `project_root` is passed to the patch reader and is the directory Git runs in; `options` carries the diff selection and Git's path operands.
/// `files` is the analysed file set that explicit ranges are applied to; the patch and Git modes ignore it.
/// Returns `Ok(None)` when no diff was requested, otherwise the filter; an `Err` carries the patch, Git or range-parsing failure message.
pub(crate) fn resolve_diff_filter(
    project_root: &Path,
    options: &AnalysisOptions,
    files: &[SourceFile],
) -> Result<Option<ResolvedDiffFilter>, String> {
    // No diff flag was passed, so the operator asked for a full scan and every finding is kept.
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
///
/// `project_root` and `path` are handed to `read_diff_patch` to load the file, and `path` is named in the not-a-diff error.
/// Returns the parsed line map; an `Err` carries a read failure, or the not-a-diff error when neither a hunk nor a changed file was found.
fn parse_patch_selection(project_root: &Path, path: &Path) -> Result<DiffPatchLineMap, String> {
    let patch_text = read_diff_patch(project_root, path)?;
    let patch = parse_unified_diff(&patch_text);
    // A patch from a different layout can name an outside path. Reject it before reporting a misleading changed-file scope.
    if patch
        .changed_files()
        .iter()
        .any(|path| !crate::diff::is_relative_scan_path(path))
    {
        return Err("--diff-patch contains a path outside the project".to_string());
    }
    // Neither a hunk nor a filename came out, so the file is not a diff at all - usually a log or an empty capture. Failing
    // here matters: a silently empty patch would filter away every finding and report a clean scan.
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
///
/// `discovery` is changed in place: its `files` keep only entries whose display path the patch lists as changed.
/// `diff_filter` is the resolved filter; `None`, a full scan, leaves `discovery` untouched.
pub(crate) fn apply_diff_file_selection(
    discovery: &mut DiscoveryResult,
    diff_filter: Option<&ResolvedDiffFilter>,
) {
    // A full scan was requested, so discovery keeps every file it found.
    let Some(diff_filter) = diff_filter else {
        return;
    };
    // The caller supplied line ranges rather than a diff, so it never told us which files to keep. Narrowing here would
    // drop every file the ranges were meant to apply to.
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
///
/// `ranges` is the raw `--changed-ranges` value, and every file in `files` is keyed by its display path to the same line set.
/// Returns the line map with `saw_hunk` set; an `Err` carries the `parse_changed_ranges` message for a malformed or empty `ranges`.
pub(crate) fn explicit_ranges_patch(
    ranges: &str,
    files: &[SourceFile],
) -> Result<DiffPatchLineMap, String> {
    let lines = parse_changed_ranges(ranges)?;
    let mut line_map = DiffPatchLineMap {
        saw_hunk: true,
        ..DiffPatchLineMap::default()
    };
    // The same ranges apply to every analysed file, because the caller already chose the files by passing them as paths.
    for file in files {
        line_map
            .lines_by_file
            .insert(file.display_path.clone(), lines.clone());
    }
    Ok(line_map)
}

/// Read changes for a caller who explicitly enabled Git-backed scanning with `--diff-git-unsafe`.
/// With `working-tree`, new untracked files enter the report as whole-file changes.
/// `mode` selects `working-tree`, `staged`, `unstaged`, or a Git ref to compare against.
///
/// `project_root` is the repository Git runs in, and `paths` are the operands passed after `--` to both the diff and the untracked-file listing.
/// Returns the parsed diff; an `Err` carries a spawn failure or Git's stderr when `git diff` or `git ls-files` fails.
pub(crate) fn git_diff_patch(
    project_root: &Path,
    mode: &str,
    paths: &[PathBuf],
) -> Result<DiffPatchLineMap, String> {
    // `--relative` keeps patch paths relative to `project_root` even inside a nested member crate;
    // `--no-ext-diff`/`--no-textconv` stop an untrusted repo's configured diff drivers from executing.
    let mut diff_arguments = vec![
        "diff",
        "--relative",
        "--no-ext-diff",
        "--no-textconv",
        "--unified=0",
    ];
    match mode {
        // Compare the working tree against the last commit, which is what an operator means by "what have I changed".
        "working-tree" => diff_arguments.push("HEAD"),
        // Only what is already staged, so a partially staged file contributes just the staged hunks.
        "staged" => diff_arguments.push("--cached"),
        // Git's own default compares the working tree against the index, so no extra operand is needed.
        "unstaged" => {}
        // Anything else is taken as a ref the operator named, such as a branch or tag to compare against.
        base => diff_arguments.push(base),
    }
    let patch = git_output(project_root, &git_args_with_paths(&diff_arguments, paths))?;
    let mut parsed = parse_unified_diff(&patch);
    // A new file has no committed side to diff against, so `git diff` says nothing about it. Working-tree mode folds those
    // in as whole-file changes; without this a file the operator just created would be scanned and then filtered away.
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
///
/// Blank parts between commas in `ranges` are skipped.
/// Returns the covered line numbers in ascending order; an `Err` quotes the offending part, or says no line was given.
fn parse_changed_ranges(ranges: &str) -> Result<BTreeSet<usize>, String> {
    let mut lines = BTreeSet::new();
    // e.g. a hook passed `--changed-ranges 3-3,8-10` after rewriting two regions of one file.
    for raw_part in ranges.split(',') {
        let part = raw_part.trim();
        // A trailing comma or doubled separator is tolerated rather than rejected, so a caller building the list by string
        // concatenation does not have to special-case the last element.
        if part.is_empty() {
            continue;
        }
        let (start, end) = match part.split_once('-') {
            // A span such as `8-10` covers every line between its ends inclusive.
            Some((start, end)) => (
                parse_positive_line(start, part)?,
                parse_positive_line(end, part)?,
            ),
            // A bare number such as `3` is the one-line span `3-3`.
            None => {
                let line = parse_positive_line(part, part)?;
                (line, line)
            }
        };
        // A reversed span would silently cover nothing, so the scan would report clean for lines the caller believes it
        // checked. Rejecting it tells them the range is wrong instead.
        if end < start {
            return Err(format!(
                "invalid changed range `{part}`: end must be >= start"
            ));
        }
        lines.extend(start..=end);
    }
    // Every part was blank, so the caller asked to scan nothing while appearing to request a filter; that would gate on an
    // empty set and pass unconditionally.
    if lines.is_empty() {
        return Err("--changed-ranges must include at least one line or range".to_string());
    }
    Ok(lines)
}

/// Parse one `--changed-ranges` line number, requiring a `>= 1` integer.
///
/// `raw` is parsed as given, without trimming, and `original` is the whole range part quoted in either error message.
/// Returns the line number; an `Err` says it is not an integer or is zero.
fn parse_positive_line(raw: &str, original: &str) -> Result<usize, String> {
    let value = raw.parse::<usize>().map_err(|_| {
        format!("invalid changed range `{original}`: line numbers must be integers")
    })?;
    // Diff line numbers start at 1, so a zero means the caller is counting from a different base and every range it sends
    // is off by one.
    if value == 0 {
        return Err(format!(
            "invalid changed range `{original}`: line numbers must be >= 1"
        ));
    }
    Ok(value)
}

/// Build a git argv: `prefix` tokens, a `--` separator, then the paths. Keeps the
/// path operands after `--` so a path that looks like a flag is never misread.
///
/// Returns the owned argument list; with empty `paths` it ends at the `--` separator.
pub(crate) fn git_args_with_paths(prefix: &[&str], paths: &[PathBuf]) -> Vec<String> {
    prefix
        .iter()
        .map(|value| value.to_string())
        .chain(std::iter::once("--".to_string()))
        .chain(paths.iter().map(|path| path.display().to_string()))
        .collect()
}

/// Prepare `git -C <root> <args>` for an explicitly requested Git operation. Refs and paths are passed as separate arguments.
///
/// Git can still get diff drivers from repository settings and attributes. `git_diff_patch` disables external diff and text conversion separately.
/// Keep those flags off other Git commands because `cat-file` and `ls-tree` reject them.
///
/// `project_root` is passed as the `-C` directory, so Git runs inside the scanned repository.
/// Returns the unspawned `Command` with system and global config, system attributes, hooks, pager and the external-diff variable disabled.
fn git_command(project_root: &Path, args: &[String]) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command
        .arg("--no-pager")
        .arg("-C")
        .arg(project_root)
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env_remove("GIT_EXTERNAL_DIFF")
        .env_remove("GIT_PAGER");
    command
}

/// Run a git command under `project_root` and return its stdout, mapping a non-zero exit to an `Err` with git's stderr,
/// and a spawn failure to an `Err` naming the subcommand.
///
/// Callers build argv with `git_args_with_paths` or fixed argument vectors so refs and paths remain inert argv data, never shell input.
///
/// `args` is the argv after git's global options; its first entry names the subcommand in a spawn-failure message.
/// Returns stdout decoded as UTF-8 with invalid bytes replaced; an `Err` carries the failure text described above.
pub(crate) fn git_output(project_root: &Path, args: &[String]) -> Result<String, String> {
    let output = git_output_bytes(project_root, args)?;
    Ok(String::from_utf8_lossy(&output).to_string())
}

/// Run a git command that produces bytes rather than text, for output such as blob contents that is not required to be
/// valid UTF-8. An empty `Ok` result means git succeeded and had nothing to say, which is a normal answer for a query that
/// matched no paths.
///
/// `project_root` is the repository Git runs in and `args` the argv after git's global options; no stdin pipe is opened.
/// Returns raw stdout; an `Err` carries git's stderr on a non-zero exit, or a spawn-failure message naming the subcommand.
pub(crate) fn git_output_bytes(project_root: &Path, args: &[String]) -> Result<Vec<u8>, String> {
    git_output_bytes_with_stdin(project_root, args, &[])
}

/// Run an opted-in Git query for changed-code scanning and return its raw output.
/// Pass stdin for batch queries such as `cat-file --batch`. Empty input runs without a pipe, and nonzero exits report Git's own stderr.
///
/// `project_root` is the repository Git runs in and `args` the argv after git's global options, its first entry naming the subcommand in errors.
/// Returns raw stdout; an `Err` also reports a failed spawn, an unavailable stdin pipe, or a failure waiting for git's output.
pub(crate) fn git_output_bytes_with_stdin(
    project_root: &Path,
    args: &[String],
    stdin: &[u8],
) -> Result<Vec<u8>, String> {
    let mut command = git_command(project_root, args);
    // This helper backs every git subcommand (diff, ls-tree, cat-file, ...), so the
    // spawn-failure message names the actual subcommand rather than always "diff".
    let subcommand = args.first().map(String::as_str).unwrap_or("command");
    // Nothing to send, so git runs without a stdin pipe and the whole exchange is one call.
    if stdin.is_empty() {
        let output = command
            .output()
            .map_err(|error| format!("unable to execute git {subcommand}: {error}"))?;
        return git_stdout_or_error(output);
    }

    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("unable to execute git {subcommand}: {error}"))?;
    // git exited between spawn and here, so there is no pipe to write the query into and the caller gets an error instead
    // of a scan built from a half-sent request.
    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "unable to open git stdin".to_string())?;
    // Write stdin on a separate thread: batched git commands (e.g. `cat-file
    // --batch -Z`) stream stdout while still reading stdin, so writing the whole
    // query buffer before reading stdout would deadlock once the stdout pipe fills.
    let stdin_payload = stdin.to_vec();
    let stdin_writer = std::thread::spawn(move || child_stdin.write_all(&stdin_payload));
    let output = child
        .wait_with_output()
        .map_err(|error| format!("unable to read git output: {error}"))?;
    // git's exit status is authoritative; a `stdin_writer` broken-pipe error (git exiting
    // early) surfaces through git's own stderr in `git_stdout_or_error`.
    let _ = stdin_writer.join();
    git_stdout_or_error(output)
}

/// Turn a finished git process into stdout bytes, or into git's own stderr text when it failed.
/// The failure string keeps git's own wording, so an operator searching for it finds git's documentation rather than
/// gruff's paraphrase; an empty stderr on failure yields an empty error string rather than a fabricated reason.
///
/// `output` is the completed process; on failure its stderr is trimmed and decoded with invalid UTF-8 replaced.
/// Returns the stdout bytes unchanged on a successful exit status, otherwise that stderr text as the `Err`.
fn git_stdout_or_error(output: std::process::Output) -> Result<Vec<u8>, String> {
    // git rejected the request - a bad ref, an unreadable object, a path outside the repo - so there is no diff to trust
    // and the caller must surface the failure rather than scan an empty result as if nothing had changed.
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(output.stdout)
}

/// List untracked, non-ignored files under `paths` via `git ls-files --others
/// --exclude-standard`, normalised to report paths. Used to treat new files as
/// whole-file changes in `working-tree` mode.
///
/// `project_root` is the repository Git runs in.
/// Returns the normalised paths with empty lines dropped; an `Err` carries the `git_output` failure for `git ls-files`.
fn git_untracked_files(project_root: &Path, paths: &[PathBuf]) -> Result<Vec<String>, String> {
    let output = git_output(
        project_root,
        &git_args_with_paths(&["ls-files", "--others", "--exclude-standard"], paths),
    )?;
    // A trailing newline leaves one empty entry; keeping it would insert a whole-file change for a path that does not exist.
    Ok(output
        .lines()
        .map(normalize_report_path)
        .filter(|path| !path.is_empty())
        .collect())
}

/// Check which findings the caller should see for their change.
/// For example, a signature finding stays visible after a body-only edit in symbol scope. Hunk scope keeps only the edited lines.
///
/// `finding` first goes through `patch_intersects_finding` with `patch` and `changed_files` under both scopes; `scope` only governs widening.
/// `function_blocks_by_file` maps a normalised report path to its parsed function blocks, searched only for a line-bearing finding.
/// Returns `true` when that check accepts the finding or, under `Symbol`, its enclosing block overlaps `patch`; else `false`.
pub(crate) fn patch_intersects_finding_with_scope(
    finding: &Finding,
    patch: &DiffPatchLineMap,
    changed_files: &BTreeSet<String>,
    function_blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
    scope: ChangedScope,
) -> bool {
    // The common case: the finding sits on a line the change touched, so it belongs to this change under either scope.
    if patch_intersects_finding(finding, patch, changed_files) {
        return true;
    }
    // Hunk scope stops here by definition - the operator asked for touched lines only, so an untouched line is out.
    if scope == ChangedScope::Hunk {
        return false;
    }
    // A file-level finding has no line to widen from, so symbol scope cannot rescue it.
    let Some(line) = finding.line else {
        return false;
    };
    let file_path = normalize_report_path(&finding.file_path);
    // No parsed functions for this file - a text or unparseable file - so there is no symbol to widen to.
    let Some(blocks) = function_blocks_by_file.get(&file_path) else {
        return false;
    };
    // The finding sits outside every function, at module level, so nothing encloses it.
    let Some(block) = enclosing_block(line, finding.symbol.as_deref(), blocks) else {
        return false;
    };
    let block_end = block.start_line + block.line_count.saturating_sub(1);
    patch_range_intersects(patch, &file_path, block.start_line, block_end)
}

/// Find the smallest function block containing `line` - preferring one whose name
/// matches `symbol`, then falling back to any block - so a finding maps to the
/// tightest enclosing function for symbol-scope checks.
///
/// `blocks` are the parsed function blocks of the finding's file.
/// Returns the chosen block, or `None` when no block in `blocks` contains `line`.
fn enclosing_block<'a>(
    line: usize,
    symbol: Option<&str>,
    blocks: &'a [FunctionBlock],
) -> Option<&'a FunctionBlock> {
    // Prefer a block whose name matches the finding's symbol; with nested functions this picks the one the finding actually
    // names rather than whichever happens to be smallest.
    blocks
        .iter()
        .filter(|block| {
            let end = block.start_line + block.line_count.saturating_sub(1);
            line >= block.start_line && line <= end && symbol_matches(symbol, &block.name)
        })
        .min_by_key(|block| block.line_count)
        .or_else(|| {
            // No name matched - the finding carries a symbol this file spells differently, or none at all - so fall back to
            // the tightest block containing the line.
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
///
/// `block_name` is the short name of the parsed function block being tested.
/// Returns `true` for an exact or dotted-suffix match, or whenever `symbol` is `None`.
fn symbol_matches(symbol: Option<&str>, block_name: &str) -> bool {
    symbol.is_none_or(|symbol| symbol == block_name || symbol.ends_with(&format!(".{block_name}")))
}
