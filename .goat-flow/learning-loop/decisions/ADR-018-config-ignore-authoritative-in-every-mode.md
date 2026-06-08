# ADR-018: Config paths.ignore Is Authoritative In Every Invocation Mode

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Claude, on user direction
**Ticket/Context:** 0.3.0 M13; coding-agent-hook correctness; follows ADR-004 (discovery) and ADR-009 (suppression/diff layering)

## Decision

Project `paths.ignore` (from `.gruff-rs.yaml`) is authoritative in **every**
invocation shape — directory traversal, explicit file arguments, and all
diff/changed-region modes (`--diff`, `--diff-patch`). A path matching
`paths.ignore` is excluded from analysis and produces **no findings**, however it
was supplied, and it is reported in the analysis JSON under
`paths.ignoredPathDetails` with its `source` and the `pattern` that matched.

`--include-ignored` opts into git-ignored and built-in default-directory paths
**only**; it never reveals a config-ignored path. VCS internals
(`.git`/`.hg`/`.svn`) remain blocked in all modes.

A new read-only `check-ignore` command answers, per path, whether gruff would
ignore it and why (`source` + `pattern`), using the **same** config loader and
ignore engine as `analyse` (`classify_ignored_path` / `config_ignore_match`); it
performs no analysis and mirrors `git check-ignore` exit codes (0 = at least one
ignored, 1 = none, 2 = error).

The reporting schema stays additive: `paths.ignoredPaths` (array of strings) is
retained for existing consumers; `paths.ignoredPathDetails`
(`[{path, source, pattern}]`) is the new parallel field. `gruff.analysis.v2` is
not bumped.

## Context

gruff's 0.3.0 mission is to run as a coding-agent hook (ADR-015). A hook passes
the agent's just-changed files to gruff as **explicit paths** (or as a diff).
Before this decision, `paths.ignore` was applied only during the discovery walk
(ADR-004); explicit file arguments and the patch-input diff path short-circuited
the walk, so an ignored file passed by the hook was analysed and flagged. The
agent then wasted effort "fixing" out-of-scope code. Two separate bugs existed,
both confirmed by repro on 2026-05-30:

1. `analyse <config-ignored-file>` (explicit arg) produced findings for the file
   and did not list it as ignored — `collect_input_path_sources` pushed file
   inputs straight to analysis without consulting `paths.ignore`.
2. `analyse . --include-ignored` revealed config-ignored files — the walk gated
   the `paths.ignore` check behind `!include_ignored`, so the git/default
   opt-in flag also overrode the analyzer's own project policy.

Two consumers need the ignore decision: the analyzer (must emit no findings for
ignored files) and the hook/agent (must be told which files were ignored and
why, to scope its own work). ADR-004 already separates git/default discovery
ignores (workspace-local, opt-out-able) from `paths.ignore` (the analyzer's
project policy); this decision makes that separation precise: `paths.ignore`
is policy and is never overridable, while git/default ignores stay opt-out.

The single-engine constraint matters: a second glob/ignore implementation would
drift from the first. `config_ignore_match` (over the existing `PathMatcher`
set) is the one config-ignore matcher, shared by the walk, explicit-file inputs,
and `check-ignore`. gitignore matching for `check-ignore` reuses the same
`ignore` crate the discovery walk uses, queried per path.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep `paths.ignore` discovery-only | Hook passes explicit/changed paths; ignored files get analysed and flagged; agent fixes out-of-scope code | Rejected; defeats the coding-agent-hook mission. |
| Let `--include-ignored` override `paths.ignore` | The git/default opt-out flag silently disables the analyzer's project policy; no way to inspect git-ignored files without also un-ignoring config-excluded ones | Rejected; conflates two independent ignore layers (ADR-004). |
| Make `paths.ignore` authoritative everywhere; `--include-ignored` for git/default only; add `check-ignore` sharing the engine | More surfaces (explicit-file path, diff path, new command) need the ignore check and tests | Accepted; each consumer routes through one engine, and the agent gets a queryable reason. |
| Add a second gitignore/glob matcher for `check-ignore` | Divergence from the discovery walk's ignore behaviour | Rejected for config (one `PathMatcher` engine); gitignore reuses the same `ignore` crate. |
| Replace `ignoredPaths: [string]` with objects | Breaks existing JSON/SARIF consumers | Rejected; `ignoredPathDetails` is added additively alongside the string list. |

## Consequences

- Behaviour change: a config-ignored path now yields zero findings when passed
  explicitly or under `--include-ignored`. gruff has no external users, so no
  migration shim is needed; the `--include-ignored` help text is corrected to say
  it does not override `paths.ignore`.
- New `source` vocabulary on ignored entries: `config` (authoritative, carries the
  exact glob), `default`/`generated` (built-in dirs; `--include-ignored` opts in),
  `gitignore` (reported by `check-ignore` via the `ignore` crate). VCS internals
  report as `default` and are always blocked.
- `check-ignore` is O(1) per path (no analysis) and is the agent-facing contract:
  JSON `[{path, ignored, source, pattern}]`, text emits ignored paths, `-v`
  appends `<path>\t<source>:<pattern>`.
- The ignore-policy types (`IgnoreSource`, `IgnoredPath`) live in their own module
  so the per-module item budget (`architecture.large-module`) is respected.

## Reversibility

Two-way door for the surfaces: `check-ignore`, `ignoredPathDetails`, and the
flag-help wording can change before they have external dependants. The core
precedence — config `paths.ignore` is never overridable — is a durable policy
decision; reversing it would re-open the coding-agent-hook scoping bug. Revisit
trigger: a real need to inspect a config-ignored file in place, which should add
an explicit, separately-named override rather than widening `--include-ignored`.
