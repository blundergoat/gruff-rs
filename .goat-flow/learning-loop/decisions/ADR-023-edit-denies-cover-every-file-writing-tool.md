# ADR-023: Edit Denies Cover Every File-Writing Tool, So `Write(...)` Rules Are Never Added

**Status:** Implemented
**Date:** 2026-08-12

## Decision

`.claude/settings.json` protects a secret path with exactly two deny entries: `Read(<glob>)` and
`Edit(<glob>)`. It never carries `Write(...)`, `MultiEdit(...)`, `NotebookEdit(...)`, or
`Glob(...)` path rules.

The invariant a reviewer should check is **pairing**: every path denied for `Read` is also denied
for `Edit`, and the reverse. It is not "one entry per tool name". `scripts/preflight-checks.sh`
(search: `permission rule hygiene`) enforces both halves — pairing, and the absence of inert forms.

An `Edit(<glob>)` deny already refuses the `Write` tool. Adding a matching `Write(<glob>)` entry
buys no protection, warns at agent launch, and is rewritten away by the next `goat-flow install`.

## Context

`main` (`2f6a25b`) carried 13 `Write(` entries. Commit `0f16748` removed them, and the
`dev` branch has carried zero since. Read as a diff, that looks like a dropped security control, and
in August 2026 a release-readiness plan was written on exactly that reading — proposing to restore
26 `Write(...)` denies as its highest-priority security fix. The premise was wrong in the opposite
direction: the entries that existed had never enforced anything.

Two independent lines of evidence settle it.

**Upstream documentation.** goat-flow's `docs/harness-audit.md` (search: `settings-rules-matched`):

> `MultiEdit(...)` rules (removed tool) and `Write`/`NotebookEdit`/`Glob` path rules (never matched -
> `Edit`/`Read` cover file access) warn at launch and enforce nothing, so they read as protection
> that does not exist. Re-running goat-flow setup/install for the agent repairs them: removed-tool
> rules are dropped and unmatched forms are rewritten to their matched `Edit`/`Read` equivalents.

The shipped `claude.json` template agrees structurally: 6 `Bash`, 22 `Read`, 22 `Edit`, 0 `Write`.

**Live measurement, 2026-08-12, against this repository's settings.** With `Edit(**/*.pem)` present
and no `Write(` rule anywhere in the file:

| Probe | Result |
| --- | --- |
| `Write` to `probe-delete-me.pem` in the project | refused — "File is in a directory that is denied by your permission settings" |
| `Write` to `probe-control-delete-me.txt` in the project | succeeded |

The refusal is pattern-scoped, not a blanket project deny, and it was produced by an `Edit` rule
acting on the `Write` tool. Both probe files were removed.

A third, weaker signal points the same way: the repository's own `.claude/settings.json` hooks block
registers `PostToolUse` matchers for `Edit`, `Write`, and `Bash`. `Write` is a real tool that fires
hooks — it is only the *permission-rule* namespace where `Edit` subsumes it. Conflating the two
subsystems is the mistake that makes the missing entries look alarming.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Pair `Read` + `Edit` only, enforce pairing in preflight | A reviewer diffing against `main` sees 13 fewer entries and suspects a regression | **Accepted.** This ADR plus the named preflight check answer that question once, with evidence. |
| Add matching `Write(...)` entries "for defence in depth" | Rules enforce nothing, warn at every agent launch, get silently rewritten by the next install, and teach readers that the file means more than it does | Rejected. Manufactures the appearance of protection — the precise failure this repository's contract-honesty work exists to remove. |
| Collapse the 26 enumerated paths into `**/.env*` style globs | Diverges from the upstream template, so every install produces churn | Rejected. The enumeration is deliberate upstream conformance; the four local extensions are additive. |
| Rely on the Bash deny hook alone | The hook sees shell commands, never direct `Read`/`Edit`/`Write` tool calls | Rejected. The two layers cover different call paths and both are required. |

## Reversibility

Two-way door, but do not walk back through it casually.

Revisit only if Claude Code's permission matcher changes so that `Write(...)` path rules are
matched. The trigger to watch is goat-flow's `settings-rules-matched` audit check: if a future
release stops classifying `Write` as an unmatched form, re-run the live probe above before changing
anything. If the probe then shows a `Write` succeeding where `Edit` denies, this ADR is superseded
and the entries must be added.

Rollback is a text edit to `.claude/settings.json` plus removing the preflight check. Nothing else
depends on the absence of these rules.

## Related

- `.claude/settings.json` (search: `"deny"`) — the enforced list.
- `scripts/preflight-checks.sh` (search: `permission rule hygiene`) — the check that keeps it honest.
- `CHANGELOG.md` (search: `Claude permission wording matches current tool semantics`) — the shipped
  user-facing statement this ADR backs with evidence.
