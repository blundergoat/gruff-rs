# ADR-019: Git-Executing Diff Modes Trust Boundary

**Status:** Accepted
**Date:** 2026-05-31
**Author(s):** Claude, on user direction (cross-port coordination sweep)
**Ticket/Context:** Resolves the trust-boundary decision deferred by ADR-009; narrows ADR-008's no-execute posture for two opt-in flags. 0.3.0 shipped the gated path; this ADR is the sanction ADR-009 required.

## Decision

`analyse` exposes two Git-executing changed-region modes — `--diff <mode>` and `--since <ref>` — that run `git` as a subprocess (`src/changed_region.rs`: `git -C <project_root> <args>` via `std::process::Command`, argv only, with a `--` path-operand separator). These modes are sanctioned only as a **bounded, opt-in exception** to the default no-execute posture of ADR-008, satisfying the trust-boundary decision ADR-009 explicitly deferred ("Implement Git-ref diff by shelling out immediately … Rejected until a trust-boundary ADR exists").

The exception is valid only while ALL of the following hold:

1. **Opt-in.** The modes require the `--diff-git-unsafe` flag (clap `requires = "diff_git_unsafe"`); invoking `--diff`/`--since` without it is a hard error (non-zero exit), not a silent fallback.
2. **Named for the risk and hidden.** The opt-in is literally `--diff-git-unsafe` and is hidden from `--help` (`hide = true`), so the Git-executing path is never the obvious default an agent reaches for.
3. **Git-free modes are the default-safe path.** `--diff-patch <file>` and `--changed-ranges <a-b,…>` parse caller-supplied input as data and never run Git; they need no opt-in and are the recommended path for a coding-agent hook.
4. **Read-only, no shell.** Git is invoked through argv (never `sh -c`), scoped with `-C <project_root>`, and path operands are passed after `--`.
5. **Default scans are unaffected.** Every invocation that does not pass `--diff-git-unsafe` keeps ADR-008's no-execute guarantee in full.

gruff never runs the target's code, build, or tests, and never executes Git unless this opt-in is present.

## Context

ADR-008 makes "the analyzer reads files; it does not run them" a public security guarantee (a one-way door). ADR-009 layered diff filtering and deliberately shipped patch-input diff first ("parse unified diff text without executing Git"), rejecting Git-ref diff "until a trust-boundary ADR exists." 0.3.0 then shipped the Git-backed modes behind `--diff-git-unsafe`, but the prerequisite ADR was never written — this ADR closes that gap and records why the exception is acceptable.

Why the exception is needed: `--since`/`--diff` let a hook scope findings to "what this change touched" using the repo's own history, which caller-supplied patch/range input cannot always reconstruct.

Why it is dangerous: running `git` inside an **untrusted worktree** is not equivalent to ADR-008's "never run the tree's code." Git honors repo-local, global, and system configuration and can hand control to attacker-influenced code through Git **hooks**, `GIT_EXTERNAL_DIFF`, attribute filters, `core.fsmonitor`, and pager configuration. The current implementation passes argv (no shell), scopes with `-C`, and separates paths with `--`, but does **not** scrub the environment or neutralize hostile Git config. So this path narrows the no-execute guarantee to: *gruff itself does not execute target code, but the Git it invokes may, per the target repo's configuration.* That residual risk is the reason the path is opt-in, risk-named, hidden, hard-errored without the flag, and not the default.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Run Git for diff with no opt-in (the ADR-009 rejected alternative) | Untrusted worktrees execute code via hooks / external-diff / config on an ordinary scan | Rejected; reinstates the ACE vector ADR-008/009 exist to prevent. |
| Remove `--diff`/`--since` entirely; patch/range input only | Loses repo-history-aware scoping a hook sometimes needs | Rejected; the Git-free modes cover the common case but not all. |
| Keep the path shipped but unsanctioned (no ADR) | A future agent "fixes" the surprising hidden/hard-error gating, or widens it, with no recorded rationale | Rejected; the gating is deliberate and must be documented. |
| Sanction as a bounded opt-in: risk-named, hidden, hard-errored, argv/`-C`/`--`, Git-free default | Residual ACE risk remains via hostile Git config until hardened | Accepted; the residual risk is documented and contained behind an explicit, non-default opt-in. |

## Consequences

- The hidden `--diff-git-unsafe` gate, the hard error without it, and the Git-free defaults are intentional and load-bearing; do not "simplify" them away.
- **Recommended hardening (follow-ups, not yet implemented).** Tighten the residual risk before relying on this path in hostile environments: neutralize Git config and hooks on the subprocess (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, `-c core.hooksPath=/dev/null`, unset `GIT_EXTERNAL_DIFF`, `GIT_ATTR_NOSYSTEM=1`, `--no-pager`), and emit a visible signal (stderr warning + run diagnostic) when the path runs.
- **Honesty correction.** `.goat-flow/architecture.md` claimed this path "emits a run diagnostic when used." It does not: `src/render/sarif.rs` has a severity branch that would map a `diff-git-unsafe` run diagnostic to SARIF `warning`, but no code path constructs that diagnostic. The architecture note is corrected to match reality in the same change as this ADR; wiring (or removing) the diagnostic is part of the recommended hardening above. Per the project mission, the doc/code mismatch is itself the signal that surfaced this gap.
- No schema, rule ID, fingerprint, or default-scan behavior changes.

## Reversibility

Two-way door on the mechanism (the opt-in spelling, the hardening, and whether the diagnostic is wired can all change while pre-public). One-way door on the principle: the Git-executing path must stay non-default and opt-in, and the no-execute guarantee must hold for every scan that does not pass `--diff-git-unsafe`. Revisit when the hardening lands (which moves this ADR from "documented residual risk" to "contained"), or if a cross-port decision changes the diff contract.
