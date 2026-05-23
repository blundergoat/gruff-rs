# ADR-009: Suppression Baseline And Diff Layering

**Status:** Accepted
**Date:** 2026-05-16

## Decision

Finding suppression mechanisms must stay layered and explicit. Future work
should use this order unless a later ADR changes it:

1. Discover input files according to ADR-004 and explicit user paths.
2. Analyze requested files and preserve diagnostics needed to explain incomplete
   analysis.
3. Apply source-local suppressions at emission time if a stable suppression
   syntax is accepted later.
4. Apply exact `gruff-baseline.json` suppression from ADR-002.
5. Apply optional count-baseline suppression from a separate schema, if that
   feature ships.
6. Apply report-level exclusions with reasons and suppression counts, if that
   feature ships.
7. Apply optional diff/new-code filtering last.

`paths.ignore` remains discovery-time "do not read" policy. Report-level
exclusions are not discovery ignores: they suppress findings after analysis and
should not hide files from sensitive-data or security scanning.

Patch-input diff mode should be the first diff implementation because it can
parse unified diff text without executing Git. Direct Git/ref-based diff or
baseline-by-ref modes require a separate trust-boundary decision before they
can execute external commands or inspect alternate trees.

## Context

The M24 matrix records convergent evidence from Clippy, rust-analyzer, Detekt,
RuboCop, SwiftLint, Semgrep, and golangci-lint:

- `.goat-flow/scratchpad/related-projects/rust-clippy/STUDY.md`
- `.goat-flow/scratchpad/related-projects/rust-analyzer/STUDY.md`
- `.goat-flow/scratchpad/related-projects/detekt/STUDY.md`
- `.goat-flow/scratchpad/related-projects/rubocop/STUDY.md`
- `.goat-flow/scratchpad/related-projects/swiftlint/STUDY.md`
- `.goat-flow/scratchpad/related-projects/semgrep/STUDY.md`
- `.goat-flow/scratchpad/related-projects/golangci-lint/STUDY.md`

M22 showed that count-like baselines can coexist with gruff's exact baseline
only as an optional second layer. M23 showed that line-level diff filtering is
report post-processing, while baseline-by-ref and direct Git execution cross
a trust boundary.

ADR-002 keeps exact baseline identity stable. ADR-004 keeps discovery policy
separate from analyzer config ignores.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Replace exact baselines with count baselines | Existing accepted findings lose deterministic identity | Rejected; exact baselines remain first. |
| Treat report exclusions as path ignores | Security and sensitive-data rules can lose visibility into committed files | Rejected; exclusions suppress findings, not scanning. |
| Apply diff filtering before baselines | Old accepted debt moved by unrelated edits can reappear as new-code noise | Rejected; baselines should suppress accepted debt first. |
| Implement Git-ref diff by shelling out immediately | Untrusted worktrees can affect analysis through Git hooks, external tools, or local state | Rejected until a trust-boundary ADR exists. |
| Layer exact baseline, optional count baseline, exclusions, then diff | More configuration surfaces need tests | Accepted; each layer has a distinct purpose and schema. |

## Reversibility

Layer ordering can be changed before the optional layers ship. Once count
baselines, report exclusions, or diff filters are public, changing order is a
compatibility decision because it changes which findings appear without
changing fingerprints.
