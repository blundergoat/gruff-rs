# ADR-016: Remove the complexity.npath Rubric

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Claude, on user direction
**Ticket/Context:** 1.0.0 M00; mission ADR-015; rubric audit 2026-05-30

## Decision

Remove `complexity.npath` from gruff-rs entirely — registry definition
(`src/rules/definitions_a.rs`), the threshold constant in `src/rules/mod.rs`, the
scanner `analyse_npath_complexity` and its call site in `analyse_block_complexity`
(`src/built_in_rules/blocks.rs`), the `approximate_npath` computation
(`src/built_in_rules/function_block_metrics.rs`), the `NPATH_*` regex statics
(`src/built_in_rules/mod.rs`), the `.gruff-rs.yaml` pin, the calibration case, the
tests, and the docs. Do NOT replace it with a higher threshold; do NOT retune it.

## Context

npath approximated an execution-path count as `2^(branch keywords) + boolean
count`, capped at `2^20`, against a default threshold of 100. The rubric audit
(2026-05-30) found three disqualifying problems:

1. **Redundant.** On an external real-world Rust scan, 44/54 npath findings also
   tripped `complexity.cyclomatic`; of the remaining 10, eight also tripped
   cognitive or nesting. The two it uniquely flagged (`validate_script_path`,
   `run_ai_installer`) were false positives.
2. **Anti-aligned with the mission (ADR-015).** npath's only *independent* signal
   is flat sequential branching — the easiest code for a reviewer to verify. As a
   coding-agent hook a finding is a command, so npath commanded the agent to make
   legible code less legible.
3. **Crude and saturating.** The `2^keywords` approximation cannot distinguish
   flat sequences (trivially testable) from deep interaction (combinatorially
   hard), saturates at `2^20`, and counted control-flow keywords inside comments
   (see `.goat-flow/footguns/analyzer.md`) — which, because npath exponentiates,
   made it false-fire where `complexity.cyclomatic` (additive) stayed silent.

A cross-port (TypeScript) review proposed keeping npath at a higher threshold
(512); rejected for gruff-rs because the redundancy and anti-alignment are
threshold-independent — raising the cutoff cuts volume but not the wrong-signal
problem.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep npath at default 100 | False commands on flat, verifiable code; comment-keyword inflation crosses the line | Rejected; anti-aligned with the mission. |
| Raise the threshold (200 / 512) | Cuts volume, but the unique signal (flat sequential) is still wrong at any threshold and it still saturates | Rejected; does not fix the metric. |
| Remove entirely | Loses the path-count metric | Accepted; cyclomatic + cognitive + nesting cover every genuinely hard-to-verify function with zero unique loss. |

## Consequences

- The complexity pillar drops from 5 rules to 4; catalogue 80 → 79 (reduced
  further by M00b).
- `rule_calibration_matrix_covers_every_rule` confirms 79/79 registry/calibration
  alignment after removal.
- A future path-explosion / testability signal, if wanted, is a NEW AST-based
  rule — not a revived `2^keywords` approximation.
- The comment-keyword inflation npath exposed still affects
  cyclomatic/cognitive/nesting; tracked separately (M00c and the analyzer
  footgun).

## Reversibility

Two-way door for the catalogue (gruff has no external users; re-adding is clean).
The decision against the crude approximation is durable: any replacement must be a
real path count over the AST with its own calibration, not this rule revived.
