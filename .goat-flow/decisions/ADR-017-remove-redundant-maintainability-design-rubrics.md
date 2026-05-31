# ADR-017: Remove Redundant Maintainability/Design Rubrics

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Claude, on user direction
**Ticket/Context:** 0.3.0 M00b; mission ADR-015; rubric audit 2026-05-30; follows ADR-016 (npath)

## Decision

Remove three rubrics that add findings without adding mission signal —
`metrics.halstead-volume`, `metrics.maintainability-pressure`, and
`design.god-function` — along with the shared `function_metrics` halstead/pressure
computation (`metric_tokens`, `round_one_decimal`, the `FunctionMetrics` struct,
`METRIC_TOKEN_REGEX`), the `analyse_design_block` god-function emission, config
pins, calibration cases, tests, and docs.

## Context

- **halstead-volume + maintainability-pressure are one signal counted twice.**
  maintainability-pressure is computed FROM halstead volume
  (`pressure = total_tokens*0.08 + cyclomatic*2 + halstead_volume/60`). On an
  external scan they co-fired 126/127 (99%); 78% of their hits also tripped a
  complexity or size rule; together they were 258 of 993 findings (26%). Halstead
  volume is an academic vocabulary metric a reviewer never acts on —
  verifiability is already carried by cyclomatic / cognitive / nesting /
  function-length.
- **god-function is pure redundancy.** It fired only when a function was both
  long and complex (`line_count > 45 && cyclomatic > 10`, hardcoded). 50/52
  external hits also tripped function-length AND cyclomatic; zero fired alone. As
  a warning it piled a third command on functions already flagged twice.

Removing all three loses zero unique verifiability signal (mission ADR-015: a
finding is a command; correctness over coverage).

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep all three | 26% of findings from redundant/academic metrics; a warning-severity duplicate on already-flagged functions | Rejected; noise without signal under the mission. |
| Collapse halstead + maintainability into one | Still an academic metric with no reviewer action | Rejected; the signal is already covered by complexity/size. |
| Remove all three | Loses the token-volume metrics and the long-and-complex composite | Accepted; cyclomatic / cognitive / nesting / function-length cover every genuinely hard-to-verify function. |

## Consequences

- Complexity 5→3 (after ADR-016 npath removal: 5→4→3), maintainability 12→11,
  design 4→3; catalogue 79→76.
- `rule_calibration_matrix_covers_every_rule` confirms 76/76 alignment.
- The `function_metrics` computation chain and `FunctionMetrics` struct are gone;
  no other consumer existed (verified: no HTML / scoring / schema use).
- A future maintainability signal, if wanted, must earn its place under the
  mission, not via token-volume proxies.

## Reversibility

Two-way door (no external users). The decision against academic token-volume
metrics and the redundant long-and-complex composite is durable; any replacement
must add signal that cyclomatic / cognitive / nesting / function-length do not
already provide.
