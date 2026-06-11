# ADR-020: Partial-Context Dead-Code Suppression

**Status:** Accepted
**Date:** 2026-06-11
**Author(s):** Codex, on user-delegated implementation
**Ticket/Context:** `.goat-flow/plans/0.4.0/M01-scope-dependent-dead-code-fp.md`; audit evidence in `.goat-flow/scratchpad/sibling-audit-2026-06-10.json`.

## Decision

`dead-code.unused-private-item-candidate` is authoritative only when the run analyses every discoverable Rust source under the selected project root. When discovery coverage is partial, the rule emits no findings and records one non-fatal `RunDiagnostic` with `diagnostic_type: partial-context-rule-suppressed`, naming the rule and pointing the operator to `gruff-rs analyse .` from the selected project root for authoritative dead-code signal.

The coverage fact is internal only. It compares the discoverable Rust file universe under the selected project root with the Rust files actually analysed after path and diff selection, and treats file-based diff narrowing as partial. It does not change `gruff.analysis.v2`, `gruff.hook.v1`, rule IDs, or finding fingerprints.

## Context

The audit reproduced a false positive in a two-file crate: `src/lib.rs` declared a private helper and `src/child.rs` called it. `analyse .` stayed clean, but `analyse src/lib.rs` flagged the helper because the cross-file reference index was built from only the discovered file. The same shape reaches agent hooks because the finding has a symbol and is therefore not removed by the hook's file/project-scope filter.

M01 measurements used a synthetic crate with 1200 generated modules, `src/lib.rs`, and `src/tiny.rs`, with config selecting only `dead-code.unused-private-item-candidate`. The candidate "discover full Rust universe but do not parse it" path stayed at about 0.02s wall time and about 16.6 MB RSS for `analyse src/tiny.rs`; a full rule-only `analyse .` scan took about 0.19s wall time and about 74.3 MB RSS. The suppression detector therefore preserves hook latency while avoiding a false deletion instruction.

ADR-015 makes false positives especially costly for hook-facing rules: a finding is not just a report entry, it can become an instruction for an agent to change code. For this rule, losing unauthoritative narrow-run signal is safer than telling an agent to remove code that a sibling file uses.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Widen discovery to the full project for this rule by default | Single-file hook runs pay full-project parse/read cost, and the default path becomes slower for the highest-volume caller | Rejected for default behavior. The measurement showed materially higher RSS and wall time on the synthetic crate. |
| Emit the finding with lower confidence and partial-context wording | The hook still receives an actionable dead-code finding for a claim the analyzer cannot prove | Rejected. Lower confidence does not remove the deletion pressure in agent workflows. |
| Suppress the rule and emit a diagnostic on partial coverage | Narrow runs lose unauthoritative dead-code candidate signal | Accepted. It matches the mission's correctness-over-coverage priority and keeps full-project scans authoritative. |
| Retire the rule entirely | Full-project true positives disappear too | Rejected. Whole-project fixtures still provide useful candidate signal for unused private items. |

## Consequences

- Full-project scans keep the existing project-level dead-code signal.
- Single-file crates named directly still run the rule because coverage is complete.
- Config-ignored Rust files are outside the discoverable universe; ignoring generated or vendored code intentionally narrows gruff's authority.
- `analyse` renderers can show the diagnostic through the existing diagnostics field. `gruff.hook.v1` does not serialize report diagnostics today, so hook users see the false positive disappear but do not see the caveat unless a future hook-contract ADR adds diagnostics.

## Reversibility

Two-way door. If future measurements show full-project widening is cheap enough for real hook workloads, a config-gated opt-in can widen discovery for this rule without changing the public report schema. Any reversal must preserve the invariant that partial-context runs do not emit medium-confidence unused-candidate findings as if the full crate had been analysed.
