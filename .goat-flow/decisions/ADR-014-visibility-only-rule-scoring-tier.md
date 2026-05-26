# ADR-014: Visibility-only rule scoring tier and per-rule deltas

**Status:** Accepted
**Date:** 2026-05-26
**Author(s):** Matthew Hansen (with Claude Code)
**Ticket/Context:** 0.1.2 M04, ported from gruff-php's 0.1.4 M06 visibility-tier work.

## Context

Before this ADR, gruff-rs's only escape valve for a rule that produces "true by the letter, irrelevant by the spirit" findings was `rules.<id>.enabled: false`. That option drops the rule entirely - the findings stop appearing in JSON, text, SARIF, markdown, and dashboard output. Teams therefore had to choose between two unsatisfying outcomes: keep the rule on and let its findings drag down the composite score, or disable it and lose visibility on a real (if low-priority) class of issue.

The cross-port pattern observed in gruff-php's 0.1.4 plan introduces a third axis: a rule can stay enabled (findings appear) while opting out of the composite-score weighting. The rule's findings are still surfaced; they just do not penalise the score. The team keeps the signal without paying the score cost.

Separately, when a baseline or diff-vs comparison is active, the per-finding noise is high but the per-rule delta signal is what humans actually want to read first ("of the rules I care about, which ones got better or worse since the baseline"). Today's reporters surface only the composite-score line; you have to scroll through individual findings to derive per-rule trends.

Both halves touch the scoring/reporting boundary; bundling them into one ADR (and milestone) keeps the surfacing decisions consistent.

## Decision

Introduce one new per-rule config field:

```yaml
rules:
  modernisation.public-field:
    excludeFromScore: true
```

`excludeFromScore` is a `bool` with default `false`. When `true`, the rule continues to run; its findings appear in every reporter; its findings count appears in pillar/file digests. Only the **composite penalty buckets** in `src/scoring.rs` skip it.

The field is on the existing per-rule `RuleSetting` shape (`src/config.rs:82`), alongside `enabled`, `threshold`, and `severity`. Reusing severity for this purpose was rejected (see Failure Mode table); the new field is an independent axis.

Surface the exclusion state to humans via at most one channel to avoid noise. The text reporter's per-pillar breakdown includes a one-line "rules excluded from score: …" footnote when any pillar contains excluded rules; JSON consumers read the resolved state from the rule config.

Add an additive `per_rule_deltas: Option<Vec<RuleDelta>>` field to `AnalysisReport` (or a sibling computed type). Each entry is `{rule_id, introduced, removed, net}`. Populated when a baseline or diff context is in scope; left `None` on full-tree runs. The text and markdown reporters render two ranked blocks BEFORE the composite-score line when the field is present:

```
Top 5 improved: -12 docs.missing-public-doc, -7 size.method-length, …
Top 5 regressed: +4 modernisation.semver-pin, +2 naming.identifier-quality, …
```

Each block caps at five entries, omits zero-net rules, and orders by absolute delta then by `rule_id` for stability.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Overload severity (`severity: disabled`) | Severity describes a single finding's strength; reusing it to mean "rule does not count toward score" conflates a per-finding property with a per-rule policy. Future severity additions become harder. | Rejected - axis muddying. |
| Per-finding `do-not-penalise` toggle | Granularity belongs at the rule level; per-finding suppression is what baselines and `exclude:` blocks are for. | Rejected - duplicates baselines. |
| Drop the rule entirely (`enabled: false`) | Loses visibility on the underlying hazard. New occurrences of the same false-positive shape will not be caught the next time the rule pattern catches a real instance. | Rejected - the visibility-first half of this decision is the whole point. |
| Differentiated penalty weights (`weight: 0.25`) | Larger design space; binary include/exclude covers the requested workflow. Differentiated weights need a separate ADR with concrete weighting evidence. | Deferred - see Deferred. |
| Silent exclusion on Security/SensitiveData pillars | A team excluding a security rule from score without any signal is exactly the failure mode `excludeFromScore` is meant to PREVENT in the limit case. The exclusion stays user-visible. | Rejected - silently swallowing security signals is the worst case. |
| Warning diagnostic when Security/SensitiveData rules are excluded | Surfaces the choice without blocking it. Strict-mode escalation to error is a follow-up when a `--strict` flag exists; today gruff-rs has none. | **Accepted** - a `RunDiagnostic` at config-load time names the rule + pillar. |
| Per-rule deltas as a separate `gruff.deltas.v1` schema | Adds a separate consumer contract for what is fundamentally a derived view of two existing reports. | Rejected - the deltas live on `AnalysisReport` as an additive optional field per ADR-006. |
| Per-rule deltas always rendered, even on full-tree runs | The "top improved / regressed" block on a fresh scan has no second snapshot to diff against; rendering it empty or with current-only counts is misleading. | Rejected - block renders only when a baseline or diff context exists. |
| **Per-rule deltas as `Option<Vec<RuleDelta>>` on AnalysisReport, rendered before composite-score line** | Single source of truth for both text/markdown rendering and JSON consumption. Suppresses cleanly on full-tree runs. | **Accepted** - same field, same population logic, multiple reporters consume it. |

## Consequences

- `RuleSetting` (`src/config.rs:82`) gains an optional `exclude_from_score: Option<bool>` field. Missing key defaults to `false`. Non-boolean values produce a config-load error naming the rule id.
- `Config` (`src/config.rs:234`) gains an `is_rule_excluded_from_score(rule_id) -> bool` accessor next to `is_rule_enabled`.
- `src/scoring.rs` checks the accessor when accumulating per-pillar penalty; excluded rules' findings skip the penalty contribution. Per-rule finding counts in digests (`PillarDigest.findings`, `FileScore.findings`) are unchanged.
- Config-load emits a `RunDiagnostic` of type `excluded-security-rule-from-score` (warning level) when an `excludeFromScore: true` rule belongs to the Security or SensitiveData pillar. The diagnostic names the rule id and pillar. Strict-mode escalation to error is deferred (no `--strict` flag exists today).
- `AnalysisReport` gains an additive optional `per_rule_deltas: Option<Vec<RuleDelta>>` field. JSON consumers see the new key only when populated; full-tree runs continue to emit byte-identical JSON.
- Text and markdown reporters render the per-rule delta block BEFORE the composite-score line when `per_rule_deltas` is `Some`. Both blocks cap at five entries each; ties break by rule id ASC.
- `summary` command surfaces the same per-rule delta data in the compact view.
- The dashboard scan and `list-rules` do not gate exit code (per ADR-013) and stay outside the per-rule-delta surface; the field is reporter-level, not command-level.

## Reversibility

Two-way door. Removing `excludeFromScore` from a config restores full scoring for that rule. Removing the `per_rule_deltas` field would require a schema-decline note in CHANGELOG and any consumer that started reading the field would see it disappear; the field is additive, so the cost is symmetric and small.

Revisit triggers:
- A real workflow surfaces where differentiated weights ("count this rule at 25% of its normal weight") deliver value the binary include/exclude does not. That ADR re-opens this decision space.
- A `--strict` flag lands; at that point the Security/SensitiveData warning diagnostic escalates to error under strict mode and this ADR's "deferred to follow-up" caveat closes.
- A per-pillar `excludeFromScore: true` aggregate becomes desirable (excluding an entire pillar from score). Today the option lives on `RuleSetting`; lifting to pillar level needs an additional config key and is a separate ADR.

## References

- ADR-009 (suppression / baseline / diff layering): the new state is layer-6.5 - post-suppression, affects scoring not visibility.
- ADR-006 (renderers preserve analysis schema): additive `per_rule_deltas` does not bump the analysis schema version.
- M04 task file: `.goat-flow/tasks/0.1.2/M04-visibility-tier-and-per-rule-deltas.md`.
- gruff-php's 0.1.4 M06 plan - sibling-port reference design.
- Auto-memory entries: `feedback-no-bc-ceremony`.

## Deferred (out of scope for this milestone)

- Per-finding scoring exclusion. Baselines and `exclude:` blocks cover the granular case; revisit only if a real workflow surfaces.
- A CLI override (`--exclude-score-rule=...`) for ephemeral exclusion. Per-rule config is enough.
- Differentiated penalty weights ("25% of normal"). Binary covers the requested workflow.
- Class-level or symbol-level inline suppression annotations (`#[gruff::allow(rule.id, reason = "...")]`). Distinct from `excludeFromScore`; user wants the warning visible AND acknowledged on a specific symbol. Separate ADR.
- Auto-surfacing all `excludeFromScore: true` rules in a dedicated "informational" section of every report. One reporter channel is enough for v0.1.2.
- Strict-mode escalation of the Security/SensitiveData warning to error. Tied to a `--strict` flag that does not exist; revisit when it does.
