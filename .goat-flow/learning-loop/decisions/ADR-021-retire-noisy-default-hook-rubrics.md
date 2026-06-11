# ADR-021: Retire noisy default hook rubrics

**Status:** Accepted
**Date:** 2026-06-12
**Author(s):** Codex, with owner approval
**Ticket/Context:** 0.4.0 M09 external-scan rubric follow-up

## Context

Gruff runs as a coding-agent hook, so a false positive is not just advisory report noise: it can
cause an agent to change code that was already correct. The 2026-06-12 external scan of
`.goat-flow/scratchpad/scan-test-repos/{Handy,RuView,bun,goose,pnpm}` showed two default-on rule
families whose remaining findings require design intent the analyzer cannot see reliably.

`modernisation.public-field` remained high-volume on DTOs, schema mirrors, transport structs, and
CLI argument structs. These public fields are often the framework or wire contract, not an
accidental representation leak.

`test-quality.no-assertions` remained noisy on success-path tests that assert through `?`
propagation, compile-check helpers, expected-panic attributes, macro harnesses, snapshot/golden
helpers, and known-failure harnesses. Keeping the rule would reward visible but fake assertions.

The same scan also reviewed `security.path-traversal-candidate`. Some findings are conservative
candidate signals, but the reviewed evidence did not justify weakening a security rule.

## Decision

Remove `modernisation.public-field` and `test-quality.no-assertions` from the built-in rule
registry, dispatch paths, documentation, and active test expectations. Retired rule IDs must not
remain as silent placeholders and must not appear in `list-rules` or normal analysis output.

Keep `security.path-traversal-candidate` default-on. Future work may clarify its message or
metadata, but M09 must not weaken its matching behavior.

This supersedes ADR-014's example use of `modernisation.public-field` as a visibility-only scoring
candidate. A rule with this false-positive profile should be retired rather than kept as a
default-on, score-excluded finding stream.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep both rules and add more carve-outs | The analyzer still cannot distinguish invariant-bearing public fields from contract structs, or setup-only tests from harness assertions, without framework/type knowledge. | Rejected - broad defaults would keep producing hook-facing noise. |
| Keep both rules but mark them visibility-only | Findings would still reach agents and reviewers even though the rule does not know enough to be actionable. | Rejected - scoring exclusion does not solve hook false positives. |
| Make replacement rules immediately | A precise replacement needs new evidence and likely semantic/framework knowledge. | Deferred - no replacement ships without its own fixtures and scan evidence. |
| Retire the two noisy rubrics and keep path traversal active | Removes known noisy defaults while preserving conservative security coverage. | Accepted - matches the external-scan evidence and owner decision. |

## Consequences

- `modernisation.public-field` and `test-quality.no-assertions` disappear from default rule
  listings and reports.
- Tests that previously tuned their false-positive carve-outs are removed or rewritten around
  remaining adjacent rules.
- Documentation must describe only active rules; historical rationale lives in M09 and this ADR.
- Any future public-field or no-assertion replacement requires a new opt-in/default decision with
  external scan evidence before becoming a hook-facing default rule.

## Reversibility

Two-way door at the code level: the rule IDs can be reintroduced in a later release. Reintroduction
requires a new ADR or amendment explaining the narrower contract, fixtures for true/false-positive
shapes, and an external scan showing the default rule will not recreate the same hook-facing noise.
