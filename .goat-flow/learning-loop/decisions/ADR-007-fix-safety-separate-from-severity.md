# ADR-007: Fix Safety Separate From Severity

**Status:** Accepted
**Date:** 2026-05-16

## Decision

Automatic fixes remain out of scope for v0.1, but any future fix mode must model
fix safety separately from finding severity and confidence.

The minimum future metadata shape is:

- `none`: the rule has no automatic fix.
- `safe`: the edit is intended to preserve behavior and may be applied when the
  user explicitly asks for fixes.
- `unsafe`: the edit may change behavior or remove intent and requires an
  explicit unsafe-fixes flag before application.

Severity continues to answer how serious the finding is. Confidence continues
to answer how likely the finding is correct. Neither field may be used as a
proxy for whether an edit is safe.

Fix metadata can be stored in rule metadata before report-visible fix payloads
exist. Adding concrete edits, dry-run output, or SARIF fixes to
`gruff.analysis.v1` requires a separate schema compatibility decision.

## Context

The M24 matrix records convergent fix-safety evidence from Ruff, Biome, Clippy,
rust-analyzer, and RuboCop:

- `.goat-flow/scratchpad/related-projects/ruff/STUDY.md`
- `.goat-flow/scratchpad/related-projects/biome/STUDY.md`
- `.goat-flow/scratchpad/related-projects/rust-clippy/STUDY.md`
- `.goat-flow/scratchpad/related-projects/rust-analyzer/STUDY.md`
- `.goat-flow/scratchpad/related-projects/rubocop/STUDY.md`

Those analyzers separate diagnostic severity from edit applicability or
autocorrect safety. This matters for gruff because many high-severity findings,
such as likely secrets or process-command risks, are not safely auto-fixable,
while some low-severity style findings could be mechanically safe.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Infer fix safety from severity | Severe findings with no safe edit look auto-fixable | Rejected; severity and edit risk are different dimensions. |
| Infer fix safety from confidence | A true finding can still require a risky edit | Rejected; confidence is not edit semantics. |
| Add fixes without unsafe gating | Users can apply behavior-changing edits accidentally | Rejected; unsafe edits need explicit consent. |
| Add rule-level fix-safety metadata before edit payloads | No automatic fixes ship immediately | Accepted; it preserves future design without changing reports now. |

## Reversibility

The enum names can change before any fix mode or schema-visible metadata ships.
After fix metadata becomes public config or report data, changes require schema
tests and migration notes. Analysis-only fingerprints must remain independent
from whether a fix is available.
