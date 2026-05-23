# ADR-006: Report Renderers Preserve Analysis Schema

**Status:** Accepted
**Date:** 2026-05-16

## Decision

New report formats should be implemented as dedicated renderers over
`AnalysisReport` and `RuleRegistry`. They must not mutate
`gruff.analysis.v1`, finding fingerprints, rule ids, or baseline behavior.

SARIF is the first CI-oriented renderer to prioritize. Checkstyle XML, Code
Climate JSON, CSV, JUnit, TeamCity, and other formats can follow as separate
renderer milestones when a consumer need is clear. Each renderer owns its
format-specific schema mapping, severity mapping, path/URI normalization,
metadata projection, and deterministic ordering.

If a renderer exposes a named output contract beyond best-effort display, that
contract needs tests and documentation. Rich SARIF features such as fixes,
code flows, or multi-location traces remain deferred until gruff records the
underlying data.

## Context

The M24 matrix records convergent renderer evidence from Ruff, Biome, Detekt,
PMD, RuboCop, Semgrep, and golangci-lint:

- `.goat-flow/scratchpad/related-projects/ruff/STUDY.md`
- `.goat-flow/scratchpad/related-projects/biome/STUDY.md`
- `.goat-flow/scratchpad/related-projects/detekt/STUDY.md`
- `.goat-flow/scratchpad/related-projects/pmd/STUDY.md`
- `.goat-flow/scratchpad/related-projects/rubocop/STUDY.md`
- `.goat-flow/scratchpad/related-projects/semgrep/STUDY.md`
- `.goat-flow/scratchpad/related-projects/golangci-lint/STUDY.md`

The projects consistently model SARIF and CI formats as reporter/emitter
surfaces, not as the analyzer's native JSON output. M19 already sketched a SARIF
mapping from gruff findings plus registry metadata.

ADR-002 makes fingerprint identity stable, and ADR-003 keeps local gates tied
to deterministic scanner smokes. A renderer can add output reach without
changing the analysis contract.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Reuse `gruff.analysis.v1` JSON as "SARIF-like" output | CI consumers expecting SARIF fields cannot ingest it correctly | Rejected; SARIF needs a dedicated mapping. |
| Add SARIF-only fields to `gruff.analysis.v1` first | Native report consumers inherit format-specific churn | Rejected; renderers should adapt existing report data. |
| Build dedicated renderers from `AnalysisReport` and `RuleRegistry` | Some advanced SARIF features are unavailable initially | Accepted; it preserves the core schema and stays deterministic. |
| Implement every observed renderer at once | More output contracts than the project can test well | Rejected; prioritize SARIF, then add formats by consumer need. |

## Reversibility

Adding a renderer is reversible while it remains undocumented or experimental.
Once a renderer is advertised as stable, incompatible format changes require a
format-specific compatibility note and golden-output tests. Reversal must not
change `gruff.analysis.v1` or baseline identity.
