---
category: research-extractions
last_reviewed: 2026-05-16
---

## Pattern: Convergent Finding Matrix

**Context:** Use this when several peer studies need to become durable project direction rather than loose scratchpad notes.
**Approach:** List every study finding exactly once, then group them into convergent themes with source projects, strength, compatibility flags, and route. `.goat-flow/scratchpad/related-projects/SYNTHESIS-MATRIX.md` is the M24 example.

## Pattern: Compatibility-First Adoption Routing

**Context:** Use this when a peer idea touches rule ids, fingerprints, report schemas, config schemas, baselines, or trust boundaries.
**Approach:** Decide the compatibility route before implementation. ADR-005 through ADR-010 show the pattern: selectors preserve built-in rule ids, renderers preserve `gruff.analysis.v1`, fix safety stays separate from severity, semantic analysis stays no-execute by default, suppression layers preserve exact baselines first, and custom rules reserve `custom.*`.

## Pattern: Single-Project Ideas Become Parked Backlog

**Context:** Use this when one analyzer has a compelling idea but the matrix does not show multi-project convergence.
**Approach:** Keep the idea with a source citation in `backlog.md` or this pattern file instead of writing a binding ADR. M24 parked Detekt's aggregate `ComplexityReport`, Biome's rule-source provenance, Ruff's force-exclude path knob, PMD's XPath-style AST rules, SwiftLint's parent/child config merge, and RuboCop's TODO-config workflow.

## Pattern: Renderer Features Adapt Reports Rather Than Redefining Analysis

**Context:** Use this when adding SARIF, Checkstyle, Code Climate, CSV, or another external output format.
**Approach:** Treat the format as a renderer over `AnalysisReport` and `RuleRegistry`. Keep native schema, fingerprints, rule ids, and baseline behavior stable unless a separate schema ADR accepts a new analysis contract.
