# ADR-005: Rule Selection Profiles And Selector Precedence

**Status:** Accepted
**Date:** 2026-05-16

## Decision

Future rule-selection work must be additive over existing gruff rule ids.
Built-in `rule_id` values remain the canonical output identity used by reports,
config rule blocks, fingerprints, and baselines.

Selectors may target exact rule ids, documented dotted prefixes, public pillars,
and future profile or lifecycle tiers. The first implementation should collect
positive selectors, then subtract negative selectors such as `ignore` or `skip`.
Negative selectors win for matching rules. A later design may add layered
`extend-select` or exact re-enable semantics, but that requires its own
compatibility review before users depend on it.

Rule-specific options and threshold settings remain keyed by exact rule id.
Strict config validation from ADR-003 continues to reject unknown selectors,
unknown rule ids, unsupported threshold shapes, and unsupported value shapes.
ADR-011 requires thresholded rubrics to use one `threshold` plus one `severity`
instead of named threshold bands.

## Context

The M24 matrix records convergent rule-selection evidence from Ruff, Biome,
Clippy, RuboCop, and SwiftLint:

- `.goat-flow/scratchpad/related-projects/ruff/STUDY.md`
- `.goat-flow/scratchpad/related-projects/biome/STUDY.md`
- `.goat-flow/scratchpad/related-projects/rust-clippy/STUDY.md`
- `.goat-flow/scratchpad/related-projects/rubocop/STUDY.md`
- `.goat-flow/scratchpad/related-projects/swiftlint/STUDY.md`

Ruff provides the strongest precedent for selector specificity. Biome and
SwiftLint provide the clearest one-shot `only`/`skip` and tier behavior.
Clippy and RuboCop show that user-facing categories and lifecycle states are
not always the same thing as quality pillars.

Gruff already has stable dotted rule ids and public pillars. Renaming rule ids
to match another analyzer would break ADR-002 baseline identity and downstream
report consumers.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Rename built-in rules to match new selector groups | Existing baselines, config, and reports lose stable identity | Rejected; selectors are aliases, not new canonical ids. |
| Filter findings after analysis only | Disabled rules can still pay analysis cost and may affect rule-local side effects later | Rejected for real selection; view-only filters can be separate UI behavior. |
| Let config string order decide conflicts | Broad and exact selectors become hard to reason about | Rejected; conflict behavior must be deterministic and documented. |
| Positive selectors, then negative selectors win | Some exact re-enable use cases need a later extension | Accepted as the simplest deterministic first contract. |

## Reversibility

This decision is reversible before selector config ships. After selectors are
released, changing conflict semantics becomes a config compatibility change and
must include migration notes plus fixture tests for broad, prefix, pillar, and
exact selector interactions.
