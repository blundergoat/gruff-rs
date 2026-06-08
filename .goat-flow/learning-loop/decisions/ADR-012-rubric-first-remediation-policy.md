# ADR-012: Rubric-first remediation policy for noisy rules

**Status:** Accepted
**Date:** 2026-05-24
**Author(s):** Matthew Hansen (with Claude Code)
**Ticket/Context:** Session that cleaned up 58 dogfood findings on 2026-05-24; replaced a ~50-line `exclude:` block in `.gruff-rs.yaml` with rubric and code fixes.

## Context

By mid-May the project's `.gruff-rs.yaml` had accumulated ~15 `exclude:` entries to silence findings that were "true by the rule's letter but not its intent" - sensitive-data errors on calibration fixtures, dead-code advisories on test helpers re-exported to sibling modules, long-test advisories on integration tests that bundle assertions with shared setup, etc. Each exclude lived in `.gruff-rs.yaml` (search: `paths.ignore`) with a documented `reason:` field, and each became a per-project maintenance item: when fixture paths moved or rule IDs changed, the excludes had to follow.

The dogfood scan running through `scripts/preflight-checks.sh` (search: `dogfood_source_scan`) gates the local release pipeline. Maintaining the exclusion list scaled badly: the cost of each new noisy finding was an exclusion-add + doc-rationale, not a fix that improved the rule for every other consumer of gruff-rs.

## Decision

When a rule fires on legitimate code, prefer the following remedies, in order:

1. **Fix the rubric.** Add path-aware skip logic, idiom-detection helpers, or context-aware exemptions to the scanner itself (`src/built_in_rules/*.rs`). Document the carve-out in code, not in `.gruff-rs.yaml`. Examples shipped 2026-05-24: `path_is_calibration_fixture` and `path_is_test_infrastructure` helpers in `src/built_in_rules/helpers.rs`; `is_parent_module_file` skip in `src/built_in_rules/dead_code.rs`; `is_binary_crate_root` skip in `src/analyse_project/architecture.rs`.
2. **Fix the code.** Refactor the offending source until the rule no longer fires. Used for `render_default_config` exceeding the Halstead-volume threshold - split into `append_paths_section` / `append_allowlists_section` helpers in `src/init.rs` (search: `fn append_paths_section`).
3. **Delete the rubric.** If the rule produces low-yield findings (cannot statically distinguish good from bad), remove it entirely from the registry, scanner, calibration matrix, default config, and any tests that asserted on it. Examples shipped 2026-05-24: `test-quality.loop-in-test` and `config.security-blind-ignore`.

`exclude:` entries in `.gruff-rs.yaml` are reserved for cases that fit none of (1)/(2)/(3) - genuinely user-project-specific suppressions that should never become a default. The `.gruff-rs.yaml` shipping with this repo no longer has any `exclude:` entries; future ones require ADR-level justification of why the rubric and code paths cannot be used.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Accumulate `exclude:` entries | Each consumer of gruff-rs re-discovers the same false positives and writes the same suppressions; rule logic stays naive forever. | Rejected for v0.1 - exclusion debt grows with users, never decreases. |
| Disable rules (`enabled: false`) | Silences the rule everywhere, including the production-relevant case. New occurrences of the same hazard go undetected. | Rejected - false negatives are worse than false positives when the rule is sound on production code. |
| Fix the rubric | Carve-out logic lives in scanner source, documented in code, exercised by the calibration matrix. Every gruff-rs user benefits without writing any config. | **Accepted** - first remedy. Cost is once-per-rule; benefit accrues to every consumer. |
| Fix the code | Source becomes cleaner or the threshold becomes legitimately satisfiable. Sometimes the rule is right and the code is wrong. | **Accepted** - second remedy. Always preferable when the finding indicates a real issue. |
| Delete the rubric | Removes a rule that cannot earn its keep. Calibration matrix test (search: `rule_calibration_matrix_covers_every_rule`) enforces that registry, scanner, and calibration cases stay in sync. | **Accepted** - third remedy. Better than carrying a rule that produces only noise. |

## Consequences

- New rules added to the registry must include a calibration positive/negative case that is robust against the rule's own carve-outs (e.g. a sensitive-data positive case must NOT live under `**/tests/calibration/**`, or it will be skipped by `path_is_calibration_fixture`).
- The `.gruff-rs.yaml` ships as a faithful registry snapshot - `gruff-rs init` regenerates it with the same defaults. Any per-project exclusion is a deliberate choice the project owner is accepting.
- The footgun at `.goat-flow/footguns/calibration.md` (search: `Footgun: Threshold tuning ripples`) documents the ripple effects of threshold and rule changes that this policy makes more common.

## Reversibility

Two-way door. Reverting to "accumulate exclusions" is always possible by adding entries back to `.gruff-rs.yaml`. The harder direction - removing accumulated exclusions and replacing them with rubric fixes - is what this ADR makes the default; reversing means accepting that maintenance debt grows with each new false positive.

Revisit triggers:
- If a rubric fix becomes too complex (e.g. needs full project-wide flow analysis) to land cheaply, an `exclude:` may be the pragmatic choice; document the trade-off here.
- If a deleted rule turns out to catch real bugs after all (post-deletion evidence from another project), restore it with the improved heuristic that motivated the original deletion.
