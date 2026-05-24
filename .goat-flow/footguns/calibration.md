---
category: calibration
last_reviewed: 2026-05-24
---

## Footgun: Threshold Tuning Ripples Through Calibration Matrix

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

Bumping any rule's numeric threshold without updating the corresponding calibration positive case silently breaks `rule_calibration_matrix_covers_every_rule` (search: `rule_calibration_matrix_covers_every_rule` in `src/tests/calibration/mod.rs`). The failure message says "calibration mismatches: under-strict=[<rule-id>]" - pointing at the calibration file, not the threshold change that caused it.

Concrete instance from 2026-05-24: bumping `TEST_LONG_THRESHOLD` (search: `TEST_LONG_THRESHOLD` in `src/rules/mod.rs`) from 80 to 120 silently invalidated:

- `src/tests/calibration/cases_c.rs` (search: `"test-quality.long-test"`) - the positive case wrote 90 `let value = value + N;` lines plus header/footer (~100 lines total), which no longer exceeded 120.
- `src/tests/scenarios/calibration_extras.rs` (search: `calibration_complexity_metrics_size_skip_test_context`) - wrote 90 `if {index} > 0 { ... }` lines (~100 total), same problem.
- `tests/fixtures/rules/test_quality_positive.rs` (search: `fn long_test_body`) - 95 lines of `let value = value + 1;`, now under threshold.
- `.gruff-rs.yaml` (search: `test-quality.long-test:`) - per-project override still pinned to 80.
- `src/built_in_rules/test_rules.rs` (search: `config.threshold(rule_id`) - scanner fallback `120.0` had to follow.

**Five places** had to change for one threshold bump. The calibration matrix catches the failure, but only after at least one fixture, the rule constant, and the per-project config have drifted apart.

When changing a numeric threshold on any rule, before declaring done:

1. Update the constant in `src/rules/mod.rs` (or wherever the rule's `*_THRESHOLD` is defined).
2. Update the scanner fallback - the second argument to `config.threshold(rule_id, fallback)` in the scanner that implements the rule. Grep `config.threshold("<rule-id>"` to find them all.
3. Update `.gruff-rs.yaml` if it pins this rule's threshold per-project. Grep the rule ID inside the `rules:` block.
4. Update every calibration positive case for the rule. Grep `"<rule-id>"` in `src/tests/calibration/cases_*.rs` and inspect the fixture body the positive closure writes.
5. Update any fixture or scenario test that asserts the rule fires on a specific input. Grep `assert_has_rule.*"<rule-id>"` and any `assert_eq!` that counts findings of that rule.

Same ripple applies when deleting a rule: registry entry in `src/rules/definitions_*.rs`, scanner implementation in `src/built_in_rules/*.rs`, calibration case in `src/tests/calibration/cases_*.rs`, calibration matrix harness if it special-cases the rule, default config entry in `.gruff-rs.yaml`, and any test asserting on the rule ID (search: `rule_id ==` and `assert_has_rule`).

Regression coverage: `rule_calibration_matrix_covers_every_rule` enforces registry-calibration alignment. It cannot enforce alignment with `.gruff-rs.yaml` or scanner fallbacks - those are silent failure modes that only show up when the dogfood scan or per-rule scenario tests run.
