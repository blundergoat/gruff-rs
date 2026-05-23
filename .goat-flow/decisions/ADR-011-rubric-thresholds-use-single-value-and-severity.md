# ADR-011: Rubric Thresholds Use Single Value And Severity

**Status:** Implemented
**Date:** 2026-05-18
**Author(s):** Codex, after human review feedback
**Ticket/Context:** M32 follow-up; gruff-php threshold contract comparison

## Decision

Every thresholded gruff-rs rubric uses exactly one numeric `threshold` and one
fixed emitted `severity`.

The public config shape for thresholded rules is:

```yaml
rules:
  size.function-length:
    threshold: 30
    severity: warning
```

Named threshold bands such as `warn` and `error` are not part of the gruff-rs
rubric contract. Config validation must reject `thresholds:` maps, reject
`threshold` without `severity`, reject `severity` without `threshold`, and reject
threshold configuration for rules that do not expose a numeric threshold.

Rule metadata must expose at most one threshold value for a built-in rule. A
rubric may still choose advisory, warning, or error as its default emitted
severity, but it must not escalate through warning/error ranges for the same
metric.

## Context

Human review feedback during M32 identified that file-size and method/function
size rules were still modeled as warning/error ranges. That shape made the
rubric harder to reason about because a single metric carried multiple
severities and multiple cutoffs, while the desired behavior is one policy value
and one emitted severity per rubric.

The gruff-php reference implementation introduced a `SeverityThreshold` object
that couples one numeric threshold with the severity it emits
(`/home/devgoat/projects/gruff-workspace/gruff-php/src/Config/SeverityThreshold.php`,
search: `public int|float $threshold`). Its config applier requires `threshold`
and `severity` together for that single-threshold path
(`/home/devgoat/projects/gruff-workspace/gruff-php/src/Config/RuleConfigApplier.php`,
search: `severityThreshold`).

gruff-rs now applies the same contract more strictly: `src/main.rs` validates
the paired keys in `fn apply_rule_thresholds`, and `src/rules.rs` exposes a
single `Option<ThresholdDefinition>` per built-in rule instead of named
threshold arrays.

This decision also narrows ADR-003 and ADR-005 language: strict config
validation still applies, but future work should describe unsupported threshold
shapes for gruff-rs thresholded rubrics. There are no named threshold bands to
configure.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep warning/error threshold ranges | One rubric has multiple policy values and may emit different severities for the same metric family | Rejected; the human-approved contract is one value and one severity for all thresholded rubrics. |
| Keep both `threshold` and legacy `thresholds` map support | Users can express the same policy two ways, examples drift, and strict config validation becomes weaker | Rejected; gruff-rs should fail closed on unsupported shapes before public release. |
| Allow `severity` without `threshold` | Severity override becomes an independent policy surface for non-threshold rules | Rejected; this ADR only accepts severity as part of the thresholded-rubric pair. |
| Use one `threshold` plus one `severity` for each thresholded rubric | Each rubric has one visible cutoff and one emitted severity | Accepted; this is deterministic, easy to document, and matches the requested contract. |

## Consequences

- `size.file-length` uses `threshold: 600` and `severity: warning`.
- `size.function-length` uses `threshold: 50` and `severity: warning`.
- Complexity, architecture, metrics, dependency, TODO-density, parameter-count,
  and long-test thresholded rubrics follow the same one-value plus one-severity
  shape.
- `list-rules --format json` should expose `threshold`, not `thresholds`, for
  thresholded built-ins.
- SARIF rule metadata should expose a single threshold property when a rule is
  thresholded, not an array of named thresholds.
- Future rubric additions must choose one default threshold and one default
  severity, or remain non-thresholded.

## Reversibility

This is reversible only before the config contract is published externally. A
future ADR may reintroduce multi-band thresholds if there is a concrete product
need, but it must define a migration path, update config validation, update rule
metadata, and explain why the added policy complexity is worth breaking this
contract.
