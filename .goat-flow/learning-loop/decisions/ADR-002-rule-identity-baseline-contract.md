# ADR-002: Rule Identity And Baseline Contract

**Status:** Implemented
**Date:** 2026-05-13
**Updated:** 2026-05-30 (M01 tri-state addendum below)

## Decision

Rule ids are stable output contracts. Finding fingerprints are derived from `rule_id`, `file_path`, `line`, and `symbol`, truncated to 16 hex characters. Baseline suppression is exact on `(fingerprint, rule_id, file_path)`. Message text, end line, and column are not baseline identity fields in v0.1.

## Context

Baselines and downstream consumers may key on rule ids and fingerprints. M01 captured the fixture identity contract, and M04 added baseline tests proving exact suppression, message-change tolerance, changed-file behavior, invalid schema rejection, and missing-baseline errors.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Include message in fingerprint identity | Message copy edits break baselines | Rejected because remediation text should be editable without invalidating accepted findings. |
| Suppress by fingerprint only | Different rule/path collisions could suppress too much | Rejected because baseline filtering must also check rule id and file path. |
| Exact `(fingerprint, rule id, file path)` suppression | Line moves can require re-baselining | Accepted because it is deterministic and avoids broad suppression. |

## Reversibility

Changing fingerprint inputs or baseline identity requires an explicit compatibility plan and fixture/baseline migration tests. A future schema version may add richer location identity, but v0.1 must keep this contract stable.

## Addendum 2026-05-30 — Tri-State Classification (M01)

Baseline matching is extended from "drop matched findings" to a three-way
classification, surfaced additively on `gruff.analysis.v2`. The identity contract
above is unchanged: classification still keys on the exact
`(fingerprint, rule_id, file_path)` tuple, and `gruff-baseline.json` files written
before this addendum load unchanged.

**Classification (computed from current findings vs the on-disk baseline only — no
Git, no prior tree):**

- `unchanged` — a current finding whose key matches a baseline entry (the set
  dropped from the default findings list today).
- `new` — a current finding whose key matches no baseline entry (the surviving
  findings after suppression).
- `absent` — a baseline entry whose key matches no current finding (resolved
  since the baseline was recorded).

**Schema additions on `BaselineReport` (camelCase in JSON), additive — old consumers
ignore them:**

- `newCount: usize`, `unchangedCount: usize`, `absentCount: usize`.
- The existing `suppressed: usize` is retained and equals `unchangedCount`.
- On a `--generate-baseline` run there is no comparison context, so the three
  counts are `0` (as `suppressed` already is).

**Default render is unchanged:** the visible findings list stays byte-identical to
prior behaviour (only `unchanged` entries are dropped; `absent` entries are not
rendered). The counts are informational only and do not affect `score` or
`summary` math.

**Deferred to a follow-up (not in this addendum):** a `--baseline-include-absent`
flag that appends synthetic `baseline.absent` advisory rows (severity `advisory`,
SARIF level `note`, original fingerprint preserved) to the findings list. When it
lands, absent rows must not change score math and must order deterministically
after real findings of the same path.
