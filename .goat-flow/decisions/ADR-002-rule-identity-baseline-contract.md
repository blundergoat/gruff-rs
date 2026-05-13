# ADR-002: Rule Identity And Baseline Contract

**Status:** Implemented
**Date:** 2026-05-13

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
