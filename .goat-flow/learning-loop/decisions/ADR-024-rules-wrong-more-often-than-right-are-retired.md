# ADR-024: Rules wrong more often than right are retired, not tuned

**Status:** Accepted
**Date:** 2026-10-05
**Author(s):** Claude, user direction
**Ticket/Context:** precision-floor M19 under family lock M82. The operator ruled on 2026-10-04 that a rule right less than
half the time is deleted, and accepted the gruff-rs table with "Accept all (Recommended)". The same decision is gruff-go
ADR-021, gruff-php ADR-034 and gruff-py ADR-029.

## Context

gruff runs as a coding-agent hook, so a wrong finding asks an agent to change code that was already right. The 0.6.0
precision measurement (the workspace's precision-floor M01) judged a sample of each rule's findings on the family corpus.
Eleven gruff-rs rules scored below half. The operator kept three for repair, and M19 turns off rather than deletes a
rule below half that fired fewer than ten times, because so few findings cannot show it is wrong more often than right.

## Decision

gruff-rs retires five rules the 0.6.0 precision measurement found right less than half the time:

- `dependency.path-source`, right on 0 of 13 judged findings: all 13 were true claims about in-repo crates that no reader
  would act on;
- `error-handling.public-unwrap`, right on 14 of 44;
- `security.path-traversal-candidate`, right on 1 of 20. This reverses this repository's ADR-021, which kept it on by default;
- `sensitive-data.database-url-password`, right on 0 of 25;
- `sensitive-data.hardcoded-env-value`, right on 0 of 25.

Each rule's detector goes, with the code only it used: the path-traversal module, the environment-assignment detector
with its test-context line ranges, the database-URL pattern, and the manifest's dependency `path` field. So do its
catalogue entry, tests, docs and dogfood config blocks, as gruff-rs ADR-021 retired two rules before.
A `rules:` block, a `rules.select`, `exclude` or `sensitiveExclusions` entry that names a retired rule exits 2.
`--include-rule` and `--exclude-rule` accept one silently, so a run narrowed to a retired rule runs no rule and passes, and a baseline row for one reports as resolved.

It also turns three rules off by default, each wrong on all 4 judged findings, too few to delete on:
`ci.github-event-shell-interpolation`, `security.sql-dynamic-query` and `security.ssrf-candidate`. They stay in the
catalogue and run when a config sets `rules.<id>.enabled: true` or `--include-rule` names them.

`sensitive-data.private-key` reads the syntax tree to prove that a header-only constant is a native format detector.
With the environment-assignment rule gone, it is the only text rule that needs a Rust parse, so a run that selects only
sensitive-data rules still parses Rust and keeps that proof.

The family specification records the retirements as a catalogue transition with no successor, and keeps each rule's
review record as `retired` (workspace ADR-010).

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Tune each rule | Each repair needs new evidence, and the rule keeps reaching agents until it lands. | Rejected - the 2026-10-04 ruling is to delete, and the roadmap keeps what a rebuilt rule needs. |
| Keep the rules but score-neutral | Findings still reach agents as hook output. | Rejected - gruff-rs ADR-021 found scoring exclusion does not stop hook noise. |
| Turn all eight off | Five rules measured on 13 to 44 findings would stay as hidden code. | Rejected - those measurements are enough to delete on. |
| Retire five, turn three off | A project that relied on a retired rule loses it. | Accepted - every retired rule was wrong or not worth acting on more often than right. |

## Reversibility

A retired rule can return as a new, measured rule; `.goat-flow/plans/0.7.0-roadmap/rules-to-rebuild.md` in the workspace
keeps its wrong shapes and what a rebuilt rule needs. A rule turned off comes back on by removing `default_enabled: false`
once a measurement on more findings puts it at half or better.
