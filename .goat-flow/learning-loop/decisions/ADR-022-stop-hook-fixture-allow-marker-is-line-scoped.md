# ADR-022: Stop-Hook Fixture Exceptions Are Line-Scoped, Never Directory-Scoped

**Status:** Implemented
**Date:** 2026-08-08

## Decision

The Stop hook's exception for intentional calibration secrets is one
`goat-flow-allow-secret` marker on the exact offending line. `fixtures/sample.rs`
(search: `let api_key`) carries that marker on its AWS-key line only. The hook is
never configured to exempt `fixtures/**`, any other directory, or any file as a
whole, and no token regex is weakened to accommodate a fixture.

## Context

`fixtures/sample.rs` intentionally contains secret-looking strings so the
analyzer's sensitive-data rules stay calibrated against a known positive. That
same line is a real high-confidence hazard to the Stop hook, so any turn that
touched the fixture blocked on content the repository is required to keep. Three
narrowing options existed and the widest two were rejected.

The marker is safe here because the analyzer and the hook have independent
allowlists. `gruff` has no inline allow-marker handling at all: no
`gitleaks:allow`, `pragma: allowlist secret`, or `goat-flow-allow-secret` appears
anywhere in `src/`. Only the hook honours the marker
(`.goat-flow/hooks/post-turn-safety.sh`, search: `is_line_allowlisted`), so a
hook exception cannot silently suppress an analyzer finding.

Verified before and after the marker landed with
`cargo run -- analyse fixtures --format json --fail-on none --no-config --no-baseline`:
3 files analysed, 16 findings, byte-identical sorted finding sets, and
`sensitive-data.aws-access-key` still reported at `fixtures/sample.rs:16` with
its payload redacted to `[redacted:aws-access-key]`.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Exempt `fixtures/**` in the hook | A real credential pasted anywhere else under `fixtures/` is never reported | Rejected. The tree is writable by any agent turn, so a directory exemption is a permanent blind spot rather than a scoped exception. |
| Weaken the AWS-key regex so the fixture token stops matching | Every real key resembling the fixture shape stops matching too | Rejected. It trades a repository-local annoyance for reduced detection everywhere. |
| Line-scoped `goat-flow-allow-secret` on the exact fixture line | Someone could copy the marker onto a genuine secret | Accepted. The failure requires deliberately annotating a real credential, which is visible in review on the same line, and it is the narrowest exception that unblocks the turn. |

## Threat Boundary

The marker suppresses the *hook's* line-level judgement, nothing else. It does
not affect analyzer findings, baselines, fingerprints, or report output. Its
blast radius is exactly one line, and adding it to a second line is a reviewable
diff on that line. A reviewer seeing `goat-flow-allow-secret` in a diff should
treat it as a claim requiring justification, the same as a suppression comment.

## Reversibility

Fully reversible: delete the trailing comment from the fixture line. Doing so
restores the pre-decision behaviour, in which any turn touching
`fixtures/sample.rs` blocks at Stop. Regression coverage lives in
`.goat-flow/hooks/post-turn-safety/post-turn-safety-self-test.sh` (search:
`fixture-marked`), which asserts both directions: the marked line passes and the
identical token without a marker still blocks, on both dispatch paths.

## Maintenance Note

`.gruff-rs.yaml` authoritatively ignores `fixtures/**` (see ADR-018), so the
smoke command in `CLAUDE.md` and the `fixture JSON scan` preflight check analyse
**zero** files and report zero findings. They prove the CLI exits 0, not that the
fixture still calibrates anything. Any future check that intends to prove
fixture calibration must pass `--no-config`.
