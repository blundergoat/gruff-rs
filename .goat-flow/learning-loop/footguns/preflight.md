---
category: preflight
last_reviewed: 2026-05-24
---

## Footgun: Preflight Dogfood Output Is Truncated To 20 Findings

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`scripts/preflight-checks.sh` (search: `dogfood_source_scan` and `sed -n '1,20p'`) caps the dogfood failure list shown to the user at 20 lines. The "First matching findings" header in the preflight output is literal - it is the FIRST 20, not the total. There is no count of how many findings were truncated.

The non-obvious failure mode is misclassifying findings from incomplete data. On 2026-05-24 the preflight reported 20 findings; a triage classified all 20 as false positives and applied 20 exclusions; the next preflight run reported a new set of 20 findings drawn from a deeper pool of 31 hidden findings. The first triage looked complete but had only seen 20 of 51 actual findings.

Symptoms that indicate truncation:

- Fixing the 20 visible findings produces another batch of ~20 on the next run, with no obvious source.
- The score shown next to "Score:" in the preflight output drops only marginally even after silencing many findings.
- The findings shown are alphabetical by file path or rule ID, with the last finding sharing a prefix with what would be the 21st (e.g. all 20 are under `src/tests/calibration/` and end just before `src/tests/scenarios/` would start).

Get the full picture by running the dogfood scan directly without the preflight wrapper:

```bash
./target/debug/gruff-rs analyse src --format text --fail-on advisory --no-baseline 2>&1 \
  | grep -E "^- \[" | wc -l                       # total count
./target/debug/gruff-rs analyse src --format text --fail-on advisory --no-baseline 2>&1 \
  | grep -E "^- \[" | sed -E 's/.*\] [^ ]+ ([^ ]+) -.*/\1/' | sort | uniq -c | sort -rn  # by rule
./target/debug/gruff-rs analyse src --format text --fail-on advisory --no-baseline 2>&1 \
  | grep -E "^- \[" | sed -E 's/.*\] ([^:]+):.*/\1/' | sort | uniq -c | sort -rn         # by file
```

These commands mirror what `dogfood_source_scan` runs internally (search: `cargo run --quiet -- analyse src --format text --fail-on` in `scripts/preflight-checks.sh`) but emit every finding instead of the first 20.

Same caveat for the `summary` command: when triaging from `gruff-rs summary` output (the "Top file offenders" table), that's a top-10 of files - it does not enumerate every offender. Use the analyse-text invocation above to confirm whether unlisted files also have findings.

Resist the temptation to "fix the truncation" by widening the `sed` window: the cap is there to keep the preflight report readable. The right move is to know when you need the full list and run the unwrapped command above.

## Footgun: Stale target/release/gruff-rs Can Invalidate Benchmarks

**Status:** active | **Created:** 2026-06-11 | **Evidence:** ACTUAL_MEASURED

`target/release/gruff-rs` is a local Cargo artifact, not a freshness-guaranteed project entrypoint. During the 2026-06-10 sibling audit (`.goat-flow/scratchpad/sibling-audit-2026-06-10.json`, search: `surprises[5]`), this checkout's release binary was five days and nine commits behind HEAD and predated the `hook` subcommand entirely. Directly timing that binary measured stale code.

The safe entrypoints are different: `bin/gruff-rs` (search: `exec cargo run`) always runs through Cargo against the current manifest, and `scripts/test-performance.sh` (search: `cargo build --release --quiet`) rebuilds before measuring its `target/release/gruff-rs` path.

Mitigation: benchmark through `scripts/test-performance.sh`, or run `cargo build --release` immediately before manually invoking `target/release/gruff-rs`. Do not treat refreshing or deleting `target/` as the durable fix; the artifact can become stale again as soon as HEAD moves.

## Footgun: Perf Harness Empty Patch Must Stay Parseable

**Status:** active | **Created:** 2026-06-11 | **Evidence:** OBSERVED

`scripts/test-performance.sh` includes a changed-region scenario named `src.diff-empty` (search:
`add_scenario "src.diff-empty"`). That scenario must write a syntactically valid unified diff to
`SCRATCH_PATCH`; a zero-byte file is not a no-op patch for the CLI. The parser intentionally rejects
non-unified input in `src/changed_region.rs` (search: `is not a parseable unified diff`), so an empty
scratch file makes the perf harness fail before it can print a summary table.

Mitigation: keep `setup_scenario` for `src.diff-empty` writing a minimal context-only unified diff
(search: `@@ -1,1 +1,1 @@`) rather than truncating the patch with `: > "${SCRATCH_PATCH}"`.
