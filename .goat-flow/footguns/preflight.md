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
