---
category: preflight
last_reviewed: 2026-07-13
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

## Footgun: Stale Target Binaries Can Invalidate CLI Proofs

**Status:** active | **Created:** 2026-06-11 | **Evidence:** ACTUAL_MEASURED

`target/debug/gruff-rs` and `target/release/gruff-rs` are local Cargo artifacts,
not freshness-guaranteed project entrypoints. During the 2026-06-10 sibling
audit (`.goat-flow/scratchpad/sibling-audit-2026-06-10.json`, search:
`surprises[5]`), this checkout's release binary was five days and nine commits
behind HEAD and predated the `hook` subcommand entirely. Directly timing that
binary measured stale code.

The debug path can also stay stale after a test-only build. During 0.5.0 M01,
`cargo test accepted_abbreviations` compiled a test binary containing
`src/init.rs` (search: `acceptedAbbreviations controls which short names`), but
the next `cargo run -- init --stdout` reported a fresh dev target and executed
an older `target/debug/gruff-rs` that omitted the new comment. The
`src/tests/config_and_selectors/init_command.rs` contract passed while the CLI
artifact remained byte-identical to the pre-change output. Running
`CARGO_INCREMENTAL=0 cargo run -v -- init --stdout` forced the normal binary to
compile and made the marker appear.

Mitigation: for behavior proofs, inspect Cargo's output for an actual compile
and sanity-check the runnable artifact for the changed marker. If Cargo reuses
a stale normal binary after a test build, use a separate non-incremental
fingerprint (`CARGO_INCREMENTAL=0 cargo run ...`) instead of trusting `Finished`
alone. Benchmark through `scripts/test-performance.sh`, or run
`cargo build --release` immediately before manually invoking
`target/release/gruff-rs`. Do not treat deleting `target/` as the durable fix;
the artifact can become stale again as soon as HEAD moves.

## Footgun: Cargo Install Will Not Adopt An Unmanaged Existing Binary

**Status:** active | **Created:** 2026-07-13 | **Evidence:** OBSERVED

`cargo install <crate> --version <exact> --locked` can fail with `binary already
exists in destination` when the destination already contains the right binary
but Cargo's install metadata does not own it. This occurs after a release
artifact or package manager placed the executable in the same install root; an
exact `--version` does not make Cargo adopt or overwrite that file.

The M03 validator installer reproduced this with `action-validator 0.9.0`.
`scripts/dependency-install.sh` (search: `install_action_validator`) now checks
the executable at the requested install-root destination first: it reuses an
exact reported version and requests a forced Cargo replacement only when an
existing destination is wrong. Keep that check destination-aware so `--root`
does not accidentally accept a matching binary found elsewhere on `PATH`.

## Footgun: Release Archive Shape Is A Cross-File Contract

**Status:** active | **Created:** 2026-07-13 | **Evidence:** OBSERVED

`.github/workflows/release.yml` (search: `Stage archive and build identity`)
invokes the production `stage-archive` contract. `scripts/release-contract.sh`
(search: `validate_archive_member_names`) requires one top-level directory
containing the binary plus README, two licenses, and CHANGELOG.
`scripts/action-install.sh` (search: `validate_release_member_list`) duplicates
that exact member set so a release archive cannot smuggle extra files into the
action install path.

M04's first production-path harness encoded the named members correctly but
asserted the wrong total: it counted six files instead of the actual five files
plus one directory. The valid fixture then failed as incomplete. The installer
now proves exactness through named presence flags plus duplicate/unexpected
rejection instead of maintaining a second numeric total. Whenever the release
workflow changes archive contents, update the named installer contract and its
valid/unexpected-member fixtures together. Never loosen the installer to accept
arbitrary extra members just to make a publisher change pass.

## Footgun: Perf Harness Empty Patch Must Stay Parseable

**Status:** active | **Created:** 2026-06-11 | **Evidence:** OBSERVED

`scripts/test-performance.sh` includes a changed-region scenario named `src.diff-empty` (search:
`add_scenario "src.diff-empty"`). That scenario must write a syntactically valid unified diff to
`SCRATCH_PATCH`; a zero-byte file is not a no-op patch for the CLI. The parser intentionally rejects
non-unified input in `src/changed_region.rs` (search: `is not a parseable unified diff`), so an empty
scratch file makes the perf harness fail before it can print a summary table.

Mitigation: keep `setup_scenario` for `src.diff-empty` writing a minimal context-only unified diff
(search: `@@ -1,1 +1,1 @@`) rather than truncating the patch with `: > "${SCRATCH_PATCH}"`.
