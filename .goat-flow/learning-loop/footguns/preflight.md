---
category: preflight
last_reviewed: 2026-08-14
---

## Footgun: Preflight Shows Only The Last 20 Lines Of A Failed Check

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Treat a failing preflight check's on-screen output as the tail of the evidence, never the whole of it. Re-run that one check unwrapped before triaging, and never infer a finding total from what preflight printed.
**Trigger phase:** VERIFY

`scripts/preflight-checks.sh` (search: `run_preflight_check`) pipes every failing check's combined output through `tail -20` before indenting it. The cap applies to every check, not just the dogfood scan, and it keeps the **last** 20 lines - the opposite end from what an unlucky reader assumes.

For the dogfood scan the ordering makes this worse than a plain cut. `analyse --format text` prints its header first (`Composite:` and the `Findings: N total · N error · N warning · N advisory` count line), then `Diagnostics:`, and the `Findings:` list **last**. Roughly a dozen non-finding lines sit above the list, so `tail -20` starts eating the header once a failing scan passes about fourteen findings: it keeps the bottom of the findings list and scrolls the composite score and the total count off the top. Past that point preflight output alone cannot tell you how many findings there are, and a real failure is usually well past it.

The non-obvious failure mode is misclassifying findings from incomplete data. On 2026-05-24 the preflight showed 20 findings; a triage classified all 20 as false positives and applied 20 exclusions; the next run showed a new set of 20 drawn from a deeper pool. The first triage looked complete but had seen 20 of 51.

**Symptoms:** fixing every visible finding produces another batch of similar size on the next run with no obvious source; no `Findings: N total` line appears in the preflight output at all; the visible findings are the alphabetically *last* ones by path, with the first file in the tree absent.

**Why it happens:** the cap lives in the shared check runner, so it is applied uniformly and knows nothing about which check produced the output or where that check's summary line sits within it.

**Evidence:** `scripts/preflight-checks.sh` (search: `tail -20`) is the single truncation site, inside the failure branch of `run_preflight_check`. `scripts/preflight-checks.sh` (search: `dogfood_scan`) is the whole check body: `bin/gruff-rs analyse . --format text --no-baseline`, gated by `minimumSeverity.analyse` in `.gruff-rs.yaml`. Measured on 2026-08-11 against a 10-finding scan: 22 lines of output, `tail -20` starting three lines in, so the header was already being clipped from the top while the count line still survived. Each further finding pushes the cut one line deeper into it.

**Prevention:** get the full picture by re-running the scan directly, from the repository root so cross-file dead-code signal stays authoritative:

```bash
bin/gruff-rs analyse . --format text --no-baseline 2>&1 \
  | grep -E "^- \[" | wc -l                       # total count
bin/gruff-rs analyse . --format text --no-baseline 2>&1 \
  | grep -E "^- \[" | sed -E 's/.*\] [^ ]+ ([^ ]+) -.*/\1/' | sort | uniq -c | sort -rn  # by rule
bin/gruff-rs analyse . --format text --no-baseline 2>&1 \
  | grep -E "^- \[" | sed -E 's/.*\] ([^:]+):.*/\1/' | sort | uniq -c | sort -rn         # by file
```

These run exactly what the check runs and emit every finding. Scanning a subpath such as `src` instead suppresses the cross-file dead-code rule and reports a different finding set than the gate.

Same caveat for the `summary` command: when triaging from `gruff-rs summary` output (the "Top file offenders" table), that's a top-10 of files - it does not enumerate every offender. Use the analyse-text invocation above to confirm whether unlisted files also have findings.

Resist the temptation to "fix the truncation" by widening the `tail` window: the cap is there to keep the preflight report readable across every check. The right move is to know when you need the full list and run the unwrapped command above.

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

**2026-07-13 extension:** Cargo package verification can produce the same trap
without a test-only build. During M07, `target/debug/gruff-rs.d` named only
`target/package/gruff-rs-0.4.0/src/...` inputs. Subsequent workspace `cargo
build` and `cargo run` both reported the dev target fresh and executed that
package-copy binary, so the new focused metadata scan falsely retained an old
permission finding while current unit tests passed. `CARGO_INCREMENTAL=0 cargo
run` rebuilt dep-info from the repository `src/` tree and the exact reproduction
became silent. `scripts/preflight-checks.sh` (search:
`focused_github_metadata_scan`) now uses that distinct fingerprint for the
security scan; keep it whenever `cargo package` and live-worktree analysis can
share one target directory and package version.

**2026-07-14 extension:** A test-only build reproduced the trap during the SQL
shape retune. `cargo test sql_dynamic_query` compiled the current
`src/built_in_rules/behavior_rules/tls_sql.rs` (search:
`normalise_sql_shape_text`) into the test harness, but the following `cargo
run` reused an older normal binary and falsely retained two PRQL findings. A
fresh `CARGO_TARGET_DIR` rebuilt the CLI from the worktree and returned the
expected empty finding set. For current-source CLI comparisons after tests,
use an isolated target directory or `CARGO_INCREMENTAL=0`, then confirm the
runnable binary timestamp changed before trusting its output.

**2026-07-14 M12 extension:** `cargo clippy --all-targets` left the same trap
after `src/built_in_rules/helpers.rs` changed (search:
`safety_rationale_words`). The focused test binary accepted `same-thread
access`, but `cargo run --verbose` printed `Fresh gruff-rs` and launched an
older `target/debug/gruff-rs`, so a manual matrix reproduced the pre-change
classifications. Repeating the exact scan with a fresh `CARGO_TARGET_DIR`
accepted both hyphenated rationales and rejected the circular one. Treat a CLI
proof after Clippy like a proof after tests or packaging: isolate its target or
force a distinct non-incremental fingerprint, and verify an actual compile.

**2026-07-14 M16 extension:** Focused and full tests compiled the current rule
catalogue, but the following `cargo run --quiet -- list-rules` still exposed
the retired relationship target `sensitive-data.api-key` instead of the live
`src/rules/idiom_security_size_test_definitions.rs` target (search:
`sensitive-data.api-key-pattern`). The normal binary predated both changed
sources, and `target/debug/gruff-rs.d` still named only
`target/package/gruff-rs-0.4.0/src/...` inputs. `CARGO_INCREMENTAL=0 cargo
build` printed `Compiling gruff-rs`, advanced the executable timestamp, exposed
the canonical target, and the complete 85-rule detail scan reported zero
dangling links. A post-test CLI proof must therefore check both the marker and
the executable freshness; a successful test harness alone does not refresh the
normal command.

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

## Footgun: Release Pin Tests Scan Shell Source As Commands

**Status:** active | **Created:** 2026-07-15 | **Evidence:** OBSERVED

`tests/release_security_contract.rs` (search: `fn logical_shell_commands`) treats
every non-empty, non-comment line in a reviewed shell script as command text;
it does not mask quoted labels or strings before
`validate_direct_cargo_installs` searches for the literal lowercase prefix
`cargo install `. During M17, the documentation checker label
`'cargo install version'` in `scripts/preflight-checks.sh` (search:
`Cargo install example version`) was therefore reported as an unpinned install
even though it was only user-facing diagnostic text.

Before adding command examples or diagnostics to a release script, run
`cargo test --test release_security_contract -- --nocapture`. Any line that
contains the lowercase executable prefix must be a real or synthetic install
command with both `--version` and `--locked`; non-command labels should use
plain descriptive prose that cannot masquerade as an executable command.

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
