---
category: verification
last_reviewed: 2026-07-14
---

## Lesson: New Rules Need A Deep Scan Against An External Repo Before Shipping

**Created:** 2026-05-24

Calibration fixtures prove a rule fires on the shape it was designed for and stays silent on a controlled negative. They cannot reveal what shapes the rule *also* fires on in real codebases — code idioms the rule author never considered. Before declaring a new default-on rule ready, run it against at least one repository outside the gruff-rs source tree and classify every finding TP/FP by reading the source.

**Concrete example (this repo, 2026-05-24):** Ten new rules landed with passing calibration and a clean dogfood scan on gruff-rs itself (14 total findings, all reviewable). A second scan against a sibling Tauri project (`/home/devgoat/projects/devgoat`) surfaced 130 findings from the same rules, including:

- 30 `security.path-traversal-candidate` findings, ~30% false positives from idioms gruff-rs's own code didn't exercise (hardcoded loop iterators over `["a", "b", "c"]`, sanitised filenames named `safe`, internal `&Path` utility helpers).
- 66 `docs.missing-param-doc` findings on `#[tauri::command]` functions whose rustdoc described the *action* (user-facing summary) without enumerating params by identifier.
- A semantic false positive class where rustdoc describes a parameter by what-it-represents ("WSL UNC path") rather than by its identifier (`working_dir`).

None of these patterns existed in gruff-rs's own source. Calibration was green; dogfood was acceptable. The rules looked ready. They weren't.

**How to apply:**

- After calibration passes for a new default-on rule, pick at least one external Rust repository (a Tauri app, a library crate, a CLI tool — something with code idioms gruff-rs doesn't have) and run the rule's selector against it.
- Read every finding the new rule produced — open the file, look at 3-5 lines of context, decide TP/FP. Don't trust counts; trust source inspection.
- For each FP class, decide: (a) tighten the rule, (b) accept and document the FP shape, or (c) delete the rule. "Accept" only when the FP rate stays under ~10% on the external repo.
- The two-stage shape (calibration + external scan) catches false positives that calibration alone misses, because calibration fixtures are written by the same person who wrote the rule. External code is the cheapest source of patterns the author didn't think of.

**Why:** Calibration proves a rule does what its author intended; an external scan reveals what the rule *also* does that the author didn't intend. Shipping without the second step ships hidden noise that erodes user trust in every other finding.

**How to apply:** For every new default-on rule, add a one-line note to the rule's `Created:` PR description: "External scan: <repo path>, <N> findings, <X> TPs / <Y> FPs / <Z> ambiguous." If <Y> exceeds 10% of <N>, tighten the rule or downgrade it to non-default-on before merge.

## Lesson: Dogfood From The Repo Root, Not A Subpath Of A Parent

**Created:** 2026-06-14

gruff roots the "project" at the invocation cwd, and `dead-code.unused-private-item-candidate` (plus any project-coverage rule) suppresses itself with a `partial-context-rule-suppressed` diagnostic when the analysed file set does not cover every discoverable Rust file under that root (see `.goat-flow/learning-loop/decisions/ADR-020-partial-context-dead-code-suppression.md`). So *how* you invoke a dogfood scan changes which rules even run - a subpath scan silently turns project-level rules off.

**Concrete example (this repo, 2026-06-14):** validating the release against five external repos, the first sweep ran `gruff-rs analyse <abs>/RuView` while the shell cwd sat at the parent `scan-test-repos/`. gruff took the parent as the project root, saw RuView's ~700 analysed files as a partial subset of the parent's thousands of discoverable `.rs`, and suppressed the project-level dead-code rule on every repo (0 candidates everywhere, each with a `partial-context-rule-suppressed` diagnostic). Re-running `cd RuView && gruff-rs analyse .` rooted correctly and produced 10 candidates with no suppression - the rule was fine, the invocation was wrong. Per-file rules (path-traversal, high-entropy, lock-across-await) were unaffected, so only the project-coverage rule went dark, which is easy to miss in a counts-only review.

**How to apply:**

- For each external repo, `cd` into its root and run `gruff-rs analyse .`. Do not scan a subpath (or an absolute path to a subdir) from a parent directory when project-level rules matter.
- After any sweep, read the `diagnostics[]` array. A `partial-context-rule-suppressed` entry means a project-coverage rule did not run, so its "zero findings" is not authoritative - pairs with [[research]]/external-scan practice above.
- The shell cwd persists across tool calls; an earlier `cd` into a scratch dir can silently re-root later scans. Set cwd deliberately and confirm it, in addition to using absolute paths for the binary and target.

## Lesson: Run Fresh Git Status Before Giving Git Next Steps

**Created:** 2026-05-31

When advising on commits, staging, or "what's next" for a dirty-looking workspace,
run `git status --short --untracked-files=all` or `git status -sb` in every
repo being discussed immediately before answering. Do not reuse a status snapshot
from earlier in the session, especially after other agents, hooks, commits, or
context compaction may have changed the tree.

**Concrete example (this repo, 2026-05-31):** After working across `gruff-rs`
and `gruff-ts`, I told the user the next step was to commit the current work
based on an earlier dirty status. A fresh `git status -sb` then showed both
repos clean (`## dev...origin/dev`), so the commit advice was wrong and stale.

**How to apply:**

- Before saying "commit", "stage", "nothing changed", "working tree is dirty",
  or "worktree is clean", run status in the relevant repo(s) in the current turn.
- If multiple repos were touched, status all of them and name each result.
- If the command was not run, phrase the answer as a caveat or run the command
  first; do not make a confident git-state claim from memory.

## Lesson: A Complete Milestone Must Have Ticked Checkboxes

**Created:** 2026-05-31

Never mark a milestone `implemented`, `testing-gate`, or `complete` while its
own task, assumption, exit-criteria, or testing-gate checkboxes remain unticked.
An implemented status with empty checkboxes is worse than no status update: it
misleads the next reader into thinking either no work happened or the tracking
artifact cannot be trusted.

**Concrete example (this repo, 2026-05-31):** a task-tracking file's top-line
status said its rubric-removal work was implemented, but every checklist item
was still `- [ ]`. The code and verification had moved, yet the plan looked
untouched until the user called it out. The corrected task now has ticked
assumptions, tasks, exit criteria, testing gates, and a `Verification Evidence`
section.

**How to apply:**

- When completing work from a plan, tick each completed checkbox immediately
  after the code or verification proves it.
- Before changing any task `Status:` to `implemented`, `testing-gate`, or
  `complete`, run `rg -n '^- \[ \]' <task-file>`. If unchecked boxes remain,
  either tick them with evidence or leave the status as in-progress/deferred.
- Before final response for plan-backed work, re-open the task file and confirm
  the checklist, status line, and verification evidence agree.
- Treat task files as review artifacts, not scratch notes. A stale checklist is
  a failed handoff even when the code is correct.

**Updated 2026-05-31:** Two failure modes worse than the above surfaced when the
user found more stale plans. (1) **The status line lies the other way.** Some
task files read `Status: planned` with zero ticks even though the feature had
already shipped (confirmed via `git log` and the live source symbols); another
read `Status: completed` with none of its boxes ticked. So the status line is
not a trustworthy done-signal — before trusting OR updating it, cross-check
against `git log` and the actual `src/` symbols (`rg` the structs/fields the
work introduced), not just "did I tick boxes." (2) **Reconciling a neglected
checklist is NOT a licence to blanket-tick.** A partially-implemented plan has
diverged from its spec: the core lands while a peripheral surface (a CLI flag, a
renderer, docs) does not. Flipping every `- [ ]` to `- [x]` to "finish the
board" writes false `[x]` on features that do not exist — the exact
false-attestation this tool exists to catch (mission: `docs/mission.md`). Verify
each box against the source this session, tick only what is real, and leave the
rest unchecked with an inline `NOT BUILT`/`NOT DONE` note plus a
`Verification Evidence` section. A half-true status (`core done … X and Y not
built`) beats both a bare `planned` and a dishonest `complete`.

## Lesson: When A Self-Scan Says Zero, Confirm The Rule Still Fires Somewhere

**Created:** 2026-05-24

After tightening a rule to eliminate false positives, a "zero findings on dogfood" result is ambiguous: either the FPs were correctly suppressed, or the rule's pattern-matching was broken so it now matches nothing. Confirm the rule still fires on its calibration positive case before declaring victory.

**Concrete example (this repo, 2026-05-24):** While tightening `modernisation.manual-contains` to require either a deref (`*x == y`) or RHS-ref (`x == &y`) shape, the regex went from broad to narrow in one edit. Dogfood went from 4 findings to 0, which could mean "the 4 FPs are gone" *or* "the regex is now broken." Running `cargo test rule_calibration_matrix_covers_every_rule -- --nocapture` confirmed the calibration positive case (`*item == target`) still fires, validating that the zero-finding result was the FP fix, not a regression.

**How to apply:**

- After every rule-tightening change, run the calibration matrix test before celebrating a zero-finding dogfood result.
- If both green: the FP fix worked. If the calibration positive case now fails: the regex was over-tightened — restore the necessary pattern coverage.
- The `rule_calibration_matrix_covers_every_rule` test catches this asymmetry by checking `positive_fired == true && negative_fired == false` for every rule.

**Why:** Pattern-matching rules can silently lose their pattern when calibration changes. The matrix is the contract; trust it over dogfood counts.

**How to apply:** Tightening a regex → run calibration matrix as the first verification command, dogfood as the second. Never declare a tightening done from dogfood alone.

## Lesson: Rule Retunes Need Parity Fixtures For Every Detection Path
**Created:** 2026-06-12
**What happened:** M02 and M08 were marked technically complete with green focused tests, but review-only scratch repros found two untested shapes: direct `prepare(&format!(...))` did not receive the same fixed-placeholder exemption as bound `let sql = format!(...)`, and inline `PathBuf::from(...).join(user_input)` / `Path::new(...).join(user_input)` were missed after receiver gating.
**Evidence:** `src/built_in_rules/behavior_rules/tls_sql.rs` (search: `push_direct_sql_dynamic_query_findings`) and `src/built_in_rules/behavior_rules/tls_sql.rs` (search: `dynamic_format_binding_name`) had separate paths with different exemption coverage. `src/built_in_rules/path_traversal_rules.rs` (search: `join_regex`) only captured simple receivers before the inline constructor fix.
**Prevention:** For every rule retune that mentions multiple detection paths or receiver shapes, add at least one positive and one negative fixture per path before closing the milestone. Re-run the original scratch repros that exposed the review finding, not just the named focused test filter.

**2026-06-14 extension - narrowing for precision silently drops valid shapes.** One review round found four coverage gaps where tightening a rule excluded shapes that still matter, and a clean dogfood/calibration run could not reveal them (a clean repo has no findings to lose - only adversarial review or an external scan carrying those shapes exposes the false negative): the SQL keyword gate (`src/built_in_rules/behavior_rules/tls_sql.rs` search: `fn template_is_flaggable`) dropped non-DML statements (`TRUNCATE`/`MERGE`/`GRANT`); the path-traversal receiver grammar (search: `fn join_regex`) stopped matching accessor-call receivers like `self.root().join(x)`; the export-attribute check (`src/project/items.rs` search: `fn has_export_attr`) missed Rust 2024 `#[unsafe(no_mangle)]` (the attribute path is `unsafe`, with the export ident nested inside); and the non-UTF-8 skip classifier (`src/discovery.rs` search: `fn is_security_relevant_text_path`) did not treat `.github/workflows/*.yml` as security-relevant, so an invalid byte skipped the `security.github-actions-*` rules. When narrowing a gate, grammar, classifier, or attribute matcher, enumerate the shapes you are now EXCLUDING and add a positive fixture for each that must still fire.

## Lesson: Shell Wrapper Path Resolution Must Pass Shellcheck

**Created:** 2026-05-16

When adding POSIX shell entrypoint wrappers, do not copy the `CDPATH= cd ...`
idiom without checking it. Shellcheck reports SC1007 because the assignment-like
prefix is easy to misread.

Use a command-substitution form that clears `CDPATH` inside the subshell:
`SCRIPT_DIR="$(unset CDPATH; cd -- "$(dirname -- "$PRG")" && pwd)"`.

## Lesson: Analyzer Fixes Need A Focused Re-Scan

**Created:** 2026-05-16

When fixing findings reported by gruff itself, run a focused analyzer scan before
declaring victory. A performance fix can move code enough to create a different
finding, such as a function-length error from adding local setup inside the
target function.

If a fix introduces setup data, prefer module-level constants or small helpers
over adding bulky local tables to an already near-threshold function.

## Lesson: Calibration Fixes Must Update Fixture Contracts

**Created:** 2026-05-16

When changing analyzer rule semantics, rerun the full unit suite after targeted
calibration tests. A desired rule behavior change can invalidate fixture-count
contracts, and the first failing assertion may poison the shared analysis lock
so later failures look unrelated.

After fixing the first semantic mismatch, rerun the full suite before diagnosing
the lock-poison follow-on failures.

## Lesson: Negative Performance Experiments Must Be Reverted

**Created:** 2026-05-17

When optimizing analyzer hot paths, measure each candidate with
`GRUFF_PERF_ITERS=3 bash scripts/test-performance.sh` before keeping it. A
plausible allocation-sharing change can regress both wall time and RSS.

If a candidate makes the `src.*` scenarios slower or noisier, revert only that
candidate and keep the measured wins. Finish with `bash scripts/preflight-checks.sh` plus a
default `bash scripts/test-performance.sh` run so the final diff has both
correctness and performance evidence.

## Lesson: Clippy Shape Failures Deserve Design Fixes

**Created:** 2026-05-18

When a late verification pass catches a structural Clippy failure, do not add an
allow just to finish the milestone. In M31, threading suppression state pushed
`src/analysis.rs` (search: `fn build_report`) over the argument-count limit; bundling
the summaries and SARIF-only suppressed findings into a small state struct kept
the pipeline explicit and lint-clean.

**2026-07-13 extension:** M07 added metadata kind to the GitHub line analyzer
and shared finding emitter, pushing both to eight arguments. The first
`cargo clippy --all-targets -- -D warnings` run rejected both helpers. Grouping
per-file rule state in `src/built_in_rules/github_metadata_rules.rs` (search:
`struct GithubMetadataScanState`) and user-visible finding copy in the same file
(search: `struct GithubStepFinding`) removed the structural warning without a
lint allow or behavior change. When a rule change threads one more concern
through an existing seven-argument helper, introduce a vocabulary-named state
or descriptor before the full gate rather than waiting for Clippy to force it.

## Lesson: Regex Match Starts Can Hide Useful Source Lines

**Created:** 2026-05-18

When testing regex-driven findings, include patterns with leading whitespace
such as `(?m)^\s*//`. Rust `regex` treats `\s` as newline-capable, so the match
may start before the visible token and report the wrong line if the analyzer
uses `match.start()` directly.

For source diagnostics, compute the displayed line from the first
non-whitespace byte inside the match when that exists, then rerun the focused
scope test before continuing with broader gates.

## Lesson: New Scenario Tests Can Trip Dogfood File-Length Gates

**Created:** 2026-05-22

When adding scenario coverage to an already large test module, check the
project dogfood thresholds before assuming the full suite is enough. In M52, a
new discovery glob test made `src/tests/scenarios/smoke.rs` exceed the
`size.file-length` warning threshold even though the Rust tests passed.

Prefer a focused scenario module such as `src/tests/scenarios/discovery.rs`
when new coverage is cohesive. Then rerun `bash scripts/preflight-checks.sh` so
the dogfood scan proves the repository still clears its own quality gate.

**Updated 2026-05-31:** The same trap applies outside `src/tests/scenarios/`.
M00c added two rule-behaviour regression tests to
`src/tests/rule_behaviours/rubric_false_positive_guards.rs` and Rust tests
passed, but preflight dogfood reported `size.file-length` at 632 lines. Split
cohesive milestone-specific checks into a focused module such as
`src/tests/rule_behaviours/mission_retune_guards.rs` before re-running
preflight. The same dogfood pass also catches helper naming drift, e.g.
boolean helper names in `src/built_in_rules/docs_rules.rs` must keep accepted
predicate prefixes like `has_`.

**Updated 2026-07-13:** New integration-test files need the same focused
dogfood pass even when they are well below the file-length threshold. M05's
release workflow graph tests passed 12/12, but full preflight still found a
102-line validator, vague mutation parameters named `to`, and YAML parsing
whose helper names did not express that the input was controlled test data.
Split contract validation by the user-visible workflow stages, use semantic
mutation names such as `replacement_text`, and name intentional local parsers
for the format they review (for example, `replace_workflow_yaml_text`). Run a
focused dogfood scan on the new test file before the full preflight so shape
and security-review findings are corrected as design feedback, not suppressed.

**Updated 2026-07-14 (M12):** A 29-line rationale table pushed
`src/tests/rule_behaviours/rust_rules.rs` to 628 lines, while the companion
classifier pushed `src/built_in_rules/helpers.rs` to 613. Focused tests and
Clippy passed; only repository dogfood exposed both 600-line breaches. Moving
the table to `safety_rationale_guards.rs` and the cohesive production helpers
to `safety_rationale.rs` preserved the same focused filters without formatter
exemptions or threshold suppression. Registering both as new top-level modules
then pushed their parents from eight to nine children, so the final wiring
nests them under `idiomatic_handling.rs` and `behavior_rules.rs`; focused
dogfood returned zero findings. Check both the destination line count and the
parent fan-out before adding a cohesive test/helper, then split and nest
ownership before the full gate when either owner is already at its limit.

**Updated 2026-07-14 (M14):** Three strict-config and metadata contracts pushed
`src/tests/config_and_selectors/config.rs` from 559 to 640 lines. Formatting,
Clippy, focused tests, and the full suite all passed, but a focused dogfood scan
reported `size.file-length`. Moving the new contracts plus the existing legacy
suppression scenario into the nested `secret_previews.rs` module keeps the
config test owner below 600 lines and its parent below the fan-out threshold.
Check the destination line count before adding even small contract-test groups;
the full Rust suite does not exercise the analyzer's own source-shape rubric.

## Lesson: Rule Helpers Must Pass Dogfood Shape Gates

**Created:** 2026-05-23

When adding analyzer rules, run a focused dogfood scan before final preflight if
the implementation introduces new helpers in `src/built_in_rules/` (search:
`analyse_weak_crypto`). In M55, Rust tests and calibration passed, but
`cargo run --quiet -- analyse . --format json --fail-on none --no-baseline`
reported a new `size.parameter-count` warning for a helper that threaded file,
line-start, findings, dedupe, primitive, and byte-index parameters separately.

Prefer a small context/reporter struct for repeated finding construction, then
rerun the dogfood scan at the same threshold before treating the verification
failure as closed.

## Lesson: Cargo Test Accepts One Name Filter Before Harness Args

**Created:** 2026-05-24

When running multiple focused Rust tests, do not pass several test names to one
`cargo test` command. Cargo accepts a single test-name filter before `--`; an
extra name is parsed as an unexpected argument and does not run either intended
set.

Run separate focused commands, use a shared substring filter, or run the module
or full suite when the desired tests do not share a stable name prefix.

## Lesson: Keep JSON Smoke Assertions One File At A Time

**Created:** 2026-05-24

When verifying CLI JSON round trips, avoid clever `jq input` pipelines across
several files. It is easy to consume the wrong stream position and turn a valid
product check into a jq error.

Assign each expected value from a separate `jq -r` read, then use shell `test`
assertions before printing the compact summary.

## Lesson: Verify Cargo Subcommand Binaries Both Ways

**Created:** 2026-05-24

When a script resolves a Cargo subcommand binary path directly, test that direct
binary invocation separately from `cargo <subcommand>`. `cargo audit` dispatches
through Cargo, but the installed `cargo-audit` binary needs the explicit
`audit` subcommand when invoked by path.

For tool-root smoke tests, run the exact path form the script will use, such as
`/tmp/tool-root/bin/cargo-audit audit`, before treating the Cargo-dispatched
form as equivalent.

## Lesson: Verify Bot Review Claims Against Current Code Before Fixing

**Created:** 2026-05-27

Automated PR reviewers (Codex / CodeRabbit / Copilot bots) generate suggestions against a specific commit snapshot. By the time their comments arrive, the same suggestions can be: (a) already addressed by a later commit, (b) based on a premise that does not match current code, or (c) describing a failure mode that an upstream guard already prevents. Acting on every bot suggestion produces churn — unnecessary diffs, false-positive backlog entries, and "fixes" that revert genuine design choices.

**Concrete examples from PR #3 review (2026-05-27):**

- **Stale: `pillar_label` duplication** — bot suggested extracting to shared module. Verified `src/report.rs` (search: `pub(crate) fn pillar_label`) already has the shared helper. Action: skip.
- **Stale: `applicable` boolean assertion** — bot suggested adding `is_boolean()` checks. Verified `src/tests/renderers/pillar_sections.rs` (search: `is_boolean`) already has them. Action: skip.
- **Stale: schemaVersion grep brittleness** — bot suggested whitespace-tolerant regex. Verified `scripts/preflight-checks.sh` (search: `[[:space:]]*`) already uses it. Action: skip.
- **False premise: `applicable` decoupled from composite** — bot claimed composite includes non-`SCORE_PILLARS` pillars. Verified `src/scoring.rs` (search: `SCORE_PILLARS.contains`) filters by the canonical pillar list. Action: skip — premise is wrong.
- **False premise: init lacks schemaVersion** — bot claimed `render_default_config` omits the key. Verified `src/init.rs` (search: `append_schema_version_section`) calls the schema renderer. Action: skip — premise is wrong.
- **Unreachable: custom security rule with `excludeFromScore`** — bot worried about silent scoring blind spot. Verified `src/config_loader/rule_settings.rs` (search: `custom rule `{rule_id}` only supports`) rejects `excludeFromScore` for custom rules at load time. Action: pin the restriction with a regression test instead of "fixing" the unreachable code path.
- **Real: HashMap iteration in security diagnostics** — verified `config.rule_settings: HashMap`. Action: fix.
- **Real: digest severity from registry default** — verified `build_rule_digest` uses `definition.default_severity`. Action: fix.

The pattern is consistent: out of 14 inline + 3 nitpick comments, 6 were real, 1 was a real-but-design-decision (queue to backlog), 5 were stale, and 5 were premise mismatches.

**How to apply:**

- For each bot comment, do not start editing. First, find the line the bot points at in the *current* code (not the diff hunk the bot quoted). Read the surrounding 10-20 lines.
- If the bot's claim describes a line, function, or shape that no longer matches current code: the comment is stale. Skip with a note in the response.
- If the bot's claim depends on a premise (e.g. "this function iterates over X and produces Y"), trace whether the premise actually holds. The premise is the part most likely to be wrong; bots can hallucinate call-graph relationships.
- If the failure mode the bot describes requires a specific config / runtime state, check whether an upstream guard prevents reaching that state. A guard makes the bot's "fix" defensive code for an unreachable scenario — which violates CLAUDE.md's "don't add fallbacks for scenarios that can't happen".
- When the bot is right but the fix is non-trivial (e.g. needs an ADR), queue to backlog with the verification evidence captured — including the bot's exact framing so the deferred decision is reviewable later.
- When the bot is right and the fix is trivial: ship the fix with a regression test that pins the contract the bot identified.
- Capture the per-comment outcome in your response so the user can see what was acted on vs. why. "Disagree because X" is more useful than silence.

Watch list (signals a bot claim is likely stale or premise-mismatched):

- The bot quotes a diff hunk's line number that does not match the current file.
- The bot's "fix" suggestion is structurally identical to code that already exists somewhere in the repo (you can find it by grep).
- The bot references a function name that has been renamed or extracted.
- The bot's premise involves a HashMap, threading, or iteration order assumption — sometimes correct, but the loudest source of false alarms.
- The bot's suggested action requires changing a contract (schema bump, fingerprint format) that the project's stability stance explicitly defers — see [[release]] for the no-bc-ceremony rule.

## Lesson: A Captured CLI Artifact Can Be A Sibling Port's Output (Shared /tmp)

**Created:** 2026-05-30

When capturing `gruff-rs` CLI output to a file for parsing (`... list-rules --format json > /tmp/rules.json`), do not trust a shared, predictable temp path. This repo lives in a `gruff-workspace` alongside sibling ports (`gruff-{go,php,py,ts}`); a sibling run can overwrite the same `/tmp/rules.json` between your capture and your parse, silently replacing the contents.

**Concrete example (this repo, 2026-05-30):** A rubric audit captured `cargo run -- list-rules --format json > /tmp/rules.json` and parsed it once correctly (80 Rust rules); a later parse of the SAME file returned 64 Go-flavoured ids (`maintainability.defer-in-loop`, `test-quality.fatal-in-goroutine`, `naming.package-stutter`) — gruff-go's catalogue. It nearly produced the false conclusion "gruff-rs ships inapplicable Go rules." Source ground-truth settled it: `rg 'fatal-in-goroutine' src/rules/` → 0 hits, `halstead-volume` → present. Re-running to a unique path (`/tmp/gruff_rs_rules_$$.json`) gave the correct catalogue.

**How to apply:**

- Capture CLI output to a unique path (`mktemp` or `...$$.json`), not a shared `/tmp/<tool>.json`, when other workspace ports may run concurrently.
- Before drawing a conclusion from a captured artifact, sanity-check it against source: `rg` one id you expect and one you don't in `src/rules/`. A surprising result (rules from another language) is far more likely a clobbered artifact than a real finding.
- This is a specific case of the universal rule: verify against current source before asserting; never fabricate codebase facts from a stale or swapped artifact.

## Lesson: Expand Abbreviated Commit IDs From Git, Not Memory

**Created:** 2026-07-13

An abbreviated commit ID is enough for human navigation but not enough to
reconstruct a full hash. During the 0.5.0 plan verification, the graph checks
were correct but the verification command invented full-length expansions for
`a3f20f2` and `2f6a25b`; the resulting exact-hash assertions failed even though
the live ancestry and tree relationship had not changed.

**Prevention:** When exact identity matters, capture it with `git rev-parse`
in the same verification command and report that value. If a plan intentionally
records only an abbreviation, compare it with `git rev-parse --short` or treat
the abbreviation as a display anchor. Never pad or infer the unseen suffix of
a Git object ID from memory or prior prose.

## Lesson: Keep Compound Verification Checks Wrapper-Safe And Scoped

**Created:** 2026-07-13

A combined plan-consistency check failed before executing any repository
assertion because a literal backtick matcher conflicted with the JavaScript
tool wrapper. After that was corrected, the repository safety hook rejected the
same command for exceeding its chained-segment limit. The first reference pass
also scanned untouched sections of a parent multi-repository prompt and
reported missing files owned by sibling ports.

**Prevention:** Split verification into bounded commands before reaching hook
limits, avoid shell tokens that conflict with the outer tool-call syntax (for
example, match Markdown backticks as `\x60`), and scope reference resolution to
the files or sections actually changed. A broad repository/workspace reference
audit is a separate check and must model intentionally future-created and
sibling-owned paths explicitly.

**2026-07-13 extension:** M07 broadened an existing workflow-event regression
test from scalar `on:` values to scalar, list, and mapping forms, then renamed
the test even though its original scalar contract still applied. `goat-flow
stats --check` caught the learning-loop reference that the rename made stale.
When expanding a referenced test without invalidating its original contract,
preserve the established semantic anchor; rename it only when the meaning truly
changes and every approved reference can move with it.

## Lesson: Use concat! For Whitespace-Sensitive Multiline Assertions

**Created:** 2026-07-13

The first M01 generated-config contract used a Rust string with backslash line
continuations around explicit `\n` escapes. Rust stripped indentation following
the physical continuation, so the expected bytes lost the two leading spaces
on later YAML comment lines. The implementation was correct, but the test stayed
red after the generator changed.

**Prevention:** Build exact multiline expectations with `concat!` and one
quoted logical line per argument. Include the actual rendered value in the
assertion failure message. Reserve backslash continuations for prose where
leading whitespace is irrelevant, not byte-sensitive YAML, JSON, or renderer
contracts.

## Lesson: Renderer Injection Assertions Must Respect Output Context

**Created:** 2026-07-14

M08's first green Markdown encoding still failed a broad
`!markdown.contains("<script>")` assertion. The message had correctly encoded
its HTML-looking text, while the same text in a file path remained safely
inside the dynamic code span produced by `src/render/markdown.rs` (search:
`fn markdown_code_span`). The assertion treated inert code content as raw HTML
and therefore rejected the correct output grammar.

**Prevention:** Keep an exact golden for delimiter-safe code fields, then
isolate the plain-text field before asserting that HTML, links, or other
structure is absent. For mixed-context formats, never use one raw substring ban
across the entire rendered document; assert per context or parse the rendered
format. Regression coverage lives in `src/tests/renderers/output.rs` (search:
`markdown_renderer_keeps_hostile_finding_fields_in_one_inert_bullet`).
