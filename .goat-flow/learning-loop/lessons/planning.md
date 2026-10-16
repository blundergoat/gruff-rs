---
category: planning
last_reviewed: 2026-10-03
---

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

## Lesson: Milestone Estimate Tokens Must Terminate Their Checklist Item

**Created:** 2026-08-08
**Decision changed:** An `(est: N min category)` token carries no weight unless it is the last text in its checklist item; evidence prose after it silently drops the estimate.
**Trigger phase:** VERIFY

**What happened:** Four migrated proof items each carried `(est: N min proof)` followed by their literal evidence on the same item. `goat-flow plans check --strict` reported `proof counted work (5 min) does not equal the split component (25 min)` plus `3 testing gate item(s) missing an (est: ...) entry`. The tokens looked present in the file and were invisible to the parser, which anchors on `/\(est:\s*(\d+)\s*min(?:ute)?s?\s+([a-z]+)\)\s*$/` — end-of-item only.

The same trap bit again a few edits later, in a form that is harder to see: a milestone had correct end-of-line tokens on every item, but a **prose paragraph after the last checkbox, inside the same `## Proof` section**, was absorbed into that final item. The estimate stopped being at the end of the item text, so exactly one item silently dropped out of the count. A blank line does not end an item. Anything that is not another checkbox belongs outside the section.

**Prevention:** Keep proof and task items short with the estimate token last, and put literal evidence in a separate section that the milestone parser does not read as Proof. Two adjacent traps in the same parser: a heading is matched by prefix, so any H2 beginning `Proof ` (for example `## Proof evidence - 2026-08-08`) is read as a second Proof section and fails with `conflicting proof representations`; and the aliases that *are* read are `Proof`, `Verification Gate`, `Testing Gate`, `Scope`, `Exit Criteria`, `Kill Criteria`, `Stop Conditions`, and `Mid-Implementation Proof`. Name an evidence section something outside that set — `## Claim evidence` works.

## Lesson: Strict Plan Validation Has No Honest Escape For A Missing Historical Estimate

**Created:** 2026-08-08
**Decision changed:** When a validator demands a field that historical evidence cannot truthfully supply, move the evidence outside the validator's scope; never back-fill the field.
**Trigger phase:** READ

**What happened:** Migrating a legacy plan set to the goat-flow 1.15.0 contract produced 80 strict errors. Most were truthful re-expressions of data the files already carried — dated statuses to the bare lifecycle vocabulary, a `## Depends On` section to the `**Depends on:**` field, an untagged human acceptance box to `[human]`. One was not: strict mode hard-requires a parseable `**Effort estimate:**` product/proof/other split on every milestone in the directory. `Actual:` has honest non-numeric states (`unavailable:`, `retrospective:`, `incomplete:`); `Effort estimate` has none, and `plans check` accepts only a directory, so there is no per-file exemption. Writing estimates onto already-complete milestones would have invented planning data they never carried.

**Prevention:** `plans check` does not recurse into subdirectories, so a `history/` subdirectory holds completed pre-contract milestones with their bytes preserved while strict validates the executable root. Two consequences worth stating wherever the result is reported: a green `--strict` then means "the executable root satisfies the contract", not "every milestone was validated"; and a live milestone that still has open work belongs in the root, with its already-delivered checklist items moved verbatim into a non-parsed section so the forward estimate covers only what remains.
