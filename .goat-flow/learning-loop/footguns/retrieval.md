---
category: retrieval
last_reviewed: 2026-08-14
---

## Footgun: A Recursive Grep Rooted At `.goat-flow/` Returns Zero For The Whole Committed Surface

**Status:** active | **Created:** 2026-08-14 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Anchor every learning-loop or skill-doc grep at the bucket directory, never at `.goat-flow/` or the repository root. A zero-hit result from either of those roots is a tooling artifact, not evidence that the term is absent.
**Trigger phase:** READ
**hallucination-risk:** high

`CLAUDE.md` Key Resources instructs the agent to grep `.goat-flow/learning-loop/footguns/`, `lessons/`, `patterns/`, and `decisions/` before changes, and `.goat-flow/skill-docs/skill-preamble.md` (search: `Learning-Loop Retrieval`) allows grepping individual buckets after the INDEX pass. Both are safe only when the search path names the bucket. Raise the root one level and the same search silently reports nothing.

**Symptoms:** a term you can see in an open editor buffer returns no matches; `grep -rn <term> .goat-flow/` exits 1 while `grep -rn <term> .goat-flow/learning-loop/lessons/` finds it; a repository-root grep returns some hits but none from `.goat-flow/`, so the result looks plausible rather than empty. The failure mode is a confident "no prior learnings" that ends retrieval before it started.

**Why it happens:** `.goat-flow/.gitignore` (search: `# Ignore everything by default`) opens with `*` and re-admits each committed path with a `!` rule, because the directory mixes committed content with local-only workspace state. The agent harness replaces `grep` with a shell function that delegates to `ugrep --ignore-files` (confirm with `type grep`). That walker reads `.goat-flow/.gitignore` whenever the walk starts at or above `.goat-flow/`, applies the leading `*`, and does not restore the subtree from the `!` re-includes the way Git does. A walk that starts inside a subdirectory never reads that file, which is why bucket-anchored searches behave correctly.

**Evidence:** first measured 2026-08-14 in this repository. Reproduce it as a comparison, never against a recorded count — every root that contains `.goat-flow/logs/` moves as local reports and review bundles accumulate, so absolute totals are noise:

```bash
for root in .goat-flow/ .goat-flow/learning-loop/footguns/; do
  printf '%-40s wrapper=%-6s real=%s\n' "$root" \
    "$(grep -rc '## Footgun:' "$root" 2>/dev/null | awk -F: '{n+=$NF} END{print n+0}')" \
    "$(command grep -rc '## Footgun:' "$root" 2>/dev/null | awk -F: '{n+=$NF} END{print n+0}')"
done
```

Two invariants hold regardless of the numbers, and they are the finding:

- Rooted at `.goat-flow/`, the wrapper returns **zero** while `command grep` returns the full set. The same holds for any term that lives only under `.goat-flow/`, such as `ADR-022`.
- Rooted at a bucket such as `.goat-flow/learning-loop/footguns/`, wrapper and `command grep` return **exactly the same count**.

A repository-root search sits between the two: non-`.goat-flow/` hits come through, every `.goat-flow/` hit is dropped, so the result looks plausible rather than empty. That is the dangerous shape.

**Prevention:**

```bash
grep -rn "<term>" .goat-flow/learning-loop/footguns/    # anchor at the bucket
command grep -rn "<term>" .goat-flow/                   # or bypass the wrapper
```

INDEX-first retrieval is unaffected: reading `.goat-flow/learning-loop/*/INDEX.md` is a file read, not a walk, and it is the protocol's first step for this reason. Reach for a bucket grep only after the INDEX pass, and when you do, point it at the bucket. The same caution applies to `.goat-flow/skill-docs/` and to any check that concludes a reference is dead because a search found nothing — see `.goat-flow/learning-loop/lessons/verification.md` (search: `## Lesson: A Dead Anchor Proves The Anchor Moved, Not That The Behaviour Went Away`).
