---
category: retrieval
last_reviewed: 2026-11-23
---

## Footgun: A Repository-Root Grep Drops Every `.goat-flow/` Hit

**Status:** active | **Created:** 2026-08-14 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Anchor every learning-loop or skill-doc grep at the bucket directory, never at `.goat-flow/` or the repository root. A zero-hit result from either of those roots is a tooling artifact, not evidence that the term is absent.
**Trigger phase:** READ
**hallucination-risk:** high

`CLAUDE.md` Key Resources instructs the agent to grep `.goat-flow/learning-loop/footguns/`, `lessons/`, `patterns/`, and `decisions/` before changes, and `.goat-flow/skill-docs/skill-preamble.md` (search: `Learning-Loop Retrieval`) allows grepping individual buckets after the INDEX pass. Both are safe only when the search path names the bucket. Raise the root one level and the same search silently reports nothing.

**Symptoms:** a term you can see in an open editor buffer returns no matches; a repository-root grep returns some hits but none from `.goat-flow/`, so the result looks plausible rather than empty. The failure mode is a confident "no prior learnings" that ends retrieval before it started.

**Why it happens:** `.goat-flow/.gitignore` (search: `# Ignore everything by default`) opens with `*` and re-admits each committed path, because the directory mixes committed content with local-only workspace state. The agent harness replaces `grep` with a shell function that delegates to `ugrep --ignore-files` (confirm with `type grep`), and that walker applies the file differently from Git. When this was first measured, a walk rooted at `.goat-flow/` returned zero as well. The goat-flow 1.17.0 upgrade rewrote the re-includes as `**/name/**` for exactly this walker. Since then a `.goat-flow/`-rooted walk returns the full committed set and drops only gitignored local content such as plans and logs, which is correct. A walk rooted at the repository root still drops every `.goat-flow/` hit. A walk that starts inside a bucket has always behaved correctly.

**Evidence:** first measured 2026-08-14 in this repository and re-measured 2026-11-23. Reproduce it as a comparison, never against a recorded count — every root that contains `.goat-flow/logs/` moves as local reports and review bundles accumulate, so absolute totals are noise:

```bash
echo "committed: $(git grep -l '## Footgun:' -- .goat-flow/ | wc -l)"
echo "repo-root wrapper: $(grep -rl '## Footgun:' . 2>/dev/null | command grep -c '^\./\.goat-flow/')"
for root in .goat-flow/ .goat-flow/learning-loop/footguns/; do
  printf '%-40s wrapper=%-6s real=%s\n' "$root" \
    "$(grep -rc '## Footgun:' "$root" 2>/dev/null | awk -F: '{n+=$NF} END{print n+0}')" \
    "$(command grep -rc '## Footgun:' "$root" 2>/dev/null | awk -F: '{n+=$NF} END{print n+0}')"
done
```

Three invariants held on 2026-11-23 regardless of the numbers, and they are the finding:

- Rooted at the repository root, the wrapper returns **zero** `.goat-flow/` files while `git grep` lists every committed one. Non-`.goat-flow/` hits still come through, so the result looks plausible rather than empty. That is the dangerous shape.
- Rooted at `.goat-flow/`, the wrapper's count equals the committed `git grep` count. `command grep` returns more only because it also reads gitignored plans and logs. Until the 1.17.0 `.gitignore` rewrite this root returned zero too.
- Rooted at a bucket such as `.goat-flow/learning-loop/footguns/`, wrapper and `command grep` return **exactly the same count**.

**Prevention:**

```bash
grep -rn "<term>" .goat-flow/learning-loop/footguns/    # anchor at the bucket
command grep -rn "<term>" .goat-flow/                   # or bypass the wrapper
```

INDEX-first retrieval is unaffected: reading `.goat-flow/learning-loop/*/INDEX.md` is a file read, not a walk, and it is the protocol's first step for this reason. Reach for a bucket grep only after the INDEX pass, and when you do, point it at the bucket. The same caution applies to `.goat-flow/skill-docs/` and to any check that concludes a reference is dead because a search found nothing — see `.goat-flow/learning-loop/lessons/verification.md` (search: `## Lesson: A Dead Anchor Proves The Anchor Moved, Not That The Behaviour Went Away`).
