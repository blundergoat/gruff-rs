---
category: hooks
last_reviewed: 2026-08-11
---

## Footgun: Interpreter Heredoc Bodies Bypass The Shell-Only Deny Guard

**Status:** active | **Created:** 2026-07-13 | **Evidence:** ACTUAL_MEASURED
**hallucination-risk:** high
**Symptoms:** A Codex Bash tool call can place a destructive shell, file, Git, or network mutation inside a Python, Node, Ruby, Perl, PHP, sed, awk, or database-client heredoc and receive no denial. A passing hook self-test does not prove these bodies were inspected.
**Why it happens:** `.goat-flow/hooks/deny-dangerous.sh` (search: `goat_first_word_is_inert`) classifies those interpreters and clients as inert heredoc consumers, then `mask_safe_quoted_heredoc_bodies` replaces their bodies before destructive-command checks. `.goat-flow/hooks/deny-dangerous/deny-dangerous-self-test.sh` (search: `ACCEPTED scope: python3 shell escape in body is not inspected`) requires a Python `os.system('rm -rf /')` heredoc, a psql `\\!` escape, and a sed `e` escape to remain allowed. `.codex/hooks.json` registers this as Codex's only PreToolUse command guard.
**Prevention:** Do not put shell, file, Git, or network mutations inside interpreter/client heredocs; issue direct commands so the registered hook can inspect them. Treat `PASS: deny-dangerous self-test` as proof of the documented shell-only contract, not proof that embedded languages are safe. Fixing enforcement belongs in the goat-flow template and its adversarial self-tests together; a consumer-only hook edit would create installer drift and disappear on reinstall.

## Footgun: A Symlinked Project Path Blocks Every Managed Hook

**Status:** active | **Created:** 2026-08-11 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Read "hook script path escaped the project root" as a path-spelling mismatch to diagnose, not as a compromised checkout or a broken install to repair.
**Trigger phase:** READ

**Symptoms:** Every hook on every agent fails with `BLOCKED: Policy hook unavailable: hook script path escaped the project root.` and exit 2, while the same checkout reached through its physical path works normally. The hook scripts, registrations, and drift audit are all clean, so nothing points at the real cause.

**Why it happens:** `.goat-flow/hooks/run-with-bash.mjs` (search: `An empty or escaping path could make an agent execute outside`) runs a text-only containment check on the raw argument before the resolved one. It compares `process.cwd()`, which Node reports as the physical path, against the hook path spelled the way the host passed it. When the agent host names the project through a symlink, the two spellings diverge and the relative path leads with `..`, so the guard rejects it. The realpath-based check further down (search: `A symlinked parent directory can leave the project even when the plain path`) resolves both sides correctly but never runs, because the text check returns first. This is a goat-flow 1.15.1 defect, latent in this repository only because its own path contains no symlink.

**Prevention:** Confirm the failing spelling with `realpath` against the path the agent host reports before touching hook code. The outcome is fail-closed, so it costs safety nothing to leave unpatched; a repair means resolving both operands before the first containment check, and it belongs in the canonical package template and the workspace mirror together, like every other managed-hook hotfix.
