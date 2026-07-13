---
category: hooks
last_reviewed: 2026-07-13
---

## Footgun: Interpreter Heredoc Bodies Bypass The Shell-Only Deny Guard

**Status:** active | **Created:** 2026-07-13 | **Evidence:** ACTUAL_MEASURED
**hallucination-risk:** high
**Symptoms:** A Codex Bash tool call can place a destructive shell, file, Git, or network mutation inside a Python, Node, Ruby, Perl, PHP, sed, awk, or database-client heredoc and receive no denial. A passing hook self-test does not prove these bodies were inspected.
**Why it happens:** `.goat-flow/hooks/deny-dangerous.sh` (search: `goat_first_word_is_inert`) classifies those interpreters and clients as inert heredoc consumers, then `mask_safe_quoted_heredoc_bodies` replaces their bodies before destructive-command checks. `.goat-flow/hooks/deny-dangerous/deny-dangerous-self-test.sh` (search: `ACCEPTED scope: python3 shell escape in body is not inspected`) requires a Python `os.system('rm -rf /')` heredoc, a psql `\\!` escape, and a sed `e` escape to remain allowed. `.codex/hooks.json` registers this as Codex's only PreToolUse command guard.
**Prevention:** Do not put shell, file, Git, or network mutations inside interpreter/client heredocs; issue direct commands so the registered hook can inspect them. Treat `PASS: deny-dangerous self-test` as proof of the documented shell-only contract, not proof that embedded languages are safe. Fixing enforcement belongs in the goat-flow template and its adversarial self-tests together; a consumer-only hook edit would create installer drift and disappear on reinstall.
