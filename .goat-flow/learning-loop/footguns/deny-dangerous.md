---
category: hooks
last_reviewed: 2026-10-03
---

## Footgun: Interpreter Heredoc Bodies Bypass The Shell-Only Deny Guard

**Status:** active | **Created:** 2026-07-13 | **Evidence:** ACTUAL_MEASURED
**hallucination-risk:** high
**Symptoms:** A Codex Bash tool call can place a destructive shell, file, Git, or network mutation inside a Python, Node, Ruby, Perl, PHP, sed, awk, or database-client heredoc and receive no denial. A passing hook self-test does not prove these bodies were inspected.
**Why it happens:** `.goat-flow/hooks/deny-dangerous/guard-runtime.sh` (search: `goat_first_word_is_inert`) classifies those interpreters and clients as inert heredoc consumers, then `mask_safe_quoted_heredoc_bodies` replaces their bodies before destructive-command checks. `.goat-flow/hooks/deny-dangerous/deny-dangerous-self-test.sh` (search: `ACCEPTED scope: python3 shell escape in body is not inspected`) requires a Python `os.system('rm -rf /')` heredoc, a psql `\\!` escape, and a sed `e` escape to remain allowed. Since goat-flow 1.17.0 that parser is shared by `deny-dangerous.sh` and `deny-git-mutations.sh`, the only PreToolUse command guards `.codex/hooks.json` registers for Codex.
**Prevention:** Do not put shell, file, Git, or network mutations inside interpreter/client heredocs; issue direct commands so the registered hook can inspect them. Treat `PASS: deny-dangerous self-test` as proof of the documented shell-only contract, not proof that embedded languages are safe. Fixing enforcement belongs in the goat-flow template and its adversarial self-tests together; a consumer-only hook edit would create installer drift and disappear on reinstall.

## Footgun: goat-flow Install Never Adds A Deny Family The Template Gained

**Status:** active | **Created:** 2026-10-03 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** After every goat-flow upgrade, compare the `.claude/settings.json` deny list with the installed package template instead of trusting the install summary.
**Trigger phase:** VERIFY

**Symptoms:** The 1.15.1 to 1.17.0 Claude install pass reported success and listed the deny rules it paired or retired, yet `goat-flow audit . --harness --agent claude` then failed Constraints with `deny-covers-secrets` and `missingPatterns` naming `file-read-secret-paths`. Twenty template rules were absent: Read and Edit of `.netrc`, `.git-credentials`, `.config/gh/hosts.yml`, `.pgpass`, and `.config/gcloud/**`, in home and repository forms.

**Why it happens:** The installer treats `.claude/settings.json` as user-owned. It pairs the deny families already present and removes rules it has retired, including `Read(**/credentials*)`, but it never inserts a family the template gained since the last install, and it prints nothing about the omission. The deny hooks match `Bash|PowerShell` only, so the ADR-023 Read/Edit layer is the only guard against the agent reading those files directly, and that layer was incomplete.

**Prevention:** `scripts/preflight-checks.sh` (search: `goat-flow template deny rules missing from`) now fails when any deny rule in the version-matched package template is absent from `.claude/settings.json`, and names each missing rule. The comparison skips when `node_modules` holds no matching goat-flow package, which is the CI case, so run preflight locally after every upgrade. Copy the missing rules from the template rather than replacing the file: this project also carries six `.env` variants that the template lacks.

## Resolved Entries

## Footgun: A Symlinked Project Path Blocks Every Managed Hook

**Status:** resolved | **Created:** 2026-08-11 | **Resolved:** 2026-10-03 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Read "hook script path escaped the project root" as a path-spelling mismatch to diagnose, not as a compromised checkout or a broken install to repair.
**Trigger phase:** READ

**Symptoms:** Every hook on every agent fails with `BLOCKED: Policy hook unavailable: hook script path escaped the project root.` and exit 2, while the same checkout reached through its physical path works normally. The hook scripts, registrations, and drift audit are all clean, so nothing points at the real cause.

**Why it happened:** The goat-flow 1.15.1 launcher ran a text-only containment check on the raw argument before the resolved one. It compared `process.cwd()`, which Node reports as the physical path, against the hook path spelled the way the host passed it, so a project named through a symlink produced a relative path leading with `..` and the guard rejected it before the realpath-based check could run.

**Resolution:** goat-flow 1.17.0 resolves both operands first: `.goat-flow/hooks/run-with-bash.mjs` (search: `Existing paths are compared by physical identity`) applies `realpathSync` to the project root and the hook path before the escape test. Reproduced on 2026-10-03 from the physical checkout with the hook path spelled through a symlink: the committed 1.15.1 launcher exited 2 with `hook script path escaped the project root`, while the 1.17.0 launcher allowed `ls -la` and blocked `rm -rf /` with its ordinary policy message.

**Prevention:** If the symptom returns after an upgrade, confirm the failing spelling with `realpath` against the path the agent host reports, then check that the containment function still resolves both operands before its escape test. The outcome is fail-closed, so diagnosing it costs no safety.
