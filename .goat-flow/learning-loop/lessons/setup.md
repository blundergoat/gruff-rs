---
category: setup
last_reviewed: 2026-08-08
---

## Lesson: Verify Goat-Flow Setup Output Before Assuming Apply Finished

**Created:** 2026-05-13
**Decision changed:** Treat setup output as one evidence source, then independently verify instruction versions and the requested audit gates.
**Incident count:** 2
**Latest occurrence:** 2026-08-08

During initial goat-flow installation, `goat-flow setup . --agent codex --apply` reran deterministic file installation but did not create project-specific docs or `AGENTS.md`. The correct recovery was to inspect `goat-flow setup . --agent codex --format markdown`, read the referenced setup workflow, then create the missing project-specific artifacts.

During the 1.13.1 to 1.14.0 upgrade, all four generated setup prompts reported `All audit checks pass`, but `AGENTS.md` still named 1.13.1 while `CLAUDE.md` and `.github/copilot-instructions.md` named 1.10.1. The installer deliberately leaves those project-authored files alone, so the prompt was not proof that their version headers were current.

Future setup work should treat command output as evidence, not intent. If audit still reports missing architecture, code map, glossary, or instruction files, follow the generated setup prompt instead of rerunning the same apply command. Even when the prompt is clean, compare active instruction headers with `goat-flow --version` and run the named agent-scoped harness audits.

## Lesson: Multi-Agent Repos Need `install` Per Agent; `drift` Is Repo-Wide

**Created:** 2026-06-06
**Decision changed:** Preview and install every configured agent separately, even when two agents share a skill directory.
**Incident count:** 2
**Latest occurrence:** 2026-08-08

Upgrading goat-flow 1.7.0 to 1.9.1 with `install . --agent claude` refreshed only the Claude surface (`.claude/skills/`, `.claude/hooks/`, `.claude/settings.json`). This repo also carries a Codex surface (`AGENTS.md`, `.codex/`, `.agents/skills/`), and the audit `drift` check is repo-wide: it compares every installed agent copy against the goat-flow skill templates bundled in the installer. So both `audit . --agent claude` and the `--harness` variant kept failing on `drift` (19 stale `.agents/skills/` files plus `.codex/hooks/deny-dangerous.sh`) even though the Claude surface was already clean. The fix was a second pass, `install . --agent codex`, which refreshed `.agents/skills/` and `.codex/hooks/` and migrated `.codex/config.toml` to the expanded secret-path deny table. Installer passes leave the instruction file (`CLAUDE.md` / `AGENTS.md`) untouched, so version headers are bumped by hand.

The 1.13.1 to 1.14.0 upgrade reproduced the agent-scoped baseline: after the Claude pass, Codex, Copilot, and Antigravity still reported missing baselines with 19 protected agent files. The Codex pass refreshed the shared `.agents/skills/` surface, which made Antigravity's preview ready without force, but Antigravity still needed its own non-forced install to load the agent baseline and reconcile its hook registration.

**How to apply:** In a multi-agent repo, preview and run `install` once per configured agent before expecting `drift` to clear; one `--agent` pass is not enough. Re-preview after each pass because shared surfaces can remove the need for force without removing the need for an agent-specific install. Confirm which surfaces exist before declaring an upgrade done, and treat any change under `.agents/`, `.codex/`, or `AGENTS.md` as a peer-agent boundary that needs explicit user direction first.

## Lesson: `config.yaml` Hook Toggles Are Declarative, Not Runtime Switches

**Created:** 2026-06-06
**Decision changed:** Snapshot hook toggles before managed installs, restore them after every forced pass, and run `hooks sync` from the restored config.
**Incident count:** 4
**Latest occurrence:** 2026-08-08

The 1.9.x installer adds a `hooks:` block to `.goat-flow/config.yaml` (for example `gruff-code-quality` set to `enabled: false`). That toggle is NOT read by the hook scripts at runtime: `.goat-flow/hooks/gruff-code-quality.sh` runs because it is wired in `.claude/settings.json` PostToolUse and gates on file extension plus a matching `.gruff-rs.yaml` and a gruff binary, never on the config toggle (a grep across `.goat-flow/hooks/` for the toggle keys returns nothing). The installer defaults `gruff-code-quality` to disabled even when the hook is live-wired.

During the 1.13.1 to 1.14.0 upgrade, each forced Claude, Codex, and Copilot install scaffolded `.goat-flow/config.yaml` and reset `gruff-code-quality.enabled` from `true` to `false`; the non-forced setup passes preserved the corrected value. Restore the intended toggle immediately after every forced pass, then run `goat-flow hooks sync .` from the corrected config. Do not read `enabled: false` as proof the hook is off; inspect both declarative state and live agent registration.

## Lesson: Forced Goat-Flow Upgrades Need External State Guards

**Created:** 2026-08-08
**Decision changed:** Before any forced managed-template install, bound the target with an ordinary preview, archive the managed surfaces, capture the Git index state and unrelated file hashes, then inspect and restore those guards after every agent pass.
**Trigger phase:** ACT

**What happened:** During the goat-flow 1.13.1 to 1.14.0 upgrade, each agent with a missing trusted installer baseline was blocked by the ordinary dry run. The CLI then rejected `--dry-run --force`, so the overwrite decision itself could not be previewed. The first approved forced pass also staged installer output and the pre-existing `Cargo.lock` modification even though that file's SHA-256 did not change.

**Prevention:** Use the non-forced dry run to enumerate and bound managed targets, create a recoverable archive, and record the clean/dirty index plus hashes for unrelated user changes. Apply force to one agent at a time only while its preview is blocked. After every pass, inspect `git diff --cached`, restore unintended index entries without touching working-tree bytes, recheck unrelated hashes, and rerun the ordinary preview before continuing.

## Lesson: goat-flow 1.10.1 Upgrade Centralizes Hooks and Needs a Hand-Made Copilot Instruction File

**Created:** 2026-06-09

The 1.9.1 -> 1.10.1 `install` restructured the shared surface: durable learning-loop content moved under `.goat-flow/learning-loop/`, the skill docs consolidated under `.goat-flow/skill-docs/` (with `playbooks/`), and per-agent hook copies were replaced by shared scripts under `.goat-flow/hooks/` with each agent's registration repointed there. The installer migrates that content automatically but leaves instruction files (`CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`) untouched, so every pre-1.10.1 path and the version header is a hand-fix in each present instruction file. The repo-wide `instruction-file-skill-docs-pointer` and `doc-paths-resolve` checks only clear once all present instruction files carry the `.goat-flow/skill-docs/playbooks/` READ rule plus Router pointer and resolve every backticked path.

**How to apply:** After running `install` once per configured agent, hand-fix each instruction file, then grep every committed `*.md` (not only the audited set) for the old directory names — `docs/` links and `.goat-flow/code-map.md` entries slip past the auditor's fixed file list. `install --agent copilot` installs skills and hooks but never creates `.github/copilot-instructions.md`; author it by hand or the copilot agent audit fails on the missing file.

## Lesson: Managed Hook Hotfixes Must Patch The Canonical Template

**Created:** 2026-08-08
**Decision changed:** When a system-owned hook template violates a retained project safety contract, keep the canonical package template and installed workspace copy aligned instead of weakening the test or accepting drift.
**Trigger phase:** VERIFY

**What happened:** Goat-flow 1.14.0 changed the post-turn safety hook's unavailable-scan branches from exit 2 to exit 1. The retained project self-test still required fail-closed exit 2, and the official 1.15.0 package preserved the regression. Patching only the workspace hook would have fixed preflight while making the managed drift audit fail. After explicit boundary approval, the canonical 1.15.0 package template and workspace mirror received the same bounded repair.

**Evidence:** `.goat-flow/hooks/post-turn-safety.sh` (search: `git repository root unavailable`) contains the fail-closed branch, while `.goat-flow/hooks/post-turn-safety/post-turn-safety-self-test.sh` (search: `expect_hook_status 2 "unavailable scan"`) pins the project contract.

**Prevention:** Reproduce the hook exit code outside a Git repository and inspect the newest package template before changing project checks. Do not weaken a fail-closed self-test or introduce a drift exception to accommodate a regressed managed template. With explicit approval, back up the official template, patch the canonical and installed copies identically, compare their hashes, and record that a future package reinstall can overwrite the hotfix.
