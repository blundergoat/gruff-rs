---
category: error-handling
last_reviewed: 2026-05-27
---

## Pattern: Typed Error Class + Central Wrapper For User-Facing CLI Errors

**Context:** Use this when adding any user-facing throw / panic / abort site in a gruff-* CLI — config parse, missing file, malformed input, validation, schema mismatch, anything caused by a user mistake (not a code bug). A raw `throw new Error(...)`, `panic!(...)`, or `die(...)` that propagates to stderr leaks implementation detail (file paths, `node_modules/` internals, source line numbers), exposes the call stack, and gives the operator zero next step. The pattern below composes across the port family so operators using more than one port see one error UX, not three.

**Evidence:** gruff-ts (2026-05-27): every config-load throw site uses `ConfigLoadError(message, suggestion)` in `src/config.ts:12,116-124`; every CLI action handler in `src/cli-program.ts:181/304/341` wraps its body in `runWithConfigErrorHandling` (`src/cli-program.ts:491`); the wrapper prints `gruff-ts: config error\n  <message>\n\nSuggested fix:\n  <suggestion>\n` and sets `process.exitCode = 2`. Reproducing a missing-`schemaVersion` scenario against HEAD produces a clean two-block message and exit 2, not a Node stack trace. A user-reported stack trace for this exact scenario turned out to be from a stale checkout — current code already implemented the pattern.

gruff-rs uses the same shape via `Result<T, String>` returned to `main` (`src/main.rs:134`), formatted and exited through `ExitCode`. gruff-php uses `ConfigError` + structured `Console::abort`. All three ports: typed error, central wrapper, two-block layout, stable exit code.

**Approach:**

- **Typed error class** with a mandatory `suggestion` (or equivalent) field. The message describes what's wrong; the suggestion names the next action (`Run \`gruff-* init --force\``, `Edit X to use Y`, `Remove this line from .gruff-*.yaml`). Raw `Error` / `panic!` / `RuntimeException` is reserved for assertion violations and code bugs — never for user input.
- **One central wrapper** at the CLI action edge (not per-handler). The wrapper catches the typed user-facing errors and formats them; everything else re-throws so the stack trace surfaces for debugging. One wrapper means consistent UX across every subcommand without per-handler ceremony.
- **Two-block output shape**: line 1 = `<binary>: <kind>` (e.g., `gruff-rs: config error`); then `  <message>` indented; blank line; `Suggested fix:` header; then `  <suggestion>` indented. Empty-suggestion paths are a smell — fix the throw site to surface a real next step before merge.
- **Stable exit code**: gruff-* ports use `2` for user-actionable config / input errors. CI scripts get a stable contract; operators can grep exit codes to distinguish "the tool itself broke" (non-2) from "fix your config" (2).
- **Before patching a reported stack trace**, reproduce the exact command against current `HEAD`. If the current code already handles it gracefully, the bug report was from a stale checkout — document the finding (or close the issue) rather than redundantly editing throw sites.

**When NOT to apply:** assertion violations and internal-invariant breaks ("unreachable" branches, compiler-detected impossibilities, "should never happen" cases). Let those panic / throw with stack trace intact — they're code bugs and a clean message would hide the diagnostic data needed to fix them. Rule of thumb: if the cause is something the user can fix without touching gruff source, it's user-facing (use this pattern). If the cause is something only a gruff maintainer can fix, it's a code bug (let it crash visibly).

**Related:** cross-port reference implementations are gruff-ts `src/config.ts:12` (`ConfigLoadError`) plus `src/cli-program.ts:491` (`runWithConfigErrorHandling`), and gruff-rs `src/main.rs:134` (`main` formatting `Result<T, String>` to `ExitCode`). The non-fatal counterpart is `RunDiagnostic` (`src/report.rs`) — used when the run should continue but a user-visible warning is required (see `excluded-security-rule-from-score` in ADR-014).
