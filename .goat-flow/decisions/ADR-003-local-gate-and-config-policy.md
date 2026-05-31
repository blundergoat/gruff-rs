# ADR-003: Local Gate And Config Policy

**Status:** Implemented
**Date:** 2026-05-13
**Updated:** 2026-05-31 (per-severity gate + baseline-aware fail-on-new addenda below)

## Decision

The default project config is `.gruff-rs.yaml`. Other gruff config names and non-YAML config files are intentionally unsupported before public release. Config validation is strict: unknown root keys, rule ids, option names, and unsupported value shapes are command errors. Thresholded rules use a single `threshold` plus one fixed `severity`; warning/error threshold maps are intentionally unsupported.

Local and CI verification use `bash scripts/preflight-checks.sh`. The script runs shell syntax/lint checks, formatting, Clippy, unit tests, `list-rules`, fixture scan, scanner feature smokes, and a dogfood `src/` scan. The dogfood scan defaults to `--fail-on warning` so warning-level analyzer debt fails the gate; advisory findings remain visible without failing unless `GRUFF_RS_FAIL_ON=advisory` is set.

## Context

The project needs a checked-in analyzer config shape that humans can copy and modify. Runtime measurements on 2026-05-13 showed the preflight script at about 2.10s and the proposed scanner-smoke bundle at about 1.93s after dependencies were built, so the scanner smokes are fast enough for the default local gate.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep JSON-only default config | Diverges from the intended project config workflow | Rejected; YAML is the default human-edited config. |
| Accept unknown config keys | Typos silently disable intended policy | Rejected; strict config failures are safer for gates. |
| Split scanner smokes into optional deep checks | Developers may skip scanner health checks | Rejected for now because measured runtime is still fast. |
| Fail on warning-level self-scan findings | Large structural debt can otherwise pass while being reported by the analyzer | Accepted; the default dogfood threshold is `warning`, while advisory findings stay non-blocking by default. |

## Reversibility

The fast gate can be split into a deep mode if `bash scripts/preflight-checks.sh` becomes slow enough to discourage use. The dogfood threshold can be temporarily relaxed with `GRUFF_RS_FAIL_ON=error` for transitional runs, but the default gate should remain warning-gated. Config compatibility changes can still add migration paths after a public release creates external users.

## Addendum 2026-05-30 — Per-Severity Quality Gates (M02)

The binary `--fail-on <severity>` flag is joined by an optional `gate:` block in
`.gruff-rs.yaml` that gates on finding *counts*. This is additive: configs without
`gate:` behave byte-identically.

**Schema (strict per the strict-validation policy above):**

```yaml
gate:
  total: 200            # optional; fails when total findings exceed this
  severity:
    error: 0            # optional per-severity caps
    warning: 10
    advisory: 50
  onMatch: fail         # `fail` (default) | `warn`
```

- Counts are `u64`; a negative or non-integer value, an unknown key under `gate`
  or `gate.severity`, or an `onMatch` other than `fail`/`warn` is a **config
  error (exit 2)**, naming the offending path.
- An omitted cap means **unlimited** for that dimension (backward-compatible). An
  empty `gate: {}` is valid and gates nothing.
- The gate is **count-based only**: it reads `Finding.severity` and the report
  summary, never the `score` model, and `Gate::evaluate` is a pure function over
  the report summary.

**Precedence (flag and block may coexist):** the gate block evaluates **first**.
If it trips with `onMatch: fail`, the run exits `1`. Otherwise the legacy
`--fail-on` flag evaluates as before. `onMatch: warn` never changes the exit code;
it only records the diagnostic. A gate trip is exit `1` (a threshold result, like
`--fail-on`), distinct from a config error (exit `2`).

**Diagnostic:** every gated run records a non-fatal `gate` `RunDiagnostic` with the
per-severity breakdown and the `pass`/`trip`/`warn` decision, so the breakdown
renders in text/json without the diagnostic itself forcing exit 2.

**Reversibility:** the `gate:` surface is additive and pre-public, so field names
can change before external users exist. Per-pillar gates, confidence-aware gates,
and coverage gates are explicitly deferred (see M02 Deferred). `--fail-on-new`
(M03) composes this gate with baseline tri-state and is a separate decision.

## Addendum 2026-05-31 — Baseline-Aware Gate Scope (`--fail-on-new`)

Composes the per-severity gate above with baseline tri-state classification so CI
can fail on newly-introduced findings while keeping baselined debt visible.

**Key implementation fact that shapes this decision:** `apply_baseline` drops
findings matched by the baseline (`unchanged`) from the finding set *before* the
report summary is computed and *before* the gate evaluates. So when a baseline is
applied, the gate already counts **new findings only**. That is the correct
default — freezing existing debt is the baseline's entire purpose — so the
default gate behavior is **unchanged** by this addendum.

**New `scope` knob (additive; default preserves current behavior):**

```yaml
gate:
  scope: new            # optional: `new` | `all`. Unset = current behavior
  severity:
    error: 0
```

- Unset (default): the gate evaluates over the report summary as today — i.e.
  new-only when a baseline is applied, all findings when none is. **No behavior
  change** for existing configs.
- `scope: new`: gate over `new`-classified findings (the post-baseline summary).
  **Requires a baseline**; resolving `scope: new` with no baseline loaded is a
  **config error (exit 2)** naming the missing baseline (a silent no-op — where
  every finding is "new" — is the rejected alternative).
- `scope: all`: gate over the full pre-baseline finding set (`new` + `unchanged`).
  Implemented by capturing an "all" per-severity summary before baseline
  suppression; `unchanged`-by-severity is then `all − new`.
- `absent` findings (baseline entries with no current match) **never** count
  toward any threshold under any scope — they are resolved, and are never present
  in the current finding set.

**`--fail-on-new` flag:** a CLI alias for `gate.scope: new` with a default
`severity.error: 0` (warning/advisory unlimited). Flag and config must produce
identical exit codes and diagnostics. Same missing-baseline rule: exit 2.

**Debt visibility:** the gate diagnostic always reports both the gated count and
the baselined `unchanged` count (sourced from the baseline report's counts), so a
passing `scope: new` run still communicates legacy-debt size. Debt is surfaced
via **counts, not retained rows** — the default render continues to drop
`unchanged`/`absent` findings (the backward-compatible baseline render decision).

**Reversibility:** `scope` is additive and pre-public; configs without it are
byte-identical. Per-pillar `fail-on-new` and `--fail-on-resolved` are deferred.
