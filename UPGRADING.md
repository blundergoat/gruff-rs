# Upgrading

`gruff-rs` follows SemVer with one explicit caveat: the `0.5.x` line is
"mostly stable", which means the surface listed below is locked across `0.5.x`
releases, but the surrounding edges may evolve.

## What is stable across `0.5.x`

These will not change in a `0.5.x` patch or minor without a bump to `0.6.0`:

- **Rule ids.** `security.process-command`, `dead-code.unused-private-function`,
  `complexity.cognitive`, etc. Baselines key on these.
- **Finding fingerprints.** The hash inputs and serialisation of
  `partialFingerprints.gruffFingerprint` (SARIF) and `findings[].fingerprint`
  (JSON). Baselines key on these.
- **JSON schema version.** `schemaVersion: "gruff.analysis.v2"` and the
  documented top-level fields (`tool`, `run`, `paths`, `summary`, `score`,
  `findings`, `diagnostics`, `suppressions`, `baseline`, optional
  `perRuleDeltas` when a baseline / diff context is active). `0.6.0` moves this
  to `gruff.analysis.v3`; see [What changes in `0.6.0`](#what-changes-in-060).
- **Config schema version.** `schemaVersion: "gruff-rs.config.v1"` is
  required on every `.gruff-rs.yaml`. Configs without it are rejected at
  load time; run `gruff-rs init --force` to regenerate.
- **SARIF surface.** SARIF 2.1.0 contract: rule descriptor shape, result
  shape, suppression kind for config-derived exclusions, `partialFingerprints`
  key.
- **Config root keys.** `paths.ignore`, `allowlists`, `rules.select`,
  `rules.ignore`, `rules.<id>`, `custom_rules`, `exclude`, `minimumSeverity`,
  `gate`. Unknown keys continue to fail closed. `0.6.0` renames the per-command
  exit gate to `failOn` and rereads `minimumSeverity` as a scalar display floor;
  see [What changes in `0.6.0`](#what-changes-in-060).
- **Exit codes.** `0` clean, `1` finding at the `--fail-on` threshold, `2`
  fatal diagnostic (parse error, missing path, etc).

## What changes in `0.6.0`

`0.6.0` is a coordinated family release: the same break lands in all five ports rather than one
at a time, so a project using more than one of them moves once. This port's recorded breaks are:

1. **baselines move to the family `gruff.baseline.v3` file, and every finding identity changes
   once** — A baseline row now stores one line-free identity and a count: sha256 over the tool
   language, native rule id, project-relative path, and a subject that is the symbol plus its
   declaration ordinal, or, when no symbol is named, the message with its measured values
   normalised. A `gruff.baseline.v1` file fails closed and names the migration command.
2. **sensitive-data findings can no longer be baselined** — A generated baseline counts them by
   rule under `sensitive.counts` and stores no row, path, or message for them, and a hand-written
   row cannot hide one.
3. **SARIF `partialFingerprints.gruffFingerprint` is the ratified identity, and a secret carries
   none** — Every existing alert closes and reopens once at this break, and each one then survives
   an ordinary edit. A sensitive finding publishes no `partialFingerprints` at all.
4. **every score changes — the family adopts one normalized scoring formula** — A pillar is now
   `floor + (100 - floor) / (1 + density / densityScale)`. Scores no longer track project size.
   The error weight rises from 8 to 12 and the advisory weight falls from 1.5 to 1; grade
   boundaries stay at A>=90, B>=80, C>=70, D>=60.
5. **the composite can be null, and so can a pillar or file grade** — `score.composite.{score,grade}`
   are `null` when the run evaluated nothing at all; every human view renders
   `Composite: n/a (nothing evaluated)`.
6. **`score.pillars[]` lists every rule-backed pillar and carries an `applicable` flag** — A
   reachable pillar that reported nothing is now visibly distinct from a pillar no rule can reach.
7. **machine JSON uses the family v3 contract** — `analyse` and `report` JSON emit
   `gruff.analysis.v3`; `summary --format json` emits `gruff.summary.v3`. Finding and
   score-offender `filePath` aliases and the top-level `suppressedCount` alias are removed; ignored
   paths move from `paths.ignoredPathDetails` to `paths.details`; Rust-only finding scope and
   per-rule deltas live under `extensions.rs`. Fingerprint and stable-identity inputs are unchanged.
8. **default scans use the family fallback policy** — Non-VCS fallbacks defer to any governing
   `.gitignore`, match at any depth, committed control metadata stays scannable, and explicit
   supported files bypass Git and fallback exclusions. Rust retains `target`; VCS internals remain
   blocked even with `--include-ignored`.
9. **the per-command exit gate moves from `minimumSeverity:` to `failOn:`** — A `0.5` config
   carrying the per-command `minimumSeverity:` map is refused at load time with exit `2` and an
   error naming `failOn`, so every config that pinned a CI threshold fails until it is renamed.
   `minimumSeverity` still loads, but only as a scalar display floor that hides findings below
   one severity and changes no count, score, or exit code; `gruff-rs migrate-config` renames it.

Each entry above is the one this port's own `CHANGELOG.md` records; nothing here is a plan.

10. **the agent-hook contract moves from `gruff.hook.v1` to `gruff.hook.v2`** — The payload's `contractVersion` changes and the envelope gains two required keys, `run` and `suppressions`. `run` carries the audit data a consumer needs to trust the verdict — mode, scope, the operands as given, `analysedFiles`, and the applied baseline — and `suppressions` carries one row per configured sensitive exclusion the run applied, `[]` when none are configured. The exits are ratified as three and no others: `0` when nothing reached the gate, `1` when something did under an explicit consumer request (`--fail-on`, `--fail-on-new`, or `--fail-on-diagnostics`), and `2` when the run could not happen. Update any consumer that validates the payload's key set; one that reads only the keys it needs is unaffected. The contract is `gruff-spec/contracts/core/hook.v2.json`, ratified 2026-09-06.

11. **`list-rules --format json` is an object carrying the rules under `rules`, and thresholds are
    a named knob map** — The catalogue was a bare array and is now `{"rules": [...]}`, the shape the
    other four ports publish. A rule's scalar `threshold` moves to `thresholds`, as
    `{"maxLines": 1000}` where gruff-go already names the knob and `{"threshold": 25}` where no port
    does, and a rule with no threshold publishes neither key. Read `.rules[]` instead of `.[]`, and
    a knob value instead of `.threshold`; `list-rules --selector`, `list-rules <id> --format json`,
    SARIF rule properties and `.gruff-rs.yaml` keys are unchanged.

## What may change in `0.5.x` with deprecation

These can evolve inside `0.5.x` provided users get at least one minor release
of warning before the change lands:

- **New rules.** Default-on additions ship as new ids. Add `rules.ignore`
  entries or pin a baseline to absorb them.
- **Rule thresholds and severity defaults.** Tightened only with a deprecation
  notice in `CHANGELOG.md` and a release dedicated to the rebalancing.
- **New CLI flags and output formats.** Additions are non-breaking.
- **New SARIF properties** under `result.properties` or `rule.properties`.
  Additions only; existing keys keep their meaning.
- **`findings[].filePath`.** Superseded by the canonical `findings[].file`
  alias added in `0.3.0`. It was emitted through `0.5.x` for the transition and
  is **removed in `0.6.0`**, along with `score.topOffenders[].filePath`. Migrate
  JSON consumers to `file`.
- **Text/Markdown/HTML output formatting.** Cosmetic improvements may land
  without a deprecation window because they are not machine-consumed.
- **Dashboard UI.** The local dashboard is explicitly best-effort.

## What may change without warning

- **Pre-`0.5.x` behaviour.** Each earlier line had its own "mostly stable" tier.
  `0.2.0` collected the `0.1.x` breaking changes (analyse-default flip from
  `error` to `advisory`, required config `schemaVersion`, analysis JSON schema
  bump from `gruff.analysis.v1` to `gruff.analysis.v2`, `gruff.summary.v1` to
  `gruff.summary.v2`); `0.4.0` retired two default rules; `0.5.0` removed the
  composite Action's `args` input. Anything that existed only inside an earlier
  line and is not named under "What is stable across `0.5.x`" is not covered.
- **Internal Rust API.** `gruff-rs` is a binary crate; its library symbols are
  `pub(crate)` and intentionally not part of the public surface. Treat
  `gruff-rs` as a CLI, not a library dependency.
- **Performance.** Wall-clock and RSS will change as rules are added.

## Upgrade workflow (0.5.x → 0.6.0)

1. Read [What changes in `0.6.0`](#what-changes-in-060) and decide which breaks touch your project.
2. Install the new line:

   ```bash
   cargo install gruff-rs --locked --version 0.6.0 --root ./.cargo-tools
   ```

3. Carry a baseline forward rather than regenerating it, so previously reviewed findings stay
   reviewed. Run `gruff-rs analyse --migrate-baseline <old path> --generate-baseline <new path>`,
   the command the tool prints when it refuses a `0.5` baseline; the original file is preserved.
4. Re-run `./.cargo-tools/bin/gruff-rs summary .` and compare the finding count and grade with the
   one you had. Both are expected to move: every score changes at this release, the fallback policy
   changes which files are scanned at all, and a secret a `0.5` baseline suppressed is reported
   again. Read a difference against the breaks above before treating it as a regression.
5. Update JSON consumers to `gruff.analysis.v3`: read `findings[].file`, `paths.details`,
   `summary.suppressedFindings`, and `extensions.rs.topLevel.perRuleDeltas`.

**Retreat path.** Pin the previous line —
`cargo install gruff-rs --locked --version 0.5.0 --root ./.cargo-tools` — and keep the `0.5`
baseline file the migration preserved.

## Upgrade workflow (0.4.x → 0.5.0)

`0.5.0` leaves rule ids, fingerprints, `gruff.analysis.v2`, `gruff-rs.config.v1`,
SARIF, and exit codes unchanged, so existing baselines and JSON consumers keep
working. Existing `.gruff-rs.yaml` files load as-is; no `init --force` is needed.
Four changes need action:

1. **The composite Action no longer accepts `args`.** Replace the free-form
   string with `argv`, one literal argument per non-empty line, and set an
   explicit `version:`. A non-empty `args` value exits with a migration error
   instead of running:

   ```yaml
   with:
     version: 0.5.0
     argv: |
       analyse
       .
       --format
       sarif
       --fail-on
       warning
   ```

   Pin the action to a full 40-character commit SHA; `latest` is rejected.
   `working-directory` and `output-file` must resolve inside
   `GITHUB_WORKSPACE`, including after symlink resolution.
2. **`size.file-length` is an error at 1000 substantive lines**, replacing a
   600-line warning. Blank and comment-only lines no longer count, so fewer
   files trip the rule, but one that does now fails a run gated on
   `--fail-on error` rather than warning. Override `threshold` or `severity`
   under `rules:` if the new default does not suit the project.
3. **Sensitive-data findings carry markers, not previews.** JSON, SARIF, and
   hook output serialise values such as `[redacted:private-key]`, so anything
   that parsed secret text out of a report now reads the marker.
4. **Markdown output escapes finding content.** Rule ids and paths render as
   code spans and messages escape Markdown and HTML structure, so untrusted
   values cannot add report blocks.

## Upgrade workflow (0.3.x → 0.4.0)

1. **Drop `modernisation.public-field` and `test-quality.no-assertions` from
   config.** Both rules were retired, and config validation rejects unknown
   rule ids, so a `rules.ignore`, `rules.<id>`, or `exclude` entry naming
   either one fails the run with exit `2` and an error naming the unknown rule
   id or selector. Their existing findings and baseline entries simply
   disappear.
2. **Rule catalogue 87 → 85.** Schema versions, rule ids, and finding
   identities are otherwise unchanged.
3. **Expect fewer findings.** Project-level dead-code findings are withheld
   when a scan does not cover the whole Rust tree, and the dynamic-SQL,
   high-entropy, path-traversal, and lock-across-await checks were narrowed.
4. **Non-UTF-8 files are skipped with a diagnostic** instead of failing the
   scan; named and security-relevant files stay visible.

## Upgrade workflow (0.2.x → 0.3.0)

`0.3.0` keeps every contract listed above — rule ids, fingerprints,
`gruff.analysis.v2`, `gruff-rs.config.v1`, SARIF, and exit codes are all
unchanged — so existing baselines and JSON/SARIF consumers keep working
without edits. The new surface is opt-in:

1. **Nothing is required for the bump.** Existing `.gruff-rs.yaml` files and
   `gruff-baseline.json` load as-is; no `init --force` needed.
2. **Four rubrics were removed:** `complexity.npath`,
   `metrics.halstead-volume`, `metrics.maintainability-pressure`, and
   `design.god-function`. Their findings and baseline entries simply disappear;
   drop any `rules.ignore` / `exclude` entries that named them.
3. **Eleven new rules** (nine security checks plus two secret checks) may
   surface new findings. Run
   `gruff-rs analyse <paths> --format json --no-baseline` to review, then
   regenerate the baseline to absorb them if desired.
4. **Two default changes:** `size.parameter-count` rose `5 → 7` (Clippy's
   default) and `waste.unnecessary-clone-candidate` now ships disabled —
   re-enable it under `rules:` if you want it.
5. **Optional new gates.** The `gate:` block (per-severity and total count
   caps) and `--fail-on-new` (gate only on findings new since the baseline)
   are both off unless configured.

## Upgrade workflow (0.1.x → 0.2.0)

1. **Regenerate `.gruff-rs.yaml`.** The config schema now requires
   `schemaVersion: gruff-rs.config.v1`. Back up your existing file, then run
   `gruff-rs init --force`. Your `paths.ignore` entries, `rules.<id>.enabled`
   overrides, and `minimumSeverity:` block (if present) are preserved; the
   header gets the new schemaVersion line.
2. **Re-read CI exit-code expectations.** `analyse --fail-on` now defaults to
   `advisory` (was `error` in `0.1.x`). Pipelines that previously relied on the
   binary default to allow advisory and warning findings will now fail. Either
   pass `--fail-on error` on the CLI or set `minimumSeverity.analyse: error`
   in `.gruff-rs.yaml`. `0.6.0` renames that per-command block to `failOn:`
   and refuses the old map at load time; see break 9 in
   [What changes in `0.6.0`](#what-changes-in-060).
3. **Re-baseline if you keep one.** `gruff-baseline.json` still uses
   `gruff.baseline.v1` (unchanged) so existing baselines still match. But the
   analyse output schema is now `gruff.analysis.v2`; consumers that validate
   the JSON `schemaVersion` field must be updated.
4. **Run `gruff-rs analyse <paths> --format json --no-baseline`** to see
   whether new default-on rules in `0.2.0` (or their tuned defaults) produce
   new findings. Regenerate the baseline if you want to absorb them:
   `gruff-rs analyse <paths> --format json --fail-on none --generate-baseline gruff-baseline.json`.
5. If a rule produces noise, prefer narrowing it (`rules.ignore`, scoped
   `exclude`, per-rule threshold override, `excludeFromScore` for visibility
   without scoring penalty) over disabling broadly.

## Reporting compatibility regressions

If a `0.5.x` upgrade silently changes a rule id, fingerprint input, exit code,
or JSON/SARIF field declared stable above, open an issue. Those are the
load-bearing contracts and breaking them inside `0.5.x` is a bug.
