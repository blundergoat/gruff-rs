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
  `perRuleDeltas` when a baseline / diff context is active).
- **Config schema version.** `schemaVersion: "gruff-rs.config.v1"` is
  required on every `.gruff-rs.yaml`. Configs without it are rejected at
  load time; run `gruff-rs init --force` to regenerate.
- **SARIF surface.** SARIF 2.1.0 contract: rule descriptor shape, result
  shape, suppression kind for config-derived exclusions, `partialFingerprints`
  key.
- **Config root keys.** `paths.ignore`, `allowlists`, `rules.select`,
  `rules.ignore`, `rules.<id>`, `custom_rules`, `exclude`, `minimumSeverity`,
  `gate`. Unknown keys continue to fail closed.
- **Exit codes.** `0` clean, `1` finding at the `--fail-on` threshold, `2`
  fatal diagnostic (parse error, missing path, etc).

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
  alias added in `0.3.0`; `filePath` is still emitted for the transition and
  will be removed in a later release. Migrate JSON consumers to `file`.
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

## Upgrade workflow (0.4.x → 0.5.0)

`0.5.0` leaves rule ids, fingerprints, `gruff.analysis.v2`, `gruff-rs.config.v1`,
SARIF, and exit codes unchanged, so existing baselines and JSON consumers keep
working. Existing `.gruff-rs.yaml` files load as-is; no `init --force` is needed.
Two changes need action:

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
   in `.gruff-rs.yaml`.
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
