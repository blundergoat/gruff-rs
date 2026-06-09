# Upgrading

`gruff-rs` follows SemVer with one explicit caveat: the `0.3.x` line is
"mostly stable", which means a compatibility-sensitive surface is locked in
across `0.3.x` patch releases, but the surrounding edges may evolve.

## What is stable across `0.3.x`

These will not change in a `0.3.x` patch or minor without a major bump to
`0.4.0`:

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

## What may change in `0.3.x` with deprecation

These can evolve inside `0.3.x` provided users get at least one minor release
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

- **Pre-`0.3.x` behaviour.** The `0.1.x` line was the original "mostly stable"
  tier; `0.2.0` collected its breaking changes (analyse-default flip from
  `error` to `advisory`, required config `schemaVersion`, analysis JSON schema
  bump from `gruff.analysis.v1` to `gruff.analysis.v2`, `gruff.summary.v1` to
  `gruff.summary.v2`). Anything that existed only inside `0.1.x` or `0.2.x` and
  is not named under "What is stable across `0.3.x`" is not covered.
- **Internal Rust API.** `gruff-rs` is a binary crate; its library symbols are
  `pub(crate)` and intentionally not part of the public surface. Treat
  `gruff-rs` as a CLI, not a library dependency.
- **Performance.** Wall-clock and RSS will change as rules are added.

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

If a `0.3.x` upgrade silently changes a rule id, fingerprint input, exit code,
or JSON/SARIF field declared stable above, open an issue. Those are the
load-bearing contracts and breaking them inside `0.3.x` is a bug.
