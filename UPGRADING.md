# Upgrading

`gruff-rs` follows SemVer with one explicit caveat: the `0.1.x` line is
"mostly stable", which means a compatibility-sensitive surface is locked in
across `0.1.x` patch releases, but the surrounding edges may evolve.

## What is stable across `0.1.x`

These will not change in a `0.1.x` patch or minor without a major bump to
`0.2.0`:

- **Rule ids.** `security.process-command`, `dead-code.unused-private-function`,
  `complexity.cognitive`, etc. Baselines key on these.
- **Finding fingerprints.** The hash inputs and serialisation of
  `partialFingerprints.gruffFingerprint` (SARIF) and `findings[].fingerprint`
  (JSON). Baselines key on these.
- **JSON schema version.** `schemaVersion: "gruff.analysis.v1"` and the
  documented top-level fields (`tool`, `run`, `paths`, `summary`, `score`,
  `findings`, `diagnostics`, `suppressions`, `baseline`).
- **SARIF surface.** SARIF 2.1.0 contract: rule descriptor shape, result
  shape, suppression kind for config-derived exclusions, `partialFingerprints`
  key.
- **Config root keys.** `paths.ignore`, `allowlists`, `rules.select`,
  `rules.ignore`, `rules.<id>`, `custom_rules`, `exclude`. Unknown keys
  continue to fail closed.
- **Exit codes.** `0` clean, `1` finding at the `--fail-on` threshold, `2`
  fatal diagnostic (parse error, missing path, etc).

## What may change in `0.1.x` with deprecation

These can evolve inside `0.1.x` provided users get at least one minor release
of warning before the change lands:

- **New rules.** Default-on additions ship as new ids. Add `rules.ignore`
  entries or pin a baseline to absorb them.
- **Rule thresholds and severity defaults.** Tightened only with a deprecation
  notice in `CHANGELOG.md` and a release dedicated to the rebalancing.
- **New CLI flags and output formats.** Additions are non-breaking.
- **New SARIF properties** under `result.properties` or `rule.properties`.
  Additions only; existing keys keep their meaning.
- **Text/Markdown/HTML output formatting.** Cosmetic improvements may land
  without a deprecation window because they are not machine-consumed.
- **Dashboard UI.** The local dashboard is explicitly best-effort.

## What may change without warning

- **`0.0.x` behaviour from the pre-release period.** Anything that existed only
  before the first published `0.1.0` is not covered.
- **Internal Rust API.** `gruff-rs` is a binary crate; its library symbols are
  `pub(crate)` and intentionally not part of the public surface. Treat
  `gruff-rs` as a CLI, not a library dependency.
- **Performance.** Wall-clock and RSS will change as rules are added.

## Upgrade workflow

1. Read the [CHANGELOG](CHANGELOG.md) for the version range you are crossing.
2. Run `gruff-rs analyse <paths> --format json --no-baseline` to see whether
   new findings appear.
3. Regenerate the baseline if you want to absorb them:
   `gruff-rs analyse <paths> --format json --fail-on none --generate-baseline gruff-baseline.json`.
4. If a rule produces noise, prefer narrowing it (`rules.ignore`, scoped
   `exclude`, or a per-rule threshold override) over disabling broadly.

## Reporting compatibility regressions

If a `0.1.x` upgrade silently changes a rule id, fingerprint input, exit code,
or JSON/SARIF field, open an issue. Those are the load-bearing contracts and
breaking them inside `0.1.x` is a bug.
