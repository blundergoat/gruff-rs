# gruff-rs

Rust project quality analyzer with deterministic, schema-versioned reports. The
0.1.0 release is built for local CLI and CI gating of Rust repositories plus
committed text/config security surfaces.

## Quickstart

```bash
./bin/gruff-rs analyse . --format text --fail-on warning
./bin/gruff-rs analyse . --format json --fail-on none
./bin/gruff-rs analyse . --format sarif --fail-on none
./bin/gruff-rs report . --format html --output gruff-report.html
./bin/gruff-rs list-rules --format text
./bin/gruff-rs list-rules --format json
bash scripts/start-dev.sh
```

From a source checkout, `bin/gruff-rs` resolves this repository's Cargo manifest
and forwards arguments to the Rust CLI.

For a local PATH install from a release checkout:

```bash
cargo install --path . --locked
```

Report formats for `analyse` are `text`, `json`, `sarif`, `html`, `markdown`,
`github`, and `hotspot`. The `report` command supports static `html` and `json`
output.

`scripts/start-dev.sh` starts the dashboard on `127.0.0.1:8766` by default. The
dashboard has no authentication; bind it to a non-loopback host only for a trusted
local network or another explicitly controlled environment. Override dashboard
settings with `GRUFF_HOST`, `GRUFF_PORT`, and `GRUFF_PROJECT_ROOT`.

## More Docs

- [Rust rubric](docs/rust-rubric.md) describes the v0.1 rule families, limits,
  and deferred checks.
- [Changelog](CHANGELOG.md) records 0.1.0 release changes.
- [Architecture](.goat-flow/architecture.md) describes analysis flow, trust
  boundaries, report contracts, and non-obvious constraints.
- [Code map](.goat-flow/code-map.md) maps source, fixtures, scripts, and local
  goat-flow memory.

## Config

`gruff-rs` reads `.gruff-rs.yaml` by default. Use `--config` to pass another YAML config path.
Unknown keys, unknown rule ids, and unknown selectors are rejected.
Advisory findings are low severity, not optional advice; projects that want
strict 100% compliance can gate with `--fail-on advisory`.

```yaml
paths:
  ignore:
    - target/**
    - fixtures/**
    - tests/fixtures/**
allowlists:
  acceptedAbbreviations:
    - id
    - db
    - io
    - ui
    - tx
    - rx
  secretPreviews: []
rules:
  select: []              # optional; empty or missing means all built-in rules
  ignore: []              # optional; negative selectors always win
  architecture.large-module:
    threshold: 25
    severity: advisory
  architecture.module-fan-out:
    threshold: 8
    severity: advisory
  architecture.public-api-surface:
    threshold: 12
    severity: advisory
  complexity.cognitive:
    threshold: 15
    severity: warning
  complexity.cyclomatic:
    threshold: 10
    severity: warning
  complexity.nesting-depth:
    threshold: 4
    severity: warning
  complexity.npath:
    threshold: 100
    severity: warning
  docs.todo-density:
    threshold: 4
    severity: advisory
  dependency.duplicate-locked-version:
    threshold: 2
    severity: advisory
  metrics.halstead-volume:
    threshold: 1500
    severity: advisory
  metrics.maintainability-pressure:
    threshold: 45
    severity: advisory
  size.file-length:
    threshold: 600
    severity: warning
  size.function-length:
    threshold: 50
    severity: warning
  size.parameter-count:
    threshold: 5
    severity: warning
  test-quality.long-test:
    threshold: 80
    severity: advisory
exclude:
  - rule: security.process-command
    paths: ["tests/**"]
    message_contains: "Command::new"
    reason: "test-only synthetic command"
```

Rule selectors can target an exact rule id, a dotted prefix, or a public pillar:

```yaml
rules:
  select: ["Security", "complexity.*"]
  ignore: ["security.process-command"]
  custom:
    complexity.cognitive:
      threshold: 20
      severity: warning
```

When `select` contains entries, unmatched rules are disabled. `ignore` wins over
overlapping positive selectors. Exact rule blocks keep configuring `enabled:
false`; thresholded rules use a single `threshold` plus one fixed `severity`,
not warning/error ranges. They do not rename rule ids or change fingerprints.
Preview a selector with:

```bash
./bin/gruff-rs list-rules --selector Security
./bin/gruff-rs list-rules --selector performance.* --format json
```

Use `--no-config` to ignore project config.

Default directory scans honour Git ignore rules and `.gruff-rs.yaml` `paths.ignore`.
Committed dot-directories remain eligible for text/security checks when they are
not ignored by Git. Pass `--include-ignored` for deliberate local inspection of
ignored paths, or pass an explicit file/directory path to scan a focused target.
VCS internals such as `.git/` remain blocked during directory traversal.

## Custom Rules

Top-level `custom_rules` entries register config-only regex rules under the
reserved `custom.<slug>` namespace. Custom ids are first-class rule ids: they can
be selected with exact ids, `custom.*`, or their public pillar, are listed by
`list-rules`, and keep the normal fingerprint formula with the full custom id.

```yaml
custom_rules:
  - id: custom.no-hack-comment
    pillar: Documentation
    severity: warning
    confidence: 0.8
    message: HACK comment marker
    scope: comments
    pattern: '(?m)^[ \t]*//[ \t]*HACK\b'
    include_paths: ["src/**"]
    exclude_paths: ["src/generated/**"]
    remediation: "Convert the marker to a tracked issue."
rules:
  select: ["custom.*"]
```

Schema:

- `id` is required and must be `custom.<slug>`; slugs use lowercase ASCII
  letters, digits, and hyphens without leading or trailing hyphens.
- `pillar` is required and must be one of the public pillars used by selectors,
  such as `Documentation`, `Security`, or `Test quality`.
- `severity` is required and must be `advisory`, `warning`, or `error`.
- `confidence` is optional, numeric `0.0..1.0`, and maps to low, medium, or
  high confidence; omitted confidence defaults to medium.
- `message`, `scope`, and `pattern` are required non-empty strings.
- `scope` is `text`, `rust-code`, or `comments`. `text` scans raw file text.
  `rust-code` scans Rust files after masking string literals. `comments` scans
  Rust comments while masking non-comment text.
- `include_paths`, `exclude_paths`, and `remediation` are optional.

Regexes compile during config loading. Bad patterns, duplicate custom ids,
unknown fields, and ids without `custom.` fail closed with config errors that
point at the offending key. Custom rules are intentionally regex-only; ADR-010
defers AST patterns, Semgrep-style metavariables, XPath, scripts, plugins, and
external runtimes.

Report-level exclusions live under top-level `exclude` and run after analysis
and exact baseline filtering. They hide reviewed findings from rendered output;
they do not stop files from being read or scanned. Each entry requires a
`reason`, accepts `rule` as an exact id, dotted prefix, or public pillar
selector, and can narrow by `paths` plus `message_contains`:

```yaml
exclude:
  - rule: sensitive-data.aws-access-key
    paths: ["tests/**"]
    message_contains: "EXAMPLE"
    reason: "test fixture uses a synthetic key shape"
```

Native JSON includes a top-level `suppressions` summary with each entry's
reason and count. Text output prints a suppression summary when an entry hides
findings. Use `paths.ignore` only for discovery-time "do not read" policy; use
`exclude` for audited report suppression.

Cargo dependency checks are local-only. They read `Cargo.toml` and `Cargo.lock`
as data and do not query registries, run Cargo, or consume vulnerability feeds.
Project architecture and dead-code candidate checks are also local-only. They use
the discovered Rust sources and phrase cross-file unused private items as
candidates because the scanner does not run rustc type resolution.
Performance and metric checks use syntactic source patterns and deterministic
token counts, not benchmarks or runtime profiling.

Security checks are also local-only static signals. The current default security
surface includes process command uses with concrete risk signals such as shell
execution, dynamic executables or arguments, custom environment values, or
custom working directories; direct `format!` SQL query arguments; TLS
verification bypasses; weak cryptographic primitive references;
non-cryptographic `rand::` calls in secret-like generation functions; unsafe
blocks without nearby `SAFETY:` rationales; unpinned git dependencies;
security-blind config ignores; and GitHub event values interpolated into
workflow shell steps. Sensitive-data checks include provider-shaped API keys,
JWT-looking tokens, private-key blocks, database URLs with passwords, HTTP(S)
URLs with embedded credentials, hardcoded secret-like assignments, and
high-entropy strings.

## 0.1.0 Contract

Default scans are source-only and local-only: gruff-rs does not execute target
code, run Cargo build scripts, call Git unless an unsafe Git diff mode is
explicitly requested, query registries, or read vulnerability feeds. The
dashboard binds to loopback by default and has no authentication.

Native JSON uses `schemaVersion: "gruff.analysis.v1"`. Rule ids, finding
fingerprints, baseline identity, and renderer behavior are compatibility
sensitive. Config validation is strict so unsupported rule ids, selectors,
threshold shapes, and unknown keys fail closed before analysis.

Gruff-rs complements Clippy, `cargo audit`, dependency policy, code review, and
tests. Candidate wording means the analyzer found a deterministic static signal,
not type-aware or runtime certainty.

## Interpreting Findings And Exits

Findings have a severity (`advisory`, `warning`, or `error`) and confidence
(`low`, `medium`, or `high`). Candidate wording means the scanner found a
conservative static signal, not type-aware certainty.

`--fail-on none` reports findings without failing for their severity. Fatal
diagnostics fail analysis with exit code 2 because they mean the analyzer could
not complete part of the requested scan. Informational diagnostics, such as
patch-filter summaries, remain visible without changing the exit code.
`--fail-on advisory` fails on any finding, `--fail-on warning` fails on warnings
and errors, and `--fail-on error` fails on errors only.

The security and sensitive-data rules are local static checks. They do not replace
`cargo audit`, vulnerability feeds, license policy, code review, or runtime tests.
See the [Rust rubric](docs/rust-rubric.md) for deferred type-aware, registry-backed,
framework-specific, and runtime checks.

## Baselines

Generate a baseline from the current findings:

```bash
./bin/gruff-rs analyse src --format json --fail-on none --generate-baseline
```

Apply the default `gruff-baseline.json` when present:

```bash
./bin/gruff-rs analyse src --format json --fail-on none --baseline
```

Baseline suppression is exact on fingerprint, rule id, and file path. Message text,
end line, and column are not baseline identity fields in `v0.1`.

## Patch Diff Filtering

Use `--diff-patch <path>` to treat a unified diff as data and report only
findings whose file and line fall inside the patch's new-side hunk ranges:

```bash
git diff --no-ext-diff > /tmp/gruff.patch
./bin/gruff-rs analyse . --diff-patch /tmp/gruff.patch --format json --fail-on none
```

Pass `--diff-patch -` to read the patch from stdin. This mode does not execute
Git or external diff tools; it runs analysis normally, applies baselines first,
applies report-level exclusions, then filters the report. The JSON/SARIF/text diagnostics include a
`patch-filter` summary with kept and suppressed finding counts. The older
Git-backed `--diff <mode>` path is available only with `--diff-git-unsafe` and
should be treated as an explicit trust-boundary opt-in. This follows
[ADR-009](.goat-flow/decisions/ADR-009-suppression-baseline-and-diff-layering.md).

## Report Contract

JSON analysis output uses `schemaVersion: "gruff.analysis.v1"`. The top-level
contract includes `schemaVersion`, `tool`, `run`, `paths`, `summary`, `score`,
`findings`, `diagnostics`, `suppressions`, and `baseline`. Finding objects include stable
integration fields such as `ruleId`, `severity`, `confidence`, `pillar`,
`filePath`, `line`, `column`, `endLine`, `symbol`, `message`, `remediation`,
`fingerprint`, `tier`, `secondaryPillars`, and `metadata`.

Rule ids and fingerprints are compatibility-sensitive because baselines and
downstream consumers may key on them. Changing a rule id, fingerprint inputs, or
`schemaVersion` is a compatibility decision.

### SARIF

`analyse --format sarif` renders SARIF 2.1.0 JSON as an adapter over the native
analysis report. It does not change `gruff.analysis.v1`, rule ids, finding
fingerprints, baselines, scoring, or fail-on behavior.

```bash
./bin/gruff-rs analyse fixtures --format sarif --fail-on none
```

SARIF driver rules come from the sorted built-in rule registry and include
native metadata such as pillar, tier, kind, default severity, confidence, a
single threshold when the rule is thresholded, and options. Results carry the
native rule id, SARIF severity level, message, URI-safe artifact path, region
data when available, and `partialFingerprints.gruffFingerprint`. Results hidden
by report-level exclusions are emitted with `suppressions[].kind = "inSource"`
and the configured reason as `justification`.

Fatal diagnostics still fail analysis with exit code 2. In SARIF output all run
diagnostics are reported under
`runs[0].invocations[0].toolExecutionNotifications`; `executionSuccessful` is
`false` only when a fatal diagnostic exists. Findings are still emitted when a
file has both diagnostics and text-rule findings.

Local validation uses focused Rust contract tests plus parseable CLI smokes; the
default gate does not require a networked SARIF schema validator.

## Local Checks

```bash
bash scripts/preflight-checks.sh
./bin/gruff-rs analyse fixtures --format json --fail-on none
./bin/gruff-rs analyse fixtures --format sarif --fail-on none
./bin/gruff-rs analyse fixtures --diff-patch /tmp/gruff.patch --format json --fail-on none
./bin/gruff-rs analyse src --format json --fail-on warning --no-baseline
./bin/gruff-rs list-rules --format json
./bin/gruff-rs list-rules --selector Security
```

`scripts/preflight-checks.sh` runs formatting, Clippy, unit tests, rule listing, JSON and
SARIF fixture scans, a patch-input diff smoke, selector/exclusion/custom-rule
smokes, and a dogfood scan of `src/`. The dogfood scan defaults to
`--fail-on warning` so warning-level analyzer debt fails preflight; set
`GRUFF_RS_FAIL_ON=error` or pass `--fail-on error` only for an explicit
transitional run.

## Performance

`scripts/test-performance.sh` runs the release binary against a fixed set of
scenarios (small fixtures, the self-scan, baseline/history/diff feature
toggles, `list-rules`) and reports median, min, max, and stddev wall-clock plus
peak RSS per scenario. Results are written to `target/perf/last-run.json`
(gitignored).

```bash
bash scripts/test-performance.sh                  # run and print a table
bash scripts/test-performance.sh --update-baseline # snapshot the baseline
bash scripts/test-performance.sh --check          # fail on regression vs baseline
```

`--check` compares the current median against `target/perf/baseline.json` and
exits non-zero if any scenario exceeds the time or RSS budget (defaults: 15%
on wall-clock, 25% on peak RSS; overridable via `GRUFF_PERF_TIME_BUDGET_PCT`
and `GRUFF_PERF_RSS_BUDGET_PCT`). Iteration count is controlled by
`GRUFF_PERF_ITERS` (default 5; first run is warm-up and discarded). Set
`GRUFF_PERF_LARGE_CORPUS=/abs/path` to add an external corpus scenario, and
`GRUFF_PERF_HOST_TAG=<name>` to tag the baseline with a machine identifier.

## Fixtures

`fixtures/` and `tests/fixtures/` intentionally contain code and config snippets that
look noisy. They prove analyzer behavior and should not be cleaned up unless the
replacement preserves the rule coverage.

The default project config ignores fixture directories during broad self-scans.
Run an explicit fixture command when verifying fixture coverage.

## Troubleshooting

- Parse diagnostics: run `./bin/gruff-rs analyse <path> --format json --fail-on none` and inspect `diagnostics`, or use SARIF invocation notifications from `./bin/gruff-rs analyse <path> --format sarif --fail-on none`; Rust AST rules are skipped for parse-failed files while text rules still run.
- Config errors: check unknown root keys, unknown rule ids, unsupported threshold shapes, and invalid value shapes in `.gruff-rs.yaml`.
- Baselines: regenerate only after confirming the current findings are intentionally accepted.
- Intentional fixture findings: use `fixtures/README.md` and `tests/fixtures/README.md` to confirm whether a noisy file is a test input.
