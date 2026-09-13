# Configuration

gruff-rs reads YAML configuration and applies it before rule analysis.

## Discovery

Default discovery checks the project root for `.gruff-rs.yaml`.

Use `--config <path>` to load a specific YAML file, or `--no-config` to run
with built-in defaults. Explicit `.json` config paths are rejected; use YAML.

## Root Keys

Every config must declare `schemaVersion: gruff-rs.config.v1` as its first key;
configs without it are rejected at load time (run `gruff-rs init --force` to
regenerate). The supported top-level sections are:

- `schemaVersion` (required) — config schema version; must be `gruff-rs.config.v1`.
- `paths`
- `allowlists`
- `rules`
- `custom_rules`
- `exclude`
- `sensitiveExclusions` — the only way to suppress a sensitive-data finding.
- `failOn` — per-subcommand `--fail-on` defaults for `analyse` and `report`.
- `minimumSeverity` — one severity; the display floor for reported findings.
- `deepScanBudget` — paired line and byte bounds for deep Rust-source analysis.
- `gate` — count-based quality gate (per-severity and total caps).

Unknown sections are rejected so config mistakes fail early.

## Deep Scan Budget

Deep Rust analysis is bounded by default after `.rs` source classification:

```yaml
deepScanBudget:
  enabled: true
  maxLines: 20000
  maxBytes: 2000000
```

Crossing either limit degrades that Rust file instead of excluding it. The file
still counts as analysed, and raw text-level size and sensitive-data checks still
run. Masking, block parsing, AST walking, Rust-code/comment custom rules, and
other deep script work do not. Non-code text such as `.env`, JSON, YAML, TOML,
and `.conf` never enters this budget and remains fully scanned.

Each degradation emits a non-fatal `bounded-deep-scan` diagnostic naming the
path, observed line and byte counts, both effective limits, and whether they came
from `default`, `config`, or `cli`. The diagnostic is visible in text, JSON,
SARIF, HTML, Markdown, GitHub annotations, hotspot JSON, summary, dashboard, and
hook outputs.

All three keys are optional, but supplied limits must be positive integers and
unknown keys are rejected. Pass `--deep-scan-budget LINES:BYTES` to `analyse`,
`report`, `summary`, `dashboard`, or `hook` to override both limits atomically;
pass `--deep-scan-budget off` to disable the budget. The CLI value takes
precedence over project config.

## Paths

Use `paths.ignore` for project-specific ignore patterns:

```yaml
paths:
  ignore:
    - target/
```

## Allowlists

`allowlists` accepts `acceptedAbbreviations`, a string array:

```yaml
allowlists:
  acceptedAbbreviations:
    - db
    - fs
```

`acceptedAbbreviations` sets which short names `naming.short-variable` permits.
The configured list replaces the built-in list rather than merging with it, and
entries are lowercased at load time, so keep the seeds you still want and append
project vocabulary below them. Run `gruff-rs init --force` to regenerate a config
carrying the current defaults.

The 0.5 key `secretPreviews` is removed: FAMILY-CONTRACT.md section 5 makes
every sensitive-data marker unconditional and zero-payload, so the key
authorised nothing. A configuration carrying it, even as an empty list, is
refused with that explanation; `gruff-rs migrate-config` deletes it. See
[Rules](rules.md) for the marker grammar.

## Rule Selection

Rust uses `rules.select` and `rules.ignore` for rule selection:

```yaml
rules:
  select:
    - security.process-command
  ignore:
    - sensitive-data.aws-access-key
```

## Custom Rules

`custom_rules` can add deterministic regex-backed checks:

```yaml
custom_rules:
  - id: custom.todo-marker
    pillar: Documentation
    severity: advisory
    message: TODO marker
    scope: text
    pattern: TODO
```

## Exclusions

Use `exclude` for documented suppressions:

```yaml
exclude:
  - rule: security.process-command
    reason: accepted fixture command
```

`exclude` covers every pillar except sensitive data; a sensitive-data finding is
suppressed only by `sensitiveExclusions` below.

## Sensitive Exclusions

`sensitiveExclusions` is the only way to suppress a `sensitive-data.*` finding. It
is a separate section from `exclude` so that no suppression can ever be expressed
in terms of a matched secret: the section accepts no message or value key at all.

```yaml
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key   # exactly one rule id, sensitive-data pillar only
    path: tests/fixtures/aws-sample.env   # exactly one project-relative path
    symbol: Fixtures::awsSample           # optional; narrows the scope further
    reason: Synthetic key used by the loader fixture; not a live credential.
```

An entry suppresses a finding only when the rule id matches exactly, the finding's
project-relative path matches exactly, and — when `symbol` is present — the
finding's symbol matches exactly. Nothing else is suppressed: the same rule in
another file, and another rule in the same file, both keep reporting. No
sensitive-data rule stamps a symbol today, so an entry carrying `symbol`
legitimately matches nothing; that is expected, not a defect.

Entries are written by hand. gruff-rs never converts a reported marker, preview,
or finding into one, because a suppression is a review decision that needs a
rationale a person can read.

These entries are rejected before analysis starts, each with an error naming the
entry index and the offending key (exit code 2):

- `rule` missing, empty, a wildcard or glob (`*`, `sensitive-data.*`), a pillar
  selector (`sensitive-data`), an unknown rule id, or a known rule outside the
  sensitive-data pillar.
- `path` missing, empty, absolute, containing a `..` component, or containing a
  glob metacharacter.
- Any key outside `rule`, `path`, `symbol`, and `reason` — including
  `message_contains`, `value`, and `preview`.
- `reason` missing, empty, or whitespace-only.
- A second entry claiming the same rule, path, and symbol as an earlier entry,
  because two entries over one scope would split the audit count arbitrarily.

An entry that matches no finding is not an error. It reports `suppressed: 0`, so
fixing the underlying problem never breaks a build.

Every entry publishes one row in the report's `suppressions` array
(`{index, rule, paths, reason, suppressed}` plus `symbol` when present) and contributes to the
`Suppressed findings: N via …` line on the `analyse` and `summary` text output,
where its row is labelled `sensitiveExclusions[<index>]`. Both commands apply the
exclusion, so both publish the count; `summary --format json` carries the same
`suppressions` array, because the `gruff.summary.v3` envelope is the analysis
envelope with only `findings` removed. Suppressed findings are excluded from scoring and
exit codes but are never silently invisible, and no reported field carries matched
value material.

## Severity Defaults

`failOn` sets the default `--fail-on` threshold per subcommand so CI
invocations can omit the flag:

```yaml
failOn:
  analyse: advisory
  report: none
```

Only `analyse` and `report` are accepted, because they are the two commands whose
exit code gates; any other key is a config error that names the valid ones.
Values are `none`, `advisory`, `warning`, or `error`, where `none` turns gating
off. An explicit `--fail-on` on the command line always wins.

Across the Gruff family only `analyse` and `report` are accepted by every port, so a
polyglot repository that shares one `failOn` block should write only those two keys.
`summary` is accepted by gruff-go and gruff-ts, and `dashboard` by gruff-go, gruff-php
and gruff-py; each other port, gruff-rs included, refuses the key with exit 2 rather
than ignoring it, because it ships no gate for that command.

`minimumSeverity` is a different key and never gates. It takes one severity —
`advisory`, `warning`, or `error` — and is the display floor, hiding findings
below it from the reported list while the counts, the score, and the exit code
stay unchanged. The 0.5 per-command `minimumSeverity:` map is refused with an
error naming `failOn`; `gruff-rs migrate-config` performs the rename.

## Quality Gate

`gate` fails a run on finding counts rather than on a single severity threshold:

```yaml
gate:
  total: 200
  severity:
    error: 0
    warning: 10
  onMatch: fail
  scope: new
```

`total` and each `severity` entry are optional caps, and an omitted severity is
unlimited. `onMatch` is `fail` (exit `1`) or `warn` (diagnostic only). `scope`
selects which findings count: `new` counts only findings introduced since the
baseline, `all` counts every finding, and leaving it unset keeps the historical
behaviour. `--fail-on-new` is the CLI alias for `scope: new` and requires a
baseline. A malformed gate is a config error (exit `2`) naming the offending path.

## Compatibility

The shared cross-language config expectations are documented in the
workspace-level `FAMILY-CONTRACT.md` (at the gruff workspace root, sibling to this
crate). Rust intentionally keeps YAML-only config loading and Rust-specific
`custom_rules` / `exclude` sections. `sensitiveExclusions` is the opposite: it is
a cross-port contracted surface, and its shape, rejections, and audit row are
identical in every gruff port.
