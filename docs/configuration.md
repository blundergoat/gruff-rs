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
- `minimumSeverity` — per-subcommand `--fail-on` defaults for `analyse` and `report`.
- `gate` — count-based quality gate (per-severity and total caps).

Unknown sections are rejected so config mistakes fail early.

## Paths

Use `paths.ignore` for project-specific ignore patterns:

```yaml
paths:
  ignore:
    - target/
```

## Allowlists

`allowlists` accepts `acceptedAbbreviations` and `secretPreviews`, both string
arrays:

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

`secretPreviews` preserves the suppression behaviour of previously reviewed
entries. It does not reveal secret material: sensitive-data findings serialize
zero-payload markers either way. See [Rules](rules.md).

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

## Severity Defaults

`minimumSeverity` sets the default `--fail-on` threshold per subcommand so CI
invocations can omit the flag:

```yaml
minimumSeverity:
  analyse: advisory
  report: none
```

Only `analyse` and `report` are accepted, because they are the two commands whose
exit code gates; any other key is a config error that names the valid ones.
Values are `none`, `advisory`, `warning`, or `error`, where `none` turns gating
off. An explicit `--fail-on` on the command line always wins.

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
workspace-level `CONTRACT.md` (at the gruff workspace root, sibling to this
crate). Rust intentionally keeps YAML-only config loading and Rust-specific
`custom_rules` / `exclude` sections.
