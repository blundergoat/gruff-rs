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

## Compatibility

The shared cross-language config expectations are documented in the
workspace-level `CONTRACT.md` (at the gruff workspace root, sibling to this
crate). Rust intentionally keeps YAML-only config loading and Rust-specific
`custom_rules` / `exclude` sections.
