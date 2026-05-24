# Configuration

gruff-rs reads YAML configuration and applies it before rule analysis.

## Discovery

Default discovery checks the project root for `.gruff-rs.yaml`.

Use `--config <path>` to load a specific YAML file, or `--no-config` to run
with built-in defaults. Explicit `.json` config paths are rejected; use YAML.

## Root Keys

Supported top-level sections are:

- `paths`
- `allowlists`
- `rules`
- `custom_rules`
- `exclude`

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

The shared cross-language config expectations are documented in
[`../../CONTRACT.md`](../../CONTRACT.md). Rust intentionally keeps YAML-only
config loading and Rust-specific `custom_rules` / `exclude` sections.
