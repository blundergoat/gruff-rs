# ADR-004: Git Ignore Aware Discovery Policy

**Status:** Accepted
**Date:** 2026-05-16

## Decision

Default project discovery will honour Git ignore rules. Paths excluded by those
rules are skipped during ordinary analysis unless the operator explicitly opts
into ignored-path scanning.

This policy is layered with gruff's own config: Git ignore rules describe local
workspace exclusion, while `.gruff.yaml` `paths.ignore` remains the analyzer's
project-specific exclusion policy. Explicit input paths and `--include-ignored`
must have documented precedence so operators can intentionally inspect excluded
content when needed.

## Context

The analyzer should scan the committed project surface by default, including
workflow, hook, config, instruction, and project-memory text that may carry
security-sensitive content. Broad path exclusions are too blunt because they can
hide committed operational surfaces from sensitive-data and security checks.

At the same time, default traversal should not report on local workspace byproducts
that Git already excludes from the repository. Reading ignore rules as data keeps
discovery deterministic and safe for untrusted source trees; ordinary analysis
must not execute Git hooks, build scripts, package managers, or network access.

ADR-003 keeps self-scan findings visible under `--fail-on none`, and ADR-002
makes finding identity a compatibility contract. Git-aware discovery must preserve
those contracts unless a later compatibility decision explicitly changes them.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep only hard-coded default directory skips | Local exclusions drift from repository policy | Rejected; Git ignore rules are the source of truth for workspace-local exclusions. |
| Add broad analyzer path ignores for operational directories | Security and sensitive-data checks lose committed surface area | Rejected; quality noise should be calibrated by rule or config policy, not by hiding whole committed surfaces. |
| Execute Git commands during discovery | Analysis becomes less safe for untrusted trees and can depend on local tool state | Rejected; discovery should read ignore files as data. |
| Honour Git ignore rules by default with an explicit opt-in override | Default scans match repository intent while still allowing deliberate local inspection | Accepted. |

## Reversibility

This is a two-way-door policy. It can be revisited if reading ignore rules proves
too slow, ambiguous across platforms, or incompatible with selected workspace
layouts. Any reversal must preserve security visibility for committed text/config
surfaces and must document how operators exclude local-only paths without hiding
committed review surfaces.
