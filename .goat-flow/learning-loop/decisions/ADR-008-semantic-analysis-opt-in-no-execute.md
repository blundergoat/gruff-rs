# ADR-008: Semantic Analysis Is Opt-In And No-Execute By Default

**Status:** Accepted
**Date:** 2026-05-16

## Decision

Gruff's default analysis remains data-only and no-execute: source text,
configuration files, `syn` ASTs, `Cargo.toml`, `Cargo.lock`, and ignore files
may be read as data, but ordinary analysis must not run Cargo, build scripts,
proc macros, package managers, hooks, external diff tools, or network access.

Future semantic or type-aware rules must declare their required phase and data
dependencies. If a semantic mode can be implemented from data-only inputs, it
may be considered for default analysis after calibration. If a semantic mode
requires rust-analyzer workspace loading, Cargo metadata execution, build
scripts, proc macros, or a large new dependency graph, it must be opt-in and
documented as a trusted-workspace mode before implementation.

Changing an existing rule from syntactic to semantic behavior is compatibility
sensitive because finding volume can change while rule ids and fingerprint
inputs remain the same. Such work needs a dedicated recalibration milestone and
tests. Prefer additive semantic rule variants or explicit mode gates when
default behavior would otherwise shift.

## Context

The M24 matrix records convergent semantic-boundary evidence from Biome, Clippy,
rust-analyzer, Detekt, and PMD:

- `.goat-flow/scratchpad/related-projects/biome/STUDY.md`
- `.goat-flow/scratchpad/related-projects/rust-clippy/STUDY.md`
- `.goat-flow/scratchpad/related-projects/rust-analyzer/STUDY.md`
- `.goat-flow/scratchpad/related-projects/detekt/STUDY.md`
- `.goat-flow/scratchpad/related-projects/pmd/STUDY.md`

rust-analyzer shows the clearest unlock path for type and path resolution, but
also shows dependency and workspace-loading costs that conflict with gruff's
safe-to-run-on-untrusted-source-trees invariant. Clippy, Biome, and Detekt show
that analyzers benefit from declaring phases rather than hiding semantic cost
behind rule names.

ADR-001 deliberately selected a `syn` source model and deferred compiler or
language-server integration until rules need semantic type information.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Load full semantic workspaces by default | Analysis can execute untrusted project code or become dependent on local tool state | Rejected for ordinary analysis. |
| Ban semantic analysis forever | Type-aware deferred rules have no path forward | Rejected; semantic modes are useful when explicit and calibrated. |
| Silently change existing rules to semantic behavior | Baseline and score drift becomes surprising | Rejected; semantic upgrades are compatibility-sensitive. |
| Keep default no-execute and make semantic phases explicit | Some advanced rules stay deferred longer | Accepted; it preserves safety and determinism. |

## Reversibility

This policy can be revisited if a future semantic provider proves deterministic,
data-only, and cheap enough for default analysis. Any reversal must preserve
the untrusted-tree safety invariant or create a separate trusted-workspace mode
with clear CLI/config naming and failure diagnostics.
