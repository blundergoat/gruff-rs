# ADR-003: Local Gate And Config Policy

**Status:** Implemented
**Date:** 2026-05-13

## Decision

The default project config is `.gruff-rs.yaml`. Other gruff config names and non-YAML config files are intentionally unsupported before public release. Config validation is strict: unknown root keys, rule ids, option names, and unsupported value shapes are command errors. Thresholded rules use a single `threshold` plus one fixed `severity`; warning/error threshold maps are intentionally unsupported.

Local and CI verification use `bash scripts/check.sh`. The script runs formatting, Clippy, unit tests, `list-rules`, fixture scan, and self-scan diagnostics smoke checks. Self-scan diagnostics fail the gate; self-scan findings are allowed under `--fail-on none` until a baseline or score threshold policy is chosen.

## Context

The project needs a checked-in analyzer config shape that humans can copy and modify. Runtime measurements on 2026-05-13 showed the preflight script at about 2.10s and the proposed scanner-smoke bundle at about 1.93s after dependencies were built, so the scanner smokes are fast enough for the default local gate.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep JSON-only default config | Diverges from the intended project config workflow | Rejected; YAML is the default human-edited config. |
| Accept unknown config keys | Typos silently disable intended policy | Rejected; strict config failures are safer for gates. |
| Split scanner smokes into optional deep checks | Developers may skip scanner health checks | Rejected for now because measured runtime is still fast. |
| Fail on self-scan findings | Current analyzer work would block on accepted debt before baseline policy exists | Deferred; diagnostics fail, findings are visible but allowed. |

## Reversibility

The fast gate can be split into a deep mode if `bash scripts/check.sh` becomes slow enough to discourage use. Config compatibility changes can still add migration paths after a public release creates external users.
