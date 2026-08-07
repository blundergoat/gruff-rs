---
category: research
last_reviewed: 2026-08-08
---

## Lesson: Count Study Findings Across Template Variants

**Created:** 2026-05-16
**What happened:** M24 initially counted only `Finding:` headings and missed the earlier Ruff and Biome `### Finding CODE` headings.
**Prevention:** For research synthesis, count both `^(### )?Finding[: ]` heading styles before claiming matrix coverage.

## Lesson: Promote Only Locally Verified Peer Features

**Created:** 2026-05-16
**What happened:** M22 and M23 invalidated tempting assumptions: RuboCop offense counts are TODO comments rather than enforced count baselines, and Reviewdog/rdjson was not observed in the local Semgrep or golangci-lint checkouts.
**Prevention:** Route plausible but unverified peer features to "Maybe" or leave them out until a local study file cites evidence.

## Lesson: Keep Copyleft Studies Concept Only

**Created:** 2026-05-16
**What happened:** Semgrep and golangci-lint are useful design references, but their LGPL/GPL licenses require concept-only extraction for this repository's implementation work.
**Prevention:** For copyleft neighbor analyzers, keep synthesis to prose, pseudocode, and behavior descriptions. Do not copy implementation code into gruff.
