---
category: release
last_reviewed: 2026-10-03
---

## Lesson: Don't Write Backwards-Compatibility Ceremony For gruff-rs

**Created:** 2026-05-25

**Review note (2026-10-03):** The reassessment trigger at the end of "How to apply" appears to have fired. The repository now ships `UPGRADING.md` (search: `follows SemVer`), which commits rule IDs and the other surfaces it lists to stability across a release line. Where this lesson and `UPGRADING.md` disagree, for example on bumping schema versions by feel or having no deprecation policy, follow `UPGRADING.md` and ask the user before applying the no-ceremony rule to a surface it lists as stable. The guidance against hedging and migration-guide padding in changelog prose still applies.

When writing CHANGELOG entries, schema-version notes, code comments, or PR descriptions for gruff-rs, do not add migration ceremony, deprecation notices, "downstream consumers must update" warnings, "compatibility-sensitive" framing, or `_v1` shims. gruff-rs has no external users — the only consumer is the user themselves across their own gruff-* language ports (`gruff-go`, `gruff-ts`, `gruff-py`, `gruff-php`). Hedging language is dead weight.

**Concrete example (this repo, 2026-05-25):** The first draft of the 0.1.2 CHANGELOG entry led the Changed section with `**Schema-version bump (compatibility-sensitive):**` and ended it with `Downstream consumers that key on the summary schemaVersion string, assert on the pillar field set, or rely on the prior pillar order need to update.` The user pushed back: "back sure there's no legacy/backwards compatible changes, because no-one is using this instead of me - do u know what i mean?" The rewrite dropped the hedging, the migration block, and the `v1 shape carried only N fields` comparison, leaving plain factual statements (`Summary JSON schemaVersion moves from gruff.summary.v1 to gruff.summary.v2`; `Analysis JSON score.pillars[] entries gain a penalty: f64`).

**Why:** The user said directly: "no-one is using this instead of me." Time spent writing migration ceremony is time taken from describing the actual change. The natural agent default (treat any schema bump as a compatibility event for an external audience) is wrong here; there is no external audience.

**How to apply:**

- Changelogs: describe what changed plainly. Drop "compatibility-sensitive", "downstream consumers", "v1 shape carried only N", "additive only" phrases.
- Code: when changing schemas, output formats, CLI flags, or rule IDs, rewrite cleanly. Don't preserve `_v1` shims, alias-rename, or carry deprecation cycles.
- Schemas: bump (or don't) the version string by feel. There is no formal deprecation policy and no external migration audience. See ../footguns/report.md "AnalysisReport Tree Silently Reshapes gruff.analysis.v2 JSON" for what to note vs. bump.
- Still note shape changes for the user's own situational awareness, but as one factual line ("Analysis JSON gains X") — not a migration guide.
- Reassess when the user mentions external integrations, third-party consumers, or publishes the cross-port ports for outside use — that's when this rule needs revisiting.

This lesson is the durable form of the rule that cross-agent and cross-session work reads; no separate memory file carries it.
