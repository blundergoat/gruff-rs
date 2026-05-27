---
category: report
last_reviewed: 2026-05-25
---

## Footgun: Per-Format Renderer Helpers Tend To Duplicate

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

`src/report.rs` (search: `pub(crate) fn pillar_label`) maps `Pillar` variants to canonical kebab-case strings used in JSON, HTML, Markdown, and text output. Before 0.1.2 this helper was duplicated as private `fn pillar_label` in `src/summary.rs`, `src/render/markdown.rs`, and `pub(crate) fn pillar_label` in `src/html_report/mod.rs` — three byte-identical 14-line match arms. PR #3 added the third copy as part of new format coverage; the duplication was invisible because each module compiled in isolation.

The trap is structural: each renderer module owns its own formatting, so the natural copy-paste move when adding a new format produces another duplicate. Adding a new `Pillar` variant then requires updating each copy by hand; drift is silent because a missed renderer keeps compiling (just falls through to a default-arm string).

`severity_text` (search: `pub(crate) fn severity_text` in `src/html_report/mod.rs`) is the next likely victim — currently only one consumer, but the same shape. Promote it to `src/report.rs` before a second renderer needs it.

**How to apply:**

- Helpers that map an enum variant defined in `src/report.rs` to a display string live in `src/report.rs` next to the enum, marked `pub(crate)`, imported by every consumer.
- Re-export at crate root via `use report::{... new_helper};` in `src/main.rs` so submodules can write `crate::new_helper`.
- When reviewing a new renderer module or `goat-review`-ing a diff, grep for `fn .*pillar.*Pillar.*->` / `fn .*severity.*Severity.*->` / `fn .*confidence.*Confidence.*->` shapes — they signal a duplication opportunity.

Pattern for the canonical-helper-next-to-enum approach: [[architecture]] in patterns/.

## Footgun: AnalysisReport Tree Silently Reshapes gruff.analysis.v1 JSON

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

`src/report.rs` (search: `pub(crate) struct AnalysisReport`) and every type reachable from it (`Summary`, `Finding`, `ScoreReport`, `PillarScore`, `FileScore`, `RunInfo`, `BaselineReport`, etc.) are `#[derive(Serialize)]`. The `--format json` renderer in `src/analysis.rs` (search: `schema_version: "gruff.analysis.v1"`) calls `serde_json::to_string_pretty(&report)` on the whole tree, so any new `pub(crate)` field on any struct in that tree lands in the v1 JSON output bytes.

Concrete instance from 2026-05-25 (PR #3): adding `pub(crate) penalty: f64` to `PillarScore` changed the v1 `score.pillars[]` shape from 3 fields (`pillar`, `score`, `findings`) to 4 (adding `penalty`). The PR shipped without flagging because there is no compiler signal — `src/scoring.rs` populated the field; the cascade through `ScoreReport → AnalysisReport → JSON` was invisible. CodeRabbit caught it as a P1 in review.

The non-obvious failure mode is that the struct may live in a module that *feels* internal (`src/scoring.rs` populates `PillarScore`, `src/baseline.rs` populates `BaselineReport`) but its serialized form is part of the v1 contract. The struct's `pub(crate)` visibility lies about its true blast radius.

**How to apply:**

- Before adding a field to any `pub(crate) struct` in `src/report.rs`, check whether the struct is reachable from `AnalysisReport` (directly, or transitively via `Vec`/`Option`/nested struct). If yes, the new field is part of the v1 JSON shape.
- The no-bc-ceremony rule for this codebase (see ../lessons/release.md) means the response is *not* to bump the schema version string. The response is to note the shape change factually in the changelog (`Analysis JSON gains <field>` rather than `unchanged`). The agent doing the field addition is the only one who can spot the cascade.
- Tests asserting on field-set equality (e.g. `src/tests/renderers/output.rs` search: `summary_json_pillar_shape_includes_canonical_fields_with_penalty`) catch additions only inside the *tested* struct. New fields on untested structs pass silently — add a contract test alongside the struct change.
