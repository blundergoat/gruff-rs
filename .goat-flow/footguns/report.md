---
category: report
last_reviewed: 2026-05-27
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


## Footgun: Digest Helpers That Pull From Registry Defaults Instead Of Findings

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED

When a digest helper (e.g. `summary::top_rule_digests` -> `build_rule_digest`) needs per-rule metadata like `severity`, `confidence`, or `pillar`, the registry default (`RuleDefinition.default_severity`) is the *wrong* source for any field the user can override at config time. The user's override applies to emitted findings via `config.severity(rule_id, default)` (search: `pub(crate) fn severity` in `src/config.rs`), but the digest helper reads from the registry and reports the pre-override value. JSON / text / `topRules[]` ends up showing severity X while the same findings carry severity Y, and counts grouped by severity (e.g. `summary.<severity>` totals) disagree with the per-rule digest.

Concrete instance from 2026-05-27 (PR #3): `build_rule_digest` (search: `fn build_rule_digest`) emitted `RuleDigest.severity = definition.default_severity` for the M03 summary v2 enrichment. A user-configured `rules.size.function-length: { threshold: 10, severity: advisory }` produced findings with `severity: advisory`, but `topRules[].severity` showed `warning` (the registry default for `size.function-length`). codex caught it post-commit on b837080.

The same trap exists for any future digest field sourced from `RuleDefinition.*` when the underlying property is configurable via `RuleSetting.*`. `confidence` is currently NOT user-configurable so pulling it from the registry is correct; `severity` (paired with `threshold`, per ADR-011) IS.

**How to apply:**

- For any per-rule digest field, ask: "is this configurable through `rules.<id>.*` in `.gruff-rs.yaml`?" If yes, source it from a representative finding (or `config.<field>(rule_id, default)`), not from `RuleDefinition.default_*`.
- The registry value is the right source ONLY for fields that are immutable at config time: `description`, `pillar` (built-in pillar is fixed), `default_enabled`, `kind` (Rust / Text / Project).
- When the report has findings for the rule, the most reliable source is the first matching finding's field — every finding for the same rule carries the same configured severity (resolved once at rule-emission time).
- Add a contract test that configures an override and asserts the digest matches: PR #3 review comment thread pinned this for `severity` via `summary_top_rules_severity_reflects_configured_override` (search: in `src/tests/scenarios/summary_enrichment.rs`).

Related: [[verification]] — "verify bot claims against current code before fixing" — covers the inverse, where a bot points at an already-fixed surface.

## Footgun: HashMap Iteration Leaks Into Deterministic Outputs

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED

`Config` (search: `pub(crate) struct Config` in `src/config.rs`) stores `rule_settings: HashMap<String, RuleSetting>` and `string_array_options: HashMap<String, Vec<String>>`. Iterating a `HashMap` in Rust produces **non-deterministic** order across runs (even on the same build). Any output that:
- gets compared in snapshot-style tests,
- is consumed by tools that diff two reports,
- is asserted on by CI / dogfood,

must NOT emit data straight from a HashMap iteration. The repo's reports are deterministic by contract, so HashMap iteration is a footgun every time it surfaces into reports / JSON / diagnostics.

Concrete instance from 2026-05-27 (PR #3, post-b837080 review): `excluded_security_rule_diagnostics` (search: `fn excluded_security_rule_diagnostics` in `src/analysis.rs`) iterated `config.rule_settings` directly and pushed `RunDiagnostic` entries into `report.diagnostics` in HashMap order. Two runs of the same scan with multiple excluded Security/SensitiveData rules emitted the diagnostics in different orders. Fixed by collecting `(rule_id, pillar)` pairs into a `Vec` and `sort_by_key(rule_id)` before constructing diagnostics.

**How to apply:**

- Any function that reads from `config.rule_settings` or `config.string_array_options` and emits output where order matters: collect intermediate keys, `sort` or `sort_by_key`, then iterate the sorted result.
- For dictionary-style state that is ORDER-relevant by design (e.g. `minimum_severity: BTreeMap<String, FailThreshold>`), use `BTreeMap` instead of `HashMap` at the type level. `BTreeMap` iteration is sorted by key.
- When converting a HashMap-sourced field into an output structure, prefer `.iter().collect::<BTreeMap<_, _>>()` over a manual sort if you want both dedup-by-key AND deterministic order.
- For Vec construction from HashMap: build the Vec, then `vec.sort_by_key(...)` — do not rely on HashMap iteration order to "happen to work" on small inputs.

Watch list (HashMap fields in `Config` whose iteration ever surfaces): `rule_settings` (covered above) and `string_array_options` (used by naming rules to merge allowlists — currently consumed via deterministic `string_array_option(rule_id, option)` getter, but flag it if a future change starts iterating the whole map).

## Footgun: Mutation-Step Ordering Decides Whether Deltas Match The Final Report

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED

`run_analysis_in_project` (search: `pub(crate) fn run_analysis_in_project` in `src/analysis.rs`) is a sequence of mutations on a `Vec<Finding>`. Each step (analyse → baseline → dedupe → exclusions → diff filter) reads the *current* state of the vector. Any step that records derived state (counts, deltas, summaries) on its way past captures a value that may be invalidated by a later step. If steps are reordered without re-checking what each one captures, those captured values drift away from the final report and silently lie to downstream consumers.

Concrete instance from 2026-05-27 (PR #3, post-b837080 review): the pipeline was `analyse → resolve_baseline → sort_and_dedupe`. `apply_baseline` computed `perRuleDeltas.introduced` by counting findings not matched by the baseline. Then `sort_and_dedupe_findings` (which exists precisely because raw rule emission can produce duplicate findings by `fingerprint`) collapsed duplicates. Result: `perRuleDeltas.introduced` over-counted by the number of duplicates dropped in the next step. codex caught it post-commit. Fixed by swapping `sort_and_dedupe_findings` ahead of `resolve_baseline`.

The same trap applies to any future step that derives per-rule / per-pillar / per-severity counts mid-pipeline: if `apply_report_exclusions` or a future suppression-policy step lands between the count and the final report, the count is stale.

**How to apply:**

- When introducing a new mid-pipeline aggregate, audit every step that runs after it. Each subsequent step that mutates `findings` is a potential drift source.
- Prefer computing aggregates AFTER all mutations are done — at `build_report` time, on the final findings list. Where that is not possible (because an earlier step is the only one with access to the right inputs — e.g. `apply_baseline` needs the baseline entries to compute `removed`), capture only what cannot be reconstructed later and recompute the rest at the end.
- Add a regression test that constructs the failure mode the ordering bug would produce. For the baseline-then-dedupe case, the failing input is "raw findings with duplicates by fingerprint + empty baseline"; the assertion is "introduced count equals final per-rule count". See `baseline_deltas_do_not_over_count_duplicate_findings` (search: in `src/tests/scenarios/baseline.rs`).
- When reading `run_analysis_in_project` in code review, treat the comment annotations on the dedupe/baseline order as load-bearing. They are documenting a constraint the code's structure cannot itself enforce.
