# Changelog

## v0.5.0 - 2026-08-16

0.5.0 is a precision, security, and contract-honesty release. Rule families retune against real Rust idiom and measured corpus noise, and size and security rules judge substantive code. Reports carry markers instead of secret or PHI payloads, the action moves to `argv` with a pinned and verified install, and the agent harness moves to goat-flow 1.15.1 with this repository's local security repairs checked in and gated.

- **`security.process-command` requires standard-library provenance.** Third-party `Command` types, shadowed imports, and comment examples stay quiet.
  - It resolves file, module, function, and nested-block imports before accepting bare `Command` or `process::Command`.
  - Clap falls from 1,265 findings to 4, so baselines shrink sharply where another crate owns `Command`.
- **GitHub `uses:` findings follow step structure.** Unpinned-action checks read only `jobs.<job>.steps` and `runs.steps`, not a nested `with` value.
- **Release setup rejects identities without published archives.** The action accepts only core `X.Y.Z` versions.
  - Dependency setup stops before archive handling when actionlint's SHA-256 verification fails.
- **`test-quality.unwrap-in-test` is off by default.** It stays available at Advisory severity, described in generated configs as a style preference.
  - Clean-corpus scans found 43 findings in `json`, 622 in clap, and 773 in tokio, sampled as fail-fast setup whose values were later asserted.
  - Baselines lose these findings unless a project enables the rule.
- **`naming.short-variable` skips narrow Rust idioms.** Loop and closure bindings, and `cx` parameters typed `*Context`, no longer report.
  - Findings fall 124 to 113 on `json`, 1,584 to 881 on tokio, and 3,793 to 1,250 on rust-clippy; baselines can drop the retired ones.
- **Agent harness upgraded to goat-flow 1.15.1.** The four agent surfaces, the shared skill docs, and the managed hooks move to the 1.15.1 templates.
  - 1.15.1 adds the `goat-flow.hook-result.v1` launcher runtime and the bounded `hooks verify` scenarios.
  - It absorbed this repo's fail-closed exit-2, Bash 3 header-content, and oversized-file repairs, so those local hotfixes are retired.
- **The `goat-flow-allow-secret` marker survives the upgrade.** Both scan paths honour it again, after CR stripping so a Windows-edited marker counts.
  - The marker has no upstream equivalent, so adopting 1.15.1 wholesale would block every turn touching `fixtures/sample.rs`.
- **The allow marker exempts secrets only.** `is_line_allowlisted` recognises `goat-flow-allow-secret` and nothing else, not `gitleaks:allow`.
  - `pragma: allowlist secret` and its kin are routine annotations elsewhere in a tree, read as tooling noise rather than a claim about this hook.
  - The check runs after merge-conflict detection on both paths, so a conflict marker carrying the comment still blocks the turn.
- **Unreadable changed files block the turn instead of passing as clean.** The scan reports `scan incomplete` and names each path it could not read.
  - Padding a credential-bearing file past 1 MiB previously ended the turn with exit 0 and no output on both dispatch paths.
  - An oversized blob that exists only in the index is scanned rather than skipped.
  - Binary changed paths hold no text hunks and block for the same reason; in 0.4.0 they passed as clean.
- **Preflight names skipped checks in its success line.** The line quoted as gate evidence carries the skip count, so green cannot mean full coverage.
- **Permission-rule hygiene and local hook repairs are gated.** `scripts/preflight-checks.sh` fails when a permission pair or a hook repair is lost.
  - A secret path that loses its paired `Read` and `Edit` denies fails, as does a never-matched rule form under `permissions`.
  - So does a goat-flow install or sync that reverts one of the six anchored security repairs across four managed hook files.
  - Each anchor row records what breaks without the fix; the hook files are tracked, so `git checkout <rev> -- .goat-flow/hooks/` restores a revert.
  - A parallel patch archive is not kept: it duplicated git and went stale against every goat-flow upgrade.
- **Managed skill-doc repairs are gated too.** Preflight (search: `MANAGED_DOC_DELTAS`) asserts two local repairs to the gruff analyzer playbook.
  - Its availability probe checks the repo-local `bin/<target>` wrapper first, so the probe no longer reports gruff unavailable inside gruff-rs.
  - Its threshold guidance sends the reader to `analyse --help` instead of naming a `--min-severity` flag this port does not expose.
- **`.goat-flow/security-policy.md` states this repository's boundaries.** Each entry names the architecture section, ADR, or footgun that decides it.
  - It records the absent auth layer, the loopback dashboard boundary, and the release supply-chain boundary.
  - It records the fixture secret class, the no-execute posture and its `--diff-git-unsafe` exception, and the deny hook's heredoc limitation.
- **Codex denies every non-sample env-file variant.** The workspace profile denies `**/.env*` for direct file tools and reopens only `.env.example`.
  - That closes suffix gaps such as `.env.backup` that the Bash hook could not cover for direct reads.
- **Claude denies every non-sample env-file variant too.** Paired `Read(**/.env*)` and `Edit(**/.env*)` denies refuse `.env.qa` and `.env.bak`.
  - The enumerated upstream entries are kept rather than collapsed, so a `goat-flow install` still finds every rule it expects.
- **Claude permission wording matches current tool semantics.** An `Edit` deny covers every file-writing tool, so `Read` and `Edit` pairs suffice.
  - `Write`, `MultiEdit`, `NotebookEdit`, and `Glob` path rules are never matched and would read as protection that does not exist.
- **Native Windows action paths.** `working-directory` and `output-file` accept a drive root such as `D:\a\repo\repo\crate` or a UNC share.
  - The action converts them and `GITHUB_WORKSPACE` to one notation before comparing, so containment still fails closed.
  - A drive-relative value such as `C:crate` is rejected rather than guessed.
- **FROM-less `SELECT` templates stay visible.** `security.sql-dynamic-query` matches an all-interpolated `SELECT` with no `FROM`, but not prose.
  - PostgreSQL and SQLite both accept that form.
- **Unused private functions report whether or not they are generic.** `fn helper<T>(..)` counted as one of its own references and went unreported.
  - `dead-code.unused-private-function` subtracts a function's own declaration, but the pattern required `fn name(`, so no generic form matched.
  - Generic dead code was previously reported only by the lower-confidence `-candidate` rule.
  - Counts rise: clap 16 to 17, diesel 65 to 68, rust-clippy 3,293 to 3,614; tokio and ripgrep are unchanged.
  - Every sampled new finding was a genuinely uncalled function, one already carrying clap's own `#[allow(unused)]`.
- **API-key detection no longer fires on hyphenated prose.** The bare `sk-` arm had no left boundary, so `risk-of-script-injections` matched.
  - Every `sensitive-data.api-key-pattern` alternative is a vendor prefix; a scan of ten Rust projects produced one finding, the false positive.
  - Vendor-prefixed keys are still reported wherever they appear as their own token.
- **Annotated deserialization sinks report.** `security.unsafe-deserialization` matched only the bare call, not `serde_yaml::from_str::<Config>(..)`.
  - All four sink families were affected; nested generics such as `::<Vec<String>>` are consumed whole, and `serde_json` stays out of scope by design.
- **Split download-to-shell pipelines report.** A `curl` and its `bash` on separate block-scalar lines are joined; a trailing `||` ends the join.
- **Stop-hook scan bypass closed on both dispatch paths.** An added line whose own text starts with `++` is no longer skipped as a file header.
  - A `+++ ` line counts as a header only directly after a `diff --git` section start, so only a real hunk header is skipped.
  - goat-flow 1.15.1 reopened this on its Bash 4+ diff walk, so a credential there ended the turn with exit 0 while the Bash 3 fallback still blocked.
- **Release reruns fail closed on an existing draft.** The workflow contract rejects `--clobber`, release deletion, and existence-probe gating.
  - The policy is deliberate: a rerun does not reconcile, repair, or replace a draft that already exists.
- **file-length: 1000 substantive lines at error (family ratification).** Blank and comment-only lines are free, replacing the 600-line warning.
- **Zero-payload sensitive metadata markers.** JSON, SARIF, and hook findings serialize detector-owned markers instead of secret or PHI previews.
- **Narrower lock-across-await signal.** I/O and domain `.read()`/`.write()` no longer read as guards; zero-arg calls need local lock evidence.
- **SQL-shaped dynamic-query warnings.** Prose and non-SQL DSL text with isolated SQL words stay quiet; `query`/`execute` coverage remains.
  - A sentence that opens with a statement verb and later reaches its partner keyword, such as `Select the note from the archive`, reads as prose.
- **Wrapper normalisation no longer stops at an unknown option.** `watch` and `parallel` skip options they do not recognise, matching `xargs`.
  - A single unfamiliar flag can no longer hide a destructive, secret, or repository-write payload from the deny hook.
- **Action metadata keys are not executable steps.** `run:` is read structurally like `uses:`, so a top-level `run` input is not scanned as shell.
- **Risk-based network-security test scans.** Executable Rust tests keep bind-all and SSRF findings; scoped mitigations replace blanket suppression.
- **Block rustdoc and function-length precision.** Doc rules accept outer `/** */` comments; `size.function-length` excludes rustdoc and attributes.
- **Structured composite-action arguments.** The action accepts newline-delimited `argv`, rejects legacy `args`, and contains paths in the workspace.
- **Explicit composite-action security coverage.** Supplied `action.yml` files now get event-interpolation, remote-shell, and full-SHA checks.
- **Inert Markdown finding fields.** Rule IDs and paths use safe code spans and messages escape as text, so untrusted values cannot inject markup.
- **SAFETY rationales follow Rust comment conventions.** `security.unsafe-block` matches `SAFETY:`, `Safety:`, and `safety:`.
  - It ignores `unsafe` text inside comments, and punctuated forms such as `SAFETY: same-thread access` no longer trip `docs.weak-safety-rationale`.
  - A bounded multiline comment prelude is joined without crossing executable code.
  - Tokio's findings fall from 704 to 493, so affected baselines can remove 211 retired findings.
- **Exact, verified composite-action install.** The action pins an exact binary version, verifies the SHA-256 sidecar and archive members.
- **Verified five-platform release candidates.** A non-publishing workflow binds commit and package to Linux, macOS, and Windows archives.
- **Pinned, least-privilege release execution.** Workflows pin full SHAs and exact tool versions, and grant write only for final publication.
- **Accurate secret-preview suppression guidance.** Mitigations name the accepted `allowlists.secretPreviews` key; `secret_previews` stays rejected.
- **Visible accepted-abbreviation contract.** `gruff-rs init` explains that `allowlists.acceptedAbbreviations` replaces the built-in list.
- **Validated rule relationships.** Registries reject related-rule links that do not resolve, and `security.process-command` links to a shipped rule.
- **Exact documentation drift checks.** Preflight derives rule and pillar counts plus release examples from the catalogue and Cargo metadata.

## v0.4.0 - 2026-06-14

0.4.0 is a precision, correctness, and runtime-efficiency release for hook-facing scans. It keeps the report schema stable, makes partial-context analysis safer, tightens high-noise rules found by external scans, and retires two default rubrics that could not be made precise enough for agent hooks.

- **Partial-context dead-code safety.** Project-level dead-code findings are held back when a scan doesn't cover the whole Rust tree; a diagnostic points to a full scan.
- **Sharper security and secret rules.** Dynamic SQL findings now require a real SQL keyword; high-entropy checks skip inert text (integrity hashes, base64 alphabets, slugs, model IDs) but still flag real secrets.
- **Hook and Rust-pipeline efficiency.** Hook diff analysis avoids duplicate work, batched Git export cuts overhead, and rule dispatch skips disabled families sooner.
- **Non-UTF-8 text robustness.** Broad scans skip invalid (non-UTF-8) text with a diagnostic instead of failing; named and security-relevant files stay visible.
- **External-scan false-positive fixes.** Dead-code skips exported/plugin/allowed items; path-traversal needs filesystem-join evidence and honors sanitizers; lock-across-await ignores immediate extraction.
- **Removed two noisy default rules:** `modernisation.public-field` and `test-quality.no-assertions`. Public contract fields and harness-style tests need design intent the analyzer can't reliably guess.
- **Kept `security.path-traversal-candidate` on by default.** A review found no reason to weaken it; wording or metadata may still change without cutting coverage.
- **Rule catalogue 87 → 85.** The two retired IDs are gone from `list-rules`, config, docs, and output; schema versions and finding identities are unchanged.

## v0.3.0 - 2026-06-09

0.3.0 makes gruff easier to adopt and sharpens its rules: a new `hook` command that speaks the cross-analyzer `gruff.hook.v1` contract, tri-state baselines, count-based gates, a "fail-on-new" mode, eleven new security/secret rules, and four low-value rubrics dropped. JSON stays additive; new gates are opt-in.

- **New `hook` command.** `gruff-rs hook --format json` emits the cross-analyzer `gruff.hook.v1` contract — render-ready findings (`file`, `scope`, `stableIdentity`, non-null `remediation`, `metadata`) plus `suppressed.count`, `ignored.paths`, and `config`; `--capabilities` advertises support.
- **Changed-region hook fairness.** `line`/`symbol` findings stay scoped to changed ranges; `file`/`project` findings are dropped and counted in `suppressed.count` instead of leaking via synthetic anchors.
- **Native new-only hook.** `hook --baseline`/`--diff <ref>` surface only findings new vs. the base, with count-based suppression so a newly added duplicate still shows. `--diff` runs Git, so it needs the hidden `--diff-git-unsafe` opt-in (per ADR-019).
- **Additive finding enrichment.** Findings gain `scope`; threshold rules emit `metadata.measured`/`threshold`/`unit`/`direction`. File/project stable identities are value-independent; fingerprints and baselines unchanged.
- **Changed-region scoping for `analyse`.** Limit findings to changed lines via `--diff-patch`/`--changed-ranges` (no Git) or `--since`/`--diff` (Git, needs `--diff-git-unsafe`).
- **`paths.ignore` applies everywhere** — the walk, explicit file args, and diff modes — so a hook can't flag a deliberately-ignored file.
- **New `check-ignore` command.** Reports whether gruff would ignore a path and why, matching `git check-ignore` exit codes.
- **Tri-state baselines.** Findings are labelled `new`/`unchanged`/`resolved`; the default list is unchanged.
- **Count-based gates + `--fail-on-new`.** A `gate:` block caps findings by count (e.g. "10 warnings, no errors"); `--fail-on-new` gates only on findings new since the baseline.
- **Nine new security rules** — five GitHub Actions checks plus SSRF, unsafe-deserialization, XXE, and template/XSS; `severity:` overrides now apply to security/dependency rules.
- **Two new secret checks** — `phi-pattern` (health IDs) and `gcp-service-account-key`, with wider token coverage. Output stays redacted.
- **Removed four low-value rubrics:** `complexity.npath`, `metrics.halstead-volume`, `metrics.maintainability-pressure`, and `design.god-function`.
- **Sharper, quieter rules** — dead-code now flags unused private `const`s/`static`s/type aliases (skipping cfg/test/trait-impl); complexity ignores comments and `?`; `parameter-count` 5 → 7.
- **Rule catalogue 80 → 87** (four removed, eleven added); `waste.unnecessary-clone-candidate` ships disabled. Schemas, rule IDs, and fingerprints unchanged.
- **JSON `file` alias.** `analyse --format json` emits canonical `findings[].file` (and `score.topOffenders[].file`) alongside the deprecated `filePath`.

## v0.2.0 - 2026-05-28

The first `0.2.x` release: cross-port ergonomics plus schema and CLI-default changes held for a major bump. See `UPGRADING.md` to migrate from 0.1.x.

- **Breaking: `analyse --fail-on` now defaults to `advisory`** (was `error`) - restore with `--fail-on error` or `minimumSeverity.analyse: error`.
- **Breaking: `.gruff-rs.yaml` requires `schemaVersion: gruff-rs.config.v1`** - configs without it are rejected; `init --force` adds it.
- **Breaking: JSON schemas bumped to v2** (`gruff.analysis.v2`, `gruff.summary.v2`) with additive fields; v1 carries forward, baseline and SARIF unchanged.
- **Per-rule scoring opt-out** - `excludeFromScore: true` keeps a rule's findings visible but drops its score penalty.
- **Per-rule deltas in baseline/diff scans** - reports show top improved/regressed rules; JSON adds `perRuleDeltas[]`.
- **`list-rules <rule_id>` detail card** - defaults, options, escape hatches, false-positive shapes, and related rules.
- **`stableIdentity` on every finding** - a line-insensitive hash so external diff tools match findings across edits; `fingerprint` stays line-sensitive.
- **Per-subcommand `--fail-on` defaults** via a `minimumSeverity:` block for `analyse` and `report`.
- **Richer summary JSON** - `pillars[]` carries nine fields for every pillar; `topRules[]` gains severity, confidence, and a description.
- **Markdown and HTML reports gain a pillars table** - seven columns; HTML drops its card grid for it.
- **Triage hint** - text scans past 50 findings point at `summary --top 20`.
- **Escape-hatch hints in eleven remediations** - each names the relevant `.gruff-rs.yaml` knob.
- **`docs.missing-*` reworded for agents** - ask for a brief intent line, not a stub doc comment.
- **Default `accepted_abbreviations` grows 6 → 16.** Upgrade note: the loader replaces (not merges) the list, so run `init --force` to pick up the new ones.
- **Twelve rules ship false-positive metadata** (`false_positive_shapes`, `related_rules`).
- **Determinism and correctness fixes** - stable diagnostic ordering, finding-sourced summary severity, and de-duplicated baseline deltas.
- **Internal refactors** - shared single sources for pillar labels/digests; v2 shape aligns with the `gruff-go`/`-ts`/`-py`/`-php` ports.

## v0.1.1 - 2026-05-24

Ten new default-on rules, the `gruff-rs init` scaffold, broader `paths.ignore` defaults, and split-out docs.

- **Ten new default-on rules** (67 → 77) - four `modernisation.*` lints, four `docs.missing-*` rules, `security.path-traversal-candidate`, and `test-quality.should-panic-without-expected`.
- **`gruff-rs init` scaffold** - writes a default `.gruff-rs.yaml`, preserving custom `paths.ignore`.
- **`security.path-traversal-candidate` precision guards** - six guards (typed-path args, validate-then-trust, sanitizer calls, …) cut false positives.
- **`modernisation.manual-contains` tightened** - matches only deref/RHS-ref shapes; bare `|x| x == y` is skipped.
- **`docs.missing-param-doc`/`-return-doc` skip bridge functions** - `#[tauri::command]`, `#[wasm_bindgen]`, `#[pyfunction]`, etc.
- **Broader `paths.ignore` defaults** - skips agent/CLI dirs (`.claude/`, `.codex/`, `.goat-flow/`, …) and lockfiles.
- **CLI and dependency tooling** - a `--baseline` path option and `dependency-{install,update}.sh` that auto-install `cargo-audit`.
- **Documentation pages** - separate guides for CI, config, the dashboard, output formats, and releases.
- **Calibration matrix 77/77 and internal refactors** - every rule has positive/negative cases (dogfood 100/A); rule files split for size, helpers renamed to predicate form.

## v0.1.0 - 2026-05-23

First public release. Deterministic, schema-versioned quality analyzer for Rust projects; single-binary CLI you can drop into CI.

- **Commands** - `analyse`, `report`, `summary`, `list-rules`, `dashboard`, `completion`.
- **Output formats** - text, JSON (`gruff.analysis.v1`), SARIF 2.1.0, HTML, Markdown, GitHub annotations, hotspot.
- **Default-on rules across eleven pillars** - complexity, dead-code, design, documentation, maintainability, modernisation, naming, security, sensitive-data, size, test-quality.
- **`.gruff-rs.yaml` config** - selectors, thresholds, allowlists, custom regex rules, and report-level exclusions.
- **Baselines and patch-diff filtering** - for incremental adoption against an existing codebase.
