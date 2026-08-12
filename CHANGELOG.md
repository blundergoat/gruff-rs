# Changelog

## v0.5.0 - 2026-08-12

0.5.0 is a precision, security, and contract-honesty release. Rule families retune against real Rust idiom and measured corpus noise, size and security rules judge substantive code, reports carry markers instead of secret or PHI payloads, the action moves to `argv` with a pinned and verified install, and the agent harness moves to goat-flow 1.15.1 with this repository's local security repairs checked in and gated.

- **Process-command findings require lexical standard-library provenance.** `security.process-command` resolves file, module, function, and nested-block imports before accepting bare `Command` or `process::Command`. Same-named third-party builders, shadowed imports, unimported names, and comment-only examples stay silent. Clap's measured findings fall from 1,265 to 4, so existing baselines can shrink sharply in projects that use another crate's `Command` type.
- **GitHub `uses:` findings follow step structure.** The unpinned-action rule inspects only direct dependencies under workflow `jobs.<job>.steps` or composite-action `runs.steps`; inputs and nested `with` values named `uses` no longer produce security findings.
- **Release setup rejects identities without published archives.** The composite action accepts only core `X.Y.Z` release versions, and dependency setup stops before archive handling when actionlint's SHA-256 verification fails.
- **Test unwraps are opt-in.** `test-quality.unwrap-in-test` remains available at Advisory severity but is disabled by default. Clean-corpus scans found 43 findings in `json`, 622 in clap, and 773 in tokio; sampled findings covered idiomatic fail-fast setup whose values were subsequently asserted. Generated configs describe the rule as a style preference. Existing baselines may lose these findings unless a project explicitly enables it.
- **Short-variable checks skip narrow Rust idioms.** `naming.short-variable` still uses the ratified `acceptedAbbreviations` list, but no longer reports loop or closure bindings, or `cx` parameters whose type ends in `Context`. Findings fell from 124 to 113 on `json`, 1,584 to 881 on tokio, and 3,793 to 1,250 on rust-clippy. Existing baselines can remove the retired findings.
- **goat-flow harness upgraded to 1.15.1.** The four agent surfaces, the shared skill docs, and the managed hooks move to the 1.15.1 templates, which add the `goat-flow.hook-result.v1` launcher runtime (`hook-launch-runtime.mjs`, `hook-provider-adapters.mjs`) and the bounded `hooks verify` scenarios; 1.15.1 absorbed this repo's earlier fail-closed exit-2 repair, its Bash 3 header-shaped-content repair, and its oversized-file blocking, so those local hotfixes are retired.
- **The line-scoped `goat-flow-allow-secret` marker survives the upgrade.** The marker is this repo's own addition and has no upstream equivalent, so adopting the 1.15.1 hook wholesale would have made every turn touching `fixtures/sample.rs` block on a calibration token the repository is required to keep; both scan paths honour it again, after CR stripping so a Windows-edited marker still counts.
- **Oversized and binary changed files block the turn instead of passing as clean.** The post-turn safety hook counted a changed file above the byte cap as scanned, so padding a credential-bearing file past 1 MiB ended the turn with exit 0 and no output on both dispatch paths. Content the scan cannot read now reports `scan incomplete` and names each unread path, and an oversized blob that exists only in the index is scanned rather than skipped. Binary changed paths hold no text hunks and block for the same reason, which is a change from 0.4.0, where they passed as clean.
- **Preflight names skipped checks in its success line.** The single literal line quoted as gate evidence reports the skip count when an optional check did not run, so a green result cannot be mistaken for full coverage.
- **Permission-rule hygiene and local hook repairs are gated.** `scripts/preflight-checks.sh` fails when a secret path loses its paired `Read` and `Edit` denies, when a never-matched rule form appears in `permissions`, or when a goat-flow install or sync reverts one of the three security repairs this repository carries on top of the managed hook templates; the repairs are checked in under `.goat-flow/hooks/local-deltas/`.
- **Codex denies every non-sample env-file variant.** Its workspace profile now denies `**/.env*` for direct file tools and reopens only `.env.example`, closing suffix gaps such as `.env.backup` that the Bash hook could not cover for direct reads.
- **Claude permission wording matches current tool semantics.** Claude applies each `Edit` deny to every built-in tool that edits files, so the settings retain paired `Read` and `Edit` controls without claiming that a separate uncovered `Write` path exists. `Write`, `MultiEdit`, `NotebookEdit`, and `Glob` path rules are never matched and would read as protection that does not exist.
- **Native Windows action paths.** `working-directory` and `output-file` accept a drive root such as `D:\a\repo\repo\crate` or a UNC share on Windows runners. The action converts them and `GITHUB_WORKSPACE` to one notation before comparing, so containment still fails closed; drive-relative values such as `C:crate` are rejected rather than guessed.
- **FROM-less `SELECT` templates stay visible.** `security.sql-dynamic-query` recognises an all-interpolated `SELECT` with no `FROM`, which is valid in PostgreSQL and SQLite, without matching prose.
- **Split download-to-shell pipelines report.** `security.github-actions-remote-shell` carries an unfinished pipeline across block-scalar lines, so a `curl` and its `bash` on separate lines are caught; a trailing `||` fallback ends the join.
- **Stop-hook scan bypass closed on both dispatch paths.** The post-turn safety hook no longer skips an added line whose own text starts with `++`; a `+++ ` line counts as a file header only directly after a `diff --git` section start. goat-flow 1.15.1 reopened this on its optimized Bash 4+ diff walk, which dropped any candidate line beginning `+++` regardless of position, so a credential on such a line ended the turn with exit 0 while the Bash 3 fallback still blocked. Only a real hunk header is skipped there now.
- **Release reruns fail closed on an existing draft.** The release-workflow contract now rejects `--clobber`, release deletion, and gating draft creation on an existence probe, pinning the deliberate no-reconciliation policy.
- **file-length: 1000 substantive lines at error (family ratification).** Blank and comment-only lines are free, replacing the 600-line warning.
- **Zero-payload sensitive metadata markers.** JSON, SARIF, and hook findings serialize detector-owned markers instead of secret or PHI previews.
- **Narrower lock-across-await signal.** I/O and domain `.read()`/`.write()` no longer read as guards; zero-arg calls need local lock evidence.
- **SQL-shaped dynamic-query warnings.** Prose and non-SQL DSL text with isolated SQL words stay quiet; `query`/`execute` coverage remains. A sentence that merely opens with a statement verb and later reaches its partner keyword, such as `Select the note from the archive about {topic}`, is read as prose rather than a query.
- **Wrapper normalisation no longer stops at an unknown option.** `watch` and `parallel` skip options they do not recognise instead of abandoning normalisation, matching `xargs`, so a single unfamiliar flag can no longer hide a destructive, secret, or repository-write payload from the deny hook.
- **Action metadata keys are not executable steps.** `run:` is interpreted structurally like `uses:`, so a top-level input named `run` no longer has its `description` and `default` text scanned as shell for remote-download and event-interpolation findings.
- **Risk-based network-security test scans.** Executable Rust tests keep bind-all and SSRF findings; scoped mitigations replace blanket suppression.
- **Block rustdoc and function-length precision.** Doc rules accept outer `/** */` comments; `size.function-length` excludes rustdoc and attributes.
- **Structured composite-action arguments.** The action accepts newline-delimited `argv`, rejects legacy `args`, and contains paths in the workspace.
- **Explicit composite-action security coverage.** Supplied `action.yml` files now get event-interpolation, remote-shell, and full-SHA checks.
- **Inert Markdown finding fields.** Rule IDs and paths use safe code spans and messages escape as text, so untrusted values cannot inject markup.
- **SAFETY rationales follow Rust comment conventions.** `security.unsafe-block` matches `SAFETY:`, `Safety:`, and `safety:`, accepts punctuated forms such as `SAFETY: same-thread access` without tripping `docs.weak-safety-rationale`, joins a bounded multiline comment prelude without crossing executable code, and ignores `unsafe` text inside comments. Tokio's measured findings fall from 704 to 493, so affected baselines can remove 211 retired findings.
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
