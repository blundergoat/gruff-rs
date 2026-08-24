# Changelog

## Unreleased

- **Heuristic rules explain exceptions.** Flat `list-rules` JSON now publishes reviewed false-positive shapes and mitigations for every medium- and low-confidence built-in rule; focused rule detail uses the same catalogue records.
- **BREAKING: default scans use the family fallback policy.** Non-VCS fallbacks now defer to any governing `.gitignore`, match at any depth, committed control metadata stays scannable, and explicit supported files bypass Git and fallback exclusions. Rust retains `target`; VCS internals remain blocked even with `--include-ignored`.
- **Bounded deep scans retain safety coverage.** Rust sources above 20,000 lines or 2,000,000 bytes remain analysed by size and sensitive-data rules while AST, masking, block parsing, and other deep work is omitted. `deepScanBudget` is configurable, `--deep-scan-budget LINES:BYTES|off` wins on every scan surface, and a non-fatal `bounded-deep-scan` diagnostic publishes both counts, both limits, and override provenance in every supported output.
- **New `sensitiveExclusions` config section.** A reviewed sensitive-data finding can now be suppressed by naming one exact `sensitive-data.*` rule id, one project-relative path, an optional symbol, and a required reason. It is the only way to suppress a sensitive-data finding, and it is deliberately separate from `exclude`: the section accepts no `message_contains`, `value`, or `preview` key, so a suppression can never be written in terms of the matched secret. Entries are authored by hand; no reported marker or preview is ever converted into one.
- **Sensitive exclusions fail closed on bad configuration.** A wildcard, glob, or pillar selector in `rule`, an unknown rule id, a rule outside the sensitive-data pillar, an absolute or `..`-bearing or globbed `path`, any unsupported key, a missing or whitespace-only `reason`, and a second entry claiming an existing scope are each a fatal config error (exit `2`) naming the entry index and the offending key. An entry that matches nothing is not an error; it reports `suppressed: 0`.
- **`summary` text reports the suppressions it applies.** The `Suppressed findings: N via …` line `analyse` prints now also closes `summary` text output, below the canonical composite block and rendered by the same function, so the two surfaces cannot report different counts for one tree. `summary --format json` still filters without publishing a count: the `gruff.summary.v2` envelope is unchanged and has no suppression surface yet.
- **Every sensitive exclusion is audited.** Each entry adds one row to `suppressions[]` (`{index, rule, paths, symbol, reason, suppressed}`) and to the `Suppressed findings: N via …` text line, labelled `sensitiveExclusions[<index>]`. `exclude[]` rows keep their existing label, shape, and `message_contains` behaviour; `suppressions[]` rows gain a `symbol` key that stays `null` for ordinary exclusions.

## v0.5.0 - 2026-08-16

0.5.0 retunes rule families against real Rust idiom and measured corpus noise, replaces secret and PHI previews with markers, moves the action to `argv` with a pinned verified install, and upgrades the agent harness to goat-flow 1.15.1.

- **`security.process-command` requires std provenance.** Third-party `Command` types and comment examples stay quiet; clap drops 1,265 findings to 4.
- **GitHub `uses:` findings follow step structure.** Unpinned-action checks read `jobs.<job>.steps`, `runs.steps`, and a job's own reusable-workflow `uses:`, not a nested `with` value.
- **Pull-request gating reads the top-level `on` mapping.** A `with:` input or matrix key named `pull_request` no longer fakes a trigger on a push-only workflow.
- **Quoted `"on":` keys and quoted event names count as triggers.** YAML 1.1 reads bare `on` as a boolean, so linters quote it and those workflows were invisible.
- **Remote-shell findings require the payload to reach the shell.** A pipe still reports; `;` and `||` report only when the interpreter reads a path the downloader wrote.
- **A `permissions:` key inside a step is an action input, not a grant.** `with: permissions: write-all` stays silent while a workflow-level grant and a job's `write-all` still report.
- **Quoted step keys are read like plain ones.** `- "uses":` and `- "run":` reach the pinning, remote-shell, and event-interpolation checks.
- **Block headers carrying an indentation indicator open a run block.** `run: |2` and `>2-` keep their shell lines in scope instead of skipping the whole step.
- **Container images must name a digest.** `docker://alpine:latest` reports as unpinned; a `docker://image@sha256:...` reference stays exempt.
- **Secret expressions match without interior whitespace.** `${{secrets.TOKEN}}` gates pull-request secret exposure like `${{ secrets.TOKEN }}`.
- **Lock guards taken from struct fields report.** `self.state.write().await` held across an await reports; I/O and domain `read`/`write` receivers stay silent.
- **Root-qualified process constructors report.** `::std::process::Command::new` names the standard-library type, while `vendor::std::process::Command` still does not.
- **Release setup rejects unpublished identities.** The action takes only core `X.Y.Z` versions and stops when actionlint's SHA-256 check fails.
- **`test-quality.unwrap-in-test` is off by default.** Still Advisory when enabled; baselines lose its findings, 622 in clap and 773 in tokio.
- **`naming.short-variable` skips narrow Rust idioms.** Loop and closure bindings and `cx: *Context` parameters stay quiet; tokio drops 1,584 to 881.
- **Agent harness upgraded to goat-flow 1.15.1.** Agent surfaces, skill docs, and managed hooks move to its templates, retiring three local hotfixes.
- **`goat-flow-allow-secret` survives the upgrade.** Both scan paths honour it again, after CR stripping so a Windows-edited marker still counts.
- **The allow marker exempts secrets only.** No other form counts, not `gitleaks:allow`, and a conflict marker carrying it still blocks the turn.
- **Unreadable changed files block the turn instead of passing as clean.** The scan reports `scan incomplete`; oversized and binary paths block too.
- **Preflight names skipped checks in its success line.** The line quoted as gate evidence carries the skip count, so green cannot mean full coverage.
- **Permission rules and hook repairs are gated.** Preflight fails on a lost `Read`/`Edit` deny pair, an inert rule form, or one of six hook repairs.
- **Managed skill-doc repairs are gated too.** Preflight asserts the analyzer playbook's `bin/<target>` probe and its `analyse --help` guidance.
- **`.goat-flow/security-policy.md` states this repository's boundaries.** Each entry names the architecture section, ADR, or footgun that decides it.
- **Codex denies every non-sample env-file variant.** The workspace profile denies `**/.env*` for direct file tools and reopens only `.env.example`.
- **Claude denies every non-sample env-file variant too.** Paired `Read(**/.env*)` and `Edit(**/.env*)` denies refuse `.env.qa` and `.env.bak`.
- **Claude permission wording matches current tool semantics.** An `Edit` deny covers every file-writing tool, so `Read` and `Edit` pairs suffice.
- **Native Windows action paths.** `working-directory` and `output-file` accept a drive root or UNC share; a drive-relative `C:crate` is rejected.
- **`security.sql-dynamic-query` reads SQL shape, not words.** An all-interpolated `SELECT` with no `FROM` reports; prose and non-SQL DSL stay quiet.
- **Unused private functions report even when generic.** `fn helper<T>(..)` and `fn helper<F: Fn()>(..)` counted as their own reference; rust-clippy rises from 3,293 to 3,630.
- **API-key detection skips hyphenated prose.** The `sk-` arm had no left boundary, so `risk-of-script-injections` matched; real keys still report.
- **Annotated deserialization sinks report.** `security.unsafe-deserialization` matches `serde_yaml::from_str::<Config>(..)` in all four families.
- **Split download-to-shell pipelines report.** A `curl` and its `bash` on separate block-scalar lines are joined; a trailing `||` ends the join.
- **Stop-hook scan bypass closed on both dispatch paths.** An added line whose own text starts with `++` is no longer skipped as a file header.
- **Release reruns fail closed on an existing draft.** The workflow contract rejects `--clobber`, release deletion, and existence-probe gating.
- **file-length: 1000 substantive lines at error (family ratification).** Blank and comment-only lines are free, replacing the 600-line warning.
- **Zero-payload sensitive metadata markers.** JSON, SARIF, and hook findings serialize detector-owned markers instead of secret or PHI previews.
- **Narrower lock-across-await signal.** I/O and domain `.read()`/`.write()` no longer read as guards; zero-arg calls need local lock evidence.
- **Wrapper normalisation skips unknown options.** `watch` and `parallel` now match `xargs`, so no destructive payload hides from the deny hook.
- **Action metadata keys are not executable steps.** `run:` is read structurally like `uses:`, so a top-level `run` input is not scanned as shell.
- **Risk-based network-security test scans.** Executable Rust tests keep bind-all and SSRF findings; scoped mitigations replace blanket suppression.
- **Block rustdoc and function-length precision.** Doc rules accept outer `/** */` comments; `size.function-length` excludes rustdoc and attributes.
- **Structured composite-action arguments.** The action accepts newline-delimited `argv`, rejects legacy `args`, and contains paths in the workspace.
- **Explicit composite-action security coverage.** Supplied `action.yml` files now get event-interpolation, remote-shell, and full-SHA checks.
- **Inert Markdown finding fields.** Rule IDs and paths use safe code spans and messages escape as text, so untrusted values cannot inject markup.
- **SAFETY rationales follow Rust conventions.** `security.unsafe-block` matches `SAFETY:`, `Safety:`, and `safety:`; tokio drops 704 to 493.
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
