use super::*;

#[test]
pub(crate) fn hook_capabilities_advertise_gruff_hook_v1() {
    let value: Value =
        serde_json::from_str(&crate::hook::render_capabilities()).expect("capabilities json");

    assert_eq!(value["contractVersion"], "gruff.hook.v1");
    assert_eq!(value["analyzer"]["name"], "gruff-rs");
    assert_eq!(value["supports"]["changedRanges"], true);
    assert_eq!(value["supports"]["baseline"], true);
    assert_eq!(value["supports"]["scopeField"], true);
    assert_eq!(value["supports"]["metadata"], true);
    assert_eq!(value["supports"]["stableIdentity"], true);
    assert_eq!(value["supports"]["ignoreReport"], true);
    assert_eq!(value["supports"]["newOnly"], true);
    assert_eq!(value["flags"]["changedRanges"], "--changed-ranges");
    assert_eq!(value["flags"]["diff"], "--diff");
    assert_eq!(value["flags"]["baseline"], "--baseline");
    assert_eq!(value["flagOrder"], "any");
}

#[test]
pub(crate) fn hook_accepts_flags_before_and_after_paths() {
    let before = Cli::try_parse_from([
        "gruff-rs",
        "hook",
        "--changed-ranges",
        "1-1",
        "--format",
        "json",
        "src/lib.rs",
    ])
    .expect("flags before path parse");
    let after = Cli::try_parse_from([
        "gruff-rs",
        "hook",
        "src/lib.rs",
        "--changed-ranges",
        "1-1",
        "--format",
        "json",
    ])
    .expect("flags after path parse");

    let Commands::Hook(before) = before.command else {
        panic!("expected hook command");
    };
    let Commands::Hook(after) = after.command else {
        panic!("expected hook command");
    };
    assert_eq!(before.paths, after.paths);
    assert_eq!(before.changed_ranges, after.changed_ranges);
    assert_eq!(before.changed_ranges.as_deref(), Some("1-1"));
}

#[test]
pub(crate) fn hook_full_scan_emits_file_and_line_scopes_with_remediation_and_metadata() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_secret_oversized_rust_file(dir.path(), 601);

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("full hook fixture analysis succeeds");
    let value = render_hook_value(report, false, false);
    let findings = value["findings"].as_array().expect("findings array");

    let file_length = finding_by_rule(findings, "size.file-length");
    assert_eq!(file_length["scope"], "file");
    assert_eq!(file_length["file"], "src/lib.rs");
    assert!(file_length["remediation"]
        .as_str()
        .is_some_and(|text| !text.is_empty()));
    assert_eq!(file_length["metadata"]["measured"], 601);
    assert_eq!(file_length["metadata"]["threshold"], 600);
    assert_eq!(file_length["metadata"]["unit"], "lines");
    assert_eq!(file_length["metadata"]["direction"], "above");
    assert!(file_length["stableIdentity"].as_str().is_some());

    let secret = finding_by_rule(findings, "sensitive-data.aws-access-key");
    assert_eq!(secret["scope"], "line");
    assert_eq!(secret["severity"], "error");
    assert!(secret["remediation"]
        .as_str()
        .is_some_and(|text| !text.is_empty()));
    assert_eq!(value["suppressed"]["count"], 0);
    assert_eq!(value["config"]["schemaOk"], true);
}

#[test]
pub(crate) fn hook_changed_region_drops_file_scope_without_anchor_residual() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    write_secret_oversized_rust_file(dir.path(), 601);

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            diff: Some(DiffSelection::ExplicitRanges {
                ranges: "1-1".to_string(),
                scope: ChangedScope::Symbol,
            }),
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("changed-region analysis succeeds");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "size.file-length"),
        "native changed-region path still has the anchor residual before hook filtering"
    );

    let value = render_hook_value(report, true, false);
    let findings = value["findings"].as_array().expect("findings array");
    assert!(
        findings
            .iter()
            .all(|finding| finding["ruleId"] != "size.file-length"),
        "hook output must omit file-scope findings under changed-region scope"
    );
    assert!(
        value["suppressed"]["count"].as_u64().unwrap_or_default() >= 1,
        "hook output must count the file-scope suppression"
    );
    assert!(findings.iter().any(|finding| finding["scope"] == "line"));
}

#[test]
pub(crate) fn hook_stable_identity_survives_line_shift_and_measured_value_change() {
    let line_ten = Finding::new(FindingDescriptor {
        rule_id: "waste.unwrap-expect".to_string(),
        message: "Function `load` unwraps an Option/Result.".to_string(),
        file_path: "src/lib.rs".to_string(),
        line: Some(10),
        severity: Severity::Advisory,
        pillar: Pillar::Waste,
        confidence: Confidence::High,
        symbol: Some("load".to_string()),
        remediation: None,
        metadata: json!({}),
    });
    let line_eleven = Finding::new(FindingDescriptor {
        line: Some(11),
        ..finding_descriptor_from(&line_ten)
    });
    assert_eq!(line_ten.stable_identity, line_eleven.stable_identity);
    assert_ne!(line_ten.fingerprint, line_eleven.fingerprint);

    let six_oh_one = file_length_finding(601);
    let six_oh_two = file_length_finding(602);
    assert_eq!(six_oh_one.stable_identity, six_oh_two.stable_identity);
    assert_eq!(six_oh_one.scope, FindingScope::File);
}

#[test]
pub(crate) fn hook_baseline_new_only_suppresses_existing_file_scope_and_keeps_new_threshold_crossing(
) {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("baseline.json");

    write_oversized_rust_file(dir.path(), 601);
    let before = analyse_lib_no_config(dir.path());
    let size = before
        .findings
        .iter()
        .find(|finding| finding.rule_id == "size.file-length")
        .expect("size finding before baseline")
        .clone();
    write_baseline(&baseline_path, &[size]).expect("baseline write");

    write_oversized_rust_file(dir.path(), 602);
    let after = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("baseline-applied analysis succeeds");
    assert_missing_rule(&after, "size.file-length");

    write_oversized_rust_file(dir.path(), 599);
    write_baseline(&baseline_path, &[]).expect("empty baseline write");
    write_oversized_rust_file(dir.path(), 601);
    let newly_crossed = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("newly crossed baseline analysis succeeds");
    assert_has_rule(&newly_crossed, "size.file-length");
}

#[test]
pub(crate) fn hook_diff_new_only_uses_stable_identity_for_file_scope_thresholds() {
    let _guard = analysis_lock();
    let existing = tempdir().expect("tempdir");
    init_git_repo(existing.path());
    write_oversized_rust_file(existing.path(), 601);
    git(existing.path(), &["add", "src/lib.rs"]);
    git(existing.path(), &["commit", "-m", "base"]);

    write_oversized_rust_file(existing.path(), 602);
    let mut current = analyse_lib_no_config(existing.path());
    assert_has_rule(&current, "size.file-length");
    let options = hook_diff_test_options();
    let base_identities = crate::hook::diff_base_stable_identities(
        existing.path(),
        &options,
        &Config::default(),
        "HEAD",
    )
    .expect("base identities");
    crate::hook::apply_stable_identity_new_only(&mut current, &base_identities);
    assert_missing_rule(&current, "size.file-length");

    let newly_crossing = tempdir().expect("tempdir");
    init_git_repo(newly_crossing.path());
    write_oversized_rust_file(newly_crossing.path(), 599);
    git(newly_crossing.path(), &["add", "src/lib.rs"]);
    git(newly_crossing.path(), &["commit", "-m", "base"]);
    write_oversized_rust_file(newly_crossing.path(), 601);
    let mut current = analyse_lib_no_config(newly_crossing.path());
    let base_identities = crate::hook::diff_base_stable_identities(
        newly_crossing.path(),
        &options,
        &Config::default(),
        "HEAD",
    )
    .expect("base identities");
    crate::hook::apply_stable_identity_new_only(&mut current, &base_identities);
    assert_has_rule(&current, "size.file-length");
}

#[test]
pub(crate) fn hook_reports_ignored_paths_and_config_errors_in_band() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("src")).expect("src dir");
    fs::write(dir.path().join("src/ignored.rs"), "fn ignored() {}\n").expect("ignored file");
    write_config(dir.path(), "paths:\n  ignore:\n    - src/ignored.rs\n");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("src/ignored.rs")],
            no_config: false,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("ignored-path analysis succeeds");
    let value = render_hook_value(report, false, false);
    let ignored = value["ignored"]["paths"].as_array().expect("ignored paths");
    assert_eq!(ignored.len(), 1);
    assert_eq!(ignored[0]["path"], "src/ignored.rs");
    assert_eq!(ignored[0]["source"], "config");
    assert_eq!(ignored[0]["pattern"], "src/ignored.rs");

    let error: Value = serde_json::from_str(&crate::hook::render_config_error("bad config"))
        .expect("config error json");
    assert_eq!(error["config"]["schemaOk"], false);
    assert_eq!(error["config"]["error"]["message"], "bad config");
    assert!(error["config"]["error"]["remediation"]
        .as_str()
        .is_some_and(|text| text.contains("configuration")));
}

#[test]
pub(crate) fn hook_diff_requires_the_unsafe_git_opt_in() {
    // `--diff` executes Git on the target repo, so per ADR-019 it must be a
    // hard error without the opt-in, exactly like `analyse --diff`. The Git-free
    // hook paths (`--changed-ranges`, `--baseline`) stay ungated.
    assert!(
        Cli::try_parse_from([
            "gruff-rs",
            "hook",
            "--diff",
            "HEAD",
            "--format",
            "json",
            "src/lib.rs",
        ])
        .is_err(),
        "hook --diff must hard-error without --diff-git-unsafe"
    );

    let allowed = Cli::try_parse_from([
        "gruff-rs",
        "hook",
        "--diff",
        "HEAD",
        "--diff-git-unsafe",
        "--format",
        "json",
        "src/lib.rs",
    ])
    .expect("hook --diff parses with the unsafe opt-in");
    let Commands::Hook(allowed) = allowed.command else {
        panic!("expected hook command");
    };
    assert_eq!(allowed.diff.as_deref(), Some("HEAD"));
    assert!(allowed.diff_git_unsafe);

    // The consumer's contract path never needs the opt-in.
    Cli::try_parse_from([
        "gruff-rs",
        "hook",
        "--format",
        "json",
        "--changed-ranges",
        "1-1",
        "src/lib.rs",
    ])
    .expect("hook --changed-ranges parses without the unsafe opt-in");
}

#[test]
pub(crate) fn hook_diff_base_export_handles_non_ascii_filenames() {
    let _guard = analysis_lock();
    let repo = tempdir().expect("tempdir");
    init_git_repo(repo.path());
    // A non-ASCII filename forces git's default `core.quotePath` C-quoting; the
    // `-z` ls-tree in export_git_base_tree is what keeps this from hard-erroring.
    write_named_oversized_rust_file(repo.path(), "src/café.rs", 601);
    git(repo.path(), &["add", "-A"]);
    git(repo.path(), &["commit", "-m", "base"]);

    let options = AnalysisOptions {
        paths: vec![PathBuf::from("src")],
        no_config: true,
        no_baseline: true,
        ..default_test_options()
    };
    let base_identities =
        crate::hook::diff_base_stable_identities(repo.path(), &options, &Config::default(), "HEAD")
            .expect("non-ascii base tree export succeeds");
    assert!(
        !base_identities.is_empty(),
        "base export should surface the oversized non-ascii file finding"
    );
}

fn render_hook_value(
    report: AnalysisReport,
    changed_region_active: bool,
    new_only_active: bool,
) -> Value {
    serde_json::from_str(&crate::hook::render_hook_report(
        report,
        changed_region_active,
        new_only_active,
    ))
    .expect("hook json")
}

fn finding_by_rule<'a>(findings: &'a [Value], rule_id: &str) -> &'a Value {
    findings
        .iter()
        .find(|finding| finding["ruleId"] == rule_id)
        .unwrap_or_else(|| panic!("missing {rule_id} in {findings:#?}"))
}

fn write_secret_oversized_rust_file(root: &Path, lines: usize) {
    fs::create_dir_all(root.join("src")).expect("src dir");
    let mut source = String::from("const LEAKED_KEY: &str = \"AKIA1234567890ABCDEF\";\n");
    for index in 1..lines {
        source.push_str(&format!("// filler {index}\n"));
    }
    fs::write(root.join("src/lib.rs"), source).expect("lib write");
}

fn write_oversized_rust_file(root: &Path, lines: usize) {
    fs::create_dir_all(root.join("src")).expect("src dir");
    let source = (0..lines)
        .map(|index| format!("// filler {index}\n"))
        .collect::<String>();
    fs::write(root.join("src/lib.rs"), source).expect("lib write");
}

fn write_named_oversized_rust_file(root: &Path, rel: &str, lines: usize) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent dir");
    }
    let source = (0..lines)
        .map(|index| format!("// filler {index}\n"))
        .collect::<String>();
    fs::write(&path, source).expect("named lib write");
}

fn analyse_lib_no_config(root: &Path) -> AnalysisReport {
    run_project_analysis(
        root,
        AnalysisOptions {
            paths: vec![PathBuf::from("src/lib.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds")
}

fn hook_diff_test_options() -> AnalysisOptions {
    AnalysisOptions {
        paths: vec![PathBuf::from("src/lib.rs")],
        no_config: true,
        no_baseline: true,
        ..default_test_options()
    }
}

fn init_git_repo(root: &Path) {
    git(root, &["init"]);
    git(root, &["config", "user.name", "Gruff Test"]);
    git(root, &["config", "user.email", "gruff@example.test"]);
}

fn git(root: &Path, args: &[&str]) {
    let args = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    crate::changed_region::git_output(root, &args).expect("git command succeeds");
}

fn file_length_finding(lines: usize) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "size.file-length".to_string(),
        message: format!("File has {lines} lines, above the threshold of 600."),
        file_path: "src/lib.rs".to_string(),
        line: Some(1),
        severity: Severity::Warning,
        pillar: Pillar::Size,
        confidence: Confidence::High,
        symbol: None,
        remediation: None,
        metadata: json!({
            "measured": lines,
            "threshold": 600,
            "unit": "lines",
            "direction": "above"
        }),
    })
}

fn finding_descriptor_from(finding: &Finding) -> FindingDescriptor {
    FindingDescriptor {
        rule_id: finding.rule_id.clone(),
        message: finding.message.clone(),
        file_path: finding.file_path.clone(),
        line: finding.line,
        severity: finding.severity,
        pillar: finding.pillar,
        confidence: finding.confidence,
        symbol: finding.symbol.clone(),
        remediation: finding.remediation.clone(),
        metadata: finding.metadata.clone(),
    }
}
