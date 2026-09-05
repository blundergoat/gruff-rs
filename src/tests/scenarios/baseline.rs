//! Baseline v3 as users meet it: reviewed debt that survives an edit, and secrets that never do.
//! These tests pin the family rules, so a reviewed finding stays hidden through line movement while a
//! new sibling, a grown count, and every secret stay visible and keep failing the run.

use super::*;

/// The digests the family case file pins for other ports; reproducing them is the only proof the rule is one rule.
const ORACLE_PINS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "rs",
        "docs.missing-readme",
        "src/widget.rs",
        "process#1",
        "aff839f0cf33b11e",
    ),
    (
        "rs",
        "docs.missing-readme",
        "src/widget.rs",
        "process#2",
        "4ab8dc0e1ec4b969",
    ),
    (
        "rs",
        "docs.missing-readme",
        "src/widget.rs",
        "File has no module documentation",
        "bdb4503a37614a4f",
    ),
    (
        "ts",
        "docs.missing-readme",
        "src/widget.rs",
        "process#1",
        "caa4bb2431af313d",
    ),
    (
        "rs",
        "docs.missing-readme",
        "src/gadget.rs",
        "process#1",
        "8f717ea2d0f8af15",
    ),
];

#[test]
pub(crate) fn identity_matches_the_family_oracle() {
    for (tool_language, rule_id, path, subject, expected) in ORACLE_PINS {
        assert_eq!(
            &compute_identity_for(tool_language, rule_id, path, subject),
            expected,
            "identity for {tool_language} {subject} must match the family oracle"
        );
    }
}

#[test]
pub(crate) fn measured_values_never_enter_a_symbol_less_identity() {
    assert_eq!(
        normalise_measured_values("file has 1010 lines, above threshold 1000"),
        "file has # lines, above threshold #"
    );
    assert_eq!(
        normalise_measured_values("12.5% over 1,234 lines in v0.5.2"),
        "#% over # lines in v#"
    );
    assert_eq!(
        normalise_measured_values("File has no module documentation"),
        "File has no module documentation"
    );
}

#[test]
pub(crate) fn a_generated_baseline_stores_one_line_free_row_per_identity() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("baseline.json");
    let reviewed = baseline_test_finding("naming.short", "src/lib.rs", 12, Some("process"));

    write_baseline(&baseline_path, std::slice::from_ref(&reviewed)).expect("baseline write");
    let document: Value =
        serde_json::from_str(&fs::read_to_string(&baseline_path).expect("baseline read"))
            .expect("baseline json");

    assert_eq!(document["schemaVersion"], "gruff.baseline.v3");
    assert_eq!(document["toolLanguage"], "rs");
    assert_eq!(
        document["occurrences"][0]["identity"],
        json!(compute_identity_for(
            "rs",
            "naming.short",
            "src/lib.rs",
            "process#1"
        ))
    );
    assert_eq!(document["occurrences"][0]["count"], 1);
    assert_eq!(document["sensitive"]["eligible"], false);
}

#[test]
pub(crate) fn a_line_shifted_finding_stays_hidden_and_a_new_sibling_does_not() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("baseline.json");
    let reviewed = baseline_test_finding("naming.short", "src/lib.rs", 12, Some("process"));
    write_baseline(&baseline_path, std::slice::from_ref(&reviewed)).expect("baseline write");

    let mut findings = vec![
        baseline_test_finding("naming.short", "src/lib.rs", 300, Some("process")),
        baseline_test_finding("naming.short", "src/lib.rs", 400, Some("other")),
    ];
    let application = apply_baseline(&baseline_path, &mut findings, &declaration_position_by_line)
        .expect("baseline applies");

    assert_eq!(application.counts.unchanged, 1);
    assert_eq!(application.counts.new, 1);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].symbol.as_deref(), Some("other"));
}

#[test]
pub(crate) fn a_second_occurrence_beyond_the_reviewed_count_is_new_and_the_lowest_line_is_spent() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("baseline.json");
    let reviewed = baseline_test_finding("size.parameter-count", "src/lib.rs", 10, None);
    write_baseline(&baseline_path, std::slice::from_ref(&reviewed)).expect("baseline write");

    // The run is supplied out of order, so a port spending the count in scan order would hide the wrong occurrence.
    let mut findings = vec![
        baseline_test_finding("size.parameter-count", "src/lib.rs", 90, None),
        baseline_test_finding("size.parameter-count", "src/lib.rs", 10, None),
    ];
    let application = apply_baseline(&baseline_path, &mut findings, &declaration_position_by_line)
        .expect("baseline applies");

    assert_eq!(application.counts.unchanged, 1);
    assert_eq!(application.counts.new, 1);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, Some(90));
}

#[test]
pub(crate) fn a_reworded_message_on_a_symbol_bearing_finding_stays_hidden() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("baseline.json");
    let reviewed = baseline_test_finding("naming.short", "src/lib.rs", 12, Some("process"));
    write_baseline(&baseline_path, std::slice::from_ref(&reviewed)).expect("baseline write");

    let mut reworded = vec![Finding::new(FindingDescriptor {
        rule_id: "naming.short".to_string(),
        message: "the rule's wording improved in a patch release".to_string(),
        file_path: "src/lib.rs".to_string(),
        line: Some(12),
        severity: Severity::Advisory,
        pillar: Pillar::Naming,
        confidence: Confidence::High,
        symbol: Some("process".to_string()),
        remediation: None,
        metadata: json!({}),
    })];
    let application = apply_baseline(&baseline_path, &mut reworded, &declaration_position_by_line)
        .expect("baseline applies");

    assert_eq!(application.counts.unchanged, 1);
    assert!(reworded.is_empty());
}

#[test]
pub(crate) fn a_measured_file_level_finding_survives_the_file_growing() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("baseline.json");
    let reviewed = measured_file_finding(1010);
    write_baseline(&baseline_path, std::slice::from_ref(&reviewed)).expect("baseline write");

    let mut grown = vec![measured_file_finding(1200)];
    let application =
        apply_baseline(&baseline_path, &mut grown, &declaration_position_by_line).expect("applies");

    assert_eq!(application.counts.unchanged, 1);
    assert_eq!(application.counts.collision, 0);
    assert!(grown.is_empty());
}

#[test]
pub(crate) fn a_sensitive_finding_is_never_stored_and_never_hidden() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("baseline.json");
    let secret = Finding::new(FindingDescriptor {
        rule_id: "sensitive-data.pii-test-fixture".to_string(),
        message: "fixture PII detected".to_string(),
        file_path: "tests/fixtures/users.txt".to_string(),
        line: Some(1),
        severity: Severity::Warning,
        pillar: Pillar::SensitiveData,
        confidence: Confidence::High,
        symbol: None,
        remediation: None,
        metadata: json!({}),
    });

    write_baseline(&baseline_path, std::slice::from_ref(&secret)).expect("baseline write");
    let document: Value =
        serde_json::from_str(&fs::read_to_string(&baseline_path).expect("baseline read"))
            .expect("baseline json");

    assert_eq!(document["occurrences"], json!([]));
    assert_eq!(document["sensitive"]["counts"]["total"], 1);

    let mut findings = vec![secret];
    let application = apply_baseline(&baseline_path, &mut findings, &declaration_position_by_line)
        .expect("baseline applies");

    assert_eq!(application.counts.not_eligible, 1);
    assert_eq!(application.counts.unchanged, 0);
    assert_eq!(findings.len(), 1, "a reviewed secret must stay visible");
}

#[test]
pub(crate) fn a_baseline_written_by_another_port_is_refused() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("baseline.json");
    write_baseline(
        &baseline_path,
        &[baseline_test_finding(
            "naming.short",
            "src/lib.rs",
            12,
            Some("process"),
        )],
    )
    .expect("baseline write");

    let mut document: Value =
        serde_json::from_str(&fs::read_to_string(&baseline_path).expect("baseline read"))
            .expect("baseline json");
    document["toolLanguage"] = json!("ts");
    fs::write(&baseline_path, document.to_string()).expect("baseline rewrite");

    let error = apply_baseline(
        &baseline_path,
        &mut Vec::new(),
        &declaration_position_by_line,
    )
    .expect_err("a foreign baseline is refused");

    assert!(error.contains("written by ts"), "error was {error}");
}

#[test]
pub(crate) fn a_row_that_could_expire_or_leak_fails_the_file() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("baseline.json");
    fs::write(
        &baseline_path,
        json!({
            "schemaVersion": "gruff.baseline.v3",
            "toolLanguage": "rs",
            "occurrences": [{"identity": "0000000000000000", "count": 1, "line": 12}],
        })
        .to_string(),
    )
    .expect("baseline write");

    let error = apply_baseline(
        &baseline_path,
        &mut Vec::new(),
        &declaration_position_by_line,
    )
    .expect_err("a positional row is refused");

    assert!(
        error.contains("forbidden key \"line\""),
        "error was {error}"
    );
}

#[test]
pub(crate) fn a_0_5_baseline_fails_closed_and_names_the_migration_command() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("legacy.json");
    write_legacy_input(&baseline_path);

    let error = apply_baseline(
        &baseline_path,
        &mut Vec::new(),
        &declaration_position_by_line,
    )
    .expect_err("a 0.5 baseline is refused");

    assert!(error.contains("--migrate-baseline"), "error was {error}");
}

#[test]
pub(crate) fn migration_carries_reviews_forward_and_leaves_its_input_byte_identical() {
    let dir = tempdir().expect("tempdir");
    let input_path = dir.path().join("legacy.json");
    let output_path = dir.path().join("migrated.json");
    let original = write_legacy_input(&input_path);

    let migration = migrate_baseline(
        &input_path,
        &output_path,
        &[
            baseline_test_finding("naming.short", "src/lib.rs", 12, Some("process")),
            baseline_test_finding("naming.short", "src/lib.rs", 400, Some("unreviewed")),
        ],
        &declaration_position_by_line,
    )
    .expect("migration succeeds");
    let migrated: Value =
        serde_json::from_str(&fs::read_to_string(&output_path).expect("migrated read"))
            .expect("migrated json");

    assert_eq!(migration.accepted, 1);
    assert_eq!(migration.entries, 1);
    // The 0.5 digest named a line and this one does not, so the migration re-identifies rather than translates.
    assert_eq!(
        migrated["occurrences"][0]["identity"],
        json!(compute_identity_for(
            "rs",
            "naming.short",
            "src/lib.rs",
            "process#1"
        ))
    );
    assert_eq!(
        fs::read(&input_path).expect("input read"),
        original,
        "the 0.5 input is the user's way back and must survive byte for byte"
    );
}

#[test]
pub(crate) fn migration_refuses_to_write_over_its_own_input() {
    let dir = tempdir().expect("tempdir");
    let input_path = dir.path().join("legacy.json");
    let original = write_legacy_input(&input_path);

    let error = migrate_baseline(&input_path, &input_path, &[], &declaration_position_by_line)
        .expect_err("an in-place migration is refused");

    assert!(error.contains("different file"), "error was {error}");
    assert_eq!(fs::read(&input_path).expect("input read"), original);
}

#[test]
pub(crate) fn baseline_generation_and_failure_modes_are_reported_cleanly() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("fixture write");

    let generated_path = dir.path().join("baseline.json");
    let generated = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            generate_baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            ..default_test_options()
        },
    )
    .expect("baseline generation succeeds");
    assert!(generated
        .baseline
        .as_ref()
        .is_some_and(|baseline| baseline.generated));
    let baseline_json: Value =
        serde_json::from_str(&fs::read_to_string(&generated_path).expect("baseline read"))
            .expect("baseline json");
    assert_eq!(baseline_json["schemaVersion"], "gruff.baseline.v3");
    assert!(baseline_json["occurrences"].as_array().is_some());

    fs::write(
        dir.path().join("bad-baseline.json"),
        r#"{ "schemaVersion": "wrong", "occurrences": [] }"#,
    )
    .expect("bad baseline write");
    let invalid_schema = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("bad-baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect_err("invalid baseline schema rejected");
    assert!(invalid_schema.contains("unsupported baseline schema"));

    let missing = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("missing-baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect_err("missing baseline rejected");
    assert!(missing.contains("unable to read baseline"));
}

#[test]
pub(crate) fn baseline_tri_state_counts_classify_new_unchanged_absent() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("sample.rs"),
        "pub fn one() {}\npub fn two() {}\npub fn three() {}\n",
    )
    .expect("fixture write");

    let baseline_path = dir.path().join("baseline.json");
    let generated = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            generate_baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            ..default_test_options()
        },
    )
    .expect("baseline generation succeeds");
    let total = generated.findings.len();
    assert!(total >= 2, "fixture must produce >=2 findings, got {total}");
    // A generate run has no comparison context: every movement count is zero.
    let generated_baseline = generated.baseline.as_ref().expect("generated baseline");
    assert!(generated_baseline.generated);
    assert_eq!(generated_baseline.new_count, 0);
    assert_eq!(generated_baseline.unchanged_count, 0);
    assert_eq!(generated_baseline.absent_count, 0);

    // Re-scan against the unmodified baseline: every finding is unchanged and none is rendered.
    let all_unchanged = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let unchanged_baseline = all_unchanged.baseline.as_ref().expect("baseline present");
    assert_eq!(unchanged_baseline.new_count, 0);
    assert_eq!(unchanged_baseline.unchanged_count, total);
    assert_eq!(unchanged_baseline.absent_count, 0);
    assert!(
        all_unchanged.findings.is_empty(),
        "default list drops unchanged findings"
    );

    // Drop one reviewed row (its finding becomes new) and add a ghost row that matches nothing (absent).
    let mut baseline_json: Value =
        serde_json::from_str(&fs::read_to_string(&baseline_path).expect("baseline read"))
            .expect("baseline json");
    let occurrences = baseline_json["occurrences"]
        .as_array_mut()
        .expect("occurrences array");
    occurrences.remove(0);
    occurrences.push(json!({
        "identity": "deadbeefdeadbeef",
        "count": 1,
        "ruleId": "ghost.removed-rule",
        "path": "sample.rs",
        "subject": "ghost#1",
    }));
    fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_json).expect("baseline serialize"),
    )
    .expect("baseline rewrite");

    let mixed = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let mixed_baseline = mixed.baseline.as_ref().expect("baseline present");
    assert_eq!(
        mixed_baseline.new_count, 1,
        "the dropped row's finding is new"
    );
    assert_eq!(mixed_baseline.unchanged_count, total - 1);
    assert_eq!(mixed_baseline.absent_count, 1, "the ghost row is resolved");
    assert_eq!(mixed.findings.len(), mixed_baseline.new_count);
}

#[test]
pub(crate) fn baseline_tri_state_all_new_and_no_baseline_short_circuit() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn one() {}\n").expect("fixture write");

    let baseline_path = dir.path().join("baseline.json");
    write_baseline(&baseline_path, &[]).expect("empty baseline write");

    let all_new = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    let baseline = all_new.baseline.as_ref().expect("baseline present");
    assert_eq!(baseline.new_count, all_new.findings.len());
    assert_eq!(baseline.unchanged_count, 0);
    assert!(baseline.new_count > 0);

    let no_baseline = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");
    assert!(
        no_baseline.baseline.is_none(),
        "--no-baseline must leave report.baseline None"
    );
}

#[test]
pub(crate) fn baseline_run_emits_per_rule_deltas_with_introduced_and_removed_counts() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(
        dir.path().join("sample.rs"),
        "pub fn one() {}\npub fn two() {}\npub fn three() {}\n",
    )
    .expect("fixture write");

    let baseline_path = dir.path().join("baseline.json");
    let generated = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            generate_baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            ..default_test_options()
        },
    )
    .expect("baseline generation succeeds");
    assert!(!generated.findings.is_empty());

    let mut baseline_json: Value =
        serde_json::from_str(&fs::read_to_string(&baseline_path).expect("baseline read"))
            .expect("baseline json");
    let occurrences = baseline_json["occurrences"]
        .as_array_mut()
        .expect("occurrences array");
    let dropped = occurrences.remove(0);
    let dropped_rule = dropped["ruleId"].as_str().expect("rule id").to_string();
    occurrences.push(json!({
        "identity": "deadbeefdeadbeef",
        "count": 1,
        "ruleId": "ghost.removed-rule",
        "path": "sample.rs",
        "subject": "ghost#1",
    }));
    fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_json).expect("baseline serialize"),
    )
    .expect("baseline rewrite");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            baseline: Some(PathBuf::from("baseline.json")),
            no_config: true,
            no_baseline: false,
            ..default_test_options()
        },
    )
    .expect("baseline analysis succeeds");

    let deltas = report
        .per_rule_deltas
        .as_ref()
        .expect("baseline run must populate per_rule_deltas");
    let dropped_delta = deltas
        .iter()
        .find(|delta| delta.rule_id == dropped_rule)
        .expect("the dropped row's rule appears as introduced");
    assert_eq!(dropped_delta.introduced, 1);
    let ghost_delta = deltas
        .iter()
        .find(|delta| delta.rule_id == "ghost.removed-rule")
        .expect("the ghost row's rule appears as removed");
    assert_eq!(ghost_delta.removed, 1);
    assert_eq!(ghost_delta.net, -1);
}

#[test]
pub(crate) fn full_tree_run_produces_no_per_rule_deltas() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("fixture write");

    let report = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            no_config: true,
            no_baseline: true,
            ..default_test_options()
        },
    )
    .expect("analysis succeeds");

    assert!(
        report.per_rule_deltas.is_none(),
        "full-tree runs must not populate per_rule_deltas; got {:?}",
        report.per_rule_deltas
    );

    let rendered_json = render_report(&report, OutputFormat::Json);
    assert!(
        !rendered_json.contains("perRuleDeltas"),
        "JSON output on a full-tree run must omit the perRuleDeltas key entirely:\n{rendered_json}"
    );
}

#[test]
pub(crate) fn migration_refuses_an_ambiguous_input() {
    let dir = tempdir().expect("tempdir");
    let input_path = dir.path().join("legacy.json");
    let output_path = dir.path().join("migrated.json");
    let ambiguous = serde_json::to_vec_pretty(&json!({
        "schemaVersion": "gruff.baseline.v1",
        "entries": [],
        "findings": [],
    }))
    .expect("ambiguous baseline serializes");
    fs::write(&input_path, &ambiguous).expect("ambiguous baseline write");

    let error = migrate_baseline(
        &input_path,
        &output_path,
        &[baseline_test_finding(
            "naming.short",
            "src/lib.rs",
            12,
            Some("process"),
        )],
        &declaration_position_by_line,
    )
    .expect_err("an ambiguous 0.5 input is refused");

    assert!(
        error.contains("more than one row container"),
        "error was {error}"
    );
    assert_eq!(
        fs::read(&input_path).expect("input read"),
        ambiguous,
        "a refused migration must leave its input alone"
    );
    // A refused migration writes nothing, so the user is not left with a half-migrated second file.
    assert!(!output_path.exists(), "a refused migration wrote an output");
}

#[test]
pub(crate) fn migration_refuses_a_hard_linked_output() {
    let dir = tempdir().expect("tempdir");
    let input_path = dir.path().join("legacy.json");
    let output_path = dir.path().join("hard-link.json");
    let original = write_legacy_input(&input_path);
    fs::hard_link(&input_path, &output_path).expect("hard link");

    let error = migrate_baseline(
        &input_path,
        &output_path,
        &[baseline_test_finding(
            "naming.short",
            "src/lib.rs",
            12,
            Some("process"),
        )],
        &declaration_position_by_line,
    )
    .expect_err("a hard-linked output is refused");

    assert!(error.contains("different file"), "error was {error}");
    assert_eq!(fs::read(&input_path).expect("input read"), original);
}

#[test]
pub(crate) fn a_baseline_only_ever_removes_reviewed_findings() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("baseline.json");
    let reviewed = baseline_test_finding("naming.short", "src/lib.rs", 12, Some("process"));
    let fresh = baseline_test_finding("naming.short", "src/lib.rs", 400, Some("other"));
    let secret = Finding::new(FindingDescriptor {
        rule_id: "sensitive-data.aws-access-key".to_string(),
        message: "Possible AWS access key".to_string(),
        file_path: "src/lib.rs".to_string(),
        line: Some(3),
        severity: Severity::Error,
        pillar: Pillar::SensitiveData,
        confidence: Confidence::High,
        symbol: None,
        remediation: None,
        metadata: json!({}),
    });
    write_baseline(&baseline_path, &[reviewed.clone(), secret.clone()]).expect("baseline write");

    let mut findings = vec![reviewed, fresh, secret];
    let application = apply_baseline(&baseline_path, &mut findings, &declaration_position_by_line)
        .expect("baseline applies");

    // Only the reviewed finding leaves the gated set; the new one and the secret still fail the run.
    assert_eq!(findings.len(), 2);
    assert_eq!(application.counts.unchanged, 1);
    assert_eq!(application.counts.new, 1);
    assert_eq!(application.counts.not_eligible, 1);
}

#[test]
pub(crate) fn a_generate_at_the_default_path_keeps_the_retreat_copy() {
    let _guard = analysis_lock();
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("README.md"), "# Fixture\n").expect("readme write");
    fs::write(dir.path().join("sample.rs"), "pub fn process() {}\n").expect("fixture write");
    let default_path = dir.path().join("gruff-baseline.json");
    let legacy_bytes = br#"{"schemaVersion":"gruff.baseline.v1","entries":[]}"#;
    fs::write(&default_path, legacy_bytes).expect("legacy baseline write");

    let refused = run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            generate_baseline: Some(PathBuf::from("gruff-baseline.json")),
            no_config: true,
            ..default_test_options()
        },
    )
    .expect_err("a generate over a 0.5 baseline is refused");

    assert!(refused.contains("--force"), "error was {refused}");
    // The refusal is not a write: the retreat copy is exactly as the user left it.
    assert_eq!(
        fs::read(&default_path).expect("baseline read"),
        legacy_bytes.to_vec()
    );

    // The destructive case stays available and stays explicit.
    run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            generate_baseline: Some(PathBuf::from("gruff-baseline.json")),
            force_baseline_overwrite: true,
            no_config: true,
            ..default_test_options()
        },
    )
    .expect("--force overwrites");
    assert_ne!(
        fs::read(&default_path).expect("baseline read"),
        legacy_bytes.to_vec()
    );

    // Regenerating v3 over v3 is not destructive, because v3 is what the tool now reads.
    run_project_analysis(
        dir.path(),
        AnalysisOptions {
            paths: vec![PathBuf::from("sample.rs")],
            generate_baseline: Some(PathBuf::from("gruff-baseline.json")),
            no_config: true,
            ..default_test_options()
        },
    )
    .expect("regenerating v3 over v3 is allowed");
}

#[test]
pub(crate) fn a_written_baseline_carries_no_sentinel() {
    let dir = tempdir().expect("tempdir");
    let baseline_path = dir.path().join("gruff-baseline.json");
    // A synthetic AWS-shaped literal, not a live credential; it exists to be searched for.
    let sentinel = format!("AKIA{}", "IOSFODNN7EXAMPLE");
    let secret = Finding::new(FindingDescriptor {
        rule_id: "sensitive-data.aws-access-key".to_string(),
        message: format!("possible AWS access key {sentinel} in a literal"),
        file_path: "src/config.rs".to_string(),
        line: Some(3),
        severity: Severity::Error,
        pillar: Pillar::SensitiveData,
        confidence: Confidence::High,
        symbol: None,
        remediation: None,
        metadata: json!({}),
    });

    write_baseline(&baseline_path, std::slice::from_ref(&secret)).expect("baseline write");
    let written = fs::read_to_string(&baseline_path).expect("baseline read");

    for (name, form) in sentinel_forms(&sentinel) {
        assert!(
            !written.contains(&form),
            "the written baseline carries the {name} form of the sentinel"
        );
    }
    // What it does carry is a count, which is what makes the secret auditable without naming it.
    assert!(written.contains(r#""sensitive-data.aws-access-key": 1"#));
}

/// Return every shape a leaked secret could take in an artifact, so a derived value is caught as well as a raw one.
fn sentinel_forms(sentinel: &str) -> Vec<(&'static str, String)> {
    let mut hasher = Sha256::new();
    hasher.update(sentinel.as_bytes());
    vec![
        ("raw", sentinel.to_string()),
        ("partial", sentinel[..8].to_string()),
        ("hashed", format!("{:x}", hasher.finalize())),
        ("encoded", base64_encode(sentinel.as_bytes())),
    ]
}

/// Encode bytes as standard base64, so the test can search for an encoded secret without a new dependency.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in input.chunks(3) {
        let mut buffer = [0_u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let bits =
            (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(ALPHABET[((bits >> (18 - index * 6)) & 0x3F) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// Build one ordinary finding; each test varies only the field whose effect on the identity it is proving.
fn baseline_test_finding(
    rule_id: &str,
    file_path: &str,
    line: usize,
    symbol: Option<&str>,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!("{rule_id} message"),
        file_path: file_path.to_string(),
        line: Some(line),
        severity: Severity::Advisory,
        pillar: Pillar::Naming,
        confidence: Confidence::High,
        symbol: symbol.map(str::to_string),
        remediation: None,
        metadata: json!({}),
    })
}

/// A file-level finding whose message states the measurement, which is the shape the amendment of 2026-09-05 covers.
fn measured_file_finding(lines: usize) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "size.file-length".to_string(),
        message: format!("file has {lines} lines, above threshold 1000"),
        file_path: "src/lib.rs".to_string(),
        line: Some(1),
        severity: Severity::Warning,
        pillar: Pillar::Size,
        confidence: Confidence::High,
        symbol: None,
        remediation: None,
        metadata: json!({"lines": lines, "threshold": 1000}),
    })
}

/// Stage the 0.5 baseline a migration reads, and hand back its bytes for the comparison after the migration.
fn write_legacy_input(path: &Path) -> Vec<u8> {
    let legacy = serde_json::to_vec_pretty(&json!({
        "schemaVersion": "gruff.baseline.v1",
        "generatedAt": "2026-08-01T00:00:00Z",
        "entries": [{
            "fingerprint": "9a4c2e7f1b8d0365",
            "ruleId": "naming.short",
            "filePath": "src/lib.rs",
            "line": 12,
            "symbol": "process",
            "message": "naming.short message",
        }],
    }))
    .expect("legacy baseline serializes");
    fs::write(path, &legacy).expect("legacy baseline write");
    legacy
}
