use super::*;

#[test]
pub(crate) fn sarif_suppression_results_carry_in_source_justification() {
    let registry = rules::builtin_registry();
    let finding = test_finding(
        "security.process-command",
        "tests/fixture.rs",
        4,
        Severity::Warning,
        Pillar::Security,
    );
    let exclusions = vec![ExclusionRule {
        selector: "security.process-command".to_string(),
        rule_ids: expand_rule_selector("security.process-command", &registry, "test.rule")
            .expect("exact selector"),
        paths: vec!["tests/**".to_string()],
        message_contains: None,
        reason: "test-only synthetic command".to_string(),
    }];
    let (findings, suppressions, suppressed_findings) =
        apply_report_exclusions(vec![finding], &exclusions);
    let mut report = sample_report_with(findings, Vec::new());
    report.summary = summarize(&report.findings);
    report.score = score_report(&report.findings);
    report.suppressions = suppressions;
    report.suppressed_findings = suppressed_findings;

    assert!(report.findings.is_empty());
    let sarif = sample_sarif(&report);
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "security.process-command");
    assert_eq!(result["suppressions"][0]["kind"], "inSource");
    assert_eq!(
        result["suppressions"][0]["justification"],
        "test-only synthetic command"
    );
}

#[test]
pub(crate) fn sarif_contract_covers_rules_locations_levels_and_metadata() {
    let mut error = Finding::new(FindingDescriptor {
        rule_id: "complexity.cyclomatic".to_string(),
        message: "Complex function".to_string(),
        file_path: r".\src\space name.rs".to_string(),
        line: Some(10),
        severity: Severity::Error,
        pillar: Pillar::Complexity,
        confidence: Confidence::Medium,
        symbol: Some("complex".to_string()),
        remediation: Some("Split branches.".to_string()),
        metadata: json!({}),
    });
    error.column = Some(5);
    error.end_line = Some(12);
    error.secondary_pillars = vec![Pillar::Size];

    let advisory = Finding::new(FindingDescriptor {
        rule_id: "docs.stale-todo".to_string(),
        message: "Stale TODO marker".to_string(),
        file_path: "src/hash#name.rs".to_string(),
        line: None,
        severity: Severity::Advisory,
        pillar: Pillar::Documentation,
        confidence: Confidence::Low,
        symbol: None,
        remediation: None,
        metadata: Value::Null,
    });
    let unknown = Finding::new(FindingDescriptor {
        rule_id: "custom.example".to_string(),
        message: "Custom warning".to_string(),
        file_path: "src/q?percent%.rs".to_string(),
        line: Some(3),
        severity: Severity::Warning,
        pillar: Pillar::Naming,
        confidence: Confidence::High,
        symbol: Some("custom".to_string()),
        remediation: None,
        metadata: json!({ "detail": "kept" }),
    });
    let report = sample_report_with(vec![error, advisory, unknown], Vec::new());
    let sarif = sample_sarif(&report);

    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules");
    let cyclomatic_rule = rules
        .iter()
        .find(|rule| rule["id"] == "complexity.cyclomatic")
        .expect("cyclomatic rule");
    assert_eq!(cyclomatic_rule["defaultConfiguration"]["level"], "warning");
    assert_eq!(cyclomatic_rule["properties"]["threshold"], json!(10.0));
    assert!(cyclomatic_rule["properties"]["options"].is_null());

    let results = sarif["runs"][0]["results"].as_array().expect("results");
    assert_eq!(results[0]["level"], "error");
    assert_eq!(results[0]["ruleId"], "complexity.cyclomatic");
    assert!(results[0]["ruleIndex"].is_number());
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/space%20name.rs"
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        10
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["startColumn"],
        5
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["endLine"],
        12
    );
    assert!(results[0]["locations"][0]["physicalLocation"]["region"]["endColumn"].is_null());
    assert_eq!(results[0]["properties"]["secondaryPillars"][0], "size");
    assert_eq!(results[0]["properties"]["metadata"], json!({}));
    assert_eq!(results[0]["properties"]["remediation"], "Split branches.");

    assert_eq!(results[1]["level"], "note");
    assert_eq!(
        results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/hash%23name.rs"
    );
    assert!(results[1]["locations"][0]["physicalLocation"]["region"].is_null());
    assert!(results[1]["properties"]["metadata"].is_null());

    assert_eq!(results[2]["level"], "warning");
    assert_eq!(results[2]["ruleId"], "custom.example");
    assert!(results[2]["ruleIndex"].is_null());
    assert_eq!(
        results[2]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/q%3Fpercent%25.rs"
    );
    assert_eq!(results[2]["properties"]["metadata"]["detail"], "kept");
}

#[test]
pub(crate) fn sarif_uri_encodes_reserved_path_characters() {
    assert_eq!(sarif_uri("./src/lib.rs"), "src/lib.rs");
    assert_eq!(sarif_uri(r"src\lib.rs"), "src/lib.rs");
    assert_eq!(sarif_uri("src/space name.rs"), "src/space%20name.rs");
    assert_eq!(sarif_uri("src/hash#name.rs"), "src/hash%23name.rs");
    assert_eq!(sarif_uri("src/q?name.rs"), "src/q%3Fname.rs");
    assert_eq!(sarif_uri("src/percent%name.rs"), "src/percent%25name.rs");
    assert_eq!(sarif_uri(""), ".");
}

#[test]
pub(crate) fn sarif_location_ignores_column_without_start_line() {
    let location = sarif_physical_location_from_parts("src/lib.rs", None, Some(5), Some(7));
    assert_eq!(location["artifactLocation"]["uri"], "src/lib.rs");
    assert!(location["region"].is_null());
}

#[test]
pub(crate) fn sarif_maps_diagnostics_to_invocation_notifications() {
    let report = sample_report_with(
        Vec::new(),
        vec![RunDiagnostic {
            diagnostic_type: "missing-path".to_string(),
            message: "Input path does not exist: missing.rs".to_string(),
            file_path: Some("missing.rs".to_string()),
            line: None,
        }],
    );
    let sarif = sample_sarif(&report);

    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        false
    );
    assert!(sarif["runs"][0]["invocations"][0]["commandLine"].is_null());
    assert!(sarif["runs"][0]["invocations"][0]["arguments"].is_null());
    assert!(sarif["runs"][0]["invocations"][0]["workingDirectory"].is_null());
    let notification = &sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0];
    assert_eq!(notification["descriptor"]["id"], "missing-path");
    assert_eq!(notification["level"], "error");
    assert!(notification["message"]["text"]
        .as_str()
        .expect("message")
        .contains("missing.rs"));
    assert_eq!(
        notification["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "missing.rs"
    );
    assert_eq!(
        sarif["runs"][0]["results"]
            .as_array()
            .expect("results")
            .len(),
        0
    );
}

#[test]
pub(crate) fn sarif_marks_clean_invocation_successful() {
    let sarif = sample_sarif(&sample_report());
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .expect("notifications")
            .len(),
        0
    );
}

#[test]
pub(crate) fn sarif_parse_error_keeps_text_rule_results() {
    let report = analyse_test_paths(vec![PathBuf::from("tests/fixtures/parser/invalid.rs")]);
    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(report.diagnostics[0].diagnostic_type, "parse-error");
    assert_has_rule(&report, "sensitive-data.aws-access-key");

    let sarif = sample_sarif(&report);
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        false
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["descriptor"]["id"],
        "parse-error"
    );
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["locations"][0]
            ["physicalLocation"]["artifactLocation"]["uri"],
        "tests/fixtures/parser/invalid.rs"
    );
    let result_rule_ids: Vec<&str> = sarif["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|result| result["ruleId"].as_str().expect("rule id"))
        .collect();
    assert!(
        result_rule_ids.contains(&"sensitive-data.aws-access-key"),
        "{result_rule_ids:?}"
    );
}
