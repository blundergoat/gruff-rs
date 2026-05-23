use super::*;

pub(super) fn render_sarif(report: &AnalysisReport) -> String {
    let (rules, rule_indices) = sarif_rules_and_indices(report);
    let results = sarif_results(report, &rule_indices);

    serde_json::to_string_pretty(&sarif_document(report, &rules, &results))
        .expect("sarif serializes")
}

fn sarif_rules_and_indices(report: &AnalysisReport) -> (Vec<Value>, HashMap<String, usize>) {
    let (mut rules, mut indices) = sarif_builtin_rules_and_indices();
    for finding in unique_custom_findings(report, &indices) {
        let index = rules.len();
        indices.insert(finding.rule_id.clone(), index);
        rules.push(sarif_rule_from_finding(finding));
    }
    (rules, indices)
}

fn sarif_builtin_rules_and_indices() -> (Vec<Value>, HashMap<String, usize>) {
    let registry = rules::builtin_registry();
    let rules: Vec<Value> = registry.definitions().iter().map(sarif_rule).collect();
    let indices: HashMap<String, usize> = registry
        .definitions()
        .iter()
        .enumerate()
        .map(|(index, definition)| (definition.id.to_string(), index))
        .collect();
    (rules, indices)
}

fn unique_custom_findings<'a>(
    report: &'a AnalysisReport,
    indices: &HashMap<String, usize>,
) -> Vec<&'a Finding> {
    let mut findings: Vec<&Finding> = report
        .findings
        .iter()
        .chain(
            report
                .suppressed_findings
                .iter()
                .map(|suppressed| &suppressed.finding),
        )
        .filter(|finding| !indices.contains_key(&finding.rule_id))
        .collect();
    findings.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    findings.dedup_by(|left, right| left.rule_id == right.rule_id);
    findings
}

fn sarif_results(report: &AnalysisReport, rule_indices: &HashMap<String, usize>) -> Vec<Value> {
    let mut results: Vec<Value> = report
        .findings
        .iter()
        .map(|finding| sarif_result(finding, rule_indices))
        .collect();
    results.extend(
        report
            .suppressed_findings
            .iter()
            .map(|suppressed| sarif_suppressed_result(suppressed, rule_indices)),
    );
    results
}

fn sarif_document(report: &AnalysisReport, rules: &[Value], results: &[Value]) -> Value {
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": &report.tool.name,
                        "semanticVersion": &report.tool.version,
                        "rules": rules,
                    },
                },
                "invocations": [
                    sarif_invocation(report),
                ],
                "results": results,
                "properties": {
                    "gruffSchemaVersion": &report.schema_version,
                    "generatedAt": &report.run.generated_at,
                    "score": report.score.composite,
                    "grade": &report.score.grade,
                },
            },
        ],
    })
}

pub(crate) fn sarif_rule(definition: &rules::RuleDefinition) -> Value {
    json!({
        "id": definition.id,
        "name": definition.name,
        "shortDescription": {
            "text": definition.name,
        },
        "fullDescription": {
            "text": definition.description,
        },
        "help": {
            "text": definition.description,
        },
        "defaultConfiguration": {
            "level": sarif_level(definition.default_severity),
        },
        "properties": sarif_rule_properties(definition),
    })
}

fn sarif_rule_properties(definition: &rules::RuleDefinition) -> Value {
    let mut properties = Map::new();
    properties.insert("pillar".to_string(), json!(definition.pillar));
    properties.insert("tier".to_string(), json!(definition.tier));
    properties.insert("kind".to_string(), json!(definition.kind));
    properties.insert(
        "defaultSeverity".to_string(),
        json!(definition.default_severity),
    );
    properties.insert("confidence".to_string(), json!(definition.confidence));
    properties.insert(
        "defaultEnabled".to_string(),
        json!(definition.default_enabled),
    );
    if let Some(threshold) = definition.threshold {
        properties.insert("threshold".to_string(), json!(threshold.default));
    }
    if !definition.options.is_empty() {
        properties.insert("options".to_string(), json!(definition.options));
    }
    Value::Object(properties)
}

fn sarif_invocation(report: &AnalysisReport) -> Value {
    let mut notifications = Vec::new();
    for diagnostic in &report.diagnostics {
        notifications.push(sarif_notification(diagnostic));
    }
    json!({
        "executionSuccessful": !report.diagnostics.iter().any(RunDiagnostic::is_failure),
        "toolExecutionNotifications": notifications,
    })
}

fn sarif_notification(diagnostic: &RunDiagnostic) -> Value {
    let mut notification = Map::new();
    notification.insert(
        "descriptor".to_string(),
        json!({
            "id": &diagnostic.diagnostic_type,
        }),
    );
    notification.insert(
        "level".to_string(),
        json!(sarif_diagnostic_level(diagnostic)),
    );
    notification.insert(
        "message".to_string(),
        json!({
            "text": &diagnostic.message,
        }),
    );
    if let Some(locations) = sarif_diagnostic_locations(diagnostic) {
        notification.insert("locations".to_string(), locations);
    }
    Value::Object(notification)
}

fn sarif_diagnostic_level(diagnostic: &RunDiagnostic) -> &'static str {
    if diagnostic.is_failure() {
        "error"
    } else if diagnostic.diagnostic_type == "diff-git-unsafe" {
        "warning"
    } else {
        "note"
    }
}

fn sarif_diagnostic_locations(diagnostic: &RunDiagnostic) -> Option<Value> {
    diagnostic.file_path.as_ref().map(|file_path| {
        json!([
            {
                "physicalLocation": sarif_physical_location_from_parts(
                    file_path,
                    diagnostic.line,
                    None,
                    None,
                ),
            },
        ])
    })
}

fn sarif_result(finding: &Finding, rule_indices: &HashMap<String, usize>) -> Value {
    let mut result = json!({
        "ruleId": &finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": {
            "text": &finding.message,
        },
        "locations": sarif_result_locations(finding),
        "partialFingerprints": {
            "gruffFingerprint": &finding.fingerprint,
        },
        "properties": sarif_result_properties(finding),
    });
    if let Some(rule_index) = rule_indices.get(finding.rule_id.as_str()) {
        result["ruleIndex"] = json!(rule_index);
    }
    result
}

fn sarif_suppressed_result(
    suppressed: &SuppressedFinding,
    rule_indices: &HashMap<String, usize>,
) -> Value {
    let mut result = sarif_result(&suppressed.finding, rule_indices);
    if let Value::Object(result_object) = &mut result {
        result_object.insert(
            "suppressions".to_string(),
            json!([
                {
                    "kind": "external",
                    "justification": &suppressed.suppression.reason,
                },
            ]),
        );
    }
    result
}

fn sarif_rule_from_finding(finding: &Finding) -> Value {
    json!({
        "id": &finding.rule_id,
        "name": &finding.rule_id,
        "shortDescription": {
            "text": &finding.rule_id,
        },
        "fullDescription": {
            "text": &finding.message,
        },
        "help": {
            "text": &finding.message,
        },
        "defaultConfiguration": {
            "level": sarif_level(finding.severity),
        },
        "properties": {
            "pillar": finding.pillar,
            "tier": &finding.tier,
            "kind": "custom",
            "defaultSeverity": finding.severity,
            "confidence": finding.confidence,
            "defaultEnabled": true,
        },
    })
}

fn sarif_result_locations(finding: &Finding) -> Value {
    json!([
        {
            "physicalLocation": sarif_physical_location_from_parts(
                &finding.file_path,
                finding.line,
                finding.column,
                finding.end_line,
            ),
        },
    ])
}

fn sarif_result_properties(finding: &Finding) -> Value {
    let mut properties = Map::new();
    properties.insert("severity".to_string(), json!(finding.severity));
    properties.insert("pillar".to_string(), json!(finding.pillar));
    properties.insert("tier".to_string(), json!(&finding.tier));
    properties.insert("confidence".to_string(), json!(finding.confidence));
    if !finding.secondary_pillars.is_empty() {
        properties.insert(
            "secondaryPillars".to_string(),
            json!(&finding.secondary_pillars),
        );
    }
    if let Some(symbol) = &finding.symbol {
        properties.insert("symbol".to_string(), json!(symbol));
    }
    if let Some(remediation) = &finding.remediation {
        properties.insert("remediation".to_string(), json!(remediation));
    }
    if !finding.metadata.is_null() {
        properties.insert("metadata".to_string(), finding.metadata.clone());
    }
    Value::Object(properties)
}

pub(crate) fn sarif_physical_location_from_parts(
    file_path: &str,
    line: Option<usize>,
    column: Option<usize>,
    end_line: Option<usize>,
) -> Value {
    let mut location = Map::new();
    location.insert(
        "artifactLocation".to_string(),
        json!({
            "uri": sarif_uri(file_path),
        }),
    );
    if let Some(line) = line {
        let mut region = Map::new();
        region.insert("startLine".to_string(), json!(line));
        if let Some(column) = column {
            region.insert("startColumn".to_string(), json!(column));
        }
        if let Some(end_line) = end_line {
            region.insert("endLine".to_string(), json!(end_line));
        }
        location.insert("region".to_string(), Value::Object(region));
    }
    Value::Object(location)
}

pub(crate) fn sarif_uri(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_start_matches("./");
    let path = if trimmed.is_empty() { "." } else { trimmed };
    let mut encoded = String::new();
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                encoded.push(byte as char);
            }
            _ => {
                push_percent_encoded(&mut encoded, byte);
            }
        }
    }
    encoded
}

fn push_percent_encoded(encoded: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    encoded.push('%');
    encoded.push(HEX[(byte >> 4) as usize] as char);
    encoded.push(HEX[(byte & 0x0F) as usize] as char);
}

pub(super) fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advisory => "note",
    }
}
