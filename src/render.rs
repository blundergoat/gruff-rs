use super::*;

#[cfg(test)]
pub(crate) fn render_report(report: &AnalysisReport, format: OutputFormat) -> String {
    render_report_with_scope(report, &RequestedScope::default(), format)
}

pub(crate) fn render_report_with_scope(
    report: &AnalysisReport,
    scope: &RequestedScope,
    format: OutputFormat,
) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).expect("report serializes"),
        OutputFormat::Sarif => render_sarif(report),
        OutputFormat::Html => html_report::render(report, scope),
        OutputFormat::Markdown => render_markdown(report),
        OutputFormat::Github => render_github(report),
        OutputFormat::Hotspot => render_hotspot(report),
        OutputFormat::Text => render_text(report),
    }
}

fn render_text(report: &AnalysisReport) -> String {
    let mut output = String::new();
    render_text_header(&mut output, report);
    render_text_diagnostics(&mut output, report);
    render_text_findings(&mut output, report);
    render_text_suppressions(&mut output, report);
    output
}

fn render_text_header(output: &mut String, report: &AnalysisReport) {
    output.push_str(&format!("gruff-rs {}\n", report.tool.version));
    output.push_str(&format!(
        "Score: {:.1} ({}) | Findings: {} advisory, {} warning, {} error\n",
        report.score.composite,
        report.score.grade,
        report.summary.advisory,
        report.summary.warning,
        report.summary.error
    ));
    output.push_str(&format!(
        "Analysed files: {}\n",
        report.paths.analysed_files
    ));
}

fn render_text_diagnostics(output: &mut String, report: &AnalysisReport) {
    if report.diagnostics.is_empty() {
        return;
    }
    output.push_str("\nDiagnostics:\n");
    for diagnostic in &report.diagnostics {
        output.push_str(&format!(
            "- {}: {}{}\n",
            diagnostic.diagnostic_type,
            diagnostic.message,
            diagnostic
                .file_path
                .as_ref()
                .map(|path| format!(" ({path})"))
                .unwrap_or_default()
        ));
    }
}

fn render_text_findings(output: &mut String, report: &AnalysisReport) {
    if report.findings.is_empty() {
        return;
    }
    output.push_str("\nFindings:\n");
    for finding in &report.findings {
        output.push_str(&format!(
            "- [{}] {}:{} {} - {}\n",
            severity_label(finding.severity),
            finding.file_path,
            finding.line.unwrap_or(1),
            finding.rule_id,
            finding.message
        ));
    }
}

fn render_text_suppressions(output: &mut String, report: &AnalysisReport) {
    let suppressed = total_suppressed_findings(&report.suppressions);
    if suppressed == 0 {
        return;
    }
    let details = report
        .suppressions
        .iter()
        .filter(|summary| summary.suppressed > 0)
        .map(|summary| {
            format!(
                "exclude[{}] {}: {} ({})",
                summary.index, summary.rule, summary.suppressed, summary.reason
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    output.push_str(&format!(
        "\nSuppressed findings: {suppressed} via {details}\n"
    ));
}

pub(crate) fn total_suppressed_findings(suppressions: &[SuppressionSummary]) -> usize {
    suppressions.iter().map(|summary| summary.suppressed).sum()
}

fn render_markdown(report: &AnalysisReport) -> String {
    let mut output = format!(
        "# gruff-rs report\n\nScore: **{:.1} ({})**\n\nFindings: {} advisory, {} warning, {} error.\n",
        report.score.composite,
        report.score.grade,
        report.summary.advisory,
        report.summary.warning,
        report.summary.error
    );
    for finding in report.findings.iter().take(50) {
        output.push_str(&format!(
            "\n- `{}` `{}`:{} - {}",
            finding.rule_id,
            finding.file_path,
            finding.line.unwrap_or(1),
            finding.message
        ));
    }
    output
}

fn render_github(report: &AnalysisReport) -> String {
    report
        .findings
        .iter()
        .map(|finding| {
            format!(
                "::{} file={},line={},title={}::{}",
                github_level(finding.severity),
                finding.file_path,
                finding.line.unwrap_or(1),
                escape_command(&finding.rule_id),
                escape_command(&finding.message)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_hotspot(report: &AnalysisReport) -> String {
    serde_json::to_string_pretty(&json!({
        "schemaVersion": "gruff.hotspot.v1",
        "tool": report.tool,
        "score": report.score.composite,
        "files": report.score.top_offenders,
    }))
    .expect("hotspot serializes")
}

fn render_sarif(report: &AnalysisReport) -> String {
    let registry = rules::builtin_registry();
    let rule_indices = sarif_rule_indices(&registry);
    let rules: Vec<Value> = registry.definitions().iter().map(sarif_rule).collect();
    let results = sarif_results(report, &rule_indices);

    serde_json::to_string_pretty(&sarif_document(report, &rules, &results))
        .expect("sarif serializes")
}

fn sarif_rule_indices(registry: &rules::RuleRegistry) -> HashMap<&str, usize> {
    registry
        .definitions()
        .iter()
        .enumerate()
        .map(|(index, definition)| (definition.id, index))
        .collect()
}

fn sarif_results(report: &AnalysisReport, rule_indices: &HashMap<&str, usize>) -> Vec<Value> {
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

fn sarif_rule(definition: &rules::RuleDefinition) -> Value {
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

fn sarif_result(finding: &Finding, rule_indices: &HashMap<&str, usize>) -> Value {
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
    rule_indices: &HashMap<&str, usize>,
) -> Value {
    let mut result = sarif_result(&suppressed.finding, rule_indices);
    if let Value::Object(result_object) = &mut result {
        result_object.insert(
            "suppressions".to_string(),
            json!([
                {
                    "kind": "inSource",
                    "justification": &suppressed.suppression.reason,
                },
            ]),
        );
    }
    result
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

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advisory => "note",
    }
}

fn github_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advisory => "notice",
    }
}

fn escape_command(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\n', "%0A")
        .replace('\r', "%0D")
}

pub(crate) fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
