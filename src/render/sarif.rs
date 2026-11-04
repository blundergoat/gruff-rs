use super::*;

/// Render a whole analysis report as a pretty-printed SARIF 2.1.0 log.
///
/// `report` supplies the active and suppressed findings, diagnostics and score; the rule table also holds every built-in registry rule.
/// Returns the JSON text; it panics through `expect` only if `serde_json` cannot serialize the assembled value.
pub(super) fn render_sarif(report: &AnalysisReport) -> String {
    let (rules, rule_indices) = sarif_rules_and_indices(report);
    let results = sarif_results(report, &rule_indices);

    serde_json::to_string_pretty(&sarif_document(report, &rules, &results))
        .expect("sarif serializes")
}

/// Build the SARIF rule table: every built-in rule, then one entry per rule id that only the report's findings use, in rule id order.
///
/// `report` supplies the active and suppressed findings whose rule ids the built-in registry does not know.
/// Returns the rule descriptors and a map from each rule id to its position in that list, which results use as `ruleIndex`.
fn sarif_rules_and_indices(report: &AnalysisReport) -> (Vec<Value>, HashMap<String, usize>) {
    let (mut rules, mut indices) = sarif_builtin_rules_and_indices();
    for finding in unique_custom_findings(report, &indices) {
        let index = rules.len();
        indices.insert(finding.rule_id.clone(), index);
        rules.push(sarif_rule_from_finding(finding));
    }
    (rules, indices)
}

/// Describe every rule in the built-in registry as a SARIF rule descriptor.
///
/// Returns the descriptors in registry order and a map from each rule id to its index in that list.
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

/// Pick one representative finding for each rule id that the rule table does not describe yet.
///
/// `report` supplies both active and suppressed findings, and `indices` maps the rule ids already in the rule table, which are skipped.
/// Returns the findings sorted by rule id, one per id, keeping the earliest so an active finding is preferred over a suppressed one.
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

/// Convert every finding in the report into a SARIF result, active findings first and suppressed findings after them.
///
/// `report` supplies the findings, and `rule_indices` maps rule ids to their rule table positions for each result's `ruleIndex`.
/// Returns the results in that order; each suppressed one also carries a `suppressions` entry.
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

/// Assemble the SARIF 2.1.0 log object with one run around the given rule table and results.
///
/// `report` supplies the driver name and version, the invocation diagnostics, and the schema version, timestamp, score and grade properties.
/// `rules` becomes the driver's rule list and `results` the run's results, both copied in as given.
///
/// Returns the complete log as a JSON value.
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

/// Describe one rule definition as a SARIF reporting descriptor.
///
/// `definition` gives the id, the name used as short description, the description used as full description and help, and the default severity.
/// Returns the descriptor JSON with its default level and the gruff rule properties built by `sarif_rule_properties`.
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

/// Collect a rule definition's gruff-specific metadata for its SARIF `properties` bag.
///
/// `definition` supplies pillar, tier, kind, default severity, confidence and default enablement, and any threshold default or options.
/// Returns a JSON object that leaves out `threshold` when the rule has none and `options` when it declares no options.
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

/// Describe the run's single invocation from the report's diagnostics.
///
/// `report` supplies the diagnostics, each of which becomes a tool execution notification.
/// Returns the invocation JSON, whose `executionSuccessful` is false when any diagnostic is a failure.
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

/// Turn one run diagnostic into a SARIF tool execution notification.
///
/// `diagnostic` supplies the descriptor id from its type, the level, the message text and, when it names a file, a location.
/// Returns the notification JSON, with no `locations` key when the diagnostic has no file path.
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

/// Choose the SARIF notification level for a run diagnostic.
///
/// `diagnostic` is classified by whether it is a failure and then by its type.
/// Returns `error` for a failure, `warning` for a `diff-git-unsafe` diagnostic, and `note` for anything else.
fn sarif_diagnostic_level(diagnostic: &RunDiagnostic) -> &'static str {
    if diagnostic.is_failure() {
        "error"
    } else if diagnostic.diagnostic_type == "diff-git-unsafe" {
        "warning"
    } else {
        "note"
    }
}

/// Build the location list for a run diagnostic that points at a file.
///
/// `diagnostic` supplies the file path and optional line; it has no column or end line to report.
/// Returns a one-element array holding the physical location, or None when the diagnostic has no file path.
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

/// Convert one finding into a SARIF result.
///
/// `finding` supplies the rule id, level, message, location and properties; `rule_indices` maps rule ids to positions in the rule table.
///
/// Returns the result JSON; it adds `partialFingerprints` only when `sarif_partial_fingerprints` yields a fingerprint.
/// It adds `ruleIndex` only when `rule_indices` holds the finding's rule id.
fn sarif_result(finding: &Finding, rule_indices: &HashMap<String, usize>) -> Value {
    let mut result = json!({
        "ruleId": &finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": {
            "text": &finding.message,
        },
        "locations": sarif_result_locations(finding),
        "properties": sarif_result_properties(finding),
    });
    // gruffFingerprint is the ratified durable identity, so an alert survives a line move while a second
    // declaration of one name opens its own alert. A sensitive finding has none, so it carries no key at all:
    // publishing one would give a secret a stable name in a system gruff does not control.
    if let Some(fingerprints) = sarif_partial_fingerprints(finding) {
        result["partialFingerprints"] = fingerprints;
    }
    if let Some(rule_index) = rule_indices.get(finding.rule_id.as_str()) {
        result["ruleIndex"] = json!(rule_index);
    }
    result
}

/// Project one finding into the fingerprints GitHub code scanning groups its alerts by.
///
/// `gruffFingerprint` is the ratified durable identity and nothing else; as the run assigns it, an alert survives a line move while a
/// second declaration of one name opens its own alert. A sensitive finding has no identity at all and therefore
/// carries no key: publishing one would give a secret a stable name in a system gruff does not control.
///
/// The run names every finding before the baseline filters any; a finding built outside that pipeline is named
/// here from `finding` alone, ranked by its own line; one the naming helper gives no identity still goes out without a fingerprint.
///
/// Returns a `gruffFingerprint` object holding the finding's baseline identity when it has one, otherwise the identity named here.
/// Returns None when naming the finding errors or gives it no identity, as for a sensitive finding.
fn sarif_partial_fingerprints(finding: &Finding) -> Option<Value> {
    if let Some(identity) = finding.baseline_identity.as_deref() {
        return Some(json!({ "gruffFingerprint": identity }));
    }
    let identities =
        finding_identities(std::slice::from_ref(finding), &declaration_position_by_line).ok()?;
    let named = identities.into_iter().next().flatten()?;
    Some(json!({ "gruffFingerprint": named.identity }))
}

/// Convert a suppressed finding into a SARIF result that records why it was suppressed.
///
/// `suppressed` supplies the finding and its suppression, and `rule_indices` maps rule ids to positions in the rule table.
///
/// Returns the result `sarif_result` builds plus one `suppressions` entry whose justification is the suppression reason.
/// The entry's kind is `inSource` for an inline suppression and `external` for any other source.
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
                    // A configured exclusion lives outside the source; another tool's attribute or comment is in it.
                    "kind": if suppressed.suppression.source == Some("inline") { "inSource" } else { "external" },
                    "justification": &suppressed.suppression.reason,
                },
            ]),
        );
    }
    result
}

/// Describe a rule the built-in registry does not know, from one of its findings plus fixed custom-rule defaults.
///
/// `finding` supplies the rule id used as id, name and short description, the message used as full description and help, and severity.
/// Returns a descriptor with kind `custom`, `defaultEnabled` true, and pillar, tier and confidence copied from `finding`.
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

/// Build the location list for a finding's SARIF result.
///
/// `finding` supplies the file path, line, column and end line.
/// Returns a one-element array holding that physical location.
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

/// Collect a finding's gruff-specific fields for its SARIF result `properties` bag.
///
/// `finding` always gives severity, pillar, tier and confidence, and adds secondary pillars, symbol, remediation and metadata when set.
/// Returns the JSON object; secondary pillars are left out when empty, symbol and remediation when absent, and metadata when null.
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

/// Build a SARIF physical location from a file path and optional position parts.
///
/// `file_path` becomes the artifact location URI through `sarif_uri`, and `line` becomes the region's start line.
/// `column` and `end_line` add the region's start column and end line, but only when `line` is present.
///
/// Returns the location JSON, with no `region` at all when `line` is None.
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

/// Turn a report file path into the percent-encoded URI form that SARIF artifact locations use.
///
/// `path` has backslashes turned into slashes and every leading `./` removed; a path left empty becomes `.`.
/// Returns the path with each byte outside ASCII letters, digits, `-`, `.`, `_`, `~` and `/` written as an uppercase `%XX` escape.
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

/// Append one byte to a URI under construction as a percent escape.
///
/// `encoded` is the URI being built and gains `%` followed by two uppercase hex digits for `byte`.
fn push_percent_encoded(encoded: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    encoded.push('%');
    encoded.push(HEX[(byte >> 4) as usize] as char);
    encoded.push(HEX[(byte & 0x0F) as usize] as char);
}

/// Map a gruff severity to its SARIF level.
///
/// `severity` is the finding or rule severity to translate.
/// Returns `error` for `Severity::Error`, `warning` for `Severity::Warning` and `note` for `Severity::Advisory`.
pub(super) fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advisory => "note",
    }
}
