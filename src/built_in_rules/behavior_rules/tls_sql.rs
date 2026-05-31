use super::*;

static SQL_DYNAMIC_QUERY_REGEX: OnceLock<Regex> = OnceLock::new();
static TLS_VERIFICATION_DISABLED_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_tls_verification_disabled(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    let direct_regex = static_regex(
        &TLS_VERIFICATION_DISABLED_REGEX,
        r"\.(?:danger_accept_invalid_certs|accept_invalid_hostnames)\s*\(\s*true\s*\)",
    );
    let true_bindings = true_boolean_bindings(&searchable);
    for (line_index, line) in searchable.lines().enumerate() {
        if direct_regex.is_match(line) || tls_bypass_uses_true_binding(line, &true_bindings) {
            findings.push(tls_verification_disabled_finding(file, line_index + 1));
        }
    }
}

fn tls_verification_disabled_finding(file: &SourceFile, line: usize) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "security.tls-verification-disabled".to_string(),
        message: "TLS certificate or hostname verification is explicitly disabled.".to_string(),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: None,
        remediation: Some(
            "Remove the TLS verification bypass or gate it behind non-production test code."
                .to_string(),
        ),
        metadata: json!({}),
    })
}

fn true_boolean_bindings(source: &str) -> BTreeSet<String> {
    static TRUE_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &TRUE_BINDING_REGEX,
        r"\blet\s+(?P<name>[a-z_][a-z0-9_]*)\s*(?::[^=]+)?=\s*true\s*;",
    );
    regex
        .captures_iter(source)
        .filter_map(|captures| captures.name("name").map(|name| name.as_str().to_string()))
        .collect()
}

fn tls_bypass_uses_true_binding(line: &str, true_bindings: &BTreeSet<String>) -> bool {
    static TLS_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &TLS_BINDING_REGEX,
        r"\.(?:danger_accept_invalid_certs|accept_invalid_hostnames)\s*\(\s*(?P<arg>[a-z_][a-z0-9_]*)\s*\)",
    );
    regex
        .captures(line)
        .and_then(|captures| captures.name("arg"))
        .is_some_and(|arg| true_bindings.contains(arg.as_str()))
}

pub(crate) fn analyse_sql_dynamic_query(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    let regex = static_regex(
        &SQL_DYNAMIC_QUERY_REGEX,
        r"(?:^|[^\w])(?P<method>query|execute|prepare)\s*\(\s*&?\s*format!\s*\(",
    );
    let starts = line_starts(source);
    let mut emitted = BTreeSet::new();
    for captures in regex.captures_iter(&searchable) {
        let Some(full_match) = captures.get(0) else {
            continue;
        };
        let method = captures
            .name("method")
            .map(|method| method.as_str())
            .unwrap_or("query");
        let line = byte_line_from_starts(&starts, full_match.start());
        if emitted.insert(line) {
            findings.push(sql_dynamic_query_finding(file, line, method));
        }
    }

    let dynamic_bindings = dynamic_sql_bindings(&searchable);
    for (line_index, line) in searchable.lines().enumerate() {
        let Some((method, binding)) = sql_sink_binding(line) else {
            continue;
        };
        if !dynamic_bindings.contains(binding) {
            continue;
        }
        let line_number = line_index + 1;
        if emitted.insert(line_number) {
            findings.push(sql_dynamic_query_finding(file, line_number, method));
        }
    }
}

fn sql_dynamic_query_finding(file: &SourceFile, line: usize, method: &str) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "security.sql-dynamic-query".to_string(),
        message: format!(
            "Direct dynamic SQL argument passed to `{method}(...)`; review query construction."
        ),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: Some(method.to_string()),
        remediation: Some(
            "Use static SQL with bind parameters instead of formatting query text. If the formatted query is non-production (test fixture, migration scratch), add the host path to `paths.ignore` in `.gruff-rs.yaml`."
                .to_string(),
        ),
        metadata: json!({ "method": method }),
    })
}

fn dynamic_sql_bindings(source: &str) -> BTreeSet<String> {
    static SQL_FORMAT_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &SQL_FORMAT_BINDING_REGEX,
        r"\blet\s+(?P<name>[a-z_][a-z0-9_]*)\s*(?::[^=]+)?=\s*&?\s*format!\s*\(",
    );
    regex
        .captures_iter(source)
        .filter_map(|captures| captures.name("name").map(|name| name.as_str().to_string()))
        .collect()
}

fn sql_sink_binding(line: &str) -> Option<(&str, &str)> {
    static SQL_BINDING_SINK_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &SQL_BINDING_SINK_REGEX,
        r"(?:^|[^\w])(?P<method>query|execute|prepare)\s*\(\s*&?\s*(?P<arg>[a-z_][a-z0-9_]*)\s*\)",
    );
    let captures = regex.captures(line)?;
    Some((
        captures.name("method")?.as_str(),
        captures.name("arg")?.as_str(),
    ))
}
