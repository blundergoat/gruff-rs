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
    // `let x = true;` bindings are tracked only within the function currently being
    // scanned: a new `fn` clears the set, and a binding counts only once it has
    // appeared above the sink. This stops a `true` binding in one function from
    // flagging a same-named parameter or shadowed binding in another (false positive).
    let mut true_bindings: BTreeSet<String> = BTreeSet::new();
    for (line_index, line) in searchable.lines().enumerate() {
        if is_function_start_line(line) {
            true_bindings.clear();
        }
        // Track which locals are currently bound to `true`. A later `let name = false;`
        // (or any non-`true` rebinding) clears it, so a shadowed binding no longer
        // looks like an explicit bypass at the sink.
        if let Some((name, is_true)) = boolean_let_binding(line) {
            if is_true {
                true_bindings.insert(name);
            } else {
                true_bindings.remove(&name);
            }
        }
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

/// A line that opens a function body (`fn name`), used to scope `true` bindings to
/// a single function so they cannot leak into a later, unrelated function.
fn is_function_start_line(line: &str) -> bool {
    static FUNCTION_START_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(&FUNCTION_START_REGEX, r"\bfn\s+[A-Za-z_]").is_match(line)
}

/// A `let name = <value>;` binding on this line: returns `(name, value_is_true)`.
/// Used to insert `true` bindings and to clear them when the same name is rebound
/// to a non-`true` value within the function.
fn boolean_let_binding(line: &str) -> Option<(String, bool)> {
    static LET_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &LET_BINDING_REGEX,
        r"\blet\s+(?P<name>[a-z_][a-z0-9_]*)\s*(?::[^=]+)?=\s*(?P<value>[^;]+);",
    );
    let captures = regex.captures(line)?;
    let name = captures.name("name")?.as_str().to_string();
    let value = captures.name("value")?.as_str().trim();
    Some((name, value == "true"))
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

    // Track format!-bound locals per function (cleared at each `fn`, inserted only
    // once seen above the sink) so a dynamic binding in one function cannot flag a
    // same-named static or parameter binding in another - mirroring the TLS path.
    let mut dynamic_bindings: BTreeSet<String> = BTreeSet::new();
    for (line_index, line) in searchable.lines().enumerate() {
        if is_function_start_line(line) {
            dynamic_bindings.clear();
        }
        if let Some(name) = dynamic_format_binding_name(line) {
            dynamic_bindings.insert(name);
        }
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

fn dynamic_format_binding_name(line: &str) -> Option<String> {
    static SQL_FORMAT_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &SQL_FORMAT_BINDING_REGEX,
        r"\blet\s+(?P<name>[a-z_][a-z0-9_]*)\s*(?::[^=]+)?=\s*&?\s*format!\s*\(",
    );
    regex
        .captures(line)
        .and_then(|captures| captures.name("name").map(|name| name.as_str().to_string()))
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
