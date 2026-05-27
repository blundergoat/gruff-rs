use super::*;

pub(crate) static BIND_ALL_INTERFACES_REGEX: OnceLock<Regex> = OnceLock::new();

/// `security.hardcoded-bind-all-interfaces` — flags listener address
/// literals that bind to every network interface, optionally followed
/// by a port. Skips test infrastructure and doc-comment lines.
pub(crate) fn analyse_hardcoded_bind_all_interfaces(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    if path_is_test_infrastructure(&file.display_path) {
        return;
    }
    let lines: Vec<&str> = source.lines().collect();
    let starts = line_starts(source);
    for capture in bind_all_interfaces_regex().captures_iter(source) {
        record_bind_capture(file, &capture, &lines, &starts, findings);
    }
}

fn record_bind_capture(
    file: &SourceFile,
    capture: &regex::Captures<'_>,
    lines: &[&str],
    starts: &[usize],
    findings: &mut Vec<Finding>,
) {
    let Some(full) = capture.get(0) else {
        return;
    };
    let line = byte_line_from_starts(starts, full.start());
    if line_is_doc_or_comment(lines, line) {
        return;
    }
    let addr = capture.name("addr").map_or("", |matched| matched.as_str());
    if addr.is_empty() {
        return;
    }
    findings.push(bind_all_interfaces_finding(file, line, addr));
}

fn bind_all_interfaces_regex() -> &'static Regex {
    static_regex(
        &BIND_ALL_INTERFACES_REGEX,
        r#""(?P<addr>0\.0\.0\.0|\[::\]|::0)(?::\d+|/\d+)?""#,
    )
}

fn line_is_doc_or_comment(lines: &[&str], line: usize) -> bool {
    if line == 0 {
        return false;
    }
    let Some(text) = lines.get(line - 1) else {
        return false;
    };
    let trimmed = text.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with("/*")
}

fn bind_all_interfaces_finding(file: &SourceFile, line: usize, addr: &str) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "security.hardcoded-bind-all-interfaces".to_string(),
        message: format!(
            "Listener address `{addr}` binds to every network interface; review whether the bind should be restricted."
        ),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: None,
        remediation: Some(
            "Bind to a loopback address for local-only servers, or gate the all-interfaces bind behind a deployment flag. If the bind is in a test harness or build script, add the host path to `paths.ignore` in `.gruff-rs.yaml`."
                .to_string(),
        ),
        metadata: json!({ "address": addr }),
    })
}
