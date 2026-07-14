//! Network-facing security rules inspect executable Rust for exposed listeners,
//! tainted requests and deserialization, dangerous XML options, and raw template output.
//! Operators reach these checks during ordinary project scans, including test and CI source.

use super::*;

pub(crate) static BIND_ALL_INTERFACES_REGEX: OnceLock<Regex> = OnceLock::new();

/// `security.hardcoded-bind-all-interfaces` — flags listener address
/// literals that bind to every network interface, optionally followed
/// by a port, in production and executable test source.
pub(crate) fn analyse_hardcoded_bind_all_interfaces(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let lines: Vec<&str> = source.lines().collect();
    let starts = line_starts(source);
    // Each all-interface literal becomes one reviewable exposure in the user's report.
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

/// Flag caller-derived request URLs even when the executable path belongs to a test or CI helper.
pub(crate) fn analyse_ssrf_candidate(
    file: &SourceFile,
    blocks: &[FunctionBlock],
    findings: &mut Vec<Finding>,
) {
    // Each function keeps input evidence local so one helper cannot implicate another.
    for block in blocks {
        let mut taint = FunctionTaint::from_block(block);
        // Each source line can validate an input or carry it into a supported request sink.
        for (line_index, line) in block.body.lines().enumerate() {
            taint.observe_line(line);
            // A line without a tainted URL sink adds nothing to the user's security report.
            let Some(argument) = ssrf_sink_argument(line, &taint) else {
                continue;
            };
            findings.push(network_candidate_finding(
                file,
                "security.ssrf-candidate",
                "HTTP request URL is derived from local input; review host allow-listing.",
                block.start_line + line_index,
                &argument,
            ));
        }
    }
}

pub(crate) fn analyse_unsafe_deserialization(
    file: &SourceFile,
    blocks: &[FunctionBlock],
    findings: &mut Vec<Finding>,
) {
    for block in blocks {
        let mut taint = FunctionTaint::from_block(block);
        for (line_index, line) in block.body.lines().enumerate() {
            taint.observe_line(line);
            if yaml_config_parse_is_intentional(block, line) {
                continue;
            }
            let Some(argument) = unsafe_deserialization_argument(line, &taint) else {
                continue;
            };
            findings.push(network_candidate_finding(
                file,
                "security.unsafe-deserialization",
                "Binary or YAML deserialization reads data derived from local input.",
                block.start_line + line_index,
                &argument,
            ));
        }
    }
}

pub(crate) fn analyse_xxe_candidate(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    for (line_index, line) in searchable.lines().enumerate() {
        if line.contains("ParserOption::NOENT")
            || line.contains("ParserOption::DTDLOAD")
            || line.contains(".resolve_entities(true)")
        {
            findings.push(network_candidate_finding(
                file,
                "security.xxe-candidate",
                "XML parser configuration enables external entity or DTD resolution.",
                line_index + 1,
                "xml-parser",
            ));
        }
    }
}

pub(crate) fn analyse_template_injection_xss(
    file: &SourceFile,
    blocks: &[FunctionBlock],
    findings: &mut Vec<Finding>,
) {
    for block in blocks {
        let mut taint = FunctionTaint::from_block(block);
        for (line_index, line) in block.body.lines().enumerate() {
            taint.observe_line(line);
            let Some(argument) = template_sink_argument(line, &taint) else {
                continue;
            };
            findings.push(network_candidate_finding(
                file,
                "security.template-injection-xss",
                "HTML or template output includes request-derived data without local escaping evidence.",
                block.start_line + line_index,
                &argument,
            ));
        }
    }
}

#[derive(Default)]
struct FunctionTaint {
    tainted: BTreeSet<String>,
    validated: BTreeSet<String>,
}

impl FunctionTaint {
    fn from_block(block: &FunctionBlock) -> Self {
        Self {
            tainted: function_param_names(&block.body)
                .into_iter()
                .filter(|name| !name_is_sanitized(name))
                .collect(),
            validated: BTreeSet::new(),
        }
    }

    fn observe_line(&mut self, line: &str) {
        for name in self.tainted.clone() {
            if line_has_validation_evidence(line, &name) || name_is_sanitized(&name) {
                self.validated.insert(name);
            }
        }
        if let Some((binding, rhs)) = let_binding(line) {
            if binding_name_is_predicate(&binding) {
                return;
            }
            self.observe_binding(binding, rhs);
        }
    }

    fn observe_binding(&mut self, binding: String, rhs: &str) {
        if rhs_is_input_source(rhs) || self.tainted.iter().any(|name| rhs_contains_name(rhs, name))
        {
            if name_is_sanitized(&binding) || line_has_validation_evidence(rhs, &binding) {
                self.validated.insert(binding.clone());
            }
            self.tainted.insert(binding);
        }
    }

    fn is_tainted(&self, name: &str) -> bool {
        self.tainted.contains(name) && !self.validated.contains(name) && !name_is_sanitized(name)
    }
}

fn function_param_names(body: &str) -> Vec<String> {
    static SIGNATURE_REGEX: OnceLock<Regex> = OnceLock::new();
    static PARAM_REGEX: OnceLock<Regex> = OnceLock::new();
    let signature = static_regex(
        &SIGNATURE_REGEX,
        r"fn\s+[A-Za-z_][A-Za-z0-9_]*\s*\((?P<params>(?s:.*?))\)",
    );
    let param = static_regex(
        &PARAM_REGEX,
        r"(?:^|,)\s*(?:mut\s+)?(?P<name>[a-z_][a-z0-9_]*)\s*:",
    );
    let Some(params) = signature
        .captures(body)
        .and_then(|captures| captures.name("params"))
    else {
        return Vec::new();
    };
    param
        .captures_iter(params.as_str())
        .filter_map(|captures| captures.name("name").map(|name| name.as_str().to_string()))
        .collect()
}

/// Return a named local assignment that can carry input evidence to a later security sink.
fn let_binding(line: &str) -> Option<(String, &str)> {
    static LET_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &LET_BINDING_REGEX,
        r"\blet\s+(?:mut\s+)?(?P<name>[a-z_][a-z0-9_]*)\s*(?::[^=]+)?=\s*(?P<rhs>[^;]+)",
    );
    // Lines without a local assignment cannot carry input into a later sink.
    let captures = regex.captures(line)?;
    // A matched assignment must expose both sides before it can extend the input trail.
    let binding = captures.name("name")?.as_str();
    let right_hand_side = captures.name("rhs")?.as_str();
    // A discarded result cannot flow into a later sink, so it has no taint identity to retain.
    (binding != "_").then(|| (binding.to_string(), right_hand_side))
}

fn rhs_is_input_source(rhs: &str) -> bool {
    rhs.contains("std::env::var")
        || rhs.contains("env::var")
        || rhs.contains(".uri()")
        || rhs.contains(".query(")
        || rhs.contains(".headers(")
        || rhs.contains(".path(")
}

fn rhs_contains_name(rhs: &str, name: &str) -> bool {
    let pattern = format!(r"\b{}\b", regex::escape(name));
    Regex::new(&pattern)
        .map(|compiled| compiled.is_match(rhs))
        .unwrap_or(false)
}

fn line_has_validation_evidence(line: &str, name: &str) -> bool {
    line_uses_url_validation(line, name)
        || line_uses_allowlist(line, name)
        || line_uses_html_escape(line, name)
}

fn line_uses_url_validation(line: &str, name: &str) -> bool {
    (line.contains("Url::parse") || line.contains("validate_url")) && rhs_contains_name(line, name)
}

fn line_uses_allowlist(line: &str, name: &str) -> bool {
    (line.contains("allowed_host") || line.contains("allowlist")) && rhs_contains_name(line, name)
}

fn line_uses_html_escape(line: &str, name: &str) -> bool {
    (line.contains("html_escape") || line.contains("escape_html")) && rhs_contains_name(line, name)
}

fn binding_name_is_predicate(name: &str) -> bool {
    name.starts_with("has_")
        || name.starts_with("is_")
        || name.starts_with("does_")
        || name.starts_with("can_")
        || name.starts_with("should_")
        || name.starts_with("contains_")
        || name.starts_with("matches_")
}

fn name_is_sanitized(name: &str) -> bool {
    name.contains("safe")
        || name.contains("sanitized")
        || name.contains("validated")
        || name.contains("allowed")
        || name.contains("escaped")
}

fn ssrf_sink_argument(line: &str, taint: &FunctionTaint) -> Option<String> {
    static SSRF_SINK_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &SSRF_SINK_REGEX,
        r"(?:reqwest::get|(?:client|http_client)\.(?:get|post|put|delete)|\.uri|hyper::Uri::from_maybe_shared)\s*\(\s*&?(?P<arg>[a-z_][a-z0-9_]*)",
    );
    let argument = regex.captures(line)?.name("arg")?.as_str();
    taint.is_tainted(argument).then(|| argument.to_string())
}

fn unsafe_deserialization_argument(line: &str, taint: &FunctionTaint) -> Option<String> {
    static DESERIALIZATION_SINK_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &DESERIALIZATION_SINK_REGEX,
        r"(?:serde_yaml::from_(?:str|reader|slice)|bincode::(?:deserialize|deserialize_from)|rmp_serde::from_(?:slice|read)|serde_pickle::from_(?:slice|reader))\s*\(\s*&?(?P<arg>[a-z_][a-z0-9_]*)",
    );
    let argument = regex.captures(line)?.name("arg")?.as_str();
    taint.is_tainted(argument).then(|| argument.to_string())
}

fn yaml_config_parse_is_intentional(block: &FunctionBlock, line: &str) -> bool {
    line.contains("serde_yaml::from_str")
        && (block.name.contains("config") || block.name.contains("yaml"))
}

fn template_sink_argument(line: &str, taint: &FunctionTaint) -> Option<String> {
    if line.contains("html_escape") || line.contains("escape_html") || line.contains("| escape") {
        return None;
    }
    let has_sink = line.contains("Html(format!")
        || line.contains(".body(format!")
        || line.contains("PreEscaped(format!")
        || line.contains("Markup::new(format!")
        || line.contains("render_str(");
    if !has_sink {
        return None;
    }
    taint
        .tainted
        .iter()
        .find(|name| taint.is_tainted(name) && rhs_contains_name(line, name))
        .cloned()
}

fn network_candidate_finding(
    file: &SourceFile,
    rule_id: &str,
    message: &str,
    line: usize,
    argument: &str,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: message.to_string(),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::Medium,
        symbol: Some(argument.to_string()),
        remediation: Some(
            "Validate, constrain, or escape untrusted input at the boundary before passing it to the sink."
                .to_string(),
        ),
        metadata: json!({ "candidate": true, "argument": argument }),
    })
}
