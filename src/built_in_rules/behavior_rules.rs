use super::*;

static PROCESS_SHELL_INTERPRETER_REGEX: OnceLock<Regex> = OnceLock::new();
static PROCESS_SHELL_ARG_REGEX: OnceLock<Regex> = OnceLock::new();
static PROCESS_DYNAMIC_EXECUTABLE_REGEX: OnceLock<Regex> = OnceLock::new();
static PROCESS_DYNAMIC_ARGUMENT_REGEX: OnceLock<Regex> = OnceLock::new();
static INSECURE_RNG_FOR_SECRETS_REGEX: OnceLock<Regex> = OnceLock::new();
static SQL_DYNAMIC_QUERY_REGEX: OnceLock<Regex> = OnceLock::new();
static TLS_VERIFICATION_DISABLED_REGEX: OnceLock<Regex> = OnceLock::new();
static WEAK_CRYPTO_IMPORT_REGEX: OnceLock<Regex> = OnceLock::new();
static WEAK_CRYPTO_CONSTRUCTOR_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_line_rules(
    file: &SourceFile,
    source: &str,
    blocks: &[FunctionBlock],
    findings: &mut Vec<Finding>,
) {
    let source_lines: Vec<&str> = source.lines().collect();
    let searchable_source = strip_rust_string_literals(source);
    let raw_lines: Vec<&str> = searchable_source.lines().collect();
    let code_only_source = strip_rust_comments_after_string_mask(&searchable_source);
    let code_only_lines: Vec<&str> = code_only_source.lines().collect();
    let test_context_ranges: Vec<(usize, usize)> = blocks
        .iter()
        .filter(|block| block.is_test_context())
        .map(|block| (block.start_line, block.start_line + block.line_count))
        .collect();
    let context = LineRuleContext {
        file,
        source_lines: &source_lines,
        raw_lines: &raw_lines,
        code_only_lines: &code_only_lines,
        test_context_ranges: &test_context_ranges,
    };

    for line_index in 0..raw_lines.len() {
        context.analyse_line(line_index, findings);
    }

    analyse_unreachable(file, &code_only_source, findings);
}

pub(crate) struct LineRuleContext<'a> {
    file: &'a SourceFile,
    source_lines: &'a [&'a str],
    raw_lines: &'a [&'a str],
    code_only_lines: &'a [&'a str],
    test_context_ranges: &'a [(usize, usize)],
}

impl LineRuleContext<'_> {
    fn analyse_line(&self, line_index: usize, findings: &mut Vec<Finding>) {
        let line_number = line_index + 1;
        let raw_line = self.raw_lines[line_index];
        let source_line = self.source_lines[line_index];
        let code_only_line = self.code_only_lines[line_index];
        self.analyse_safety_line(raw_line, line_index, line_number, findings);
        self.analyse_waste_line(code_only_line, source_line, line_number, findings);
    }

    fn line_is_in_test_context(&self, line_number: usize) -> bool {
        if file_path_is_test_code(&self.file.display_path) {
            return true;
        }
        self.test_context_ranges
            .iter()
            .any(|(start, end)| line_number >= *start && line_number < *end)
    }
}

/// Returns true when `display_path` lives under a conventional test
/// directory (`tests/`, `src/tests/`) or ends in a `_test`/`_tests`
/// segment. Lets `waste.unwrap-expect` and
/// `waste.unnecessary-clone-candidate` stay silent inside test trees
/// even when individual functions are not marked `#[test]` (a common
/// shape for shared test fixture helpers).
fn file_path_is_test_code(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    if normalized.starts_with("tests/") || normalized.contains("/tests/") {
        return true;
    }
    let stem = std::path::Path::new(&normalized)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    stem.ends_with("_test") || stem.ends_with("_tests")
}

impl LineRuleContext<'_> {
    fn analyse_safety_line(
        &self,
        line: &str,
        line_index: usize,
        line_number: usize,
        findings: &mut Vec<Finding>,
    ) {
        let has_unsafe = static_regex(&UNSAFE_BLOCK_REGEX, r"\bunsafe\s*\{").is_match(line);
        if !has_unsafe {
            return;
        }
        match find_nearby_safety_rationale(self.raw_lines, line_index) {
            None => findings.push(finding(SimpleFindingDescriptor {
                rule_id: "security.unsafe-block",
                message: "Unsafe block lacks a nearby SAFETY rationale.".into(),
                file: self.file,
                line: Some(line_number),
                severity: Severity::Warning,
                pillar: Pillar::Security,
            })),
            Some(rationale) if is_weak_safety_rationale(&rationale) => {
                findings.push(Finding::new(FindingDescriptor {
                        rule_id: "docs.weak-safety-rationale".to_string(),
                        message: format!(
                            "Unsafe block's SAFETY rationale is too short or vague: `{}`.",
                            rationale.trim()
                        ),
                        file_path: self.file.display_path.clone(),
                        line: Some(line_number),
                        severity: Severity::Advisory,
                        pillar: Pillar::Documentation,
                        confidence: Confidence::Medium,
                        symbol: None,
                        remediation: Some(
                            "Explain the invariants the caller must uphold or why the operation is sound."
                                .to_string(),
                        ),
                        metadata: json!({ "rationale": rationale.trim() }),
                    }));
            }
            Some(_) => {}
        }
    }

    fn analyse_waste_line(
        &self,
        line: &str,
        raw_line: &str,
        line_number: usize,
        findings: &mut Vec<Finding>,
    ) {
        if static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(").is_match(line)
            && !expect_has_substantive_rationale(raw_line)
            && !line.contains("#[test]")
            && !self.line_is_in_test_context(line_number)
        {
            findings.push(finding(SimpleFindingDescriptor {
                rule_id: "waste.unwrap-expect",
                message: "unwrap()/expect() can turn recoverable errors into panics.".into(),
                file: self.file,
                line: Some(line_number),
                severity: Severity::Advisory,
                pillar: Pillar::Maintainability,
            }));
        }

        if static_regex(&CLONE_CALL_REGEX, r"\.clone\(\)").is_match(line)
            && !clone_is_consumed_or_owned(line)
            && !line.contains("#[test]")
            && !self.line_is_in_test_context(line_number)
        {
            findings.push(finding(SimpleFindingDescriptor {
                rule_id: "waste.unnecessary-clone-candidate",
                message: "clone() call may be avoidable; confirm ownership requires it.".into(),
                file: self.file,
                line: Some(line_number),
                severity: Severity::Advisory,
                pillar: Pillar::Maintainability,
            }));
        }
    }
}

pub(crate) fn analyse_process_commands(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let command_regex = static_regex(
        &PROCESS_COMMAND_REGEX,
        r"(std::process::Command|Command)::new\s*\(",
    );
    let searchable = strip_rust_string_literals(source);
    let searchable_lines: Vec<&str> = searchable.lines().collect();
    let source_lines: Vec<&str> = source.lines().collect();
    for (line_index, line) in searchable_lines.iter().enumerate() {
        if command_regex.is_match(line) {
            let raw_window = line_window(&source_lines, line_index);
            let searchable_window = line_window(&searchable_lines, line_index);
            if process_command_is_returned_builder(&source_lines, line_index)
                || process_command_is_fixed_taskkill_cleanup(&raw_window)
            {
                continue;
            }
            let risk_signals = process_command_risk_signals(&raw_window, &searchable_window);
            if risk_signals.is_empty() {
                continue;
            }
            push_process_command_finding(file, line_index + 1, risk_signals, findings);
        }
    }
}

pub(crate) fn analyse_tls_verification_disabled(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    let regex = static_regex(
        &TLS_VERIFICATION_DISABLED_REGEX,
        r"\.(?:danger_accept_invalid_certs|accept_invalid_hostnames)\s*\(\s*true\s*\)",
    );
    for (line_index, line) in searchable.lines().enumerate() {
        if regex.is_match(line) {
            findings.push(Finding::new(FindingDescriptor {
                rule_id: "security.tls-verification-disabled".to_string(),
                message: "TLS certificate or hostname verification is explicitly disabled."
                    .to_string(),
                file_path: file.display_path.clone(),
                line: Some(line_index + 1),
                severity: Severity::Warning,
                pillar: Pillar::Security,
                confidence: Confidence::High,
                symbol: None,
                remediation: Some(
                    "Remove the TLS verification bypass or gate it behind non-production test code."
                        .to_string(),
                ),
                metadata: json!({}),
            }));
        }
    }
}

pub(crate) fn analyse_insecure_rng_for_secrets(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    if !is_secret_like_rng_function_name(&block.name) {
        return;
    }

    let code_only = strip_rust_comments_after_string_mask(searchable_body);
    let regex = static_regex(
        &INSECURE_RNG_FOR_SECRETS_REGEX,
        r"\brand\s*::\s*(?P<call>thread_rng|random)\s*(?:::<[^>\n]+>)?\s*\(",
    );
    for (line_offset, line) in code_only.lines().enumerate() {
        let Some(call) = insecure_rng_call(line, regex) else {
            continue;
        };
        findings.push(insecure_rng_for_secrets_finding(
            file,
            block,
            line_offset,
            call,
        ));
        return;
    }
}

fn insecure_rng_call<'a>(line: &'a str, regex: &Regex) -> Option<&'a str> {
    regex.captures(line)?.name("call").map(|call| call.as_str())
}

fn insecure_rng_for_secrets_finding(
    file: &SourceFile,
    block: &FunctionBlock,
    line_offset: usize,
    call: &str,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "security.insecure-rng-for-secrets".to_string(),
        message: format!(
            "Function `{}` appears to generate secret material with non-cryptographic rand.",
            block.name
        ),
        file_path: file.display_path.clone(),
        line: Some(block.start_line + line_offset),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::Medium,
        symbol: Some(block.name.clone()),
        remediation: Some(
            "Use a cryptographically secure RNG such as rand::rngs::OsRng for tokens, keys, nonces, salts, and passwords."
                .to_string(),
        ),
        metadata: json!({ "function": block.name, "call": format!("rand::{call}") }),
    })
}

fn is_secret_like_rng_function_name(name: &str) -> bool {
    name.to_ascii_lowercase()
        .split(|character: char| character == '_' || !character.is_ascii_alphanumeric())
        .any(|segment| {
            matches!(
                segment,
                "token"
                    | "tokens"
                    | "secret"
                    | "secrets"
                    | "key"
                    | "keys"
                    | "password"
                    | "passwords"
                    | "nonce"
                    | "nonces"
                    | "salt"
                    | "salts"
            )
        })
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
    for captures in regex.captures_iter(&searchable) {
        let Some(full_match) = captures.get(0) else {
            continue;
        };
        let method = captures
            .name("method")
            .map(|method| method.as_str())
            .unwrap_or("query");
        findings.push(Finding::new(FindingDescriptor {
            rule_id: "security.sql-dynamic-query".to_string(),
            message: format!(
                "Direct dynamic SQL argument passed to `{method}(...)`; review query construction."
            ),
            file_path: file.display_path.clone(),
            line: Some(byte_line_from_starts(&starts, full_match.start())),
            severity: Severity::Warning,
            pillar: Pillar::Security,
            confidence: Confidence::High,
            symbol: Some(method.to_string()),
            remediation: Some(
                "Use static SQL with bind parameters instead of formatting query text.".to_string(),
            ),
            metadata: json!({ "method": method }),
        }));
    }
}

pub(crate) fn analyse_weak_crypto(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    let starts = line_starts(source);
    let mut reporter = WeakCryptoReporter {
        file,
        line_starts: &starts,
        findings,
        emitted: std::collections::BTreeSet::new(),
    };

    let import_regex = static_regex(
        &WEAK_CRYPTO_IMPORT_REGEX,
        r"(?m)^\s*use\s+(?P<primitive>md5|md_5|sha1|sha_1|rc4|des)(?:::|\s*;)",
    );
    for captures in import_regex.captures_iter(&searchable) {
        let Some(primitive) = captures.name("primitive") else {
            continue;
        };
        reporter.push(primitive.as_str(), primitive.start());
    }

    let constructor_regex = static_regex(
        &WEAK_CRYPTO_CONSTRUCTOR_REGEX,
        r"\b(?P<primitive>Md5|Sha1|Rc4|Des)::new\s*\(",
    );
    for captures in constructor_regex.captures_iter(&searchable) {
        let Some(primitive) = captures.name("primitive") else {
            continue;
        };
        reporter.push(primitive.as_str(), primitive.start());
    }
}

struct WeakCryptoReporter<'a, 'b> {
    file: &'a SourceFile,
    line_starts: &'a [usize],
    findings: &'b mut Vec<Finding>,
    emitted: std::collections::BTreeSet<String>,
}

impl WeakCryptoReporter<'_, '_> {
    fn push(&mut self, primitive: &str, byte_index: usize) {
        let normalized = normalize_weak_crypto_primitive(primitive);
        if !self.emitted.insert(normalized.to_string()) {
            return;
        }

        self.findings.push(Finding::new(FindingDescriptor {
            rule_id: "security.weak-crypto".to_string(),
            message: format!(
                "Weak cryptographic primitive `{primitive}` is referenced; review cryptographic use."
            ),
            file_path: self.file.display_path.clone(),
            line: Some(byte_line_from_starts(self.line_starts, byte_index)),
            severity: Severity::Warning,
            pillar: Pillar::Security,
            confidence: Confidence::Medium,
            symbol: Some(primitive.to_string()),
            remediation: Some(
                "Use modern primitives such as SHA-256/SHA-3 or audited password/key-derivation APIs for security-sensitive uses."
                    .to_string(),
            ),
            metadata: json!({ "primitive": primitive }),
        }));
    }
}

fn normalize_weak_crypto_primitive(primitive: &str) -> &'static str {
    match primitive {
        "md5" | "md_5" | "Md5" => "md5",
        "sha1" | "sha_1" | "Sha1" => "sha1",
        "rc4" | "Rc4" => "rc4",
        "des" | "Des" => "des",
        _ => "unknown",
    }
}

fn process_command_risk_signals(raw_window: &str, searchable_window: &str) -> Vec<&'static str> {
    let mut signals = Vec::new();

    if static_regex(
        &PROCESS_SHELL_INTERPRETER_REGEX,
        r#"(?i)(std::process::Command|Command)::new\s*\(\s*"(?:sh|bash|dash|zsh|cmd|powershell|pwsh)"\s*\)"#,
    )
    .is_match(raw_window)
    {
        signals.push("shell-interpreter");
    }
    if static_regex(
        &PROCESS_SHELL_ARG_REGEX,
        r#"\.(?:arg|args)\s*\([^)]*"(?:-c|/C)""#,
    )
    .is_match(raw_window)
    {
        signals.push("shell-command-argument");
    }
    if static_regex(
        &PROCESS_DYNAMIC_EXECUTABLE_REGEX,
        r"(std::process::Command|Command)::new\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_:]*::)",
    )
    .is_match(searchable_window)
    {
        signals.push("dynamic-executable");
    }
    if static_regex(
        &PROCESS_DYNAMIC_ARGUMENT_REGEX,
        r"\.(?:arg|args)\s*\(\s*(?:&?[A-Za-z_][A-Za-z0-9_]*|\[[^\]]*(?:&?[A-Za-z_][A-Za-z0-9_]*|format!\s*\())",
    )
    .is_match(searchable_window)
    {
        signals.push("dynamic-arguments");
    }
    if raw_window.contains(".env(") || raw_window.contains(".envs(") {
        signals.push("custom-environment");
    }
    if raw_window.contains(".current_dir(") {
        signals.push("custom-working-directory");
    }

    signals
}

fn line_window(lines: &[&str], line_index: usize) -> String {
    let end = usize::min(line_index + 8, lines.len());
    lines[line_index..end].join("\n")
}

fn process_command_is_returned_builder(source_lines: &[&str], line_index: usize) -> bool {
    let Some(function_line_index) = (0..=line_index)
        .rev()
        .take(24)
        .find(|index| source_lines[*index].contains("fn "))
    else {
        return false;
    };
    let signature = source_lines[function_line_index..=line_index].join(" ");
    static COMMAND_RETURN_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(&COMMAND_RETURN_REGEX, r"->\s*(?:std::process::)?Command\b").is_match(&signature)
        && !process_command_has_execution_sink(&line_window(source_lines, line_index))
}

fn process_command_has_execution_sink(raw_window: &str) -> bool {
    static COMMAND_EXECUTION_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &COMMAND_EXECUTION_REGEX,
        r"\.(?:spawn|output|status|wait_with_output)\s*\(",
    )
    .is_match(raw_window)
}

fn push_process_command_finding(
    file: &SourceFile,
    line: usize,
    risk_signals: Vec<&'static str>,
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding::new(FindingDescriptor {
        rule_id: "security.process-command".to_string(),
        message: "Process command execution is used; validate command arguments are not user-controlled."
            .to_string(),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: None,
        remediation: Some(
            "Prefer direct executable arguments, avoid shell command strings, and validate any user-controlled inputs."
                .to_string(),
        ),
        metadata: json!({ "riskSignals": risk_signals }),
    }));
}

fn process_command_is_fixed_taskkill_cleanup(raw_window: &str) -> bool {
    static TASKKILL_PID_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &TASKKILL_PID_REGEX,
        r#"Command::new\s*\(\s*"taskkill"\s*\)[\s\S]*\.args\s*\(\s*\[\s*"/PID"\s*,\s*&?[A-Za-z_][A-Za-z0-9_]*\.to_string\(\)\s*,\s*"/F"\s*,\s*"/T"\s*\]"#,
    )
    .is_match(raw_window)
}
