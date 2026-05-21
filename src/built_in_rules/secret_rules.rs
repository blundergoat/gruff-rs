use super::*;

pub(crate) struct RegexRule {
    pub(crate) rule_id: &'static str,
    pub(crate) regex: &'static OnceLock<Regex>,
    pub(crate) pattern: &'static str,
    pub(crate) message: &'static str,
}

pub(crate) static AWS_ACCESS_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PRIVATE_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static JWT_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static DATABASE_URL_PASSWORD_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static API_KEY_PATTERN_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) const SENSITIVE_PATTERNS: &[RegexRule] = &[
    RegexRule {
        rule_id: "sensitive-data.aws-access-key",
        regex: &AWS_ACCESS_KEY_REGEX,
        pattern: r"AKIA[0-9A-Z]{16}",
        message: "AWS access key pattern detected.",
    },
    RegexRule {
        rule_id: "sensitive-data.private-key",
        regex: &PRIVATE_KEY_REGEX,
        pattern: r"BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY",
        message: "Private key block detected.",
    },
    RegexRule {
        rule_id: "sensitive-data.jwt-token",
        regex: &JWT_TOKEN_REGEX,
        pattern: r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        message: "JWT-looking token detected.",
    },
    RegexRule {
        rule_id: "sensitive-data.database-url-password",
        regex: &DATABASE_URL_PASSWORD_REGEX,
        pattern: r"[a-z]+://[^:\s]+:[^@\s]+@",
        message: "Database URL appears to include a password.",
    },
    RegexRule {
        rule_id: "sensitive-data.api-key-pattern",
        regex: &API_KEY_PATTERN_REGEX,
        pattern: r"(sk_(?:live|test)_[A-Za-z0-9]{16,}|pk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{32,}|Endpoint=sb://[^;\s]+;[^\s]*SharedAccessKey=[A-Za-z0-9+/=]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})",
        message: "API key pattern detected.",
    },
];

pub(crate) static ENV_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static HIGH_ENTROPY_STRING_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_sensitive_data(
    file: &SourceFile,
    source: &str,
    rust_ast: Option<&syn::File>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    for rule in SENSITIVE_PATTERNS {
        for capture in static_regex(rule.regex, rule.pattern).find_iter(source) {
            let preview = redact(capture.as_str());
            if config.secret_previews.contains(&preview) {
                continue;
            }
            findings.push(Finding::new(FindingDescriptor {
                rule_id: rule.rule_id.to_string(),
                message: rule.message.to_string(),
                file_path: file.display_path.clone(),
                line: Some(byte_line(source, capture.start())),
                severity: Severity::Error,
                pillar: Pillar::SensitiveData,
                confidence: Confidence::High,
                symbol: None,
                remediation: Some(
                    "Remove the secret and load it from a secure runtime source.".to_string(),
                ),
                metadata: json!({ "preview": preview }),
            }));
        }
    }

    analyse_env_like_secrets(file, source, rust_ast, config, findings);
    analyse_high_entropy_strings(file, source, config, findings);
}

pub(crate) fn analyse_env_like_secrets(
    file: &SourceFile,
    source: &str,
    rust_ast: Option<&syn::File>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &ENV_LIKE_SECRET_REGEX,
        r#"\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|DATABASE_URL)[A-Z0-9_]*\s*=\s*["']?([^"'\s]+)"#,
    );
    let test_ranges = rust_ast.map(test_context_line_ranges).unwrap_or_default();

    for capture in regex.find_iter(source) {
        let line = byte_line(source, capture.start());
        if line_in_ranges(line, &test_ranges) {
            continue;
        }
        let preview = redact(capture.as_str());
        if config.secret_previews.contains(&preview) {
            continue;
        }
        findings.push(Finding::new(FindingDescriptor {
            rule_id: "sensitive-data.hardcoded-env-value".to_string(),
            message: "Hardcoded environment-style secret assignment detected.".to_string(),
            file_path: file.display_path.clone(),
            line: Some(line),
            severity: Severity::Error,
            pillar: Pillar::SensitiveData,
            confidence: Confidence::High,
            symbol: None,
            remediation: Some(
                "Load secret values from runtime configuration instead of source.".to_string(),
            ),
            metadata: json!({ "preview": preview }),
        }));
    }
}

pub(crate) fn analyse_high_entropy_strings(
    file: &SourceFile,
    source: &str,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &HIGH_ENTROPY_STRING_REGEX,
        r#""([A-Za-z0-9+/=_-]{32,})"|'([A-Za-z0-9+/=_-]{32,})'"#,
    );

    for captures in regex.captures_iter(source) {
        let Some(secret) = captures.get(1).or_else(|| captures.get(2)) else {
            continue;
        };
        let value = secret.as_str();
        if !is_high_entropy(value) {
            continue;
        }
        let preview = redact(value);
        if config.secret_previews.contains(&preview) {
            continue;
        }
        findings.push(Finding::new(FindingDescriptor {
            rule_id: "sensitive-data.high-entropy-string".to_string(),
            message: "High-entropy string literal detected.".to_string(),
            file_path: file.display_path.clone(),
            line: Some(byte_line(source, secret.start())),
            severity: Severity::Error,
            pillar: Pillar::SensitiveData,
            confidence: Confidence::Medium,
            symbol: None,
            remediation: Some(
                "Move generated secrets to a secure runtime secret source.".to_string(),
            ),
            metadata: json!({ "preview": preview, "entropy": shannon_entropy(value) }),
        }));
    }
}
