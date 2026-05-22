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
        pattern: r"(sk_(?:live|test)_[A-Za-z0-9]{16,}|pk_(?:live|test)_[A-Za-z0-9]{16,}|rk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{32,}|Endpoint=sb://[^;\s]+;[^\s]*SharedAccessKey=[A-Za-z0-9+/=]{20,}|DefaultEndpointsProtocol=[^;\s]+;[^\s]*AccountKey=[A-Za-z0-9+/=]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})",
        message: "API key pattern detected.",
    },
];

pub(crate) static ENV_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static CONFIG_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static HIGH_ENTROPY_STRING_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_sensitive_data(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    for rule in SENSITIVE_PATTERNS {
        for capture in static_regex(rule.regex, rule.pattern).find_iter(unit.source) {
            let preview = redact(capture.as_str());
            if config.secret_previews.contains(&preview) {
                continue;
            }
            findings.push(Finding::new(FindingDescriptor {
                rule_id: rule.rule_id.to_string(),
                message: rule.message.to_string(),
                file_path: unit.file.display_path.clone(),
                line: Some(byte_line_from_starts(unit.line_starts(), capture.start())),
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

    analyse_env_like_secrets(unit, config, findings);
    analyse_high_entropy_strings(unit, config, findings);
}

pub(crate) fn analyse_env_like_secrets(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let test_ranges = unit
        .rust_ast
        .map(test_context_line_ranges)
        .unwrap_or_default();
    if unit.file.is_rust {
        let env_regex = static_regex(
            &ENV_LIKE_SECRET_REGEX,
            r#"(?i)(?:^|[^\w.-])(["']?(?:[A-Z][A-Z0-9_-]*?(?:SECRET|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*|(?:SECRET|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*)["']?)\s*=\s*["']?([^"'\s,}]+)"#,
        );
        push_env_like_secret_matches(unit, config, findings, env_regex, &test_ranges);
    } else {
        let config_regex = static_regex(
            &CONFIG_LIKE_SECRET_REGEX,
            r#"(?i)(?:^|[^\w.-])(["']?(?:[A-Z][A-Z0-9_-]*?(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*|(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*)["']?)\s*(?:=|:)\s*["']?([^"'\s,}]+)"#,
        );
        push_env_like_secret_matches(unit, config, findings, config_regex, &test_ranges);
    }
}

fn push_env_like_secret_matches(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
    regex: &Regex,
    test_ranges: &[(usize, usize)],
) {
    for captures in regex.captures_iter(unit.source) {
        let Some(full_match) = captures.get(0) else {
            continue;
        };
        let Some(key) = captures.get(1) else {
            continue;
        };
        let line = byte_line_from_starts(unit.line_starts(), key.start());
        if line_in_ranges(line, test_ranges) {
            continue;
        }
        let preview = redact(full_match.as_str());
        if config.secret_previews.contains(&preview) {
            continue;
        }
        findings.push(Finding::new(FindingDescriptor {
            rule_id: "sensitive-data.hardcoded-env-value".to_string(),
            message: "Hardcoded environment-style secret assignment detected.".to_string(),
            file_path: unit.file.display_path.clone(),
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

/// Recognises subresource-integrity hash literals (`sha256-...`,
/// `sha384-...`, `sha512-...`, generic `sri-...`) that lockfiles and
/// integrity manifests commit on purpose. The byte body of these is
/// always a base64 cryptographic digest, so it trivially trips entropy
/// thresholds; the rule should skip them to avoid blanket false
/// positives on `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
/// `<link integrity="...">` HTML, and similar.
fn is_integrity_hash(value: &str) -> bool {
    const PREFIXES: &[&str] = &["sha256-", "sha384-", "sha512-", "sri-"];
    PREFIXES.iter().any(|prefix| value.starts_with(prefix))
}

pub(crate) fn analyse_high_entropy_strings(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &HIGH_ENTROPY_STRING_REGEX,
        r#""([A-Za-z0-9+/=_-]{32,})"|'([A-Za-z0-9+/=_-]{32,})'"#,
    );

    for captures in regex.captures_iter(unit.source) {
        let Some(secret) = captures.get(1).or_else(|| captures.get(2)) else {
            continue;
        };
        let value = secret.as_str();
        let Some(preview) = high_entropy_secret_preview(value, config) else {
            continue;
        };
        findings.push(high_entropy_finding(unit, &secret, &preview));
    }
}

/// Returns the redacted preview for `value` if the high-entropy rule
/// should fire — or `None` when the value is below the entropy bar, is
/// a recognised integrity-hash literal, or matches the configured
/// `secret_previews` allowlist. Centralising the skip logic keeps the
/// outer loop body terse.
fn high_entropy_secret_preview(value: &str, config: &Config) -> Option<String> {
    if !is_high_entropy(value) || is_integrity_hash(value) {
        return None;
    }
    let preview = redact(value);
    if config.secret_previews.contains(&preview) {
        return None;
    }
    Some(preview)
}

fn high_entropy_finding(
    unit: &SourceUnit<'_>,
    secret: &regex::Match<'_>,
    preview: &str,
) -> Finding {
    let value = secret.as_str();
    Finding::new(FindingDescriptor {
        rule_id: "sensitive-data.high-entropy-string".to_string(),
        message: "High-entropy string literal detected.".to_string(),
        file_path: unit.file.display_path.clone(),
        line: Some(byte_line_from_starts(unit.line_starts(), secret.start())),
        severity: Severity::Error,
        pillar: Pillar::SensitiveData,
        confidence: Confidence::Medium,
        symbol: None,
        remediation: Some("Move generated secrets to a secure runtime secret source.".to_string()),
        metadata: json!({ "preview": preview, "entropy": shannon_entropy(value) }),
    })
}
