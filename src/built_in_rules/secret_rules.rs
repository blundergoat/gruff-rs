use super::*;

// PII-in-fixtures detection is a sensitive-data sub-concern kept in its own
// file; nested here (rather than a top-level sibling) so `built_in_rules`
// keeps a low module fan-out.
#[path = "pii_rules.rs"]
mod pii_rules;
pub(crate) use pii_rules::analyse_pii_test_fixture;

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
pub(crate) static URL_EMBEDDED_CREDENTIALS_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static API_KEY_PATTERN_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PHI_SSN_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PHI_MRN_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static PHI_MEDICARE_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static GCP_SERVICE_ACCOUNT_REGEX: OnceLock<Regex> = OnceLock::new();

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
        pattern: r"(?s)-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{16,}\s+-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----",
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
        pattern: r"(?:postgres|postgresql|mysql|mariadb|mongodb|redis|rediss|amqp|amqps)://[^:\s]+:[^@\s]+@",
        message: "Database URL appears to include a password.",
    },
    RegexRule {
        rule_id: "sensitive-data.url-embedded-credentials",
        regex: &URL_EMBEDDED_CREDENTIALS_REGEX,
        pattern: r"https?://[^/\s:@]+:[^/\s:@]+@",
        message: "HTTP(S) URL appears to include embedded credentials.",
    },
    RegexRule {
        rule_id: "sensitive-data.api-key-pattern",
        regex: &API_KEY_PATTERN_REGEX,
        pattern: r"(sk_(?:live|test)_[A-Za-z0-9]{16,}|pk_(?:live|test)_[A-Za-z0-9]{16,}|rk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}|https://discord(?:app)?\.com/api/webhooks/[0-9]{8,}/[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{32,}|Endpoint=sb://[^;\s]+;[^\s]*SharedAccessKey=[A-Za-z0-9+/=]{20,}|DefaultEndpointsProtocol=[^;\s]+;[^\s]*AccountKey=[A-Za-z0-9+/=]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})",
        message: "API key pattern detected.",
    },
];

pub(crate) static ENV_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static CONFIG_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static STRUCTURED_CONFIG_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static HIGH_ENTROPY_STRING_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_sensitive_data(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    if path_is_calibration_fixture(&unit.file.display_path)
        || path_is_test_infrastructure(&unit.file.display_path)
    {
        return;
    }
    for rule in SENSITIVE_PATTERNS {
        push_regex_pattern_matches(unit, config, rule, findings);
    }

    analyse_phi_patterns(unit, config, findings);
    analyse_gcp_service_account_keys(unit, config, findings);
    analyse_env_like_secrets(unit, config, findings);
    analyse_high_entropy_strings(unit, config, findings);
}

fn push_regex_pattern_matches(
    unit: &SourceUnit<'_>,
    config: &Config,
    rule: &RegexRule,
    findings: &mut Vec<Finding>,
) {
    for capture in static_regex(rule.regex, rule.pattern).find_iter(unit.source) {
        if regex_match_should_be_suppressed(unit.source, config, rule.rule_id, &capture) {
            continue;
        }
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

fn regex_match_should_be_suppressed(
    source: &str,
    config: &Config,
    rule_id: &str,
    capture: &regex::Match<'_>,
) -> bool {
    match rule_id {
        "sensitive-data.database-url-password" | "sensitive-data.url-embedded-credentials" => {
            credential_url_is_placeholder(capture.as_str())
        }
        // Suppress the generic private-key finding only when the GCP-specific rule
        // will actually emit a finding covering this key: it must be enabled AND its
        // pattern must match here. Otherwise a reordered-field or disabled-GCP key
        // would be dropped by both rules and produce no finding at all.
        "sensitive-data.private-key" => gcp_finding_contains_private_key(source, config, capture),
        _ => false,
    }
}

fn credential_url_is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("@example.")
        || lower.contains("@localhost")
        || lower.contains("@127.0.0.1")
        || lower.contains(":password@")
        || lower.contains(":changeme@")
        || lower.contains(":placeholder@")
}

fn gcp_finding_contains_private_key(
    source: &str,
    config: &Config,
    capture: &regex::Match<'_>,
) -> bool {
    if !config.is_rule_enabled("sensitive-data.gcp-service-account-key") {
        return false;
    }
    let regex = static_regex(&GCP_SERVICE_ACCOUNT_REGEX, GCP_SERVICE_ACCOUNT_PATTERN);
    regex
        .find_iter(source)
        .any(|gcp| gcp.start() <= capture.start() && capture.start() < gcp.end())
}

fn analyse_phi_patterns(unit: &SourceUnit<'_>, config: &Config, findings: &mut Vec<Finding>) {
    push_phi_matches(
        unit,
        config,
        "ssn",
        static_regex(
            &PHI_SSN_REGEX,
            r#"(?i)\b(?:SSN|social_security_number|patient_ssn)\b\s*[:=]\s*["']?(?P<value>\d{3}-\d{2}-\d{4})"#,
        ),
        findings,
    );
    push_phi_matches(
        unit,
        config,
        "mrn",
        static_regex(
            &PHI_MRN_REGEX,
            r#"(?i)\b(?:MRN|medical_record(?:_number)?|patient_id)\b\s*[:=]\s*["']?(?P<value>[A-Z]{0,3}\d{6,10})"#,
        ),
        findings,
    );
    push_phi_matches(
        unit,
        config,
        "medicare",
        static_regex(
            &PHI_MEDICARE_REGEX,
            r#"(?i)\b(?:MBI|Medicare)\b\s*[:=]\s*["']?(?P<value>[1-9][A-Z0-9]{10})"#,
        ),
        findings,
    );
}

fn push_phi_matches(
    unit: &SourceUnit<'_>,
    config: &Config,
    category: &str,
    regex: &Regex,
    findings: &mut Vec<Finding>,
) {
    for captures in regex.captures_iter(unit.source) {
        let Some(value) = captures.name("value") else {
            continue;
        };
        if phi_value_is_placeholder(category, value.as_str()) {
            continue;
        }
        let preview = redact(value.as_str());
        if config.secret_previews.contains(&preview) {
            continue;
        }
        findings.push(Finding::new(FindingDescriptor {
            rule_id: "sensitive-data.phi-pattern".to_string(),
            message: format!("Protected health identifier pattern detected for {category}."),
            file_path: unit.file.display_path.clone(),
            line: Some(byte_line_from_starts(unit.line_starts(), value.start())),
            severity: Severity::Error,
            pillar: Pillar::SensitiveData,
            confidence: Confidence::High,
            symbol: None,
            remediation: Some(
                "Replace committed health identifiers with standards-reserved placeholders."
                    .to_string(),
            ),
            metadata: json!({ "category": category, "preview": preview }),
        }));
    }
}

fn phi_value_is_placeholder(category: &str, value: &str) -> bool {
    let normalized = value.trim_matches('"').trim_matches('\'');
    match category {
        "ssn" => {
            normalized.starts_with("000")
                || normalized.starts_with("666")
                || normalized.starts_with('9')
        }
        "mrn" => normalized
            .chars()
            .all(|character| matches!(character, '0' | 'X' | 'x')),
        "medicare" => normalized.eq_ignore_ascii_case("1EG4TE5MK73"),
        _ => false,
    }
}

// Order-sensitive shape of a GCP service-account JSON key. Shared by the
// GCP-specific rule and the generic private-key suppression check so both agree
// on exactly when a GCP finding exists.
const GCP_SERVICE_ACCOUNT_PATTERN: &str = r#"(?s)"type"\s*:\s*"service_account".{0,2500}"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----"#;

fn analyse_gcp_service_account_keys(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(&GCP_SERVICE_ACCOUNT_REGEX, GCP_SERVICE_ACCOUNT_PATTERN);
    for capture in regex.find_iter(unit.source) {
        let preview = "service_account private key (redacted)".to_string();
        if config.secret_previews.contains(&preview) {
            continue;
        }
        findings.push(Finding::new(FindingDescriptor {
            rule_id: "sensitive-data.gcp-service-account-key".to_string(),
            message: "GCP service account private key material detected.".to_string(),
            file_path: unit.file.display_path.clone(),
            line: Some(byte_line_from_starts(unit.line_starts(), capture.start())),
            severity: Severity::Error,
            pillar: Pillar::SensitiveData,
            confidence: Confidence::High,
            symbol: None,
            remediation: Some(
                "Remove the service account key and rotate it in Google Cloud IAM.".to_string(),
            ),
            metadata: json!({ "provider": "gcp", "preview": preview }),
        }));
    }
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
            r#"(?:^|[^\w.-])(["']?(?:[A-Z][A-Z0-9_-]*?(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*|(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*)["']?)\s*=\s*["']?([^"'\s,}]+)"#,
        );
        push_env_like_secret_matches(unit, config, findings, env_regex, &test_ranges);
    } else {
        let config_regex = config_like_secret_regex(unit.file);
        push_env_like_secret_matches(unit, config, findings, config_regex, &test_ranges);
    }
}

fn config_like_secret_regex(file: &SourceFile) -> &'static Regex {
    if allows_lowercase_secret_keys(&file.display_path) {
        return static_regex(
            &STRUCTURED_CONFIG_LIKE_SECRET_REGEX,
            r#"(?i)(?:^|[^\w.-])(["']?(?:[A-Z][A-Z0-9_-]*?(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*|(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*)["']?)\s*(?:=|:)\s*["']?([^"'\s,}]+)"#,
        );
    }
    static_regex(
        &CONFIG_LIKE_SECRET_REGEX,
        r#"(?:^|[^\w.-])(["']?(?:[A-Z][A-Z0-9_-]*?(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*|(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*)["']?)\s*(?:=|:)\s*["']?([^"'\s,}]+)"#,
    )
}

fn allows_lowercase_secret_keys(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);
    if file_name.starts_with(".env") {
        return true;
    }
    matches!(
        std::path::Path::new(file_name)
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "env" | "ini" | "json" | "properties" | "tf" | "tfvars" | "toml" | "yaml" | "yml"
    )
}

fn push_env_like_secret_matches(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
    regex: &Regex,
    test_ranges: &[(usize, usize)],
) {
    for captures in regex.captures_iter(unit.source) {
        let Some((line, preview)) = env_like_secret_match(unit, config, &captures, test_ranges)
        else {
            continue;
        };
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

fn env_like_secret_match(
    unit: &SourceUnit<'_>,
    config: &Config,
    captures: &regex::Captures<'_>,
    test_ranges: &[(usize, usize)],
) -> Option<(usize, String)> {
    let full_match = captures.get(0)?;
    let key = captures.get(1)?;
    let value = captures.get(2)?;
    let line = byte_line_from_starts(unit.line_starts(), key.start());
    if line_in_ranges(line, test_ranges) || !is_credible_secret_assignment_value(value.as_str()) {
        return None;
    }
    let preview = redact(full_match.as_str());
    (!config.secret_previews.contains(&preview)).then_some((line, preview))
}

fn is_credible_secret_assignment_value(value: &str) -> bool {
    let value = clean_secret_assignment_value(value);
    if value.len() < 8 || is_secret_reference(value) || is_secret_placeholder(value) {
        return false;
    }
    has_secret_value_shape(value)
}

fn clean_secret_assignment_value(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

fn is_secret_reference(value: &str) -> bool {
    value.starts_with("${{") || value.starts_with('$')
}

fn is_secret_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("your_")
        || lower.contains("_here")
        || lower.contains("<your")
        || lower.contains("placeholder")
        || lower.contains("example")
        || lower.contains("redacted")
        || lower.contains("changeme")
        || lower.starts_with("arn:aws:secretsmanager:")
    {
        return true;
    }
    value
        .chars()
        .all(|character| matches!(character, '*' | 'x' | 'X'))
}

fn has_secret_value_shape(value: &str) -> bool {
    let has_letter = value
        .chars()
        .any(|character| character.is_ascii_alphabetic());
    let has_digit_or_symbol = value
        .chars()
        .any(|character| character.is_ascii_digit() || !character.is_ascii_alphanumeric());
    has_letter && has_digit_or_symbol
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
/// should fire - or `None` when the value is below the entropy bar, is
/// a recognised integrity-hash literal, has a known structured
/// non-secret shape, or matches the configured `secret_previews`
/// allowlist. Centralising the skip logic keeps the outer loop body
/// terse.
fn high_entropy_secret_preview(value: &str, config: &Config) -> Option<String> {
    if !is_high_entropy(value)
        || is_integrity_hash(value)
        || is_structured_high_entropy_non_secret(value)
    {
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
