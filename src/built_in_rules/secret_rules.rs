//! Detect secret-like and protected-health values in supported source files.
//! Findings expose detector-owned zero-payload markers while legacy config
//! aliases stay internal to exact suppression checks.

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
        // Every alternative is a vendor prefix, so the match must start one. Without the leading
        // `\b` the bare `sk-` arm matches inside any word ending in "sk" - `risk-of-script-injections`,
        // `task-management-configuration` - turning ordinary hyphenated prose into a credential finding.
        pattern: r"\b(sk_(?:live|test)_[A-Za-z0-9]{16,}|pk_(?:live|test)_[A-Za-z0-9]{16,}|rk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}|https://discord(?:app)?\.com/api/webhooks/[0-9]{8,}/[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{32,}|Endpoint=sb://[^;\s]+;[^\s]*SharedAccessKey=[A-Za-z0-9+/=]{20,}|DefaultEndpointsProtocol=[^;\s]+;[^\s]*AccountKey=[A-Za-z0-9+/=]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})",
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

/// Emit generic pattern findings after placeholder and legacy-alias suppression.
/// The finding message and identity stay unchanged while metadata receives a safe marker.
fn push_regex_pattern_matches(
    unit: &SourceUnit<'_>,
    config: &Config,
    rule: &RegexRule,
    findings: &mut Vec<Finding>,
) {
    // Each regex match is independently classified, suppressed, or reported to the user.
    for capture in static_regex(rule.regex, rule.pattern).find_iter(unit.source) {
        // Known placeholders and overlapping GCP keys stay suppressed by detector policy.
        if regex_match_should_be_suppressed(unit.source, config, rule.rule_id, &capture) {
            continue;
        }
        // A reviewed historic alias suppresses the same finding without entering report data.
        if legacy_secret_is_suppressed(config, capture.as_str()) {
            continue;
        }
        let display_marker = regex_display_marker(rule.rule_id, capture.as_str());
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
            metadata: json!({ "preview": display_marker }),
        }));
    }
}

/// Choose a zero-payload marker from the rule and its regex-approved match shape.
/// Generic provider-token patterns intentionally reveal no provider guess.
fn regex_display_marker(rule_id: &str, matched_value: &str) -> String {
    match rule_id {
        // AWS has a dedicated rule, so the report can safely name its credential class.
        "sensitive-data.aws-access-key" => SensitiveDisplayMarker::AwsAccessKey.render(),
        // Private-key findings expose only the key-material class.
        "sensitive-data.private-key" => SensitiveDisplayMarker::PrivateKey.render(),
        // JWT findings expose only the token class.
        "sensitive-data.jwt-token" => SensitiveDisplayMarker::Jwt.render(),
        // Credential URLs expose only a scheme already accepted by their detector regex.
        "sensitive-data.database-url-password" | "sensitive-data.url-embedded-credentials" => {
            connection_string_display_marker(matched_value)
        }
        // Mixed provider tokens keep the family contract's generic zero-payload marker.
        _ => SensitiveDisplayMarker::Generic.render(),
    }
}

/// Render a connection-string marker from the detector-approved URL scheme.
/// A malformed match falls back to the generic marker instead of exposing source text.
fn connection_string_display_marker(matched_value: &str) -> String {
    // The URL regex normally guarantees `://`; absence means no safe public scheme is available.
    let Some((scheme, _)) = matched_value.split_once("://") else {
        return SensitiveDisplayMarker::Generic.render();
    };
    SensitiveDisplayMarker::ConnectionString(scheme).render()
}

/// Check the exact historic alias used by `allowlists.secretPreviews`.
/// The alias exists only for this comparison and is never attached to a finding.
fn legacy_secret_is_suppressed(config: &Config, value: &str) -> bool {
    let legacy_alias = legacy_secret_suppression_alias(value);
    config.secret_previews.contains(&legacy_alias)
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

/// Emit one PHI finding per non-placeholder identifier not suppressed by its legacy alias.
/// Metadata exposes only the detector-owned health-identifier category.
fn push_phi_matches(
    unit: &SourceUnit<'_>,
    config: &Config,
    category: &str,
    regex: &Regex,
    findings: &mut Vec<Finding>,
) {
    // Each structured identifier is checked independently for placeholder and suppression policy.
    for captures in regex.captures_iter(unit.source) {
        // An incomplete named capture cannot identify a value for the user to replace.
        let Some(value) = captures.name("value") else {
            continue;
        };
        // Standards-reserved placeholders remain silent so fixtures can use safe examples.
        if phi_value_is_placeholder(category, value.as_str()) {
            continue;
        }
        // Existing configs still suppress the exact legacy alias without serializing it.
        if legacy_secret_is_suppressed(config, value.as_str()) {
            continue;
        }
        let display_marker = SensitiveDisplayMarker::ProtectedIdentifier(category).render();
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
            metadata: json!({ "category": category, "preview": display_marker }),
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
const GCP_LEGACY_SUPPRESSION_ALIAS: &str = "service_account private key (redacted)";

/// Emit GCP service-account findings with a provider marker and historic suppression alias.
/// Generic private-key coverage remains coordinated by `gcp_finding_contains_private_key`.
fn analyse_gcp_service_account_keys(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(&GCP_SERVICE_ACCOUNT_REGEX, GCP_SERVICE_ACCOUNT_PATTERN);
    // Each matched service-account object produces at most one provider-specific finding.
    for capture in regex.find_iter(unit.source) {
        // Existing configs keep suppressing the fixed historic GCP alias.
        if config
            .secret_previews
            .contains(GCP_LEGACY_SUPPRESSION_ALIAS)
        {
            continue;
        }
        let display_marker = SensitiveDisplayMarker::GcpServiceAccount.render();
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
            metadata: json!({ "provider": "gcp", "preview": display_marker }),
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

/// Emit credible environment-style assignments after exact legacy-alias suppression.
/// Reports receive only the generic zero-payload marker.
fn push_env_like_secret_matches(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
    regex: &Regex,
    test_ranges: &[(usize, usize)],
) {
    // Each assignment is independently validated against test context and placeholder shapes.
    for captures in regex.captures_iter(unit.source) {
        // Suppressed or non-credible assignments do not become findings.
        let Some(line) = env_like_secret_match(unit, config, &captures, test_ranges) else {
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
            metadata: json!({ "preview": SensitiveDisplayMarker::Generic.render() }),
        }));
    }
}

/// Return the source line for one reportable environment-style assignment.
/// Missing captures, test-only lines, placeholders, and legacy aliases stay silent.
fn env_like_secret_match(
    unit: &SourceUnit<'_>,
    config: &Config,
    captures: &regex::Captures<'_>,
    test_ranges: &[(usize, usize)],
) -> Option<usize> {
    // An incomplete regex capture cannot support a trustworthy finding location or value shape.
    let (Some(full_match), Some(key), Some(value)) =
        (captures.get(0), captures.get(1), captures.get(2))
    else {
        return None;
    };
    let line = byte_line_from_starts(unit.line_starts(), key.start());
    // Test-context assignments and non-credible values stay silent for the source author.
    if line_in_ranges(line, test_ranges) || !is_credible_secret_assignment_value(value.as_str()) {
        return None;
    }
    // A reviewed legacy alias suppresses the finding without becoming report metadata.
    if legacy_secret_is_suppressed(config, full_match.as_str()) {
        return None;
    }
    Some(line)
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

/// Report generated-looking string literals that survive inert-shape and legacy-alias checks.
/// Project analysis reaches this after the structured sensitive-data detectors.
pub(crate) fn analyse_high_entropy_strings(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &HIGH_ENTROPY_STRING_REGEX,
        r#""([A-Za-z0-9+/=_-]{32,})"|'([A-Za-z0-9+/=_-]{32,})'"#,
    );

    // Each quoted candidate is classified before any finding metadata is built.
    for captures in regex.captures_iter(unit.source) {
        // A regex alternative without a captured value cannot support entropy analysis.
        let Some(secret) = captures.get(1).or_else(|| captures.get(2)) else {
            continue;
        };
        let value = secret.as_str();
        // Inert shapes and reviewed legacy aliases remain silent.
        if !high_entropy_secret_should_report(value, config) {
            continue;
        }
        findings.push(high_entropy_finding(unit, &secret));
    }
}

/// Return whether a high-entropy value should produce a finding.
/// Inert shapes and exact historic suppression aliases remain silent without
/// exposing the alias to report construction.
fn high_entropy_secret_should_report(value: &str, config: &Config) -> bool {
    // Values below the entropy bar or with known inert shapes are not secret findings.
    if !is_high_entropy(value)
        || is_integrity_hash(value)
        || is_structured_high_entropy_non_secret(value)
    {
        return false;
    }
    !legacy_secret_is_suppressed(config, value)
}

/// Build a high-entropy finding with a generic marker and measured entropy.
/// The raw value is used only for the numeric calculation and is never serialized.
fn high_entropy_finding(unit: &SourceUnit<'_>, secret: &regex::Match<'_>) -> Finding {
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
        metadata: json!({
            "preview": SensitiveDisplayMarker::Generic.render(),
            "entropy": shannon_entropy(value)
        }),
    })
}
