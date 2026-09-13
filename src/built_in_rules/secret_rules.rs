//! Detect secret-like and protected-health values in supported source files.
//!
//! Users receive one finding per reportable occurrence with a detector-owned
//! zero-payload marker; legacy preview config cannot remove those findings.

use super::*;

// Fixture-PII checks stay nested here because users encounter them as part of the same sensitive-data scan.
#[path = "pii_rules.rs"]
mod pii_rules;
pub(crate) use pii_rules::analyse_pii_test_fixture;

/// Describe one regex-backed detector and the message users see for a match.
///
/// The pattern identifies source text, while report construction replaces that text with a fixed marker.
/// Rules use static regex storage so repeated files share the compiled detector.
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
        // Vendor prefixes must start at a word boundary so ordinary hyphenated UI text does not look like a credential.
        // For example, a user writing `risk-of-script-injections` should not receive an API-key finding for its `sk-` characters.
        pattern: r"\b(sk_(?:live|test)_[A-Za-z0-9]{16,}|pk_(?:live|test)_[A-Za-z0-9]{16,}|rk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}|https://discord(?:app)?\.com/api/webhooks/[0-9]{8,}/[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{32,}|Endpoint=sb://[^;\s]+;[^\s]*SharedAccessKey=[A-Za-z0-9+/=]{20,}|DefaultEndpointsProtocol=[^;\s]+;[^\s]*AccountKey=[A-Za-z0-9+/=]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})",
        message: "API key pattern detected.",
    },
];

pub(crate) static ENV_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static CONFIG_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static STRUCTURED_CONFIG_LIKE_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static HIGH_ENTROPY_STRING_REGEX: OnceLock<Regex> = OnceLock::new();

/// Run every sensitive-data detector that applies to one discovered user file.
/// A test or calibration path receives the same scan; only a reviewed sensitive exclusion may filter it later.
pub(crate) fn analyse_sensitive_data(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    // Every enabled generic detector contributes its reportable occurrences to the same user result.
    for rule in SENSITIVE_PATTERNS {
        push_regex_pattern_matches(unit, config, rule, findings);
    }

    analyse_phi_patterns(unit, findings);
    analyse_gcp_service_account_keys(unit, findings);
    analyse_env_like_secrets(unit, findings);
    analyse_high_entropy_strings(unit, findings);
}

/// Emit generic pattern findings after detector-owned placeholder checks.
/// Users receive a separate fixed-marker finding for every reportable match.
fn push_regex_pattern_matches(
    unit: &SourceUnit<'_>,
    config: &Config,
    rule: &RegexRule,
    findings: &mut Vec<Finding>,
) {
    // Each regex match is independently classified so users can remediate every occurrence.
    for capture in static_regex(rule.regex, rule.pattern).find_iter(unit.source) {
        // Known placeholders and overlapping GCP keys stay suppressed by detector policy.
        if regex_match_should_be_suppressed(unit.source, config, rule.rule_id, &capture) {
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
            // Regex-level secret matches do not resolve to a named code symbol in the user's report.
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

/// Decide whether detector-owned placeholder or overlap policy already accounts for a regex match.
/// Returning true keeps an intentionally safe example or duplicate finding out of the user's report.
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
        // Hide the generic private-key duplicate only when the enabled GCP rule will show the user a more specific finding.
        "sensitive-data.private-key" => gcp_finding_contains_private_key(source, config, capture),
        _ => false,
    }
}

/// Recognise safe credentials intentionally used in example or local-only URLs.
/// Users do not need findings for values such as `password@localhost` that cannot authenticate a remote service.
fn credential_url_is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("@example.")
        || lower.contains("@localhost")
        || lower.contains("@127.0.0.1")
        || lower.contains(":password@")
        || lower.contains(":changeme@")
        || lower.contains(":placeholder@")
}

/// Check whether an enabled GCP finding covers the same private-key match.
/// This prevents duplicate UI entries without dropping the user's only finding.
fn gcp_finding_contains_private_key(
    source: &str,
    config: &Config,
    capture: &regex::Match<'_>,
) -> bool {
    // A disabled GCP rule cannot replace the generic private-key finding in the user's report.
    if !config.is_rule_enabled("sensitive-data.gcp-service-account-key") {
        return false;
    }
    let regex = static_regex(&GCP_SERVICE_ACCOUNT_REGEX, GCP_SERVICE_ACCOUNT_PATTERN);
    regex
        .find_iter(source)
        .any(|gcp| gcp.start() <= capture.start() && capture.start() < gcp.end())
}

/// Run every protected-health identifier detector for one user-visible source file.
fn analyse_phi_patterns(unit: &SourceUnit<'_>, findings: &mut Vec<Finding>) {
    push_phi_matches(
        unit,
        "ssn",
        static_regex(
            &PHI_SSN_REGEX,
            r#"(?i)\b(?:SSN|social_security_number|patient_ssn)\b\s*[:=]\s*["']?(?P<value>\d{3}-\d{2}-\d{4})"#,
        ),
        findings,
    );
    push_phi_matches(
        unit,
        "mrn",
        static_regex(
            &PHI_MRN_REGEX,
            r#"(?i)\b(?:MRN|medical_record(?:_number)?|patient_id)\b\s*[:=]\s*["']?(?P<value>[A-Z]{0,3}\d{6,10})"#,
        ),
        findings,
    );
    push_phi_matches(
        unit,
        "medicare",
        static_regex(
            &PHI_MEDICARE_REGEX,
            r#"(?i)\b(?:MBI|Medicare)\b\s*[:=]\s*["']?(?P<value>[1-9][A-Z0-9]{10})"#,
        ),
        findings,
    );
}

/// Emit one PHI finding per non-placeholder identifier found in user source.
/// Metadata exposes only the detector-owned health-identifier category.
fn push_phi_matches(
    unit: &SourceUnit<'_>,
    category: &str,
    regex: &Regex,
    findings: &mut Vec<Finding>,
) {
    // Each structured identifier is checked independently so users can replace every occurrence.
    for captures in regex.captures_iter(unit.source) {
        // An incomplete named capture cannot identify a value for the user to replace.
        let Some(value) = captures.name("value") else {
            continue;
        };
        // Standards-reserved placeholders remain silent so fixtures can use safe examples.
        if phi_value_is_placeholder(category, value.as_str()) {
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
            // PHI matches identify a source line and category, not a parsed code symbol.
            symbol: None,
            remediation: Some(
                "Replace committed health identifiers with standards-reserved placeholders."
                    .to_string(),
            ),
            metadata: json!({ "category": category, "preview": display_marker }),
        }));
    }
}

/// Recognise standards-reserved PHI examples that users can safely keep in fixtures.
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

// The GCP detector and generic-key overlap check share this shape so the user always receives exactly one applicable finding.
const GCP_SERVICE_ACCOUNT_PATTERN: &str = r#"(?s)"type"\s*:\s*"service_account".{0,2500}"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----"#;

/// Emit each GCP service-account finding with a fixed provider marker.
/// Generic private-key coverage remains coordinated by `gcp_finding_contains_private_key`.
fn analyse_gcp_service_account_keys(unit: &SourceUnit<'_>, findings: &mut Vec<Finding>) {
    let regex = static_regex(&GCP_SERVICE_ACCOUNT_REGEX, GCP_SERVICE_ACCOUNT_PATTERN);
    // Each matched service-account object produces at most one provider-specific finding.
    for capture in regex.find_iter(unit.source) {
        let display_marker = SensitiveDisplayMarker::GcpServiceAccount.render();
        findings.push(Finding::new(FindingDescriptor {
            rule_id: "sensitive-data.gcp-service-account-key".to_string(),
            message: "GCP service account private key material detected.".to_string(),
            file_path: unit.file.display_path.clone(),
            line: Some(byte_line_from_starts(unit.line_starts(), capture.start())),
            severity: Severity::Error,
            pillar: Pillar::SensitiveData,
            confidence: Confidence::High,
            // A service-account object is shown by file and line rather than a language symbol.
            symbol: None,
            remediation: Some(
                "Remove the service account key and rotate it in Google Cloud IAM.".to_string(),
            ),
            metadata: json!({ "provider": "gcp", "preview": display_marker }),
        }));
    }
}

/// Detect credible environment-style assignments in Rust and supported config files.
/// Users receive a separate fixed-marker finding for each reportable assignment.
pub(crate) fn analyse_env_like_secrets(unit: &SourceUnit<'_>, findings: &mut Vec<Finding>) {
    let test_ranges = unit
        .rust_ast
        .map(test_context_line_ranges)
        .unwrap_or_default();
    // Rust assignments and structured config use different separators and key-case conventions.
    if unit.file.is_rust {
        let env_regex = static_regex(
            &ENV_LIKE_SECRET_REGEX,
            r#"(?:^|[^\w.-])(["']?(?:[A-Z][A-Z0-9_-]*?(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*|(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|DATABASE[_-]?URL)[A-Z0-9_-]*)["']?)\s*=\s*["']?([^"'\s,}]+)"#,
        );
        push_env_like_secret_matches(unit, findings, env_regex, &test_ranges);
    } else {
        let config_regex = config_like_secret_regex(unit.file);
        push_env_like_secret_matches(unit, findings, config_regex, &test_ranges);
    }
}

/// Select the structured-config detector appropriate to the user's file type.
/// Formats with conventional lowercase keys receive case-insensitive matching.
fn config_like_secret_regex(file: &SourceFile) -> &'static Regex {
    // Lowercase-key formats need case-insensitive detection so values such as `api_key:` remain visible to users.
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

/// Decide whether a config filename convention permits lowercase secret-like keys.
fn allows_lowercase_secret_keys(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);
    // Dot-env variants conventionally contain assignment keys regardless of their extension.
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

/// Emit credible environment-style assignments with a generic zero-payload marker.
/// Each reportable assignment remains visible for the user to remediate.
fn push_env_like_secret_matches(
    unit: &SourceUnit<'_>,
    findings: &mut Vec<Finding>,
    regex: &Regex,
    test_ranges: &[(usize, usize)],
) {
    // Each assignment is independently validated against test context and placeholder shapes.
    for captures in regex.captures_iter(unit.source) {
        // Non-credible assignments do not become findings in the user's report.
        let Some(line) = env_like_secret_match(unit, &captures, test_ranges) else {
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
            // Config-style assignments may not belong to a language symbol the UI can display.
            symbol: None,
            remediation: Some(
                "Load secret values from runtime configuration instead of source.".to_string(),
            ),
            metadata: json!({ "preview": SensitiveDisplayMarker::Generic.render() }),
        }));
    }
}

/// Return the source line for one reportable environment-style assignment.
/// Missing captures, test-only lines, and placeholders stay silent for users.
fn env_like_secret_match(
    unit: &SourceUnit<'_>,
    captures: &regex::Captures<'_>,
    test_ranges: &[(usize, usize)],
) -> Option<usize> {
    // An incomplete regex capture cannot support a trustworthy finding location or value shape.
    let (Some(key), Some(value)) = (captures.get(1), captures.get(2)) else {
        return None;
    };
    let line = byte_line_from_starts(unit.line_starts(), key.start());
    // Test-context assignments and non-credible values stay silent for the source author.
    if line_in_ranges(line, test_ranges) || !is_credible_secret_assignment_value(value.as_str()) {
        return None;
    }
    Some(line)
}

/// Decide whether a captured assignment looks like a committed value rather than a safe reference or placeholder.
fn is_credible_secret_assignment_value(value: &str) -> bool {
    let value = clean_secret_assignment_value(value);
    // Short values, runtime references, and explicit placeholders do not ask the user to remove real credential material.
    if value.len() < 8 || is_secret_reference(value) || is_secret_placeholder(value) {
        return false;
    }
    has_secret_value_shape(value)
}

/// Remove surrounding whitespace and quotes before classifying an assignment value.
fn clean_secret_assignment_value(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

/// Recognise runtime interpolation that resolves after the user's source is loaded.
fn is_secret_reference(value: &str) -> bool {
    value.starts_with("${{") || value.starts_with('$')
}

/// Recognise explicit example, redaction, and masked values that users can safely keep.
fn is_secret_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    // Familiar example labels tell users and the analyser that no usable credential is present.
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

/// Require both letters and digits or symbols before an assignment becomes a credible secret finding.
fn has_secret_value_shape(value: &str) -> bool {
    let has_letter = value
        .chars()
        .any(|character| character.is_ascii_alphabetic());
    let has_digit_or_symbol = value
        .chars()
        .any(|character| character.is_ascii_digit() || !character.is_ascii_alphanumeric());
    has_letter && has_digit_or_symbol
}

/// Report generated-looking string literals that survive detector-owned inert-shape checks.
/// Project analysis reaches this after the structured sensitive-data detectors.
pub(crate) fn analyse_high_entropy_strings(unit: &SourceUnit<'_>, findings: &mut Vec<Finding>) {
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
        // Inert shapes remain silent so users can focus on credible generated-secret candidates.
        if !high_entropy_secret_should_report(value) {
            continue;
        }
        findings.push(high_entropy_finding(unit, &secret));
    }
}

/// Return whether a high-entropy value should produce a finding.
/// Detector-owned inert shapes stay silent without consulting user preview text.
fn high_entropy_secret_should_report(value: &str) -> bool {
    // Values below the entropy bar or with known inert shapes are not secret findings.
    if !is_high_entropy(value)
        || is_integrity_hash(value)
        || is_structured_high_entropy_non_secret(value)
    {
        return false;
    }
    true
}

/// Build a high-entropy finding carrying only the generic zero-payload marker.
/// The matched text is used for detection alone and never reaches a serialized field.
fn high_entropy_finding(unit: &SourceUnit<'_>, secret: &regex::Match<'_>) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "sensitive-data.high-entropy-string".to_string(),
        message: "High-entropy string literal detected.".to_string(),
        file_path: unit.file.display_path.clone(),
        line: Some(byte_line_from_starts(unit.line_starts(), secret.start())),
        severity: Severity::Error,
        pillar: Pillar::SensitiveData,
        confidence: Confidence::Medium,
        // Entropy matches are string locations rather than parsed symbols in the user's report.
        symbol: None,
        remediation: Some("Move generated secrets to a secure runtime secret source.".to_string()),
        // The rule's own threshold already explains why this fired. The value's entropy is a
        // statistic computed from the matched characters and is forbidden in serialized output
        // by FAMILY-CONTRACT section 5.
        metadata: json!({
            "preview": SensitiveDisplayMarker::Generic.render()
        }),
    })
}
