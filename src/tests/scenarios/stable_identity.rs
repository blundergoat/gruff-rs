use super::*;

fn make_finding(rule_id: &str, file: &str, line: usize, symbol: Option<&str>) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!("Synthetic finding for {rule_id} at line {line}"),
        file_path: file.to_string(),
        line: Some(line),
        severity: Severity::Advisory,
        pillar: Pillar::Naming,
        confidence: Confidence::High,
        symbol: symbol.map(str::to_string),
        remediation: None,
        metadata: serde_json::json!({}),
    })
}

#[test]
pub(crate) fn stable_identity_is_invariant_under_line_shifts() {
    let same_symbol_line_1 = make_finding("naming.short", "src/foo.rs", 1, Some("x"));
    let same_symbol_line_42 = make_finding("naming.short", "src/foo.rs", 42, Some("x"));

    assert_eq!(
        same_symbol_line_1.stable_identity, same_symbol_line_42.stable_identity,
        "stable identity must be invariant under line shifts for the same rule + symbol",
    );
    assert_ne!(
        same_symbol_line_1.fingerprint, same_symbol_line_42.fingerprint,
        "fingerprint MUST shift with line - that's the baseline contract this milestone preserves",
    );
}

#[test]
pub(crate) fn stable_identity_distinguishes_rule_ids() {
    let one_rule = make_finding("naming.short", "src/foo.rs", 10, Some("x"));
    let other_rule = make_finding("naming.generic", "src/foo.rs", 10, Some("x"));

    assert_ne!(
        one_rule.stable_identity, other_rule.stable_identity,
        "two findings differing only by rule_id must have different stable identities",
    );
}

#[test]
pub(crate) fn stable_identity_distinguishes_files() {
    let in_first_file = make_finding("naming.short", "src/auth.rs", 10, Some("x"));
    let in_second_file = make_finding("naming.short", "src/api.rs", 10, Some("x"));

    assert_ne!(
        in_first_file.stable_identity,
        in_second_file.stable_identity
    );
}

#[test]
pub(crate) fn stable_identity_falls_back_to_message_when_symbol_is_none() {
    fn finding_with(message: &str, file: &str, line: usize) -> Finding {
        Finding::new(FindingDescriptor {
            rule_id: "sensitive-data.api-key".to_string(),
            message: message.to_string(),
            file_path: file.to_string(),
            line: Some(line),
            severity: Severity::Advisory,
            pillar: Pillar::SensitiveData,
            confidence: Confidence::High,
            symbol: None,
            remediation: None,
            metadata: serde_json::json!({}),
        })
    }

    let same_message_line_10 = finding_with("API key pattern detected.", "src/foo.rs", 10);
    let same_message_line_20 = finding_with("API key pattern detected.", "src/foo.rs", 20);
    assert_eq!(
        same_message_line_10.stable_identity, same_message_line_20.stable_identity,
        "same message + same file + no symbol must produce a line-invariant identity",
    );

    let different_message = finding_with("Different message.", "src/foo.rs", 10);
    assert_ne!(
        same_message_line_10.stable_identity, different_message.stable_identity,
        "different message text must produce a different identity when symbol is absent",
    );
}

#[test]
pub(crate) fn stable_identity_is_sixteen_hex_chars() {
    let finding = make_finding("naming.short", "src/foo.rs", 1, Some("x"));
    assert_eq!(
        finding.stable_identity.len(),
        16,
        "stable identity must be a 16-character SHA-256 prefix (got {:?})",
        finding.stable_identity
    );
    assert!(
        finding
            .stable_identity
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "stable identity must be lowercase hex",
    );
}

#[test]
pub(crate) fn fingerprint_byte_identical_to_pre_m02_formula() {
    // The fingerprint formula hashes rule_id, file_path, line (or 0), and
    // symbol (or empty) with `\0` separators. This test pins the
    // byte-for-byte output so any accidental change to the formula breaks
    // here before consumer baselines break.
    let finding = make_finding("naming.short", "src/foo.rs", 42, Some("x"));
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, b"naming.short");
    sha2::Digest::update(&mut hasher, b"\0");
    sha2::Digest::update(&mut hasher, b"src/foo.rs");
    sha2::Digest::update(&mut hasher, b"\0");
    sha2::Digest::update(&mut hasher, b"42");
    sha2::Digest::update(&mut hasher, b"\0");
    sha2::Digest::update(&mut hasher, b"x");
    let expected = format!("{:x}", hasher.finalize())[..16].to_string();
    assert_eq!(finding.fingerprint, expected);
}

#[test]
pub(crate) fn analyse_resolution_falls_through_cli_then_config_then_default() {
    let mut config = Config::default();
    config
        .minimum_severity
        .insert("analyse".to_string(), FailThreshold::Error);

    // No CLI override -> config wins.
    assert_eq!(
        resolve_fail_on(None, &config, "analyse", FailThreshold::Advisory),
        FailThreshold::Error
    );
    // CLI override beats config.
    assert_eq!(
        resolve_fail_on(
            Some(FailThreshold::Warning),
            &config,
            "analyse",
            FailThreshold::Advisory
        ),
        FailThreshold::Warning
    );
    // No config entry, no CLI -> binary default.
    let empty = Config::default();
    assert_eq!(
        resolve_fail_on(None, &empty, "analyse", FailThreshold::Error),
        FailThreshold::Error
    );
}

#[test]
pub(crate) fn report_resolution_returns_none_default_when_unset() {
    let empty = Config::default();
    assert_eq!(
        resolve_fail_on(None, &empty, "report", FailThreshold::None),
        FailThreshold::None
    );

    let mut config = Config::default();
    config
        .minimum_severity
        .insert("report".to_string(), FailThreshold::Warning);
    assert_eq!(
        resolve_fail_on(None, &config, "report", FailThreshold::None),
        FailThreshold::Warning
    );
    assert_eq!(
        resolve_fail_on(
            Some(FailThreshold::Error),
            &config,
            "report",
            FailThreshold::None
        ),
        FailThreshold::Error
    );
}

#[test]
pub(crate) fn config_entry_for_one_command_does_not_leak_to_another() {
    let mut config = Config::default();
    config
        .minimum_severity
        .insert("analyse".to_string(), FailThreshold::Error);

    // analyse picks up its own override.
    assert_eq!(
        resolve_fail_on(None, &config, "analyse", FailThreshold::Advisory),
        FailThreshold::Error
    );
    // report does not see analyse's override.
    assert_eq!(
        resolve_fail_on(None, &config, "report", FailThreshold::None),
        FailThreshold::None
    );
}
