use super::*;

static PII_EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
static PII_SSN_REGEX: OnceLock<Regex> = OnceLock::new();
static PII_PHONE_REGEX: OnceLock<Regex> = OnceLock::new();

/// Flags realistic emails, SSN-shaped strings, and US-format phone numbers
/// in fixture-like files while skipping obvious placeholders.
///
/// `unit` is the file to scan; nothing is reported unless `path_is_test_fixture` accepts its display path.
/// Findings are appended to `findings`, one per realistic match, in email, SSN, then phone order.
pub(crate) fn analyse_pii_test_fixture(unit: &SourceUnit<'_>, findings: &mut Vec<Finding>) {
    if !path_is_test_fixture(&unit.file.display_path) {
        return;
    }
    let starts = unit.line_starts();
    push_pii_email_findings(unit, starts, findings);
    push_pii_ssn_findings(unit, starts, findings);
    push_pii_phone_findings(unit, starts, findings);
}

/// Recognises a fixture-like file path, the only kind of file the PII fixture rule scans.
///
/// `display_path` is lowercased, backslashes become slashes, and each path segment is compared whole against a fixed list of names.
/// A file name counts only when it equals a listed name exactly, so `fixtures.rs` on its own does not qualify.
///
/// Returns true when any segment is a singular or plural `fixture`, `sample`, `seed` or `mock`, or `testdata` or `test_data`.
fn path_is_test_fixture(display_path: &str) -> bool {
    const FIXTURE_DIR_NAMES: &[&str] = &[
        "fixture",
        "fixtures",
        "sample",
        "samples",
        "seed",
        "seeds",
        "mock",
        "mocks",
        "testdata",
        "test_data",
    ];
    let normalized = display_path.to_ascii_lowercase().replace('\\', "/");
    normalized
        .split('/')
        .any(|segment| FIXTURE_DIR_NAMES.contains(&segment))
}

/// Reports every email-shaped string in the file whose domain is not an obvious placeholder.
///
/// `unit` supplies the source text and `starts` its line starts, used to turn each match offset into a line number.
/// Each finding of kind `email` is appended to `findings`.
fn push_pii_email_findings(unit: &SourceUnit<'_>, starts: &[usize], findings: &mut Vec<Finding>) {
    let regex = static_regex(
        &PII_EMAIL_REGEX,
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    );
    for capture in regex.find_iter(unit.source) {
        let address = capture.as_str();
        if email_is_obvious_placeholder(address) {
            continue;
        }
        findings.push(pii_finding(
            unit,
            byte_line_from_starts(starts, capture.start()),
            "email",
        ));
    }
}

/// Reports every SSN-shaped string in the file unless it starts with `000`, `666` or `9`.
///
/// `unit` supplies the source text and `starts` its line starts, used to turn each match offset into a line number.
/// Each finding of kind `ssn` is appended to `findings`.
fn push_pii_ssn_findings(unit: &SourceUnit<'_>, starts: &[usize], findings: &mut Vec<Finding>) {
    let regex = static_regex(&PII_SSN_REGEX, r"\b\d{3}-\d{2}-\d{4}\b");
    for capture in regex.find_iter(unit.source) {
        let value = capture.as_str();
        if value.starts_with("000") || value.starts_with("666") || value.starts_with('9') {
            continue;
        }
        findings.push(pii_finding(
            unit,
            byte_line_from_starts(starts, capture.start()),
            "ssn",
        ));
    }
}

/// Reports every dash-separated ten-digit phone number in the file that `phone_is_obvious_placeholder` does not exempt.
///
/// `unit` supplies the source text and `starts` its line starts, used to turn each match offset into a line number.
/// Each finding of kind `phone` is appended to `findings`.
fn push_pii_phone_findings(unit: &SourceUnit<'_>, starts: &[usize], findings: &mut Vec<Finding>) {
    let regex = static_regex(&PII_PHONE_REGEX, r"\b\d{3}-\d{3}-\d{4}\b");
    for capture in regex.find_iter(unit.source) {
        let value = capture.as_str();
        if phone_is_obvious_placeholder(value) {
            continue;
        }
        findings.push(pii_finding(
            unit,
            byte_line_from_starts(starts, capture.start()),
            "phone",
        ));
    }
}

/// Common synthetic NANP placeholders: the reserved `555` exchange
/// (`AAA-555-NNNN`, e.g. `212-555-0100`) plus the non-assignable `555` and
/// `000` area codes. The regex guarantees the `AAA-EEE-NNNN` shape, so `-555-`
/// can only be the exchange segment.
///
/// `value` is a matched number in that shape; it is a placeholder when its area code is `555` or `000` or its exchange is `555`.
/// Returns true for a placeholder, which the caller skips, and false for a number that should be reported.
fn phone_is_obvious_placeholder(value: &str) -> bool {
    value.starts_with("555-") || value.starts_with("000-") || value.contains("-555-")
}

/// Decides whether an email address uses a reserved or obviously fake domain that the PII fixture rule should not report.
///
/// `address` is a matched email; only the domain after its first `@` is compared, ignoring case.
/// Placeholder domains are exactly `example.com`, `example.org`, `example.net`, `test.com`, `test.org` or `localhost`.
/// So are domains starting with `foo.`, `bar.` or `baz.` and domains ending in `.local`, `.invalid`, `.test` or `.example`.
///
/// Returns true for a placeholder domain, and false for any other domain or for text without an `@`.
fn email_is_obvious_placeholder(address: &str) -> bool {
    let lower = address.to_ascii_lowercase();
    let Some((_, domain)) = lower.split_once('@') else {
        return false;
    };
    matches!(
        domain,
        "example.com" | "example.org" | "example.net" | "test.com" | "test.org" | "localhost"
    ) || domain.starts_with("foo.")
        || domain.starts_with("bar.")
        || domain.starts_with("baz.")
        || domain.ends_with(".local")
        || domain.ends_with(".invalid")
        || domain.ends_with(".test")
        || domain.ends_with(".example")
}

/// Builds the `sensitive-data.pii-test-fixture` finding for one match, leaving the matched characters out of the report.
///
/// `unit` supplies the file's display path and `line` is the line where the match starts.
/// `kind` names the category, such as `email`, `ssn` or `phone`, and is the only classification the message and metadata carry.
///
/// Returns a high-confidence finding at the rule's built-in severity, with a remediation pointing to placeholder values.
fn pii_finding(unit: &SourceUnit<'_>, line: usize, kind: &str) -> Finding {
    // The detector-owned category is the only classification a report may carry: the matched
    // characters and their count are forbidden by FAMILY-CONTRACT section 5. Masking the message
    // collapses two occurrences of one kind in one file onto one stableIdentity, which the hook
    // already resolves by counting identical identities.
    let display_marker = SensitiveDisplayMarker::ProtectedIdentifier(kind).render();
    Finding::new(FindingDescriptor {
        rule_id: "sensitive-data.pii-test-fixture".to_string(),
        message: format!(
            "Realistic {kind} value `{display_marker}` found in a fixture/sample file; replace with synthetic placeholder."
        ),
        file_path: unit.file.display_path.clone(),
        line: Some(line),
        severity: rules::builtin_severity("sensitive-data.pii-test-fixture"),
        pillar: Pillar::SensitiveData,
        confidence: Confidence::High,
        symbol: None,
        remediation: Some(
            "Use placeholder domains (`@example.com`), 555-prefix phone numbers, or 000-prefix SSNs in committed sample data."
                .to_string(),
        ),
        metadata: json!({ "kind": kind, "preview": display_marker }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_placeholder_covers_555_exchange_and_reserved_area_codes() {
        // Standard reserved-for-fiction 555 exchange (the common case the
        // area-code-only check used to miss).
        assert!(phone_is_obvious_placeholder("212-555-0100"));
        assert!(phone_is_obvious_placeholder("415-555-0123"));
        // Non-assignable placeholder area codes.
        assert!(phone_is_obvious_placeholder("555-123-4567"));
        assert!(phone_is_obvious_placeholder("000-123-4567"));
    }

    #[test]
    fn phone_placeholder_leaves_realistic_numbers_flagged() {
        assert!(!phone_is_obvious_placeholder("212-867-5309"));
        assert!(!phone_is_obvious_placeholder("415-123-4567"));
        // `555` only in the subscriber segment is not the reserved exchange.
        assert!(!phone_is_obvious_placeholder("212-867-5550"));
    }
}
