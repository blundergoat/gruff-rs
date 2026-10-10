//! Shared constructors and predicates for built-in source checks.
//!
//! Rule modules use these helpers to create deterministic findings, classify
//! source shapes, and keep sensitive source values out of user-facing reports.

use super::*;

/// Check whether nearby source documents a deliberate panic or invariant.
/// Rules use this signal to avoid asking users to change already-explained behavior.
pub(crate) fn has_nearby_invariant_comment(source: &str) -> bool {
    source
        .lines()
        .any(|line| line.contains("PANIC:") || line.contains("INVARIANT:"))
}

/// Detect an assertion that proves only a literal or its unchanged binding.
/// Call this on masked test source so commented examples do not become user findings.
pub(crate) fn has_trivial_assertion(source: &str) -> bool {
    let literal_assert = static_regex(&TRIVIAL_ASSERT_REGEX, r"\bassert!\s*\(\s*(true|false)\s*\)");
    // A literal assertion gives the user no confidence that application behavior works.
    if literal_assert.is_match(source) {
        return true;
    }

    let same_literal = static_regex(
        &SAME_LITERAL_ASSERT_REGEX,
        r#"\bassert_eq!\s*\(\s*([0-9]+|"[^"]*"|'[^']*')\s*,\s*([0-9]+|"[^"]*"|'[^']*')\s*\)"#,
    );
    let has_same_literal = same_literal.captures_iter(source).any(|captures| {
        captures.get(1).map(|left| left.as_str()) == captures.get(2).map(|right| right.as_str())
    });
    // Equal literal arguments exercise the assertion macro, not the user's code.
    if has_same_literal {
        return true;
    }

    has_literal_binding_tautology(source)
}

/// Detect an immutable literal binding asserted unchanged before any shadowing.
/// This catches tests such as `let answer = 42; assert_eq!(answer, 42)` without guessing about computed values.
fn has_literal_binding_tautology(source: &str) -> bool {
    let binding = static_regex(
        &LITERAL_BINDING_REGEX,
        r"\blet\s+(mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;\n]+)?=\s*(true|false|[0-9][0-9_]*(?:\.[0-9][0-9_]*)?)\s*;",
    );
    binding.captures_iter(source).any(|captures| {
        // Mutable bindings may change before the assertion, so users should not see a tautology finding.
        if captures.get(1).is_some() {
            return false;
        }
        // Missing regex groups cannot identify a binding and assertion pair for the user.
        let (Some(name), Some(literal), Some(whole)) =
            (captures.get(2), captures.get(3), captures.get(0))
        else {
            return false;
        };
        literal_is_asserted_before_shadow(&source[whole.end()..], name.as_str(), literal.as_str())
    })
}

/// Check whether a literal binding is asserted before the same name is rebound.
/// Conservative misses are preferred because a false finding would ask the user to rewrite a meaningful test.
fn literal_is_asserted_before_shadow(rest: &str, name: &str, literal: &str) -> bool {
    let escaped_name = regex::escape(name);
    let escaped_literal = regex::escape(literal);

    // A later binding ends the safe comparison window because the assertion may refer to a different user value.
    let shadow = Regex::new(&format!(r"\blet\b[^;=]*\b{escaped_name}\b[^;=]*="))
        .expect("literal-binding shadow regex compiles");
    let window_end = shadow.find(rest).map_or(rest.len(), |found| found.start());

    let assertion = Regex::new(&format!(
        r"\bassert_eq!\s*\(\s*(?:\b{escaped_name}\b\s*,\s*\b{escaped_literal}\b|\b{escaped_literal}\b\s*,\s*\b{escaped_name}\b)\s*[,)]"
    ))
    .expect("literal-binding assertion regex compiles");
    assertion.is_match(&rest[..window_end])
}

/// Describe the common fields needed to show a source-level finding to the user.
///
/// Rule helpers add confidence and metadata before the finding reaches a renderer.
/// An absent line means the issue applies to the file rather than one source line.
pub(crate) struct SimpleFindingDescriptor<'a> {
    pub(crate) rule_id: &'a str,
    pub(crate) message: String,
    pub(crate) file: &'a SourceFile,
    pub(crate) line: Option<usize>,
    pub(crate) severity: Severity,
    pub(crate) pillar: Pillar,
}

/// Build a source-level finding with high confidence and empty metadata.
/// Use this when the user only needs the rule message and location.
pub(crate) fn finding(descriptor: SimpleFindingDescriptor<'_>) -> Finding {
    finding_with_metadata(descriptor, json!({}))
}

/// Build a source-level finding with rule-specific metadata for reports and UI details.
/// Empty metadata means the finding has no safe supplemental values to display.
pub(crate) fn finding_with_metadata(
    descriptor: SimpleFindingDescriptor<'_>,
    metadata: Value,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: descriptor.rule_id.to_string(),
        message: descriptor.message,
        file_path: descriptor.file.display_path.clone(),
        line: descriptor.line,
        severity: descriptor.severity,
        pillar: descriptor.pillar,
        confidence: Confidence::High,
        // File-level helper findings have no parsed symbol to show in the user's report.
        symbol: None,
        // The calling rule's message is complete, so the shared default adds no remediation text.
        remediation: None,
        metadata,
    })
}

/// Describe a measured limit in the stable metadata shape shown by threshold-based rules.
/// Users see the measured value, configured threshold, unit, and comparison direction.
pub(crate) fn threshold_metadata(measured: usize, threshold: usize, unit: &str) -> Value {
    json!({
        "measured": measured,
        "threshold": threshold,
        "unit": unit,
        "direction": "above"
    })
}

/// Describe a finding attached to one parsed function or block.
///
/// The block supplies the symbol and first line shown to the user.
/// Rule helpers add confidence, remediation, and metadata before rendering.
pub(crate) struct BlockFindingDescriptor<'a> {
    pub(crate) rule_id: &'a str,
    pub(crate) message: String,
    pub(crate) file: &'a SourceFile,
    pub(crate) block: &'a FunctionBlock,
    pub(crate) severity: Severity,
    pub(crate) pillar: Pillar,
}

/// Build a high-confidence block finding with no supplemental metadata.
/// Use this for a user-facing issue whose message and symbol carry the full explanation.
pub(crate) fn block_finding(descriptor: BlockFindingDescriptor<'_>) -> Finding {
    block_finding_with_metadata(descriptor, json!({}))
}

/// Build a high-confidence block finding with safe rule-specific metadata.
/// Empty metadata means reports show only the message, symbol, and location.
pub(crate) fn block_finding_with_metadata(
    descriptor: BlockFindingDescriptor<'_>,
    metadata: Value,
) -> Finding {
    block_finding_with_extras(
        descriptor,
        BlockFindingExtras {
            confidence: Confidence::High,
            // The calling block rule's message already gives the user its default remediation context.
            remediation: None,
            metadata,
        },
    )
}

/// Hold optional presentation details for a block finding.
///
/// Rules use these fields when users need calibrated confidence, remediation, or metadata.
/// `None` remediation means the rule message already gives sufficient guidance.
pub(crate) struct BlockFindingExtras {
    pub(crate) confidence: Confidence,
    pub(crate) remediation: Option<String>,
    pub(crate) metadata: Value,
}

/// Build a block finding with explicitly selected confidence and presentation details.
/// This is the final shared step before the finding enters the user's report.
pub(crate) fn block_finding_with_extras(
    descriptor: BlockFindingDescriptor<'_>,
    extras: BlockFindingExtras,
) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: descriptor.rule_id.to_string(),
        message: descriptor.message,
        file_path: descriptor.file.display_path.clone(),
        line: Some(descriptor.block.start_line),
        severity: descriptor.severity,
        pillar: descriptor.pillar,
        confidence: extras.confidence,
        symbol: Some(descriptor.block.name.clone()),
        remediation: extras.remediation,
        metadata: extras.metadata,
    })
}

/// Find the first one-based line containing text for a user-visible location.
/// `None` means the requested text does not occur in the scanned source.
#[allow(dead_code)]
pub(crate) fn first_matching_line(source: &str, needle: &str) -> Option<usize> {
    source
        .lines()
        .enumerate()
        .find_map(|(index, line)| line.contains(needle).then_some(index + 1))
}

/// Select a zero-payload marker from detector-owned categories after matched source text has been classified.
///
/// Reports receive only these markers; source text never becomes user-facing metadata.
/// Category variants explain the remediation users need without revealing matched characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SensitiveDisplayMarker<'a> {
    Generic,
    AwsAccessKey,
    PrivateKey,
    Jwt,
    GcpServiceAccount,
    ProtectedIdentifier(&'a str),
    ConnectionString(&'a str),
}

impl SensitiveDisplayMarker<'_> {
    /// Render the zero-payload text serialized in a sensitive finding's metadata.
    /// Category and scheme values come from detector constants or accepted regex alternatives.
    pub(crate) fn render(self) -> String {
        match self {
            // Generic token and entropy matches reveal no narrower detector class.
            Self::Generic => "[redacted]".to_string(),
            // AWS access-key matches expose the credential class but no key characters.
            Self::AwsAccessKey => "[redacted:aws-access-key]".to_string(),
            // Private-key matches expose the material class but no header or body bytes.
            Self::PrivateKey => "[redacted:private-key]".to_string(),
            // JWT matches expose the token class but no encoded segment bytes.
            Self::Jwt => "[redacted:jwt]".to_string(),
            // GCP service-account matches expose the provider class but no key fields.
            Self::GcpServiceAccount => "[redacted:gcp-service-account]".to_string(),
            // PHI markers expose only the detector-owned identifier category.
            Self::ProtectedIdentifier(category) => format!("[redacted:{category}]"),
            // Connection markers expose only the regex-approved public URL scheme.
            Self::ConnectionString(scheme) => {
                format!("[redacted:connection-string:{scheme}]")
            }
        }
    }
}

/// Decide whether a value has enough length, character variety, and entropy to warrant a secret finding.
/// This is a candidate check; detector-owned inert shapes are filtered later. Both bars come from the
/// rule's configured detector parameters, so a value's fate never depends on a number repeated here.
/// Variety is FAMILY-CONTRACT section 12's floor: a letter and a digit. A run of one character class clears the
/// entropy bar by construction, and a digit-free mix of cases is an identifier; gruff-rs once required upper,
/// lower and digit together, which hid lowercase-and-digit keys the other four ports report.
pub(crate) fn is_high_entropy(value: &str, min_length: usize, min_entropy: f64) -> bool {
    // Short values do not meet the detector's minimum evidence bar for a user finding.
    if value.chars().count() < min_length {
        return false;
    }
    let has_upper = value
        .chars()
        .any(|character| character.is_ascii_uppercase());
    let has_lower = value
        .chars()
        .any(|character| character.is_ascii_lowercase());
    let has_digit = value.chars().any(|character| character.is_ascii_digit());
    (has_upper || has_lower) && has_digit && shannon_entropy(value) >= min_entropy
}

/// Measure Shannon entropy so generated-looking values can be separated from ordinary user text.
pub(crate) fn shannon_entropy(value: &str) -> f64 {
    // The frequency table starts empty because every count must come from the candidate currently being classified.
    let mut counts: HashMap<char, usize> = HashMap::new();
    // Character frequencies provide the distribution used by the detector's entropy score.
    for character in value.chars() {
        *counts.entry(character).or_default() += 1;
    }
    let length = value.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

/// Recognise integrity hashes that users intentionally commit in lockfiles and manifests.
/// Their digest bodies look secret-like, but the public prefix makes their purpose explicit.
pub(crate) fn is_integrity_hash(value: &str) -> bool {
    const PREFIXES: &[&str] = &["sha1-", "sha256-", "sha384-", "sha512-", "sri-"];
    PREFIXES.iter().any(|prefix| value.starts_with(prefix))
}

/// Check a complete literal before the scanner raises an entropy warning.
/// Empty content matches no exception; accepting a shape does not prove the value is public.
pub(crate) fn is_structured_high_entropy_non_secret(value: &str) -> bool {
    const ALPHABETS: &[&str] = &[
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_",
        "abcdefghijklmnopqrstuvwxyz0123456789-_",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXY23456789",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_",
    ];
    static PUBLIC_FORMAT: OnceLock<Regex> = OnceLock::new();
    ALPHABETS.contains(&value)
        || static_regex(
            &PUBLIC_FORMAT,
            r"^(?:https://entra\.microsoft\.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/isMSAApp~/false\?Microsoft_AAD_IAM_legacyAADRedirect=true|security\.access_token_handler\.oidc\.signature\.(?:ES|RS|PS)(?:256|384|512)|[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com|soljson-v[0-9]+\.[0-9]+\.[0-9]+\+commit\.[0-9a-f]{8}\.js|https://github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9][A-Za-z0-9._-]{0,99}/commit/[0-9a-f]{40})$",
        ).is_match(value)
        || is_bounded_public_entropy_format(value)
        || is_structured_entropy_name(value)
}

/// Keep established help routes and clinical codes quiet only when every word fits their complete format.
/// An unmatched or malformed value stays eligible for entropy scoring.
fn is_bounded_public_entropy_format(value: &str) -> bool {
    static HELP_ARTICLE: OnceLock<Regex> = OnceLock::new();
    // A stored relative help link uses its own title grammar after the complete route matches.
    if let Some(article) = static_regex(
        &HELP_ARTICLE,
        r"^/hc/[a-z]{2}-[a-z]{2}/articles/[0-9]{12,13}-([A-Za-z]+(?:-[A-Za-z]+)*)$",
    )
    .captures(value)
    {
        // Only the approved short joiners may accompany otherwise bounded title words.
        return article[1].split('-').all(|word| {
            matches!(word, "a" | "to" | "in")
                || ((3..=32).contains(&word.len()) && has_entropy_word_case(word))
        });
    }
    static HELP_ROUTE: OnceLock<Regex> = OnceLock::new();
    static CLINICAL_CODE: OnceLock<Regex> = OnceLock::new();
    let formats = [
        static_regex(
            &HELP_ROUTE,
            r"^/hc/[a-z]{2}-[a-z]{2}/(?:sections|categories)/[0-9]{12}-([A-Za-z]+(?:-[A-Za-z]+)*)$",
        ),
        static_regex(&CLINICAL_CODE, r"^(?:PH|PHVS)_([A-Za-z]+)_HL7_V[0-9]{1,4}$"),
    ];
    // Either recognized format must account for the complete literal the user committed.
    formats.iter().any(|pattern| {
        // A missing match or an opaque label cannot grant an exception to the value.
        pattern.captures(value).is_some_and(|matched| {
            matched[1]
                .split('-')
                .all(|word| (3..=32).contains(&word.len()) && has_entropy_word_case(word))
        })
    })
}

/// Decide whether a letter run reads as an ordinary word or a compound name before granting a name exception.
fn has_entropy_word_case(word: &str) -> bool {
    static WORD_CASE: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &WORD_CASE,
        r"^(?:[A-Z]*[a-z]+|[A-Z]+|(?:[a-z]{3,}|[A-Z]{3,}|[A-Z][a-z]{2,})(?:[A-Z][a-z]{2,}|[A-Z]{3,})+)$",
    ).is_match(word)
}

/// Recognize readable names and repository paths without letting their words hide an opaque tail.
/// At least two word segments must supply a strict letter majority; empty or malformed names remain eligible for scoring.
fn is_structured_entropy_name(value: &str) -> bool {
    static NAME_SHAPE: OnceLock<Regex> = OnceLock::new();
    // A committed path may start with two parent components or one rooted, hidden or current-directory prefix.
    let normalized = value
        .strip_prefix("../../")
        .or_else(|| value.strip_prefix("../"))
        .or_else(|| value.strip_prefix("./"))
        .or_else(|| value.strip_prefix('/'))
        .or_else(|| value.strip_prefix('.'))
        .unwrap_or(value);
    // Missing segments or other punctuation keep the value eligible for a warning.
    if !static_regex(&NAME_SHAPE, r"^[A-Za-z0-9]+(?:[/._-]+[A-Za-z0-9]+)+$").is_match(normalized) {
        return false;
    }
    let mut alphanumeric_count = 0;
    let mut word_letter_count = 0;
    let mut word_segment_count = 0;
    // Readable directories do not excuse a random-looking filename; check each populated part independently.
    for segment in normalized
        .split(['/', '.', '_', '-'])
        .filter(|part| !part.is_empty())
    {
        // A rejected segment prevents the whole value from receiving the public-name exception.
        let Some(segment_word_letters) = entropy_segment_word_letters(segment) else {
            return false;
        };
        alphanumeric_count += segment.len();
        word_letter_count += segment_word_letters;
        word_segment_count += usize::from(segment_word_letters > 0);
    }
    word_segment_count >= 2 && word_letter_count * 2 > alphanumeric_count
}

/// Count readable word letters without accepting an opaque suffix in the same populated ASCII segment.
/// A zero count supplies no word evidence; None rejects the whole name and keeps it eligible for scoring.
fn entropy_segment_word_letters(segment: &str) -> Option<usize> {
    static SHORT_CODE: OnceLock<Regex> = OnceLock::new();
    static RUNS: OnceLock<Regex> = OnceLock::new();
    // Long undivided segments can hold opaque values, so they remain eligible for a warning.
    if segment.len() > 32 {
        return None;
    }
    // Model codes and timestamps may occur in public paths but contribute no readable-word evidence.
    if static_regex(
        &SHORT_CODE,
        r"^(?:[vVxXrR][0-9]{1,4}|[0-9]{1,4}[bBeE]|[aA][0-9]{1,4}[bB]|FP[0-9]{1,4}|i18n|ec2|[mMtT][0-9]{2,3}|[0-9]{8}T[0-9]{4}(?:[0-9]{2})?Z)$",
    )
    .is_match(segment)
    {
        return Some(0);
    }
    let (digits, letters): (Vec<_>, Vec<_>) = static_regex(&RUNS, r"[A-Za-z]+|[0-9]+")
        .find_iter(segment)
        .map(|part| part.as_str())
        .partition(|part| part.as_bytes()[0].is_ascii_digit());
    // A standalone short number can label a version; numbers mixed with words need tighter bounds.
    let max_digits = if letters.is_empty() { 6 } else { 4 };
    // Repeated or long number runs prevent the name from receiving an exception.
    if digits.len() > 2 || digits.iter().any(|part| part.len() > max_digits) {
        return None;
    }
    // Short labels may occur alone, but short letters interleaved with numbers do not establish a readable name.
    let min_letters = if digits.is_empty() { 1 } else { 3 };
    // Arbitrary case changes keep the value eligible for a warning.
    if letters
        .iter()
        .any(|part| part.len() < min_letters || !has_entropy_word_case(part))
    {
        return None;
    }
    Some(
        letters
            .iter()
            .filter(|part| part.len() >= 3)
            .map(|part| part.len())
            .sum(),
    )
}

/// Recognise analyser calibration fixtures that intentionally contain patterns users should normally fix.
/// Excluding them keeps self-analysis results focused on production behavior rather than the rule corpus.
pub(crate) fn path_is_calibration_fixture(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    // Files under the calibration tree are deliberate positive and negative rule examples.
    if normalized.contains("/tests/calibration/") || normalized.starts_with("tests/calibration/") {
        return true;
    }
    // The standalone calibration extras file serves the same test-only purpose.
    if normalized.ends_with("/calibration_extras.rs") || normalized == "calibration_extras.rs" {
        return true;
    }
    false
}

/// Recognise Rust test infrastructure where panic and unwrap patterns are expected scaffolding.
/// Fixture inputs remain analysable because users rely on them to prove sensitive-data rules fire.
/// The code before a trailing `//` comment, found outside string literals, so `let a = read(p); // slow path :(`
/// ends in `;` and `} // end match` is a closing brace.
pub(crate) fn without_trailing_comment(text: &str) -> &str {
    let masked = crate::strip_rust_string_literals(text);
    masked
        .find("//")
        .map_or(text, |position| text[..position].trim_end())
}

pub(crate) fn path_is_test_infrastructure(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    // Fixture files are user-like scan inputs, not test harness code to silence.
    if normalized.contains("/fixtures/") || normalized.starts_with("fixtures/") {
        return false;
    }
    normalized.contains("/tests/")
        || normalized.starts_with("tests/")
        || normalized.ends_with("/tests.rs")
        || normalized == "tests.rs"
}

#[cfg(test)]
mod high_entropy_tests {
    use super::*;

    const CLASSIC_BASE64_SECRET: &str =
        concat!("mF9qL2sT8vX3pR6n", "Y0aB4cD7eG1hJ5k", "M9pQ2rS+T=");
    const BASE64URL_SECRET: &str = concat!("Az9qL2sT8vX3pR6n", "Y0aB4cD7eG1hJ5k", "M9pQ2rS");
    const JWT_PAYLOAD_SEGMENT: &str =
        concat!("eyJzdWIiOiIxMjM0", "NTY3ODkwIiwibmFt", "ZSI6IkpvaG4ifQ");
    const GITHUB_PAT_LIKE_SECRET: &str = concat!("ghp_Az9qL2sT8vX", "3pR6nY0aB4cD7eG", "1hJ5kM9");
    const REPO_SLUG: &str = concat!("Microsoft/Type", "Script-Website-", "Builder12");
    const STANDARD_BASE64_ALPHABET: &str = concat!(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "+/"
    );
    const URL_SAFE_BASE64_ALPHABET: &str = concat!(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "-_"
    );
    const MODEL_IDENTIFIER: &str = concat!("deepinfra/Qwen/", "Qwen3-235B-A22B-", "Instruct-2507");
    // These real model-name shapes previously produced error findings: bare and single-slash IDs plus lowercase size codes.
    const BARE_MODEL_NAME: &str = "Llama-4-Maverick-17B-128E-Instruct-FP8";
    const SINGLE_SLASH_MODEL: &str = "Qwen/Qwen3-Coder-480B-A35B-Instruct";
    const LOWERCASE_MODEL_ID: &str = "abacus/Qwen/qwen3-coder-480b-a35b-instruct";
    // An opaque API response id and a separated value hiding a long high-entropy run:
    // both must stay flagged so the broadened skip cannot mask a credential.
    const OPAQUE_RESPONSE_ID: &str = concat!("chatcmpl-Bk9Ye6Y0", "t9E7bC3DOMxCpW8eJkTKU");
    const SEPARATED_SECRET_BLOB: &str = concat!("key-Zx9Q2rS8vX3pR", "6nY0aB4cD7eG1hJ-end");

    #[test]
    fn high_entropy_structured_predicates_accept_only_inert_shapes() {
        assert!(is_structured_high_entropy_non_secret(REPO_SLUG));
        assert!(is_structured_high_entropy_non_secret(
            STANDARD_BASE64_ALPHABET
        ));
        assert!(is_structured_high_entropy_non_secret(
            URL_SAFE_BASE64_ALPHABET
        ));
        assert!(is_structured_high_entropy_non_secret(MODEL_IDENTIFIER));

        assert!(!is_structured_high_entropy_non_secret(
            CLASSIC_BASE64_SECRET
        ));
        assert!(!is_structured_high_entropy_non_secret(BASE64URL_SECRET));
        assert!(!is_structured_high_entropy_non_secret(
            GITHUB_PAT_LIKE_SECRET
        ));
    }

    #[test]
    fn high_entropy_skips_model_identifiers_without_masking_secrets() {
        // Model names and IDs are concatenated low-entropy tokens, not credentials.
        assert!(is_structured_high_entropy_non_secret(BARE_MODEL_NAME));
        assert!(is_structured_high_entropy_non_secret(SINGLE_SLASH_MODEL));
        assert!(is_structured_high_entropy_non_secret(LOWERCASE_MODEL_ID));

        // A two-segment opaque id and a slug hiding a long random run keep flagging.
        assert!(!is_structured_high_entropy_non_secret(OPAQUE_RESPONSE_ID));
        assert!(!is_structured_high_entropy_non_secret(
            SEPARATED_SECRET_BLOB
        ));
    }

    #[test]
    fn high_entropy_predicates_keep_jwt_segment_flaggable() {
        assert!(is_high_entropy(JWT_PAYLOAD_SEGMENT, 32, 4.2));
        assert!(!is_structured_high_entropy_non_secret(JWT_PAYLOAD_SEGMENT));
    }

    #[test]
    fn high_entropy_integrity_hashes_include_sha1() {
        assert!(is_integrity_hash(concat!(
            "sha1-",
            "3GuHKO69A8db",
            "+HYIftzVDpy1aZQ="
        )));
        assert!(is_integrity_hash(concat!(
            "sha512-",
            "j51egjPa7/i+HYI",
            "ftzVDpy1aZQ=="
        )));
    }
}
