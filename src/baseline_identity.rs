//! The one line-free identity a baseline stores for a finding, ratified for the family in
//! `contracts/core/finding-identity.v1.json`.
//!
//! When a user runs `gruff-rs analyse --generate-baseline`, every ordinary finding is named by this identity
//! and nothing positional. On the next `analyse --baseline` a finding that moved lines still matches, while a
//! new sibling of the same rule never inherits the review.
//!
//! Three decisions live here:
//! - a symbol-bearing finding is named by its symbol plus a declaration ordinal, so two same-named functions stay apart;
//! - a finding naming no symbol falls back to its message with measured values normalised, so a grown file keeps its review;
//! - a sensitive finding receives no identity at all, because a stored identity is what would let a review hide a secret.

use super::*;

/// Token gruff-rs contributes to every identity, so the same rule on the same path never collides with another port's.
pub(crate) const TOOL_LANGUAGE: &str = "rs";

/// Joins a symbol to its declaration ordinal; a symbol carrying it could forge another symbol's ordinal.
const ORDINAL_SEPARATOR: char = '#';

/// What every measured value becomes in a subject, so a file that grew from 1010 to 1200 lines keeps its review.
const MEASURED_VALUE_PLACEHOLDER: char = '#';

/// One finding's durable name, plus the two facts matching needs alongside it.
///
/// `declaration_key` is equal for two findings on one declaration; two different keys under one identity are a
/// collision, which the run reports and never hides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingIdentity {
    pub(crate) identity: String,
    pub(crate) subject: String,
    pub(crate) declaration_key: String,
}

/// Report whether a finding may ever receive a baseline identity.
///
/// A sensitive finding never does: it stays visible and blocking on every run until the user fixes it or
/// excludes it with a written reason under `sensitiveExclusions`.
pub(crate) fn is_baseline_eligible(finding: &Finding) -> bool {
    !matches!(finding.pillar, Pillar::SensitiveData)
        && !finding.rule_id.starts_with("sensitive-data.")
}

/// Replace every measured value in a message with `#`, per the identity amendment of 2026-09-05.
///
/// A file-level message such as "file has 1010 lines" becomes "file has # lines", so growing the file does not
/// re-key the finding; rewording it still does, because the message is the only stable name such a finding has.
pub(crate) fn normalise_measured_values(message: &str) -> String {
    let mut normalised = String::with_capacity(message.len());
    let mut inside_number = false;
    let mut characters = message.chars().peekable();

    while let Some(character) = characters.next() {
        if character.is_ascii_digit() {
            // A run of digits, and any single `.` or `,` joining two runs, is one measured value.
            if !inside_number {
                normalised.push(MEASURED_VALUE_PLACEHOLDER);
                inside_number = true;
            }
            continue;
        }
        if inside_number
            && (character == '.' || character == ',')
            && characters.peek().is_some_and(char::is_ascii_digit)
        {
            continue;
        }
        inside_number = false;
        normalised.push(character);
    }

    normalised
}

/// Build the identity subject: `symbol#ordinal` for a symbol-bearing finding, else the normalised message.
///
/// The ordinal keeps two same-named functions apart; without it, reviewing one silently baselines the other.
pub(crate) fn baseline_subject(finding: &Finding, ordinal: usize) -> Result<String, String> {
    let Some(symbol) = finding
        .symbol
        .as_deref()
        .filter(|symbol| !symbol.is_empty())
    else {
        // A file-level finding has nothing but its message to name it, so its measurement is stripped first.
        if finding.message.is_empty() {
            return Err(format!(
                "finding {} in {} names neither a symbol nor a message",
                finding.rule_id, finding.file_path
            ));
        }
        return Ok(normalise_measured_values(&finding.message));
    };

    // A symbol carrying the separator could pose as another symbol's ordinal, so it is refused rather than guessed at.
    if symbol.contains(ORDINAL_SEPARATOR) {
        return Err(format!(
            "finding {} in {} has symbol {symbol:?} containing {ORDINAL_SEPARATOR:?}",
            finding.rule_id, finding.file_path
        ));
    }
    // Defaulting a missing ordinal to 1 would merge namesakes back together, the collision the ordinal prevents.
    if ordinal < 1 {
        return Err(format!(
            "finding {} in {} has symbol {symbol:?} without a declaration ordinal",
            finding.rule_id, finding.file_path
        ));
    }

    Ok(format!("{symbol}{ORDINAL_SEPARATOR}{ordinal}"))
}

/// Hash the ratified identity under an explicit tool language.
///
/// Conformance tests use it to reproduce the digests the family oracle pins for other ports, which is the only
/// proof the rule is one rule rather than five that happen to agree today.
pub(crate) fn compute_identity_for(
    tool_language: &str,
    rule_id: &str,
    path: &str,
    subject: &str,
) -> String {
    let mut hasher = Sha256::new();
    for (index, field) in [tool_language, rule_id, path, subject].iter().enumerate() {
        if index > 0 {
            hasher.update(b"\0");
        }
        hasher.update(field.as_bytes());
    }
    format!("{:x}", hasher.finalize())[..16].to_string()
}

/// Name every eligible finding in one run, ranking same-named declarations as it goes.
///
/// This is the single entry point baseline generation and matching both use, so a written identity and a matched
/// identity can never be computed two different ways. A sensitive finding maps to `None` and joins no group.
pub(crate) fn finding_identities(
    findings: &[Finding],
    declaration_position: &dyn Fn(&Finding) -> usize,
) -> Result<Vec<Option<FindingIdentity>>, String> {
    let ordinals = symbol_ordinals(findings, declaration_position);
    let mut identities = Vec::with_capacity(findings.len());

    for (index, finding) in findings.iter().enumerate() {
        // A sensitive finding is skipped before any hashing, so no secret ever reaches a stored identity.
        if !is_baseline_eligible(finding) {
            identities.push(None);
            continue;
        }
        let subject = baseline_subject(finding, ordinals[index])?;
        identities.push(Some(FindingIdentity {
            identity: compute_identity_for(
                TOOL_LANGUAGE,
                &finding.rule_id,
                &finding.file_path,
                &subject,
            ),
            subject,
            declaration_key: declaration_key(finding, declaration_position),
        }));
    }

    Ok(identities)
}

/// Rank each symbol-bearing finding's declaration among same-named declarations in its file.
///
/// Two findings on one declaration share a position and therefore an ordinal; a second declaration of that name
/// takes the next one, which is what stops one review from covering both.
fn symbol_ordinals(
    findings: &[Finding],
    declaration_position: &dyn Fn(&Finding) -> usize,
) -> Vec<usize> {
    let mut positions_by_symbol: BTreeMap<(&str, &str), BTreeSet<usize>> = BTreeMap::new();
    for finding in findings {
        if let Some(symbol) = named_symbol(finding) {
            positions_by_symbol
                .entry((finding.file_path.as_str(), symbol))
                .or_default()
                .insert(declaration_position(finding));
        }
    }

    findings
        .iter()
        .map(|finding| {
            // A symbol-less finding is named by its message, so it needs no ordinal and takes the sentinel zero.
            let Some(symbol) = named_symbol(finding) else {
                return 0;
            };
            let position = declaration_position(finding);
            positions_by_symbol
                .get(&(finding.file_path.as_str(), symbol))
                .and_then(|positions| positions.iter().position(|ranked| *ranked == position))
                .map_or(0, |rank| rank + 1)
        })
        .collect()
}

/// Name the declaration a finding sits on, for collision detection only.
///
/// A file-level finding names no declaration at all, so every symbol-less occurrence shares one key and is matched
/// by count; keying them by message would report two measurements of one file as an unresolvable collision.
fn declaration_key(finding: &Finding, declaration_position: &dyn Fn(&Finding) -> usize) -> String {
    match named_symbol(finding) {
        Some(_) => format!("declaration:{}", declaration_position(finding)),
        None => "declaration:file".to_string(),
    }
}

/// Read a finding's symbol only when it actually names one, so an empty string never becomes a declaration.
fn named_symbol(finding: &Finding) -> Option<&str> {
    if !is_baseline_eligible(finding) {
        return None;
    }
    finding
        .symbol
        .as_deref()
        .filter(|symbol| !symbol.is_empty())
}

/// Build the resolver that maps a finding to the line its declaration begins on, from this run's parsed functions.
///
/// The ordinal then counts declarations rather than lines: inserting code above a function moves its line and not
/// its ordinal, which is the whole point of a line-free identity.
pub(crate) fn declaration_position_from_blocks(
    blocks_by_file: &BTreeMap<String, Vec<FunctionBlock>>,
) -> impl Fn(&Finding) -> usize + '_ {
    move |finding: &Finding| {
        let line = finding.line.unwrap_or(1).max(1);
        let Some(symbol) = finding
            .symbol
            .as_deref()
            .filter(|symbol| !symbol.is_empty())
        else {
            return line;
        };
        let wanted = symbol.rsplit("::").next().unwrap_or(symbol);
        blocks_by_file
            .get(&finding.file_path)
            .and_then(|blocks| {
                blocks.iter().find(|block| {
                    block.name == wanted
                        && block.start_line <= line
                        && line <= block.start_line + block.line_count.saturating_sub(1)
                })
            })
            .map_or(line, |block| block.start_line)
    }
}

/// Rank a symbol on its own line when no parsed functions are available, as a direct API call has.
pub(crate) fn declaration_position_by_line(finding: &Finding) -> usize {
    finding.line.unwrap_or(1).max(1)
}
