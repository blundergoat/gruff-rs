//! Size and complexity findings report in two bands (FAMILY-CONTRACT section 12, search `Size and complexity findings
//! in two bands`). A unit over its limit but under one and a half times it gets an advisory notice not to grow; at that
//! ratio or above it keeps its severity and the advice to split or simplify. The message never changes between bands,
//! so a finding keeps its identity when its unit crosses the boundary.

use super::*;

/// Metadata key every banded finding carries.
pub(crate) const LIMIT_BAND_KEY: &str = "limitBand";
/// The fixed ratio at which a finding moves into the upper band; no option changes it.
const UPPER_BAND_RATIO: f64 = 1.5;

/// Lower-band advice for function length and complexity.
pub(crate) const LOWER_BAND_FUNCTION: &str =
    "Do not add to this function; put new code in a new function.";
/// Lower-band advice for file length.
pub(crate) const LOWER_BAND_FILE: &str = "Do not add to this file; put new code in a new file.";
/// Lower-band advice for parameter count.
pub(crate) const LOWER_BAND_PARAMETER: &str = "Do not add another parameter to this function.";
/// Upper-band advice for file length.
pub(crate) const SPLIT_FILE: &str =
    "Split this file by responsibility, one responsibility per file.";
/// Upper-band advice for function length.
pub(crate) const SPLIT_FUNCTION: &str = "Split this function at its steps, one step per function.";
/// Upper-band advice for parameter count.
pub(crate) const GROUP_PARAMETERS: &str =
    "Group the parameters that travel together into one object, or split the function by caller.";
/// Upper-band advice for every complexity rule.
pub(crate) const SIMPLIFY_PATH: &str = "Simplify the execution path: return early, merge branches that lead to the same result, and drop flags that steer later branches. Moving branches into helpers leaves the path as hard to follow.";

/// Name the band a measured value falls in against the limit in force, compared in floating point without rounding.
pub(crate) fn limit_band(measured: usize, limit: f64) -> &'static str {
    if measured as f64 >= UPPER_BAND_RATIO * limit {
        "upper"
    } else {
        "lower"
    }
}

/// Whether a finding sits in the lower band, which keeps it advisory after the configured severity is applied.
pub(crate) fn is_lower_band(finding: &Finding) -> bool {
    finding.metadata.get(LIMIT_BAND_KEY).and_then(Value::as_str) == Some("lower")
}

/// Put a size or complexity finding in its band: a lower-band finding is advisory whatever the configured severity,
/// and every banded finding carries its band's advice and the `limitBand` key.
pub(crate) fn apply_limit_band(
    finding: &mut Finding,
    measured: usize,
    limit: f64,
    lower_advice: &str,
    upper_advice: &str,
) {
    let band = limit_band(measured, limit);
    // A unit just over its limit is a notice not to grow, so it never carries the rule's louder severity.
    let advice = if band == "lower" {
        finding.severity = Severity::Advisory;
        lower_advice
    } else {
        upper_advice
    };
    finding.remediation = Some(advice.to_string());
    // Every banded rule builds its metadata as an object, so the key always has a place to go.
    if let Value::Object(metadata) = &mut finding.metadata {
        metadata.insert(LIMIT_BAND_KEY.to_string(), Value::from(band));
    }
}
