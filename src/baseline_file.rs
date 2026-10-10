//! The on-disk shape of `gruff-baseline.json`: what a reviewed row stores, and what the file says about secrets.
//!
//! These types are the file itself rather than the matching rules, so a reader who opens a user's baseline can
//! find every field it may carry in one place. Matching reads only the identity and the count; the rule, path,
//! and subject exist so a reviewer can read the file, and the sensitive block explains what it deliberately omits.

use super::*;

/// One reviewed row: a line-free identity and how many occurrences of it the team signed off.
///
/// Because no line, column, message, or severity is stored, everyday reformatting never re-flags debt the team
/// already accepted, and a second occurrence beyond the count is still reported as new.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineEntry {
    /// 16 lowercase hex characters; the only field baseline matching reads.
    pub(crate) identity: String,
    /// Occurrences the team accepted, at least one; an extra occurrence beyond it surfaces as new.
    pub(crate) count: usize,
    /// Descriptive rule id, kept so a reviewer can read the file; absent when the row omits it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rule_id: Option<String>,
    /// Descriptive project-relative path; absent when the row omits it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    /// Descriptive identity subject, so a reviewer sees what was reviewed; absent when the row omits it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) subject: Option<String>,
}

/// A whole baseline file: who wrote it, when, what it accepted, and what it only counted.
///
/// Every field is optional on read so a hand-edited file produces a named error rather than a parse failure the
/// user cannot act on.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineData {
    pub(crate) schema_version: Option<String>,
    /// Port that wrote the file; a foreign value is refused rather than applied to this run.
    pub(crate) tool_language: Option<String>,
    pub(crate) generated_at: Option<String>,
    /// Reviewed rows in ascending identity order; absent in a hand-written file, which then accepts nothing.
    pub(crate) occurrences: Option<Vec<BaselineEntry>>,
    /// Why the file stores no secret, and how many it counted instead.
    pub(crate) sensitive: Option<SensitiveSummary>,
}

/// The sensitive block every generated baseline carries: the policy, in words, plus counts and no identities.
///
/// A reader meets the rule in the file itself rather than in the docs: secrets are counted here and stay visible
/// until they are fixed or excluded with a written reason.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SensitiveSummary {
    pub(crate) eligible: bool,
    pub(crate) reason: String,
    pub(crate) counts: SensitiveCounts,
}

/// How many sensitive findings the writing run saw, in total and per rule; no path, message, or value is stored.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SensitiveCounts {
    pub(crate) total: usize,
    pub(crate) by_rule: BTreeMap<String, usize>,
}
