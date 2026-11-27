//! Define what one analysis records before text, JSON, SARIF, or HTML renders it.
//!
//! Findings name individual rule results. Diagnostics tell callers what prevented or limited the run.
//! The same report carries summaries, scores, baseline outcomes, and the suppression audit.

use super::*;
use crate::report_identity::{
    compute_stable_identity, infer_finding_scope, lower_hex, FindingScope,
};
use serde::ser::{SerializeStruct, Serializer};

/// How serious a finding is in the report.
///
/// The caller can choose a display floor or an exit threshold using these levels.
/// A severity gate can fail even when the display filter hides the finding.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Severity {
    Advisory,
    Warning,
    Error,
}

/// How certain a rule is about a finding.
///
/// A reviewer sees this alongside severity. The two describe different parts of the result.
/// A caller can set a confidence floor to limit which findings fail a severity gate.
#[derive(Debug, Clone, Copy, Serialize, ValueEnum, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Confidence {
    Low,
    Medium,
    High,
}

impl Severity {
    /// Rank this severity so a display floor or an exit gate can compare against it.
    ///
    /// Returns 0 for `Advisory`, 1 for `Warning` and 2 for `Error`, so a larger rank is more severe.
    pub(crate) fn rank(self) -> usize {
        match self {
            Self::Advisory => 0,
            Self::Warning => 1,
            Self::Error => 2,
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    /// Read one of the three ratified severities, refusing anything else rather than guessing a floor.
    ///
    /// `value` is the text to parse; only the exact lowercase `advisory`, `warning` or `error` is accepted, with no trimming.
    /// Returns the matching `Severity`, or an `Err` message that names the rejected text as an unknown severity.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "advisory" => Ok(Self::Advisory),
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            other => Err(format!("unknown severity `{other}`")),
        }
    }
}

impl Confidence {
    /// Name this confidence as the family contract spells it, for the hook payload a consumer parses.
    ///
    /// Returns the static lowercase name `low`, `medium` or `high`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// The quality area a rule reports against.
///
/// Callers use pillars to select rules and read grouped results.
/// The score uses the applicable standard pillars when it can grade a run.
#[derive(Debug, Clone, Copy, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Pillar {
    Size,
    Complexity,
    DeadCode,
    Waste,
    Maintainability,
    Naming,
    Documentation,
    Modernisation,
    Security,
    SensitiveData,
    TestQuality,
    Design,
}

pub(crate) const SCORE_PILLARS: &[Pillar] = &[
    Pillar::Size,
    Pillar::Complexity,
    Pillar::DeadCode,
    Pillar::Maintainability,
    Pillar::Naming,
    Pillar::Documentation,
    Pillar::Modernisation,
    Pillar::Security,
    Pillar::SensitiveData,
    Pillar::TestQuality,
    Pillar::Design,
];

/// Spell one pillar as its kebab-case label, the same name its `Serialize` derive writes.
///
/// `pillar` is the pillar to name; the match covers every variant, including `Waste`, which `SCORE_PILLARS` leaves out.
/// Returns the static label, such as `dead-code` for `Pillar::DeadCode`.
pub(crate) fn pillar_label(pillar: Pillar) -> &'static str {
    match pillar {
        Pillar::Size => "size",
        Pillar::Complexity => "complexity",
        Pillar::DeadCode => "dead-code",
        Pillar::Waste => "waste",
        Pillar::Maintainability => "maintainability",
        Pillar::Naming => "naming",
        Pillar::Documentation => "documentation",
        Pillar::Modernisation => "modernisation",
        Pillar::Security => "security",
        Pillar::SensitiveData => "sensitive-data",
        Pillar::TestQuality => "test-quality",
        Pillar::Design => "design",
    }
}

/// One result a rule asks the caller to review.
///
/// Rule, location, message, severity, and confidence describe the issue. A finding without a line applies more broadly.
/// The analysis attaches review identity and baseline status when that information is available.
#[derive(Debug, Clone)]
pub(crate) struct Finding {
    pub(crate) rule_id: String,
    pub(crate) message: String,
    pub(crate) file_path: String,
    pub(crate) line: Option<usize>,
    pub(crate) end_line: Option<usize>,
    pub(crate) column: Option<usize>,
    pub(crate) severity: Severity,
    pub(crate) pillar: Pillar,
    pub(crate) secondary_pillars: Vec<Pillar>,
    pub(crate) tier: String,
    pub(crate) confidence: Confidence,
    pub(crate) symbol: Option<String>,
    pub(crate) remediation: Option<String>,
    pub(crate) metadata: Value,
    pub(crate) scope: FindingScope,
    pub(crate) fingerprint: String,
    /// Line-free identity for baseline matching and supported report projections, including SARIF and the hook.
    /// `None` means the finding has no publishable baseline identity or has not been through analysis yet.
    pub(crate) baseline_identity: Option<String>,
    /// A line-free native identity based on rule, path, and scope or symbol.
    /// Internal hook comparisons can use it when the baseline identity is unavailable. The legacy fingerprint still includes location.
    pub(crate) stable_identity: String,
    /// The subject the ratified identity hashed, carrying the declaration ordinal a consumer needs to recompute it.
    /// `None` for a sensitive finding, which is never named, and for a finding built outside the analysis pipeline.
    pub(crate) baseline_subject: Option<String>,
    /// What an applied baseline made of this finding, and `None` when no baseline was applied.
    pub(crate) baseline_status: Option<String>,
}

impl Serialize for Finding {
    /// Serialize this finding as an 18-field struct with camelCase keys, writing `file_path` under both `file` and `filePath`.
    ///
    /// `serializer` is the serde backend that receives the fields.
    /// `baseline_identity`, `baseline_subject` and `baseline_status` are never written.
    /// Returns the serializer's success value, or the first error from starting the struct, writing a field or closing it with `end`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Finding", 18)?;
        state.serialize_field("ruleId", &self.rule_id)?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field("file", &self.file_path)?;
        state.serialize_field("filePath", &self.file_path)?;
        state.serialize_field("line", &self.line)?;
        state.serialize_field("endLine", &self.end_line)?;
        state.serialize_field("column", &self.column)?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("pillar", &self.pillar)?;
        state.serialize_field("secondaryPillars", &self.secondary_pillars)?;
        state.serialize_field("tier", &self.tier)?;
        state.serialize_field("confidence", &self.confidence)?;
        state.serialize_field("symbol", &self.symbol)?;
        state.serialize_field("remediation", &self.remediation)?;
        state.serialize_field("metadata", &self.metadata)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("fingerprint", &self.fingerprint)?;
        state.serialize_field("stableIdentity", &self.stable_identity)?;
        state.end()
    }
}

/// Give the report the evidence a rule collected about one finding.
///
/// The constructor uses these fields to attach scope and the native fingerprint consistently.
/// An absent line or symbol leaves the result at file or project scope where appropriate.
pub(crate) struct FindingDescriptor {
    pub(crate) rule_id: String,
    pub(crate) message: String,
    pub(crate) file_path: String,
    pub(crate) line: Option<usize>,
    pub(crate) severity: Severity,
    pub(crate) pillar: Pillar,
    pub(crate) confidence: Confidence,
    pub(crate) symbol: Option<String>,
    pub(crate) remediation: Option<String>,
    pub(crate) metadata: Value,
}

impl Finding {
    /// Build a finding from its descriptor, deriving its scope, line-sensitive fingerprint and stable identity from those fields.
    ///
    /// `descriptor` holds the caller's rule, message, path, line, symbol and other fields, which move into the finding unchanged.
    /// Returns the finding with tier `v0.1`, no end line, column or secondary pillars, and its three baseline fields `None`.
    pub(crate) fn new(descriptor: FindingDescriptor) -> Self {
        let FindingDescriptor {
            rule_id,
            message,
            file_path,
            line,
            severity,
            pillar,
            confidence,
            symbol,
            remediation,
            metadata,
        } = descriptor;
        let scope = infer_finding_scope(&rule_id, symbol.as_deref(), line);
        let fingerprint = line_sensitive_fingerprint(&rule_id, &file_path, line, symbol.as_deref());
        let stable_identity =
            compute_stable_identity(&rule_id, &file_path, scope, symbol.as_deref(), &message);

        Self {
            rule_id,
            message,
            file_path,
            line,
            end_line: None,
            column: None,
            severity,
            pillar,
            secondary_pillars: Vec::new(),
            tier: "v0.1".to_string(),
            confidence,
            symbol,
            remediation,
            metadata,
            scope,
            fingerprint,
            stable_identity,
            // The run names a finding once the parsed declarations are known, which is after construction.
            baseline_identity: None,
            baseline_subject: None,
            // No baseline has been applied yet; whichever one runs stamps this when it classifies the finding.
            baseline_status: None,
        }
    }
}

/// The finding's line-sensitive fingerprint, which `Finding::new` stores in the published `fingerprint` field.
///
/// Moving a finding to a different line changes this by design.
/// `Finding::new` derives `stable_identity` separately, from the rule, path, message, symbol and a scope inferred with the line.
///
/// `rule_id`, `file_path`, `line` and `symbol` are hashed with SHA-256 in that order, separated by NUL bytes.
/// A missing `line` hashes as 0 and a missing `symbol` as an empty string.
/// Returns the first 16 lowercase hex characters of the digest.
fn line_sensitive_fingerprint(
    rule_id: &str,
    file_path: &str,
    line: Option<usize>,
    symbol: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(file_path.as_bytes());
    hasher.update(b"\0");
    hasher.update(line.unwrap_or_default().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(symbol.unwrap_or_default().as_bytes());
    lower_hex(&hasher.finalize())[..16].to_string()
}

/// Explain a run-level problem a caller may need to act on before trusting the findings.
///
/// A diagnostic can name a source location or apply to the whole run, such as a config error.
/// Fatal diagnostics invalidate the scan. A budget note can accompany a completed result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunDiagnostic {
    pub(crate) diagnostic_type: String,
    pub(crate) message: String,
    pub(crate) file_path: Option<String>,
    pub(crate) line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) invalidates_run: Option<bool>,
}

impl RunDiagnostic {
    /// Returns whether the diagnostic invalidates the run, honoring an explicit flag before the type default.
    pub(crate) fn is_failure(&self) -> bool {
        // An explicit marker lets a budget note stay non-fatal and a setup failure stay fatal across formats.
        if let Some(invalidates_run) = self.invalidates_run {
            return invalidates_run;
        }
        matches!(
            self.diagnostic_type.as_str(),
            "missing-path"
                | "read-error"
                | "parse-error"
                | "manifest-read-error"
                | "manifest-parse-error"
                | "lockfile-read-error"
                | "lockfile-parse-error"
                | "history-error"
                | "gate-config-error"
        )
    }
}

/// The results and audit record for a single scan.
///
/// Renderers read this to show findings, counts, scores, and diagnostic context.
/// A result can include a baseline or diff comparison when the caller requested one.
#[derive(Debug)]
pub(crate) struct AnalysisReport {
    pub(crate) schema_version: String,
    pub(crate) tool: ToolInfo,
    pub(crate) run: RunInfo,
    pub(crate) summary: Summary,
    pub(crate) paths: PathSummary,
    pub(crate) diagnostics: Vec<RunDiagnostic>,
    pub(crate) suppressions: Vec<SuppressionSummary>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) suppressed_count: Option<usize>,
    pub(crate) score: ScoreReport,
    pub(crate) baseline: Option<BaselineReport>,
    /// Per-rule change counts from a baseline or diff comparison, published in `extensions.rs.topLevel.perRuleDeltas` by v3 JSON.
    /// `None` means there was no comparison result to show.
    pub(crate) per_rule_deltas: Option<Vec<RuleDelta>>,
    pub(crate) suppressed_findings: Vec<SuppressedFinding>,
    /// The `gate.scope: all` tally keeps reviewed baseline occurrences in scope and respects audited suppressions.
    /// This internal total can differ from the report's visible finding counts.
    pub(crate) all_findings_summary: Option<Summary>,
    pub(crate) machine_context: MachineReportContext,
}

impl Serialize for AnalysisReport {
    /// Serialize this report by delegating entirely to `crate::machine_contract::serialize_analysis`.
    ///
    /// `serializer` is the serde backend, passed through unchanged.
    /// Returns whatever that function returns: the serializer's success value or its error.
    ///
    /// Building the envelope assumes required paths were validated and any default ignore has a canonical reason.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        crate::machine_contract::serialize_analysis(self, serializer)
    }
}

/// Show what changed for one rule after comparison with a baseline or diff.
///
/// The caller can see introduced and removed occurrences separately.
/// The net count helps a reviewer understand the overall direction without losing either count.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuleDelta {
    pub(crate) rule_id: String,
    pub(crate) introduced: usize,
    pub(crate) removed: usize,
    pub(crate) net: i64,
}

/// Identify the analyzer that produced a report.
///
/// The tool name and version let automation match the output to the installed binary.
/// Use these fields when comparing results from different invocations.
#[derive(Debug, Serialize)]
pub(crate) struct ToolInfo {
    pub(crate) name: String,
    pub(crate) version: String,
}

/// Record the settings and timestamp that describe a scan.
///
/// Use the project root, format, and failure threshold to interpret the result.
/// The timestamp tells the caller when the report was produced.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunInfo {
    pub(crate) project_root: String,
    pub(crate) format: String,
    pub(crate) fail_on: String,
    pub(crate) generated_at: String,
}

/// The finding counts used by the report and exit gates.
///
/// Each severity has its own count so callers can interpret a configured threshold.
/// Zero counts mean no findings reached this tally. Diagnostic status is recorded alongside it.
#[derive(Debug, Serialize, Clone, Copy)]
pub(crate) struct Summary {
    pub(crate) advisory: usize,
    pub(crate) warning: usize,
    pub(crate) error: usize,
    pub(crate) total: usize,
}

/// Explain which paths the scan found, skipped, or could not locate.
///
/// Use ignored-path details to trace skips with known reasons.
/// The discovered file count can exceed the number successfully read or parsed.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PathSummary {
    pub(crate) analysed_files: usize,
    /// Flat ignored display paths paired with canonical v3 path details at serialization.
    pub(crate) ignored_paths: Vec<String>,
    /// Additive per-entry ignore detail: path + why it was ignored. Same data as
    /// `ignoredPaths` plus `source`/`pattern`; new in the changed-code-scope
    /// fix (ADR-018). `ignoredPaths` is retained so existing consumers do not break.
    pub(crate) ignored_path_details: Vec<IgnoredPath>,
    pub(crate) missing_paths: Vec<String>,
}

/// Show which reviewed baseline a scan read or generated and how it was used.
///
/// Occurrence counts distinguish reviewed findings, new findings, and reviews that are no longer needed.
/// `entries` counts rows in the baseline itself. A row can cover more than one occurrence.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineReport {
    pub(crate) path: String,
    pub(crate) source: String,
    /// Retained for backward compatibility; equals `unchanged_count` (ADR-002 addendum).
    pub(crate) suppressed: usize,
    /// Current findings absent from the baseline, or beyond the count it reviewed.
    pub(crate) new_count: usize,
    /// Current findings within the reviewed count, hidden from the failing set.
    pub(crate) unchanged_count: usize,
    /// Reviewed occurrences no longer present, which is debt the user has since fixed.
    pub(crate) absent_count: usize,
    /// Findings whose identity could not separate two declarations; reported, never hidden.
    pub(crate) collision_count: usize,
    /// Findings a baseline cannot hide, including sensitive findings and findings with no eligible identity.
    pub(crate) not_eligible_count: usize,
    /// Sensitive findings a generated baseline counted rather than stored; 0 on an apply run.
    pub(crate) sensitive_counted: usize,
    /// Rows the baseline holds, so a reader can see the size of the reviewed set.
    pub(crate) entries: usize,
    pub(crate) generated: bool,
}

/// Record a rule or attribute that hid findings and explain why it applied.
///
/// The caller sees the rule, scope, reason, and count. A zero count means the configured row matched nothing in this run.
/// Source metadata distinguishes built-in or inline suppressions from a caller's config entry.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SuppressionSummary {
    pub(crate) index: usize,
    pub(crate) rule: String,
    pub(crate) paths: Vec<String>,
    pub(crate) message_contains: Option<String>,
    /// Symbol narrowing from `sensitiveExclusions`; always null for `exclude` rows,
    /// which have no symbol scope.
    pub(crate) symbol: Option<String>,
    pub(crate) reason: String,
    pub(crate) suppressed: usize,
    /// `built-in` on a row the family's lockfile or test-path skip produced, `inline` on a row another tool's attribute
    /// or comment produced (FAMILY-CONTRACT.md section 13c); absent on a configured entry's row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<&'static str>,
    /// The owning config key or built-in audit label. Text can show `exclude[0]` and `sensitiveExclusions[0]` as separate entries.
    /// Section 13a of `FAMILY-CONTRACT.md` keeps this label internal and fixes the published audit keys.
    #[serde(skip)]
    pub(crate) config_key: &'static str,
}

/// Pair a hidden finding with the audit row that explains why it was suppressed.
///
/// Renderers can describe the reason without displaying the hidden finding as active.
/// Changed-code filtering can keep this evidence only for findings within the requested scope.
#[derive(Debug, Clone)]
pub(crate) struct SuppressedFinding {
    pub(crate) finding: Finding,
    pub(crate) suppression: SuppressionSummary,
}

/// Gather the audit summaries and the findings they suppressed.
///
/// Count summaries for the caller's report, and keep finding-level evidence for filtering and renderers that need it.
/// Both lists can be empty when no applicable suppression exists.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReportSuppressions {
    pub(crate) summaries: Vec<SuppressionSummary>,
    pub(crate) suppressed_findings: Vec<SuppressedFinding>,
}

/// Explain how the report reached its grade.
///
/// The composite, pillar scores, and highest-penalty files show where the caller can start reviewing.
/// With no evaluated Rust files, the report has no composite grade.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScoreReport {
    /// Mean of the applicable pillar scores, `None` when nothing applicable was evaluated and
    /// there is no health to report.
    pub(crate) composite: Option<f64>,
    /// Letter grade derived from `composite`, `None` whenever `composite` is.
    pub(crate) grade: Option<String>,
    /// Rust files used as the scoring denominator. Unread or unsuccessfully parsed Rust does not inflate this count.
    pub(crate) evaluated_files: usize,
    /// Standard pillars that contributed a numeric score to the composite. Empty when the run could not be graded.
    pub(crate) scored_pillars: Vec<Pillar>,
    /// Correlated concepts that billed one shared weight, so a reader can see which findings the
    /// grade counted once rather than inferring it from a total lower than the sum of its parts.
    pub(crate) clusters: Vec<ScoreCluster>,
    /// How much weight each native rule removed from the score. The native rule id is the ratified
    /// attribution key; a concept identifier may group reporting but never attribution.
    pub(crate) rule_attribution: Vec<RuleWeight>,
    pub(crate) pillars: Vec<PillarScore>,
    pub(crate) top_offenders: Vec<FileScore>,
}

/// Show one quality area's score and finding count.
///
/// A caller can distinguish a reachable pillar with no findings from one with no applicable checks.
/// A pillar can have findings but no numeric score when the run has no evaluated Rust files.
#[derive(Debug, Serialize)]
pub(crate) struct PillarScore {
    pub(crate) pillar: Pillar,
    /// Whether any rule in this port can reach the pillar, separating "reachable and clean", which
    /// scores 100, from a pillar with no opinion at all.
    pub(crate) applicable: bool,
    pub(crate) score: Option<f64>,
    pub(crate) grade: Option<String>,
    pub(crate) penalty: f64,
    pub(crate) findings: usize,
}

/// Rank one source file by the scoring penalties assigned to its findings.
///
/// The count tells the caller how many findings the file contributed. The penalty explains its position in the ranking.
/// The grade can be absent when there is no file count available for scoring.
#[derive(Debug)]
pub(crate) struct FileScore {
    pub(crate) file_path: String,
    pub(crate) score: Option<f64>,
    /// Summed ratified weight for this file, published beside its score so the curve is reproducible.
    pub(crate) penalty: f64,
    pub(crate) findings: usize,
}

impl Serialize for FileScore {
    /// Serialize the hotspot score with both v1 file path spellings.
    ///
    /// `serializer` receives `file`, `filePath`, `score`, and `findings`.
    /// Returns the serializer's success value, or the first error from starting the struct, writing a field or closing it with `end`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("FileScore", 4)?;
        state.serialize_field("file", &self.file_path)?;
        state.serialize_field("filePath", &self.file_path)?;
        state.serialize_field("score", &self.score)?;
        state.serialize_field("findings", &self.findings)?;
        state.end()
    }
}
