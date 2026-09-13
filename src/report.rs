use super::*;
use crate::report_identity::{compute_stable_identity, infer_finding_scope, FindingScope};
use serde::ser::{SerializeStruct, Serializer};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Severity {
    Advisory,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, ValueEnum, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Confidence {
    Low,
    Medium,
    High,
}

impl Severity {
    /// Rank this severity so a display floor or an exit gate can compare against it.
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
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

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
    /// The ratified durable identity this run computed, which SARIF publishes as the code-scanning
    /// fingerprint. `None` for a sensitive finding, which has no durable name, and for a finding built
    /// outside the analysis pipeline. Never serialized: the envelope publishes it through SARIF only.
    pub(crate) baseline_identity: Option<String>,
    /// Line-insensitive identity intended for external diff tooling.
    /// Computed from `rule_id`, `file_path`, and a stable subject based on
    /// scope/symbol. Independent of `fingerprint`, which
    /// remains line-sensitive so the baseline matcher in
    /// `src/baseline.rs` keeps its existing semantics.
    pub(crate) stable_identity: String,
    /// The subject the ratified identity hashed, carrying the declaration ordinal a consumer needs to recompute it.
    /// `None` for a sensitive finding, which is never named, and for a finding built outside the analysis pipeline.
    pub(crate) baseline_subject: Option<String>,
    /// What an applied baseline made of this finding, and `None` when no baseline was applied.
    pub(crate) baseline_status: Option<String>,
}

impl Serialize for Finding {
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

/// The finding's line-sensitive fingerprint, which is what the baseline matcher in `src/baseline.rs` keys on.
///
/// Moving a finding to a different line changes this by design; the ratified `stable_identity` is the one that
/// survives a move.
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
    format!("{:x}", hasher.finalize())[..16].to_string()
}

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
    pub(crate) fn is_failure(&self) -> bool {
        if self.invalidates_run == Some(false) {
            return false;
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
    /// Per-rule introduced/removed/net counts when a baseline or diff
    /// comparison context is active. The v3 machine adapter publishes these
    /// under `extensions.rs.topLevel.perRuleDeltas` and omits the extension on
    /// full-tree runs. Populated by `apply_baseline` and `apply_diff_patch_filter`.
    pub(crate) per_rule_deltas: Option<Vec<RuleDelta>>,
    pub(crate) suppressed_findings: Vec<SuppressedFinding>,
    /// Severity summary over the full finding set *before* baseline suppression,
    /// consumed by `gate.scope: all`. Internal only (`#[serde(skip)]`) so the JSON
    /// schema is unchanged; equals `summary` when no baseline dropped findings.
    pub(crate) all_findings_summary: Option<Summary>,
    pub(crate) machine_context: MachineReportContext,
}

impl Serialize for AnalysisReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        crate::machine_contract::serialize_analysis(self, serializer)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuleDelta {
    pub(crate) rule_id: String,
    pub(crate) introduced: usize,
    pub(crate) removed: usize,
    pub(crate) net: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ToolInfo {
    pub(crate) name: String,
    pub(crate) version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunInfo {
    pub(crate) project_root: String,
    pub(crate) format: String,
    pub(crate) fail_on: String,
    pub(crate) generated_at: String,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub(crate) struct Summary {
    pub(crate) advisory: usize,
    pub(crate) warning: usize,
    pub(crate) error: usize,
    pub(crate) total: usize,
}

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
    /// Sensitive findings, which no reviewed row may ever hide.
    pub(crate) not_eligible_count: usize,
    /// Sensitive findings a generated baseline counted rather than stored; 0 on an apply run.
    pub(crate) sensitive_counted: usize,
    /// Rows the baseline holds, so a reader can see the size of the reviewed set.
    pub(crate) entries: usize,
    pub(crate) generated: bool,
}

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
    /// Top-level config key that authored this row, `exclude` or `sensitiveExclusions`.
    /// `index` is section-local, so this pair is what identifies one row and lets text
    /// output name a config entry the user can edit. Internal only (`#[serde(skip)]`)
    /// because the family audit shape in FAMILY-CONTRACT.md section 13a fixes the
    /// published keys, and four other ports copy that shape.
    #[serde(skip)]
    pub(crate) config_key: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) struct SuppressedFinding {
    pub(crate) finding: Finding,
    pub(crate) suppression: SuppressionSummary,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ReportSuppressions {
    pub(crate) summaries: Vec<SuppressionSummary>,
    pub(crate) suppressed_findings: Vec<SuppressedFinding>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScoreReport {
    /// Mean of the applicable pillar scores, `None` when nothing applicable was evaluated and
    /// there is no health to report.
    pub(crate) composite: Option<f64>,
    /// Letter grade derived from `composite`, `None` whenever `composite` is.
    pub(crate) grade: Option<String>,
    /// Ratified scoring denominator: Rust files that survived discovery. Published so a reader can
    /// reproduce the composite without guessing which of the file counts it used.
    pub(crate) evaluated_files: usize,
    /// Every pillar this run could reach, so the composite's denominator is visible rather than
    /// inferred from the rows that happened to carry findings.
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

#[derive(Debug)]
pub(crate) struct FileScore {
    pub(crate) file_path: String,
    pub(crate) score: Option<f64>,
    /// Summed ratified weight for this file, published beside its score so the curve is reproducible.
    pub(crate) penalty: f64,
    pub(crate) findings: usize,
}

impl Serialize for FileScore {
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
