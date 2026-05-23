use super::*;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Severity {
    Advisory,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Pillar {
    Size,
    Complexity,
    DeadCode,
    Waste,
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
    Pillar::Waste,
    Pillar::Naming,
    Pillar::Documentation,
    Pillar::Modernisation,
    Pillar::Security,
    Pillar::SensitiveData,
    Pillar::TestQuality,
    Pillar::Design,
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
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
    pub(crate) fingerprint: String,
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
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(file_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(line.unwrap_or_default().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(symbol.clone().unwrap_or_default().as_bytes());
        let fingerprint = format!("{:x}", hasher.finalize())[..16].to_string();

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
            fingerprint,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunDiagnostic {
    pub(crate) diagnostic_type: String,
    pub(crate) message: String,
    pub(crate) file_path: Option<String>,
    pub(crate) line: Option<usize>,
}

impl RunDiagnostic {
    pub(crate) fn is_failure(&self) -> bool {
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
        )
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnalysisReport {
    pub(crate) schema_version: String,
    pub(crate) tool: ToolInfo,
    pub(crate) run: RunInfo,
    pub(crate) summary: Summary,
    pub(crate) paths: PathSummary,
    pub(crate) diagnostics: Vec<RunDiagnostic>,
    pub(crate) suppressions: Vec<SuppressionSummary>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) score: ScoreReport,
    pub(crate) baseline: Option<BaselineReport>,
    #[serde(skip)]
    pub(crate) suppressed_findings: Vec<SuppressedFinding>,
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

#[derive(Debug, Serialize)]
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
    pub(crate) ignored_paths: Vec<String>,
    pub(crate) missing_paths: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineReport {
    pub(crate) path: String,
    pub(crate) source: String,
    pub(crate) suppressed: usize,
    pub(crate) generated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SuppressionSummary {
    pub(crate) index: usize,
    pub(crate) rule: String,
    pub(crate) paths: Vec<String>,
    pub(crate) message_contains: Option<String>,
    pub(crate) reason: String,
    pub(crate) suppressed: usize,
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
    pub(crate) composite: f64,
    pub(crate) grade: String,
    pub(crate) pillars: Vec<PillarScore>,
    pub(crate) top_offenders: Vec<FileScore>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PillarScore {
    pub(crate) pillar: Pillar,
    pub(crate) score: f64,
    pub(crate) findings: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileScore {
    pub(crate) file_path: String,
    pub(crate) score: f64,
    pub(crate) findings: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineData {
    pub(crate) schema_version: Option<String>,
    pub(crate) entries: Vec<BaselineEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineEntry {
    pub(crate) fingerprint: String,
    pub(crate) rule_id: String,
    pub(crate) file_path: String,
    pub(crate) line: Option<usize>,
    pub(crate) symbol: Option<String>,
    pub(crate) message: String,
}
