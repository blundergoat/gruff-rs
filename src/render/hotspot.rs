use super::*;

pub(super) fn render_hotspot(report: &AnalysisReport) -> String {
    serde_json::to_string_pretty(&json!({
        "schemaVersion": "gruff.hotspot.v1",
        "tool": report.tool,
        "score": report.score.composite,
        "files": report.score.top_offenders,
    }))
    .expect("hotspot serializes")
}
