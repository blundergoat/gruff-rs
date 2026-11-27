//! Render the compact `gruff.hotspot.v1` JSON view for consumers ranking files by scan score.
//!
//! Callers get the composite and the standard number of top offenders for a quick inspection.
//! The v1 file rows retain both path spellings for existing scripts.

use super::*;

/// Renders a report as the pretty-printed `gruff.hotspot.v1` JSON document of its composite score and top offender files.
///
/// The document also carries the report's tool metadata and run diagnostics.
///
/// Returns the JSON text built from `report`, with the keys `schemaVersion`, `tool`, `score`, `diagnostics` and `files`.
/// The `score` value is `null` when the report has no composite score.
pub(super) fn render_hotspot(report: &AnalysisReport) -> String {
    serde_json::to_string_pretty(&json!({
        "schemaVersion": "gruff.hotspot.v1",
        "tool": report.tool,
        "score": report.score.composite,
        "diagnostics": report.diagnostics,
        "files": &report.score.top_offenders[..report.score.top_offenders.len().min(crate::scoring::TOP_OFFENDER_LIMIT)],
    }))
    .expect("hotspot serializes")
}
