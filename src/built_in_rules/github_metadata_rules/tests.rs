//! Focused matcher contracts for GitHub workflow permission syntax.
//! These tests replay individual YAML lines so quoting, comments, scope, and
//! block boundaries stay deterministic before findings reach CLI reports.

use super::*;

/// Replay `lines` through one permissions state, reporting whether any line
/// is judged to grant broad write access.
fn has_broad_permission(lines: &[&str]) -> bool {
    let mut state = WorkflowPermissionsState::default();
    // The first broad grant makes the synthetic workflow actionable to a user.
    lines
        .iter()
        .any(|line| state.line_allows_broad_permission(line))
}

/// Workflow-level scoped writes remain reportable across valid scalar spellings.
#[test]
fn per_permission_write_is_detected_regardless_of_quoting() {
    // Unquoted baseline plus the valid-YAML quoted and commented variants
    // that all grant the same write access.
    assert!(has_broad_permission(&["permissions:", "  contents: write"]));
    assert!(has_broad_permission(&[
        "permissions:",
        "  contents: \"write\"",
    ]));
    assert!(has_broad_permission(&[
        "permissions:",
        "  contents: 'write'",
    ]));
    assert!(has_broad_permission(&[
        "permissions:",
        "  contents: write  # needed for release",
    ]));
    assert!(has_broad_permission(&[
        "permissions:",
        "  contents: \"write\"  # needed for release",
    ]));
    assert!(has_broad_permission(&[
        "permissions:",
        "  packages: \"write\"",
    ]));
}

/// Narrow values, unrelated keys, and job-scoped mappings remain silent.
#[test]
fn narrow_or_out_of_block_permissions_stay_silent() {
    assert!(!has_broad_permission(&["permissions:", "  contents: read"]));
    assert!(!has_broad_permission(&[
        "permissions:",
        "  contents: 'read'",
    ]));
    // `id-token: write` is a narrow, expected grant, not a broad one.
    assert!(!has_broad_permission(&[
        "permissions:",
        "  id-token: write",
    ]));
    // A step input named like a permission, outside any permissions block.
    assert!(!has_broad_permission(&["with:", "  contents: write"]));
    // A single job can receive its required scope without widening every workflow job.
    assert!(!has_broad_permission(&[
        "jobs:",
        "  publish:",
        "    permissions:",
        "      contents: write",
    ]));
}

/// `write-all` remains broad with quotes, comments, or job indentation.
#[test]
fn inline_write_all_scalar_is_detected_regardless_of_quoting() {
    assert!(has_broad_permission(&["permissions: write-all"]));
    assert!(has_broad_permission(&["permissions: \"write-all\""]));
    assert!(has_broad_permission(&["permissions: write-all  # broad",]));
    assert!(has_broad_permission(&[
        "jobs:",
        "  publish:",
        "    permissions: write-all",
    ]));
    assert!(!has_broad_permission(&["permissions: read-all"]));
}
