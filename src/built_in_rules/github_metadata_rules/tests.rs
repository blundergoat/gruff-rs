//! Focused matcher contracts for GitHub workflow permission syntax.
//! These tests replay individual YAML lines so quoting, comments, scope, and
//! block boundaries stay deterministic before findings reach CLI reports.

use super::*;

/// Run the complete expression/ownership matrix through the existing native workflow sink.
#[test]
fn workflow_secret_event_guard_matrix() {
    let cases = [
("expression github.event_name == 'issues'", "jobs:\n  build:\n    if: github.event_name == 'issues'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 0usize),
("expression github.event_name != 'pull_request_target'", "jobs:\n  build:\n    if: github.event_name != 'pull_request_target'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 0usize),
("expression ${{ !(github.event_name == 'pull_request_target') }}", "jobs:\n  build:\n    if: ${{ !(github.event_name == 'pull_request_target') }}\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 0usize),
("expression (github.event_name == 'push' || github.event_name == 'issues')", "jobs:\n  build:\n    if: (github.event_name == 'push' || github.event_name == 'issues')\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 0usize),
("expression github.event_name == 'issues' && inputs.enabled", "jobs:\n  build:\n    if: github.event_name == 'issues' && inputs.enabled\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 0usize),
("expression inputs.enabled && github.event_name == 'issues'", "jobs:\n  build:\n    if: inputs.enabled && github.event_name == 'issues'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 0usize),
("expression github.event_name == 'PULL_REQUEST_TARGET'", "jobs:\n  build:\n    if: github.event_name == 'PULL_REQUEST_TARGET'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("expression github.event_name == 'pull_request_target'", "jobs:\n  build:\n    if: github.event_name == 'pull_request_target'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("expression github.event_name != 'issues'", "jobs:\n  build:\n    if: github.event_name != 'issues'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("expression inputs.enabled", "jobs:\n  build:\n    if: inputs.enabled\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("expression github.event_name == 'issues' || inputs.enabled", "jobs:\n  build:\n    if: github.event_name == 'issues' || inputs.enabled\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("expression ${{ github.event_name == 'issues' }} trailing", "jobs:\n  build:\n    if: ${{ github.event_name == 'issues' }} trailing\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("expression github.event_name == 'issues' trailing", "jobs:\n  build:\n    if: github.event_name == 'issues' trailing\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("expression github.event_name == 'issues' &&", "jobs:\n  build:\n    if: github.event_name == 'issues' &&\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("expression github.event_name == 'issues' && contains(inputs.x, 'x')", "jobs:\n  build:\n    if: github.event_name == 'issues' && contains(inputs.x, 'x')\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("expression github.event_name == 0", "jobs:\n  build:\n    if: github.event_name == 0\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("expression !github.event_name == 'issues'", "jobs:\n  build:\n    if: !github.event_name == 'issues'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("ownership 1", "jobs:\n  build:\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n    if: github.event_name == 'issues'\n", 0usize),
("ownership 2", "'jobs':\n  'build':\n    'steps':\n      - 'run': echo ${{ secrets.DEPLOY_TOKEN }}\n        'if': github.event_name == 'issues'\n", 0usize),
("ownership 3", "jobs:\n  build:\n    steps:\n      - if: github.event_name == 'issues'\n        run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 0usize),
("ownership 4", "jobs:\n  build:\n    steps:\n      - run: |\n          if: github.event_name == 'issues'\n          echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("ownership 5", "jobs:\n  build:\n    steps:\n      - run: |\n          echo ${{ secrets.DEPLOY_TOKEN }}\n        if: github.event_name == 'issues'\n", 0usize),
("ownership 6", "env:\n  TOKEN: ${{ secrets.DEPLOY_TOKEN }}\njobs:\n  build:\n    if: github.event_name == 'issues'\n    steps:\n      - run: echo ready\n", 1usize),
("ownership 7", "jobs:\n  build:\n    env:\n      TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n    steps:\n      - if: github.event_name == 'issues'\n        run: echo ready\n", 1usize),
("ownership 8", "jobs:\n  safe:\n    if: github.event_name == 'issues'\n    steps:\n      - run: echo ready\n  build:\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("ownership 9", "jobs:\n  build:\n    steps:\n      - if: github.event_name == 'issues'\n        run: echo ready\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("ownership 10", "jobs:\n  build:\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n        with:\n          if: github.event_name == 'issues'\n", 1usize),
("ownership 11", "jobs:\n  build:\n    if: github.event_name == 'issues'\n    if: inputs.enabled\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("ownership 12", "jobs:\n  build:\n    if: github.event_name == 'issues'\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n  build:\n    steps:\n      - run: echo ready\n", 1usize),
("ownership 13", "jobs:\n  build:\n    if: github.event_name == 'issues'\n    env: &shared\n      TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n    steps:\n      - run: echo ready\n", 1usize),
("ownership 14", "jobs:\n  build:\n    if: github.event_name == 'issues'\n    <<: *shared\n    steps:\n      - run: echo ${{ secrets.DEPLOY_TOKEN }}\n", 1usize),
("ownership 15", "jobs: {build: {if: \"github.event_name == 'issues'\", env: {TOKEN: ${{ secrets.DEPLOY_TOKEN }}}}}\n", 1usize),
("scalar list alias", "jobs:\n  build:\n    if: github.event_name == 'issues'\n    env:\n      TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n    steps:\n      - *shared\n", 1usize),
 ];
    for (name, body, expected) in cases {
        let parsed = crate::source::ParsedSource {
            file: SourceFile {
                absolute_path: PathBuf::from(".github/workflows/guard.yml"),
                display_path: ".github/workflows/guard.yml".to_string(),
                is_rust: false,
                origin: SourceOrigin::Directory,
            },
            source: format!("on:\n  pull_request_target:\n{body}"),
            rust_ast: None,
            bounded_deep_scan: false,
            diagnostics: vec![],
            line_starts: std::sync::OnceLock::new(),
        };
        let mut findings = vec![];
        analyse_github_actions_rules(&parsed.as_source_unit(false), &mut findings);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == "security.github-actions-secrets-in-pr")
                .count(),
            expected,
            "{name}"
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == "security.github-actions-pull-request-target")
                .count(),
            1,
            "{name}"
        );
    }
}

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
