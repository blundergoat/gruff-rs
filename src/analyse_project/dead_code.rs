use super::*;

/// Emits `dead-code.unused-private-item-candidate` for private items that appear
/// unreferenced across the whole project.
///
/// Usage: invoked by `analyse_project` after the identifier index is built.
///
/// Contract: emits only when the rule is enabled AND project coverage is
/// complete; a private item flags when its identifier appears at most once
/// (its definition) across all analysed sources.
///
/// Failure behaviour: on partial coverage it emits no findings and instead
/// appends a `partial-context-rule-suppressed` diagnostic pointing at a full
/// `analyse .`, because cross-file reference counts are not authoritative then.
pub(crate) fn analyse_project_dead_code_rules(
    context: &ProjectContext,
    config: &Config,
    diagnostics: &mut Vec<RunDiagnostic>,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "dead-code.unused-private-item-candidate";
    if !config.is_rule_enabled(rule_id) {
        return;
    }
    if context.coverage.is_partial() {
        diagnostics.push(partial_context_rule_diagnostic(rule_id));
        return;
    }

    for item in context
        .items
        .iter()
        .filter(|item| is_private_item_candidate(item))
    {
        if context.identifier_count(&item.name) > 1 {
            continue;
        }
        findings.push(unused_private_item_finding(rule_id, item));
    }
}

/// Builds the non-failing `partial-context-rule-suppressed` diagnostic recorded
/// when `rule_id` is skipped because the run did not cover the whole discoverable
/// Rust source universe under the project root.
fn partial_context_rule_diagnostic(rule_id: &str) -> RunDiagnostic {
    RunDiagnostic {
        diagnostic_type: "partial-context-rule-suppressed".to_string(),
        message: format!(
            "Rule `{rule_id}` was skipped because this run did not analyse every discoverable Rust source under the selected project root; run `gruff-rs analyse .` from that root for authoritative dead-code signal."
        ),
        file_path: None,
        line: None,
    }
}

fn is_private_item_candidate(item: &ItemSummary) -> bool {
    !item.public
        && !item.cfg_gated
        && !item.test_context
        && !item.trait_impl
        && !item.exported_by_attr
        && !item.allow_dead_code
        && matches!(
            item.kind.as_str(),
            "function" | "struct" | "enum" | "trait" | "const" | "static" | "type alias"
        )
        && item.name != "main"
}

fn unused_private_item_finding(rule_id: &str, item: &ItemSummary) -> Finding {
    let symbol = item_symbol(item);
    Finding::new(FindingDescriptor {
        rule_id: rule_id.to_string(),
        message: format!(
            "Private {} `{}` is an unused candidate; no other discovered Rust source references its name.",
            item.kind, item.name
        ),
        file_path: item.file_path.clone(),
        line: Some(item.line),
        severity: Severity::Advisory,
        pillar: Pillar::DeadCode,
        confidence: Confidence::Medium,
        symbol: Some(symbol),
        remediation: Some(
            "Remove the item, make the reference explicit, or keep it documented if it is used through macros or cfg-specific builds."
                .to_string(),
        ),
        metadata: json!({ "kind": item.kind.as_str(), "module": item.module_path.as_str(), "candidate": true }),
    })
}
