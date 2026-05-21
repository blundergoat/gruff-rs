use super::*;

pub(crate) fn analyse_project_dead_code_rules(
    context: &ProjectContext,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "dead-code.unused-private-item-candidate";
    if !config.is_rule_enabled(rule_id) {
        return;
    }

    for item in context
        .items
        .iter()
        .filter(|item| is_private_item_candidate(item))
    {
        if rust_identifier_occurrences(context, &item.name) > 1 {
            continue;
        }
        findings.push(unused_private_item_finding(rule_id, item));
    }
}

fn is_private_item_candidate(item: &ItemSummary) -> bool {
    !item.public
        && !item.cfg_gated
        && !item.test_context
        && matches!(item.kind.as_str(), "function" | "struct" | "enum" | "trait")
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
