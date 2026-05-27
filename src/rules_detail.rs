use super::*;
use crate::rules::{RuleDefinition, RuleRegistry};
use serde_json::json;
use std::fmt::Write as _;

const SUGGESTION_LIMIT: usize = 3;
const SUGGESTION_MAX_DISTANCE: usize = 3;

/// Render the deep-view card for a single rule, or surface a
/// suggestions-bearing error when the id does not match. Looks at
/// built-in rules first, then `custom_rules` so configured `custom.<slug>`
/// ids resolve symmetrically with the catalogue view.
pub(crate) fn render_rule_detail(
    rule_id: &str,
    registry: &RuleRegistry,
    custom_rules: &[CustomRule],
    format: RuleListFormat,
) -> Result<String, String> {
    if let Some(definition) = registry.get(rule_id) {
        return Ok(match format {
            RuleListFormat::Json => render_detail_json(definition),
            RuleListFormat::Text => render_detail_text(definition),
        });
    }
    if let Some(custom) = custom_rules.iter().find(|rule| rule.id == rule_id) {
        return Ok(match format {
            RuleListFormat::Json => render_custom_detail_json(custom),
            RuleListFormat::Text => render_custom_detail_text(custom),
        });
    }
    let suggestions = suggest_rule_ids(rule_id, registry, custom_rules);
    Err(format_unknown_rule_error(rule_id, &suggestions))
}

fn render_custom_detail_text(rule: &CustomRule) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Rule: {}", rule.id);
    let _ = writeln!(out, "  Kind:                custom");
    let _ = writeln!(out, "  Pillar:              {:?}", rule.pillar);
    let _ = writeln!(
        out,
        "  Severity:            {}",
        severity_word(rule.severity)
    );
    let _ = writeln!(
        out,
        "  Confidence:          {}",
        confidence_word(rule.confidence)
    );
    let _ = writeln!(out, "  Scope:               {}", rule.scope.as_str());
    out.push('\n');

    out.push_str("Message:\n");
    let _ = writeln!(out, "  {}", rule.message);
    out.push('\n');

    out.push_str("Pattern:\n");
    let _ = writeln!(out, "  {}", rule.pattern);
    out.push('\n');

    if let Some(remediation) = rule.remediation.as_deref() {
        out.push_str("Remediation:\n");
        let _ = writeln!(out, "  {remediation}");
        out.push('\n');
    }

    out.push_str("Escape hatches:\n");
    let _ = writeln!(out, "  custom_rules[id={}]", rule.id);
    let _ = writeln!(out, "  paths.ignore");
    out.push('\n');

    out.trim_end_matches('\n').to_string()
}

fn render_custom_detail_json(rule: &CustomRule) -> String {
    let payload = json!({
        "id": rule.id,
        "kind": "custom",
        "pillar": pillar_label(rule.pillar),
        "severity": severity_word(rule.severity),
        "confidence": confidence_word(rule.confidence),
        "scope": rule.scope.as_str(),
        "pattern": rule.pattern,
        "message": rule.message,
        "remediation": rule.remediation,
        "escapeHatches": [
            format!("custom_rules[id={}]", rule.id),
            "paths.ignore".to_string(),
        ],
    });
    serde_json::to_string_pretty(&payload).expect("custom rule detail serializes")
}

fn render_detail_text(definition: &RuleDefinition) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Rule: {}", definition.id);
    let _ = writeln!(out, "  Name:                {}", definition.name);
    let _ = writeln!(out, "  Pillar:              {:?}", definition.pillar);
    let _ = writeln!(out, "  Tier:                {}", definition.tier);
    let _ = writeln!(
        out,
        "  Kind:                {}",
        rule_kind_name(definition.kind)
    );
    let _ = writeln!(
        out,
        "  Default severity:    {}",
        severity_word(definition.default_severity)
    );
    let _ = writeln!(
        out,
        "  Confidence:          {}",
        confidence_word(definition.confidence)
    );
    let _ = writeln!(
        out,
        "  Enabled by default:  {}",
        if definition.default_enabled {
            "yes"
        } else {
            "no"
        }
    );
    out.push('\n');

    out.push_str("Description:\n");
    let _ = writeln!(out, "  {}", definition.description);
    out.push('\n');

    render_options_block(&mut out, definition);
    render_escape_hatches_block(&mut out, definition);
    render_false_positive_block(&mut out, definition);
    render_related_block(&mut out, definition);

    out.trim_end_matches('\n').to_string()
}

fn render_options_block(out: &mut String, definition: &RuleDefinition) {
    if definition.options.is_empty() {
        return;
    }
    out.push_str("Default options:\n");
    let name_width = definition
        .options
        .iter()
        .map(|opt| opt.name.len())
        .max()
        .unwrap_or(0);
    for option in definition.options {
        let _ = writeln!(
            out,
            "  {name:<name_width$}  list  {description}",
            name = option.name,
            name_width = name_width,
            description = option.description,
        );
    }
    out.push('\n');
}

fn render_escape_hatches_block(out: &mut String, definition: &RuleDefinition) {
    out.push_str("Escape hatches:\n");
    for option in definition.options {
        let _ = writeln!(out, "  rules.{}.options.{}", definition.id, option.name);
    }
    let _ = writeln!(out, "  rules.{}.enabled", definition.id);
    let _ = writeln!(out, "  paths.ignore");
    out.push('\n');
}

fn render_false_positive_block(out: &mut String, definition: &RuleDefinition) {
    if definition.false_positive_shapes.is_empty() {
        return;
    }
    out.push_str("Common false-positive shapes:\n");
    for shape in definition.false_positive_shapes {
        let _ = writeln!(out, "  - {}", shape.shape);
        let _ = writeln!(out, "    Mitigation: {}", shape.mitigation);
    }
    out.push('\n');
}

fn render_related_block(out: &mut String, definition: &RuleDefinition) {
    if definition.related_rules.is_empty() {
        return;
    }
    out.push_str("Related rules:\n");
    for related in definition.related_rules {
        let _ = writeln!(out, "  - {related}");
    }
    out.push('\n');
}

fn render_detail_json(definition: &RuleDefinition) -> String {
    let escape_hatches: Vec<String> = definition
        .options
        .iter()
        .map(|opt| format!("rules.{}.options.{}", definition.id, opt.name))
        .chain([
            format!("rules.{}.enabled", definition.id),
            "paths.ignore".to_string(),
        ])
        .collect();
    let payload = json!({
        "id": definition.id,
        "name": definition.name,
        "pillar": pillar_label(definition.pillar),
        "tier": definition.tier,
        "kind": rule_kind_name(definition.kind),
        "defaultSeverity": severity_word(definition.default_severity),
        "confidence": confidence_word(definition.confidence),
        "defaultEnabled": definition.default_enabled,
        "description": definition.description,
        "options": definition.options,
        "escapeHatches": escape_hatches,
        "falsePositiveShapes": definition.false_positive_shapes,
        "relatedRules": definition.related_rules,
    });
    serde_json::to_string_pretty(&payload).expect("rule detail serializes")
}

fn format_unknown_rule_error(rule_id: &str, suggestions: &[String]) -> String {
    if suggestions.is_empty() {
        return format!("Unknown rule: {rule_id}.");
    }
    format!(
        "Unknown rule: {rule_id}. Did you mean: {}?",
        suggestions.join(", ")
    )
}

fn suggest_rule_ids(
    rule_id: &str,
    registry: &RuleRegistry,
    custom_rules: &[CustomRule],
) -> Vec<String> {
    let builtin_ids = registry.definitions().iter().map(|def| def.id);
    let custom_ids = custom_rules.iter().map(|rule| rule.id.as_str());
    let mut scored: Vec<(usize, &str)> = builtin_ids
        .chain(custom_ids)
        .map(|id| (levenshtein_distance(rule_id, id), id))
        .filter(|(distance, _)| *distance <= SUGGESTION_MAX_DISTANCE)
        .collect();
    scored.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
    scored
        .into_iter()
        .take(SUGGESTION_LIMIT)
        .map(|(_, id)| id.to_string())
        .collect()
}

fn levenshtein_distance(left: &str, right: &str) -> usize {
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    let columns = right_bytes.len() + 1;
    let mut prev = (0..=right_bytes.len()).collect::<Vec<_>>();
    let mut curr = vec![0usize; columns];
    for (row, left_byte) in left_bytes.iter().enumerate() {
        curr[0] = row + 1;
        for (column, right_byte) in right_bytes.iter().enumerate() {
            let cost = if left_byte == right_byte { 0 } else { 1 };
            curr[column + 1] = (prev[column] + cost)
                .min(prev[column + 1] + 1)
                .min(curr[column] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[right_bytes.len()]
}

fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Advisory => "advisory",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

fn confidence_word(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}
